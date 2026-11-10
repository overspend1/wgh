// Package coord is the wgh coordinator: the one small server that knows the
// device list. It hands out join tokens, gives each device an address and the
// public keys of the others, and runs a WireGuard relay that both shows
// devices their public address and carries traffic when no direct path works.
// It never sees a device's private key.
package coord

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/overspend1/wgh/internal/ipam"
	"github.com/overspend1/wgh/internal/keys"
	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/render"
	"github.com/overspend1/wgh/internal/wgctl"
)

// Options configures a coordinator.
type Options struct {
	Dir       string // state directory, created 0700
	Listen    string // HTTPS address, e.g. ":8443"
	URL       string // public URL put in join tokens; default https://Endpoint:port
	Endpoint  string // public host (or host:port) of the relay
	Port      int    // relay UDP port
	Interface string // relay interface name
	Subnet    string
	Name      string // the relay's name in the mesh
	Exit      bool   // offer the relay as an exit node
	NoRelay   bool   // run the control plane only, with no WireGuard relay
	PlainHTTP bool   // serve plain HTTP, for running behind a TLS proxy
	Backend   wgctl.Backend
	Logf      func(format string, a ...any)
	Now       func() time.Time
}

// Defaults fills in unset options.
func (o *Options) defaults() {
	if o.Listen == "" {
		o.Listen = ":8443"
	}
	if o.Port == 0 {
		o.Port = 51820
	}
	if o.Interface == "" {
		o.Interface = "wgh-relay"
	}
	if o.Subnet == "" {
		o.Subnet = mesh.DefaultSubnet
	}
	if o.Name == "" {
		o.Name = "relay"
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// Server is a running coordinator.
type Server struct {
	o        Options
	path     string
	pin      string
	cert     tls.Certificate
	mu       sync.Mutex
	st       *store
	subnet   netip.Prefix
	changed  chan struct{}
	relayCfg []wgctl.Peer
}

// New loads or creates the coordinator state in o.Dir.
func New(o Options) (*Server, error) {
	o.defaults()
	if o.Dir == "" {
		return nil, errors.New("coordinator needs a state directory")
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}
	host := strings.TrimSpace(o.Endpoint)
	if host == "" && (!o.NoRelay || o.URL == "") {
		return nil, errors.New("--endpoint is required: the public host name or IP devices reach this machine at")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	s := &Server{o: o, path: filepath.Join(o.Dir, "coordinator.json"), changed: make(chan struct{})}
	st, err := loadStore(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		prefix, err := ipam.ParseSubnet(o.Subnet)
		if err != nil {
			return nil, err
		}
		if prefix.Bits() > 28 {
			return nil, fmt.Errorf("subnet %s is too small for a mesh: use /28 or larger", prefix)
		}
		kp, err := keys.NewPair()
		if err != nil {
			return nil, err
		}
		st = &store{Subnet: prefix.String(), Domain: mesh.DefaultDomain, NetVersion: 1,
			Relay: relayKeys{PrivateKey: kp.Private, PublicKey: kp.Public, Address: ipam.First(prefix).String()}}
		if err := st.save(s.path); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	}
	s.st = st
	s.subnet, err = netip.ParsePrefix(st.Subnet)
	if err != nil {
		return nil, err
	}
	if !o.PlainHTTP {
		s.cert, s.pin, err = loadOrCreateCert(o.Dir, []string{host})
		if err != nil {
			return nil, err
		}
	}
	if s.o.URL == "" {
		_, port, _ := net.SplitHostPort(o.Listen)
		if port == "" {
			port = "8443"
		}
		scheme := "https"
		if o.PlainHTTP {
			scheme = "http"
		}
		s.o.URL = scheme + "://" + net.JoinHostPort(host, port)
	}
	return s, nil
}

// URL is the address put in join tokens.
func (s *Server) URL() string { return s.o.URL }

// Pin is the TLS certificate pin put in join tokens (empty in plain mode).
func (s *Server) Pin() string { return s.pin }

// AdminSocket is the path of the local admin socket.
func (s *Server) AdminSocket() string { return filepath.Join(s.o.Dir, "admin.sock") }

func (s *Server) saveLocked() {
	if err := s.st.save(s.path); err != nil {
		s.o.Logf("save state: %v", err)
	}
}

// bumpLocked records a change to the network and wakes long polls.
func (s *Server) bumpLocked() {
	s.st.NetVersion++
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *Server) findLocked(name string) (*device, int) {
	for i, d := range s.st.Devices {
		if d.Name == name {
			return d, i
		}
	}
	return nil, -1
}

func (s *Server) byKeyLocked(apiKey string) *device {
	for _, d := range s.st.Devices {
		if d.KeyHash != "" && mesh.HashEqual(apiKey, d.KeyHash) {
			return d
		}
	}
	return nil
}

func (s *Server) usedLocked() []netip.Addr {
	used := []netip.Addr{netip.MustParseAddr(s.st.Relay.Address)}
	for _, d := range s.st.Devices {
		if a, err := netip.ParseAddr(d.Address); err == nil {
			used = append(used, a)
		}
	}
	return used
}

func (s *Server) newDeviceLocked(name string) (*device, error) {
	if err := mesh.ValidName(name); err != nil {
		return nil, err
	}
	if name == s.o.Name {
		return nil, fmt.Errorf("%q is the relay's name; pick another", name)
	}
	if d, _ := s.findLocked(name); d != nil {
		return nil, fmt.Errorf("a device called %q is already in the mesh: pick another name with --name, or remove the old one first (wgh admin remove %s)", name, name)
	}
	addr, err := ipam.Next(s.subnet, s.usedLocked())
	if err != nil {
		return nil, err
	}
	id, err := mesh.RandomSecret(6)
	if err != nil {
		return nil, err
	}
	return &device{ID: id, Name: name, Address: addr.String(), Created: s.o.Now()}, nil
}

// NewToken makes a join token valid for ttl.
func (s *Server) NewToken(ttl time.Duration, reusable, approve bool) (string, error) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	secret, err := mesh.RandomSecret(24)
	if err != nil {
		return "", err
	}
	now := s.o.Now()
	s.mu.Lock()
	// Drop expired tokens while we are here.
	s.st.Tokens = slices.DeleteFunc(s.st.Tokens, func(t *token) bool { return now.After(t.Expires) })
	s.st.Tokens = append(s.st.Tokens, &token{Hash: mesh.Hash(secret), Created: now, Expires: now.Add(ttl), Reusable: reusable, Approve: approve})
	s.saveLocked()
	s.mu.Unlock()
	return mesh.Token{URL: s.o.URL, Pin: s.pin, Secret: secret}.Encode(), nil
}

// Join adds a device using a token.
func (s *Server) Join(req mesh.JoinRequest, seenIP string) (mesh.JoinResponse, error) {
	t, err := mesh.ParseToken(req.Token)
	if err != nil {
		return mesh.JoinResponse{}, err
	}
	if err := keys.Validate(req.PublicKey); err != nil {
		return mesh.JoinResponse{}, fmt.Errorf("public key: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.o.Now()
	var tok *token
	idx := -1
	for i, x := range s.st.Tokens {
		if mesh.HashEqual(t.Secret, x.Hash) {
			tok, idx = x, i
		}
	}
	if tok == nil || now.After(tok.Expires) {
		return mesh.JoinResponse{}, errUnauthorized("this join token is unknown, used or expired: make a new one with 'wgh admin token'")
	}
	for _, d := range s.st.Devices {
		if d.PublicKey == req.PublicKey {
			return mesh.JoinResponse{}, errors.New("this public key is already in the mesh")
		}
	}
	d, err := s.newDeviceLocked(req.Name)
	if err != nil {
		return mesh.JoinResponse{}, err
	}
	apiKey, err := mesh.RandomSecret(32)
	if err != nil {
		return mesh.JoinResponse{}, err
	}
	d.PublicKey, d.KeyHash, d.OS, d.Version = req.PublicKey, mesh.Hash(apiKey), req.OS, req.Version
	d.AutoApprove, d.SeenIP, d.LastSeen = tok.Approve, seenIP, now
	if tok.Reusable {
		tok.Uses++
	} else {
		s.st.Tokens = append(s.st.Tokens[:idx], s.st.Tokens[idx+1:]...)
	}
	s.st.Devices = append(s.st.Devices, d)
	s.bumpLocked()
	s.saveLocked()
	s.o.Logf("%s joined at %s", d.Name, d.Address)
	return mesh.JoinResponse{ID: d.ID, Name: d.Name, APIKey: apiKey, Address: d.Address, Subnet: s.st.Subnet}, nil
}

type errUnauthorized string

func (e errUnauthorized) Error() string { return string(e) }

// Update applies a heartbeat.
func (s *Server) Update(apiKey string, req mesh.UpdateRequest, seenIP string) error {
	if err := mesh.ValidRoutes(req.Routes); err != nil {
		return err
	}
	if req.PublicKey != "" {
		if err := keys.Validate(req.PublicKey); err != nil {
			return fmt.Errorf("public key: %w", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.byKeyLocked(apiKey)
	if d == nil {
		return errUnauthorized("this device is not in the mesh (it was removed?)")
	}
	changed := false
	set := func(dst *[]string, v []string) {
		v = append([]string(nil), v...)
		sort.Strings(v)
		if !slices.Equal(*dst, v) {
			*dst, changed = v, true
		}
	}
	if req.PublicKey != "" && req.PublicKey != d.PublicKey {
		for _, o := range s.st.Devices {
			if o != d && o.PublicKey == req.PublicKey {
				return errors.New("this public key belongs to another device")
			}
		}
		d.PublicKey, d.RelayEndpoint, d.RelayHS, changed = req.PublicKey, "", time.Time{}, true
		s.o.Logf("%s rotated its key", d.Name)
	}
	if req.ListenPort != d.ListenPort {
		d.ListenPort, changed = req.ListenPort, true
	}
	if seenIP != "" && seenIP != d.SeenIP {
		d.SeenIP, changed = seenIP, true
	}
	set(&d.Local, req.Endpoints)
	set(&d.Routes, req.Routes)
	if req.Exit != d.Exit {
		d.Exit, changed = req.Exit, true
	}
	if d.AutoApprove {
		if !slices.Equal(d.ApprovedRoutes, d.Routes) || d.ExitApproved != d.Exit {
			d.ApprovedRoutes, d.ExitApproved, changed = append([]string(nil), d.Routes...), d.Exit, true
		}
	} else {
		// Approval never covers routes the device has stopped advertising.
		kept := slices.DeleteFunc(append([]string(nil), d.ApprovedRoutes...), func(r string) bool { return !slices.Contains(d.Routes, r) })
		if !slices.Equal(kept, d.ApprovedRoutes) {
			d.ApprovedRoutes, changed = kept, true
		}
		if d.ExitApproved && !d.Exit {
			d.ExitApproved, changed = false, true
		}
	}
	if req.OS != "" && req.OS != d.OS {
		d.OS, changed = req.OS, true
	}
	if req.Version != "" && req.Version != d.Version {
		d.Version, changed = req.Version, true
	}
	d.Rx, d.Tx = req.RxBytes, req.TxBytes
	d.LastSeen = s.o.Now()
	if !d.Online {
		d.Online, changed = true, true
	}
	if changed {
		s.bumpLocked()
		s.saveLocked()
	}
	return nil
}

// Leave removes the calling device.
func (s *Server) Leave(apiKey string) error {
	s.mu.Lock()
	d := s.byKeyLocked(apiKey)
	s.mu.Unlock()
	if d == nil {
		return errUnauthorized("this device is not in the mesh")
	}
	return s.Remove(d.Name)
}

// Remove deletes a device; its key stops working at once.
func (s *Server) Remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, i := s.findLocked(name)
	if i < 0 {
		return fmt.Errorf("no device called %q", name)
	}
	s.st.Devices = append(s.st.Devices[:i], s.st.Devices[i+1:]...)
	s.bumpLocked()
	s.saveLocked()
	s.o.Logf("%s removed", name)
	return nil
}

// Approve allows a device's advertised subnet routes and exit node.
func (s *Server) Approve(name string) (routes []string, exit bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, _ := s.findLocked(name)
	if d == nil {
		return nil, false, fmt.Errorf("no device called %q", name)
	}
	d.ApprovedRoutes, d.ExitApproved = append([]string(nil), d.Routes...), d.Exit
	s.bumpLocked()
	s.saveLocked()
	return d.ApprovedRoutes, d.ExitApproved, nil
}

// AddStatic adds a device that can't run the agent, such as a phone, and
// returns its wg-quick config. It reaches the mesh through the relay.
func (s *Server) AddStatic(name string, exit bool) (string, error) {
	if s.o.NoRelay {
		return "", errors.New("phones and other plain WireGuard devices need the relay; restart without --no-relay")
	}
	if exit && !s.o.Exit {
		return "", errors.New("the relay is not an exit node: restart wgh serve with --exit to send a phone's internet traffic through it")
	}
	kp, err := keys.NewPair()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	d, err := s.newDeviceLocked(name)
	if err != nil {
		s.mu.Unlock()
		return "", err
	}
	d.Static, d.StaticPrivate, d.StaticExit, d.PublicKey, d.OS = true, kp.Private, exit, kp.Public, "wireguard app"
	s.st.Devices = append(s.st.Devices, d)
	s.bumpLocked()
	s.saveLocked()
	s.mu.Unlock()
	return s.StaticConfig(name)
}

// StaticConfig renders the wg-quick config of a static device.
func (s *Server) StaticConfig(name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, _ := s.findLocked(name)
	if d == nil || !d.Static {
		return "", fmt.Errorf("no phone or plain WireGuard device called %q", name)
	}
	allowed := []string{s.st.Subnet}
	for _, o := range s.st.Devices {
		allowed = append(allowed, o.ApprovedRoutes...)
	}
	if d.StaticExit {
		allowed = []string{"0.0.0.0/0"}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n# Name = %s\nAddress = %s/32\nPrivateKey = %s\n", d.Name, d.Address, d.StaticPrivate)
	fmt.Fprintf(&b, "\n[Peer]\n# %s (wgh relay)\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n",
		s.o.Name, s.st.Relay.PublicKey, render.Endpoint(s.o.Endpoint, s.o.Port), strings.Join(dedupe(allowed), ", "))
	return b.String(), nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func (s *Server) nodeLocked(d *device, viewer *device) mesh.Node {
	n := mesh.Node{ID: d.ID, Name: d.Name, Address: d.Address, PublicKey: d.PublicKey,
		Routes: append([]string(nil), d.ApprovedRoutes...), Exit: d.ExitApproved, Online: d.Online,
		LastSeen: d.LastSeen, Static: d.Static, OS: d.OS, Version: d.Version, RxBytes: d.Rx, TxBytes: d.Tx}
	for _, r := range d.Routes {
		if !slices.Contains(d.ApprovedRoutes, r) {
			n.PendingRoutes = append(n.PendingRoutes, r)
		}
	}
	n.PendingExit = d.Exit && !d.ExitApproved
	if d.Static {
		return n
	}
	var public []string
	if d.RelayEndpoint != "" {
		public = append(public, d.RelayEndpoint)
	}
	if d.SeenIP != "" && d.ListenPort > 0 {
		public = append(public, net.JoinHostPort(d.SeenIP, strconv.Itoa(d.ListenPort)))
	}
	// Two devices behind the same public address are probably on the same
	// LAN, where the LAN address works and hairpinning often doesn't.
	if viewer != nil && viewer.SeenIP != "" && viewer.SeenIP == d.SeenIP {
		n.Endpoints = dedupe(append(append([]string(nil), d.Local...), public...))
	} else {
		n.Endpoints = dedupe(append(public, d.Local...))
	}
	return n
}

func (s *Server) relayLocked() *mesh.Relay {
	if s.o.NoRelay {
		return nil
	}
	return &mesh.Relay{Name: s.o.Name, Address: s.st.Relay.Address, PublicKey: s.st.Relay.PublicKey,
		Endpoint: render.Endpoint(s.o.Endpoint, s.o.Port), Exit: s.o.Exit}
}

// NetMap builds the network map for the device with apiKey.
func (s *Server) NetMap(apiKey string) (mesh.NetMap, <-chan struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.byKeyLocked(apiKey)
	if d == nil {
		return mesh.NetMap{}, nil, errUnauthorized("this device is not in the mesh (it was removed?)")
	}
	nm := mesh.NetMap{Version: s.st.NetVersion, Subnet: s.st.Subnet, Domain: s.st.Domain,
		Self: s.nodeLocked(d, d), Relay: s.relayLocked()}
	for _, o := range s.st.Devices {
		if o != d {
			nm.Peers = append(nm.Peers, s.nodeLocked(o, d))
		}
	}
	return nm, s.changed, nil
}

// Status is the admin view of the mesh.
type Status struct {
	URL     string      `json:"url"`
	Subnet  string      `json:"subnet"`
	Relay   *mesh.Relay `json:"relay,omitempty"`
	Devices []mesh.Node `json:"devices"`
	Tokens  int         `json:"tokens"`
	Version uint64      `json:"version"`
}

// Status returns every device, including pending approvals.
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.o.Now()
	st := Status{URL: s.o.URL, Subnet: s.st.Subnet, Relay: s.relayLocked(), Version: s.st.NetVersion}
	for _, t := range s.st.Tokens {
		if now.Before(t.Expires) {
			st.Tokens++
		}
	}
	for _, d := range s.st.Devices {
		st.Devices = append(st.Devices, s.nodeLocked(d, nil))
	}
	return st
}

// Sweep refreshes online flags and the relay's view of each device. It runs
// every few seconds and on its own changes nothing a device sends.
func (s *Server) Sweep() {
	var stats map[string]wgctl.PeerStat
	if !s.o.NoRelay && s.o.Backend != nil {
		if list, err := s.o.Backend.Stats(s.o.Interface); err == nil {
			stats = map[string]wgctl.PeerStat{}
			for _, p := range list {
				stats[p.PublicKey] = p
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.o.Now()
	changed := false
	for _, d := range s.st.Devices {
		if p, ok := stats[d.PublicKey]; ok {
			if p.Endpoint != "" && p.Endpoint != d.RelayEndpoint {
				d.RelayEndpoint, changed = p.Endpoint, true
			}
			d.RelayHS = p.LastHandshake
			if d.Static {
				d.Rx, d.Tx = p.RxBytes, p.TxBytes
			}
		}
		online := now.Sub(d.LastSeen) < mesh.OnlineAfter
		if d.Static {
			online = !d.RelayHS.IsZero() && now.Sub(d.RelayHS) < 3*time.Minute
			if online {
				d.LastSeen = d.RelayHS
			}
		}
		if online != d.Online {
			d.Online, changed = online, true
		}
	}
	if changed {
		s.bumpLocked()
	}
}

// relayPeersLocked is the relay's desired WireGuard peer list.
func (s *Server) relayPeersLocked() []wgctl.Peer {
	var peers []wgctl.Peer
	for _, d := range s.st.Devices {
		allowed := []string{d.Address + "/32"}
		allowed = append(allowed, d.ApprovedRoutes...)
		peers = append(peers, wgctl.Peer{PublicKey: d.PublicKey, AllowedIPs: allowed})
	}
	return peers
}

func (s *Server) relayInterface() wgctl.Interface {
	bits := s.subnet.Bits()
	return wgctl.Interface{Name: s.o.Interface, ListenPort: s.o.Port, PrivateKey: s.st.Relay.PrivateKey,
		Address: netip.PrefixFrom(netip.MustParseAddr(s.st.Relay.Address), bits)}
}

// syncRelay applies the relay peer list when it has changed.
func (s *Server) syncRelay() error {
	if s.o.NoRelay || s.o.Backend == nil {
		return nil
	}
	s.mu.Lock()
	peers := s.relayPeersLocked()
	ifc := s.relayInterface()
	same := s.relayCfg != nil && wgctl.EqualPeers(peers, s.relayCfg)
	s.mu.Unlock()
	if same {
		return nil
	}
	if err := s.o.Backend.SetPeers(ifc, peers); err != nil {
		return err
	}
	s.mu.Lock()
	s.relayCfg = peers
	if len(s.relayCfg) == 0 {
		s.relayCfg = []wgctl.Peer{}
	}
	s.mu.Unlock()
	return nil
}

// Run serves the API and the admin socket until ctx ends, then removes the
// relay interface.
func (s *Server) Run(ctx context.Context) error {
	if !s.o.NoRelay {
		if s.o.Backend == nil {
			return errors.New("no WireGuard backend configured for the relay")
		}
		if err := s.o.Backend.Up(s.relayInterface()); err != nil {
			return fmt.Errorf("start relay: %w", err)
		}
		defer s.o.Backend.Down(s.o.Interface)
		if err := s.o.Backend.SetForward(s.o.Interface, s.st.Subnet, true); err != nil {
			return fmt.Errorf("enable forwarding for the relay: %w", err)
		}
		if err := s.syncRelay(); err != nil {
			return fmt.Errorf("configure relay: %w", err)
		}
	}
	ln, err := net.Listen("tcp", s.o.Listen)
	if err != nil {
		return err
	}
	if !s.o.PlainHTTP {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS13})
	}
	sock := s.AdminSocket()
	_ = os.Remove(sock)
	aln, err := net.Listen("unix", sock)
	if err != nil {
		ln.Close()
		return fmt.Errorf("admin socket: %w", err)
	}
	_ = os.Chmod(sock, 0o600)
	defer os.Remove(sock)

	api := &http.Server{Handler: s.APIHandler(), ReadHeaderTimeout: 10 * time.Second}
	admin := &http.Server{Handler: s.AdminHandler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- api.Serve(ln) }()
	go func() { errc <- admin.Serve(aln) }()
	s.o.Logf("coordinator listening on %s (public URL %s)", s.o.Listen, s.o.URL)

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			api.Shutdown(sctx)
			admin.Shutdown(sctx)
			return nil
		case err := <-errc:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-tick.C:
			s.Sweep()
			if err := s.syncRelay(); err != nil {
				s.o.Logf("relay: %v", err)
			}
		}
	}
}

// ---- HTTP ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	var ua errUnauthorized
	if errors.As(err, &ua) {
		code = http.StatusUnauthorized
	}
	writeJSON(w, code, mesh.ErrorResponse{Error: err.Error()})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("bad request body: %w", err)
	}
	return nil
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if k, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(k)
	}
	return ""
}

func (s *Server) remoteIP(r *http.Request) string {
	if s.o.PlainHTTP {
		// Behind a proxy: the proxy puts the real client first.
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			first := strings.TrimSpace(strings.Split(xf, ",")[0])
			if a, err := netip.ParseAddr(first); err == nil {
				return a.Unmap().String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

// APIHandler serves the device API.
func (s *Server) APIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/join", func(w http.ResponseWriter, r *http.Request) {
		var req mesh.JoinRequest
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		resp, err := s.Join(req, s.remoteIP(r))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("POST /v1/update", func(w http.ResponseWriter, r *http.Request) {
		var req mesh.UpdateRequest
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		if err := s.Update(bearer(r), req, s.remoteIP(r)); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/netmap", func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
		if wait < 0 || wait > 60 {
			wait = 25
		}
		key := bearer(r)
		deadline := time.NewTimer(time.Duration(wait) * time.Second)
		defer deadline.Stop()
		for {
			nm, changed, err := s.NetMap(key)
			if err != nil {
				writeErr(w, err)
				return
			}
			if nm.Version != since || wait == 0 {
				writeJSON(w, http.StatusOK, nm)
				return
			}
			select {
			case <-changed:
			case <-deadline.C:
				writeJSON(w, http.StatusOK, nm)
				return
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("POST /v1/leave", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Leave(bearer(r)); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// TokenRequest asks the admin API for a join token.
type TokenRequest struct {
	TTL      string `json:"ttl,omitempty"`
	Reusable bool   `json:"reusable,omitempty"`
	Approve  bool   `json:"approve,omitempty"`
}

// NameRequest names a device for the admin API.
type NameRequest struct {
	Name string `json:"name"`
	Exit bool   `json:"exit,omitempty"`
}

// AdminHandler serves the admin API on the local socket. Anyone who can open
// the socket (file mode 0600) is an admin.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Status())
	})
	mux.HandleFunc("POST /admin/token", func(w http.ResponseWriter, r *http.Request) {
		var req TokenRequest
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		ttl := time.Hour
		if req.TTL != "" {
			d, err := time.ParseDuration(req.TTL)
			if err != nil || d <= 0 {
				writeErr(w, fmt.Errorf("bad ttl %q: use e.g. 30m, 24h", req.TTL))
				return
			}
			ttl = d
		}
		tok, err := s.NewToken(ttl, req.Reusable, req.Approve)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"token": tok, "expires_in": ttl.String()})
	})
	nameOp := func(f func(NameRequest) (any, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var req NameRequest
			if err := readJSON(r, &req); err != nil {
				writeErr(w, err)
				return
			}
			v, err := f(req)
			if err != nil {
				writeErr(w, err)
				return
			}
			writeJSON(w, http.StatusOK, v)
		}
	}
	mux.HandleFunc("POST /admin/remove", nameOp(func(n NameRequest) (any, error) {
		return map[string]string{"removed": n.Name}, s.Remove(n.Name)
	}))
	mux.HandleFunc("POST /admin/approve", nameOp(func(n NameRequest) (any, error) {
		routes, exit, err := s.Approve(n.Name)
		return map[string]any{"routes": routes, "exit": exit}, err
	}))
	mux.HandleFunc("POST /admin/phone", nameOp(func(n NameRequest) (any, error) {
		conf, err := s.AddStatic(n.Name, n.Exit)
		return map[string]string{"config": conf}, err
	}))
	mux.HandleFunc("POST /admin/phone-config", nameOp(func(n NameRequest) (any, error) {
		conf, err := s.StaticConfig(n.Name)
		return map[string]string{"config": conf}, err
	}))
	return mux
}
