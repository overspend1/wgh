package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/wgctl"
)

// Path names shown in status.
const (
	PathDirect  = "direct"
	PathRelay   = "relay"
	PathOffline = "offline"
	PathStatic  = "via relay" // phones and other plain WireGuard devices
	PathSelf    = "this device"
)

// PeerStatus is one device as this agent sees it.
type PeerStatus struct {
	Name          string    `json:"name"`
	Address       string    `json:"address"`
	Address6      string    `json:"address6,omitempty"`
	OS            string    `json:"os,omitempty"`
	Online        bool      `json:"online"`
	Path          string    `json:"path"`
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	LastSeen      time.Time `json:"last_seen,omitempty"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	Routes        []string  `json:"routes,omitempty"`
	Exit          bool      `json:"exit,omitempty"`
	Static        bool      `json:"static,omitempty"`
	Relay         bool      `json:"relay,omitempty"`
}

// Status is the whole picture for 'wgh status' and the TUI.
type Status struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	// Address6 is this device's IPv6 address inside the mesh; empty with a
	// coordinator from before IPv6, or on a host with IPv6 turned off.
	Address6      string       `json:"address6,omitempty"`
	Subnet        string       `json:"subnet"`
	Subnet6       string       `json:"subnet6,omitempty"`
	Interface     string       `json:"interface"`
	ListenPort    int          `json:"listen_port"`
	URL           string       `json:"url"`
	Connected     bool         `json:"connected"`
	LastError     string       `json:"last_error,omitempty"`
	ExitNode      string       `json:"exit_node,omitempty"`
	ExitActive    bool         `json:"exit_active"`
	ExitNote      string       `json:"exit_note,omitempty"`
	ForwardNote   string       `json:"forward_note,omitempty"`
	Routes        []string     `json:"advertise_routes,omitempty"`
	AdvertiseExit bool         `json:"advertise_exit,omitempty"`
	PendingRoutes []string     `json:"pending_routes,omitempty"`
	PendingExit   bool         `json:"pending_exit,omitempty"`
	DryRun        bool         `json:"dry_run,omitempty"`
	DNS           string       `json:"dns,omitempty"` // DNSOn, DNSHostsOnly or DNSOff
	Version       string       `json:"version"`
	Peers         []PeerStatus `json:"peers"`
	At            time.Time    `json:"at"`
}

// Status reports the current state.
func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Status{Name: a.st.Name, Address: a.st.Address, Subnet: a.st.Subnet, Interface: a.st.Interface,
		ListenPort: a.st.ListenPort, URL: a.st.URL, Connected: a.connected, LastError: a.lastErr,
		ExitNode: a.st.ExitNode, ExitActive: a.exitOn, ExitNote: a.exitNote, Routes: a.st.Routes,
		AdvertiseExit: a.st.Exit, DryRun: a.o.DryRun, Version: a.o.Version, At: a.o.Now(),
		DNS: a.dnsModeLocked(), ForwardNote: a.forwardNoteLocked()}
	if a.nm == nil {
		return s
	}
	s.PendingRoutes, s.PendingExit = a.nm.Self.PendingRoutes, a.nm.Self.PendingExit
	if a.upAddr6.IsValid() && wgctl.IPv6Off(a.o.Backend, a.st.Interface) == nil {
		s.Address6, s.Subnet6 = a.upAddr6.Addr().String(), a.nm.Subnet6
	}
	if r := a.nm.Relay; r != nil {
		ps := PeerStatus{Name: r.Name, Address: r.Address, Address6: r.Address6, Online: a.connected, Path: PathRelay,
			Endpoint: r.Endpoint, Exit: r.Exit, Relay: true}
		if st, ok := a.relayStatLocked(r.PublicKey); ok {
			ps.LastHandshake, ps.RxBytes, ps.TxBytes = st.LastHandshake, st.RxBytes, st.TxBytes
			if st.Endpoint != "" {
				ps.Endpoint = st.Endpoint
			}
		}
		ps.Path = "relay server"
		s.Peers = append(s.Peers, ps)
	}
	for _, n := range a.nm.Peers {
		ps := PeerStatus{Name: n.Name, Address: n.Address, Address6: n.Address6, OS: n.OS, Online: n.Online, LastSeen: n.LastSeen,
			Routes: n.Routes, Exit: n.Exit, Static: n.Static}
		switch p := a.paths[n.PublicKey]; {
		case n.Static:
			ps.Path, ps.RxBytes, ps.TxBytes = PathStatic, n.RxBytes, n.TxBytes
		case p == nil:
			ps.Path = PathOffline
		default:
			ps.Endpoint, ps.LastHandshake = p.endpoint, p.stat.LastHandshake
			ps.RxBytes, ps.TxBytes = p.stat.RxBytes, p.stat.TxBytes
			switch {
			case p.direct && a.nm.Relay != nil:
				ps.Path = PathDirect
			case a.nm.Relay == nil:
				ps.Path = PathDirect
			case !n.Online:
				ps.Path = PathOffline
			default:
				ps.Path = PathRelay
			}
		}
		if !n.Online && ps.Path != PathDirect {
			ps.Path = PathOffline
		}
		s.Peers = append(s.Peers, ps)
	}
	sort.SliceStable(s.Peers, func(i, j int) bool {
		if s.Peers[i].Relay != s.Peers[j].Relay {
			return !s.Peers[i].Relay
		}
		return s.Peers[i].Name < s.Peers[j].Name
	})
	return s
}

func (a *Agent) relayStatLocked(pub string) (st struct {
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
	Endpoint      string
}, ok bool) {
	stats, err := a.o.Backend.Stats(a.st.Interface)
	if err != nil {
		return st, false
	}
	for _, p := range stats {
		if p.PublicKey == pub {
			st.LastHandshake, st.RxBytes, st.TxBytes, st.Endpoint = p.LastHandshake, p.RxBytes, p.TxBytes, p.Endpoint
			return st, true
		}
	}
	return st, false
}

// ExitRequest picks an exit node over the socket.
type ExitRequest struct {
	Name string `json:"name"`
}

func (a *Agent) serveSocket(path string) (func(), error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(mesh.ErrorResponse{Error: err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(a.Status())
	}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { reply(w, nil) })
	mux.HandleFunc("POST /exit", func(w http.ResponseWriter, r *http.Request) {
		var req ExitRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			reply(w, err)
			return
		}
		err := a.SetExitNode(req.Name)
		if err == nil {
			a.reconcile()
		}
		reply(w, err)
	})
	mux.HandleFunc("POST /rotate", func(w http.ResponseWriter, r *http.Request) {
		err := a.Rotate(r.Context())
		if err == nil {
			a.reconcile()
		}
		reply(w, err)
	})
	mux.HandleFunc("POST /down", func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil)
		go a.Stop()
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		os.Remove(path)
	}, nil
}

// Local talks to a running agent over its socket.
type Local struct {
	HTTP *http.Client
}

// NewLocal returns a client for the agent socket at path.
func NewLocal(path string) *Local {
	return &Local{HTTP: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
	}}}
}

// ErrNotRunning means no agent answered on the socket.
var ErrNotRunning = errors.New("wgh up is not running on this device")

func (l *Local) do(method, path string, in any) (Status, error) {
	var s Status
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytesReader(b)
	}
	req, err := http.NewRequest(method, "http://agent"+path, body)
	if err != nil {
		return s, err
	}
	resp, err := l.HTTP.Do(req)
	if err != nil {
		return s, fmt.Errorf("%w (%v)", ErrNotRunning, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		var e mesh.ErrorResponse
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return s, errors.New(e.Error)
		}
		return s, fmt.Errorf("agent: %s", resp.Status)
	}
	return s, json.Unmarshal(b, &s)
}

// Status asks the agent for its status.
func (l *Local) Status() (Status, error) { return l.do("GET", "/status", nil) }

// SetExit picks an exit node ("" for none).
func (l *Local) SetExit(name string) (Status, error) {
	return l.do("POST", "/exit", ExitRequest{Name: name})
}

// Rotate rotates the device key.
func (l *Local) Rotate() (Status, error) { return l.do("POST", "/rotate", nil) }

// Down stops the agent, which takes the interface down.
func (l *Local) Down() error {
	_, err := l.do("POST", "/down", nil)
	return err
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
