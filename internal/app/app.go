// Package app holds the operations shared by the CLI and the TUI: creating a
// server, adding peers, exporting configs and making QR codes. Nothing here
// prints or touches a network interface.
package app

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/overspend1/wgh/internal/ipam"
	"github.com/overspend1/wgh/internal/keys"
	"github.com/overspend1/wgh/internal/render"
	"github.com/overspend1/wgh/internal/state"
)

var ifaceRE = regexp.MustCompile(`^[A-Za-z0-9_=+.-]{1,15}$`)

// InitOptions describes a new server.
type InitOptions struct {
	Endpoint     string
	Subnet       string
	Port         int
	Interface    string
	Address      string // optional; default is the first host in Subnet
	DNS          []string
	NATInterface string
	MTU          int
}

// DefaultInitOptions returns the defaults used by 'wgh init' and the TUI.
func DefaultInitOptions() InitOptions {
	return InitOptions{Subnet: "10.8.0.0/24", Port: 51820, Interface: "wg0"}
}

// NewServer validates o and returns a fresh state with new server keys.
func NewServer(o InitOptions) (*state.State, error) {
	o.Endpoint = strings.TrimSpace(o.Endpoint)
	if o.Endpoint == "" || strings.ContainsAny(o.Endpoint, " \t\n") {
		return nil, errors.New("endpoint is required, e.g. vpn.example.com")
	}
	if o.Port < 1 || o.Port > 65535 {
		return nil, fmt.Errorf("port %d is out of range", o.Port)
	}
	if !ifaceRE.MatchString(o.Interface) {
		return nil, fmt.Errorf("interface %q is not a valid interface name (max 15 chars)", o.Interface)
	}
	if o.MTU != 0 && (o.MTU < 1280 || o.MTU > 9000) {
		return nil, fmt.Errorf("MTU %d should be between 1280 and 9000", o.MTU)
	}
	if o.NATInterface != "" && !ifaceRE.MatchString(o.NATInterface) {
		return nil, fmt.Errorf("NAT interface %q is not a valid interface name", o.NATInterface)
	}
	prefix, err := ipam.ParseSubnet(o.Subnet)
	if err != nil {
		return nil, err
	}
	addr := ipam.First(prefix)
	if o.Address != "" {
		a, err := netip.ParseAddr(o.Address)
		if err != nil {
			return nil, fmt.Errorf("server address: %w", err)
		}
		if err := ipam.Claim(prefix, a, nil); err != nil {
			return nil, fmt.Errorf("server address: %w", err)
		}
		addr = a
	}
	if err := render.ValidateIPs(o.DNS); err != nil {
		return nil, fmt.Errorf("DNS: %w", err)
	}
	kp, err := keys.NewPair()
	if err != nil {
		return nil, err
	}
	return &state.State{
		Version: state.Version,
		Server: state.Server{
			Interface:    o.Interface,
			Subnet:       prefix.String(),
			Address:      addr.String(),
			ListenPort:   o.Port,
			Endpoint:     o.Endpoint,
			PrivateKey:   kp.Private,
			PublicKey:    kp.Public,
			DNS:          o.DNS,
			NATInterface: o.NATInterface,
			MTU:          o.MTU,
		},
		Peers: []state.Peer{},
	}, nil
}

// PeerOptions describes a new peer.
type PeerOptions struct {
	Name       string
	IP         string // optional; default is the next free address
	PSK        bool
	AllowedIPs []string
	DNS        []string
	Keepalive  int
}

// DefaultPeerOptions returns the defaults used by 'wgh add' and the TUI.
func DefaultPeerOptions() PeerOptions {
	return PeerOptions{PSK: true, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, Keepalive: 25}
}

// AddPeer validates o, allocates an address, generates keys and appends the
// peer to s. The caller saves s.
func AddPeer(s *state.State, o PeerOptions, now time.Time) (*state.Peer, error) {
	if err := state.ValidName(o.Name); err != nil {
		return nil, err
	}
	if p, _ := s.Find(o.Name); p != nil {
		return nil, fmt.Errorf("a peer named %q already exists (%s)", o.Name, p.Address)
	}
	if o.Keepalive < 0 || o.Keepalive > 65535 {
		return nil, fmt.Errorf("keepalive %d is out of range", o.Keepalive)
	}
	if len(o.AllowedIPs) == 0 {
		return nil, errors.New("allowed IPs must not be empty")
	}
	if err := render.ValidateCIDRs(o.AllowedIPs); err != nil {
		return nil, err
	}
	if err := render.ValidateIPs(o.DNS); err != nil {
		return nil, fmt.Errorf("DNS: %w", err)
	}
	prefix, err := s.Subnet()
	if err != nil {
		return nil, err
	}
	used, err := s.UsedAddrs()
	if err != nil {
		return nil, err
	}
	var addr netip.Addr
	if o.IP != "" {
		if addr, err = netip.ParseAddr(o.IP); err != nil {
			return nil, fmt.Errorf("IP: %w", err)
		}
		if err := ipam.Claim(prefix, addr, used); err != nil {
			return nil, err
		}
	} else if addr, err = ipam.Next(prefix, used); err != nil {
		return nil, err
	}
	kp, err := keys.NewPair()
	if err != nil {
		return nil, err
	}
	peer := state.Peer{
		Name:       o.Name,
		Address:    addr.String(),
		PrivateKey: kp.Private,
		PublicKey:  kp.Public,
		AllowedIPs: o.AllowedIPs,
		DNS:        o.DNS,
		Keepalive:  o.Keepalive,
		CreatedAt:  now.UTC().Truncate(time.Second),
	}
	if o.PSK {
		if peer.PresharedKey, err = keys.GeneratePreshared(); err != nil {
			return nil, err
		}
	}
	s.Peers = append(s.Peers, peer)
	s.SortPeers()
	p, _ := s.Find(o.Name)
	return p, nil
}

// QRTerminal renders text as a compact QR code made of half-block
// characters, two modules per character row, with a two-module quiet zone.
// Light modules are drawn as filled blocks, which suits light-on-dark
// terminals; invert swaps that.
func QRTerminal(text string, invert bool) (string, error) {
	q, err := qrcode.New(text, qrcode.Low)
	if err != nil {
		return "", fmt.Errorf("qr: %w", err)
	}
	q.DisableBorder = true
	bm := q.Bitmap() // true = dark module
	const border = 2
	n := len(bm) + 2*border
	dark := func(r, c int) bool {
		r, c = r-border, c-border
		if r < 0 || c < 0 || r >= len(bm) || c >= len(bm) {
			return false
		}
		return bm[r][c]
	}
	var b strings.Builder
	for r := 0; r < n; r += 2 {
		for c := 0; c < n; c++ {
			top := !dark(r, c)
			bot := r+1 < n && !dark(r+1, c)
			if invert {
				top, bot = !top, r+1 < n && !bot
			}
			switch {
			case top && bot:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bot:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

// QRPNG renders text as a size x size PNG.
func QRPNG(text string, size int) ([]byte, error) {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return nil, fmt.Errorf("qr: %w", err)
	}
	return q.PNG(size)
}

// Export writes the server config and every client config (and optionally a
// QR PNG per client) under dir, all mode 0600. It returns the paths written.
func Export(s *state.State, dir string, withQR bool) ([]string, error) {
	if dir == "" {
		return nil, errors.New("export directory is required")
	}
	var written []string
	srv, err := render.Server(s)
	if err != nil {
		return nil, err
	}
	srvPath := filepath.Join(dir, s.Server.Interface+".conf")
	if err := state.WriteSecret(srvPath, []byte(srv)); err != nil {
		return nil, err
	}
	written = append(written, srvPath)
	for i := range s.Peers {
		p := &s.Peers[i]
		conf, err := render.Client(s, p)
		if err != nil {
			return written, err
		}
		path := filepath.Join(dir, "peers", p.Name+".conf")
		if err := state.WriteSecret(path, []byte(conf)); err != nil {
			return written, err
		}
		written = append(written, path)
		if withQR {
			img, err := QRPNG(conf, 512)
			if err != nil {
				return written, fmt.Errorf("qr for %s: %w", p.Name, err)
			}
			pngPath := filepath.Join(dir, "peers", p.Name+".png")
			if err := state.WriteSecret(pngPath, img); err != nil {
				return written, err
			}
			written = append(written, pngPath)
		}
	}
	return written, nil
}

// Ago describes how long before now t was, in a few characters.
func Ago(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// Bytes formats a byte count like 1.2 MiB.
func Bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
