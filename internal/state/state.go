// Package state holds the server and peer definitions and persists them to a
// local JSON file that is only readable by its owner.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// Version is the state file format version.
const Version = 1

// Server describes the WireGuard server side of the tunnel.
type Server struct {
	Interface  string `json:"interface"`
	Subnet     string `json:"subnet"`
	Address    string `json:"address"`
	ListenPort int    `json:"listen_port"`
	Endpoint   string `json:"endpoint"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	// DNS is offered to clients, e.g. a Pi-hole on the LAN. Optional.
	DNS []string `json:"dns,omitempty"`
	// NATInterface, if set, adds iptables MASQUERADE rules for that
	// outgoing interface to the server config's PostUp/PostDown.
	NATInterface string `json:"nat_interface,omitempty"`
	MTU          int    `json:"mtu,omitempty"`
}

// Peer is one client of the server.
type Peer struct {
	Name         string    `json:"name"`
	Address      string    `json:"address"`
	PrivateKey   string    `json:"private_key"`
	PublicKey    string    `json:"public_key"`
	PresharedKey string    `json:"preshared_key,omitempty"`
	AllowedIPs   []string  `json:"allowed_ips"`
	DNS          []string  `json:"dns,omitempty"`
	Keepalive    int       `json:"persistent_keepalive,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// State is the whole file.
type State struct {
	Version int    `json:"version"`
	Server  Server `json:"server"`
	Peers   []Peer `json:"peers"`
}

// ErrNotInitialized means no state file exists yet.
var ErrNotInitialized = errors.New("no state file yet: run 'wgh init' first")

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ValidName reports whether name is safe to use as a peer name and file name.
func ValidName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid peer name %q: use letters, digits, '.', '_' or '-' (max 63, no leading punctuation)", name)
	}
	return nil
}

// DefaultPath returns $WGH_STATE, or $XDG_CONFIG_HOME/wgh/state.json, or
// ~/.config/wgh/state.json.
func DefaultPath() string {
	if p := os.Getenv("WGH_STATE"); p != "" {
		return p
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "wgh", "state.json")
	}
	return "wgh-state.json"
}

// Load reads the state file at path.
func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.Version != Version {
		return nil, fmt.Errorf("state %s has version %d, this build understands %d", path, s.Version, Version)
	}
	return &s, nil
}

// Save writes the state atomically with mode 0600, creating the parent
// directory with mode 0700 if needed.
func Save(path string, s *State) error {
	s.Version = Version
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	b = append(b, '\n')
	return WriteSecret(path, b)
}

// WriteSecret writes data to path atomically with mode 0600, creating the
// parent directory with mode 0700 if it does not exist.
func WriteSecret(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".wgh-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// Subnet parses the server subnet.
func (s *State) Subnet() (netip.Prefix, error) {
	return netip.ParsePrefix(s.Server.Subnet)
}

// UsedAddrs returns the server address and every peer address.
func (s *State) UsedAddrs() ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(s.Peers)+1)
	a, err := netip.ParseAddr(s.Server.Address)
	if err != nil {
		return nil, fmt.Errorf("server address: %w", err)
	}
	out = append(out, a)
	for _, p := range s.Peers {
		a, err := netip.ParseAddr(p.Address)
		if err != nil {
			return nil, fmt.Errorf("peer %s address: %w", p.Name, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// Find returns the peer called name and its index, or -1.
func (s *State) Find(name string) (*Peer, int) {
	for i := range s.Peers {
		if s.Peers[i].Name == name {
			return &s.Peers[i], i
		}
	}
	return nil, -1
}

// Remove deletes the peer called name.
func (s *State) Remove(name string) error {
	_, i := s.Find(name)
	if i < 0 {
		return fmt.Errorf("no peer named %q", name)
	}
	s.Peers = append(s.Peers[:i], s.Peers[i+1:]...)
	return nil
}

// SortPeers orders peers by tunnel address.
func (s *State) SortPeers() {
	sort.SliceStable(s.Peers, func(i, j int) bool {
		a, errA := netip.ParseAddr(s.Peers[i].Address)
		b, errB := netip.ParseAddr(s.Peers[j].Address)
		if errA != nil || errB != nil {
			return s.Peers[i].Name < s.Peers[j].Name
		}
		return a.Less(b)
	})
}
