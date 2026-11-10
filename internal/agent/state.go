// Package agent is what runs on each device: 'wgh join' registers it with
// the coordinator and 'wgh up' keeps its WireGuard interface matching the
// mesh, picking direct paths where they work and the relay where they don't.
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/overspend1/wgh/internal/state"
)

const stateVersion = 1

// State is the device's identity, kept in a 0600 file. The private key
// never leaves this file.
type State struct {
	Version    int    `json:"version"`
	URL        string `json:"url"`
	Pin        string `json:"pin,omitempty"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	APIKey     string `json:"api_key"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Address    string `json:"address"`
	Subnet     string `json:"subnet"`

	// Preferences, changeable with flags to 'wgh up' or from the TUI.
	Interface  string   `json:"interface"`
	ListenPort int      `json:"listen_port"`
	Routes     []string `json:"advertise_routes,omitempty"`
	Exit       bool     `json:"advertise_exit,omitempty"`
	ExitNode   string   `json:"exit_node,omitempty"`
	NoRoutes   bool     `json:"no_accept_routes,omitempty"`
	NoDNS      bool     `json:"no_dns,omitempty"` // don't run the built-in DNS server
	// NoPortMap: don't ask the router to forward the port.
	NoPortMap bool `json:"no_portmap,omitempty"`
}

// ErrNotJoined means there is no agent state yet.
var ErrNotJoined = errors.New("this device has not joined a mesh yet: run 'wgh join <token>'")

// DefaultPath is $WGH_AGENT_STATE, else RootDir/agent.json for root (on
// Linux /var/lib/wgh/agent.json), else agent.json in the user's config dir.
func DefaultPath() string {
	if p := os.Getenv("WGH_AGENT_STATE"); p != "" {
		return p
	}
	if os.Geteuid() == 0 {
		return filepath.Join(RootDir, "agent.json")
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "wgh", "agent.json")
	}
	return "wgh-agent.json"
}

// SocketPath is where a running agent answers status requests.
func SocketPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "agent.sock")
}

// Load reads the agent state.
func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotJoined
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("%s has version %d, this build understands %d", path, s.Version, stateVersion)
	}
	if s.Interface == "" {
		s.Interface = DefaultInterface
	}
	if s.ListenPort == 0 {
		s.ListenPort = DefaultPort
	}
	return &s, nil
}

// Save writes the agent state with mode 0600.
func Save(path string, s *State) error {
	s.Version = stateVersion
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return state.WriteSecret(path, append(b, '\n'))
}

// DefaultInterface is the device's WireGuard interface name.
const DefaultInterface = "wgh0"

// DefaultPort is the device's UDP port; it differs from the relay's 51820 so
// the coordinator machine can also be a device.
const DefaultPort = 41820
