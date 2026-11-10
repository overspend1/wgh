// Package mesh holds the wire format shared by the coordinator (wgh serve)
// and the device agent (wgh up): join tokens, the network map and the
// requests the agent sends.
package mesh

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// DefaultSubnet is the mesh address range. It sits outside 100.64.0.0/10 so
// wgh can run next to Tailscale while you move devices over.
const DefaultSubnet = "10.144.0.0/16"

// DefaultDomain is the suffix added to device names in /etc/hosts.
const DefaultDomain = "wgh"

// OnlineAfter is how long after its last heartbeat a device counts as online.
const OnlineAfter = 75 * time.Second

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidName reports whether name works as a device name and a host name.
func ValidName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid device name %q: use lowercase letters, digits and '-' (max 63, no leading or trailing '-')", name)
	}
	return nil
}

// CleanName turns something like a hostname into a valid device name.
func CleanName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	if out == "" {
		out = "device"
	}
	return out
}

// Token is what 'wgh join' needs to reach a coordinator: its URL, the
// SHA-256 pin of its TLS certificate (empty for a publicly trusted
// certificate) and a one-time secret.
type Token struct {
	URL    string `json:"u"`
	Pin    string `json:"p,omitempty"`
	Secret string `json:"s"`
}

const tokenPrefix = "wgh1_"

// Encode renders the token as a single copy-pasteable string.
func (t Token) Encode() string {
	b, _ := json.Marshal(t)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// ParseToken decodes a token made by Encode.
func ParseToken(s string) (Token, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, tokenPrefix) {
		return Token{}, errors.New("not a wgh join token (it should start with wgh1_)")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, tokenPrefix))
	if err != nil {
		return Token{}, fmt.Errorf("join token is damaged: %w", err)
	}
	var t Token
	if err := json.Unmarshal(b, &t); err != nil {
		return Token{}, fmt.Errorf("join token is damaged: %w", err)
	}
	if !strings.HasPrefix(t.URL, "https://") && !strings.HasPrefix(t.URL, "http://") {
		return Token{}, errors.New("join token has no coordinator URL")
	}
	if t.Secret == "" {
		return Token{}, errors.New("join token has no secret")
	}
	return t, nil
}

// RandomSecret returns n random bytes, base64url-encoded.
func RandomSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Hash returns the hex SHA-256 of a secret; only hashes are stored.
func Hash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// HashEqual compares a secret against a stored hash in constant time.
func HashEqual(secret, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(Hash(secret)), []byte(hash)) == 1
}

// JoinRequest is sent once by 'wgh join'. The private key never leaves the
// device: only the public key is sent.
type JoinRequest struct {
	Token     string `json:"token"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	OS        string `json:"os,omitempty"`
	Version   string `json:"version,omitempty"`
}

// JoinResponse gives the device its identity in the mesh.
type JoinResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	APIKey  string `json:"api_key"`
	Address string `json:"address"`
	Subnet  string `json:"subnet"`
}

// UpdateRequest is the agent's heartbeat. Zero fields are left unchanged
// except Endpoints, Routes and Exit, which always replace what was there.
type UpdateRequest struct {
	ListenPort int      `json:"listen_port"`
	Endpoints  []string `json:"endpoints,omitempty"`
	Routes     []string `json:"routes,omitempty"`
	Exit       bool     `json:"exit,omitempty"`
	PublicKey  string   `json:"public_key,omitempty"`
	OS         string   `json:"os,omitempty"`
	Version    string   `json:"version,omitempty"`
	RxBytes    int64    `json:"rx_bytes,omitempty"`
	TxBytes    int64    `json:"tx_bytes,omitempty"`
}

// Node is one device as the rest of the mesh sees it.
type Node struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	PublicKey string    `json:"public_key"`
	// Endpoints are candidate UDP addresses to try, best first: what the
	// relay saw, then the source of its last heartbeat, then its LAN.
	Endpoints []string  `json:"endpoints,omitempty"`
	Routes    []string  `json:"routes,omitempty"` // approved subnet routes
	Exit      bool      `json:"exit,omitempty"`   // approved as an exit node
	Online    bool      `json:"online"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	// Static devices (phones, routers) use a plain WireGuard config and are
	// only reachable through the relay.
	Static  bool   `json:"static,omitempty"`
	OS      string `json:"os,omitempty"`
	Version string `json:"version,omitempty"`
	// Advertised but not yet approved, shown to admins.
	PendingRoutes []string `json:"pending_routes,omitempty"`
	PendingExit   bool     `json:"pending_exit,omitempty"`
	RxBytes       int64    `json:"rx_bytes,omitempty"`
	TxBytes       int64    `json:"tx_bytes,omitempty"`
}

// Relay is the coordinator's own WireGuard peer: it relays traffic when two
// devices can't reach each other directly and shows each device its public
// address.
type Relay struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"`
	Exit      bool   `json:"exit,omitempty"`
}

// NetMap is everything a device needs to configure itself.
type NetMap struct {
	Version uint64 `json:"version"`
	Subnet  string `json:"subnet"`
	Domain  string `json:"domain"`
	Self    Node   `json:"self"`
	Relay   *Relay `json:"relay,omitempty"`
	Peers   []Node `json:"peers"`
}

// ErrorResponse is the body of every non-2xx reply.
type ErrorResponse struct {
	Error string `json:"error"`
}

// ValidRoutes checks a list of advertised subnet routes.
func ValidRoutes(routes []string) error {
	for _, r := range routes {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return fmt.Errorf("route %q: %w", r, err)
		}
		if p != p.Masked() {
			return fmt.Errorf("route %q has host bits set; did you mean %s?", r, p.Masked())
		}
		if p.Bits() == 0 {
			return fmt.Errorf("route %q: use --advertise-exit to offer a default route", r)
		}
	}
	return nil
}
