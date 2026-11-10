package coord

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/overspend1/wgh/internal/state"
)

const stateVersion = 1

type relayKeys struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Address    string `json:"address"`
}

type device struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	PublicKey string    `json:"public_key"`
	KeyHash   string    `json:"api_key_sha256,omitempty"`
	Created   time.Time `json:"created"`
	OS        string    `json:"os,omitempty"`
	Version   string    `json:"version,omitempty"`

	// Static devices (phones) get a plain config; the coordinator keeps
	// their private key because it made it, so the QR can be shown again.
	Static        bool   `json:"static,omitempty"`
	StaticPrivate string `json:"static_private_key,omitempty"`
	StaticExit    bool   `json:"static_exit,omitempty"`

	Routes         []string `json:"routes,omitempty"` // advertised
	ApprovedRoutes []string `json:"approved_routes,omitempty"`
	Exit           bool     `json:"exit,omitempty"` // advertised
	ExitApproved   bool     `json:"exit_approved,omitempty"`
	AutoApprove    bool     `json:"auto_approve,omitempty"`

	// Runtime facts, refreshed by heartbeats and the relay.
	LastSeen   time.Time `json:"last_seen,omitempty"`
	ListenPort int       `json:"listen_port,omitempty"`
	Local      []string  `json:"local_endpoints,omitempty"`
	SeenIP     string    `json:"seen_ip,omitempty"`
	// WantRelayExit is the exit node this device asks the relay to reach
	// for it (runtime only).
	WantRelayExit string    `json:"-"`
	RelayEndpoint string    `json:"relay_endpoint,omitempty"`
	RelayHS       time.Time `json:"relay_handshake,omitempty"`
	Online        bool      `json:"-"`
	Rx            int64     `json:"-"`
	Tx            int64     `json:"-"`
}

type token struct {
	Hash     string    `json:"sha256"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	Reusable bool      `json:"reusable,omitempty"`
	Approve  bool      `json:"approve,omitempty"`
	Uses     int       `json:"uses,omitempty"`
}

type store struct {
	Version    int       `json:"version"`
	Subnet     string    `json:"subnet"`
	Domain     string    `json:"domain"`
	Relay      relayKeys `json:"relay"`
	NetVersion uint64    `json:"net_version"`
	Devices    []*device `json:"devices"`
	Tokens     []*token  `json:"tokens"`
}

func loadStore(path string) (*store, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s store
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("%s has version %d, this build understands %d", path, s.Version, stateVersion)
	}
	return &s, nil
}

func (s *store) save(path string) error {
	s.Version = stateVersion
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return state.WriteSecret(path, append(b, '\n'))
}

// loadOrCreateCert returns the coordinator's TLS certificate, creating a
// self-signed one on first start, and its pin (base64url SHA-256 of the DER).
func loadOrCreateCert(dir string, hosts []string) (tls.Certificate, string, error) {
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		if err := makeCert(certPath, keyPath, hosts); err != nil {
			return tls.Certificate{}, "", err
		}
	}
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("load TLS certificate: %w", err)
	}
	return c, Pin(c.Certificate[0]), nil
}

// Pin returns the pin of a DER certificate: the first 16 bytes of its
// SHA-256, base64url.
func Pin(der []byte) string {
	h := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(h[:16])
}

func makeCert(certPath, keyPath string, hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "wgh coordinator"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"wgh-coordinator"},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := state.WriteSecret(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})); err != nil {
		return err
	}
	return state.WriteSecret(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
