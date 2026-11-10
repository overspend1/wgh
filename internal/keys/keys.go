// Package keys generates WireGuard keys (Curve25519) natively, with no
// dependency on the wg binary.
package keys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the length in bytes of every WireGuard key.
const KeySize = 32

// Pair is a WireGuard key pair, both halves base64-encoded as wg expects.
type Pair struct {
	Private string
	Public  string
}

// GeneratePrivate returns a new clamped Curve25519 private key, base64-encoded.
func GeneratePrivate() (string, error) {
	var k [KeySize]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	clamp(&k)
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// Public derives the public key from a base64 private key.
func Public(private string) (string, error) {
	k, err := decode(private)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	pub, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// NewPair generates a private key and derives its public key.
func NewPair() (Pair, error) {
	priv, err := GeneratePrivate()
	if err != nil {
		return Pair{}, err
	}
	pub, err := Public(priv)
	if err != nil {
		return Pair{}, err
	}
	return Pair{Private: priv, Public: pub}, nil
}

// GeneratePreshared returns a random 32-byte preshared key, base64-encoded.
// Unlike a private key it is not clamped.
func GeneratePreshared() (string, error) {
	var k [KeySize]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// Validate reports whether s is a well-formed base64 WireGuard key.
func Validate(s string) error {
	_, err := decode(s)
	return err
}

func decode(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	if len(b) != KeySize {
		return nil, fmt.Errorf("want %d bytes, got %d", KeySize, len(b))
	}
	return b, nil
}

// clamp applies the standard Curve25519 private key clamping, as wg genkey does.
func clamp(k *[KeySize]byte) {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}
