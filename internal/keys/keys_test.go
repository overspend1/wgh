package keys

import (
	"encoding/base64"
	"testing"
)

// Known pair from RFC 7748 section 6.1 (Alice), base64-encoded.
func TestPublicKnownVector(t *testing.T) {
	priv := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	want := mustHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	got, err := Public(base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	if got != base64.StdEncoding.EncodeToString(want) {
		t.Fatalf("Public = %s, want %s", got, base64.StdEncoding.EncodeToString(want))
	}
}

func TestNewPairIsClampedAndDistinct(t *testing.T) {
	a, err := NewPair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPair()
	if err != nil {
		t.Fatal(err)
	}
	if a.Private == b.Private || a.Public == b.Public {
		t.Fatal("two generated pairs are identical")
	}
	raw, _ := base64.StdEncoding.DecodeString(a.Private)
	if raw[0]&7 != 0 || raw[31]&128 != 0 || raw[31]&64 == 0 {
		t.Fatalf("private key is not clamped: first=%08b last=%08b", raw[0], raw[31])
	}
	if err := Validate(a.Public); err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	psk, err := GeneratePreshared()
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(psk); err != nil {
		t.Errorf("Validate(psk) = %v", err)
	}
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if Validate(bad) == nil {
			t.Errorf("Validate(%q) succeeded, want error", bad)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c - 'a' + 10)
			default:
				t.Fatalf("bad hex %q", s)
			}
		}
		b[i] = v
	}
	return b
}
