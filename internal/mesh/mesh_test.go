package mesh

import (
	"strings"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	pin, _ := RandomSecret(16)
	sec, _ := RandomSecret(16)
	in := Token{URL: "https://vpn.example.com:8443", Pin: pin, Secret: sec}
	s := in.Encode()
	if !strings.HasPrefix(s, "wgh1_") || strings.ContainsAny(s, " +/=") || len(s) > 90 {
		t.Fatalf("token %q (%d chars) is not copy-paste friendly", s, len(s))
	}
	out, err := ParseToken("  " + s + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip: %+v", out)
	}
	plain, err := ParseToken(Token{URL: "http://10.0.0.1:8080", Secret: sec}.Encode())
	if err != nil || plain.Pin != "" || plain.URL != "http://10.0.0.1:8080" || plain.Secret != sec {
		t.Fatalf("no-pin token: %+v %v", plain, err)
	}
	for _, bad := range []string{"", "wgh1_!!!", "tskey-abc", s[:30], Token{URL: "ftp://x", Secret: sec}.Encode()} {
		if _, err := ParseToken(bad); err == nil {
			t.Errorf("ParseToken(%q) succeeded", bad)
		}
	}
}

func TestNames(t *testing.T) {
	for in, want := range map[string]string{
		"Wiktors-MacBook-Pro.local": "wiktors-macbook-pro",
		"pve1":                      "pve1",
		"my_box  2":                 "my-box-2",
		"---":                       "device",
		"":                          "device",
	} {
		if got := CleanName(in); got != want {
			t.Errorf("CleanName(%q) = %q, want %q", in, got, want)
		}
		if err := ValidName(CleanName(in)); err != nil {
			t.Errorf("CleanName(%q) is not valid: %v", in, err)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "Upper", "a.b", strings.Repeat("a", 64)} {
		if ValidName(bad) == nil {
			t.Errorf("ValidName(%q) succeeded", bad)
		}
	}
}

func TestHash(t *testing.T) {
	h := Hash("key")
	if !HashEqual("key", h) || HashEqual("other", h) {
		t.Fatal("HashEqual wrong")
	}
	a, _ := RandomSecret(24)
	b, _ := RandomSecret(24)
	if a == b || len(a) != 32 {
		t.Fatalf("RandomSecret: %q %q", a, b)
	}
}

func TestValidRoutes(t *testing.T) {
	if err := ValidRoutes([]string{"192.168.1.0/24", "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"192.168.1.5/24", "0.0.0.0/0", "nope"} {
		if ValidRoutes([]string{bad}) == nil {
			t.Errorf("ValidRoutes(%q) succeeded", bad)
		}
	}
}
