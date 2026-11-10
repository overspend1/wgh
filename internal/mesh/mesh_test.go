package mesh

import (
	"strings"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	in := Token{URL: "https://vpn.example.com:8443", Pin: "abc", Secret: "s3cret"}
	s := in.Encode()
	if !strings.HasPrefix(s, "wgh1_") || strings.ContainsAny(s, " +/=") {
		t.Fatalf("token %q is not copy-paste friendly", s)
	}
	out, err := ParseToken("  " + s + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip: %+v", out)
	}
	for _, bad := range []string{"", "wgh1_!!!", "tskey-abc", Token{URL: "ftp://x", Secret: "s"}.Encode(), Token{URL: "https://x"}.Encode()} {
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
