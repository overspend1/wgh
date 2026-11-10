package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/overspend1/wgh/internal/agent"
)

func TestPrintStatusDNS(t *testing.T) {
	for _, mode := range []string{agent.DNSOn, agent.DNSHostsOnly, agent.DNSOff} {
		var b bytes.Buffer
		printStatus(&b, agent.Status{Name: "laptop", Address: "10.144.0.2", Connected: true, DNS: mode})
		if !strings.Contains(b.String(), "dns "+mode+"\n") {
			t.Errorf("status for %q:\n%s", mode, b.String())
		}
	}
}

func TestUpRejectsBadDNSFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := agent.Save(path, &agent.State{Name: "laptop", Address: "10.144.0.2", Subnet: "10.144.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	_, err := wgh(t, "up", "--state", path, "--dns", "maybe", "--dry-run")
	if err == nil || !strings.Contains(err.Error(), "--dns wants true or false") {
		t.Fatalf("bad --dns value: %v", err)
	}
}
