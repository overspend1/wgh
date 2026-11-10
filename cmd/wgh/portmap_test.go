package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/overspend1/wgh/internal/agent"
	"github.com/overspend1/wgh/internal/coord"
	"github.com/overspend1/wgh/internal/mesh"
)

func TestPortMapOutput(t *testing.T) {
	var b bytes.Buffer
	printStatus(&b, agent.Status{Name: "laptop", Address: "10.144.0.2", Connected: true, PortMap: "UPnP 203.0.113.5:41820"})
	if !strings.Contains(b.String(), "portmap UPnP 203.0.113.5:41820\n") {
		t.Errorf("status:\n%s", b.String())
	}
	b.Reset()
	printAdmin(&b, coord.Status{URL: "https://x", Devices: []mesh.Node{{Name: "laptop", Address: "10.144.0.2",
		Mapped: "203.0.113.5:41820"}}}, time.Now())
	if !strings.Contains(b.String(), "port mapped 203.0.113.5:41820") {
		t.Errorf("admin devices:\n%s", b.String())
	}
}

func TestUpRejectsBadPortMapFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := agent.Save(path, &agent.State{Name: "laptop", Address: "10.144.0.2", Subnet: "10.144.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	_, err := wgh(t, "up", "--state", path, "--portmap", "maybe", "--dry-run")
	if err == nil || !strings.Contains(err.Error(), "--portmap wants true or false") {
		t.Fatalf("bad --portmap value: %v", err)
	}
}
