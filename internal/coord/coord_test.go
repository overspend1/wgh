package coord_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/overspend1/wgh/internal/agent"
	"github.com/overspend1/wgh/internal/coord"
	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/wgctl"
)

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// TestServeOverTLSAndAdminSocket runs the real server: TLS with a pinned
// self-signed certificate, the admin socket, and a device joining.
func TestServeOverTLSAndAdminSocket(t *testing.T) {
	dir := t.TempDir()
	addr := freePort(t)
	relay := wgctl.NewFake(nil, nil, "")
	srv, err := coord.New(coord.Options{Dir: dir, Listen: addr, Endpoint: "127.0.0.1", Backend: relay})
	if err != nil {
		t.Fatal(err)
	}
	if srv.Pin() == "" || !strings.HasPrefix(srv.URL(), "https://127.0.0.1:") {
		t.Fatalf("url %q pin %q", srv.URL(), srv.Pin())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		if relay.Snapshot().Up {
			t.Error("relay interface left up")
		}
	}()
	adm := coord.NewAdmin(srv.AdminSocket())
	var tok string
	deadline := time.Now().Add(5 * time.Second)
	for {
		tok, err = adm.Token(coord.TokenRequest{TTL: "10m"})
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(srv.AdminSocket())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("admin socket mode: %v %v", fi, err)
	}
	if !relay.Snapshot().Up || !relay.Snapshot().Forward {
		t.Fatalf("relay not set up: %+v", relay.Snapshot())
	}

	// A token whose pin doesn't match is refused before anything is sent.
	tk, _ := mesh.ParseToken(tok)
	bad := mesh.Token{URL: tk.URL, Pin: "AAAAAAAAAAAAAAAAAAAAAA", Secret: tk.Secret}.Encode()
	if _, err := agent.Join(context.Background(), filepath.Join(dir, "bad.json"), agent.JoinOptions{Token: bad, Name: "evil"}); err == nil ||
		!strings.Contains(err.Error(), "does not match the pin") {
		t.Fatalf("join with wrong pin: %v", err)
	}

	st, err := agent.Join(context.Background(), filepath.Join(dir, "dev", "agent.json"), agent.JoinOptions{Token: tok, Name: "laptop", Routes: []string{"192.168.1.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Address != "10.144.0.2" || st.Subnet != "10.144.0.0/16" {
		t.Fatalf("joined state: %+v", st)
	}
	status, err := adm.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Devices) != 1 || status.Devices[0].Name != "laptop" || status.Relay == nil {
		t.Fatalf("status: %+v", status)
	}
	if acl, err := adm.ACL(); err != nil || acl.InUse || acl.Path != filepath.Join(dir, "acl.json") ||
		len(acl.Reach) != 1 || acl.Reach[0].From != "laptop" {
		t.Fatalf("acl over the admin socket: %+v %v", acl, err)
	}
	if conf, err := adm.AddPhone("phone", false); err != nil || !strings.Contains(conf, "AllowedIPs = 10.144.0.0/16") {
		t.Fatalf("phone: %v\n%s", err, conf)
	}
	if _, err := adm.AddPhone("phone", false); err == nil {
		t.Error("duplicate phone accepted")
	}
	if err := adm.Remove("phone"); err != nil {
		t.Fatal(err)
	}
	if err := adm.Remove("phone"); err == nil {
		t.Error("removing twice succeeded")
	}
	// The coordinator state file never holds a device private key or API key.
	b, _ := os.ReadFile(filepath.Join(dir, "coordinator.json"))
	ast, _ := agent.Load(filepath.Join(dir, "dev", "agent.json"))
	if strings.Contains(string(b), ast.PrivateKey) || strings.Contains(string(b), ast.APIKey) {
		t.Fatal("coordinator stored a device secret")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "coordinator.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("coordinator.json mode %o", fi.Mode().Perm())
	}
}

func TestNewNeedsEndpoint(t *testing.T) {
	if _, err := coord.New(coord.Options{Dir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "--endpoint") {
		t.Fatalf("err = %v", err)
	}
}
