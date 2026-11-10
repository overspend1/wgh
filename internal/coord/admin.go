package coord

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/overspend1/wgh/internal/mesh"
)

// Admin talks to a running coordinator over its local admin socket.
type Admin struct {
	HTTP *http.Client
}

// NewAdmin returns a client for the admin socket at path.
func NewAdmin(path string) *Admin {
	return &Admin{HTTP: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
	}}}
}

func (a *Admin) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://wgh"+path, body)
	if err != nil {
		return err
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach the coordinator's admin socket (is 'wgh serve' running here, and are you the same user or root?): %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		var e mesh.ErrorResponse
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("coordinator: %s", resp.Status)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// Status lists the mesh.
func (a *Admin) Status() (Status, error) {
	var s Status
	return s, a.do("GET", "/admin/status", nil, &s)
}

// Token makes a join token.
func (a *Admin) Token(req TokenRequest) (string, error) {
	var out struct{ Token string }
	return out.Token, a.do("POST", "/admin/token", req, &out)
}

// Remove removes a device.
func (a *Admin) Remove(name string) error {
	return a.do("POST", "/admin/remove", NameRequest{Name: name}, nil)
}

// Approve approves a device's advertised routes and exit node.
func (a *Admin) Approve(name string) (routes []string, exit bool, err error) {
	var out struct {
		Routes []string
		Exit   bool
	}
	err = a.do("POST", "/admin/approve", NameRequest{Name: name}, &out)
	return out.Routes, out.Exit, err
}

// AddPhone adds a plain WireGuard device and returns its config.
func (a *Admin) AddPhone(name string, exit bool) (string, error) {
	var out struct{ Config string }
	return out.Config, a.do("POST", "/admin/phone", NameRequest{Name: name, Exit: exit}, &out)
}

// PhoneConfig returns the config of an existing plain WireGuard device.
func (a *Admin) PhoneConfig(name string) (string, error) {
	var out struct{ Config string }
	return out.Config, a.do("POST", "/admin/phone-config", NameRequest{Name: name}, &out)
}
