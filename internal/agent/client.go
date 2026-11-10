package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/overspend1/wgh/internal/mesh"
)

// ErrRemoved means the coordinator no longer knows this device.
var ErrRemoved = errors.New("this device was removed from the mesh")

// Client talks to the coordinator.
type Client struct {
	URL    string
	APIKey string
	HTTP   *http.Client
}

// NewClient returns a client that checks the coordinator's certificate
// against pin, or against the system roots when pin is empty.
func NewClient(baseURL, pin, apiKey string) *Client {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: markControl}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
	}
	if pin != "" {
		tr.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			// The certificate is self-signed; trust comes from the pin in
			// the join token instead of a CA.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("coordinator sent no certificate")
				}
				h := sha256.Sum256(cs.PeerCertificates[0].Raw)
				if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(h[:16])), []byte(pin)) != 1 {
					return errors.New("coordinator certificate does not match the pin in the join token")
				}
				return nil
			},
		}
	}
	return &Client{URL: baseURL, APIKey: apiKey, HTTP: &http.Client{Transport: tr}}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.URL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized && c.APIKey != "" {
		return ErrRemoved
	}
	if resp.StatusCode >= 300 {
		var e mesh.ErrorResponse
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("coordinator: %s", resp.Status)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// Join registers a device.
func (c *Client) Join(ctx context.Context, req mesh.JoinRequest) (mesh.JoinResponse, error) {
	var resp mesh.JoinResponse
	return resp, c.do(ctx, "POST", "/v1/join", req, &resp)
}

// Update sends a heartbeat.
func (c *Client) Update(ctx context.Context, req mesh.UpdateRequest) error {
	return c.do(ctx, "POST", "/v1/update", req, nil)
}

// NetMap long-polls for a network map newer than since.
func (c *Client) NetMap(ctx context.Context, since uint64, wait time.Duration) (mesh.NetMap, error) {
	var nm mesh.NetMap
	q := url.Values{"since": {strconv.FormatUint(since, 10)}, "wait": {strconv.Itoa(int(wait / time.Second))}}
	return nm, c.do(ctx, "GET", "/v1/netmap?"+q.Encode(), nil, &nm)
}

// Leave removes this device from the mesh.
func (c *Client) Leave(ctx context.Context) error {
	return c.do(ctx, "POST", "/v1/leave", struct{}{}, nil)
}
