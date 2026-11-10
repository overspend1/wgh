// Package update checks GitHub for a newer wgh release and replaces the
// running binary with it, after verifying the download against the
// release's checksums.txt. Nothing here runs unless the user asks for it.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub repository releases come from.
const Repo = "overspend1/wgh"

// maxAsset caps a download so a bad response cannot fill the disk.
const maxAsset = 64 << 20

// Client talks to GitHub's release download URLs. It does not use the GitHub
// API, so it needs no token and is not rate limited.
type Client struct {
	BaseURL string // normally https://github.com
	Repo    string
	HTTP    *http.Client
}

// Default returns a client for the real wgh releases.
func Default() *Client {
	return &Client{
		BaseURL: "https://github.com",
		Repo:    Repo,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

// Latest returns the tag of the newest release, such as "v0.2.0". It reads
// the redirect of /releases/latest instead of calling the API.
func (c *Client) Latest(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.BaseURL+"/"+c.Repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	hc := *c.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("check latest release: %w", err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode/100 != 3 || loc == "" {
		return "", fmt.Errorf("check latest release: unexpected HTTP %d (no releases yet?)", resp.StatusCode)
	}
	i := strings.LastIndex(loc, "/tag/")
	if i < 0 {
		return "", fmt.Errorf("check latest release: unexpected redirect to %q", loc)
	}
	tag := loc[i+len("/tag/"):]
	if _, ok := parseVersion(tag); !ok {
		return "", fmt.Errorf("check latest release: %q is not a version tag", tag)
	}
	return tag, nil
}

// Download fetches asset from release tag and checks it against the
// release's checksums.txt. It returns the verified bytes.
func (c *Client) Download(ctx context.Context, tag, asset string) ([]byte, error) {
	base := c.BaseURL + "/" + c.Repo + "/releases/download/" + tag + "/"
	sums, err := c.get(ctx, base+"checksums.txt", 1<<20)
	if err != nil {
		return nil, err
	}
	want, err := checksumFor(sums, asset)
	if err != nil {
		return nil, err
	}
	data, err := c.get(ctx, base+asset, maxAsset)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("checksum mismatch for %s: want %s, got %s", asset, want, got)
	}
	return data, nil
}

func (c *Client) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("download %s: larger than %d bytes", url, limit)
	}
	return b, nil
}

// checksumFor finds asset's hash in a sha256sum-format file.
func checksumFor(sums []byte, asset string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == asset {
			if len(f[0]) != 64 {
				return "", fmt.Errorf("bad checksum line for %s", asset)
			}
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("no checksum for %s in checksums.txt", asset)
}

// AssetName returns the release asset for a platform, e.g. wgh-linux-armv7.
func AssetName(goos, goarch, goarm string) (string, error) {
	switch goos {
	case "linux", "darwin":
	default:
		return "", fmt.Errorf("no release builds for %s", goos)
	}
	arch := goarch
	switch goarch {
	case "amd64", "arm64":
	case "mips", "mipsle":
		if goos != "linux" {
			return "", fmt.Errorf("no release builds for %s/%s", goos, goarch)
		}
	case "arm":
		if goos != "linux" {
			return "", fmt.Errorf("no release builds for %s/%s", goos, goarch)
		}
		arch = "armv7"
		if strings.HasPrefix(goarm, "5") || strings.HasPrefix(goarm, "6") {
			arch = "armv6"
		}
	default:
		return "", fmt.Errorf("no release builds for %s/%s", goos, goarch)
	}
	return "wgh-" + goos + "-" + arch, nil
}

// CurrentAsset is AssetName for the running binary.
func CurrentAsset() (string, error) {
	goarm := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "GOARM" {
				goarm = s.Value
			}
		}
	}
	return AssetName(runtime.GOOS, runtime.GOARCH, goarm)
}

// Newer reports whether latest is a higher version than current. A current
// version that is not a release (such as "dev") never counts as older.
func Newer(current, latest string) bool {
	c, ok1 := parseVersion(current)
	l, ok2 := parseVersion(latest)
	if !ok1 || !ok2 {
		return false
	}
	for i := range c {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// IsRelease reports whether v looks like a release version (0.1.0 or v0.1.0).
func IsRelease(v string) bool {
	_, ok := parseVersion(v)
	return ok
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Replace swaps the binary at exe for data. It writes a temp file next to the
// real (symlink-resolved) path, checks that it runs and reports wantVersion,
// then renames it into place, so a failed update leaves the old binary alone.
func Replace(exe string, data []byte, wantVersion string) error {
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("find current binary: %w", err)
	}
	dir := filepath.Dir(real)
	tmp, err := os.CreateTemp(dir, ".wgh-update-*")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("cannot write to %s; run 'wgh update' as a user who can, or reinstall with the install script", dir)
		}
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write new binary: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod new binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close new binary: %w", err)
	}
	if wantVersion != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, tmpName, "version").Output()
		if err != nil {
			return fmt.Errorf("new binary does not run on this machine: %w", err)
		}
		if !strings.Contains(string(out), strings.TrimPrefix(wantVersion, "v")) {
			return fmt.Errorf("new binary reports %q, expected %s", strings.TrimSpace(string(out)), wantVersion)
		}
	}
	if err := os.Rename(tmpName, real); err != nil {
		return fmt.Errorf("replace %s: %w", real, err)
	}
	return nil
}
