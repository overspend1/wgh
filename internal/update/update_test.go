package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		cur, latest string
		want        bool
	}{
		{"0.1.0", "v0.2.0", true},
		{"v0.2.0", "v0.2.0", false},
		{"0.2.1", "v0.2.0", false},
		{"0.9.9", "v0.10.0", true},
		{"1.0.0", "v0.99.0", false},
		{"dev", "v0.2.0", false},
		{"0.1.0", "garbage", false},
		{"0.1.0-rc1", "v0.1.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.cur, c.latest); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.cur, c.latest, got, c.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	cases := []struct {
		goos, goarch, goarm, want string
	}{
		{"linux", "amd64", "", "wgh-linux-amd64"},
		{"linux", "arm64", "", "wgh-linux-arm64"},
		{"linux", "arm", "7", "wgh-linux-armv7"},
		{"linux", "arm", "6", "wgh-linux-armv6"},
		{"linux", "arm", "", "wgh-linux-armv7"},
		{"linux", "mips", "", "wgh-linux-mips"},
		{"linux", "mipsle", "", "wgh-linux-mipsle"},
		{"darwin", "arm64", "", "wgh-darwin-arm64"},
	}
	for _, c := range cases {
		got, err := AssetName(c.goos, c.goarch, c.goarm)
		if err != nil || got != c.want {
			t.Errorf("AssetName(%s,%s,%s) = %q, %v; want %q", c.goos, c.goarch, c.goarm, got, err, c.want)
		}
	}
	for _, bad := range [][2]string{{"windows", "amd64"}, {"darwin", "mips"}, {"linux", "riscv64"}} {
		if _, err := AssetName(bad[0], bad[1], ""); err == nil {
			t.Errorf("AssetName(%s,%s) succeeded, want error", bad[0], bad[1])
		}
	}
}

// fakeGitHub serves /owner/wgh/releases/latest and the download URLs.
func fakeGitHub(t *testing.T, tag string, assets map[string][]byte, sums string) *Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/o/wgh/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/o/wgh/releases/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc("/o/wgh/releases/download/"+tag+"/", func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		if name == "checksums.txt" {
			fmt.Fprint(w, sums)
			return
		}
		b, ok := assets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, Repo: "o/wgh", HTTP: srv.Client()}
}

func sumLine(name string, b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]) + "  " + name + "\n"
}

func TestLatestAndDownload(t *testing.T) {
	bin := []byte("pretend binary")
	c := fakeGitHub(t, "v0.2.0", map[string][]byte{"wgh-linux-amd64": bin},
		sumLine("wgh-linux-arm64", []byte("other"))+sumLine("wgh-linux-amd64", bin))

	tag, err := c.Latest(context.Background())
	if err != nil || tag != "v0.2.0" {
		t.Fatalf("Latest = %q, %v", tag, err)
	}
	got, err := c.Download(context.Background(), tag, "wgh-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bin) {
		t.Fatalf("Download returned %q", got)
	}
	if _, err := c.Download(context.Background(), tag, "wgh-linux-mips"); err == nil {
		t.Fatal("asset missing from checksums.txt should fail")
	}
}

func TestDownloadRejectsTampered(t *testing.T) {
	c := fakeGitHub(t, "v0.2.0", map[string][]byte{"wgh-linux-amd64": []byte("evil")},
		sumLine("wgh-linux-amd64", []byte("good")))
	_, err := c.Download(context.Background(), "v0.2.0", "wgh-linux-amd64")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v, want checksum mismatch", err)
	}
}

func TestLatestNoReleases(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, Repo: "o/wgh", HTTP: srv.Client()}
	if _, err := c.Latest(context.Background()); err == nil {
		t.Fatal("want error when there is no latest release")
	}
}

func TestReplace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "wgh")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho wgh 0.1.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "wgh-link")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}

	// A binary that reports the wrong version is refused and the old one stays.
	if err := Replace(link, []byte("#!/bin/sh\necho wgh 0.1.5\n"), "v0.2.0"); err == nil {
		t.Fatal("want error for wrong version")
	}
	if b, _ := os.ReadFile(exe); !strings.Contains(string(b), "0.1.0") {
		t.Fatal("old binary was changed after a failed update")
	}

	// A good one replaces the real file behind the symlink.
	if err := Replace(link, []byte("#!/bin/sh\necho wgh 0.2.0\n"), "v0.2.0"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(exe)
	if !strings.Contains(string(b), "0.2.0") {
		t.Fatalf("binary not replaced: %q", b)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced instead of its target")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("temp files left behind: %d entries", len(entries))
	}
}
