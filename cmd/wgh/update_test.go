package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/overspend1/wgh/internal/update"
)

func fakeRelease(t *testing.T, tag string, newBin []byte) *update.Client {
	t.Helper()
	asset, err := update.CurrentAsset()
	if err != nil {
		t.Skip(err)
	}
	sum := sha256.Sum256(newBin)
	mux := http.NewServeMux()
	mux.HandleFunc("/o/wgh/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/o/wgh/releases/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc("/o/wgh/releases/download/"+tag+"/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
	})
	mux.HandleFunc("/o/wgh/releases/download/"+tag+"/"+asset, func(w http.ResponseWriter, r *http.Request) {
		w.Write(newBin)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &update.Client{BaseURL: srv.URL, Repo: "o/wgh", HTTP: srv.Client()}
}

func TestUpdateCommand(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	dir := t.TempDir()
	exe := filepath.Join(dir, "wgh")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho wgh 0.1.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	exeFn := func() (string, error) { return exe, nil }
	c := fakeRelease(t, "v0.2.0", []byte("#!/bin/sh\necho wgh 0.2.0\n"))

	runUpdate := func(args ...string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if err := cmdUpdate(args, &out, &errOut, c, exeFn); err != nil {
			t.Fatalf("update %v: %v\n%s", args, err, errOut.String())
		}
		return out.String()
	}

	version = "dev"
	if out := runUpdate(); !strings.Contains(out, "dev build") {
		t.Errorf("dev build should not self-update without --force: %q", out)
	}

	version = "0.1.0"
	if out := runUpdate("--check"); !strings.Contains(out, "v0.2.0 is available") {
		t.Errorf("--check output: %q", out)
	}
	if b, _ := os.ReadFile(exe); !strings.Contains(string(b), "0.1.0") {
		t.Fatal("--check must not change the binary")
	}

	if out := runUpdate(); !strings.Contains(out, "Updated wgh 0.1.0 -> 0.2.0") {
		t.Errorf("update output: %q", out)
	}
	if b, _ := os.ReadFile(exe); !strings.Contains(string(b), "0.2.0") {
		t.Fatal("binary was not replaced")
	}

	version = "0.2.0"
	if out := runUpdate(); !strings.Contains(out, "up to date") {
		t.Errorf("up to date output: %q", out)
	}
}
