package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/overspend1/wgh/internal/acl"
	"github.com/overspend1/wgh/internal/coord"
)

func TestAdminACLCheck(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	os.WriteFile(good, []byte(`{"groups": {"g": []}, "rules": [{"from": ["laptop"], "to": ["group:g"]}]}`), 0o600)
	out := mustWgh(t, "admin", "acl", "check", good, "--dir", dir) // no coordinator runs there
	for _, want := range []string{"is valid: 1 rule(s), 1 group(s)", "device names were not checked", `group "g" is empty`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"rules": [{"from": ["group:nope"], "to": ["*"]}]}`), 0o600)
	if out, err := wgh(t, "admin", "acl", "check", bad, "--dir", dir); err == nil || !strings.Contains(err.Error(), `unknown group "nope"`) {
		t.Fatalf("bad file: %v\n%s", err, out)
	}
	if _, err := wgh(t, "admin", "acl", "check", filepath.Join(dir, "missing.json"), "--dir", dir); err == nil {
		t.Fatal("missing file passed the check")
	}
	if _, err := wgh(t, "admin", "acl", "bogus", "--dir", dir); err == nil {
		t.Fatal("unknown acl subcommand accepted")
	}
}

func TestPrintACL(t *testing.T) {
	var b bytes.Buffer
	printACL(&b, coord.ACLStatus{Path: "/c/acl.json", InUse: true, Rules: 2, RelayFilter: true,
		Warnings: []string{`"ghost" is not a device in the mesh (yet)`},
		Reach:    []acl.Reach{{From: "laptop", To: []string{"nas", "pve1"}}, {From: "nas", To: []string{}}, {From: "pve1", To: []string{"nas"}}}})
	out := b.String()
	for _, want := range []string{"/c/acl.json, in use (2 rule(s)", `"ghost"`, "laptop  everyone", "nas     nobody", "pve1    nas"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	b.Reset()
	printACL(&b, coord.ACLStatus{Path: "/c/acl.json", Error: "bad", Reach: []acl.Reach{{From: "a", To: []string{}}}})
	if !strings.Contains(b.String(), "none (no /c/acl.json)") || !strings.Contains(b.String(), "NOT loaded") {
		t.Errorf("output:\n%s", b.String())
	}
}
