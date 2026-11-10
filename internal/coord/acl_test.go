package coord

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/overspend1/wgh/internal/keys"
	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/wgctl"
)

const testPolicy = `{
  "groups": {"servers": ["pve1", "nas"], "admins": ["laptop"]},
  "rules": [
    {"from": ["group:admins"], "to": ["*"]},
    {"from": ["*"], "to": ["nas"]}
  ]
}`

type aclRig struct {
	t     *testing.T
	srv   *Server
	relay *wgctl.Fake
	keys  map[string]string // device name -> API key
	logs  []string
}

func newACLRig(t *testing.T, policy string) *aclRig {
	t.Helper()
	dir := t.TempDir()
	if policy != "" {
		if err := os.WriteFile(filepath.Join(dir, "acl.json"), []byte(policy), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := &aclRig{t: t, relay: wgctl.NewFake(nil, nil, ""), keys: map[string]string{}}
	srv, err := New(Options{Dir: dir, Endpoint: "relay.example", PlainHTTP: true, URL: "http://127.0.0.1:1",
		Backend: r.relay, Logf: func(f string, a ...any) { r.logs = append(r.logs, f) }})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = srv
	return r
}

// join adds a device; routes and exit are advertised and approved.
func (r *aclRig) join(name string, routes []string, exit bool) {
	r.t.Helper()
	tok, err := r.srv.NewToken(time.Hour, false, false)
	if err != nil {
		r.t.Fatal(err)
	}
	kp, _ := keys.NewPair()
	resp, err := r.srv.Join(mesh.JoinRequest{Token: tok, Name: name, PublicKey: kp.Public}, "")
	if err != nil {
		r.t.Fatal(err)
	}
	r.keys[name] = resp.APIKey
	if len(routes) > 0 || exit {
		if err := r.srv.Update(resp.APIKey, mesh.UpdateRequest{Routes: routes, Exit: exit}, ""); err != nil {
			r.t.Fatal(err)
		}
		if _, _, err := r.srv.Approve(name); err != nil {
			r.t.Fatal(err)
		}
	}
}

func (r *aclRig) netmap(name string) mesh.NetMap {
	r.t.Helper()
	nm, _, err := r.srv.NetMap(r.keys[name])
	if err != nil {
		r.t.Fatal(err)
	}
	return nm
}

// view is a compact picture of a netmap: each peer's name, with "<" when it
// may connect in, and its routes and exit flag.
func view(nm mesh.NetMap) string {
	var parts []string
	for _, p := range nm.Peers {
		s := p.Name
		if p.CanConnect {
			s += "<"
		}
		if len(p.Routes) > 0 {
			s += "[" + strings.Join(p.Routes, ",") + "]"
		}
		if p.Exit {
			s += "!"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func addr(r *aclRig, name string) string {
	for _, d := range r.srv.Status().Devices {
		if d.Name == name {
			return d.Address + "/32"
		}
	}
	r.t.Fatalf("no device %s", name)
	return ""
}

func TestACLNetMap(t *testing.T) {
	r := newACLRig(t, testPolicy)
	r.join("laptop", nil, false)
	r.join("pve1", []string{"192.168.50.0/24"}, true)
	r.join("nas", nil, false)
	if _, err := r.srv.AddStatic("phone", false); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		// laptop reaches everyone; nobody but nas is reached back.
		"laptop": "pve1[192.168.50.0/24]! nas phone",
		// pve1 is reached by laptop and reaches only nas.
		"pve1": "laptop< nas",
		// Everyone reaches nas; nas reaches nobody, so pve1 shows it no
		// routes and is no exit node for it.
		"nas": "laptop< pve1< phone<",
	} {
		nm := r.netmap(name)
		if !nm.ACL {
			t.Errorf("%s: ACL not set", name)
		}
		if got := view(nm); got != want {
			t.Errorf("%s sees %q, want %q", name, got, want)
		}
	}

	// The relay forwards only allowed pairs, LAN routes included.
	laptop, pve1, nas, phone := addr(r, "laptop"), addr(r, "pve1"), addr(r, "nas"), addr(r, "phone")
	want := []wgctl.FilterRule{
		{Src: laptop, Dst: pve1}, {Src: laptop, Dst: "192.168.50.0/24"},
		{Src: laptop, Dst: nas}, {Src: laptop, Dst: phone},
		{Src: pve1, Dst: nas}, {Src: "192.168.50.0/24", Dst: nas},
		{Src: phone, Dst: nas},
	}
	if got := r.srv.RelayFilter(); !slices.Equal(got, want) {
		t.Fatalf("relay filter:\n%v\nwant:\n%v", got, want)
	}
	if err := r.srv.syncRelay(); err != nil {
		t.Fatal(err)
	}
	snap := r.relay.Snapshot()
	if !snap.Filter || snap.FilterScope != wgctl.FilterRelayed || !slices.Equal(snap.FilterRules, want) {
		t.Fatalf("relay fake: %+v", snap)
	}
	if len(snap.Peers) != 4 {
		t.Errorf("relay has %d peers, want every device", len(snap.Peers))
	}

	st := r.srv.ACLStatus()
	if !st.InUse || st.Rules != 2 || st.Groups != 2 || !st.RelayFilter || st.Error != "" {
		t.Errorf("acl status: %+v", st)
	}
	if len(st.Warnings) != 0 {
		t.Errorf("warnings: %q", st.Warnings)
	}
	if len(st.Reach) != 4 || st.Reach[0].From != "laptop" || len(st.Reach[0].To) != 3 || len(st.Reach[2].To) != 0 {
		t.Errorf("reach: %+v", st.Reach)
	}
}

func TestACLNoFileAllowsAll(t *testing.T) {
	r := newACLRig(t, "")
	r.join("laptop", nil, false)
	r.join("pve1", []string{"192.168.50.0/24"}, true)
	nm := r.netmap("laptop")
	if nm.ACL || view(nm) != "pve1<[192.168.50.0/24]!" {
		t.Fatalf("laptop sees %q (acl %v)", view(nm), nm.ACL)
	}
	if f := r.srv.RelayFilter(); f != nil {
		t.Fatalf("relay filter without a policy: %v", f)
	}
	if err := r.srv.syncRelay(); err != nil {
		t.Fatal(err)
	}
	if r.relay.Snapshot().Filter {
		t.Error("relay filters without a policy")
	}
	if st := r.srv.ACLStatus(); st.InUse || st.RelayFilter || len(st.Reach) != 2 {
		t.Errorf("acl status: %+v", st)
	}
}

func TestACLInvalidAtStart(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "acl.json"), []byte(`{"rules": [{"from": ["group:x"], "to": ["*"]}]}`), 0o600)
	_, err := New(Options{Dir: dir, Endpoint: "relay.example", PlainHTTP: true, Backend: wgctl.NewFake(nil, nil, "")})
	if err == nil || !strings.Contains(err.Error(), `unknown group "x"`) {
		t.Fatalf("New with a bad policy: %v", err)
	}
}

func TestACLHotReload(t *testing.T) {
	r := newACLRig(t, "")
	r.join("laptop", nil, false)
	r.join("nas", nil, false)
	path := r.srv.ACLPath()
	stamp := time.Now()
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		stamp = stamp.Add(time.Second) // a new mtime even on coarse clocks
		os.Chtimes(path, stamp, stamp)
	}
	v0 := r.netmap("laptop").Version

	// A new file takes effect on the next sweep, and devices are woken.
	write(`{"rules": [{"from": ["laptop"], "to": ["nas"]}, {"from": ["laptop"], "to": ["ghost"]}]}`)
	r.srv.Sweep()
	nm := r.netmap("nas")
	if !nm.ACL || view(nm) != "laptop<" || nm.Version == v0 {
		t.Fatalf("after reload nas sees %q (acl %v, version %d -> %d)", view(nm), nm.ACL, v0, nm.Version)
	}
	if view(r.netmap("laptop")) != "nas" {
		t.Fatalf("laptop sees %q", view(r.netmap("laptop")))
	}
	if w := r.srv.ACLStatus().Warnings; len(w) != 1 || !strings.Contains(w[0], `"ghost"`) {
		t.Errorf("warnings: %q", w)
	}
	if err := r.srv.syncRelay(); err != nil {
		t.Fatal(err)
	}
	if got := r.relay.Snapshot().FilterRules; len(got) != 1 {
		t.Fatalf("relay filter after reload: %v", got)
	}

	// Nothing changed: no new version.
	v1 := r.netmap("nas").Version
	r.srv.Sweep()
	if r.netmap("nas").Version != v1 {
		t.Error("sweep without a change bumped the version")
	}

	// An invalid file is ignored and the old policy stays.
	write(`{"rules": [{"from": ["laptop"], "to": ["nas"]}], "typo": true}`)
	r.srv.Sweep()
	if nm := r.netmap("nas"); view(nm) != "laptop<" || nm.Version != v1 {
		t.Fatalf("invalid file changed the map: %q", view(nm))
	}
	st := r.srv.ACLStatus()
	if !st.InUse || !strings.Contains(st.Error, `unknown field "typo"`) {
		t.Fatalf("status after a bad file: %+v", st)
	}
	if !slices.ContainsFunc(r.logs, func(s string) bool { return strings.Contains(s, "not reloaded") }) {
		t.Errorf("bad file not logged: %q", r.logs)
	}

	// Fixing it loads it and clears the error.
	write(`{"rules": [{"from": ["*"], "to": ["*"]}]}`)
	r.srv.Sweep()
	if nm := r.netmap("nas"); view(nm) != "laptop<" || !nm.ACL || r.srv.ACLStatus().Error != "" {
		t.Fatalf("after fix: %q %+v", view(nm), r.srv.ACLStatus())
	}
	if view(r.netmap("laptop")) != "nas<" {
		t.Fatalf("laptop sees %q", view(r.netmap("laptop")))
	}

	// Removing the file goes back to allow-all with no filter anywhere.
	os.Remove(path)
	r.srv.Sweep()
	if nm := r.netmap("laptop"); nm.ACL || view(nm) != "nas<" {
		t.Fatalf("after removal: %q acl %v", view(nm), nm.ACL)
	}
	if err := r.srv.syncRelay(); err != nil {
		t.Fatal(err)
	}
	if r.relay.Snapshot().Filter {
		t.Error("relay still filters after the policy was removed")
	}
}
