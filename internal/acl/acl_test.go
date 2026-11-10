package acl

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const example = `{
  "groups": {"servers": ["pve1", "nas"], "admins": ["laptop"]},
  "rules": [
    {"from": ["group:admins"], "to": ["*"]},
    {"from": ["*"], "to": ["nas"]},
    {"from": ["pve1"], "to": ["group:servers"]}
  ]
}`

func TestAllows(t *testing.T) {
	p, err := Parse([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if p.IsAllowAll() {
		t.Fatal("parsed policy reports allow-all")
	}
	for _, c := range []struct {
		from, to string
		want     bool
	}{
		{"laptop", "pve1", true},  // admins reach everything
		{"laptop", "phone", true}, // including devices not named anywhere
		{"phone", "nas", true},    // everyone reaches nas
		{"phone", "pve1", false},
		{"pve1", "laptop", false}, // rules are one-way
		{"pve1", "nas", true},
		{"nas", "pve1", false},
		{"phone", "phone", true}, // a device always reaches itself
		{"stranger", "nas", true},
	} {
		if got := p.Allows(c.from, c.to); got != c.want {
			t.Errorf("Allows(%s, %s) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
	reach := p.Reach([]string{"laptop", "pve1", "nas", "phone"})
	want := []Reach{
		{"laptop", []string{"pve1", "nas", "phone"}},
		{"pve1", []string{"nas"}},
		{"nas", []string{}},
		{"phone", []string{"nas"}},
	}
	for i := range want {
		if reach[i].From != want[i].From || !slices.Equal(reach[i].To, want[i].To) {
			t.Errorf("reach[%d] = %+v, want %+v", i, reach[i], want[i])
		}
	}
	if p.Groups() != 2 || p.Rules() != 3 {
		t.Errorf("groups %d rules %d", p.Groups(), p.Rules())
	}
}

func TestAllowAll(t *testing.T) {
	for _, p := range []*Policy{AllowAll(), nil, {}} {
		if !p.IsAllowAll() || !p.Allows("a", "b") || p.Warnings([]string{"a"}) != nil {
			t.Errorf("%#v is not allow-all", p)
		}
	}
	if r := AllowAll().Reach([]string{"a", "b"}); !slices.Equal(r[0].To, []string{"b"}) {
		t.Errorf("reach = %+v", r)
	}
}

func TestEmptyRulesBlockEverything(t *testing.T) {
	p, err := Parse([]byte(`{"rules": []}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Allows("a", "b") {
		t.Error("empty rule list allowed a connection")
	}
	if w := p.Warnings(nil); len(w) != 1 || !strings.Contains(w[0], "no rules") {
		t.Errorf("warnings = %q", w)
	}
}

func TestParseErrors(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{``, "empty policy"},
		{`{}`, `no "rules"`},
		{`{"rules": [], "extra": 1}`, `unknown field "extra"`},
		{`{"rules": [{"from": ["*"], "to": ["*"], "ports": [22]}]}`, `unknown field "ports"`},
		{`{"rules": [{"from": ["group:nope"], "to": ["*"]}]}`, `unknown group "nope"`},
		{`{"rules": [{"from": ["Laptop"], "to": ["*"]}]}`, `invalid device name "Laptop"`},
		{`{"rules": [{"from": ["*"], "to": ["a b"]}]}`, `invalid device name "a b"`},
		{`{"rules": [{"from": [], "to": ["*"]}]}`, `rule 1: "from" is empty`},
		{`{"rules": [{"from": ["*"]}]}`, `rule 1: "to" is empty`},
		{`{"groups": {"Bad": ["a"]}, "rules": []}`, `bad group name`},
		{`{"groups": {"g": ["group:h"]}, "rules": []}`, `device names only`},
		{`{"groups": {"g": ["*"]}, "rules": []}`, `device names only`},
		{`{"groups": {"g": ["-x"]}, "rules": []}`, `invalid device name`},
		{`{"rules": []} {"rules": []}`, `unexpected data`},
		{`{"rules": {}}`, `cannot unmarshal`},
	} {
		_, err := Parse([]byte(c.in))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Parse(%s) = %v, want an error containing %q", c.in, err, c.want)
		}
	}
}

func TestWarnings(t *testing.T) {
	p, err := Parse([]byte(`{"groups": {"servers": ["pve1", "nas"], "empty": []},
		"rules": [{"from": ["laptop"], "to": ["group:servers", "group:empty"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	got := p.Warnings([]string{"laptop", "pve1"})
	want := []string{`"nas" is not a device in the mesh (yet)`, `group "empty" is empty`}
	if !slices.Equal(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := ParseFile(filepath.Join(dir, FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	path := filepath.Join(dir, FileName)
	os.WriteFile(path, []byte(`{"rules": [{"from": ["*"], "to": ["nope!"]}]}`), 0o600)
	if _, err := ParseFile(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("bad file: %v", err)
	}
	os.WriteFile(path, []byte(example), 0o600)
	if p, err := ParseFile(path); err != nil || p.IsAllowAll() {
		t.Fatalf("good file: %v", err)
	}
}
