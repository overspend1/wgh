// Package acl is the mesh access policy: which devices may open connections
// to which. The coordinator reads it from acl.json in its state directory.
// With no file every device reaches every other one.
//
//	{
//	  "groups": {"servers": ["pve1", "nas"], "admins": ["laptop"]},
//	  "rules": [
//	    {"from": ["group:admins"], "to": ["*"]},
//	    {"from": ["*"], "to": ["nas"]}
//	  ]
//	}
//
// An entry is a device name, "group:NAME" or "*". A rule lets its from
// devices open connections to its to devices, including the LAN routes those
// devices share and their use as an exit node. Replies always flow back.
package acl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/overspend1/wgh/internal/mesh"
)

// FileName is the policy file's name in the coordinator directory.
const FileName = "acl.json"

// File is the JSON layout of acl.json.
type File struct {
	Groups map[string][]string `json:"groups,omitempty"`
	Rules  []Rule              `json:"rules"`
}

// Rule lets the From devices open connections to the To devices.
type Rule struct {
	From []string `json:"from"`
	To   []string `json:"to"`
}

// set is a parsed rule side: everyone, or a set of device names.
type set struct {
	all   bool
	names map[string]bool
}

func (s set) has(name string) bool { return s.all || s.names[name] }

// Policy is a parsed, validated access policy. The zero value and AllowAll
// allow everything.
type Policy struct {
	restricted bool
	file       File
	rules      [][2]set
	named      []string // device names the file mentions, sorted
}

// AllowAll is the default policy: every device reaches every other one.
func AllowAll() *Policy { return &Policy{} }

// IsAllowAll reports whether p is the default allow-everything policy, which
// needs no filtering anywhere.
func (p *Policy) IsAllowAll() bool { return p == nil || !p.restricted }

// Parse reads and validates a policy. Unknown fields, unknown groups and bad
// names are errors; device names not in the mesh are not (see Warnings).
func Parse(b []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty policy: write {\"rules\": [...]}, or delete the file to let every device reach every other one")
		}
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the policy object")
	}
	if f.Rules == nil {
		return nil, errors.New(`no "rules" list: add one (an empty list blocks everything)`)
	}
	p := &Policy{restricted: true, file: f}
	named := map[string]bool{}
	groups := map[string]map[string]bool{}
	for g, members := range f.Groups {
		if err := mesh.ValidName(g); err != nil {
			return nil, fmt.Errorf("group %q: bad group name: use lowercase letters, digits and '-'", g)
		}
		m := map[string]bool{}
		for _, d := range members {
			if strings.HasPrefix(d, "group:") || d == "*" {
				return nil, fmt.Errorf("group %q: %q: groups hold device names only", g, d)
			}
			if err := mesh.ValidName(d); err != nil {
				return nil, fmt.Errorf("group %q: %w", g, err)
			}
			m[d], named[d] = true, true
		}
		groups[g] = m
	}
	side := func(i int, what string, entries []string) (set, error) {
		if len(entries) == 0 {
			return set{}, fmt.Errorf("rule %d: %q is empty", i+1, what)
		}
		s := set{names: map[string]bool{}}
		for _, e := range entries {
			switch {
			case e == "*":
				s.all = true
			case strings.HasPrefix(e, "group:"):
				g := strings.TrimPrefix(e, "group:")
				m, ok := groups[g]
				if !ok {
					return set{}, fmt.Errorf("rule %d: %s: unknown group %q", i+1, what, g)
				}
				for d := range m {
					s.names[d] = true
				}
			default:
				if err := mesh.ValidName(e); err != nil {
					return set{}, fmt.Errorf("rule %d: %s: %w", i+1, what, err)
				}
				s.names[e], named[e] = true, true
			}
		}
		return s, nil
	}
	for i, r := range f.Rules {
		from, err := side(i, "from", r.From)
		if err != nil {
			return nil, err
		}
		to, err := side(i, "to", r.To)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, [2]set{from, to})
	}
	for n := range named {
		p.named = append(p.named, n)
	}
	sort.Strings(p.named)
	return p, nil
}

// ParseFile reads and validates the policy at path. A missing file returns
// an error matching os.ErrNotExist.
func ParseFile(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Allows reports whether device from may open connections to device to. A
// device always reaches itself.
func (p *Policy) Allows(from, to string) bool {
	if p.IsAllowAll() || from == to {
		return true
	}
	for _, r := range p.rules {
		if r[0].has(from) && r[1].has(to) {
			return true
		}
	}
	return false
}

// Groups and Rules count what the file holds.
func (p *Policy) Groups() int { return len(p.file.Groups) }

// Rules is the number of rules.
func (p *Policy) Rules() int { return len(p.file.Rules) }

// Warnings lists things in the policy that are valid but probably not what
// was meant, given the devices now in the mesh. With devices nil (not
// known) names are not checked.
func (p *Policy) Warnings(devices []string) []string {
	if p.IsAllowAll() {
		return nil
	}
	var out []string
	if len(p.rules) == 0 {
		out = append(out, "there are no rules: no device can reach another")
	}
	known := map[string]bool{}
	for _, d := range devices {
		known[d] = true
	}
	for _, n := range p.named {
		if devices != nil && !known[n] {
			out = append(out, fmt.Sprintf("%q is not a device in the mesh (yet)", n))
		}
	}
	var empty []string
	for g, m := range p.file.Groups {
		if len(m) == 0 {
			empty = append(empty, g)
		}
	}
	sort.Strings(empty)
	for _, g := range empty {
		out = append(out, fmt.Sprintf("group %q is empty", g))
	}
	return out
}

// Reach is who one device may open connections to.
type Reach struct {
	From string   `json:"from"`
	To   []string `json:"to"`
}

// Reach lists, for each device in order, the other devices it may reach.
func (p *Policy) Reach(devices []string) []Reach {
	out := make([]Reach, 0, len(devices))
	for _, a := range devices {
		r := Reach{From: a, To: []string{}}
		for _, b := range devices {
			if a != b && p.Allows(a, b) {
				r.To = append(r.To, b)
			}
		}
		out = append(out, r)
	}
	return out
}
