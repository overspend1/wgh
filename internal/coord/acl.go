package coord

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/overspend1/wgh/internal/acl"
	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/wgctl"
)

// aclState is the access policy in use and what was done with it.
type aclState struct {
	path   string
	policy *acl.Policy
	stamp  fileStamp
	err    string // why the file on disk is not the policy in use

	filter    []wgctl.FilterRule // relay filter last applied
	filterSet bool
	warned    bool // told the log the relay backend can't filter
}

// fileStamp tells whether acl.json changed since it was last read.
type fileStamp struct {
	exists bool
	mod    time.Time
	size   int64
}

func stampOf(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileStamp{}, nil
	}
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{exists: true, mod: fi.ModTime(), size: fi.Size()}, nil
}

func readPolicy(path string, st fileStamp) (*acl.Policy, error) {
	if !st.exists {
		return acl.AllowAll(), nil
	}
	return acl.ParseFile(path)
}

// ACLPath is where the coordinator reads its access policy.
func (s *Server) ACLPath() string { return filepath.Join(s.o.Dir, acl.FileName) }

// loadACL reads the policy at start. An invalid file stops the start: falling
// back to allow-all could open what the file meant to close.
func (s *Server) loadACL() error {
	s.acl.path = s.ACLPath()
	st, err := stampOf(s.acl.path)
	if err != nil {
		return fmt.Errorf("access policy: %w", err)
	}
	p, err := readPolicy(s.acl.path, st)
	if err != nil {
		return fmt.Errorf("access policy: %w (fix it, or move it away to let every device reach every other one)", err)
	}
	s.acl.policy, s.acl.stamp = p, st
	if !p.IsAllowAll() {
		s.o.Logf("access policy %s: %d rule(s)", s.acl.path, p.Rules())
		for _, w := range p.Warnings(s.deviceNamesLocked()) {
			s.o.Logf("access policy: warning: %s", w)
		}
	}
	return nil
}

// checkACL reloads acl.json when its modification time or size changed.
// An invalid new file is logged and the old policy stays in use.
func (s *Server) checkACL() {
	s.mu.Lock()
	path, old := s.acl.path, s.acl.stamp
	s.mu.Unlock()
	if path == "" {
		return
	}
	st, err := stampOf(path)
	if err == nil && st == old {
		return
	}
	var p *acl.Policy
	if err == nil {
		p, err = readPolicy(path, st)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acl.stamp = st
	if err != nil {
		s.acl.err = err.Error()
		s.o.Logf("access policy not reloaded, the previous one stays in use: %v", err)
		return
	}
	s.acl.err = ""
	s.acl.policy = p
	if p.IsAllowAll() {
		s.o.Logf("access policy %s removed: every device can reach every other one", path)
	} else {
		s.o.Logf("access policy %s reloaded: %d rule(s)", path, p.Rules())
		for _, w := range p.Warnings(s.deviceNamesLocked()) {
			s.o.Logf("access policy: warning: %s", w)
		}
	}
	s.bumpLocked()
}

func (s *Server) policyLocked() *acl.Policy {
	if s.acl.policy == nil {
		return acl.AllowAll()
	}
	return s.acl.policy
}

func (s *Server) deviceNamesLocked() []string {
	names := make([]string, 0, len(s.st.Devices))
	for _, d := range s.st.Devices {
		names = append(names, d.Name)
	}
	return names
}

// peerViewLocked is o as viewer sees it, and whether viewer sees it at all:
// only when one of them may reach the other. A peer viewer may not reach
// shows no routes and is no exit node for it.
func (s *Server) peerViewLocked(o, viewer *device) (mesh.Node, bool) {
	p := s.policyLocked()
	out, in := p.Allows(viewer.Name, o.Name), p.Allows(o.Name, viewer.Name)
	if !out && !in {
		return mesh.Node{}, false
	}
	n := s.nodeLocked(o, viewer)
	n.CanConnect = in
	if !out {
		n.Routes, n.Exit = nil, false
	}
	return n, true
}

// prefixes are the addresses a device answers for: its own, IPv4 and IPv6,
// and the LAN routes it shares.
func prefixes(d *device) []string {
	out := []string{d.Address + "/32"}
	if a6 := mesh.Addr6(d.Address); a6 != "" {
		out = append(out, a6+"/128")
	}
	return append(out, d.ApprovedRoutes...)
}

// sameFamily reports whether two prefixes are both IPv4 or both IPv6: a
// rule from one family to the other could never match.
func sameFamily(a, b string) bool {
	return strings.Contains(a, ":") == strings.Contains(b, ":")
}

// relayFilterLocked is the relay's forwarding filter: for every pair the
// policy allows, the source device's addresses may open connections to the
// destination's. nil (no filter) for the default allow-all policy.
func (s *Server) relayFilterLocked() []wgctl.FilterRule {
	p := s.policyLocked()
	if p.IsAllowAll() {
		return nil
	}
	rules := []wgctl.FilterRule{}
	for _, a := range s.st.Devices {
		for _, b := range s.st.Devices {
			if a == b || !p.Allows(a.Name, b.Name) {
				continue
			}
			for _, src := range prefixes(a) {
				for _, dst := range prefixes(b) {
					if !sameFamily(src, dst) {
						continue
					}
					rules = append(rules, wgctl.FilterRule{Src: src, Dst: dst})
				}
			}
		}
	}
	return rules
}

// syncRelayFilter applies the relay filter when it changed.
func (s *Server) syncRelayFilter() error {
	f, ok := s.o.Backend.(wgctl.Filter)
	s.mu.Lock()
	rules := s.relayFilterLocked()
	if !ok {
		if rules != nil && !s.acl.warned {
			s.acl.warned = true
			s.o.Logf("access policy: this relay backend can't filter, so relayed traffic is not checked; devices still filter what reaches them")
		}
		s.mu.Unlock()
		return nil
	}
	same := s.acl.filterSet && (rules == nil) == (s.acl.filter == nil) && slices.Equal(rules, s.acl.filter)
	s.mu.Unlock()
	if same {
		return nil
	}
	if err := f.SetFilter(s.o.Interface, wgctl.FilterRelayed, rules); err != nil {
		return fmt.Errorf("relay access filter: %w", err)
	}
	s.mu.Lock()
	s.acl.filter, s.acl.filterSet = rules, true
	s.mu.Unlock()
	return nil
}

// RelayFilter returns the relay filter rules as the policy and the devices
// now stand (nil: no filter), for tests and the admin view.
func (s *Server) RelayFilter() []wgctl.FilterRule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.relayFilterLocked()
}

// ACLStatus is the admin view of the access policy.
type ACLStatus struct {
	Path        string      `json:"path"`
	InUse       bool        `json:"in_use"` // a policy file is loaded and enforced
	Rules       int         `json:"rules"`
	Groups      int         `json:"groups"`
	Error       string      `json:"error,omitempty"` // the file on disk failed to load
	Warnings    []string    `json:"warnings,omitempty"`
	Reach       []acl.Reach `json:"reach"`
	RelayFilter bool        `json:"relay_filter"` // the relay enforces it too
}

// ACLStatus reports the policy in use and who can reach whom.
func (s *Server) ACLStatus() ACLStatus {
	_, canFilter := s.o.Backend.(wgctl.Filter)
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.policyLocked()
	names := s.deviceNamesLocked()
	return ACLStatus{Path: s.acl.path, InUse: !p.IsAllowAll(), Rules: p.Rules(), Groups: p.Groups(),
		Error: s.acl.err, Warnings: p.Warnings(names), Reach: p.Reach(names),
		RelayFilter: !p.IsAllowAll() && canFilter && !s.o.NoRelay}
}

// ACL reports the coordinator's access policy.
func (a *Admin) ACL() (ACLStatus, error) {
	var s ACLStatus
	return s, a.do("GET", "/admin/acl", nil, &s)
}
