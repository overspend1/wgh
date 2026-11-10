package wgctl

import (
	"strings"
	"testing"
)

// TestLinuxFilterCommands checks the exact iptables commands of SetFilter,
// with a Runner that records them instead of running anything.
func TestLinuxFilterCommands(t *testing.T) {
	var ran []string
	var stdin []string
	l := &Linux{Run: func(in []byte, name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		ran = append(ran, line)
		if in != nil {
			stdin = append(stdin, string(in))
		}
		if strings.Contains(line, " -C ") {
			return nil, errFake // no jump there yet
		}
		return nil, nil
	}}
	rules := []FilterRule{{Src: "10.144.0.2/32", Dst: "10.144.0.3/32"}, {Src: "10.144.0.2/32", Dst: "192.168.50.0/24"}}
	if err := l.SetFilter("wgh-relay", FilterRelayed, rules); err != nil {
		t.Fatal(err)
	}
	// The same rules again change nothing.
	if err := l.SetFilter("wgh-relay", FilterRelayed, rules); err != nil {
		t.Fatal(err)
	}
	// New rules replace the chain's content; the jump stays.
	if err := l.SetFilter("wgh-relay", FilterRelayed, []FilterRule{}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetFilter("wgh0", FilterInbound, []FilterRule{{Src: "10.144.0.1/32"}}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetFilter("wgh-relay", FilterRelayed, nil); err != nil {
		t.Fatal(err)
	}
	if err := l.SetFilter("wgh-relay", FilterRelayed, nil); err != nil { // already off
		t.Fatal(err)
	}
	ran = append(ran, "--- down")
	if err := l.Down("wgh0"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"iptables-restore -w --noflush",
		"iptables -w -C FORWARD -i wgh-relay -o wgh-relay -j WGH-wgh-relay -m comment --comment wgh",
		"iptables -w -I FORWARD 1 -i wgh-relay -o wgh-relay -j WGH-wgh-relay -m comment --comment wgh",
		"iptables-restore -w --noflush",
		"iptables-restore -w --noflush",
		"iptables -w -C INPUT -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"iptables -w -I INPUT 1 -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"iptables -w -C FORWARD -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"iptables -w -I FORWARD 1 -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"iptables -w -D FORWARD -i wgh-relay -o wgh-relay -j WGH-wgh-relay -m comment --comment wgh",
		"iptables -w -F WGH-wgh-relay",
		"iptables -w -X WGH-wgh-relay",
		"--- down",
		"iptables -w -D INPUT -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"iptables -w -D FORWARD -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"iptables -w -F WGH-wgh0",
		"iptables -w -X WGH-wgh0",
		"ip link show dev wgh0",
		"ip link del dev wgh0",
	}
	if strings.Join(ran, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\n\nwant:\n%s", strings.Join(ran, "\n"), strings.Join(want, "\n"))
	}
	wantIn := []string{
		`*filter
:WGH-wgh-relay - [0:0]
-A WGH-wgh-relay -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment wgh
-A WGH-wgh-relay -s 10.144.0.2/32 -d 10.144.0.3/32 -j ACCEPT -m comment --comment wgh
-A WGH-wgh-relay -s 10.144.0.2/32 -d 192.168.50.0/24 -j ACCEPT -m comment --comment wgh
-A WGH-wgh-relay -j DROP -m comment --comment wgh
COMMIT
`,
		`*filter
:WGH-wgh-relay - [0:0]
-A WGH-wgh-relay -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment wgh
-A WGH-wgh-relay -j DROP -m comment --comment wgh
COMMIT
`,
		`*filter
:WGH-wgh0 - [0:0]
-A WGH-wgh0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment wgh
-A WGH-wgh0 -s 10.144.0.1/32 -j ACCEPT -m comment --comment wgh
-A WGH-wgh0 -j DROP -m comment --comment wgh
COMMIT
`,
	}
	if strings.Join(stdin, "|") != strings.Join(wantIn, "|") {
		t.Fatalf("restore input:\n%s\nwant:\n%s", strings.Join(stdin, "\n"), strings.Join(wantIn, "\n"))
	}
}

// TestLinuxFilterKeepsExistingJump: a jump left by an earlier run is found
// with -C and not added twice.
func TestLinuxFilterKeepsExistingJump(t *testing.T) {
	var ran []string
	l := &Linux{Run: func(_ []byte, name string, args ...string) ([]byte, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return nil, nil
	}}
	if err := l.SetFilter("wgh-relay", FilterRelayed, []FilterRule{}); err != nil {
		t.Fatal(err)
	}
	for _, r := range ran {
		if strings.Contains(r, " -I ") {
			t.Fatalf("jump inserted again: %q", ran)
		}
	}
}

func TestFilterRejectsBadPrefixes(t *testing.T) {
	l := &Linux{Run: func([]byte, string, ...string) ([]byte, error) {
		t.Fatal("ran a command for a bad rule")
		return nil, nil
	}}
	for _, r := range []FilterRule{{Src: "10.0.0.1"}, {Dst: "10.0.0.0/8\n-A INPUT -j ACCEPT"}, {Src: "10.0.0.1/8"}} {
		if err := l.SetFilter("wgh0", FilterInbound, []FilterRule{r}); err == nil {
			t.Errorf("rule %+v accepted", r)
		}
	}
}

func TestFakeFilter(t *testing.T) {
	var log strings.Builder
	f := NewFake(&log, nil, "")
	if err := f.SetFilter("wgh0", FilterInbound, []FilterRule{{Src: "10.144.0.3/32"}}); err != nil {
		t.Fatal(err)
	}
	s := f.Snapshot()
	if !s.Filter || s.FilterScope != FilterInbound || len(s.FilterRules) != 1 || s.FilterRules[0].Src != "10.144.0.3/32" {
		t.Fatalf("snapshot %+v", s)
	}
	if !strings.Contains(log.String(), "inbound filter: allow new connections 10.144.0.3/32 -> any") {
		t.Errorf("log: %s", log.String())
	}
	_ = f.SetFilter("wgh0", FilterInbound, nil)
	if f.Snapshot().Filter {
		t.Error("filter still on after nil rules")
	}
}
