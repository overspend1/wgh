package wgctl

import (
	"errors"
	"strings"
	"testing"
)

func TestLinuxSourceRoutes(t *testing.T) {
	var got []string
	dels := 0
	l := &Linux{Run: func(stdin []byte, name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		got = append(got, cmd)
		if cmd == "ip rule del priority 5768" {
			dels++
			if dels > 1 {
				return nil, errors.New("no such rule")
			}
		}
		return nil, nil
	}}
	if err := l.SetSourceRoutes("wgh-relay", []string{"10.144.0.2/32", "10.144.0.7/32"}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetSourceRoutes("wgh-relay", []string{"10.144.0.2/32", "10.144.0.7/32"}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetSourceRoutes("wgh-relay", nil); err != nil {
		t.Fatal(err)
	}
	want := []string{
		// leftovers from an earlier run
		"ip rule del priority 5768",
		"ip rule del priority 5768",
		"ip route flush table 5768",
		"ip route replace default dev wgh-relay table 5768",
		"ip rule add from 10.144.0.2/32 iif wgh-relay lookup 5768 priority 5768",
		"ip rule add from 10.144.0.7/32 iif wgh-relay lookup 5768 priority 5768",
		// the same list again changes nothing; then off
		"ip rule del from 10.144.0.2/32 lookup 5768 priority 5768",
		"ip rule del from 10.144.0.7/32 lookup 5768 priority 5768",
		"ip route flush table 5768",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
