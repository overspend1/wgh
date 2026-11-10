package portmap

import (
	"strings"
	"testing"
)

func TestParseProcNetRoute(t *testing.T) {
	const table = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wgh0	00009000	00000000	0001	0	0	0	0000FFFF	0	0	0
wlan0	00000000	FE01A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
tun0	00000000	00000000	0001	0	0	50	00000000	0	0	0
`
	gw, err := parseProcNetRoute(strings.NewReader(table))
	if err != nil || gw.String() != "192.168.1.1" {
		t.Fatalf("gateway = %v, %v; want 192.168.1.1 (lowest metric with a gateway)", gw, err)
	}
	if _, err := parseProcNetRoute(strings.NewReader("Iface\tDestination\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")); err == nil {
		t.Error("no default route, no error")
	}
	if _, err := parseProcNetRoute(strings.NewReader("")); err == nil {
		t.Error("empty table, no error")
	}
}

func TestParseDarwinRoute(t *testing.T) {
	const out = `   route to: default
destination: default
       mask: default
    gateway: 192.168.178.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
`
	gw, err := parseDarwinRoute([]byte(out))
	if err != nil || gw.String() != "192.168.178.1" {
		t.Fatalf("gateway = %v, %v", gw, err)
	}
	for _, bad := range []string{
		"route: writing to routing socket: not in table\n",
		"   route to: default\n    gateway: utun4\n  interface: utun4\n",
		"    gateway: fe80::1%en0\n",
	} {
		if gw, err := parseDarwinRoute([]byte(bad)); err == nil {
			t.Errorf("%q: gateway %v", bad, gw)
		}
	}
}
