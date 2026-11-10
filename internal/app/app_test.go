package app

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestNewServerValidation(t *testing.T) {
	ok := DefaultInitOptions()
	ok.Endpoint = "vpn.example.com"
	s, err := NewServer(ok)
	if err != nil {
		t.Fatal(err)
	}
	if s.Server.Address != "10.8.0.1" || s.Server.PublicKey == "" {
		t.Fatalf("unexpected server %+v", s.Server)
	}

	bad := []func(*InitOptions){
		func(o *InitOptions) { o.Endpoint = "" },
		func(o *InitOptions) { o.Endpoint = "has space" },
		func(o *InitOptions) { o.Port = 0 },
		func(o *InitOptions) { o.Interface = "this-name-is-too-long" },
		func(o *InitOptions) { o.Subnet = "10.8.0.0/31" },
		func(o *InitOptions) { o.Address = "10.9.0.1" },
		func(o *InitOptions) { o.DNS = []string{"not-an-ip"} },
		func(o *InitOptions) { o.MTU = 100 },
	}
	for i, mut := range bad {
		o := ok
		mut(&o)
		if _, err := NewServer(o); err == nil {
			t.Errorf("case %d: want error for %+v", i, o)
		}
	}
}

func TestAddPeerLeavesStateAloneOnError(t *testing.T) {
	o := DefaultInitOptions()
	o.Endpoint = "vpn.example.com"
	s, _ := NewServer(o)
	now := time.Unix(0, 0)

	p := DefaultPeerOptions()
	p.Name = "phone"
	if _, err := AddPeer(s, p, now); err != nil {
		t.Fatal(err)
	}
	for _, mut := range []func(*PeerOptions){
		func(p *PeerOptions) { p.Name = "phone" },
		func(p *PeerOptions) { p.Name = "../x" },
		func(p *PeerOptions) { p.Name = "a"; p.IP = "10.8.0.2" },
		func(p *PeerOptions) { p.Name = "b"; p.AllowedIPs = nil },
		func(p *PeerOptions) { p.Name = "c"; p.AllowedIPs = []string{"nope"} },
		func(p *PeerOptions) { p.Name = "d"; p.Keepalive = -1 },
	} {
		q := DefaultPeerOptions()
		mut(&q)
		if _, err := AddPeer(s, q, now); err == nil {
			t.Errorf("want error for %+v", q)
		}
	}
	if len(s.Peers) != 1 {
		t.Fatalf("failed adds changed the state: %d peers", len(s.Peers))
	}
}

// TestQRTerminalScans turns the half-block QR back into pixels and, when
// zbarimg is installed, checks that it decodes to the original text.
func TestQRTerminalScans(t *testing.T) {
	text := strings.Repeat("[Interface]\nPrivateKey = abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG=\n", 4)
	for _, invert := range []bool{false, true} {
		qr, err := QRTerminal(text, invert)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(qr, "\n"), "\n")
		w := utf8.RuneCountInString(lines[0])
		const scale = 8
		img := image.NewGray(image.Rect(0, 0, w*scale, len(lines)*2*scale))
		for y, line := range lines {
			for x, r := range []rune(line) {
				top := r == '█' || r == '▀'
				bot := r == '█' || r == '▄'
				if invert {
					// Inverted output is meant for dark-on-light terminals.
					top, bot = !top, !bot
				}
				for dy := 0; dy < 2*scale; dy++ {
					light := top
					if dy >= scale {
						light = bot
					}
					for dx := 0; dx < scale; dx++ {
						c := color.Gray{Y: 0}
						if light {
							c.Y = 255
						}
						img.SetGray(x*scale+dx, (y*2)*scale+dy, c)
					}
				}
			}
		}
		zbar, err := exec.LookPath("zbarimg")
		if err != nil {
			t.Skip("zbarimg not installed")
		}
		f := filepath.Join(t.TempDir(), "qr.png")
		out, _ := os.Create(f)
		png.Encode(out, img)
		out.Close()
		got, err := exec.Command(zbar, "-q", "--raw", f).Output()
		if err != nil {
			t.Fatalf("invert=%v: zbarimg could not read the QR: %v", invert, err)
		}
		if strings.TrimRight(string(got), "\n") != strings.TrimRight(text, "\n") {
			t.Fatalf("invert=%v: decoded %q", invert, got)
		}
	}
}
