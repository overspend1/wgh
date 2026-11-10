// Command wgh manages a small WireGuard server and its peers as plain files:
// keys, wg-quick configs and QR codes. It never touches a network interface
// and never needs root.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/overspend1/wgh/internal/ipam"
	"github.com/overspend1/wgh/internal/keys"
	"github.com/overspend1/wgh/internal/render"
	"github.com/overspend1/wgh/internal/state"
)

var version = "dev"

const usage = `wgh: a small WireGuard helper that only writes files.

Usage:
  wgh <command> [flags] [args]

Commands:
  init     create the server (keys, subnet, port, endpoint)
  add      add a peer with the next free address
  list     list peers
  remove   remove a peer
  show     print a peer's client config
  qr       print a peer's config as a QR code (or save a PNG)
  server   print the server config
  export   write the server and all client configs to a directory
  version  print the version

Every command takes --state PATH (default $WGH_STATE, else
~/.config/wgh/state.json). Run 'wgh <command> -h' for its flags.
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "wgh:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return errors.New("no command given")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return cmdInit(rest, stdout, stderr)
	case "add":
		return cmdAdd(rest, stdout, stderr)
	case "list", "ls":
		return cmdList(rest, stdout, stderr)
	case "remove", "rm":
		return cmdRemove(rest, stdout, stderr)
	case "show":
		return cmdShow(rest, stdout, stderr)
	case "qr":
		return cmdQR(rest, stdout, stderr)
	case "server":
		return cmdServer(rest, stdout, stderr)
	case "export":
		return cmdExport(rest, stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, "wgh", version)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// newFlags returns a FlagSet with the shared --state flag.
func newFlags(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("wgh "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	p := fs.String("state", state.DefaultPath(), "path to the state file")
	return fs, p
}

// parse lets flags appear before or after positional arguments, so both
// 'wgh add --psk=false phone' and 'wgh add phone --psk=false' work.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func onePositional(fs *flag.FlagSet, args []string, what string) (string, error) {
	pos, err := parse(fs, args)
	if err != nil {
		return "", err
	}
	if len(pos) != 1 {
		return "", fmt.Errorf("%s: want exactly one %s, got %d", fs.Name(), what, len(pos))
	}
	return pos[0], nil
}

var ifaceRE = regexp.MustCompile(`^[A-Za-z0-9_=+.-]{1,15}$`)

func cmdInit(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("init", stderr)
	endpoint := fs.String("endpoint", "", "public host or IP clients connect to, optionally host:port (required)")
	subnet := fs.String("subnet", "10.8.0.0/24", "tunnel subnet (IPv4)")
	port := fs.Int("port", 51820, "UDP listen port")
	iface := fs.String("interface", "wg0", "interface name, used for the server config file name")
	address := fs.String("address", "", "server tunnel address (default: first host in subnet)")
	dns := fs.String("dns", "", "comma-separated DNS servers offered to clients, e.g. a Pi-hole")
	nat := fs.String("nat-iface", "", "outgoing LAN interface for iptables NAT rules in PostUp/PostDown, e.g. eth0")
	mtu := fs.Int("mtu", 0, "interface MTU (0 leaves the WireGuard default)")
	force := fs.Bool("force", false, "overwrite an existing state file (destroys all keys in it)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return fmt.Errorf("init takes no arguments, got %q", pos)
	}

	if strings.TrimSpace(*endpoint) == "" || strings.ContainsAny(*endpoint, " \t\n") {
		return errors.New("init: --endpoint is required, e.g. --endpoint vpn.example.com")
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("init: --port %d is out of range", *port)
	}
	if !ifaceRE.MatchString(*iface) {
		return fmt.Errorf("init: --interface %q is not a valid interface name (max 15 chars)", *iface)
	}
	if *mtu != 0 && (*mtu < 1280 || *mtu > 9000) {
		return fmt.Errorf("init: --mtu %d should be between 1280 and 9000", *mtu)
	}
	if *nat != "" && !ifaceRE.MatchString(*nat) {
		return fmt.Errorf("init: --nat-iface %q is not a valid interface name", *nat)
	}
	prefix, err := ipam.ParseSubnet(*subnet)
	if err != nil {
		return err
	}
	srvAddr := ipam.First(prefix)
	if *address != "" {
		a, err := netip.ParseAddr(*address)
		if err != nil {
			return fmt.Errorf("init: --address: %w", err)
		}
		if err := ipam.Claim(prefix, a, nil); err != nil {
			return fmt.Errorf("init: --address: %w", err)
		}
		srvAddr = a
	}
	dnsList := render.SplitList(*dns)
	if err := render.ValidateIPs(dnsList); err != nil {
		return fmt.Errorf("init: --dns: %w", err)
	}

	if !*force {
		if _, err := os.Stat(*statePath); err == nil {
			return fmt.Errorf("init: %s already exists; use --force to replace it (this throws away every key in it)", *statePath)
		}
	}

	kp, err := keys.NewPair()
	if err != nil {
		return err
	}
	st := &state.State{
		Server: state.Server{
			Interface:    *iface,
			Subnet:       prefix.String(),
			Address:      srvAddr.String(),
			ListenPort:   *port,
			Endpoint:     *endpoint,
			PrivateKey:   kp.Private,
			PublicKey:    kp.Public,
			DNS:          dnsList,
			NATInterface: *nat,
			MTU:          *mtu,
		},
		Peers: []state.Peer{},
	}
	if err := state.Save(*statePath, st); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Initialised %s\n", *statePath)
	fmt.Fprintf(stdout, "  interface  %s\n  subnet     %s\n  address    %s\n  endpoint   %s\n  public key %s\n",
		*iface, prefix, srvAddr, render.Endpoint(*endpoint, *port), kp.Public)
	fmt.Fprintln(stdout, "Next: wgh add <name>")
	return nil
}

func cmdAdd(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("add", stderr)
	ip := fs.String("ip", "", "tunnel address for this peer (default: next free)")
	psk := fs.Bool("psk", true, "generate a preshared key (use --psk=false to skip)")
	allowed := fs.String("allowed-ips", "0.0.0.0/0, ::/0", "comma-separated routes the client sends through the tunnel")
	dns := fs.String("dns", "", "comma-separated DNS servers for this peer (default: the server's --dns)")
	keepalive := fs.Int("keepalive", 25, "PersistentKeepalive seconds (0 disables)")
	showQR := fs.Bool("qr", false, "print the client config as a QR code after adding")
	name, err := onePositional(fs, args, "peer name")
	if err != nil {
		return err
	}
	if err := state.ValidName(name); err != nil {
		return err
	}
	if *keepalive < 0 || *keepalive > 65535 {
		return fmt.Errorf("add: --keepalive %d is out of range", *keepalive)
	}
	allowedList := render.SplitList(*allowed)
	if len(allowedList) == 0 {
		return errors.New("add: --allowed-ips must not be empty")
	}
	if err := render.ValidateCIDRs(allowedList); err != nil {
		return fmt.Errorf("add: %w", err)
	}
	dnsList := render.SplitList(*dns)
	if err := render.ValidateIPs(dnsList); err != nil {
		return fmt.Errorf("add: --dns: %w", err)
	}

	st, err := state.Load(*statePath)
	if err != nil {
		return err
	}
	if p, _ := st.Find(name); p != nil {
		return fmt.Errorf("add: a peer named %q already exists (%s)", name, p.Address)
	}
	prefix, err := st.Subnet()
	if err != nil {
		return err
	}
	used, err := st.UsedAddrs()
	if err != nil {
		return err
	}
	var addr netip.Addr
	if *ip != "" {
		addr, err = netip.ParseAddr(*ip)
		if err != nil {
			return fmt.Errorf("add: --ip: %w", err)
		}
		if err := ipam.Claim(prefix, addr, used); err != nil {
			return fmt.Errorf("add: --ip: %w", err)
		}
	} else if addr, err = ipam.Next(prefix, used); err != nil {
		return fmt.Errorf("add: %w", err)
	}

	kp, err := keys.NewPair()
	if err != nil {
		return err
	}
	peer := state.Peer{
		Name:       name,
		Address:    addr.String(),
		PrivateKey: kp.Private,
		PublicKey:  kp.Public,
		AllowedIPs: allowedList,
		DNS:        dnsList,
		Keepalive:  *keepalive,
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}
	if *psk {
		if peer.PresharedKey, err = keys.GeneratePreshared(); err != nil {
			return err
		}
	}
	st.Peers = append(st.Peers, peer)
	st.SortPeers()
	if err := state.Save(*statePath, st); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Added %s at %s\n", name, addr)
	fmt.Fprintln(stdout, "Re-export the server config so it knows the new peer: wgh export --dir <dir>")
	if *showQR {
		p, _ := st.Find(name)
		conf, err := render.Client(st, p)
		if err != nil {
			return err
		}
		return printQR(stdout, conf, false)
	}
	return nil
}

func cmdList(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("list", stderr)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return fmt.Errorf("list takes no arguments, got %q", pos)
	}
	st, err := state.Load(*statePath)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s  %s  server %s  endpoint %s\n", st.Server.Interface, st.Server.Subnet,
		st.Server.Address, render.Endpoint(st.Server.Endpoint, st.Server.ListenPort))
	if len(st.Peers) == 0 {
		fmt.Fprintln(stdout, "No peers yet. Add one with: wgh add <name>")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDRESS\tPSK\tPUBLIC KEY\tCREATED")
	for _, p := range st.Peers {
		psk := "no"
		if p.PresharedKey != "" {
			psk = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Address, psk, p.PublicKey, p.CreatedAt.Format("2006-01-02"))
	}
	return tw.Flush()
}

func cmdRemove(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("remove", stderr)
	name, err := onePositional(fs, args, "peer name")
	if err != nil {
		return err
	}
	st, err := state.Load(*statePath)
	if err != nil {
		return err
	}
	if err := st.Remove(name); err != nil {
		return err
	}
	if err := state.Save(*statePath, st); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Removed %s. Re-export and reload the server config to revoke it.\n", name)
	return nil
}

func loadPeer(statePath, name string) (*state.State, *state.Peer, error) {
	st, err := state.Load(statePath)
	if err != nil {
		return nil, nil, err
	}
	p, _ := st.Find(name)
	if p == nil {
		return nil, nil, fmt.Errorf("no peer named %q", name)
	}
	return st, p, nil
}

func cmdShow(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("show", stderr)
	out := fs.String("o", "", "write the config to this file (mode 0600) instead of stdout")
	name, err := onePositional(fs, args, "peer name")
	if err != nil {
		return err
	}
	st, p, err := loadPeer(*statePath, name)
	if err != nil {
		return err
	}
	conf, err := render.Client(st, p)
	if err != nil {
		return err
	}
	if *out != "" {
		if err := state.WriteSecret(*out, []byte(conf)); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Wrote %s\n", *out)
		return nil
	}
	_, err = io.WriteString(stdout, conf)
	return err
}

func cmdQR(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("qr", stderr)
	png := fs.String("png", "", "also save the QR code as a PNG at this path (mode 0600)")
	size := fs.Int("size", 512, "PNG width and height in pixels")
	invert := fs.Bool("invert", false, "invert terminal colours (try this if your phone can't scan it)")
	name, err := onePositional(fs, args, "peer name")
	if err != nil {
		return err
	}
	if *size < 128 || *size > 4096 {
		return fmt.Errorf("qr: --size %d should be between 128 and 4096", *size)
	}
	st, p, err := loadPeer(*statePath, name)
	if err != nil {
		return err
	}
	conf, err := render.Client(st, p)
	if err != nil {
		return err
	}
	if err := printQR(stdout, conf, *invert); err != nil {
		return err
	}
	if *png != "" {
		q, err := qrcode.New(conf, qrcode.Medium)
		if err != nil {
			return fmt.Errorf("qr: %w", err)
		}
		img, err := q.PNG(*size)
		if err != nil {
			return fmt.Errorf("qr: encode png: %w", err)
		}
		// The PNG contains the peer's private key, so keep it private.
		if err := state.WriteSecret(*png, img); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Saved %s\n", *png)
	}
	return nil
}

func printQR(w io.Writer, conf string, invert bool) error {
	q, err := qrcode.New(conf, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("qr: %w", err)
	}
	_, err = io.WriteString(w, q.ToSmallString(invert))
	return err
}

func cmdServer(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("server", stderr)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return fmt.Errorf("server takes no arguments, got %q", pos)
	}
	st, err := state.Load(*statePath)
	if err != nil {
		return err
	}
	conf, err := render.Server(st)
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, conf)
	return err
}

func cmdExport(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("export", stderr)
	dir := fs.String("dir", "", "output directory (required)")
	withQR := fs.Bool("qr", false, "also write a QR PNG next to each client config")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return fmt.Errorf("export takes no arguments, got %q", pos)
	}
	if *dir == "" {
		return errors.New("export: --dir is required")
	}
	st, err := state.Load(*statePath)
	if err != nil {
		return err
	}
	srv, err := render.Server(st)
	if err != nil {
		return err
	}
	srvPath := filepath.Join(*dir, st.Server.Interface+".conf")
	if err := state.WriteSecret(srvPath, []byte(srv)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Wrote %s\n", srvPath)
	for i := range st.Peers {
		p := &st.Peers[i]
		conf, err := render.Client(st, p)
		if err != nil {
			return err
		}
		path := filepath.Join(*dir, "peers", p.Name+".conf")
		if err := state.WriteSecret(path, []byte(conf)); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Wrote %s\n", path)
		if *withQR {
			q, err := qrcode.New(conf, qrcode.Medium)
			if err != nil {
				return fmt.Errorf("qr for %s: %w", p.Name, err)
			}
			img, err := q.PNG(512)
			if err != nil {
				return fmt.Errorf("qr for %s: %w", p.Name, err)
			}
			pngPath := filepath.Join(*dir, "peers", p.Name+".png")
			if err := state.WriteSecret(pngPath, img); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Wrote %s\n", pngPath)
		}
	}
	return nil
}
