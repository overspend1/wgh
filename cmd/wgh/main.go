// Command wgh is a self-hosted WireGuard mesh (a coordinator, a relay and an
// agent on each device) and a simple helper that writes WireGuard configs
// and QR codes. Run it with no arguments for the full-screen TUI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/overspend1/wgh/internal/agent"
	"github.com/overspend1/wgh/internal/app"
	"github.com/overspend1/wgh/internal/render"
	"github.com/overspend1/wgh/internal/state"
	"github.com/overspend1/wgh/internal/tui"
	"github.com/overspend1/wgh/internal/update"
)

var version = "dev"

const usage = `wgh: a self-hosted WireGuard mesh, and a simple WireGuard config helper.

Run wgh with no arguments for the full-screen interface.

Mesh (your own Tailscale):
  serve    run the coordinator and relay, on a server or VPS
  admin    manage the mesh, on the coordinator: token, devices, approve, remove, phone, qr, acl
  join     join this device with a token from 'wgh admin token'
  up       connect and keep WireGuard set up (needs root)
  down     stop a running 'wgh up'
  status   show devices, paths and traffic
  exit     send internet traffic through a device: wgh exit <name>, or wgh exit off
  rotate   switch this device to a new WireGuard key
  leave    leave the mesh and delete this device's key

Simple server (only writes config files and QR codes, never needs root):
  init     create the server (keys, subnet, port, endpoint)
  add      add a peer with the next free address
  list     list peers
  remove   remove a peer
  show     print a peer's client config
  qr       print a peer's config as a QR code (or save a PNG)
  server   print the server config
  export   write the server and all client configs to a directory

Other:
  tui      open the full-screen interface (the default in a terminal)
  update   check for and install a newer wgh release
  version  print the version

Run 'wgh <command> -h' for its flags.
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

func isTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		if isTerminal() {
			return cmdTUI(nil, stdout, stderr)
		}
		fmt.Fprint(stderr, usage)
		return errors.New("no command given")
	}
	cmd, rest := args[0], args[1:]
	// 'wgh --state x' and 'wgh --no-update-check' open the TUI with those flags.
	if strings.HasPrefix(cmd, "-") && cmd != "-h" && cmd != "--help" && cmd != "-v" && cmd != "--version" {
		return cmdTUI(args, stdout, stderr)
	}
	switch cmd {
	case "tui", "ui":
		return cmdTUI(rest, stdout, stderr)
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
	case "serve", "coordinator":
		return cmdServe(rest, stdout, stderr)
	case "admin":
		return cmdAdmin(rest, stdout, stderr)
	case "join":
		return cmdJoin(rest, stdout, stderr)
	case "up":
		return cmdUp(rest, stdout, stderr)
	case "down":
		return cmdDown(rest, stdout, stderr)
	case "status", "st":
		return cmdStatus(rest, stdout, stderr)
	case "exit":
		return cmdExit(rest, stdout, stderr)
	case "rotate":
		return cmdRotate(rest, stdout, stderr)
	case "leave":
		return cmdLeave(rest, stdout, stderr)
	case "update", "self-update", "upgrade":
		return cmdUpdate(rest, stdout, stderr, update.Default(), os.Executable)
	case "version", "--version", "-v":
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

func noPositional(fs *flag.FlagSet, args []string) error {
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return fmt.Errorf("%s takes no arguments, got %q", fs.Name(), pos)
	}
	return nil
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

func cmdTUI(args []string, _, stderr io.Writer) error {
	fs, statePath := newFlags("tui", stderr)
	noCheck := fs.Bool("no-update-check", os.Getenv("WGH_NO_UPDATE_CHECK") != "",
		"don't look for a newer release on start (also: WGH_NO_UPDATE_CHECK=1)")
	agentState := fs.String("agent-state", agent.DefaultPath(), "this device's mesh state file")
	coordDir := fs.String("dir", defaultCoordDir(), "coordinator directory, for the Admin tab")
	if err := noPositional(fs, args); err != nil {
		return err
	}
	if !isTerminal() {
		return errors.New("the interface needs a terminal; use the subcommands in scripts")
	}
	return tui.Run(tui.Options{StatePath: *statePath, Version: version, CheckUpdates: !*noCheck,
		AgentState: *agentState, CoordDir: *coordDir})
}

func cmdInit(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("init", stderr)
	d := app.DefaultInitOptions()
	endpoint := fs.String("endpoint", "", "public host or IP clients connect to, optionally host:port (required)")
	subnet := fs.String("subnet", d.Subnet, "tunnel subnet (IPv4)")
	port := fs.Int("port", d.Port, "UDP listen port")
	iface := fs.String("interface", d.Interface, "interface name, used for the server config file name")
	address := fs.String("address", "", "server tunnel address (default: first host in subnet)")
	dns := fs.String("dns", "", "comma-separated DNS servers offered to clients, e.g. a Pi-hole")
	nat := fs.String("nat-iface", "", "outgoing LAN interface for iptables NAT rules in PostUp/PostDown, e.g. eth0")
	mtu := fs.Int("mtu", 0, "interface MTU (0 leaves the WireGuard default)")
	force := fs.Bool("force", false, "overwrite an existing state file (destroys all keys in it)")
	if err := noPositional(fs, args); err != nil {
		return err
	}
	if !*force {
		if _, err := os.Stat(*statePath); err == nil {
			return fmt.Errorf("init: %s already exists; use --force to replace it (this throws away every key in it)", *statePath)
		}
	}
	st, err := app.NewServer(app.InitOptions{
		Endpoint: *endpoint, Subnet: *subnet, Port: *port, Interface: *iface,
		Address: *address, DNS: render.SplitList(*dns), NATInterface: *nat, MTU: *mtu,
	})
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if err := state.Save(*statePath, st); err != nil {
		return err
	}
	s := st.Server
	fmt.Fprintf(stdout, "Initialised %s\n", *statePath)
	fmt.Fprintf(stdout, "  interface  %s\n  subnet     %s\n  address    %s\n  endpoint   %s\n  public key %s\n",
		s.Interface, s.Subnet, s.Address, render.Endpoint(s.Endpoint, s.ListenPort), s.PublicKey)
	fmt.Fprintln(stdout, "Next: wgh add <name>")
	return nil
}

func cmdAdd(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("add", stderr)
	d := app.DefaultPeerOptions()
	ip := fs.String("ip", "", "tunnel address for this peer (default: next free)")
	psk := fs.Bool("psk", d.PSK, "generate a preshared key (use --psk=false to skip)")
	allowed := fs.String("allowed-ips", strings.Join(d.AllowedIPs, ", "), "comma-separated routes the client sends through the tunnel")
	dns := fs.String("dns", "", "comma-separated DNS servers for this peer (default: the server's --dns)")
	keepalive := fs.Int("keepalive", d.Keepalive, "PersistentKeepalive seconds (0 disables)")
	showQR := fs.Bool("qr", false, "print the client config as a QR code after adding")
	name, err := onePositional(fs, args, "peer name")
	if err != nil {
		return err
	}
	st, err := state.Load(*statePath)
	if err != nil {
		return err
	}
	p, err := app.AddPeer(st, app.PeerOptions{
		Name: name, IP: *ip, PSK: *psk, AllowedIPs: render.SplitList(*allowed),
		DNS: render.SplitList(*dns), Keepalive: *keepalive,
	}, time.Now())
	if err != nil {
		return fmt.Errorf("add: %w", err)
	}
	if err := state.Save(*statePath, st); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Added %s at %s\n", p.Name, p.Address)
	fmt.Fprintln(stdout, "Re-export the server config so it knows the new peer: wgh export --dir <dir>")
	if *showQR {
		conf, err := render.Client(st, p)
		if err != nil {
			return err
		}
		qr, err := app.QRTerminal(conf, false)
		if err != nil {
			return err
		}
		_, err = io.WriteString(stdout, qr)
		return err
	}
	return nil
}

func cmdList(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("list", stderr)
	if err := noPositional(fs, args); err != nil {
		return err
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
	qr, err := app.QRTerminal(conf, *invert)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(stdout, qr); err != nil {
		return err
	}
	if *png != "" {
		img, err := app.QRPNG(conf, *size)
		if err != nil {
			return err
		}
		// The PNG contains the peer's private key, so keep it private.
		if err := state.WriteSecret(*png, img); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Saved %s\n", *png)
	}
	return nil
}

func cmdServer(args []string, stdout, stderr io.Writer) error {
	fs, statePath := newFlags("server", stderr)
	if err := noPositional(fs, args); err != nil {
		return err
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
	if err := noPositional(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("export: --dir is required")
	}
	st, err := state.Load(*statePath)
	if err != nil {
		return err
	}
	written, err := app.Export(st, *dir, *withQR)
	for _, w := range written {
		fmt.Fprintf(stdout, "Wrote %s\n", w)
	}
	return err
}

func cmdUpdate(args []string, stdout, stderr io.Writer, c *update.Client, exe func() (string, error)) error {
	fs := flag.NewFlagSet("wgh update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "only report whether a newer release exists")
	force := fs.Bool("force", false, "reinstall even if already up to date, or if this is a dev build")
	if err := noPositional(fs, args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	latest, err := c.Latest(ctx)
	if err != nil {
		return err
	}
	newer := update.Newer(version, latest)
	switch {
	case !update.IsRelease(version) && !*force:
		fmt.Fprintf(stdout, "This is a %s build; the latest release is %s. Use --force to replace it.\n", version, latest)
		return nil
	case !newer && !*force:
		fmt.Fprintf(stdout, "wgh %s is up to date.\n", version)
		return nil
	case *check:
		fmt.Fprintf(stdout, "wgh %s is available (you have %s). Run 'wgh update' to install it.\n", latest, version)
		return nil
	}

	asset, err := update.CurrentAsset()
	if err != nil {
		return err
	}
	path, err := exe()
	if err != nil {
		return fmt.Errorf("find current binary: %w", err)
	}
	fmt.Fprintf(stdout, "Downloading %s %s...\n", asset, latest)
	data, err := c.Download(ctx, latest, asset)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Checksum ok.")
	if err := update.Replace(path, data, latest); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Updated wgh %s -> %s at %s\n", version, strings.TrimPrefix(latest, "v"), path)
	return nil
}
