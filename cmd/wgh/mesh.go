package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/overspend1/wgh/internal/agent"
	"github.com/overspend1/wgh/internal/app"
	"github.com/overspend1/wgh/internal/coord"
	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/render"
	"github.com/overspend1/wgh/internal/wgctl"
)

// defaultCoordDir is where 'wgh serve' keeps its state.
func defaultCoordDir() string {
	if p := os.Getenv("WGH_COORD_DIR"); p != "" {
		return p
	}
	if os.Geteuid() == 0 {
		return "/var/lib/wgh/coordinator"
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "wgh", "coordinator")
	}
	return "wgh-coordinator"
}

func agentFlags(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("wgh "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs, fs.String("state", agent.DefaultPath(), "device state file")
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func logger(w io.Writer) func(string, ...any) {
	return func(format string, a ...any) {
		fmt.Fprintf(w, "%s %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
	}
}

func cmdServe(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("wgh serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", defaultCoordDir(), "coordinator state directory")
	endpoint := fs.String("endpoint", "", "public host name or IP of this machine (required)")
	listen := fs.String("listen", ":8443", "HTTPS address for the device API")
	url := fs.String("url", "", "public URL devices use (default https://ENDPOINT:8443)")
	port := fs.Int("port", 51820, "UDP port of the WireGuard relay")
	subnet := fs.String("subnet", mesh.DefaultSubnet, "mesh address range (only used on first start)")
	name := fs.String("name", "relay", "the relay's name in the mesh")
	iface := fs.String("interface", "wgh-relay", "relay interface name")
	exit := fs.Bool("exit", false, "let devices use this machine as an exit node")
	noRelay := fs.Bool("no-relay", false, "control plane only: no WireGuard relay, so no fallback and no phones")
	plain := fs.Bool("plain-http", false, "serve plain HTTP for a TLS reverse proxy in front (set --url to its https address)")
	dry := fs.Bool("dry-run", false, "don't touch any interface: print what the relay would do")
	if err := noPositional(fs, args); err != nil {
		return err
	}
	var backend wgctl.Backend
	switch {
	case *noRelay:
	case *dry:
		backend = wgctl.NewFake(stdout, nil, "")
	default:
		if err := wgctl.Check(); err != nil {
			return fmt.Errorf("serve: %w (or run with --no-relay for the control plane only)", err)
		}
		backend = wgctl.NewLinux()
	}
	srv, err := coord.New(coord.Options{Dir: *dir, Listen: *listen, URL: *url, Endpoint: *endpoint, Port: *port,
		Interface: *iface, Subnet: *subnet, Name: *name, Exit: *exit, NoRelay: *noRelay, PlainHTTP: *plain,
		Backend: backend, Logf: logger(stdout)})
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	fmt.Fprintf(stdout, "wgh coordinator %s\n  state  %s\n  url    %s\n", version, *dir, srv.URL())
	if !*noRelay {
		fmt.Fprintf(stdout, "  relay  %s on UDP %d\n", *iface, *port)
	}
	fmt.Fprintln(stdout, "Add a device: run 'wgh admin token' here, then 'wgh join <token>' on the device.")
	ctx, cancel := signalContext()
	defer cancel()
	return srv.Run(ctx)
}

func cmdJoin(args []string, stdout, stderr io.Writer) error {
	fs, statePath := agentFlags("join", stderr)
	h, _ := os.Hostname()
	name := fs.String("name", mesh.CleanName(h), "this device's name in the mesh")
	routes := fs.String("advertise-routes", "", "comma-separated LAN ranges to share, e.g. 192.168.1.0/24")
	exit := fs.Bool("advertise-exit", false, "offer this device as an exit node")
	port := fs.Int("port", agent.DefaultPort, "UDP port for WireGuard")
	iface := fs.String("interface", agent.DefaultInterface, "WireGuard interface name")
	tok, err := onePositional(fs, args, "join token")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := agent.Join(ctx, *statePath, agent.JoinOptions{Token: tok, Name: *name, Routes: render.SplitList(*routes),
		Exit: *exit, ListenPort: *port, Interface: *iface, Version: version})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Joined as %s with address %s.\nState saved to %s (keep it private: it holds this device's key).\n",
		st.Name, st.Address, *statePath)
	fmt.Fprintln(stdout, "Next: sudo wgh up")
	return nil
}

func cmdUp(args []string, stdout, stderr io.Writer) error {
	fs, statePath := agentFlags("up", stderr)
	dry := fs.Bool("dry-run", false, "don't touch any interface or file: print what would be done")
	var exitNode, routes optString
	fs.Var(&exitNode, "exit-node", "send internet traffic through this device (\"\" turns it off)")
	fs.Var(&routes, "advertise-routes", "comma-separated LAN ranges to share (\"\" stops)")
	advExit := fs.String("advertise-exit", "", "offer this device as an exit node: true or false")
	acceptRoutes := fs.String("accept-routes", "", "use routes other devices share: true or false (default true)")
	hostsPath := fs.String("hosts", "/etc/hosts", "hosts file for device names (\"\" to leave it alone)")
	if err := noPositional(fs, args); err != nil {
		return err
	}
	st, err := agent.Load(*statePath)
	if err != nil {
		return err
	}
	changed := false
	if exitNode.set {
		st.ExitNode, changed = exitNode.v, true
	}
	if routes.set {
		r := render.SplitList(routes.v)
		if err := mesh.ValidRoutes(r); err != nil {
			return err
		}
		st.Routes, changed = r, true
	}
	if v, ok, err := optBool(*advExit, "--advertise-exit"); err != nil {
		return err
	} else if ok {
		st.Exit, changed = v, true
	}
	if v, ok, err := optBool(*acceptRoutes, "--accept-routes"); err != nil {
		return err
	} else if ok {
		st.NoRoutes, changed = !v, true
	}
	var backend wgctl.Backend
	hosts := *hostsPath
	if *dry {
		backend = wgctl.NewFake(stdout, nil, "")
		hosts = ""
	} else {
		if err := wgctl.Check(); err != nil {
			return err
		}
		backend = wgctl.NewLinux()
	}
	if changed && !*dry {
		if err := agent.Save(*statePath, st); err != nil {
			return err
		}
	}
	if *dry && changed {
		// Run from a copy so a dry run never changes the saved preferences.
		tmp, err := os.MkdirTemp("", "wgh-dry-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		p := filepath.Join(tmp, "agent.json")
		if err := agent.Save(p, st); err != nil {
			return err
		}
		*statePath = p
	}
	a, err := agent.New(agent.Options{StatePath: *statePath, Backend: backend, HostsPath: hosts, Version: version,
		DryRun: *dry, Logf: logger(stdout)})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wgh %s: %s (%s) on %s, coordinator %s\n", version, st.Name, st.Address, st.Interface, st.URL)
	if *dry {
		fmt.Fprintln(stdout, "Dry run: nothing on this machine is changed. Ctrl-C to stop.")
	}
	ctx, cancel := signalContext()
	defer cancel()
	err = a.Run(ctx)
	if errors.Is(err, agent.ErrRemoved) && !*dry {
		_ = os.Remove(*statePath)
		return errors.New("this device was removed from the mesh; its state was deleted. Join again with a new token")
	}
	return err
}

func optBool(v, flagName string) (val, set bool, err error) {
	switch strings.ToLower(v) {
	case "":
		return false, false, nil
	case "true", "yes", "on", "1":
		return true, true, nil
	case "false", "no", "off", "0":
		return false, true, nil
	}
	return false, false, fmt.Errorf("%s wants true or false, got %q", flagName, v)
}

func cmdDown(args []string, stdout, stderr io.Writer) error {
	fs, statePath := agentFlags("down", stderr)
	if err := noPositional(fs, args); err != nil {
		return err
	}
	if err := agent.NewLocal(agent.SocketPath(*statePath)).Down(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Stopping wgh up; the interface is removed as it exits.")
	return nil
}

func cmdStatus(args []string, stdout, stderr io.Writer) error {
	fs, statePath := agentFlags("status", stderr)
	if err := noPositional(fs, args); err != nil {
		return err
	}
	s, err := agent.NewLocal(agent.SocketPath(*statePath)).Status()
	if err != nil {
		if st, lerr := agent.Load(*statePath); lerr == nil {
			fmt.Fprintf(stdout, "%s (%s) is in the mesh at %s but wgh up is not running.\nStart it with: sudo wgh up\n", st.Name, st.Address, st.URL)
			return nil
		}
		return err
	}
	printStatus(stdout, s)
	return nil
}

func printStatus(w io.Writer, s agent.Status) {
	conn := "connected"
	if !s.Connected {
		conn = "can't reach the coordinator"
		if s.LastError != "" {
			conn += ": " + s.LastError
		}
	}
	fmt.Fprintf(w, "%s  %s  %s\n", s.Name, s.Address, conn)
	if s.ExitNode != "" {
		state := "on"
		if !s.ExitActive {
			state = "off: " + s.ExitNote
		}
		fmt.Fprintf(w, "exit node %s (%s)\n", s.ExitNode, state)
	}
	if len(s.PendingRoutes) > 0 || s.PendingExit {
		fmt.Fprintln(w, "waiting for approval on the coordinator: wgh admin approve", s.Name)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nNAME\tADDRESS\tPATH\tENDPOINT\tHANDSHAKE\tRX\tTX")
	for _, p := range s.Peers {
		ep := p.Endpoint
		if ep == "" {
			ep = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, p.Address, p.Path, ep,
			app.Ago(s.At, p.LastHandshake), app.Bytes(p.RxBytes), app.Bytes(p.TxBytes))
	}
	tw.Flush()
}

func cmdLeave(args []string, stdout, stderr io.Writer) error {
	fs, statePath := agentFlags("leave", stderr)
	if err := noPositional(fs, args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := agent.Leave(ctx, *statePath, nil); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Left the mesh and deleted this device's key. A running wgh up stops by itself.")
	return nil
}

func cmdRotate(args []string, stdout, stderr io.Writer) error {
	fs, statePath := agentFlags("rotate", stderr)
	if err := noPositional(fs, args); err != nil {
		return err
	}
	if _, err := agent.NewLocal(agent.SocketPath(*statePath)).Rotate(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "New WireGuard key in use; the other devices pick it up within seconds.")
	return nil
}

func cmdExit(args []string, stdout, stderr io.Writer) error {
	fs, statePath := agentFlags("exit", stderr)
	name, err := onePositional(fs, args, "exit node name, or off")
	if err != nil {
		return err
	}
	if name == "off" || name == "none" {
		name = ""
	}
	s, err := agent.NewLocal(agent.SocketPath(*statePath)).SetExit(name)
	if err != nil {
		return err
	}
	switch {
	case name == "":
		fmt.Fprintln(stdout, "Exit node off: internet traffic goes out locally.")
	case s.ExitActive:
		fmt.Fprintf(stdout, "Internet traffic now goes out through %s.\n", name)
	default:
		fmt.Fprintf(stdout, "Exit node set to %s, not active yet: %s\n", name, s.ExitNote)
	}
	return nil
}

const adminUsage = `Usage: wgh admin <command> [flags]   (run on the coordinator machine)

  token     make a join token (one use, 1 hour by default)
  devices   list devices, their status and pending approvals
  approve   approve a device's shared routes and exit node
  remove    remove a device; its key stops working at once
  phone     add a phone or other plain WireGuard device and show its QR code
  qr        show the QR code of an existing phone again
`

func cmdAdmin(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, adminUsage)
		return errors.New("admin: no command given")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("wgh admin "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", defaultCoordDir(), "coordinator state directory")
	adm := func() *coord.Admin { return coord.NewAdmin(filepath.Join(*dir, "admin.sock")) }
	switch sub {
	case "token":
		ttl := fs.String("ttl", "1h", "how long the token works")
		reusable := fs.Bool("reusable", false, "allow many devices to join with it until it expires")
		approve := fs.Bool("approve", false, "approve routes and exit nodes of devices joining with it")
		if err := noPositional(fs, rest); err != nil {
			return err
		}
		tok, err := adm().Token(coord.TokenRequest{TTL: *ttl, Reusable: *reusable, Approve: *approve})
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s\n\nOn the device: wgh join %s\n", tok, tok)
		return nil
	case "devices", "ls", "list":
		if err := noPositional(fs, rest); err != nil {
			return err
		}
		st, err := adm().Status()
		if err != nil {
			return err
		}
		printAdmin(stdout, st, time.Now())
		return nil
	case "approve", "remove", "rm", "qr":
		name, err := onePositional(fs, rest, "device name")
		if err != nil {
			return err
		}
		switch sub {
		case "approve":
			routes, exit, err := adm().Approve(name)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Approved %s: routes %s, exit node %v\n", name, orNone(routes), exit)
		case "qr":
			conf, err := adm().PhoneConfig(name)
			if err != nil {
				return err
			}
			return printQR(stdout, conf)
		default:
			if err := adm().Remove(name); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Removed %s.\n", name)
		}
		return nil
	case "phone":
		exit := fs.Bool("exit", false, "send all of the phone's internet traffic through the relay")
		name, err := onePositional(fs, rest, "device name")
		if err != nil {
			return err
		}
		conf, err := adm().AddPhone(name, *exit)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Added %s. Scan this in the WireGuard app:\n", name)
		return printQR(stdout, conf)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, adminUsage)
		return nil
	}
	fmt.Fprint(stderr, adminUsage)
	return fmt.Errorf("admin: unknown command %q", sub)
}

func printQR(w io.Writer, conf string) error {
	qr, err := app.QRTerminal(conf, false)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, qr)
	return err
}

func orNone(v []string) string {
	if len(v) == 0 {
		return "none"
	}
	return strings.Join(v, ", ")
}

func printAdmin(w io.Writer, st coord.Status, now time.Time) {
	online := 0
	for _, d := range st.Devices {
		if d.Online {
			online++
		}
	}
	fmt.Fprintf(w, "%s  %s  %d device(s), %d online\n", st.URL, st.Subnet, len(st.Devices), online)
	if len(st.Devices) == 0 {
		fmt.Fprintln(w, "No devices yet. Make a token: wgh admin token")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nNAME\tADDRESS\tSTATUS\tLAST SEEN\tOS\tROUTES\tNOTE")
	for _, d := range st.Devices {
		status := "offline"
		if d.Online {
			status = "online"
		}
		var note []string
		if len(d.PendingRoutes) > 0 || d.PendingExit {
			note = append(note, "needs approval")
		}
		if d.Exit {
			note = append(note, "exit node")
		}
		if d.Static {
			note = append(note, "phone")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.Name, d.Address, status, app.Ago(now, d.LastSeen),
			orDash(d.OS), orNone(append(append([]string(nil), d.Routes...), d.PendingRoutes...)), strings.Join(note, ", "))
	}
	tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// optString is a string flag that remembers whether it was given, so an
// explicit empty value can mean "turn it off".
type optString struct {
	v   string
	set bool
}

func (o *optString) String() string     { return o.v }
func (o *optString) Set(v string) error { o.v, o.set = v, true; return nil }
