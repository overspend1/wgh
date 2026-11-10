# wgh

Your own WireGuard mesh, in one small binary. It does the job Tailscale does
for a home lab, without an account or anyone's cloud: one machine you own runs
the coordinator, every other device joins with a one-time token, and from then
on wgh writes and updates the WireGuard config by itself. Devices talk to each
other directly when they can and through your own relay when they can't.

Run `wgh` and you get a full-screen interface, in WireGuard red, that shows
every device with its path, endpoint, last handshake and traffic.

wgh also still does what it started as: a **simple server** mode that only
writes WireGuard config files and QR codes for one classic server, never
touching the network and never needing root. See [Simple server](#simple-server).

- Single static Go binary. No other daemons, no database.
- Each device makes its own key and never sends the private half anywhere.
- Devices find each other by name: `ssh pve1` or `ssh pve1.wgh`.
- Exit node, shared LAN routes, key rotation, removal, phones by QR code.
- `wgh update` replaces itself with the latest release, checksum-verified.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/overspend1/wgh/main/install.sh | sh
```

The script detects your OS and CPU, downloads the matching binary from this
repo's GitHub releases, checks it against `checksums.txt`, and installs it to
`/usr/local/bin` if you can write there, otherwise `~/.local/bin`. It never
uses sudo. On OpenWrt without curl, use `wget -qO- <same URL> | sh`.

Options: `WGH_VERSION=v0.1.0` pins a release, `WGH_INSTALL_DIR=/opt/bin`
picks the directory, `WGH_ARCH=linux-mipsle` skips detection.

Release binaries: `linux-amd64`, `linux-arm64`, `linux-armv7`, `linux-armv6`,
`linux-mips`, `linux-mipsle` (softfloat, for OpenWrt), `darwin-amd64`,
`darwin-arm64`. Or install from source:

```sh
go install github.com/overspend1/wgh/cmd/wgh@latest
```

## Mesh

### What you need

- **Root.** `wgh serve` and `wgh up` create a WireGuard interface, set routes
  and, for an exit node, firewall rules. Both refuse to run without root and
  say so. Nothing else in wgh needs root.
- **Linux** on the coordinator and on every device that runs `wgh up`, with
  `wireguard-tools` (the `wg` command) and `iproute2` (`ip`). The kernel
  WireGuard module is used when it is there (any kernel from 5.6, and most
  older distribution kernels); otherwise wgh starts `wireguard-go` if it is
  installed. An exit node or relay also needs `iptables`.
- **Phones, tablets and other OSes** join as plain WireGuard peers through the
  relay, using the official WireGuard app (see [Phones](#phones)).
- One machine every device can reach for the coordinator: a small VPS, or a
  box at home with two ports forwarded.

Ports:

| Where | Port | What |
| --- | --- | --- |
| coordinator | TCP 8443 | device API (HTTPS) |
| coordinator | UDP 51820 | relay |
| each device | UDP 41820 | direct connections (forwarding it helps but is optional) |

### Quick start

On the coordinator:

```sh
sudo wgh serve --endpoint vpn.example.com    # leave it running, or use the systemd unit
sudo wgh admin token                         # prints: sudo wgh join wgh1_...
```

On each device:

```sh
sudo wgh join wgh1_...       # once; picks its name from the hostname, or --name
sudo wgh up                  # connects and keeps the config up to date
wgh status                   # devices, paths, handshakes, traffic
```

That is all the configuration there is. When a device joins, leaves, moves to
another network or gets a new key, every other device picks it up within a
second or two.

Try it without touching anything: `wgh serve --dry-run ...` and
`wgh up --dry-run` print every `ip`, `wg` and `iptables` command they would run
instead of running it, and skip the hosts file.

### Run it with systemd

[`contrib/systemd`](contrib/systemd) has a unit for each side:

```sh
sudo install -m 644 contrib/systemd/wgh-serve.service /etc/systemd/system/   # coordinator; edit --endpoint first
sudo install -m 644 contrib/systemd/wgh-up.service /etc/systemd/system/      # devices, after 'wgh join'
sudo systemctl enable --now wgh-serve    # or wgh-up
```

### Commands

| Command | What it does |
| --- | --- |
| `wgh serve --endpoint HOST` | Run the coordinator and relay. `--exit` offers the relay as an exit node. |
| `wgh admin token [--ttl 1h] [--reusable] [--approve]` | Make a join token. One use and one hour by default; `--approve` pre-approves the routes the device shares. |
| `wgh admin devices` | Every device, online or not, and what waits for approval. |
| `wgh admin approve <name>` | Approve the routes or exit node a device offers. |
| `wgh admin remove <name>` | Remove a device. Its key stops working at once. |
| `wgh admin phone <name> [--exit]` | Add a phone and print its QR code. `wgh admin qr <name>` shows it again. |
| `wgh admin acl` | The access rules in use and who can reach whom. `wgh admin acl check FILE` validates a file first. |
| `wgh join <token>` | Join this device. Flags: `--name`, `--advertise-routes`, `--advertise-exit`. |
| `wgh up` | Connect and stay connected. Flags below. |
| `wgh down` | Stop a running `wgh up`; the interface goes away. |
| `wgh status` | This device and every peer: path, endpoint, handshake, traffic. |
| `wgh exit <name>` / `wgh exit off` | Send internet traffic through a device, or stop. |
| `wgh rotate` | Switch this device to a new WireGuard key. |
| `wgh leave` | Leave the mesh and delete this device's key. |

`wgh up` flags, each remembered for next time:

| Flag | Meaning |
| --- | --- |
| `--exit-node NAME` | use that device for internet traffic (`""` turns it off) |
| `--advertise-routes 192.168.1.0/24` | share these LAN ranges (needs approval on the coordinator) |
| `--advertise-exit=true` | offer this device as an exit node (needs approval) |
| `--accept-routes=false` | ignore routes other devices share |
| `--hosts ""` | leave `/etc/hosts` alone |
| `--dry-run` | print what would be done, change nothing |

### How it works

- **Coordinator.** `wgh serve` keeps the device list, addresses and public keys
  in one `0600` file. Devices hold a long poll open to it, so changes reach them
  at once. The coordinator never sees a device's private key.
- **Pinned TLS.** The coordinator makes its own certificate. The join token
  carries a fingerprint of it, so a device only ever talks to your coordinator,
  with no certificate authority involved. Behind a reverse proxy that already
  does TLS, run `wgh serve --plain-http --url https://your.proxy` and devices
  check the proxy's normal certificate instead.
- **Direct first.** Every device tries every other one directly: the public
  address the relay saw it come from (that is the STUN-style part), its listen
  port on that address, and its LAN addresses, LAN first when two devices sit
  behind the same router. Whatever answers is used.
- **Relay when it has to.** Until a direct path answers, traffic goes through
  the relay on the coordinator. When a direct path appears, traffic moves onto
  it within seconds; if it breaks, it falls back.
- **Names.** wgh keeps a marked block in `/etc/hosts` with every device as
  `name` and `name.wgh`, and removes it on `wgh down`.
- **Exit node.** Internet traffic goes through the chosen device with policy
  routing (the same trick `wg-quick` uses), and the connection to the
  coordinator stays outside the tunnel. A device used as exit node needs a
  direct path; the relay itself can be the exit node with `wgh serve --exit`.
- **Shared routes.** A device can share its LAN (`--advertise-routes`). Once the
  coordinator approves, every other device can reach that LAN through it.
- **Removal and rotation.** Removing a device drops it from everyone at once.
  `wgh rotate` makes a new key on the device and switches over without
  rejoining.

Addresses come from `10.144.0.0/16` by default (`wgh serve --subnet` on first
start), picked so it does not clash with Tailscale's `100.64.0.0/10` if you
run both while you move over.

Every device also gets an IPv6 address in `fd77:6768::/64`, made from its
IPv4 one (`10.144.0.5` is `fd77:6768::a90:5`), so nothing new is stored.
Names resolve to both (`/etc/hosts` gets a second line, DNS answers AAAA),
shared routes may be IPv6 prefixes, and an exit node takes IPv6 too (`::/0`,
NATed out from the exit node's own address). Access rules and their filters
cover IPv6 the same way (`ip6tables`). On a host with IPv6 turned off, `wgh
up` logs it once and runs IPv4 only; a coordinator from before IPv6 keeps
the mesh IPv4 only. The relay forwards IPv6 between devices only with
`--exit`: turning on IPv6 forwarding makes Linux ignore router
advertisements, so if the server gets its own IPv6 that way, set
`net.ipv6.conf.<if>.accept_ra=2` first. The same goes for a Linux exit node
or a device sharing an IPv6 route.

### Phones

```sh
sudo wgh admin phone pixel          # add --exit to send all its traffic through the relay
```

Scan the QR code with the WireGuard app. The phone reaches every device
through the relay. Its key is made on the coordinator, because a phone cannot
run `wgh`, so the QR code holds a private key: do not screenshot or share it.

### Access rules

With no rules every device reaches every other one. To limit that, put
`acl.json` in the coordinator directory (`/var/lib/wgh/coordinator/`):

```json
{
  "groups": {"servers": ["pve1", "nas"], "admins": ["laptop"]},
  "rules": [
    {"from": ["group:admins"], "to": ["*"]},
    {"from": ["*"], "to": ["nas"]}
  ]
}
```

A rule lets its `from` devices open connections to its `to` devices, the LAN
routes they share and their use as an exit node included; replies always come
back. An entry is a device name, `group:NAME` or `*`. Anything not allowed is
blocked, in both places it could pass: each Linux device filters what comes in
on its interface (iptables chain `WGH-wgh0`), and the relay filters what it
forwards between devices, phones included (`WGH-wgh-relay`). The relay itself
stays reachable by every device.

The coordinator checks the file every few seconds and applies a change within
a few more. A file with a mistake is not applied: the previous rules stay and
`wgh admin acl` shows the error. Run `wgh admin acl check acl.json` before
copying a new file in. Names of devices that have not joined yet are allowed,
with a warning.

### Security notes

- A join token is a password for your mesh until it is used or expires. Send it
  privately. Tokens are one use and one hour unless you ask otherwise, and only
  their hash is stored.
- The admin commands talk to the coordinator over a unix socket that only root
  can open. There is no web admin page to expose.
- Traffic through the relay is decrypted and re-encrypted on the coordinator,
  because the relay is a WireGuard peer of both sides. Direct traffic is end to
  end. If you do not trust the machine that runs the relay, that matters (unlike
  Tailscale's relays, which only pass encrypted packets along).
- Device state lives in `/var/lib/wgh/agent.json` (mode `0600`, root's), and the
  coordinator's in `/var/lib/wgh/coordinator/`. Back up the coordinator
  directory; losing it means every device has to join again.

### Not done yet

The core works; these are not there yet:

- Devices behind two strict (symmetric) NATs never get a direct path and stay
  on the relay. No port prediction or birthday tricks yet.
- IPv4 only, inside the mesh and for endpoints.
- `wgh up` runs on Linux only. macOS and Windows join as phones for now.
- Names come from the hosts file, not a DNS server, so other machines on your
  LAN cannot look them up.
- Access rules work per device, not per port, and a device whose backend has
  no firewall (macOS) does not filter by itself; the relay still does.
- A device that is itself only reachable through the relay cannot be an exit
  node yet.
- Not tested on a real kernel by the automated tests, which run against a fake
  WireGuard backend. Tested by hand with `--dry-run`.

## The interface

```sh
sudo wgh                 # opens the TUI
wgh --state ./home.json  # the simple server for another site
```

It shows tabs for what this machine runs:

- **Devices** (after `wgh join`): every device with its path (direct, relay or
  offline), endpoint, last handshake and traffic. `x` uses the selected device
  as exit node, `X` turns that off, `R` switches to a new key.
- **Admin** (on the coordinator): every device, last seen, and what waits for
  approval. `t` makes a join token, `p` adds a phone and shows its QR code, `a`
  approves, `d` removes.
- **Simple server** (when there is a simple-server state file).
- **Start** when none of these exist yet: join a mesh by pasting a token, read
  how to run a coordinator, or set up a simple server.

`tab` or the number keys switch tabs, `?` lists the keys of the tab you are on,
`q` quits. Anything that removes, approves or changes a key asks first. The
interface reads the running `wgh up` and `wgh serve` over their local sockets,
so it needs the same user they run as (usually root).

On start the TUI checks GitHub once for a newer release and shows a badge if
there is one. It never installs anything by itself. Turn the check off with
`wgh --no-update-check` or `WGH_NO_UPDATE_CHECK=1`.

## Updating

```sh
wgh update          # download, verify and install the latest release
wgh update --check  # only say whether there is one
```

`wgh update` finds the latest release of `overspend1/wgh`, downloads the
binary for your OS and CPU, checks it against that release's `checksums.txt`,
makes sure the new binary runs, then swaps it in atomically (following a
symlink to the real file). If the download or the check fails, the old binary
is left alone. It uses GitHub's plain download URLs, not the API, so it needs
no token. A binary you built yourself reports version `dev` and is only
replaced with `--force`.

If wgh lives somewhere only root can write, such as `/usr/local/bin`, run
`sudo wgh update`, or just run the install script again.

## Simple server

The original wgh: one classic WireGuard server and its peers, as config files
and QR codes. It only ever writes files. It never touches a network interface,
never calls `wg` or `ip`, and never needs root. You copy the server config to
the box that runs WireGuard (an OpenWrt router, a Proxmox LXC, any Linux host)
yourself.

- Keys are generated natively (Curve25519, clamped exactly like `wg genkey`).
- State lives in one JSON file, mode `0600`, in a `0700` directory.
- Every exported config and QR PNG is also written `0600`, atomically.

In the TUI, with no simple-server state yet, choose **Simple server** on the
Start tab to get a setup form: endpoint, subnet, port, interface, DNS and NAT
interface. Leave a field blank to take the default shown in grey. After that
you land on the peer list.

| Key | Action |
| --- | --- |
| `a` | add a peer; its QR code opens straight away |
| `d` | remove the selected peer (asks first) |
| `enter` | show the selected peer's client config |
| `r` | show the selected peer's QR code |
| `s` | show the server config |
| `e` | export the server and all client configs to a directory |
| `?` | help |
| `q`, `esc` | back, or quit from the list |

In forms, `tab` and the arrow keys move between fields, `space` flips a yes/no,
`enter` on the last field (or `ctrl+s` anywhere) submits. On the QR screen,
`p` saves a PNG of it to the current directory.

The QR code is always drawn white on black so phones can scan it whatever your
terminal theme. It needs a window of roughly 70 by 38; if yours is smaller, the
screen says so and you can save the PNG instead.

### Quick start (subcommands)

```sh
# 1. Create the server: a dynamic DNS name or public IP, plus the LAN
#    interface to NAT out of if you want full-tunnel clients to reach the internet.
wgh init --endpoint vpn.example.com --dns 192.168.1.53 --nat-iface eth0

# 2. Add peers. Each gets the next free address and its own preshared key.
wgh add phone --qr                       # prints the QR straight away
wgh add laptop --allowed-ips 10.8.0.0/24,192.168.1.0/24   # split tunnel
wgh add pve1 --ip 10.8.0.50 --keepalive 0

# 3. Write everything out.
wgh export --dir ./wg-out --qr
#   ./wg-out/wg0.conf            -> /etc/wireguard/wg0.conf on the server
#   ./wg-out/peers/phone.conf    -> import on the client
#   ./wg-out/peers/phone.png     -> scan with the WireGuard app

# 4. On the server (wgh does not do this for you):
#    sudo install -m 600 wg-out/wg0.conf /etc/wireguard/wg0.conf
#    sudo systemctl enable --now wg-quick@wg0
#    and forward UDP 51820 on your router to that host.
```

After adding or removing a peer, export again and reload the server
(`sudo systemctl restart wg-quick@wg0`, or `wg syncconf wg0 <(wg-quick strip wg0)`
to apply without dropping existing sessions).

### Commands

| Command | What it does |
| --- | --- |
| `wgh init` | Create the server keys and settings. Refuses to overwrite unless `--force`. |
| `wgh add <name>` | Add a peer with the next free address. |
| `wgh list` | Show the server line and a table of peers. |
| `wgh remove <name>` | Delete a peer. Its address becomes free again. |
| `wgh show <name> [-o file]` | Print a peer's client config, or write it (mode 0600). |
| `wgh qr <name> [--png file]` | Print the client config as a terminal QR code; optionally save a PNG. |
| `wgh server` | Print the server config. |
| `wgh export --dir DIR [--qr]` | Write `DIR/<interface>.conf` and `DIR/peers/<name>.conf` (and PNGs). |
| `wgh` or `wgh tui` | Open the full-screen interface. |
| `wgh update [--check] [--force]` | Install the latest release, after verifying it. |
| `wgh version` | Print the version. |

Flags can go before or after the peer name. `wgh <command> -h` lists them.

#### `init` flags

| Flag | Default | Notes |
| --- | --- | --- |
| `--endpoint` | (required) | Host or IP clients dial. `host:port` overrides the port in client configs only (useful behind a port forward). IPv6 literals are bracketed for you. |
| `--subnet` | `10.8.0.0/24` | IPv4 tunnel subnet, `/30` or larger. |
| `--port` | `51820` | UDP listen port. |
| `--interface` | `wg0` | Used for the server config's file name. |
| `--address` | first host | Server's tunnel address, `10.8.0.1` by default. |
| `--dns` | none | DNS for clients, e.g. a Pi-hole. Peers can override. |
| `--nat-iface` | none | Adds iptables forward and MASQUERADE rules to `PostUp`/`PostDown`. Leave it out on OpenWrt, where the firewall zone does this. |
| `--mtu` | unset | Written to both server and client configs. |
| `--force` | false | Replace an existing state file. This throws away every key in it. |

#### `add` flags

| Flag | Default | Notes |
| --- | --- | --- |
| `--ip` | next free | Pick an address yourself. Must be free and inside the subnet. |
| `--psk` | `true` | Preshared key per peer (extra symmetric layer). `--psk=false` to skip. |
| `--allowed-ips` | `0.0.0.0/0, ::/0` | Full tunnel by default. Use your tunnel and LAN subnets for split tunnel. |
| `--dns` | server's | Per-peer DNS override. |
| `--keepalive` | `25` | Keeps NAT mappings alive for phones. `0` disables. |
| `--qr` | false | Print the QR code right after adding. |

### State file

Default path, in order: `--state PATH`, `$WGH_STATE`,
`$XDG_CONFIG_HOME/wgh/state.json` (usually `~/.config/wgh/state.json`).

It holds every private key in plain JSON, so treat it like an SSH key: keep it
`0600` (wgh does), back it up somewhere encrypted, and do not commit it. Keep a
separate state file per site with `--state` or `WGH_STATE`.

```json
{
  "version": 1,
  "server": {
    "interface": "wg0",
    "subnet": "10.8.0.0/24",
    "address": "10.8.0.1",
    "listen_port": 51820,
    "endpoint": "vpn.example.com",
    "private_key": "...",
    "public_key": "...",
    "dns": ["192.168.1.53"]
  },
  "peers": [
    {
      "name": "phone",
      "address": "10.8.0.2",
      "private_key": "...",
      "public_key": "...",
      "preshared_key": "...",
      "allowed_ips": ["0.0.0.0/0", "::/0"],
      "persistent_keepalive": 25,
      "created_at": "2026-11-10T10:00:00Z"
    }
  ]
}
```

### Address allocation

The server takes the first host address (`.1`). Each new peer gets the lowest
free host address, so a removed peer's address is reused first. The network and
broadcast addresses are never handed out. A `/24` holds the server plus 253
peers; adding past that fails with a clear error.

### Limits and choices

- IPv4 tunnel subnet only. Clients can still route `::/0` through it.
- No locking: do not run two `wgh` commands against the same state file at once.
- Client private keys are generated here, not on the device. That is what makes
  the one-scan QR flow work; if you would rather a device keep its own key,
  that is a small addition (an `--pubkey` flag on `add`).
- QR codes contain the client's private key. Do not screenshot or share them.
- If a phone cannot read the QR printed by `wgh qr` on a light terminal, try
  `wgh qr <name> --invert`, or use the PNG.

## Build

```sh
go build -o wgh ./cmd/wgh
```

All release binaries at once, into `dist/` with checksums:

```sh
sh scripts/build-release.sh v0.1.0
```

A fully static, stripped binary (works on any Linux, including Alpine-based
containers):

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=0.1.0" -o wgh ./cmd/wgh
```

Cross-compile for a router, for example a MIPS or ARM OpenWrt box:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o wgh-arm64 ./cmd/wgh
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -o wgh-mipsle ./cmd/wgh
```

Run the tests:

```sh
go test ./...
```

## Layout

```
cmd/wgh/            CLI and end-to-end test
scripts/            release build script
contrib/systemd/    units for 'wgh serve' and 'wgh up'
install.sh          one-line installer
.github/workflows/  tests on push, release builds on v* tags
internal/mesh/      shared types, join tokens, names
internal/coord/     the coordinator: device list, API, relay, admin socket
internal/acl/       access rules (acl.json): parsing and matching
internal/agent/     the device side: join, long poll, path choice, hosts file
internal/wgctl/     drives WireGuard with ip, wg and iptables (plus a fake for tests)
internal/keys/      key generation (tested against RFC 7748 vectors)
internal/ipam/      address allocation
internal/state/     JSON state, 0600 atomic writes
internal/render/    server and client .conf rendering
internal/app/       operations shared by the CLI and the TUI
internal/tui/       Bubble Tea interface and the red theme
internal/update/    self-update from GitHub releases
```
