# wgh

A small WireGuard helper for a home network. Run `wgh` and you get a
full-screen interface, in WireGuard red, that sets up the server, adds and
removes peers, shows their configs and puts a QR code on screen for the phone
apps. Every action is also a plain subcommand for scripts.

It only ever writes files. It never touches a network interface, never calls
`wg` or `ip`, and never needs root. You copy the server config to the box that
runs WireGuard (an OpenWrt router, a Proxmox LXC, any Linux host) yourself.

- Single static Go binary.
- Keys are generated natively (Curve25519, clamped exactly like `wg genkey`).
- State lives in one JSON file, mode `0600`, in a `0700` directory.
- Every exported config and QR PNG is also written `0600`, atomically.
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

## The interface

```sh
wgh                      # opens the TUI (uses ~/.config/wgh/state.json)
wgh --state ./home.json  # another site
```

With no state file yet, it opens a setup form: endpoint, subnet, port,
interface, DNS and NAT interface. Leave a field blank to take the default shown
in grey. After that you land on the peer list.

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

## Quick start (subcommands)

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

## Commands

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

### `init` flags

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

### `add` flags

| Flag | Default | Notes |
| --- | --- | --- |
| `--ip` | next free | Pick an address yourself. Must be free and inside the subnet. |
| `--psk` | `true` | Preshared key per peer (extra symmetric layer). `--psk=false` to skip. |
| `--allowed-ips` | `0.0.0.0/0, ::/0` | Full tunnel by default. Use your tunnel and LAN subnets for split tunnel. |
| `--dns` | server's | Per-peer DNS override. |
| `--keepalive` | `25` | Keeps NAT mappings alive for phones. `0` disables. |
| `--qr` | false | Print the QR code right after adding. |

## State file

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

## Address allocation

The server takes the first host address (`.1`). Each new peer gets the lowest
free host address, so a removed peer's address is reused first. The network and
broadcast addresses are never handed out. A `/24` holds the server plus 253
peers; adding past that fails with a clear error.

## Limits and choices

- IPv4 tunnel subnet only. Clients can still route `::/0` through it.
- No locking: do not run two `wgh` commands against the same state file at once.
- Client private keys are generated here, not on the device. That is what makes
  the one-scan QR flow work; if you would rather a device keep its own key,
  that is a small addition (an `--pubkey` flag on `add`).
- QR codes contain the client's private key. Do not screenshot or share them.
- If a phone cannot read the QR printed by `wgh qr` on a light terminal, try
  `wgh qr <name> --invert`, or use the PNG.

## Layout

```
cmd/wgh/            CLI and end-to-end test
scripts/            release build script
install.sh          one-line installer
.github/workflows/  tests on push, release builds on v* tags
internal/keys/      key generation (tested against RFC 7748 vectors)
internal/ipam/      address allocation
internal/state/     JSON state, 0600 atomic writes
internal/render/    server and client .conf rendering
internal/app/       operations shared by the CLI and the TUI
internal/tui/       Bubble Tea interface and the red theme
internal/update/    self-update from GitHub releases
```
