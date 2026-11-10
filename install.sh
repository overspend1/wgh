#!/bin/sh
# Install wgh from its GitHub releases.
#
#   curl -fsSL https://raw.githubusercontent.com/overspend1/wgh/main/install.sh | sh
#
# Environment overrides:
#   WGH_VERSION      release tag to install, e.g. v0.1.0 (default: latest)
#   WGH_INSTALL_DIR  where to put the binary (default: /usr/local/bin if
#                    writable, else ~/.local/bin)
#   WGH_ARCH         skip detection, e.g. linux-mipsle
#
# It never uses sudo. To install system-wide, run it as root or point
# WGH_INSTALL_DIR at a directory you can write to.
set -eu

repo="overspend1/wgh"
version="${WGH_VERSION:-latest}"

say() { printf 'wgh-install: %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

# --- detect target -----------------------------------------------------------

is_little_endian() {
	# Byte 5 of an ELF header (EI_DATA) is 1 for little-endian, 2 for big-endian.
	for f in /bin/sh /bin/busybox /bin/ls; do
		[ -r "$f" ] || continue
		b=$(dd if="$f" bs=1 skip=5 count=1 2>/dev/null | od -An -tu1 | tr -d ' \n')
		case "$b" in
		1) return 0 ;;
		2) return 1 ;;
		esac
	done
	die "could not tell whether this MIPS CPU is big- or little-endian; set WGH_ARCH=linux-mips or linux-mipsle"
}

detect() {
	os=$(uname -s)
	arch=$(uname -m)
	case "$os" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) die "unsupported OS: $os" ;;
	esac
	case "$arch" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	armv7* | armv8l) arch=armv7 ;;
	armv6* | armv5*) arch=armv6 ;;
	mips | mipsel | mipsle)
		if is_little_endian; then arch=mipsle; else arch=mips; fi
		;;
	*) die "unsupported CPU: $arch (set WGH_ARCH to override)" ;;
	esac
	echo "$os-$arch"
}

target="${WGH_ARCH:-$(detect)}"
asset="wgh-$target"

# --- pick tools --------------------------------------------------------------

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	die "need curl or wget"
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	die "need sha256sum or shasum to verify the download"
fi

if [ "$version" = latest ]; then
	base="https://github.com/$repo/releases/latest/download"
else
	base="https://github.com/$repo/releases/download/$version"
fi

# --- download and verify -----------------------------------------------------

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t wgh)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $asset ($version)"
fetch "$base/$asset" "$tmp/$asset" || die "download failed: $base/$asset"
fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "download failed: $base/checksums.txt"

want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/checksums.txt")
[ -n "$want" ] || die "no checksum for $asset in checksums.txt"
got=$(sha256 "$tmp/$asset")
[ "$want" = "$got" ] || die "checksum mismatch for $asset (want $want, got $got)"
say "checksum ok"

# --- install -----------------------------------------------------------------

if [ -n "${WGH_INSTALL_DIR:-}" ]; then
	dir="$WGH_INSTALL_DIR"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
	dir=/usr/local/bin
else
	dir="${HOME:?HOME is not set}/.local/bin"
fi
mkdir -p "$dir" || die "cannot create $dir"
[ -w "$dir" ] || die "$dir is not writable; set WGH_INSTALL_DIR or run as a user who can write there"

chmod 0755 "$tmp/$asset"
mv "$tmp/$asset" "$dir/wgh"
v=$("$dir/wgh" version 2>/dev/null) || v="wgh ($target)"
say "installed $v to $dir/wgh"

case ":$PATH:" in
*":$dir:"*) ;;
*) say "note: $dir is not on your PATH; add it, e.g. export PATH=\"$dir:\$PATH\"" ;;
esac
