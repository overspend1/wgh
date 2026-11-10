#!/bin/sh
# Build static wgh binaries for every release target into ./dist, plus a
# checksums.txt in sha256sum format. Used by the release workflow and can be
# run locally: scripts/build-release.sh v0.1.0
set -eu

version="${1:?usage: build-release.sh <version, e.g. v0.1.0>}"
out="dist"
rm -rf "$out"
mkdir -p "$out"

# name goos goarch extra-env
targets="
linux-amd64   linux  amd64
linux-arm64   linux  arm64
linux-armv7   linux  arm    GOARM=7
linux-armv6   linux  arm    GOARM=6
linux-mips    linux  mips   GOMIPS=softfloat
linux-mipsle  linux  mipsle GOMIPS=softfloat
darwin-amd64  darwin amd64
darwin-arm64  darwin arm64
"

echo "$targets" | while read -r name goos goarch extra; do
	[ -n "$name" ] || continue
	echo "building $name"
	env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" $extra \
		go build -trimpath -ldflags "-s -w -X main.version=${version#v}" \
		-o "$out/wgh-$name" ./cmd/wgh
done

cd "$out"
sha256sum wgh-* > checksums.txt
cat checksums.txt
