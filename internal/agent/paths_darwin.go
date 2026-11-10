package agent

// RootDir is where root keeps wgh's state on this system. macOS has no
// /var/lib; "/Library/Application Support" is Apple's place for system-wide
// app data, exists on every Mac, is writable only by root and admins, and
// survives reboots. /usr/local/var is only a Homebrew convention on Intel
// Macs (Apple Silicon Homebrew uses /opt/homebrew) and may not exist.
const RootDir = "/Library/Application Support/wgh"
