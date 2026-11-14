#!/usr/bin/env bash
# Check the native macOS lab: Xcode, simulators, Appium and resources.
set -uo pipefail

. "$(dirname "$0")/lib.sh"
require_macos

FAIL=0
ok()   { printf '  [ok]   %s\n' "$*"; }
warn() { printf '  [warn] %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

say "host"
ok "$(sw_vers -productName) $(sw_vers -productVersion) ($(uname -m))"
ok "cpu: $(sysctl -n hw.ncpu) cores"
MEM_GB=$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
if [ "$MEM_GB" -lt 16 ]; then warn "memory: ${MEM_GB} GB (16 GB+ recommended for Xcode + Simulator)"; else ok "memory: ${MEM_GB} GB"; fi
DISK_AVAIL="$(df -h "$LAB_DIR" | awk 'NR==2 {print $4}')"
ok "disk free: $DISK_AVAIL"
if [ "$(uname -m)" = "arm64" ]; then ok "Apple Silicon: native arm64 simulators"; else warn "Intel Mac: newest supported simulators depend on the installed macOS/Xcode"; fi

say "xcode"
if command -v xcodebuild >/dev/null 2>&1 && xcodebuild -version >/dev/null 2>&1; then
  ok "$(xcodebuild -version | tr '\n' ' ')"
  ok "developer dir: $(xcode-select -p)"
else
  bad "Xcode or the command line tools are missing; run: xcode-select --install"
fi

say "simulators"
if command -v xcrun >/dev/null 2>&1 && xcrun simctl list runtimes >/dev/null 2>&1; then
  RUNTIMES="$(xcrun simctl list runtimes 2>/dev/null | grep -c '^iOS ' || true)"
  if [ "$RUNTIMES" -eq 0 ]; then
    warn "no iOS runtimes installed; open Xcode > Settings > Components"
  else
    ok "$RUNTIMES iOS runtime(s)"
    xcrun simctl list runtimes 2>/dev/null | grep '^iOS ' | sed 's/^/       /'
  fi
  DEVICE="$(pick_device "$SIM_DEVICE")"
  if [ -n "$DEVICE" ]; then ok "selected device: $DEVICE"; else bad "no simulator devices available"; fi
  BOOTED="$(booted_devices)"
  if [ -n "$BOOTED" ]; then printf '%s\n' "$BOOTED" | sed 's/^/       /'; else warn "no booted simulator"; fi
else
  bad "simctl is unavailable"
fi

say "appium"
if command -v node >/dev/null 2>&1; then ok "node: $(node --version)"; else warn "node not found (brew install node)"; fi
if command -v appium >/dev/null 2>&1; then
  ok "appium: $(appium --version 2>/dev/null || echo present)"
  if appium driver list --installed 2>/dev/null | grep -q xcuitest; then ok "xcuitest driver installed"; else warn "xcuitest driver missing (appium driver install xcuitest)"; fi
else
  warn "appium not found (npm install -g appium)"
fi
if curl -fsS --max-time 2 "http://${APPIUM_HOST}:${APPIUM_PORT}/status" >/dev/null 2>&1; then
  ok "Appium is listening on ${APPIUM_HOST}:${APPIUM_PORT}"
else
  warn "Appium is not running on ${APPIUM_HOST}:${APPIUM_PORT}"
fi

say "idb"
IDB_BIN="$(command -v idb 2>/dev/null || true)"
if [ -z "$IDB_BIN" ] && [ -x "$HOME/.oslab/idb/bin/idb" ]; then IDB_BIN="$HOME/.oslab/idb/bin/idb"; fi
if [ -n "$IDB_BIN" ]; then ok "idb client: $IDB_BIN"; else warn "idb client not found (Install idb in the dashboard, or pipx install fb-idb)"; fi
if command -v idb_companion >/dev/null 2>&1; then ok "idb companion: present"; else warn "idb companion not found (brew install idb-companion)"; fi
if [ -f "$MAC_DIR/.idb-companion.pid" ] && kill -0 "$(cat "$MAC_DIR/.idb-companion.pid")" 2>/dev/null; then
  ok "idb companion is running (grpc :$IDB_PORT)"
else
  warn "idb companion is not running (make mac-idb)"
fi

say "config"
ok "device: $SIM_DEVICE"
ok "runtime: $IOS_RUNTIME"
ok "config file: $CONFIG"

echo
if [ "$FAIL" -eq 0 ]; then echo "macOS lab ready. Next: make mac-sim"; else echo "macOS lab has failures."; fi
exit "$FAIL"
