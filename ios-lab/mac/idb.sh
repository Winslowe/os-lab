#!/usr/bin/env bash
# Start, stop or inspect the idb companion for the booted iOS Simulator.
#
#   idb.sh install       install idb-companion (Homebrew) and the idb client for this user only
#   idb.sh start|stop|status
set -euo pipefail

. "$(dirname "$0")/lib.sh"
require_macos
require_xcode

ACTION="${1:-status}"
PID_FILE="$MAC_DIR/.idb-companion.pid"
LOG="$LAB_DIR/artifacts/idb-companion.log"
mkdir -p "$(dirname "$LOG")"

# idb companion comes from Homebrew; the client lives in its own virtualenv under ~/.oslab/idb,
# so no administrator rights, global site-packages or PATH changes are needed. A copy already
# on PATH keeps working.
IDB_PREFIX="${OSLAB_IDB_HOME:-$HOME/.oslab/idb}"
MANAGED_IDB="$IDB_PREFIX/bin/idb"
idb_bin() {
  if [ -x "$MANAGED_IDB" ]; then echo "$MANAGED_IDB"; else command -v idb 2>/dev/null || true; fi
}

progress() { printf '##PROGRESS %s/%s %s\n' "$1" "$2" "$3"; say "$3"; }

companion_running() {
  [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

first_booted_udid() {
  xcrun simctl list devices 2>/dev/null \
    | awk '/Booted/ { for (i = 1; i <= NF; i++) if ($i ~ /^\([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\)$/) { gsub(/[()]/, "", $i); print $i; exit } }'
}

case "$ACTION" in
  install)
    TOTAL=4
    progress 1 $TOTAL "Checking Homebrew"
    command -v brew >/dev/null 2>&1 || die "Homebrew is required for idb companion; install it from https://brew.sh, then try again"
    progress 2 $TOTAL "Installing idb companion"
    if command -v idb_companion >/dev/null 2>&1; then
      say "idb companion already installed"
    else
      brew install idb-companion
      hash -r
      command -v idb_companion >/dev/null 2>&1 || die "idb companion is still missing after the Homebrew install"
    fi
    progress 3 $TOTAL "Installing the idb client into $IDB_PREFIX"
    python3 -m venv "$IDB_PREFIX" 2>/dev/null || die "could not create the idb virtualenv at $IDB_PREFIX"
    "$IDB_PREFIX/bin/pip" install --quiet --upgrade pip
    "$IDB_PREFIX/bin/pip" install --quiet fb-idb
    progress 4 $TOTAL "Checking the install"
    "$MANAGED_IDB" --help >/dev/null 2>&1 || die "the idb client is not usable; see $LOG"
    say "idb is ready. Start it from the iOS Lab page (Start idb)."
    ;;
  start)
    UDID="$(first_booted_udid)"
    [ -n "$UDID" ] || die "no booted simulator; attach one in the iOS Lab first"
    IDB="$(idb_bin)"
    [ -n "$IDB" ] || die "the idb client is not installed; use Install idb in the iOS Lab page"
    if companion_running; then
      say "idb companion already running (pid $(cat "$PID_FILE")) on grpc port $IDB_PORT"
      "$IDB" connect "127.0.0.1" "$IDB_PORT" >/dev/null 2>&1 || true
      exit 0
    fi
    say "starting idb companion for $UDID on grpc port $IDB_PORT"
    nohup idb_companion --udid "$UDID" --grpc-port "$IDB_PORT" >"$LOG" 2>&1 &
    echo $! > "$PID_FILE"
    for ((i = 0; i < 30; i++)); do
      if "$IDB" connect "127.0.0.1" "$IDB_PORT" >/dev/null 2>&1; then
        say "idb ready: companion (pid $(cat "$PID_FILE")) connected to $UDID (log $LOG)"
        exit 0
      fi
      sleep 1
    done
    tail -20 "$LOG" >&2 || true
    die "idb companion did not become ready; see $LOG"
    ;;
  stop)
    if companion_running; then
      IDB="$(idb_bin)"
      if [ -n "$IDB" ]; then "$IDB" disconnect "127.0.0.1" "$IDB_PORT" >/dev/null 2>&1 || true; fi
      PID="$(cat "$PID_FILE")"
      kill "$PID" 2>/dev/null || true
      for ((i = 0; i < 15; i++)); do
        kill -0 "$PID" 2>/dev/null || break
        sleep 1
      done
      kill -9 "$PID" 2>/dev/null || true
      rm -f "$PID_FILE"
      say "idb companion stopped"
    else
      rm -f "$PID_FILE"
      say "idb companion is not running"
    fi
    ;;
  status)
    if companion_running; then
      say "idb companion running (pid $(cat "$PID_FILE")) on grpc port $IDB_PORT"
      IDB="$(idb_bin)" && "$IDB" list-targets 2>/dev/null | head -5 || true
    else
      say "idb companion is not running"
    fi
    ;;
  *)
    die "usage: $0 install|start|stop|status"
    ;;
esac
