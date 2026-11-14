#!/usr/bin/env bash
# Boot an iOS Simulator (optionally a --device UDID or name) and open Simulator.app.
set -euo pipefail

. "$(dirname "$0")/lib.sh"
require_macos
require_xcode

SELECTED=""
while [ $# -gt 0 ]; do
  case "$1" in
    --device) [ $# -ge 2 ] || die "--device needs a UDID or device name"; SELECTED="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [ -n "$SELECTED" ]; then
  # The console passes a UDID it verified against the installed devices.
  DEVICE="$SELECTED"
  xcrun simctl list devices | grep -F "($DEVICE)" >/dev/null || die "no installed simulator device matches $SELECTED"
else
  DEVICE="$(pick_device "$SIM_DEVICE")"
  [ -n "$DEVICE" ] || die "no installed simulator device found; open Xcode > Settings > Components"
fi

say "booting $DEVICE"
# A name is listed as "Name (UDID)"; a UDID appears inside its parentheses.
if xcrun simctl list devices | grep -F -e "$DEVICE (" -e "($DEVICE)" | grep -q Booted; then
  say "$DEVICE is already booted"
else
  xcrun simctl boot "$DEVICE" 2>/dev/null || true
fi

open -a Simulator
say "waiting for boot (timeout ${BOOT_TIMEOUT}s)"
if ! xcrun simctl bootstatus "$DEVICE" -b >/tmp/ios-lab-bootstatus.log 2>&1; then
  tail -20 /tmp/ios-lab-bootstatus.log >&2 || true
  die "simulator did not finish booting"
fi
NAME="$DEVICE"
if [[ "$DEVICE" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]]; then
  NAME="$(xcrun simctl list devices | grep -F "($DEVICE)" | head -1 | sed -E 's/^ +//' | sed -E 's/ \(.*//')"
fi
printf '%s\n' "$NAME" > "$MAC_DIR/.sim-device"
say "$NAME is ready"
echo "    open Simulator.app to interact"
echo "    Appium: make mac-appium"
