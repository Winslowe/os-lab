#!/usr/bin/env bash
# Run one real XCUITest session (Appium + WebDriverAgent) against the booted simulator.
#
#   xcuitest.sh smoke    create a session, launch an app, close it: proves the whole chain
set -euo pipefail

. "$(dirname "$0")/lib.sh"
require_macos
require_xcode

ACTION="${1:-smoke}"

APPIUM_PREFIX="${OSLAB_APPIUM_HOME:-$HOME/.oslab/appium}"
MANAGED_BIN="$APPIUM_PREFIX/node_modules/.bin/appium"
appium_bin() {
  if [ -x "$MANAGED_BIN" ]; then echo "$MANAGED_BIN"; else command -v appium 2>/dev/null || true; fi
}

progress() { printf '##PROGRESS %s/%s %s\n' "$1" "$2" "$3"; say "$3"; }

first_booted() {
  xcrun simctl list devices 2>/dev/null \
    | awk '/Booted/ { for (i = 1; i <= NF; i++) if ($i ~ /^\([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\)$/) { gsub(/[()]/, "", $i); print $i; exit } }'
}

case "$ACTION" in
  smoke)
    TOTAL=4
    progress 1 $TOTAL "Checking the automation stack"
    UDID="$(first_booted)"
    [ -n "$UDID" ] || die "no booted simulator; attach one in the iOS Lab first"
    NAME="$(xcrun simctl list devices | grep -F "($UDID)" | head -1 | sed -E 's/^ +//' | sed -E 's/ \(.*//')"
    APPIUM="$(appium_bin)"
    [ -n "$APPIUM" ] || die "Appium is not installed; use Install Appium in the iOS Lab page"
    if [ -x "$MANAGED_BIN" ]; then export APPIUM_HOME="$APPIUM_PREFIX/home"; fi
    "$APPIUM" driver list --installed 2>/dev/null | grep -q xcuitest \
      || die "the Appium XCUITest driver is not installed; run Install Appium again"
    curl -fsS --max-time 2 "http://${APPIUM_HOST}:${APPIUM_PORT}/status" >/dev/null 2>&1 \
      || die "Appium is not running on ${APPIUM_HOST}:${APPIUM_PORT}; start it first (Start Appium)"

    progress 2 $TOTAL "Preparing the XCUITest session for $NAME"
    CAPS="$(SIM_NAME="$NAME" SIM_UDID="$UDID" python3 -c '
import json, os
print(json.dumps({"capabilities": {"alwaysMatch": {
    "platformName": "iOS",
    "appium:automationName": "XCUITest",
    "appium:deviceName": os.environ["SIM_NAME"],
    "appium:udid": os.environ["SIM_UDID"],
    "appium:bundleId": "com.apple.Preferences",
}}}'))"

    progress 3 $TOTAL "Creating the XCUITest session (first run may build WebDriverAgent)"
    RESPONSE="$(curl -fsS --max-time 1500 -X POST "http://${APPIUM_HOST}:${APPIUM_PORT}/session" \
      -H "Content-Type: application/json" -d "$CAPS")" \
      || die "the XCUITest session failed; see the Appium log (artifacts/appium.log)"
    SESSION_ID="$(printf '%s' "$RESPONSE" | python3 -c 'import json, sys; print(json.load(sys.stdin)["value"]["sessionId"])' 2>/dev/null || true)"
    [ -n "$SESSION_ID" ] || die "Appium did not return a session id; see the Appium log (artifacts/appium.log)"

    progress 4 $TOTAL "Closing the session"
    curl -fsS --max-time 30 -X DELETE "http://${APPIUM_HOST}:${APPIUM_PORT}/session/$SESSION_ID" >/dev/null 2>&1 || true
    say "XCUITest smoke passed: session $SESSION_ID on $NAME ($UDID)"
    ;;
  *)
    die "usage: $0 smoke"
    ;;
esac
