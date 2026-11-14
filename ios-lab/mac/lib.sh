#!/usr/bin/env bash

MAC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$MAC_DIR/.." && pwd)"
CONFIG="$MAC_DIR/config.env"

if [ ! -f "$CONFIG" ]; then
  cp "$MAC_DIR/config.env.example" "$CONFIG"
fi

set -a
. "$CONFIG"
set +a

SIM_DEVICE="${SIM_DEVICE:-iPhone 16 Pro}"
IOS_RUNTIME="${IOS_RUNTIME:-latest}"
APPIUM_HOST="${APPIUM_HOST:-127.0.0.1}"
APPIUM_PORT="${APPIUM_PORT:-4723}"
APPIUM_LOG="${APPIUM_LOG:-artifacts/appium.log}"
IDB_PORT="${IDB_PORT:-10882}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"

say() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_macos() {
  [ "$(uname -s)" = "Darwin" ] || die "this path is macOS only; use the Docker lab on Ubuntu Server"
}

require_xcode() {
  command -v xcodebuild >/dev/null 2>&1 || die "Xcode is not installed; run: xcode-select --install (then open Xcode once)"
  xcodebuild -version >/dev/null 2>&1 || die "Xcode is present but not usable; open Xcode and accept the licence"
}

available_devices() {
  xcrun simctl list devices available 2>/dev/null
}

pick_device() {
  local wanted="$1" found
  found="$(available_devices | awk -v d="$wanted" 'index($0, "    " d " (") == 1 { print d; exit }')"
  if [ -z "$found" ]; then
    found="$(available_devices | awk '/^    iPhone/ { sub(/ \(.*/, ""); sub(/^    /, ""); print; exit }')"
  fi
  if [ -z "$found" ]; then
    found="$(available_devices | awk '/^    / { sub(/ \(.*/, ""); sub(/^    /, ""); print; exit }')"
  fi
  printf '%s' "$found"
}

booted_devices() {
  xcrun simctl list devices 2>/dev/null | grep 'Booted' || true
}
