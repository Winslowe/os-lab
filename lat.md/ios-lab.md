# ios-lab

An iOS Simulator lab with two paths: a macOS VM in `dockurr/macos` on Ubuntu
Server, or native Xcode / `xcrun simctl` / Appium on real macOS (Apple's EULA
restricts macOS virtualization to Apple hardware).

See [[ios-lab]], the Ubuntu service [[ios-lab/docker-compose.yml]], the native
scripts [[ios-lab/mac]] and the runbook [[ios-lab/README.md]].

## Ubuntu path (macOS VM)

The `macos` service exposes a web viewer (:8006) and VNC (:5900) and requires
KVM, following the shared VM pattern.

Host provisioning is [[ios-lab/scripts/setup-ubuntu.sh]]; readiness is
[[ios-lab/scripts/wait-ready.sh]]; a GPU override is
[[ios-lab/docker-compose.gpu.yml]]. Research is in
[[ios-lab/knowledge/setup-ubuntu.md]].

## Native macOS path

On macOS the lab drives the real Simulator toolchain through `make -C ios-lab
mac-*`.

Environment checks [[ios-lab/mac/doctor-mac.sh]], setup
[[ios-lab/mac/setup-mac.sh]], simulator control [[ios-lab/mac/run-simulator.sh]]
and [[ios-lab/mac/stop-simulator.sh]], Appium [[ios-lab/mac/appium.sh]], idb
[[ios-lab/mac/idb.sh]] and the XCUITest smoke run
[[ios-lab/mac/xcuitest.sh]]; device presets in [[ios-lab/mac/profiles]].
`labctl` refuses the Ubuntu path on macOS — see [[labctl#Lab dispatch]].

Optional automation follows the same install/start/stop pattern as Appium:
`idb.sh install` puts the client in `~/.oslab/idb` and takes the companion
from Homebrew, `idb.sh start` runs a companion for the booted simulator, and
`xcuitest.sh smoke` creates a real XCUITest session through the running
Appium server to prove the whole chain. All three appear on the iOS and
macOS Lab pages as previewed actions and stay optional — the simulator runs
without them.

The dashboard's simulator panel (see [[dashboard]]) drives the same scripts:
`start` accepts a `device` (a UDID or unique name, validated against
`xcrun simctl` by the console) so the panel can boot the device picked in its
frame, and read-only `/api/labs/ios/simulator` and
`/api/labs/ios/screenshot` endpoints feed the panel's device list and live
screen.

## Research

The top iOS-in-Docker options, networking and operational limits.

They are documented across [[ios-lab/knowledge]] (docker-options, networking,
operations, usecases, references) and [[ios-lab/knowledge/setup-mac.md]].
