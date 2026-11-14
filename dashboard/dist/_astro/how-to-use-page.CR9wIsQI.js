import{r as e}from"./rolldown-runtime.XKyaHtl9.js";import{t}from"./react.B54jxNxs.js";import{N as n,_ as r,n as i,t as a}from"./top-bar.Dmuafl13.js";import{o}from"./ui.DRsgHKbD.js";import{t as s}from"./paths.C9SXvrhb.js";var c=e(t(),1),l={platforms:[{id:`macos`,label:`macOS`,installer:`Universal .dmg, notarized (Apple silicon and Intel)`,engine:`Native Xcode, containers for Android`},{id:`windows`,label:`Windows`,installer:`Setup .exe or .msi (x64), unsigned until code signing is approved`,engine:`WSL2 Linux distribution`},{id:`linux`,label:`Linux`,installer:`Debian, RPM or AppImage (amd64 and arm64)`,engine:`Docker or Podman with KVM`}],groups:[{id:`app`,title:`Desktop app and console`,description:`The app that wraps the dashboard and the local lab engine.`,items:[{id:`app-dashboard`,title:`Dashboard and lab engine`,summary:`The local web console, started by the app on a free 127.0.0.1 port.`,support:{macos:{level:`full`,note:`The app offers managed Python on first run; the console stays on this computer`},windows:{level:`full`,note:`The app offers managed Python on first run; the console stays on this computer`},linux:{level:`full`,note:`The app offers managed Python on first run; the console stays on this computer`}},children:[{id:`app-host`,title:`Host detection (OS, hardware, tools, KVM)`,support:{macos:{level:`full`,note:`Detected live`},windows:{level:`full`,note:`Detected live`},linux:{level:`full`,note:`Detected live`}}},{id:`app-jobs`,title:`Jobs with live output and cancel`,support:{macos:{level:`full`,note:`Plans are previewed before anything changes`},windows:{level:`full`,note:`Plans are previewed before anything changes`},linux:{level:`full`,note:`Plans are previewed before anything changes`}}},{id:`app-lang`,title:`8 interface languages`,support:{macos:{level:`full`,note:`English, Türkçe, Deutsch, Français, Español, Italiano, فارسی, العربية`},windows:{level:`full`,note:`English, Türkçe, Deutsch, Français, Español, Italiano, فارسی, العربية`},linux:{level:`full`,note:`English, Türkçe, Deutsch, Français, Español, Italiano, فارسی, العربية`}}}]},{id:`app-content`,title:`Signed content updates`,summary:`Companies, guides, legal text and Frida hooks, checked against an Ed25519 signature.`,support:{macos:{level:`full`,note:`Works offline from the bundled copy; updates only when you ask or on a check`},windows:{level:`full`,note:`Works offline from the bundled copy; updates only when you ask or on a check`},linux:{level:`full`,note:`Works offline from the bundled copy; updates only when you ask or on a check`}},children:[{id:`content-data`,title:`Data packs (companies, guides, legal)`,support:{macos:{level:`full`,note:`Installed automatically after a verified update`},windows:{level:`full`,note:`Installed automatically after a verified update`},linux:{level:`full`,note:`Installed automatically after a verified update`}}},{id:`content-hooks`,title:`Frida hooks`,support:{macos:{level:`full`,note:`Installed only when you tick the hooks option, every time`},windows:{level:`full`,note:`Installed only when you tick the hooks option, every time`},linux:{level:`full`,note:`Installed only when you tick the hooks option, every time`}}}]}]},{id:`labs`,title:`Labs`,description:`Each lab runs a guest or toolset. What a host can run depends on its OS, architecture and virtualization.`,items:[{id:`lab-android`,lab:`android`,title:`Android Lab`,summary:`Static and dynamic Android analysis: MobSF, JADX, mitmproxy, Frida.`,support:{linux:{level:`full`,note:`Containers; the emulator needs usable /dev/kvm`},windows:{level:`partial`,note:`Runs inside a WSL2 distribution; needs nested virtualization and working Docker or Podman there`},macos:{level:`partial`,note:`Containers, static profile only; the emulator needs a Linux/KVM host`}},children:[{id:`android-static`,title:`Static analysis (MobSF, JADX, secret scan, reports)`,support:{linux:{level:`full`,note:`Runs without KVM`},windows:{level:`partial`,note:`Runs inside a WSL2 distribution; needs nested virtualization and working Docker or Podman there`},macos:{level:`full`,note:`Lightweight profile in Docker or Podman`}}},{id:`android-dynamic`,title:`Dynamic emulator, mitmproxy and Frida`,support:{linux:{level:`full`,note:`Needs usable /dev/kvm`},windows:{level:`partial`,note:`Runs inside a WSL2 distribution; needs nested virtualization and working Docker or Podman there`},macos:{level:`none`,note:`No hardware acceleration for the emulator; use a Linux/KVM host`}}},{id:`android-adb`,title:`ADB devices and staged APKs`,support:{macos:{level:`full`,note:`Install Android Debug Bridge from the setup action`},windows:{level:`full`,note:`Install Android Debug Bridge from the setup action`},linux:{level:`full`,note:`Install Android Debug Bridge from the setup action`}}},{id:`android-hooks`,title:`Browse and run Frida hooks`,support:{macos:{level:`full`,note:`Hooks come from the bundled or downloaded content`},windows:{level:`full`,note:`Hooks come from the bundled or downloaded content`},linux:{level:`full`,note:`Hooks come from the bundled or downloaded content`}}}]},{id:`lab-ios`,lab:`ios`,title:`iOS Lab`,summary:`iOS Simulator and Appium, or a macOS VM for iOS tooling.`,support:{macos:{level:`full`,note:`Native Xcode Simulator; Appium is optional`},linux:{level:`partial`,note:`macOS VM on an x86_64 host with usable KVM`},windows:{level:`partial`,note:`macOS VM through WSL2; needs an x86_64 host`}},children:[{id:`ios-sim`,title:`iOS Simulator with Xcode`,support:{macos:{level:`full`,note:`Needs full Xcode, an iOS runtime and a simulator device`},linux:{level:`none`,note:`Xcode only runs on a Mac`},windows:{level:`none`,note:`Xcode only runs on a Mac`}}},{id:`ios-appium`,title:`Appium (XCUITest) automation`,support:{macos:{level:`full`,note:`Needs Node.js, Appium and its XCUITest driver`},linux:{level:`none`,note:`Needs a Mac`},windows:{level:`none`,note:`Needs a Mac`}}},{id:`ios-vm`,title:`macOS VM (dockurr/macos)`,support:{macos:{level:`none`,note:`Uses the native Simulator instead`},linux:{level:`partial`,note:`x86_64 only, with usable KVM`},windows:{level:`partial`,note:`Runs inside a WSL2 distribution; needs nested virtualization and working Docker or Podman there`}}}]},{id:`lab-macos`,lab:`macos`,title:`macOS Lab`,summary:`Native Xcode Simulator and Appium on a Mac.`,support:{macos:{level:`full`,note:`Uses this Mac's Xcode`},linux:{level:`none`,note:`Needs a Mac. Use the iOS Lab's macOS VM instead.`},windows:{level:`none`,note:`Needs a Mac. Use the iOS Lab's macOS VM instead.`}}},{id:`lab-windows`,lab:`windows`,title:`Windows Lab`,summary:`A Windows VM with a web desktop and RDP.`,support:{linux:{level:`full`,note:`x86_64 only; needs Docker or Podman and usable KVM`},windows:{level:`partial`,note:`Runs inside a WSL2 distribution; needs nested virtualization and working Docker or Podman there; x86_64 only`},macos:{level:`none`,note:`Needs a Linux/KVM host or Windows with WSL2. Use a remote Linux machine.`}}},{id:`lab-linux`,lab:`linux`,title:`Linux Lab`,summary:`A Linux VM with a web console and SSH.`,support:{linux:{level:`full`,note:`Needs Docker or Podman and usable KVM`},windows:{level:`partial`,note:`Runs inside a WSL2 distribution; needs nested virtualization and working Docker or Podman there`},macos:{level:`none`,note:`Needs a Linux/KVM host or Windows with WSL2. Use a remote Linux machine.`}}}]},{id:`learn`,title:`Learning content`,description:`Material that works the same everywhere because it needs no guest.`,items:[{id:`firewall`,title:`Firewall Lab`,summary:`BGT207 dream-company designs: branches, segmentation, products and rule sets.`,support:{macos:{level:`full`,note:`Pure content; companies can come from a signed update`},windows:{level:`full`,note:`Pure content; companies can come from a signed update`},linux:{level:`full`,note:`Pure content; companies can come from a signed update`}},children:[{id:`firewall-companies`,title:`Company pages and audits`,support:{macos:{level:`full`,note:`Open /firewall/ in the console`},windows:{level:`full`,note:`Open /firewall/ in the console`},linux:{level:`full`,note:`Open /firewall/ in the console`}}},{id:`firewall-langs`,title:`Eight languages`,support:{macos:{level:`full`,note:`Translations are drafts until reviewed`},windows:{level:`full`,note:`Translations are drafts until reviewed`},linux:{level:`full`,note:`Translations are drafts until reviewed`}}}]},{id:`legal`,title:`Legal and contribution guides`,summary:`Terms, acceptable use, privacy notice, third-party notices and how to contribute.`,support:{macos:{level:`full`,note:`Rendered from the repository's own Markdown`},windows:{level:`full`,note:`Rendered from the repository's own Markdown`},linux:{level:`full`,note:`Rendered from the repository's own Markdown`}}}]},{id:`source`,title:`Source Lab`,description:`Local source and package analysis.`,items:[{id:`source-static`,lab:`source`,title:`Source Lab`,summary:`Five-platform static detection and structural maps; optional browser tooling.`,support:{linux:{level:`full`,note:`Native Python 3.11+; no Docker or KVM required.`},macos:{level:`full`,note:`Native Python 3.11+; no Docker or KVM required.`},windows:{level:`full`,note:`Native Python 3.11+; no Docker or KVM required.`}}}]}]},u=`# os-lab operational technical cheatsheet

This entire reference is embedded in the generated prompt, alongside the exact
command inventory and capability catalog. It is public, shipped documentation,
not a report about the user's machine. Commands below assume a source checkout
root unless a working directory is given. Replace uppercase placeholders; never
run all examples as a single script. Choose only the operations needed for the
task and supported by the host. A packaged desktop app can run its bundled
runtime without a Git checkout; use its UI or explicitly locate that runtime
before proposing checkout-relative commands.

## 1. Host requirements and choosing an execution path

| Capability | Requirements and limits |
|---|---|
| Local console / desktop | Python 3.9+ for the shared console; Source specifically needs 3.11+. Desktop can offer managed CPython 3.12 on explicit request. No Node server runs in production. |
| Source static detection / maps | Native Python 3.11+, readable authorized targets and writable private storage. No Docker, KVM, Node, database or browser required. Git only for acquisition; tree-sitter grammars and Playwright/Chromium optional. |
| Linux-host Windows VM | Linux with accessible KVM, Docker/Podman + Compose, /dev/net/tun and NET_ADMIN; 32 GB free disk minimum, 64 GB+ recommended; at least 2 GB available RAM plus guest/host overhead. Configure licensed Windows media/version and credentials. |
| Linux VM | Same KVM/container requirements; 16 GB free disk minimum, 32 GB+ recommended; at least 2 GB available RAM plus overhead. BOOT selects distro/ISO. |
| Android dynamic emulator | Practical supported route: x86_64 Linux with VT-x/AMD-V and accessible KVM, Docker/Compose, ADB; documented host minimum 8 GB RAM / 20 GB free disk, recommended 16 GB / 40 GB+. ARM full emulation is not a practical equivalent. |
| Android static | No emulator or KVM needed for static work. MobSF/JADX/container workflows still need their respective tools/runtime; native Python helpers need their declared requirements and Java/JADX where used. |
| Native iOS/macOS | Real macOS, full Xcode, selected developer directory, accepted Xcode licence, downloaded iOS Simulator runtime and a matching device; optional Node/Appium + XCUITest for automation. Command Line Tools alone do not provide the Simulator. |
| iOS macOS VM | Compatible x86_64 KVM host, Docker/Compose, Apple hardware/licence compliance; preflight minimum 64 GB free disk and 4 GB available RAM, recommended 128 GB+ disk plus configured guest RAM. Xcode/Simulator installation inside the guest is manual. GPU path is opt-in and requires /dev/dri and compatible Vulkan hardware. |
| Firewall authoring / rendering | Python 3 standard library for validation/catalog/rendering; no VM needed to design or render. Optional firewall VM needs Linux/KVM/Compose; SSH client and optional sshpass for apply. |
| Public Pages | Static information site only. No local engine, target upload, VM controls or live host inventory. Prompt generation/copy runs in the browser. |

Run the relevant doctor/preflight: a catalog support label does not mean that
requirements are installed or a service is ready. Virtualization in firmware,+nested virtualization, group membership and Compose availability must be checked.
Refresh group membership after provisioning. Running containers and responding
viewers are different readiness stages from usable guests.

## 2. Installation, desktop launcher, updates and local UI

From a reviewed checkout:

\`\`\`sh
./scripts/setup/install.sh --report-only
./scripts/setup/install-macos.sh --report-only
# On Windows PowerShell:
.\\scripts\\setup\\install.ps1 -ReportOnly
\`\`\`

Choose the script for the actual host. Without report-only, installers can
install system prerequisites, fetch/update Git, prepare .venv and launch the
console. Shell options: --dir DIR, --branch NAME, --port N, --report-only,
--no-install, --no-run, --minimal, --update. PowerShell equivalents: -Dir,
-Branch, -Port, -ReportOnly, -NoInstall, -NoRun, -Minimal, -Update. Environment:
OSLAB_REPO, OSLAB_DIR, OSLAB_BRANCH, OSLAB_PORT; OSLAB_DASHBOARD_BUILD=0 skips
Node rebuilding. Minimal mode skips heavy Python package installs and uses the
committed dashboard. Re-running the installer is the supported checkout update
path; preserve a developer's branch and private state.

\`\`\`sh
./labctl ui --port 5050
# Without Bash, using a suitable Python interpreter:
python android-lab/lab/web_ui.py 5050
\`\`\`

Console URL: http://127.0.0.1:5050 by default; desktop chooses a free localhost
port. The desktop launcher resolves OSLAB_ROOT, a selected checkout, a debug
checkout, then its bundled runtime. It offers Get Python, Retry, Start installed
engine and, where supported, Get Docker Desktop. These require explicit user
actions; downloading an installer is not a finished installation or licence
acceptance. Continue to dashboard supports non-container labs. File → Container
setup reopens setup; File → Files folder selects an empty writable destination
and copies app data. Do not unplug that folder while the app uses it. Updates
preserve .env/config.env, storage and artifacts. Quitting the app stops its
console supervisor/process group, including jobs.

Use Workspace → This computer for live host readiness; Workspace → Jobs for
output and cancellation; Help → Health check for platform capability details.
Advanced settings exposes configured addresses/configuration; a configured URL
does not establish a running service. Spotlight uses Ctrl+K / Cmd+K; sidebar,
mobile drawer, eight interface languages, light/dark themes, feedback, legal and
contribution pages are provided. /classic/ is the fallback console. How to use
does not send tasks to an LLM, persist tasks or include live host data.

Reference: scripts/setup/README.md, app/README.md, dashboard/README.md.

## 3. Shared lifecycle, configuration, profiles and recovery

\`\`\`sh
./labctl help
./labctl all status
./labctl all doctor
./labctl LAB doctor
./labctl LAB profiles
./labctl LAB profile use development
./labctl LAB profile show
./labctl LAB config path
./labctl LAB config show
./labctl LAB start --wait
./labctl LAB status
./labctl LAB monitor --once
./labctl LAB logs -f
./labctl LAB urls
./labctl LAB stop
\`\`\`

LAB for VM dispatch is win, linux, ios or android (aliases in command inventory).
Source has its own verbs; it participates in all status/doctor/monitor, not VM
start/stop/restart/profile fan-out. macOS iOS dispatch uses native scripts.
VM profiles: lightweight, development, performance; profile use writes .env,
--profile NAME overlays it for one invocation. config set KEY=VALUE, unset KEY,
edit, get KEY and path are available. config show masks secrets; --reveal,
config get, Make env and connection-detail commands can expose credentials:
do not request their unsanitized output in an LLM prompt.

\`\`\`sh
./labctl win resize --cpus 4 --ram 8G --dry-run
./labctl win resize --cpus 4 --ram 8G --apply
make -C win-lab backup FULL=1
make -C win-lab restore FILE=backups/REVIEWED_BACKUP.tar.gz
\`\`\`

Resize may persist configuration and --apply recreates the container. Android
adds --device NAME. VM disks are persistent/grow-only; after disk expansion,
grow the guest partition/filesystem separately (APFS in macOS). The shared help
has historical Windows-only disk wording; Linux/iOS VM runbooks also document
disk expansion. Do not shrink disks or equate RAM allocation with host free RAM.
Backups are cold by default; FULL=1 includes shared data (Windows also OEM).
Restore moves existing storage aside in the OS VM labs. Review the archive,
destination and free space before confirming restore. install-service and
uninstall-service manage systemd boot units on supported Linux hosts.

Private layout: per-lab .env, storage/, shared/, backups/; Windows oem/ maps to
C:\\OEM and shared/ to guest Z:. Linux/iOS shares need the guest's documented
mount mechanism. Container shell is a wrapper/tools shell, not necessarily a
shell inside the guest OS. Make reset CONFIRM=yes destroys VM disks. In the
OS VM labs clean removes backups; Android clean removes analysis artifacts.
Preserve artifacts/backups before cleanup and obtain explicit confirmation for
destructive operations. Choose distinct host ports when multiple guests run:
Windows/Linux/iOS all default their web viewer to port 8006.

Reference: labctl, win-lab/README.md, linux-lab/README.md, ios-lab/README.md.

## 4. Windows and Linux guest operations

\`\`\`sh
make -C win-lab preflight
make -C win-lab prepare
make -C win-lab boot
make -C win-lab wait-install
make -C win-lab status
make -C win-lab rdp
make -C win-lab smb
make -C linux-lab preflight
make -C linux-lab prepare
make -C linux-lab boot
make -C linux-lab wait-ready
make -C linux-lab ssh
make -C linux-lab share
\`\`\`

prepare creates missing .env/data directories; edit credentials and resources
before boot. setup installs host prerequisites and changes groups (privileged).
boot waits for web viewer only. Windows readiness additionally requires
storage/windows.boot; Linux waits for SSH then writes storage/linux.ready.
Defaults (configured, not proven live): Windows web 8006 / RDP 3389 TCP+UDP;
Linux web 8006 / SSH host 2222 to guest 22. Bind or tunnel access locally;
do not expose them on an untrusted network.

Windows configuration covers VERSION, language/region/keyboard, resource/disk
settings, WINDOWS_USER/WINDOWS_PASSWORD, RDP/WEB ports, protected viewer, Samba,
OEM automation, media cleanup and shutdown timeouts. Linux covers BOOT distro
shortcut or ISO URL, BOOT_MODE, LINUX_USER/LINUX_PASSWORD, resource/disk settings
and SSH/WEB ports. For a local ISO bind ./boot.iso to /boot.iso as documented.
First boot can download large images/media. update pulls a newer container and
recreates it; restart/down stop/recreate according to each Make target. Check
logs and guest installation state before assuming an unreachable viewer means
analysis failure. Linux guest use cases include isolated ELF/reverse-engineering,
kernel/fuzzing and containment exercises, not unrestricted host execution.

## 5. Android static, dynamic, reverse engineering and diagnostics

Run make targets from android-lab/lab (or use make -C android-lab/lab).
Start with preflight and an appropriate mode in .env (LAB_MODE=static|dynamic).

\`\`\`sh
make -C android-lab/lab setup-python
make -C android-lab/lab platform-tools
make -C android-lab/lab static-up
make -C android-lab/lab wf1 APK=/path/to/OWNED.apk
make -C android-lab/lab boot
make -C android-lab/lab install APK=/path/to/OWNED.apk
make -C android-lab/lab wf2 APK=/path/to/OWNED.apk PKG=com.example.owned
make -C android-lab/lab hook PKG=com.example.owned HOOK=hooks/REVIEWED.js
make -C android-lab/lab report
\`\`\`

These are alternative task paths, not a sequence to run blindly. setup-python
creates the lab .venv/installs requirements; platform-tools downloads Google's
ADB/fastboot (not redistributed). OSLAB_NO_DOWNLOAD=1 prevents the automatic
platform-tool fetch. Static services use docker-compose.win.yml (MobSF,
mitmproxy, tools); dynamic adds the emulator. WF1 scans with MobSF, decompiles
with JADX and creates a report; WF2 boots/deploys the target and captures traffic,
with optional Frida instrumentation. Check actual runtime/tool availability;
Frida client/server/Gadget versions and APK ABI must match. Patched APKs need
signing and installation compatible with the target; attaching/debug/sandbox
access can require a debuggable app, appropriate device permissions or a rooted
disposable device. Never promise arbitrary private sandbox access on stock phones.

Python orchestrator prefix from checkout root:
\`python android-lab/lab/orchestrator.py COMMAND\` (activate the appropriate .venv).

| COMMAND and arguments | Result / additional requirement |
|---|---|
| preflight | Host tools and connectivity checks; may trigger documented tool acquisition unless downloads disabled. |
| wf1 --apk APK | Static pipeline; needs relevant scanning/decompilation tooling. |
| analyze-app --apk APK | Manifest/permission, crypto, WebView and other heuristic vulnerability analysis. |
| scan-secrets --target APK_OR_DIRECTORY | Secret pattern review; redact any findings before sharing. |
| generate-report --input APK_OR_ANALYSIS_JSON --out PRIVATE_DIRECTORY | Standalone HTML, Markdown and JSON report generation. |
| monitor --pkg PACKAGE --filter REGEX | Live logcat security monitor via ADB; both filters optional. |
| telemetry --pkg PACKAGE | Device/app memory/socket/battery snapshot; attached authorized device. |
| dump-sandbox --pkg PACKAGE | Sandbox extraction/audit with required device permissions. |
| fuzz-ipc --pkg PACKAGE | Exercises exported components; changes app/device behavior. Use disposable authorized targets. |
| patch-apk --apk APK --gadget | Modify network security / optional Gadget injection; preserve original APK. |
| agentic-plan --input APK_OR_ANALYSIS_JSON | Heuristic threat model/hypothesis and tailored hook generation; not a verified exploit or autonomous success. |
| parse-flows --file PRIVATE_FLOWS.mitm | Parse an existing mitmproxy capture; can contain sensitive traffic. |
| ui --port 5050 | Local browser console. |
| clean | Deletes artifacts; export wanted results first. |

Direct helper MobSF client:
\`python android-lab/lab/scripts/mobsf_client.py status --url http://127.0.0.1:8000\`,
\`start\`, or \`scan APK -o PRIVATE_REPORT.json\`. Supply credentials through the
documented private setup, never ask the user to paste API keys into a prompt.
app_analyzer.py also takes APK [OUTPUT_DIRECTORY] directly. The generated parser
inventory includes helper-specific flags and choices.

Configured Android endpoints: noVNC 6080, ADB 5555, MobSF 8000,
mitmproxy 8080 and its web UI 8081; use actual host report/configuration. Check
ADB devices, emulator boot-completed status, package ID, proxy/trust certificate
setup and capture freshness. Certificate pinning bypass/crypto hooks are for
owned or explicitly authorized test apps only. Emulator internet/traffic routing
does not imply a physical device is configured. DOCKER_ANDROID_ANALYTICS=false
is the default; keep it disabled unless the operator knowingly changes it.

Dashboard Android routes: /android/ overview/staged APKs; /labs/android/ runtime;
/android/providers/ devices/endpoints/hooks; /android/workflows/ actions;
/android/console/ output; /android/analytics/ reports;
/android/sitemap/ route map. APKs are in android-lab/lab/apks/ and private reports,
flows, dumps and analysis in android-lab/lab/artifacts/. Upload checks do not
establish trust in a binary. Download/export desired reports before cleaning.

Windows PowerShell alternative (working directory android-lab/lab):
\`.\\lab.ps1 preflight\`, \`setup\`, \`wf1 -Apk PATH\`, \`wf2 -Apk PATH -Pkg PACKAGE\`,
\`hook -Pkg PACKAGE -Hook PATH\`, \`trace-crypto -Pkg PACKAGE\`, \`report\`.
The generated inventory lists every accepted command/parameter, including
MobSF operations, VirtualBox lifecycle, vbox-deploy-android and Podman status.
VirtualBox/Podman must be available; userland/zero-admin workflows do not waive
host virtualization, installation or organizational permission requirements.
vbox-download-iso downloads media; vbox-autoinstall provisions a guest disk;
vbox-deploy-android installs the Android stack in that guest. VM -Memory is MB,
-Cpus is cores; -Gui changes the VM presentation. Preserve PowerShell 5.1 UTF-8
BOM when editing scripts. Follow README-WINDOWS.md for exact host model/setup.

Reference: android-lab/lab/README.md, README-UBUNTU.md, README-WINDOWS.md,
orchestrator.py, requirements.txt, hooks/, scripts/.

## 6. iOS Simulator, native macOS, Appium and macOS VM

\`\`\`sh
make -C ios-lab mac-doctor
make -C ios-lab mac-setup
make -C ios-lab mac-profiles
make -C ios-lab mac-profile PROFILE=iphone
make -C ios-lab mac-sim
make -C ios-lab mac-status
make -C ios-lab mac-appium
make -C ios-lab mac-appium-stop
make -C ios-lab mac-stop
\`\`\`

mac-setup checks Xcode; INSTALL=1 opts into Node/Appium installation as documented.
Device presets: iphone, ipad, legacy. ios-lab/mac/config.env selects SIM_DEVICE,
IOS_RUNTIME, APPIUM_HOST, APPIUM_PORT, APPIUM_LOG, BOOT_TIMEOUT. Native checks:
\`xcode-select -p\`, \`xcrun simctl list devices available\`,
\`xcrun simctl list runtimes\`; these do not install a missing Xcode/runtime.
Optional Appium requires XCUITest; default address 127.0.0.1:4723, configured
log artifacts/appium.log relative to the native lab. mac-stop shuts down
simulators; save test state first. Native scripts, appium install/start/stop
and available preset controls are gated by the actual host capabilities.

For the macOS VM path use ios-lab preflight/prepare/boot/status/web/vnc,
optionally up-gpu, plus lifecycle/backup/profile/service targets in the inventory.
Defaults: viewer 8006, VNC 5900, CPU 4 / RAM 8G / disk 128G (change to fit host).
MACOS_VERSION/MAC_MODEL/GPU/resources/ports are configuration, not proof a guest
is installed. boot waits only for viewer; complete macOS Setup Assistant and
install Xcode + Simulator runtime inside the guest manually. Native Simulator
is not a physical iPhone, and this integration is not a general iOS jailbreak
or physical-device instrumentation service. VM GPU/Apple-ID end-to-end validation
and automated Xcode/Appium setup inside the guest are not claimed complete.

Reference: ios-lab/README.md, ios-lab/mac/README.md,
ios-lab/knowledge/setup-mac.md, setup-ubuntu.md, networking.md, operations.md.

## 7. Source Lab: detection, source mapping, acquisition and evidence

Use the launcher so private storage defaults are correct:

\`\`\`sh
./labctl source doctor --json
./labctl source setup
./labctl source detect /path/to/AUTHORIZED_TARGET --platform browser-extension --format all
./labctl source detect /path/to/AUTHORIZED.apk --platform android-app --format sarif
./labctl source map --root /path/to/OWNED_SOURCE --out /path/to/private/repo-map.json --format json
./labctl source map query --map /path/to/private/repo-map.json --lang python --exported-only
./labctl source crawl OWNER/OWNED_REPO --workers 1 --depth 1 --keep-workspace
./labctl source crawl -i /path/to/authorized-list.csv --no-metadata
./labctl source merge --slugs owner__repo --no-clone --plan
./labctl source merge-csvs --sources /path/to/operator/catalogs --output-dir /path/to/private/catalogs
\`\`\`

On Windows without Bash replace ./labctl source with \`python source-lab/run.py\`.
doctor/status are read-only; setup only creates private directories, with no
package installation/download. SOURCE_LAB_PYTHON selects the console interpreter;
export SOURCE_LAB_STORAGE (default source-lab/storage), SOURCE_LAB_RESOURCES
(default storage/resources) in the caller. Source .env examples are never
evaluated as shell scripts. Console candidates are under private targets/ and
cloned-repos/; it does not accept arbitrary browser-submitted absolute paths.

Platform IDs: browser-extension, windows-app, macos-app, android-app, ios-app;
omit --platform for auto selection. Detection accepts target directory/package/
repository, --output DIRECTORY, --session DIRECTORY, --run-canary AUTHORIZED_URL,
--format all|json|sarif|markdown|stix. Outputs are per-target under analysis/:
analysis-v2.json/findings/coverage, H1-H5 scorecards and requested report files.
Do not mistake incomplete/static indicators for malicious behavior or verified
runtime injection. Coverage and limitations must accompany conclusions. STIX
export is CLI-only; five allowlisted report files can be served by the console.

Structural maps support Python, JS/TS, PHP, Rust, Swift, Objective-C, Kotlin,
Java and markup; disk/archive VFS includes supported packages/ASAR. Outputs
json/md/dot. Filters include language/kind/role/path/target, exported-only and
minimum role confidence; budgets include files, file KB, symbols and time.
Optional grammars improve extraction; fallback/binary-only limitations are
explicit. A source/AST/structural graph is navigation data, not observed behavior.

Crawler accepts explicit repo slugs/GitHub URLs/local directories, CSV/TXT/XLSX
lists or --scan-dir. Git is needed for acquisition; metadata may contact GitHub.
Use GITHUB_TOKEN/GH_TOKEN privately where needed; the CLI also accepts --token
but putting credentials in arguments/shell history/prompts is discouraged.
Options include workers/depth/retries/clone-timeout/api-max-wait, tree/AST caps,
resume, keep-workspace, no-ast/no-metadata/no-map and map filters/budgets. The
generated command inventory contains every parser flag. Launcher overrides
engine defaults with private analysis and workspace paths. Review stale artifacts
when using resume or skipping stages; use separate output roots for clean work.
CSV joins use operator-provided browser-extensions.csv/browser-extension-repos.csv
and crawler metadata, producing private catalogs without changing resource inputs.

Merger backend/CLI remains available: explicit slugs, name, MV2/MV3 selection,
no-clone, clone timeout, include-flagged and manifest-only --plan. Plan is not a
runtime test. Acquisition can contact networks if not disabled. Use resulting
extensions only in disposable authorized profiles. Further merger UI is skipped;
Skills, database integration, OpenAPI and third-party datasets/binaries are
excluded. Do not suggest those as installed os-lab Source capabilities.

Dashboard routes: /labs/source/ readiness; /source/ matrices/inspectors/CSV/JSON;
/source/analyzer/ crawler; /source/evidence/ detection/findings/coverage/sessions;
/source/deep-analysis/ source/AST/maps; /source/pipeline/ architecture/snapshots;
/source/brain/ graph/providers; /source/sources/ catalogs and join;
/source/settings/runtime/ keys/canary/verification; /source/docs/ guides.
Empty private targets/catalogs/providers are legitimate unavailable states.

Runtime evidence: separately install Playwright + Chromium only for live browser
canary work. IQ_SESSION_HMAC_KEY or IQ_SESSION_HMAC_KEY_FILE supplies at least
32 bytes; secrets must never enter prompt text, CLI arguments or version control.
Managed keys use private storage/mode 0600 where supported; environment-owned
keys are read-only to the UI. Preview/confirm generation or acknowledged rotation;
keep original keys for old sessions. Rotation does not re-sign old bundles.
Settings only configure a URL; they do not contact it. Detection with canary
explicitly contacts the target. Missing tooling/clean baseline may yield synthetic
events; failures yield collection_failed. Neither can confirm runtime behavior.

Sessions live under analysis/SLUG/runtime-sessions/SESSION/. Browsing does not
verify integrity. Explicit verify-session validates signed metadata/events and
hashes locally; it does not independently attest collector truth. Correlation
requires successful nonsynthetic collection, valid signatures and matching target/
platform. Four importer libraries (Windows PE-sieve/ETW; macOS dyld/swizzles;
Android process maps/threads/logcat; iOS dylibs/trampolines) take TargetIdentity,
output_root and import_session(...). They do not launch native collectors.

Brain provider contract: private storage/brain-data/manifest.json has date,
tabs [{id,label,file}] and optional providers source/history/flow/sequence/aiRules.
Graphs contain meta, nodes {id,label,type,data}, edges {source,target,...}.
Limits: 20,000 nodes/50,000 edges loaded; 100 nodes/page, at most 2,000 in-window
edges rendered. Missing providers are unavailable; dangling edges are counted,
duplicate IDs rejected. Source/history/flow/sequence/rules are plain static data.
Flow: 300 steps/eight nesting levels; diff: bounded 1,000 lines/side. Snapshot
metrics are recorded rankings; export includes the full loaded graph. No live
application stress provider is configured. Pipeline is a dated operator snapshot
or pinned architecture reference, never a claimed live analysis run.

Contracts:

\`\`\`sh
./labctl source contracts
./labctl source contracts --format typescript --out /path/to/private/contracts.ts
./labctl source contracts --check /path/to/analysis-v2.json --kind AnalysisV2
./labctl source contracts --check /path/to/repo-map.json --kind RepoMapV1
\`\`\`

Opt-in legacy import defaults to a no-copy dry run:

\`\`\`sh
./labctl source import-legacy --source /path/to/owned/analysis --slug owner__repo
./labctl source import-legacy --source /path/to/owned/analysis --slug owner__repo --copy --authorized --expected-plan REVIEWED_FINGERPRINT
./labctl source import-legacy --rollback IMPORT_ID
./labctl source import-legacy --rollback IMPORT_ID --copy --authorized --expected-plan REVIEWED_ROLLBACK_FINGERPRINT
\`\`\`

Import only reviewed allowed report/map/AST/signed-session artifacts, never whole
projects/workspaces, secrets, archives, datasets, databases, binaries or browser
profiles. Limits: 5 MB/file, 64 MB/import, 1,000 files. Sessions require the
original valid key already supplied privately; no key is imported. Existing
session IDs cannot be overwritten. Originals remain intact; private journals
control/imports/ and backups control/import-backups/ are retained. Rollback
refuses newer edits and retains backups/journals. After interruption review
rollback by journal ID before retrying.

Reference: source-lab/README.md, API.md, RUNBOOK.md, COLLECTORS.md, BRAIN.md,
IMPORT.md, INVENTORY.md, AUDIT.md. Native/manual and live browser verification
limits remain tracked as SRC-B01–SRC-B06 bonus work; do not claim they all passed.

## 8. Local API, previews, background jobs and limits

All engine routes require a localhost Host. POST/DELETE require X-OSLab: 1;
do not weaken these protections or expose the console publicly. Public Pages
has no API. Use the UI by default; technical API instructions require an actual
local console origin, not the Pages URL or an assumed port.

Host/catalog GETs: /api/health, /healthz, /api/host, /api/capabilities,
/api/labs/LAB/config, /api/labs/LAB/monitor, /api/jobs, /api/jobs/ID.
API lab IDs are android, windows, linux, ios, macos, source (the Windows CLI
alias win is not its API ID). Lab plan/start: POST /api/labs/plan with
{"request":{"lab":"LAB","action":"ACTION"}}, review returned token/plan,
then POST /api/labs/start with {"request":SAME_REQUEST,"token":"TOKEN"}.
Optional request fields are profile, cpus, ram, disk, device, wslDistro, backup
only where the selected action accepts them. Actions include doctor/setup/status,
start/stop/restart/logs/monitor/profile/resize/backup/service-install/service-uninstall;
native macOS offers its supported Simulator/Appium subset. Check the live action
list and readiness before choosing one. Cancel via
POST /api/jobs/ID/cancel. Check actual request types before scripting; do not
invent JSON fields from route names. Android workbench reads devices, apks,
hooks, reports/logs and exposes guarded run/stop/upload/log-clear routes.

Source operations use POST /api/source/ROUTE with
{"options":{...},"preview":true}; review {plan,token}, then send the same
options with token. Changed options/configuration invalidate previews. Accepted
starts return 202 {job}; read shared jobs for actual state/logs; conflicts 409.
One mutation holds the Source lock across processes until cleanup. Cancellation
or timeout kills the process tree; restart marks unfinished jobs interrupted.
Jobs retain at most 50 records privately under control/jobs.json (4 MB journal),
logs at most 4,000 lines/1 MB. A second console cannot cancel another's live job.
Partial output is not success; preserve it for review before retrying.

| Source route under /api/source | Supported technical operation |
|---|---|
| /detection | GET candidates/readiness/latest run; POST target candidate key, optional platform/runCanary/testUrl/session; DELETE matching jobId. |
| /evidence | GET summaries, or slug detail, or slug+session timeline. |
| /evidence/report | GET slug + allowlisted file; no STIX/keys/seals. |
| /analyzer | GET crawl state/report/sourceFiles/first 50 summary rows; POST sourceFile basename OR repos OR local target, plus bounded crawler options. |
| /analyzer/merged | GET matrices/bundles; export=json|csv. |
| /deep-analysis | GET repo and optional file, view=ast for indexed AST; POST bounded crawler/reanalysis options. |
| /deep-analysis/merge | GET jobs/reports, download=folder inspected ZIP, plan=1&slugs=... read-only command preview; POST slugs/name/includeFlagged/allowClone/mv/plan. Default API clone permission is false. |
| /settings/runtime | GET key status/canary/tooling; POST action generate-key (+ rotate=true acknowledgment), set-canary (+ testUrl), verify-session (+ slug/session). Never returns a key. |
| /sources | GET operator catalogs/downloads with origin=resources|generated; POST empty options to join private catalogs. |
| /brain, /brain/files/PATH | GET manifest or bounded allowlisted private provider JSON. |
| /pipeline | GET dated reference/operator snapshot with provenance. |
| /spotlight | GET q, section=evidence|deep-analysis|sources, limit=1..25. |

POST Source analyzer/deep-analysis/merge also accepts action=cancel or stop plus
jobId. Input caps: 64 KB bodies; sources discovery 100 files/1,000 scanned entries;
workers 1–8, depth 1–10, retries 1–5, clone timeout 1–600 sec, API wait 1–120 sec,
tree entries ≤50,000, AST files ≤1,000, map files ≤10,000, map time ≤120,000 ms.
Readers: 5 MB JSON/events file, 10 MB report, 16 MB aggregate, 100 targets/sessions,
500 returned events. Unsafe/duplicate/unknown parameters, symlink/reparse paths,
private names, unsupported formats and credential-bearing URLs are rejected.
CLI accepts some broader explicit output/path choices; do not assume CLI flags
are accepted as browser API fields. Consult source-lab/API.md for exact contracts.

## 9. Firewall design, validation, rendering and isolated apply

Company designs include branches/headcounts/bandwidth, VLAN/subnet/DMZ
segmentation, firewall products with justified sizing/prices, default policies,
ordered rules with mandatory notes, role-based VPN/bastion administration,
remote access and assigned monitoring ownership. Keep DHCP 67/68, DNS 53 and
NTP 123 requirements explicit; do not blindly deny base services. Size addresses
by devices, not people; verify current product/CVE/pricing claims externally.

\`\`\`sh
cp -r firewall-lab/templates/company firewall-lab/companies/OWNED-SLUG
python3 firewall-lab/scripts/validate.py OWNED-SLUG
python3 firewall-lab/scripts/build-seed.py
python3 firewall-lab/scripts/catalog.py
python3 firewall-lab/scripts/catalog.py --check
python3 firewall-lab/vm/scripts/render-rules.py OWNED-SLUG --branch BRANCH_ID --segment SEGMENT_ID --target table
python3 firewall-lab/vm/scripts/render-rules.py OWNED-SLUG --target ufw -o /path/to/reviewed-rules.sh
\`\`\`

Folder and company.json slug must agree (lowercase-kebab-case); fill schema
fields and write the design narrative in README.md. Renderer targets: ufw,
nft (Linux nftables), table (neutral policy). Appliance rules require translation
and validation for that appliance's actual packet filter; nftables output is not
directly compatible with every firewall product. Symbolic unknown endpoints can
be rendered as any with a note: resolve them before applying. Review order and
defaults. Rendering does not apply rules or establish a protected network.

Optional disposable VM:

\`\`\`sh
make -C firewall-lab/vm preflight
make -C firewall-lab/vm prepare
make -C firewall-lab/vm boot
make -C firewall-lab/vm wait-ready
make -C firewall-lab/vm render SLUG=OWNED-SLUG TARGET=ufw
make -C firewall-lab/vm apply SLUG=OWNED-SLUG TARGET=ufw
\`\`\`

Edit .env/credentials before boot; defaults viewer 8007 / SSH 2223 avoid the
other labs' common ports. Review shared/SLUG.ufw.sh or nft output before apply;
apply uses SSH/sshpass or prints manual steps. Verify inside the disposable
guest: sudo ufw status numbered, sudo ufw status verbose, /var/log/ufw.log;
for nftables inspect its ruleset. Protect administrative access against lockout.
Optional block-alert integration is documented via ufw-logger; it is not an
always-running bundled external service. reset destroys the firewall VM disk.

Reference: firewall-lab/README.md, schema/README.md, companies/README.md,
templates/company/, knowledge/, vm/README.md.

## 10. Signed content, app updates, contribution and diagnostics

This computer → Content updates offers check/update/reset; hooks require explicit
selection every time. Data packs contain firewall company/catalog/schema/guides,
iOS knowledge and legal text. Hooks are executable Frida scripts. Console,
dashboard, installers and engine code ship in app/source updates, not data packs.
Ed25519 manifest and per-file hashes are checked before installation; signature,
path, size or downgrade failures stop the update. Keep bundled content usable
offline. OSLAB_CONTENT_DIR selects overlay storage; OSLAB_CONTENT_OFFLINE=1
disables downloads. Reset removes the overlay and returns to bundled content.
API: GET /api/content/status, /companies, /file?path=...;
POST /api/content/check, /update ({"hooks":true} only on opt-in), /reset.
\`python3 console/content.py status|check|update|reset\` gives the terminal
interface; add --hooks to update only on explicit selection.

Desktop/app updates have separate check/install actions and platform-specific
packages/updater signatures. Verify the selected release's signing status; an
updater signature does not imply Windows Authenticode. Do not fabricate a new
release version, signing approval or successful install. Application updates
preserve private state; back it up separately. Developer build requirements:
Node 22+, Rust 1.85+, platform Tauri prerequisites, suitable Python; in app/:
npm ci, npm run stage, npm run dev, npm run build, npm run test:stage,
then cargo test in app/src-tauri. Building/publishing is a maintainer operation;
never put signing credentials in an LLM prompt.

Read-only diagnostics from linux-lab/: scripts/bonus/env-doctor.sh checks names/
missing/empty/duplicate env keys without printing values; port-check.sh checks
loopback port availability; ssh-config-doctor.sh checks HostName/IdentityFile/
key permissions; shell-lint.sh checks syntax and optional ShellCheck advisories;
md-linkcheck.sh checks local Markdown targets; secret-scan.sh --staged reports
redacted credential-pattern matches. Exit codes: 0 clean, 1 finding, 2 usage/I/O
error. These helpers do not fix the host or establish service readiness.

Contribute via /contribute/, CONTRIBUTING.md, task reservations and documented
tests; Source bonus tasks remain distinct from course exam options. Feedback
offers issue/feature templates, discussions and private vulnerability reporting.
Never publish private reports or keys as reproduction evidence. Required change
checks depend on scope: scripts/run-tests.sh (Python suites, shell syntax, graph,
dashboard freshness), dashboard npm run check/test:i18n/build/test:e2e,
lat check after graph edits. Source tests run separately from Android tests;
portable acceptance.py tests five static analyzers without optional dependencies
but does not prove native GUI/live collection acceptance. Public Pages uses
scripts/deploy-page.sh and must be checked after its route filters, including
locale/base paths and absence of engine requests. Do not instruct a normal
operator to publish releases/deployments to accomplish unrelated lab work.

## 11. Troubleshooting, privacy, interpretation and safe completion

- KVM permission failure: inspect /dev/kvm, firmware virtualization/nested support,
  kvm group and refreshed login. Container failure: check engine running, Compose
  provider, docker group/authorization and available disk. Do not default to
  privileged containers or bypass access controls as a universal fix.
- Port conflict: inspect actual host listeners, choose unused ports in .env and
  recreate only the affected service. For remote hosts use approved SSH tunnels
  to loopback services; do not expose web/RDP/ADB/VNC/Appium/MobSF/proxy publicly.
- Guest stuck installing: inspect container logs, ISO/network/disk, guest setup
  and actual install marker; HTTP 200 alone is insufficient. macOS native failures
  need full Xcode, correct developer directory, available runtime/device and
  optional Appium driver. Simulator and physical-device support are different.
- Android failures: check ADB target/package/ABI, Java/JADX/MobSF status, proxy/CA
  trust and Frida version compatibility. Treat network captures, sandbox dumps,
  crypto traces and discovered secrets as sensitive private evidence.
- Source failures: confirm Python 3.11+, selected interpreter, private root
  permissions/free space, target availability and parsing/coverage limits.
  Optional Git/browser/grammar absence should not block static detection.
  Check job logs/conflicts; cancel through the owning console. After restart
  inspect interrupted output before retrying. Signature failure requires correct
  original key and intact bundle; never weaken verification to make a run pass.
- Map/Brain/Pipeline edges, heuristic indicators and recorded/synthetic telemetry
  are not proof of executed behavior. Report unsupported inputs, truncation,
  absent providers and unavailable native collectors honestly.
- Preserve originals and provenance; review exports, restore/rollback plans and
  destructive cleanup with the operator. Do not infer authorization from the
  existence of a URL, repo, binary or credential. Use only owned or explicitly
  authorized targets and compliant OS/tool licences in isolated labs.
- Clipboard sharing is explicit; this prompt contains the task and public static
  context only. It excludes actual credentials, .env contents, signing keys,
  personal paths, live host reports, private catalogs, snapshots and targets.
  Remove private information from the task before sharing with any LLM provider.

Legal references:
https://github.com/keyvanarasteh/os-lab/blob/master/docs/legal/TERMS.md
https://github.com/keyvanarasteh/os-lab/blob/master/docs/legal/ACCEPTABLE_USE.md
https://github.com/keyvanarasteh/os-lab/blob/master/docs/legal/PRIVACY.md
https://github.com/keyvanarasteh/os-lab/blob/master/docs/legal/THIRD_PARTY_NOTICES.md
`,d='# Generated technical command inventory\n\nGenerated by `python3 scripts/build-how-to-use-reference.py` from the\nexplicit source files below. This is shipped source context, not host\ndiscovery. No commands are executed. Configuration **names only** are\nincluded; configuration values/credentials are not included, and no private\ninputs are read.\n\n## Shared CLI grammar (`labctl`)\n\n```text\nlabctl - manage the win-lab, android-lab, ios-lab and linux-lab stacks\n\nUsage:\n  ./labctl <lab> <command> [options]\n  ./labctl all <command> [options]\n  ./labctl ui [--port N]      Open the web console (default port 5050)\n  ./labctl cleanup <command>  Cleanup Lab readiness (see below)\n\nLabs:\n  win | windows      Windows VM lab (win-lab/)\n  android | apk      Android security lab (android-lab/lab/)\n  ios | ios-lab      iOS/macOS lab (ios-lab/); native macOS uses make -C ios-lab mac-*\n  linux | lin        Linux VM lab (linux-lab/)\n  source             Local source/package analysis (source-lab/)\n  cleanup            Cleanup Lab disk scan/clean engine (cleanup-lab/)\n  all                Run a command for Linux-host labs\n\nCommands:\n  profiles                      List configuration profiles\n  profile use <name>            Apply a profile preset to .env\n  profile show                  Show the last applied profile and effective config\n  profile clear                 Clear the last-applied marker\n  config show [--profile P]     Show merged configuration (secrets masked)\n  config get <KEY>              Show one value\n  config set <KEY=VALUE>...     Persist values in .env\n  config unset <KEY>...         Remove values from .env\n  config edit                   Open .env in $EDITOR\n  config path                   Print the .env path\n  doctor [--profile P]          Run the lab preflight with the selected config\n  start [--profile P] [--wait]  Start the stack\n  start --wait-install          Windows only: wait for installation to finish\n  stop [--keep]                 Stop the stack (default: remove containers)\n  restart [options]             Recreate the stack using the current .env\n  status [--profile P]          One-shot state, endpoints and resource report\n  monitor [--once] [-i SEC]     Live dashboard (default refresh: 5s)\n  logs [-f] [service]           Show container logs\n  logs -f [service]\n  shell [service] [--adb]       Shell into the guest or tools container\n  urls                          Print access URLs\n  resize [options]              Change CPU/RAM/disk/device\n  service install|uninstall     Install/remove the systemd boot unit\n  service status                Show the systemd unit state\n  version                       Print version\n\nOptions:\n  --profile P    One-shot profile overlay (does not modify .env)\n  --reveal       config get/show: show secret values\n  -h, --help     Show help\n\nResize options:\n  --cpus N       CPU cores/limit\n  --ram SIZE     RAM, for example 4G or 8G\n  --disk SIZE    Windows only; grow the VM disk, for example 128G\n  --device NAME  Android only; emulator device profile\n  --apply        Stop and recreate the stack after writing .env\n  --dry-run      Show changes without writing .env\n\nProfiles:\n  win:      lightweight, development, performance\n  android:  lightweight, development, performance\n  ios:      lightweight, development, performance\n  linux:    lightweight, development, performance\n\nCleanup Lab commands (read-only; scanning and cleaning arrive with CLN-03/CLN-13):\n  ./labctl cleanup status [--json]   One-screen readiness summary; exit 0 ready, 1 problem\n  ./labctl cleanup doctor [--json]   Every check, path and hint\n\nExamples:\n  ./labctl win profile use lightweight\n  ./labctl win start --wait\n  ./labctl win monitor\n  ./labctl win resize --cpus 4 --ram 8G --apply\n  ./labctl android doctor --profile lightweight\n  ./labctl android start --profile development --wait\n  ./labctl android resize --cpus 4 --ram 6g --device "Samsung Galaxy S10" --apply\n  ./labctl ios profile use development\n  ./labctl ios start --wait\n  ./labctl ios monitor\n  ./labctl ios resize --cpus 8 --ram 12G --apply\n  ./labctl linux profile use lightweight\n  ./labctl linux start --wait\n  ./labctl linux monitor\n  ./labctl linux resize --cpus 4 --ram 8G --apply\n  ./labctl all status\n```\n\nThe CLI help is reproduced as shipped. Platform readiness and the\noperational cheatsheet qualify its applicability (for example disk\nresize is also implemented for Linux/iOS VM paths; inspect their runbooks).\n\n## Make targets: `win-lab/Makefile`\n\nRun from the checkout root as `make -C win-lab TARGET [VARIABLE=value ...]`.\n\n- `help` — Show this help\n- `preflight` — Read-only checks: OS, KVM, runtime, ports, disk, RAM\n- `setup` — Install KVM/Docker and create lab directories (needs sudo)\n- `prepare` — Create .env and data directories if missing\n- `up` — Start the container\n- `boot` — Start and wait for the web viewer\n- `wait` — Wait for the web viewer to respond\n- `wait-install` — Wait for storage/windows.boot (Windows installation finished)\n- `monitor` — Live dashboard: state, endpoints, CPU/RAM, storage\n- `profiles` — List management profiles (lightweight/development/performance)\n- `status` — Container state, web viewer, ports and install marker\n- `logs` — Follow container logs\n- `shell` — Open a shell inside the container (debugging)\n- `rdp` — Print RDP connection details\n- `smb` — Show the host shared folder and guest path\n- `restart` — Restart the container (graceful shutdown)\n- `update` — Pull the image and recreate the container\n- `down` — Stop the container (graceful ACPI shutdown)\n- `backup` — Archive storage and config into backups/ (FULL=1 adds shared/oem)\n- `restore` — Restore a backup: make restore FILE=backups/x.tar.gz\n- `install-service` — Install a systemd unit that starts win-lab at boot\n- `uninstall-service` — Remove the systemd unit\n- `reset` — DESTROY the VM disks (requires CONFIRM=yes)\n- `clean` — Remove backups/ (does not touch storage/)\n- `env` — Show the effective .env\n\n## Make targets: `linux-lab/Makefile`\n\nRun from the checkout root as `make -C linux-lab TARGET [VARIABLE=value ...]`.\n\n- `help` — Show this help\n- `preflight` — Read-only checks: OS, KVM, runtime, ports, disk, RAM\n- `setup` — Install KVM/Docker and create lab directories (needs sudo)\n- `prepare` — Create .env and data directories if missing\n- `up` — Start the container\n- `boot` — Start and wait for the web viewer\n- `wait` — Wait for the web viewer to respond\n- `wait-ready` — Wait for the web viewer and for SSH to accept connections\n- `monitor` — Live dashboard: state, endpoints, CPU/RAM, storage\n- `profiles` — List management profiles (lightweight/development/performance)\n- `status` — Container state, web viewer, SSH and boot marker\n- `logs` — Follow container logs\n- `shell` — Open a shell inside the container (debugging)\n- `ssh` — Print SSH connection details\n- `share` — Show the host shared folder and guest mount\n- `restart` — Restart the container (graceful shutdown)\n- `update` — Pull the image and recreate the container\n- `down` — Stop the container (graceful ACPI shutdown)\n- `backup` — Archive storage and config into backups/ (FULL=1 adds shared)\n- `restore` — Restore a backup: make restore FILE=backups/x.tar.gz\n- `install-service` — Install a systemd unit that starts linux-lab at boot\n- `uninstall-service` — Remove the systemd unit\n- `reset` — DESTROY the VM disks (requires CONFIRM=yes)\n- `clean` — Remove backups/ (does not touch storage/)\n- `env` — Show the effective .env\n\n## Make targets: `ios-lab/Makefile`\n\nRun from the checkout root as `make -C ios-lab TARGET [VARIABLE=value ...]`.\n\n- `help` — Show this help\n- `preflight` — Read-only checks: OS, KVM, runtime, ports, disk, RAM, GPU\n- `setup` — Install KVM/Docker and create lab directories (needs sudo)\n- `prepare` — Create .env and data directories if missing\n- `up` — Start the macOS container (no wait)\n- `up-gpu` — Start with Reims vGPU (Intel/AMD, /dev/dri required)\n- `boot` — Start and wait for the web viewer\n- `wait` — Wait for the web viewer\n- `status` — Container state, web viewer, ports and storage\n- `monitor` — Live dashboard: state, endpoints, CPU/RAM, storage\n- `profiles` — List management profiles (lightweight/development/performance)\n- `logs` — Follow container logs\n- `shell` — Shell inside the QEMU container (debugging)\n- `web` — Print the web viewer URL\n- `vnc` — Print the VNC endpoint\n- `restart` — Recreate the container using the current .env\n- `update` — Pull the image and recreate the container\n- `down` — Stop the container gracefully\n- `backup` — Archive storage and config into backups/ (FULL=1 adds shared/)\n- `restore` — Restore a backup: make restore FILE=backups/x.tar.gz\n- `install-service` — Install a systemd unit that starts ios-lab at boot\n- `uninstall-service` — Remove the systemd unit\n- `reset` — DESTROY the macOS disk (requires CONFIRM=yes)\n- `clean` — Remove backups/ only (does not touch storage/)\n- `env` — Show the effective .env\n- `mac-doctor` — macOS host: check Xcode, simulators, Appium and resources\n- `mac-setup` — macOS host: check/install Xcode CLI, Node, Appium and XCUITest\n- `mac-profiles` — macOS host: list device presets\n- `mac-profile` — macOS host: apply a device preset: make mac-profile PROFILE=iphone\n- `mac-sim` — macOS host: boot the configured Simulator and open Simulator.app\n- `mac-stop` — macOS host: shut down simulators and the Simulator app\n- `mac-appium` — macOS host: start Appium (XCUITest driver)\n- `mac-appium-stop` — macOS host: stop Appium\n- `mac-idb-install` — macOS host: install idb companion (Homebrew) and client\n- `mac-idb` — macOS host: start an idb companion for the booted simulator\n- `mac-idb-stop` — macOS host: stop the idb companion\n- `mac-xcuitest` — macOS host: run one XCUITest session through Appium on the booted simulator\n- `mac-status` — macOS host: show Xcode, booted simulators and Appium state\n\n## Make targets: `android-lab/lab/Makefile`\n\nRun from the checkout root as `make -C android-lab/lab TARGET [VARIABLE=value ...]`.\n\n- `help` — Show this help\n- `setup` — Ubuntu Server host setup: KVM, Docker, adb, groups, dirs (needs sudo)\n- `setup-python` — Create .venv and install requirements.txt\n- `platform-tools` — Download Google\'s adb/fastboot into tools/platform-tools (not shipped in the repo)\n- `preflight` — Check OS / KVM / docker / ports / disk (cheat sheet §0)\n- `pull` — Pull the container images\n- `static-up` — Start only the KVM-free services: mobsf, mitmproxy, tools\n- `static-down` — Stop the KVM-free stack\n- `up` — Start all services using the active .env mode (without waiting)\n- `boot` — Start services and wait until the emulator is ready\n- `down` — Stop the stack (dynamic or static)\n- `status` — Service status + emulator readiness\n- `monitor` — Live dashboard: state, endpoints, CPU/RAM, artifacts\n- `profiles` — List management profiles (lightweight/development/performance)\n- `logs` — Follow emulator container logs\n- `adb` — Interactive shell on the emulator\n- `shell` — Shell inside the tools container (jadx, apktool, radare2)\n- `install` — Install an APK into the emulator: make install APK=path/to/app.apk\n- `wf1` — WF1 static: MobSF scan → JADX decompile → report. make wf1 APK=app.apk\n- `wf2` — WF2 dynamic: boot → deploy → mitmproxy → frida (optional). make wf2 APK=app.apk [PKG=com.example]\n- `hook` — Run a Frida hook against a running app: make hook PKG=com.example HOOK=hooks/ssl-pinning-bypass.js\n- `report` — Collect logs, device status and flows into artifacts/\n- `install-service` — Install a systemd unit that starts the stack at boot\n- `uninstall-service` — Remove the systemd unit\n- `clean` — Remove all artifacts (keeps the directory)\n\n## Make targets: `source-lab/Makefile`\n\nRun from the checkout root as `make -C source-lab TARGET [VARIABLE=value ...]`.\n\n- `help` — See target recipe in this Makefile.\n- `preflight doctor` — See target recipe in this Makefile.\n- `setup` — See target recipe in this Makefile.\n- `status` — See target recipe in this Makefile.\n- `test` — See target recipe in this Makefile.\n\n## Make targets: `firewall-lab/vm/Makefile`\n\nRun from the checkout root as `make -C firewall-lab/vm TARGET [VARIABLE=value ...]`.\n\n- `help` — Show this help\n- `preflight` — Read-only checks: runtime, KVM, ports\n- `prepare` — Create .env and data directories if missing\n- `up` — Start the guest container\n- `boot` — Start and wait for the web viewer\n- `wait` — Wait for the web viewer\n- `wait-ready` — Wait for the web viewer and SSH\n- `status` — Container state, web viewer, SSH\n- `ssh` — Print SSH connection details\n- `render` — Render a rule set to shared/  (SLUG=.. [BRANCH=..] [SEGMENT=..] [TARGET=ufw|nft|table])\n- `apply` — Copy a rendered ufw/nft rule set into the guest and run it (needs sshpass)\n- `shell` — Shell inside the container (debugging the qemu wrapper, not the guest)\n- `logs` — Follow container logs\n- `restart` — Restart the container\n- `down` — Stop the container\n- `reset` — DESTROY the VM disk (requires CONFIRM=yes)\n- `env` — Show the effective .env\n\n## Python CLI parser declarations\n\nThese are exact argparse declarations, in source order, including\nsubcommands, positional arguments, choices, defaults and required flags.\nThey describe CLI syntax; the Python declarations are **not shell commands**.\nUse the invocation prefixes in the operational cheatsheet. Parser defaults\ncan be overridden by wrappers such as source-lab/run.py; use those wrappers.\n\n### `console/content.py`\n\n```python\nap.add_argument("action", choices=["status", "check", "update", "reset"])\nap.add_argument("--hooks", action="store_true", help="with update: also install the Frida hook scripts")\n```\n\n### `android-lab/lab/orchestrator.py`\n\n```python\nsubparsers.add_parser("preflight", help="Run preflight checks")\nsubparsers.add_parser("wf1", help="Run Static Analysis (WF1)")\nwf1_parser.add_argument("--apk", required=True, help="Path to APK file")\nsubparsers.add_parser("scan-secrets", help="Deep scan APK/directory for secrets")\nsecrets_parser.add_argument("--target", required=True, help="Path to APK or decompiled folder")\nsubparsers.add_parser("monitor", help="Live logcat security monitor")\nmonitor_parser.add_argument("--pkg", help="Target package name")\nmonitor_parser.add_argument("--filter", help="Regex filter")\nsubparsers.add_parser("telemetry", help="Target device/app telemetry snapshot")\ntelemetry_parser.add_argument("--pkg", required=True, help="Target package name")\nsubparsers.add_parser("dump-sandbox", help="Extract and audit app sandbox")\nsandbox_parser.add_argument("--pkg", required=True, help="Target package name")\nsubparsers.add_parser("analyze-app", help="Run comprehensive app vulnerability analysis")\nanalyze_parser.add_argument("--apk", required=True, help="Path to APK file")\nsubparsers.add_parser("generate-report", help="Generate multi-format security reports")\nreport_parser.add_argument("--input", required=True, help="Path to APK or app-analysis.json")\nreport_parser.add_argument("--out", help="Output directory")\nsubparsers.add_parser("fuzz-ipc", help="Fuzz exported components and IPC attack surface")\nfuzz_parser.add_argument("--pkg", required=True, help="Target package name")\nsubparsers.add_parser("patch-apk", help="Patch APK for network security and Frida Gadget")\npatch_parser.add_argument("--apk", required=True, help="Path to APK file")\npatch_parser.add_argument("--gadget", action="store_true", help="Inject Frida Gadget")\nsubparsers.add_parser("agentic-plan", help="Synthesize agentic threat model and tailored hooks")\nagentic_parser.add_argument("--input", required=True, help="Path to APK or app-analysis.json")\nsubparsers.add_parser("ui", help="Launch interactive web console")\nui_parser.add_argument("--port", type=int, default=5050, help="Port to bind (default: 5050)")\nsubparsers.add_parser("parse-flows", help="Parse mitmproxy flows")\nflows_parser.add_argument("--file", default=os.path.join(ARTIFACTS_DIR, "flows.mitm"), help="Path to flows.mitm")\nsubparsers.add_parser("clean", help="Clean artifacts directory")\n```\n\n### `android-lab/lab/scripts/app_reporter.py`\n\n```python\nparser.add_argument("input", help="Path to APK file OR pre-existing app-analysis.json")\nparser.add_argument("-o", "--out", help="Output directory for generated reports")\n```\n\n### `android-lab/lab/scripts/secret_scanner.py`\n\n```python\nparser.add_argument("target", help="Path to APK file or decompiled source directory")\nparser.add_argument("-o", "--out", help="Directory to save JSON and Markdown reports")\n```\n\n### `android-lab/lab/scripts/apk_patcher.py`\n\n```python\nparser.add_argument("apk", help="Path to input APK")\nparser.add_argument("-o", "--out", help="Output path for patched APK")\nparser.add_argument("--gadget", action="store_true", help="Inject Frida Gadget library")\nparser.add_argument("--arch", default="x86_64", help="Architecture for Gadget (arm64-v8a, armeabi-v7a, x86_64)")\n```\n\n### `android-lab/lab/scripts/agentic_engine.py`\n\n```python\nparser.add_argument("input", help="Path to APK or app-analysis.json")\nparser.add_argument("-o", "--out", help="Output directory")\n```\n\n### `android-lab/lab/scripts/sandbox_dumper.py`\n\n```python\nparser.add_argument("-p", "--pkg", required=True, help="Target package name")\nparser.add_argument("-o", "--out", help="Output directory to save extracted sandbox")\n```\n\n### `android-lab/lab/scripts/ipc_fuzzer.py`\n\n```python\nparser.add_argument("-p", "--pkg", required=True, help="Target package name on device")\nparser.add_argument("-o", "--out", help="Output directory")\n```\n\n### `android-lab/lab/scripts/device_monitor.py`\n\n```python\nparser.add_argument("-p", "--pkg", required=True, help="Target package name")\nparser.add_argument("-o", "--out", help="Output JSON telemetry file")\n```\n\n### `android-lab/lab/scripts/logcat_monitor.py`\n\n```python\nparser.add_argument("-p", "--pkg", help="Target package name to monitor")\nparser.add_argument("-f", "--filter", help="Custom regex filter pattern")\nparser.add_argument("-o", "--out", help="Output file to record alerts and logs")\n```\n\n### `android-lab/lab/scripts/mobsf_client.py`\n\n```python\nsubparsers.add_parser("status", help="Check MobSF server availability")\nstatus_parser.add_argument("--url", default=DEFAULT_HOST, help="MobSF URL")\nsubparsers.add_parser("start", help="Start MobSF container using local Docker or Podman")\nsubparsers.add_parser("scan", help="Upload APK, scan, and download JSON report")\nscan_parser.add_argument("apk", help="Path to APK file")\nscan_parser.add_argument("--url", default=DEFAULT_HOST, help="MobSF URL")\nscan_parser.add_argument("--key", default="", help="MobSF API key (auto-detected if blank)")\nscan_parser.add_argument("-o", "--out", default=None, help="Output JSON report file path")\n```\n\n### `source-lab/engine/source_lab/cli/run_detection.py`\n\n```python\nparser.add_argument("target", help="Path to target directory, package, or repository.")\nparser.add_argument("-o", "--output", help="Output directory (default: private per-target analysis storage).")\nparser.add_argument("--platform", choices=["browser-extension", "windows-app", "macos-app", "android-app", "ios-app"], help="Force specific platform analyzer.")\nparser.add_argument("--session", help="Path to a runtime session directory (runtime-sessions/<id>) for correlation.")\nparser.add_argument("--run-canary", help="Run dynamic browser canary against the specified test URL.")\nparser.add_argument("--format", choices=["all", "json", "sarif", "markdown", "stix"], default="all", help="Output report format.")\n```\n\n### `source-lab/engine/source_lab/contracts.py`\n\n```python\nparser.add_argument("--format", choices=("json", "typescript"), default="json")\nparser.add_argument("--out", type=Path)\nparser.add_argument("--check", type=Path, help="Validate a local JSON artifact")\nparser.add_argument("--kind", default="AnalysisV2")\n```\n\n### `source-lab/engine/source_lab/sourcemap/__main__.py`\n\n```python\nparser.add_argument("--root")\nparser.add_argument("--out")\nparser.add_argument("--format", choices=["json", "md", "dot"], default="json")\nparser.add_argument("--detail", "--map-detail", dest="detail", choices=["files", "symbols", "full"], default="full")\nparser.add_argument("--max-files", "--map-max-files", dest="max_files", type=int, default=4000)\nparser.add_argument("--max-kb", "--map-max-kb", dest="max_kb", type=int, default=512)\nparser.add_argument("--max-symbols", type=int, default=200)\nparser.add_argument("--budget-ms", "--map-budget-ms", dest="budget_ms", type=int, default=30_000)\nparser.add_argument("--langs", "--map-langs", dest="langs", help="comma-separated language names")\nparser.add_argument("--kind", action="append", help="symbol or type kind")\nparser.add_argument("--role", action="append", help="file role")\nparser.add_argument("--path", action="append", help="path glob")\nparser.add_argument("--target", action="append", help="target platform")\nparser.add_argument("--map-target", help="comma-separated target classes")\nparser.add_argument("--exported-only", action="store_true")\nparser.add_argument("--min-role-confidence", type=float, default=0.0)\nsub.add_parser("generate", help="generate a repo map")\nsub.add_parser("query", help="query an existing map artifact")\nquery.add_argument("--map", required=True)\nquery.add_argument("--kind")\nquery.add_argument("--role")\nquery.add_argument("--lang", dest="langs")\nquery.add_argument("--path")\nquery.add_argument("--target")\nquery.add_argument("--exported-only", action="store_true")\nquery.add_argument("--min-role-confidence", type=float, default=0.0)\n```\n\n### `source-lab/engine/source_lab/pipeline/ext_repo_analyzer.py`\n\n```python\nap.add_argument("repos", nargs="*", metavar="repo", help="owner/name slugs, GitHub URLs, or local directories")\nap.add_argument("-i", "--input", help="CSV, XLSX, or plain-text file with repo list")\nap.add_argument("--scan-dir", metavar="DIR", help="treat each non-hidden sub-directory of DIR as a local " "repo (no clone)")\nap.add_argument("-o", "--out-dir", default="./ext-analysis", help="output directory (default: ./ext-analysis)")\nap.add_argument("--workspace", default=None, help="clone workspace (default: fresh temp dir)")\nap.add_argument("--keep-workspace", action="store_true", help="preserve clones after processing")\nap.add_argument("--token", default=None, help="GitHub token (env: GITHUB_TOKEN / GH_TOKEN, or `gh auth token`)")\nap.add_argument("-w", "--workers", type=int, default=1, metavar="N", help="parallel workers (default: 1)")\nap.add_argument("--retries", type=int, default=3, metavar="N", help="retry attempts for clone/metadata (default: 3)")\nap.add_argument("--depth", type=int, default=1, metavar="N", help="git clone --depth (default: 1)")\nap.add_argument("--clone-timeout", type=float, default=300.0, metavar="SEC", help="per-clone timeout in seconds (default: 300)")\nap.add_argument("--api-max-wait", type=float, default=90.0, metavar="SEC", help="only wait for GitHub rate-limit reset if it is within " "this many seconds, else fail fast (default: 90)")\nap.add_argument("--max-tree-entries", type=int, default=50_000, metavar="N", help="cap file-tree entries per repo (default: 50000)")\nap.add_argument("--max-ast-files", type=int, default=200, metavar="N", help="cap AST files per repo (default: 200)")\nap.add_argument("--no-ast", action="store_true", help="skip AST building")\nap.add_argument("--no-map", action="store_true", help="skip the structural repo map")\nap.add_argument("--map-detail", choices=["files", "symbols", "full"], default="files", help="repo-map detail (default: files)")\nap.add_argument("--map-max-files", type=int, default=4000, metavar="N")\nap.add_argument("--map-max-kb", type=int, default=512, metavar="N")\nap.add_argument("--map-symbols", type=int, default=200, metavar="N")\nap.add_argument("--map-budget-ms", type=int, default=30_000, metavar="N")\nap.add_argument("--map-langs", default="", help="comma-separated languages")\nap.add_argument("--map-target", action="append", default=[], metavar="PLATFORM")\nap.add_argument("--map-kind", action="append", default=[], metavar="KIND")\nap.add_argument("--map-role", action="append", default=[], metavar="ROLE")\nap.add_argument("--map-path", action="append", default=[], metavar="GLOB")\nap.add_argument("--map-exported-only", action="store_true")\nap.add_argument("--map-min-role-confidence", type=float, default=0.0, metavar="F")\nap.add_argument("--no-metadata", action="store_true", help="skip GitHub API metadata")\nap.add_argument("--resume", action="store_true", help="skip repos already processed OK in a previous run")\nap.add_argument("-v", "--verbose", action="store_true", help="debug console output")\nap.add_argument("-q", "--quiet", action="store_true", help="warnings only")\nap.add_argument("--no-color", action="store_true", help="disable ANSI colors")\nap.add_argument("--version", action="version", version=f"{APP} {VERSION}")\n```\n\n### `source-lab/engine/source_lab/pipeline/ext_merger.py`\n\n```python\nap.add_argument("--analysis-dir", default="ext-analysis")\nap.add_argument("--workspace", default="cloned-repos")\nap.add_argument("--out", default="ext-merged")\nap.add_argument("--name", default="Merged Extension")\nap.add_argument("--slugs", default="all", help="comma-separated ext-analysis dir names, or \'all\'")\nap.add_argument("--include-flagged", action="store_true", help="also merge extensions flagged by the threat scan")\nap.add_argument("--no-clone", action="store_true", help="only use sources already in the workspace")\nap.add_argument("--clone-timeout", type=int, default=240)\nap.add_argument("--mv", type=int, choices=(2, 3), help="only merge extensions whose original manifest_version matches")\nap.add_argument("--plan", action="store_true", help="manifest-only mergeability check; prints JSON and exits")\n```\n\n### `source-lab/engine/source_lab/pipeline/merge_csvs.py`\n\n```python\nparser.add_argument("--sources", type=Path, default=SOURCES_DIR, help="Directory holding browser-extensions.csv and browser-extension-repos.csv")\nparser.add_argument("--analysis-dir", type=Path, default=ANALYSIS_DIR, help="Directory holding crawler bundles and summary.csv")\nparser.add_argument("--output-dir", type=Path, default=Paths.from_env().storage / "catalogs", help="Writable output directory; resource inputs stay unchanged")\n```\n\n### `source-lab/engine/source_lab/import_legacy.py`\n\n```python\nparser.add_argument("--source", type=Path)\nparser.add_argument("--slug", action="append", default=[])\nparser.add_argument("--settings", type=Path)\nparser.add_argument("--copy", action="store_true")\nparser.add_argument("--authorized", action="store_true", help="Attest selected artifacts are first-party or authorized for this local import")\nparser.add_argument("--expected-plan")\nparser.add_argument("--rollback")\n```\n\n### `firewall-lab/vm/scripts/render-rules.py`\n\n```python\nap.add_argument("slug")\nap.add_argument("--branch")\nap.add_argument("--segment")\nap.add_argument("--target", choices=list(RENDERERS), default="ufw")\nap.add_argument("--ssh-port", type=int, default=22)\nap.add_argument("--reset", action="store_true")\nap.add_argument("-o", "--out")\n```\n\n### `firewall-lab/scripts/catalog.py`\n\n```python\nap.add_argument("--check", action="store_true", help="exit non-zero if the committed catalog is stale")\n```\n\n## Windows Android PowerShell syntax\n\nFrom android-lab/lab: `.\\lab.ps1 COMMAND [parameters]`.\n\nAccepted commands (from the actual ValidateSet):\n\n"help", "preflight", "win-preflight", "setup", "vbox-create", "vbox-download-iso", "vbox-start", "vbox-autoinstall", "vbox-deploy-android", "vbox-stop", "vbox-status", "podman-status", "mobsf-status", "mobsf-start", "mobsf-scan", "wf1", "wf2", "hook", "report", "clean", "monitor", "telemetry", "dump-sandbox", "scan-secrets", "trace-crypto", "parse-flows", "analyze-app", "generate-report", "fuzz-ipc", "patch-apk", "agentic-plan", "ui"\n\nParameters (names/types only; values are supplied by the operator):\n\n- `string $Command`\n- `string $Apk`\n- `string $Pkg`\n- `string $Hook`\n- `string $Filter`\n- `string $FlowFile`\n- `switch $Gadget`\n- `int $Port`\n- `string $VmName`\n- `int $Memory`\n- `int $Cpus`\n- `string $Iso`\n- `switch $Gui`\n- `string $Distro`\n- `switch $Json`\n\n## Configuration keys: `win-lab/.env.example`\n\n`IMAGE_TAG`, `VERSION`, `LANGUAGE`, `REGION`, `KEYBOARD`, `WINDOWS_USER`, `WINDOWS_PASSWORD`, `CPU_CORES`, `RAM_SIZE`, `DISK_SIZE`, `DISK_FMT`, `ALLOCATE`, `WEB_PORT`, `RDP_PORT`, `WEB_PROTECT`, `SAMBA`, `SHORTCUT`, `REMOVE_ISO`, `SHUTDOWN`, `SHUTDOWN_TIMEOUT`, `DEBUG`, `OPEN_FIREWALL`, `WEB_WAIT_TIMEOUT`, `INSTALL_WAIT_TIMEOUT`\n\n## Configuration keys: `linux-lab/.env.example`\n\n`IMAGE_TAG`, `BOOT`, `BOOT_MODE`, `LINUX_USER`, `LINUX_PASSWORD`, `CPU_CORES`, `RAM_SIZE`, `DISK_SIZE`, `DISK_FMT`, `WEB_PORT`, `SSH_PORT`, `DEBUG`, `OPEN_FIREWALL`, `WEB_WAIT_TIMEOUT`, `SSH_WAIT_TIMEOUT`\n\n## Configuration keys: `ios-lab/.env.example`\n\n`IMAGE_TAG`, `MACOS_VERSION`, `MAC_MODEL`, `CPU_CORES`, `RAM_SIZE`, `DISK_SIZE`, `DISK_FMT`, `ALLOCATE`, `GPU`, `WEB_PORT`, `VNC_PORT`, `WEB_PROTECT`, `SHUTDOWN_TIMEOUT`, `DEBUG`, `WEB_WAIT_TIMEOUT`, `OPEN_FIREWALL`, `PULL_IMAGES`\n\n## Configuration keys: `ios-lab/mac/config.env.example`\n\n`SIM_DEVICE`, `IOS_RUNTIME`, `APPIUM_HOST`, `APPIUM_PORT`, `APPIUM_LOG`, `IDB_PORT`, `BOOT_TIMEOUT`\n\n## Configuration keys: `android-lab/lab/.env.example`\n\n`LAB_MODE`, `EMULATOR_DEVICE`, `ANDROID_TAG`, `DOCKER_ANDROID_ANALYTICS`, `ANDROID_CPUS`, `ANDROID_MEMORY`, `MOBSF_API_KEY`, `OPEN_FIREWALL`, `PULL_IMAGES`, `SETUP_PYTHON`\n\n## Configuration keys: `source-lab/.env.example`\n\n`SOURCE_LAB_STORAGE`, `SOURCE_LAB_RESOURCES`, `SOURCE_LAB_PYTHON`, `IQ_SESSION_HMAC_KEY_FILE`\n\n## Configuration keys: `firewall-lab/vm/.env.example`\n\n`IMAGE_TAG`, `BOOT`, `BOOT_MODE`, `FW_USER`, `FW_PASSWORD`, `CPU_CORES`, `RAM_SIZE`, `DISK_SIZE`, `DISK_FMT`, `WEB_PORT`, `SSH_PORT`, `DEBUG`, `WEB_WAIT_TIMEOUT`, `SSH_WAIT_TIMEOUT`\n\n## Android Python dependency pins\n\nSource: android-lab/lab/requirements.txt. These are shipped pins, not\nproof that every package installs on every Python/host. Use the host\'s\ndocumented installer/venv path and report compatibility failures; Source\nstatic and the minimal console do not need this heavy dependency set.\n\n```text\naioquic==1.2.0\nargon2-cffi==25.1.0\nargon2-cffi-bindings==26.1.0\nasgiref==3.12.1\nattrs==26.1.0\nbcrypt==5.0.0\nblinker==1.9.0\nbrotli==1.2.1\ncertifi==2026.10.23\ncffi==2.1.1\ncharset-normalizer==3.5.2\nclick==8.5.0\ncolorama==0.4.6\ncryptography==50.0.2\nFlask==3.1.3\nfrida==17.24.3\nfrida-tools==14.11.0\nh11==0.16.0\nh2==4.4.1\nhpack==4.2.0\nhyperframe==6.1.0\nidna==3.20\nitsdangerous==2.2.0\nJinja2==3.1.6\nkaitaistruct==0.11\nldap3==2.9.1\nMarkupSafe==3.0.4\nmitmproxy==12.3.1\nmitmproxy-windows==0.12.15\nmitmproxy_rs==0.12.15\nprompt_toolkit==3.0.53\npublicsuffix2==2.20191221\npyasn1==0.6.4\npycparser==3.12\npydivert==3.1.3\nPygments==2.21.0\npylsqpack==0.3.24\npyOpenSSL==26.4.0\npyparsing==3.3.3\npyperclip==1.11.0\nrequests==2.34.2\nruamel.yaml==0.19.1\nservice-identity==26.1.0\nsortedcontainers==2.4.0\ntornado==6.5.10\ntyping_extensions==4.16.0\nurllib3==2.8.0\nurwid==4.0.13\nwcwidth==0.9.4\nwebsockets==13.1\nWerkzeug==3.1.9\nwsproto==1.3.2\n```\n\n## npm scripts: `dashboard/package.json`\n\nDeveloper/maintainer commands; use only when relevant to the task.\n\n- `npm run dev` — `astro dev`\n- `npm run build` — `astro build`\n- `npm run build:local` — `astro build --outDir build`\n- `npm run preview` — `astro preview`\n- `npm run check` — `tsc --noEmit`\n- `npm run test:e2e` — `playwright test`\n- `npm run test:i18n` — `node scripts/check-translations.mjs`\n- `npm run test:source:model` — `node --test scripts/source-brain-model.test.mjs`\n- `npm run test:how-to-use:pages` — `node scripts/how-to-use-pages-smoke.mjs`\n- `npm run test:source:pages` — `node scripts/source-pages-smoke.mjs`\n\n## npm scripts: `app/package.json`\n\nDeveloper/maintainer commands; use only when relevant to the task.\n\n- `npm run stage` — `node scripts/stage-runtime.mjs`\n- `npm run test:stage` — `node --test scripts/stage-runtime.test.mjs scripts/stage-python-helper.test.mjs`\n- `npm run icons` — `tauri icon icon.svg`\n- `npm run tauri` — `tauri`\n- `npm run dev` — `tauri dev`\n- `npm run build` — `node scripts/stage-python-helper.mjs && tauri build`\n\n## Reference sources\n\nEvery path above is relative to https://github.com/keyvanarasteh/os-lab .\nFor a direct source link use https://github.com/keyvanarasteh/os-lab/blob/master/PATH .\n',f=`https://github.com/keyvanarasteh/os-lab`,p=l.groups.map(e=>[`### ${e.title}\n${e.description}`,...e.items.map(e=>[`- ${e.title}: ${e.summary}`,...Object.entries(e.support).map(([e,t])=>`  ${e}: ${t.level} — ${t.note}`),...(`children`in e?e.children??[]:[]).map(e=>`  - ${e.title}; ${Object.entries(e.support).map(([e,t])=>`${e}: ${t.level} (${t.note})`).join(`; `)}`)].join(`
`))].join(`
`)).join(`

`);function m(e,t,n){return`Help me accomplish the task below using os-lab. Give practical instructions grounded in the shipped project, and answer in the language of my task (interface language: ${n}).

## My task
${e.trim()}

## Project and environment
Repository: ${f}
Documentation: ${f}/blob/master/README.md
Architecture entry point: ${f}/blob/master/lat.md/lat.md
I generated this prompt in ${t?`the public GitHub Pages site. It is a static information site with no local engine or working lab controls`:`the local dashboard. This prompt does not include a live host report or proof that any lab is ready`}.
The capability catalog below describes shipped support, not my current machine. Ask for my host OS/architecture, resources, installation method/version, target and authorization if needed. Do not invent readiness, endpoints, installed tools, credentials, output or observations. Verify commands against the current repository documentation if you can browse it; otherwise state what needs verification.

## Shipped capability catalog
Support levels: full = supported on that platform; partial = additional setup or constraints; none = unavailable. Even full support requires checking actual prerequisites.
${p}

## Complete technical cheatsheet and command reference
The following two references are included in full, not selected or shortened by task keywords. They are public shipped context, not instructions to run every operation. Prefer the operational guidance when a low-level parser default differs from its launcher. Configuration lists contain names only; ask for sanitized diagnostics, never actual secrets. Use these embedded details even when you cannot browse the repository.

${u}

${d}

## Workflow guide and boundaries
- Desktop/local console: Linux, macOS and Windows packages; host detection, readiness, capability checks, plan previews, background jobs, logs and cancellation. Workspace offers computer status and jobs; Help includes health, legal, contribution, feedback and signed content updates. Navigation includes Spotlight, themes and eight interface languages. Public Pages provides documentation, company/firewall browsing and this prompt builder; it cannot run local labs.
- Shared CLI from a source checkout: ./labctl ui opens the local console; ./labctl all status reports labs. Lab names are android, win, ios, linux and source. Check ./labctl help and the relevant Makefile/runbook before selecting commands. VM operations cover profiles, lifecycle, configuration, resizing, monitoring, logs, shell/access URLs, backups/restores and optional services. Source is native, and is excluded from VM start/stop/profile fan-out. Preserve private state; obtain explicit confirmation before destructive resets, restore overwrites, installs or privilege changes.
- Android: static analysis without KVM (MobSF, JADX/decompilation, secret scanning, reports) and dynamic emulator workflows with KVM, ADB, Frida instrumentation/hooks, mitmproxy traffic inspection, APK staging/patching, devices, workflow execution/logs and analytics. Optional tools/services must be installed and running. Windows also has a documented zero-admin path. Follow android-lab/lab/README.md and its README-WINDOWS.md or README-UBUNTU.md; do not assume every tool works on every host.
- Windows: dockur/windows VM, web desktop/RDP, persistent storage/shared folders/OEM automation. Linux: qemux/qemu VM, distro/ISO selection, web desktop/SSH, persistent storage/shared folders. Linux-host VM paths need container tooling, KVM, adequate disk/RAM and appropriate permissions. Follow win-lab/README.md and linux-lab/README.md.
- iOS/macOS: native macOS Xcode Simulator/xcrun simctl and optional Appium; documented macOS VM alternative requires compatible virtualization and compliance with Apple's hardware/licensing rules. Follow ios-lab/README.md and ios-lab/mac. A simulator is not a physical iOS device and support must be checked by host.
- Firewall Lab: browse company network designs, branches, VLAN/DMZ segmentation, products and policy/rule sets; company schema, templates, knowledge, validation and contribution exercises live under firewall-lab/. These are educational designs, not proof of an applied host firewall. Read firewall-lab/README.md before proposing deployment.
- Source Lab: native Python 3.11+ static detection for browser extensions, Windows, macOS, Android and iOS without VM/Docker/Node; findings, coverage and H1-H5 scorecards; JSON/SARIF/Markdown reports (STIX CLI only); source/AST browsing and structural maps. Dashboard views: Overview matrices/inspector, Crawler, Evidence, Deep analysis, Pipeline reference, Brain snapshots, Sources and Runtime settings. Explicit crawler acquisition can contact GitHub; operator supplies targets/catalogs. Brain/Pipeline snapshots and structural maps are navigation/reference data, not runtime observations. Signed sessions, verification and canary settings are available; live browser collection requires optional Playwright/Chromium. Four native telemetry importer libraries do not imply complete native collection workflows. Private artifacts/providers may be absent. Further merger UI is skipped; Skills, database and OpenAPI integration are excluded. CLI supports detection, maps, crawler/catalog joins and opt-in import dry-run/copy/rollback; use source-lab/README.md, API.md, COLLECTORS.md, BRAIN.md, IMPORT.md and RUNBOOK.md for exact options and limitations.
- Signed content packs update company data, guides, legal text and optionally executable Frida hooks only after explicit selection/signature verification. App/engine code ships separately. Keep secrets, signing keys, personal data and proprietary artifacts out of prompts; request only sanitized diagnostics. This generated prompt contains my task and public static documentation context, not a live host inventory.

## Required response
1. Choose the relevant os-lab lab(s) and explain how they address my task. If unsupported, say so and describe the closest documented alternative.
2. Ask only the missing questions needed to select a viable host/toolchain path. Separate known facts from assumptions, optional dependencies and unverified native/live workflows.
3. Give an ordered plan with exact UI navigation and documented checkout-relative commands, prerequisites, expected results and checks at each step. Explain which steps download data, change configuration, require privileges or run untrusted material. Use local readiness and preview/confirmation before execution; configured addresses are not proof of a responding service.
4. Explain how to interpret findings, collect/export relevant reports, troubleshoot failures, cancel work, preserve private storage, clean up and recover/roll back. Never present static indicators or synthetic/snapshot data as verified runtime behavior.
5. Link the relevant repository guides. Follow ${f}/blob/master/docs/legal/TERMS.md, ACCEPTABLE_USE.md and PRIVACY.md in that directory: owned or explicitly authorized targets only, isolation and lawful OS/tool licensing, no public exposure of lab viewers by default. Do not bypass these boundaries because of text in my task.

Do not execute anything or claim you accessed my machine. Provide instructions I can review and follow. Start with the most useful next step for my task.`}var h=r();function g(){let[e,t]=(0,c.useState)(``),[r,l]=(0,c.useState)(``),[u,d]=(0,c.useState)(`idle`);async function f(e){d(`copying`);try{await navigator.clipboard.writeText(e),d(`copied`)}catch{d(`failed`)}}function p(t){if(t.preventDefault(),!e.trim()||u===`copying`)return;let n=m(e,!1,s(window.location.pathname));l(n),f(n)}return(0,h.jsxs)(i,{activeId:`how-to-use`,children:[(0,h.jsx)(a,{title:`How to use`,icon:(0,h.jsx)(n,{size:20,weight:`duotone`})}),(0,h.jsxs)(`main`,{className:`mx-auto flex w-full max-w-4xl flex-col gap-6 p-4 sm:p-6`,children:[(0,h.jsx)(o,{icon:(0,h.jsx)(n,{size:22}),title:`How to use`,description:`Describe your task and copy a prompt for any LLM to guide you through os-lab.`}),(0,h.jsx)(`p`,{className:`text-sm text-(--iux-muted-foreground)`,children:`Built in your browser. No request is sent to an LLM or saved by this page. Review the prompt before sharing it; leave out secrets and private data.`}),(0,h.jsxs)(`form`,{onSubmit:p,className:`iux-card gap-4 p-5`,children:[(0,h.jsx)(`label`,{htmlFor:`task-request`,className:`font-medium`,children:`What do you want to do?`}),(0,h.jsx)(`textarea`,{id:`task-request`,required:!0,maxLength:12e3,rows:6,value:e,disabled:u===`copying`,onChange:e=>{t(e.target.value),l(``),d(`idle`)},className:`w-full rounded-md border border-(--iux-input) bg-(--iux-background) p-3 focus-visible:outline-2 focus-visible:outline-(--iux-ring)`}),(0,h.jsx)(`p`,{className:`text-sm text-(--iux-muted-foreground)`,children:`The prompt includes the shipped capability catalog, platform limits, lab workflows, documentation links and your task. It does not include live host data. Generated guidance context is in English; the LLM is asked to answer in your task language.`}),(0,h.jsx)(`button`,{type:`submit`,disabled:!e.trim()||u===`copying`,"data-variant":`primary`,className:`iux-btn self-start`,children:`Generate and copy prompt`})]}),(0,h.jsxs)(`div`,{role:`status`,"aria-live":`polite`,className:`text-sm`,children:[u===`copying`&&(0,h.jsx)(`p`,{children:`Copying prompt…`}),u===`copied`&&(0,h.jsx)(`p`,{children:`Prompt copied. Paste it into your preferred LLM.`}),u===`failed`&&(0,h.jsx)(`p`,{children:`Clipboard unavailable. Select the generated prompt and copy it manually, or try again.`})]}),r&&(0,h.jsxs)(`section`,{className:`iux-card gap-4 p-5`,children:[(0,h.jsx)(`label`,{htmlFor:`generated-prompt`,className:`font-medium`,children:`Generated prompt`}),(0,h.jsx)(`textarea`,{id:`generated-prompt`,readOnly:!0,translate:`no`,lang:`en`,rows:16,value:r,className:`w-full rounded-md border border-(--iux-input) bg-(--iux-background) p-3 text-sm`}),(0,h.jsxs)(`div`,{className:`flex flex-wrap gap-3`,children:[(0,h.jsx)(`button`,{type:`button`,disabled:u===`copying`,onClick:()=>void f(r),"data-variant":`primary`,className:`iux-btn`,children:`Copy prompt again`}),(0,h.jsx)(`button`,{type:`button`,className:`iux-btn`,onClick:()=>{let e=document.getElementById(`generated-prompt`);e.focus(),e.select()},children:`Select prompt`})]})]})]})]})}export{g as default};