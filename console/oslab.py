"""os-lab host engine: host detection, lab availability, typed action plans, jobs and monitoring.

A standard-library port of the OS Lab desktop runtime in qLar PR #174
(os_lab_runtime.rs, os_lab_provider.rs, os_lab_jobs.rs, os_lab_monitor.rs):

- ``host_info()``      what this computer is: OS, arch, CPU, memory, disk, KVM, WSL and host tools.
- ``lab_catalog()``    which labs this host can run, through which provider, and what is missing.
- ``plan()``           a typed, validated command for one lab action. Pages never send command
                       strings: they send {lab, action, profile, ...} and get back the exact
                       program, arguments, effects and setup prerequisites to confirm.
- ``JobService``       runs a confirmed plan in the background with captured, secret-redacted
                       output, a timeout and cancellation.
- ``monitor()``        container state and resource use for a lab.

The web console in android-lab/lab/web_ui.py exposes these over a localhost JSON API.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import secrets as _secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid

# ── Static lab model ─────────────────────────────────────────────────────────

LAB_ORDER = ["android", "windows", "linux", "ios", "macos", "source"]

LABS = {
    "source": {"label": "Source Lab", "dir": "source-lab", "labctl": "source", "containers": [],
               "summary": "Local source and package analysis across five platforms."},
    "android": {
        "label": "Android Lab",
        "dir": "android-lab/lab",
        "labctl": "android",
        "containers": ["lab-android", "lab-mobsf", "lab-mitmproxy", "lab-tools"],
        "summary": "Docker-Android emulator, MobSF, mitmproxy and Frida for mobile security work.",
    },
    "windows": {
        "label": "Windows Lab",
        "dir": "win-lab",
        "labctl": "win",
        "containers": ["win-lab"],
        "disk_default": "64G",
        "summary": "Windows in Docker with KVM, a web desktop, RDP and shared storage.",
    },
    "linux": {
        "label": "Linux Lab",
        "dir": "linux-lab",
        "labctl": "linux",
        "containers": ["linux-lab"],
        "summary": "Linux in Docker with KVM, a web console, SSH and shared storage.",
    },
    "ios": {
        "label": "iOS Lab",
        "dir": "ios-lab",
        "labctl": "ios",
        "containers": ["ios-lab"],
        "disk_default": "128G",
        "summary": "iOS tooling through a macOS VM on a Linux/KVM host, or native Xcode on a Mac.",
    },
    "macos": {
        "label": "macOS Lab",
        "dir": "ios-lab/mac",
        "labctl": None,
        "containers": [],
        "summary": "Manage this Mac's Xcode simulators and optional Appium/XCUITest automation.",
    },
}

# Tools reported on the host page (id, label). Mirrors os_lab_runtime.rs plus a few installers.
TOOLS = [
    ("docker", "Docker CLI"),
    ("podman", "Podman CLI"),
    ("bash", "Bash"),
    ("make", "Make"),
    ("git", "Git"),
    ("python3", "Python 3"),
    ("adb", "Android Debug Bridge"),
    ("java", "Java"),
    ("xcrun", "Xcode tools"),
    ("brew", "Homebrew"),
    ("node", "Node.js"),
    ("appium", "Appium"),
    ("wsl", "Windows Subsystem for Linux"),
    ("apt-get", "APT package manager"),
    ("pkexec", "Polkit (graphical sudo)"),
    ("sudo", "sudo"),
]

# Tools that only make sense on some hosts; everything else is reported everywhere.
TOOL_HOSTS = {
    "xcrun": {"macos"}, "brew": {"macos"},
    "wsl": {"windows"},
    "apt-get": {"linux"}, "pkexec": {"linux"}, "sudo": {"linux", "macos"},
}


def tools_for_host(os_name: str) -> list[tuple[str, str]]:
    return [(t, label) for t, label in TOOLS if os_name in TOOL_HOSTS.get(t, {os_name})]


LABCTL_ACTIONS = ["status", "doctor", "urls", "logs", "monitor", "start", "stop", "restart",
                  "profile", "resize", "setup", "backup", "service-install", "service-uninstall"]
MAC_ACTIONS = ["status", "doctor", "setup", "start", "stop", "appium-install", "appium-start", "appium-stop"]

ACTION_INFO = {
    "csv-merge": ("Join catalogs", "Join operator catalogs into private storage."),
    "detect": ("Detect", "Analyze a selected local target."),
    "crawl": ("Crawl", "Analyze explicitly selected repositories."),
    "merge": ("Merge", "Plan or build selected authorized extensions."),
    "runtime": ("Runtime settings", "Change private Source Lab runtime settings."),
    "status": ("Status", "One-shot state, endpoints and resource report."),
    "doctor": ("Doctor", "Run the lab preflight: OS, KVM, runtime, ports and disk."),
    "urls": ("URLs", "Print the lab's access addresses."),
    "logs": ("Logs", "Show recent container logs."),
    "monitor": ("Snapshot", "One monitor frame: containers, CPU and memory."),
    "start": ("Start", "Start the lab stack with the current configuration."),
    "stop": ("Stop", "Stop the lab stack."),
    "restart": ("Restart", "Recreate the stack from the current configuration."),
    "profile": ("Apply profile", "Write a profile preset (lightweight/development/performance) to .env."),
    "resize": ("Resize", "Change CPU/RAM (and disk for Windows) in .env; restart to apply."),
    "setup": ("Install dependencies", "Install the host prerequisites for this lab."),
    "backup": ("Backup", "Write a guest backup archive into the lab's backups/ folder."),
    "service-install": ("Install boot service", "Start this lab automatically at boot (systemd)."),
    "service-uninstall": ("Remove boot service", "Remove the systemd boot unit."),
    "appium-install": ("Install Appium", "Install Node (Homebrew if needed), Appium and the XCUITest driver for this user only. No administrator rights."),
    "appium-start": ("Start Appium", "Start the Appium server with XCUITest."),
    "appium-stop": ("Stop Appium", "Stop the Appium server."),
}

# On the native Mac path "start" and "stop" drive the iOS Simulator, not a container stack.
NATIVE_SIMULATOR_INFO = {
    "start": ("Start iOS Simulator", "Boot the configured iOS Simulator device on this Mac."),
    "stop": ("Stop iOS Simulator", "Shut the iOS Simulator down."),
}

# Offered while a required dependency is missing: install it, install Appium, or run the preflight.
SETUP_STATE_ACTIONS = {"setup", "appium-install", "doctor"}

PRIVILEGED = {"setup", "service-install", "service-uninstall"}
SECRET_PARTS = ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY", "CREDENTIAL")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SIZE = re.compile(r"^[1-9][0-9]{0,5}[MmGgTt]?$")


class PlanError(ValueError):
    """A request the lab model refuses; the message is safe to show to the user."""


# ── Host detection ───────────────────────────────────────────────────────────

def host_os() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform in ("win32", "cygwin"):
        return "windows"
    return sys.platform


def host_arch() -> str:
    m = platform.machine().lower()
    return {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64"}.get(m, m)


def _managed_appium() -> str | None:
    """Appium installed by ios-lab/mac/appium.sh install (user folder, no global npm)."""
    path = os.path.join(os.environ.get("OSLAB_APPIUM_HOME") or os.path.expanduser("~/.oslab/appium"),
                        "node_modules", ".bin", "appium")
    return path if os.path.isfile(path) and os.access(path, os.X_OK) else None


def _which(name: str) -> str | None:
    found = shutil.which(name)
    return found or (_managed_appium() if name == "appium" else None)


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _capture(args: list[str], timeout: float = 5.0, decode: str = "utf-8") -> tuple[int, str]:
    try:
        out = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return out.returncode, out.stdout.decode(decode, errors="replace")
    except (OSError, subprocess.SubprocessError) as e:
        return 127, str(e)


def os_pretty(os_name: str) -> str:
    if os_name == "linux":
        for line in _read("/etc/os-release").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
        return "Linux " + platform.release()
    if os_name == "macos":
        return "macOS " + (platform.mac_ver()[0] or platform.release())
    if os_name == "windows":
        return "Windows " + platform.release() + " (" + platform.version() + ")"
    return platform.platform()


def memory_bytes(os_name: str) -> int | None:
    try:
        if os_name == "linux":
            m = re.search(r"MemTotal:\s+(\d+)\s+kB", _read("/proc/meminfo"))
            return int(m.group(1)) * 1024 if m else None
        if os_name == "macos":
            code, out = _capture(["sysctl", "-n", "hw.memsize"])
            return int(out.strip()) if code == 0 else None
        if os_name == "windows":
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            status = MemoryStatus()
            status.dwLength = ctypes.sizeof(MemoryStatus)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))  # type: ignore[attr-defined]
            return int(status.ullTotalPhys)
    except (OSError, ValueError, AttributeError):
        return None
    return None


def wsl_distributions() -> list[str]:
    """Installed WSL distributions (Windows host only). `wsl -l -q` prints UTF-16LE."""
    if host_os() != "windows" or not _which("wsl"):
        return []
    code, out = _capture(["wsl", "-l", "-q"], timeout=10, decode="utf-16-le")
    if code != 0:
        return []
    return [d.strip().strip("\x00") for d in out.splitlines() if d.strip().strip("\x00")]


def container_runtime() -> str | None:
    for name in ("docker", "podman"):
        if _which(name) and _capture([name, "info"], timeout=5)[0] == 0 \
                and _capture([name, "compose", "version"], timeout=5)[0] == 0:
            return name
    return None


def xcode_status() -> dict:
    """Full Xcode and an available iOS Simulator, not just the command-line tools."""
    if host_os() != "macos":
        return {"installed": False, "iosRuntime": False, "iosDevice": False}
    installed = _capture(["xcodebuild", "-version"], timeout=5)[0] == 0
    if not installed:
        return {"installed": False, "iosRuntime": False, "iosDevice": False}
    code, output = _capture(["xcrun", "simctl", "list", "-j", "devices", "available"], timeout=10)
    try:
        devices = json.loads(output)["devices"] if code == 0 else {}
        ios_device = any("iOS" in runtime and any(d.get("isAvailable", True) for d in entries)
                         for runtime, entries in devices.items())
    except (ValueError, KeyError, TypeError, AttributeError):
        ios_device = False
    code, output = _capture(["xcrun", "simctl", "list", "runtimes"], timeout=10)
    ios_runtime = code == 0 and any(line.startswith("iOS ") for line in output.splitlines())
    return {"installed": installed, "iosRuntime": ios_runtime, "iosDevice": ios_device}


def host_info(root: str) -> dict:
    os_name = host_os()
    arch = host_arch()
    kvm_path = "/dev/kvm"
    kvm_exists = os.path.exists(kvm_path)
    try:
        disk = shutil.disk_usage(root)
        disk_info = {"total": disk.total, "free": disk.free}
    except OSError:
        disk_info = None
    in_wsl = os_name == "linux" and "microsoft" in _read("/proc/version").lower()
    return {
        "os": os_name,
        "osPretty": os_pretty(os_name),
        "arch": arch,
        "hostname": platform.node(),
        "cpus": os.cpu_count(),
        "memory": memory_bytes(os_name),
        "disk": disk_info,
        "kvm": {"present": kvm_exists, "usable": kvm_exists and os.access(kvm_path, os.R_OK | os.W_OK)},
        "wsl": {"guest": in_wsl, "distributions": wsl_distributions()},
        "runtime": container_runtime(),
        "xcode": xcode_status() if os_name == "macos" else None,
        "python": platform.python_version(),
        "root": root,
        "tools": [{"id": t, "label": label, "found": bool(_which(t)), "path": _which(t)} for t, label in tools_for_host(os_name)],
        "providers": [p for p in provider_report(os_name, arch) if p["candidate"]],
    }


def provider_report(os_name: str, arch: str) -> list[dict]:
    """Which providers are candidates on this host (os_lab_runtime.rs::provider_report)."""
    vm_linux = os_name == "linux" and arch == "x86_64"
    return [
        {"id": "native-python", "guest": "Source / package analysis", "candidate": os_name in ("linux", "macos", "windows"),
         "requirements": "Native Python 3.11+ and writable private storage; no VM or containers"},
        {"id": "windows-container", "guest": "Windows", "candidate": vm_linux or os_name == "windows",
         "requirements": "WSL2 Linux, working Docker/Podman and usable KVM" if os_name == "windows"
         else "x86_64 Linux, working Docker/Podman and usable KVM"},
        {"id": "linux-container", "guest": "Linux", "candidate": os_name in ("linux", "windows"),
         "requirements": "Linux (or WSL2), working Docker/Podman and usable KVM"},
        {"id": "android-container", "guest": "Android / static analysis", "candidate": True,
         "requirements": "Working Docker/Podman; the dynamic emulator also needs usable acceleration"},
        {"id": "native-macos", "guest": "iOS Simulator / Appium", "candidate": os_name == "macos",
         "requirements": "Mac with Xcode, an installed Simulator runtime and Appium/XCUITest"},
        {"id": "ios-vm", "guest": "macOS VM / iOS tooling", "candidate": vm_linux or os_name == "windows",
         "requirements": "Suitable Linux/KVM host and guest/tool prerequisites"},
    ]


# ── Lab availability ─────────────────────────────────────────────────────────

def _req(id_: str, label: str, found: bool, required: bool = True, hint: str = "") -> dict:
    return {"id": id_, "label": label, "found": bool(found), "required": required, "hint": hint}


def provider_for(lab: str, os_name: str) -> str | None:
    if lab == "source":
        return "native-python" if os_name in ("linux", "macos", "windows") else None
    if lab == "macos":
        return "native-macos" if os_name == "macos" else None
    if os_name == "macos":
        if lab == "ios":
            return "native-macos"
        if lab == "android":
            return "macos-containers"
        return None
    if os_name == "windows":
        return "wsl2"
    if os_name == "linux":
        return "linux-containers"
    return None


def lab_status(lab: str, host: dict) -> dict:
    """Availability of one lab on this host: ready, needs-setup or unavailable, with the reasons."""
    if lab == "source":
        import source_control
        return source_control.lab_status(host["root"], host["os"])
    meta = LABS[lab]
    os_name, arch = host["os"], host["arch"]
    tools = {t["id"]: t["found"] for t in host["tools"]}
    runtime = bool(host["runtime"])
    kvm = host["kvm"]["usable"]
    provider = provider_for(lab, os_name)
    reasons: list[str] = []
    reqs: list[dict] = []
    notes: list[str] = []
    state = "ready"

    if provider is None:
        if lab == "macos":
            reasons.append("Native Simulator and Appium need a Mac. On Linux use the iOS Lab's macOS VM.")
        else:
            reasons.append("This lab needs a Linux/KVM host (or Windows with WSL2). Use a remote Linux machine.")
        return {"id": lab, "label": meta["label"], "summary": meta["summary"], "state": "unavailable",
                "provider": None, "reasons": reasons, "requirements": reqs, "notes": notes,
                "actions": [], "installed": os.path.isdir(os.path.join(host["root"], meta["dir"]))}

    if provider == "native-macos":
        if lab == "ios":
            notes.append("Uses the same native Xcode installation as macOS Lab on this Mac.")
        xcode = host.get("xcode") or {}
        reqs += [
            _req("xcode", "Full Xcode", xcode.get("installed"), hint="Install and open Xcode, then accept its license"),
            _req("ios-runtime", "iOS Simulator runtime", xcode.get("iosRuntime"), hint="Xcode > Settings > Components"),
            _req("ios-device", "Available iOS Simulator device", xcode.get("iosDevice"), hint="Add a simulator in Xcode"),
            _req("brew", "Homebrew", tools.get("brew"), required=False, hint="https://brew.sh (needed for automated Appium setup)"),
            _req("node", "Node.js", tools.get("node"), required=False, hint="brew install node"),
            _req("appium", "Appium (XCUITest)", tools.get("appium"), required=False, hint="Install Appium (no administrator rights)"),
        ]
        if not tools.get("appium"):
            notes.append("Appium automation needs Appium and its XCUITest driver; the simulator can run without them.")
    elif provider == "wsl2":
        distros = host["wsl"]["distributions"]
        reqs += [
            _req("wsl", "WSL2", tools.get("wsl"), hint="wsl --install"),
            _req("wsl-distro", "A WSL2 Linux distribution", bool(distros), hint="wsl --install -d Ubuntu"),
        ]
        notes.append("Commands run inside the selected WSL2 distribution; Docker/Podman and KVM are checked there by Doctor.")
    else:
        reqs.append(_req("runtime", "Working Docker or Podman with Compose", runtime,
                         hint="Start the engine and install its Compose plugin if needed"))
        reqs.append(_req("bash", "Bash", tools.get("bash")))
        needs_kvm = lab in ("windows", "linux", "ios")
        if os_name == "linux":
            reqs.append(_req("kvm", "Usable /dev/kvm", kvm, required=needs_kvm,
                             hint="Enable virtualization in firmware, then Install dependencies (adds you to the kvm group)"))
        if lab in ("windows", "ios") and arch != "x86_64":
            reasons.append(f"{meta['label']} guests need an x86_64 host; this host is {arch}.")
            state = "unavailable"
        if lab == "android":
            reqs.append(_req("adb", "Android Debug Bridge", tools.get("adb"), required=False, hint="Install dependencies"))
            if os_name == "linux" and not kvm:
                notes.append("No usable KVM: static analysis (MobSF, mitmproxy, tools) works; the emulator needs KVM.")
        if provider == "macos-containers":
            notes.append("On macOS only the lightweight/static Android profile runs; the emulator needs a Linux/KVM host.")

    if state != "unavailable" and any(r["required"] and not r["found"] for r in reqs):
        state = "needs-setup"
        reasons.append("Missing: " + ", ".join(r["label"] for r in reqs if r["required"] and not r["found"]) + ".")

    actions = actions_for(lab, provider) if state != "unavailable" else []
    if state == "needs-setup":
        # Something this lab requires is missing: only the ways to fix or diagnose that are offered.
        # Start, stop, resize, logs and the rest come back once the requirements are met.
        actions = [x for x in actions if x["id"] in SETUP_STATE_ACTIONS]
    if provider == "native-macos":
        # Installed Appium: offer start/stop, not install. Not installed: offer install, not start/stop.
        drop = {"appium-install"} if tools.get("appium") else {"appium-start", "appium-stop"}
        actions = [a for a in actions if a["id"] not in drop]
        for a in actions:
            if a["id"] in NATIVE_SIMULATOR_INFO:
                a["label"], a["description"] = NATIVE_SIMULATOR_INFO[a["id"]]
    summary = ("Run the iOS Simulator with this Mac's Xcode; Appium automation is optional."
               if lab == "ios" and provider == "native-macos" else meta["summary"])
    return {"id": lab, "label": meta["label"], "summary": summary, "state": state, "provider": provider,
            "reasons": reasons, "requirements": reqs, "notes": notes, "actions": actions,
            "installed": os.path.isdir(os.path.join(host["root"], meta["dir"]))}


def actions_for(lab: str, provider: str | None) -> list[dict]:
    if provider == "native-macos":
        names = MAC_ACTIONS
    elif provider:
        names = [a for a in LABCTL_ACTIONS if not (a == "backup" and lab == "android")]
        if provider == "macos-containers":
            names = [a for a in names if a not in PRIVILEGED]
    else:
        names = []
    return [{"id": n, "label": ACTION_INFO[n][0], "description": ACTION_INFO[n][1],
             "privileged": n in PRIVILEGED and provider != "native-macos"} for n in names]


def lab_catalog(root: str, host: dict | None = None) -> dict:
    host = host or host_info(root)
    return {"host": {"os": host["os"], "arch": host["arch"]},
            "labs": [lab_status(lab, host) for lab in LAB_ORDER]}


def capability_catalog() -> dict:
    """Health's platform tree. Lab support levels follow the same provider rules as lab_status."""
    with open(os.path.join(os.path.dirname(__file__), "capabilities.json"), encoding="utf-8") as f:
        catalog = json.load(f)
    for group in catalog["groups"]:
        for item in group["items"]:
            lab = item.get("lab")
            if not lab:
                continue
            for platform in ("macos", "windows", "linux"):
                provider = provider_for(lab, platform)
                if provider is None:
                    level = "none"
                elif provider in ("wsl2", "macos-containers") or (lab == "ios" and platform == "linux"):
                    level = "partial"
                else:
                    level = "full"
                item["support"][platform]["level"] = level
    return catalog


# ── Configuration ────────────────────────────────────────────────────────────

def env_entries(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            out[key] = value.strip().strip("'\"")
    return out


def is_secret(key: str) -> bool:
    return any(part in key.upper() for part in SECRET_PARTS)


def lab_config(root: str, lab: str) -> dict:
    """Effective configuration: .env.example defaults overlaid by .env, with secrets masked."""
    if lab == "source":
        import source_control
        base = source_control.storage(root)
        resources = os.environ.get("SOURCE_LAB_RESOURCES", str(base / "resources"))
        return {"lab": lab, "path": "Process environment (example files are not loaded)", "exists": False,
                "fields": [{"key": "SOURCE_LAB_STORAGE", "value": str(base), "local": "SOURCE_LAB_STORAGE" in os.environ},
                           {"key": "SOURCE_LAB_RESOURCES", "value": resources, "local": "SOURCE_LAB_RESOURCES" in os.environ}],
                "profiles": [], "backups": [], "endpoints": []}
    meta = LABS[lab]
    base = os.path.join(root, meta["dir"])
    config_name = "config.env" if lab == "macos" else ".env"
    values = env_entries(_read(os.path.join(base, config_name + ".example")))
    local = env_entries(_read(os.path.join(base, config_name)))
    values.update(local)
    fields = [{"key": k, "value": "••••••" if is_secret(k) and v else v, "local": k in local}
              for k, v in sorted(values.items())]
    prof_dir = os.path.join(base, "profiles")
    profiles = sorted(n[:-4] for n in os.listdir(prof_dir) if n.endswith(".env")) if os.path.isdir(prof_dir) else []
    backups_dir = os.path.join(base, "backups")
    backups = sorted(n for n in os.listdir(backups_dir) if n.endswith(".tar.gz")) if os.path.isdir(backups_dir) else []
    return {"lab": lab, "path": os.path.join(meta["dir"], config_name), "exists": os.path.isfile(os.path.join(base, config_name)),
            "fields": fields, "profiles": profiles, "backups": backups, "endpoints": endpoints(lab, values)}


def endpoints(lab: str, values: dict[str, str]) -> list[dict]:
    web = values.get("WEB_PORT", "8006")
    if lab == "windows":
        return [{"label": "Web desktop", "address": f"http://127.0.0.1:{web}/"},
                {"label": "RDP", "address": f"127.0.0.1:{values.get('RDP_PORT', '3389')}"}]
    if lab == "linux":
        return [{"label": "Web console", "address": f"http://127.0.0.1:{web}/"},
                {"label": "SSH", "address": f"ssh -p {values.get('SSH_PORT', '2222')} {values.get('LINUX_USER', 'root')}@127.0.0.1"}]
    if lab == "ios":
        return [{"label": "Web viewer", "address": f"http://127.0.0.1:{web}/"},
                {"label": "VNC", "address": f"127.0.0.1:{values.get('VNC_PORT', '5900')}"}]
    if lab == "android":
        return [{"label": "noVNC", "address": "http://127.0.0.1:6080/"},
                {"label": "MobSF", "address": "http://127.0.0.1:8000/"},
                {"label": "mitmweb", "address": "http://127.0.0.1:8081/"},
                {"label": "mitmproxy", "address": "127.0.0.1:8080"},
                {"label": "ADB", "address": "127.0.0.1:5555"}]
    if lab == "macos":
        return [{"label": "Appium", "address": f"http://127.0.0.1:{values.get('APPIUM_PORT', '4723')}/"}]
    return []


def secret_values(root: str) -> list[str]:
    values = []
    for lab, meta in LABS.items():
        name = "config.env" if lab == "macos" else ".env"
        for key, value in env_entries(_read(os.path.join(root, meta["dir"], name))).items():
            if is_secret(key) and len(value) >= 3:
                values.append(value)
    for key, value in os.environ.items():
        if is_secret(key) and len(value) >= 3:
            values.append(value)
    try:
        from source_artifacts import SourceArtifacts
        raw = SourceArtifacts(root)._read(("control", "session-hmac.key"), 4096, optional=True)
        if raw:
            values.append(raw.decode("utf-8").strip())
    except (ValueError, OSError):
        pass
    key_file = os.environ.get("IQ_SESSION_HMAC_KEY_FILE")
    if key_file:
        try:
            import stat
            fd = os.open(key_file, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                if stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raw = stream.read(4097)
                    if len(raw) <= 4096:
                        values.append(raw.decode("utf-8").strip())
        except (OSError, ValueError):
            pass
    return sorted(set(values), key=len, reverse=True)


def redact_text(root: str, text: str, values=None) -> str:
    for value in secret_values(root) if values is None else values:
        if value:
            text = text.replace(value, "[redacted]")
    text = re.sub(r"(?i)(https?://)[^/\s@]+@", r"\1[redacted]@", text)
    text = re.sub(r"(?i)((?:password|token|secret|api[_-]?key|authorization)\s*[=:]\s*)[^\s,;]+", r"\1[redacted]", text)
    return text


# ── Plans ────────────────────────────────────────────────────────────────────

def setup_details(root: str, lab: str, provider: str) -> dict:
    """What "Install dependencies" needs and changes (os_lab_provider.rs::setup_details)."""
    meta = LABS[lab]
    values = {}
    if lab != "macos":
        values = env_entries(_read(os.path.join(root, meta["dir"], ".env.example")))
        values.update(env_entries(_read(os.path.join(root, meta["dir"], ".env"))))
    disk = values.get("DISK_SIZE") if SIZE.match(values.get("DISK_SIZE", "")) else meta.get("disk_default")
    if provider == "native-macos":
        deps = ["Xcode and an installed iOS Simulator runtime", "Homebrew", "Node.js", "Appium with XCUITest"]
        downloads = ["The setup script checks prerequisites and installs Homebrew packages. Xcode/runtime "
                     "installation and license acceptance remain explicit user actions."]
        privileges = "Runs as the current user; Xcode installation or license acceptance may need macOS authorization."
    else:
        deps = ["Ubuntu/Debian host or WSL2 distribution", "Docker or Podman and Compose",
                "KVM for accelerated guests", "Python 3 for restore/report workflows"]
        if lab == "android":
            deps.insert(2, "adb (Android platform tools)")
        downloads = ["The setup script may install system packages and a container runtime. Image tags and guest "
                     "install media resolve at start; their download size is unknown until then."]
        privileges = ("Requires administrator authorization. The script may change groups (docker, kvm), services, "
                      "KVM modules and explicitly configured firewall rules.")
    return {
        "dependencies": deps,
        "downloads": downloads,
        "privileges": privileges,
        "guestDisk": disk,
        "diskNote": ("Configured guest virtual disk capacity; allow extra space for images, install media, logs "
                     "and backups. Sparse allocation is not a free-space guarantee.") if disk else
                    ("Download and expanded sizes are unresolved. Reserve space for images, artifacts and backups."),
        "verifiedDownloads": False,
    }


def _scoped(root: str, *parts: str) -> str:
    path = os.path.realpath(os.path.join(root, *parts))
    real_root = os.path.realpath(root)
    if os.path.commonpath([real_root, path]) != real_root:
        raise PlanError("Path escapes the os-lab checkout")
    return path


def plan(root: str, request: dict, host: dict | None = None) -> dict:
    """Validate a lab request and build the exact command to run. Raises PlanError."""
    if request.get("lab") == "source":
        import source_control
        return source_control.plan(root, request)
    allowed = {"lab", "action", "profile", "cpus", "ram", "disk", "device", "wslDistro", "backup"}
    unknown = set(request) - allowed
    if unknown:
        raise PlanError("Unknown request fields: " + ", ".join(sorted(unknown)))
    lab = request.get("lab")
    action = request.get("action")
    if lab not in LABS:
        raise PlanError("Unknown lab")
    host = host or host_info(root)
    status = lab_status(lab, host)
    provider = status["provider"]
    if status["state"] == "unavailable" or not provider:
        raise PlanError(" ".join(status["reasons"]) or "This lab is unavailable on this host")
    if action not in {a["id"] for a in status["actions"]}:
        raise PlanError(f"Unsupported action for {LABS[lab]['label']}: {action}")

    profile = request.get("profile") or None
    if profile is not None and (not isinstance(profile, str) or not SAFE_NAME.match(profile) or profile.startswith("-")):
        raise PlanError("Invalid profile name")
    distro = request.get("wslDistro") or None
    if distro is not None and (not isinstance(distro, str) or len(distro) > 128 or distro.startswith("-")
                               or any(c in distro for c in "\r\n\0")):
        raise PlanError("Invalid WSL distribution")
    for key in ("cpus", "ram", "disk", "device"):
        if request.get(key) not in (None, "") and action != "resize":
            raise PlanError("Resource parameters are only accepted by resize")
    if request.get("backup"):
        raise PlanError("Restore is not available from the web console; use the lab's scripts/restore.sh")

    meta = LABS[lab]
    effects = ["Runs os-lab scripts in " + root + " and reads the lab's environment configuration"]
    privileged = action in PRIVILEGED
    timeout = 120
    manual = None

    if provider == "native-macos":
        if profile:
            raise PlanError("Native simulator settings live in ios-lab/mac/config.env")
        script, extra = {
            "status": ("status-mac.sh", None), "doctor": ("doctor-mac.sh", None),
            "setup": ("setup-mac.sh", "--install"), "start": ("run-simulator.sh", None),
            "stop": ("stop-simulator.sh", None), "appium-install": ("appium.sh", "install"), "appium-start": ("appium.sh", "start"),
            "appium-stop": ("appium.sh", "stop"),
        }[action]
        path = _scoped(root, "ios-lab", "mac", script)
        if not os.path.isfile(path):
            raise PlanError("Provider script is missing: ios-lab/mac/" + script)
        program, args = "bash", [path] + ([extra] if extra else [])
        privileged = False
        timeout = 3600 if action == "setup" else 1800 if action == "appium-install" else 300
    else:
        labctl = _scoped(root, "labctl")
        if not os.path.isfile(labctl):
            raise PlanError("labctl is missing from the checkout")
        lab_dir = meta["dir"]
        if action in PRIVILEGED or action == "backup":
            name = {"setup": "setup-ubuntu.sh", "service-install": "install-service.sh",
                    "service-uninstall": "uninstall-service.sh", "backup": "backup.sh"}[action]
            script = _scoped(root, lab_dir, "scripts", name)
            if not os.path.isfile(script):
                raise PlanError("This lab does not provide " + name)
            if profile:
                raise PlanError("Apply a profile first, then run this action")
            program, args = "bash", [script]
            effects.append({
                "setup": "Installs packages, changes user groups and may alter firewall rules according to configuration.",
                "service-install": "Changes system service boot configuration and may start the lab.",
                "service-uninstall": "Removes the systemd unit; a running lab keeps running until stopped.",
                "backup": "Writes a guest backup into the lab's backups/ folder. Ensure enough free space.",
            }[action])
            timeout = 3600
        else:
            args = [labctl, meta["labctl"]]
            if action == "monitor":
                args += ["monitor", "--once"]
            elif action == "profile":
                if not profile:
                    raise PlanError("Choose a profile to apply")
                if not os.path.isfile(_scoped(root, lab_dir, "profiles", profile + ".env")):
                    raise PlanError("Profile not found")
                args += ["profile", "use", profile]
                effects.append(f"Writes the {profile} preset into {lab_dir}/.env.")
                profile = None
            elif action == "resize":
                args.append("resize")
                cpus = request.get("cpus")
                if cpus not in (None, ""):
                    try:
                        cpus = int(cpus)
                    except (TypeError, ValueError):
                        raise PlanError("CPU count must be a number") from None
                    if not 1 <= cpus <= 128:
                        raise PlanError("CPU count must be 1–128")
                    args += ["--cpus", str(cpus)]
                for flag, key in (("--ram", "ram"), ("--disk", "disk")):
                    value = request.get(key)
                    if value in (None, ""):
                        continue
                    if not isinstance(value, str) or not SIZE.match(value):
                        raise PlanError("Sizes must be positive numbers with an optional M/G/T unit")
                    if key == "disk" and lab != "windows":
                        raise PlanError("Disk resize supports the Windows lab only")
                    args += [flag, value]
                device = request.get("device")
                if device not in (None, ""):
                    if lab != "android" or not isinstance(device, str) or len(device) > 128 or any(c in device for c in "\r\n\0"):
                        raise PlanError("Invalid Android device")
                    args += ["--device", device]
                if len(args) == 3:
                    raise PlanError("Choose a resource to resize")
                effects.append("Writes resource configuration to .env. Restart to apply; guest disks only grow.")
            else:
                args.append(action)
            if profile:
                if action not in ("status", "doctor", "start", "restart"):
                    raise PlanError("A one-shot profile applies to status, doctor, start and restart only")
                if not os.path.isfile(_scoped(root, lab_dir, "profiles", profile + ".env")):
                    raise PlanError("Profile not found")
                args += ["--profile", profile]
            program = "bash"
            if provider == "macos-containers" and action in ("start", "restart"):
                mode = env_entries(_read(os.path.join(root, lab_dir, ".env"))).get("LAB_MODE")
                if mode != "static" and profile != "lightweight":
                    raise PlanError("On macOS apply Android's lightweight (static) profile first; the emulator needs Linux/KVM")
            timeout = 900 if action in ("start", "restart") else 120

    if action in ("start", "stop", "restart", "appium-start", "appium-stop"):
        effects.append("Changes guest, container or service lifecycle.")

    # Elevation and WSL wrapping
    os_name = host["os"]
    if provider == "wsl2":
        if not distro:
            raise PlanError("Choose an installed WSL2 distribution")
        if distro not in host["wsl"]["distributions"]:
            raise PlanError("That WSL distribution is not installed")
        args = [wsl_path(distro, a) if os.path.isabs(a) else a for a in args]
        prefix = ["--distribution", distro, "--cd", wsl_path(distro, root), "--exec"]
        prefix += ["sudo", "-n", "bash"] if privileged else ["bash"]
        program, args = "wsl.exe", prefix + args
        if privileged:
            effects.append("Uses passwordless sudo inside the distribution; configure it or run the command in a WSL terminal.")
    elif privileged and os_name == "linux":
        user = os.environ.get("USER", "")
        graphical = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        manual = "sudo " + (f"LAB_USER={user} " if SAFE_NAME.match(user or "-") else "") + "bash " + " ".join(args)
        if _which("pkexec") and graphical:
            env = ["/usr/bin/env", f"LAB_USER={user}"] if SAFE_NAME.match(user or "-") else []
            program, args = "pkexec", env + ["/bin/bash"] + args
            effects.append("Asks for your password through the system authorization dialog (pkexec).")
        else:
            program = None
            effects.append("No graphical authorization agent is available here: run the command below in a terminal.")

    if privileged:
        effects.append("Administrator rights are required.")

    result = {
        "lab": lab, "action": action, "provider": provider, "workspace": root,
        "program": program, "args": args, "effects": effects, "timeoutSec": timeout,
        "privileged": privileged, "runnable": program is not None,
        "manualCommand": manual if program is None else None,
        "setup": setup_details(root, lab, provider) if action == "setup" else None,
        "display": " ".join(_quote(p) for p in ([program] if program else []) + args),
    }
    return result


def _quote(value: str) -> str:
    return value if re.match(r"^[A-Za-z0-9_./:=@%+,-]+$", value) else "'" + value.replace("'", "'\\''") + "'"


def wsl_path(distro: str, path: str) -> str:
    code, out = _capture(["wsl.exe", "--distribution", distro, "--exec", "wslpath", "-a", "-u", path], timeout=10)
    mapped = out.strip()
    if code != 0 or not mapped.startswith("/") or any(c in mapped for c in "\r\n\0"):
        raise PlanError("WSL could not translate the workspace path")
    return mapped


class PlanSigner:
    """Binds a confirmed plan to its request, so /start only runs what was previewed."""

    def __init__(self) -> None:
        self._key = _secrets.token_bytes(32)

    def sign(self, request: dict) -> str:
        body = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, body, hashlib.sha256).hexdigest()

    def verify(self, request: dict, token: str) -> bool:
        return isinstance(token, str) and hmac.compare_digest(self.sign(request), token)


# ── Jobs ─────────────────────────────────────────────────────────────────────

MAX_LINES = 4000


class Job:
    def __init__(self, label: str, lab: str, action: str, plan_: dict) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.label = label
        self.lab = lab
        self.action = action
        self.command = plan_["display"]
        self.state = "running"
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.exit_code: int | None = None
        self.error: str | None = None
        self.truncated = False
        self.lines: list[str] = []
        self.proc: subprocess.Popen | None = None
        self.cancelled = False

    def to_dict(self, logs: bool = False) -> dict:
        d = {"id": self.id, "label": self.label, "lab": self.lab, "action": self.action, "command": self.command,
             "state": self.state, "startedAt": self.started_at, "finishedAt": self.finished_at,
             "exitCode": self.exit_code, "error": self.error, "truncated": self.truncated, "lines": len(self.lines)}
        if logs:
            d["logs"] = list(self.lines)
        return d


class JobService:
    def __init__(self, root: str) -> None:
        self.root = root
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()

    def list(self) -> list[dict]:
        import source_jobs
        with self.lock:
            source_jobs.recover(self)
            return [j.to_dict() for j in sorted(self.jobs.values(), key=lambda j: j.started_at, reverse=True)]

    def get(self, job_id: str) -> Job | None:
        self.list()
        return self.jobs.get(job_id)

    def start(self, plan_: dict) -> Job:
        if not plan_.get("runnable"):
            raise PlanError("This action must be run in a terminal: " + (plan_.get("manualCommand") or ""))
        import source_jobs
        with self.lock:
            source_jobs.recover(self)
            busy = [j for j in self.jobs.values() if j.lab == plan_["lab"] and (j.state == "running" or j.proc is not None)]
            if busy:
                raise PlanError(f"Wait for the running {busy[0].label} job on this lab to finish")
            job = Job(f"{LABS[plan_['lab']]['label']} · {ACTION_INFO[plan_['action']][0]}", plan_["lab"], plan_["action"], plan_)
            if job.lab == "source":
                job.source_lock = source_jobs.claim(self.root)
            self.jobs[job.id] = job
            if job.lab == "source":
                try:
                    source_jobs.save(self)
                except Exception:
                    source_jobs.release(job.source_lock)
                    self.jobs.pop(job.id, None)
                    raise
            # Keep the 50 most recent jobs
            for old in sorted(self.jobs.values(), key=lambda j: j.started_at)[:-50]:
                if old.state != "running":
                    self.jobs.pop(old.id, None)
        try:
            threading.Thread(target=self._run, args=(job, plan_), daemon=True).start()
        except RuntimeError as e:
            job.state = "failed"
            job.error = f"Could not start the job worker: {e}"
            job.finished_at = time.time()
            if job.lab == "source":
                try:
                    source_jobs.save(self)
                finally:
                    source_jobs.release(job.source_lock)
                    job.source_lock = None
        return job

    def _run(self, job: Job, plan_: dict) -> None:
        timer: threading.Timer | None = None
        redact: list[str] = []
        try:
            redact = secret_values(self.root)
            env = dict(os.environ, NO_COLOR="1", TERM="dumb", PYTHONUNBUFFERED="1")
            if job.lab == "source" and job.action != "runtime" and not env.get("IQ_SESSION_HMAC_KEY") and not env.get("IQ_SESSION_HMAC_KEY_FILE"):
                import source_control
                key = source_control.checked(source_control.storage(self.root), "control/session-hmac.key")
                if key.is_file():
                    env["IQ_SESSION_HMAC_KEY_FILE"] = str(key)
            popen_kw: dict = {}
            if os.name == "posix":
                popen_kw["start_new_session"] = True
                if job.lab == "source":
                    popen_kw["pass_fds"] = (job.source_lock,)
            else:
                popen_kw["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            if job.cancelled:
                job.state = "cancelled"
                return
            job.proc = subprocess.Popen([plan_["program"]] + plan_["args"], cwd=self.root, env=env,
                                        stdin=subprocess.PIPE if job.lab == "source" else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        bufsize=1, text=True, encoding="utf-8", errors="replace", **popen_kw)
            timer = threading.Timer(plan_["timeoutSec"], self._timeout, args=(job,))
            timer.daemon = True
            timer.start()
            if job.cancelled:
                self._signal(job)
            assert job.proc.stdout is not None
            discard_line = False
            log_bytes = 0
            while True:
                line = job.proc.stdout.readline(8193)
                if not line:
                    break
                if len(line) > 8192 or discard_line:
                    discard_line = not line.endswith("\n")
                    job.truncated = True
                    if not discard_line:
                        job.lines.append("[oversized log line omitted]")
                    continue
                line = redact_text(self.root, ANSI.sub("", line.rstrip("\r\n")), redact)
                job.lines.append(line)
                log_bytes += len(line)
                if job.lab == "source":
                    while log_bytes > 1024 * 1024 and job.lines:
                        log_bytes -= len(job.lines.pop(0))
                        job.truncated = True
                if len(job.lines) > MAX_LINES:
                    del job.lines[: len(job.lines) - MAX_LINES]
                    job.truncated = True
            job.exit_code = job.proc.wait()
            if job.state == "running":
                job.state = "cancelled" if job.cancelled else ("succeeded" if job.exit_code == 0 else "failed")
                if job.state == "failed":
                    job.error = f"Command exited with status {job.exit_code}. See output below."
        except Exception as e:
            if job.state == "running":
                job.state = "failed"
            if job.proc and job.proc.poll() is None:
                self._signal(job)
                try:
                    job.exit_code = job.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    job.proc.kill()
                    job.exit_code = job.proc.wait()
            error = str(e)
            for value in redact:
                error = error.replace(value, "[redacted]")
            job.error = error or type(e).__name__
        finally:
            if timer:
                timer.cancel()
            job.finished_at = time.time()
            if job.lab == "source":
                import source_jobs
                try:
                    source_jobs.save(self)
                except (OSError, ValueError):
                    job.error = "Could not save the private Source job record; inspect storage permissions."
                    if job.state == "succeeded":
                        job.state = "failed"
                finally:
                    source_jobs.release(job.source_lock)
                    job.source_lock = None
            if job.proc and job.proc.stdin:
                job.proc.stdin.close()
            job.proc = None

    def _timeout(self, job: Job) -> None:
        if job.state == "running" and job.proc:
            job.state = "timed-out"
            job.error = "Timed out"
            self._signal(job)

    def cancel(self, job_id: str) -> Job:
        job = self.jobs.get(job_id)
        if not job:
            raise KeyError(job_id)
        if getattr(job, "external", False) and job.state == "running":
            raise PlanError("This Source job is owned by another console process")
        if job.state == "running":
            job.cancelled = True
            if job.proc:
                self._signal(job)
        return job

    @staticmethod
    def _signal(job: Job) -> None:
        proc = job.proc
        if not proc:
            return
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGTERM)
            else:
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=10)
        except (OSError, ProcessLookupError, subprocess.SubprocessError):
            pass
        if os.name == "posix":
            def force():
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
            timer = threading.Timer(2, force)
            timer.daemon = True
            timer.start()


# ── Monitor ──────────────────────────────────────────────────────────────────

def _json_lines(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            data = json.loads(text)
            return data if isinstance(data, list) else []
        except ValueError:
            return []
    rows = []
    for line in text.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def monitor(root: str, lab: str, host: dict | None = None) -> dict:
    """Container state and resource use for a lab (docker or podman on this host)."""
    if lab not in LABS:
        raise PlanError("Unknown lab")
    if lab == "source":
        import source_control
        return {"lab": lab, "state": source_control.readiness(root)["state"], "containers": [],
                "note": "Native Python analysis; no containers."}
    host = host or host_info(root)
    names = LABS[lab]["containers"]
    runtime = host["runtime"]
    if host["os"] == "windows":
        return {"lab": lab, "state": "unknown", "note": "On Windows the lab runs inside WSL2; run Status or Snapshot.", "containers": []}
    if not names:
        return {"lab": lab, "state": "unknown", "note": "This lab runs natively; use Status.", "containers": []}
    if not runtime:
        return {"lab": lab, "state": "no-runtime", "note": "No working Docker or Podman engine with Compose is available.", "containers": []}
    fmt = ["--format", "json"] if runtime == "podman" else ["--format", "{{json .}}"]
    code, out = _capture([runtime, "ps", "-a"] + fmt, timeout=8)
    if code != 0:
        return {"lab": lab, "state": "error", "note": out.strip()[:300] or "The container runtime did not answer.", "containers": []}
    containers = {}
    for row in _json_lines(out):
        raw = row.get("Names")
        row_names = raw if isinstance(raw, list) else str(raw or "").split(",")
        for name in row_names:
            name = name.strip().lstrip("/")
            if name in names:
                ports = row.get("Ports")
                if isinstance(ports, list):
                    ports = ", ".join(f"{p.get('host_ip') or '0.0.0.0'}:{p.get('host_port')}→{p.get('container_port')}"
                                      for p in ports if isinstance(p, dict) and p.get("host_port"))
                containers[name] = {"name": name, "state": str(row.get("State") or "").lower(),
                                    "status": row.get("Status") or "", "ports": ports or "", "cpu": "—", "memory": "—"}
    running = [n for n, c in containers.items() if c["state"] == "running"]
    if running:
        code, out = _capture([runtime, "stats", "--no-stream"] + fmt + running, timeout=10)
        if code == 0:
            for row in _json_lines(out):
                name = str(row.get("Name") or row.get("name") or "").lstrip("/")
                if name in containers:
                    containers[name]["cpu"] = row.get("CPUPerc") or row.get("cpu_percent") or row.get("CPU") or "—"
                    containers[name]["memory"] = row.get("MemUsage") or row.get("mem_usage") or "—"
    rows = [containers.get(n) or {"name": n, "state": "absent", "status": "not created", "ports": "", "cpu": "—", "memory": "—"}
            for n in names]
    overall = "running" if running and len(running) == len(rows) else "partial" if running else "stopped"
    return {"lab": lab, "state": overall, "runtime": runtime, "containers": rows, "checkedAt": time.time()}


def dropper_audit(root: str, target: str | None = None, rehearse: bool = False) -> dict:
    """Run the PENT-15 two-stage 'clean dropper' detector on a scoped path under root."""
    rel_target = target if target is not None else os.path.join("scripts", "analysis", "dropper_lab")
    scoped_target = _scoped(root, rel_target)
    if not os.path.exists(scoped_target):
        raise PlanError("Dropper analysis target does not exist: " + rel_target)
    if root not in sys.path:
        sys.path.insert(0, root)
    from scripts.analysis import dropper_detect

    report = dropper_detect.scan_path(scoped_target)
    if rehearse:
        from scripts.analysis.dropper_lab.stage2_server import run_lab_rehearsal

        report["rehearsal"] = run_lab_rehearsal(allow_exec=True)
    return report

