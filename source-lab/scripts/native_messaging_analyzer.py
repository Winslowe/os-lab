#!/usr/bin/env python3
"""Extension Native-Messaging Host Risk Analyzer (PENT-18).

Audits browser extension manifests (Manifest V2/V3) and OS-level Native Messaging
host manifests/binaries to detect high-risk browser-to-native privilege bridges.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

HIGH_RISK_BINARIES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "bash",
    "sh",
    "zsh",
    "dash",
    "python",
    "python3",
    "python.exe",
    "node",
    "node.exe",
    "perl",
    "ruby",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
}

WRITABLE_PATH_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "c:\\temp\\",
    "c:\\users\\public\\",
)


@dataclass
class Finding:
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    target: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditReport:
    scanned_extension_manifests: int = 0
    scanned_host_manifests: int = 0
    risk_score: int = 0
    risk_level: str = "LOW"
    findings: list[Finding] = field(default_factory=list)

    def finalize(self) -> None:
        weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 0}
        self.risk_score = min(100, sum(weights.get(f.severity, 0) for f in self.findings))
        if any(f.severity == "CRITICAL" for f in self.findings) or self.risk_score >= 70:
            self.risk_level = "CRITICAL"
        elif any(f.severity == "HIGH" for f in self.findings) or self.risk_score >= 40:
            self.risk_level = "HIGH"
        elif self.risk_score >= 15:
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"

    def to_dict(self) -> dict[str, Any]:
        self.finalize()
        return {
            "task": "PENT-18",
            "scanned_extension_manifests": self.scanned_extension_manifests,
            "scanned_host_manifests": self.scanned_host_manifests,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "findings": [asdict(f) for f in self.findings],
        }


def analyze_extension_manifest(manifest_path: Path, report: AuditReport) -> None:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        report.findings.append(
            Finding(
                rule_id="NM-EXT-PARSE",
                severity="LOW",
                target=str(manifest_path),
                message=f"Failed to parse extension manifest: {exc}",
            )
        )
        return

    if not isinstance(data, dict) or "manifest_version" not in data:
        return

    report.scanned_extension_manifests += 1
    perms = set(data.get("permissions") or [])
    optional_perms = set(data.get("optional_permissions") or [])
    host_perms = set(data.get("host_permissions") or [])
    all_perms = perms | optional_perms | host_perms

    if "nativeMessaging" not in (perms | optional_perms):
        return

    ext_name = data.get("name", manifest_path.parent.name)
    report.findings.append(
        Finding(
            rule_id="NM-EXT-CAPABILITY",
            severity="MEDIUM",
            target=str(manifest_path),
            message=f"Extension '{ext_name}' requests nativeMessaging bridge privilege.",
            evidence={"extension": ext_name, "manifest_version": data.get("manifest_version")},
        )
    )

    broad_hosts = [p for p in all_perms if p in {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}]
    if broad_hosts:
        report.findings.append(
            Finding(
                rule_id="NM-EXT-BROAD-HOST",
                severity="HIGH",
                target=str(manifest_path),
                message="Extension combines nativeMessaging with broad host access (arbitrary page -> native execution bridge).",
                evidence={"extension": ext_name, "broad_hosts": sorted(broad_hosts)},
            )
        )

    sensitive_combos = sorted(all_perms & {"cookies", "webRequest", "webRequestBlocking", "debugger", "tabs", "scripting"})
    if sensitive_combos:
        report.findings.append(
            Finding(
                rule_id="NM-EXT-SENSITIVE-COMBO",
                severity="HIGH",
                target=str(manifest_path),
                message="Extension pairs nativeMessaging with high-privilege browser APIs.",
                evidence={"extension": ext_name, "permissions": sensitive_combos},
            )
        )

    csp = data.get("content_security_policy")
    csp_str = json.dumps(csp) if isinstance(csp, dict) else str(csp or "")
    if "unsafe-eval" in csp_str or "unsafe-inline" in csp_str:
        report.findings.append(
            Finding(
                rule_id="NM-EXT-WEAK-CSP",
                severity="HIGH",
                target=str(manifest_path),
                message="Weak CSP (unsafe-eval/unsafe-inline) increases XSS-to-nativeMessaging RCE risk.",
                evidence={"extension": ext_name, "csp": csp},
            )
        )


def analyze_host_manifest(manifest_path: Path, report: AuditReport, check_fs: bool = True) -> None:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        report.findings.append(
            Finding(
                rule_id="NM-HOST-PARSE",
                severity="LOW",
                target=str(manifest_path),
                message=f"Failed to parse native host manifest: {exc}",
            )
        )
        return

    if not isinstance(data, dict) or data.get("type") != "stdio" or "path" not in data:
        return

    report.scanned_host_manifests += 1
    host_name = str(data.get("name", manifest_path.stem))
    raw_bin_path = str(data.get("path", "")).strip()
    allowed_origins = data.get("allowed_origins") or []
    allowed_extensions = data.get("allowed_extensions") or []

    # 1. Wildcard or overly broad allowed_origins / allowed_extensions check
    if not allowed_origins and not allowed_extensions:
        report.findings.append(
            Finding(
                rule_id="NM-HOST-NO-ALLOWLIST",
                severity="HIGH",
                target=str(manifest_path),
                message=f"Native host '{host_name}' defines neither allowed_origins nor allowed_extensions.",
                evidence={"host_name": host_name},
            )
        )

    wildcard_origins = [
        o for o in allowed_origins
        if "*" in str(o) or not str(o).startswith("chrome-extension://")
    ]
    if wildcard_origins:
        report.findings.append(
            Finding(
                rule_id="NM-HOST-WILDCARD-ORIGIN",
                severity="CRITICAL",
                target=str(manifest_path),
                message=f"Native host '{host_name}' allows wildcard or non-extension origin.",
                evidence={"host_name": host_name, "invalid_origins": wildcard_origins},
            )
        )

    if any("*" in str(ext) for ext in allowed_extensions):
        report.findings.append(
            Finding(
                rule_id="NM-HOST-WILDCARD-EXT",
                severity="CRITICAL",
                target=str(manifest_path),
                message=f"Native host '{host_name}' allows wildcard extension ID.",
                evidence={"host_name": host_name, "allowed_extensions": allowed_extensions},
            )
        )

    # 2. Dangerous interpreter / shell binary check
    bin_name = Path(raw_bin_path.replace("\\", "/")).name.lower()
    if bin_name in HIGH_RISK_BINARIES:
        report.findings.append(
            Finding(
                rule_id="NM-HOST-INTERPRETER-BIN",
                severity="CRITICAL",
                target=str(manifest_path),
                message=f"Native host '{host_name}' directly exposes a shell/interpreter binary ({bin_name}).",
                evidence={"host_name": host_name, "binary": raw_bin_path},
            )
        )

    # 3. Relative or world-writable staging directory path check
    norm_path = raw_bin_path.replace("\\", "/").lower()
    if not (raw_bin_path.startswith("/") or (len(raw_bin_path) > 2 and raw_bin_path[1] == ":")):
        report.findings.append(
            Finding(
                rule_id="NM-HOST-RELATIVE-PATH",
                severity="HIGH",
                target=str(manifest_path),
                message=f"Native host '{host_name}' uses a relative binary path (PATH hijacking risk).",
                evidence={"host_name": host_name, "binary": raw_bin_path},
            )
        )

    if any(norm_path.startswith(prefix) for prefix in WRITABLE_PATH_PREFIXES):
        report.findings.append(
            Finding(
                rule_id="NM-HOST-TEMP-DIR",
                severity="HIGH",
                target=str(manifest_path),
                message=f"Native host '{host_name}' executes from a shared/temporary directory.",
                evidence={"host_name": host_name, "binary": raw_bin_path},
            )
        )

    # 4. Filesystem existence & world-writable permissions check (when present locally)
    if check_fs and raw_bin_path.startswith("/"):
        bin_file = Path(raw_bin_path)
        if not bin_file.exists():
            report.findings.append(
                Finding(
                    rule_id="NM-HOST-DANGLING-BIN",
                    severity="MEDIUM",
                    target=str(manifest_path),
                    message=f"Native host '{host_name}' points to missing binary (binary planting risk).",
                    evidence={"host_name": host_name, "binary": raw_bin_path},
                )
            )
        else:
            try:
                mode = bin_file.stat().st_mode
                if mode & stat.S_IWOTH:
                    report.findings.append(
                        Finding(
                            rule_id="NM-HOST-WORLD-WRITABLE",
                            severity="CRITICAL",
                            target=str(manifest_path),
                            message=f"Native host binary '{raw_bin_path}' is world-writable (local privilege escalation).",
                            evidence={"host_name": host_name, "mode": oct(mode)},
                        )
                    )
            except OSError:
                pass


def scan_target(target_path: Path, check_fs: bool = True) -> AuditReport:
    report = AuditReport()
    files = [target_path] if target_path.is_file() else sorted(target_path.rglob("*.json"))

    for fpath in files:
        if fpath.name == "manifest.json":
            analyze_extension_manifest(fpath, report)
        else:
            # Could be either a native messaging host manifest or an extension manifest
            try:
                raw = json.loads(fpath.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(raw, dict):
                if raw.get("type") == "stdio" and "path" in raw:
                    analyze_host_manifest(fpath, report, check_fs=check_fs)
                elif "manifest_version" in raw:
                    analyze_extension_manifest(fpath, report)

    report.finalize()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PENT-18: Extension Native-Messaging Host Risk Analyzer"
    )
    parser.add_argument("target", type=Path, help="Path to extension/host manifest JSON or directory")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON report")
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with code 2 if HIGH or CRITICAL findings are detected",
    )
    parser.add_argument(
        "--no-fs-check",
        action="store_true",
        help="Skip local filesystem existence/permission checks for host binaries",
    )
    args = parser.parse_args(argv)

    if not args.target.exists():
        print(f"[ERROR] Target path does not exist: {args.target}", file=sys.stderr)
        return 1

    report = scan_target(args.target, check_fs=not args.no_fs_check)
    result = report.to_dict()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== PENT-18 Native-Messaging Risk Report ({args.target}) ===")
        print(
            f"Extensions scanned: {result['scanned_extension_manifests']} | "
            f"Host manifests scanned: {result['scanned_host_manifests']}"
        )
        print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']}/100)")
        if not result["findings"]:
            print("[OK] No high-risk nativeMessaging bridge issues detected.")
        for item in result["findings"]:
            print(f"[{item['severity']}] {item['rule_id']} ({item['target']}): {item['message']}")

    if args.fail_on_high and result["risk_level"] in {"HIGH", "CRITICAL"}:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
