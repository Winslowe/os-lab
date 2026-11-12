#!/usr/bin/env python3
"""Two-Stage 'Clean Dropper' Static & Behavioral Detection Engine (PENT-15).

Detects the 'clean loader -> deferred cloud stage-2 payload' trojan pattern taught in
MYO062 (19.10 lecture):
  1. Stage-1 Remote Fetch (urllib / requests / fetch / XMLHttpRequest)
  2. Deferred Trigger / Evasion Gate (time.sleep / threading.Timer / setTimeout)
  3. Payload Decode / Unpack (base64.b64decode / atob / zlib.decompress / marshal)
  4. Stage-2 Dynamic Execution Sink (exec / eval / compile / new Function)

Rather than alerting on isolated network calls, the engine correlates primitives across
stages within the same artifact so benign utilities and ordinary HTTP helpers remain CLEAN
while multi-stage droppers are flagged as HIGH / CRITICAL with line-level evidence.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import pathlib
import re
import sys
from typing import Any

SUPPORTED_EXTENSIONS = {".py", ".js", ".mjs", ".cjs", ".ts", ".sh"}

# Regex signature rules applied per line (comments stripped prior to matching).
LINE_SIGNATURES: list[dict[str, Any]] = [
    {
        "id": "STAGE1_REMOTE_FETCH",
        "stage": "fetch",
        "severity": "MEDIUM",
        "weight": 20,
        "title": "Remote stage payload fetch",
        "pattern": re.compile(
            r"\b(?:urllib\.request\.(?:urlopen|Request)|requests\.(?:get|post|request)|"
            r"http\.client\.HTTP(?:S)?Connection|fetch\s*\(|new\s+XMLHttpRequest\b|"
            r"axios\.(?:get|post)|curl\s+-[fsSL]+|wget\s+-qO-)"
        ),
    },
    {
        "id": "STAGE_DEFERRED_TRIGGER",
        "stage": "defer",
        "severity": "LOW",
        "weight": 10,
        "title": "Deferred or time-gated execution window",
        "pattern": re.compile(
            r"\b(?:time\.sleep\s*\(|threading\.Timer\s*\(|setTimeout\s*\(|"
            r"setInterval\s*\(|requestIdleCallback\s*\(|chrome\.alarms\.create\b)"
        ),
    },
    {
        "id": "STAGE_PAYLOAD_DECODE",
        "stage": "decode",
        "severity": "MEDIUM",
        "weight": 15,
        "title": "Encoded or compressed stage-2 payload unpacking",
        "pattern": re.compile(
            r"\b(?:base64\.b64decode\s*\(|atob\s*\(|zlib\.decompress\s*\(|"
            r"marshal\.loads\s*\(|Buffer\.from\s*\([^)]*['\"]base64['\"]|"
            r"String\.fromCharCode\s*\()"
        ),
    },
    {
        "id": "STAGE2_DYNAMIC_EXEC",
        "stage": "exec",
        "severity": "HIGH",
        "weight": 35,
        "title": "Dynamic runtime code evaluation sink",
        "pattern": re.compile(
            r"(?:\b(?:exec|eval)\s*\(|\bcompile\s*\([^)]*['\"]exec['\"]|"
            r"\bnew\s+Function\s*\(|\bFunction\s*\([^)]*\)\s*\(|"
            r"\bchrome\.scripting\.executeScript\b|\bloadUrl\s*\(\s*['\"]javascript:)"
        ),
    },
]

PYTHON_AST_CALL_MAP: dict[str, tuple[str, str, str, int, str]] = {
    "urllib.request.urlopen": ("STAGE1_REMOTE_FETCH", "fetch", "MEDIUM", 20, "AST call to urllib.request.urlopen"),
    "urllib.request.Request": ("STAGE1_REMOTE_FETCH", "fetch", "MEDIUM", 20, "AST call to urllib.request.Request"),
    "requests.get": ("STAGE1_REMOTE_FETCH", "fetch", "MEDIUM", 20, "AST call to requests.get"),
    "requests.post": ("STAGE1_REMOTE_FETCH", "fetch", "MEDIUM", 20, "AST call to requests.post"),
    "time.sleep": ("STAGE_DEFERRED_TRIGGER", "defer", "LOW", 10, "AST call to time.sleep"),
    "threading.Timer": ("STAGE_DEFERRED_TRIGGER", "defer", "LOW", 10, "AST call to threading.Timer"),
    "base64.b64decode": ("STAGE_PAYLOAD_DECODE", "decode", "MEDIUM", 15, "AST call to base64.b64decode"),
    "zlib.decompress": ("STAGE_PAYLOAD_DECODE", "decode", "MEDIUM", 15, "AST call to zlib.decompress"),
    "marshal.loads": ("STAGE_PAYLOAD_DECODE", "decode", "MEDIUM", 15, "AST call to marshal.loads"),
    "exec": ("STAGE2_DYNAMIC_EXEC", "exec", "HIGH", 35, "AST dynamic code execution via exec()"),
    "eval": ("STAGE2_DYNAMIC_EXEC", "exec", "HIGH", 35, "AST dynamic code evaluation via eval()"),
    "compile": ("STAGE2_DYNAMIC_EXEC", "exec", "HIGH", 35, "AST runtime code compilation via compile()"),
}


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _analyze_python_ast(content: str, lines: list[str]) -> list[dict[str, Any]]:
    """Extract call-site indicators from Python source using the standard-library AST."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _dotted_name(node.func)
        if call_name not in PYTHON_AST_CALL_MAP:
            continue
        rule_id, stage, severity, weight, title = PYTHON_AST_CALL_MAP[call_name]
        lineno = int(getattr(node, "lineno", 1))
        snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else call_name
        findings.append(
            {
                "rule_id": rule_id,
                "stage": stage,
                "severity": severity,
                "weight": weight,
                "title": title,
                "line": lineno,
                "evidence": snippet[:200],
                "source": "python-ast",
            }
        )
    return findings


def _is_comment_line(stripped: str) -> bool:
    return (
        not stripped
        or stripped.startswith("#")
        or stripped.startswith("//")
        or stripped.startswith("/*")
        or stripped.startswith("*")
    )


def _analyze_lines(lines: list[str], is_python: bool = False) -> list[dict[str, Any]]:
    """Scan non-comment source lines with regex signatures."""
    findings: list[dict[str, Any]] = []
    in_block_comment = False

    for idx, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if "/*" in stripped:
            in_block_comment = True
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if _is_comment_line(stripped):
            continue

        # Strip trailing inline comments before pattern matching.
        code_part = stripped.split("#", 1)[0] if is_python else stripped.split("//", 1)[0]
        for sig in LINE_SIGNATURES:
            if sig["pattern"].search(code_part):
                findings.append(
                    {
                        "rule_id": sig["id"],
                        "stage": sig["stage"],
                        "severity": sig["severity"],
                        "weight": sig["weight"],
                        "title": sig["title"],
                        "line": idx,
                        "evidence": stripped[:200],
                        "source": "line-signature",
                    }
                )
    return findings


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings by (rule_id, line), preferring AST-backed evidence."""
    by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for item in findings:
        key = (item["rule_id"], int(item["line"]))
        existing = by_key.get(key)
        if existing is None or (item.get("source") == "python-ast" and existing.get("source") != "python-ast"):
            by_key[key] = item
    return sorted(by_key.values(), key=lambda f: (int(f["line"]), f["rule_id"]))


def _classify_risk(score: int, stages_present: set[str]) -> tuple[str, str]:
    """Return (risk_level, classification) based on correlated dropper stages and score."""
    has_fetch_and_exec = {"fetch", "exec"}.issubset(stages_present)
    if has_fetch_and_exec and score >= 75:
        return "CRITICAL", "TWO_STAGE_DROPPER"
    if has_fetch_and_exec or score >= 55:
        return "HIGH", "TWO_STAGE_DROPPER"
    if "exec" in stages_present and score >= 35:
        return "MEDIUM", "SUSPICIOUS_DYNAMIC_LOADER"
    if score >= 25 and len(stages_present) >= 2:
        return "LOW", "STAGING_PRIMITIVES_ONLY"
    return "CLEAN", "BENIGN"


def scan_content(content: str, filename: str = "<memory>") -> dict[str, Any]:
    """Analyze a single source string for two-stage 'clean dropper' indicators."""
    lines = content.splitlines()
    ext = os.path.splitext(filename)[1].lower()
    is_python = ext == ".py" or content.lstrip().startswith("#!/usr/bin/env python")

    raw_findings: list[dict[str, Any]] = []
    if is_python:
        raw_findings.extend(_analyze_python_ast(content, lines))
    raw_findings.extend(_analyze_lines(lines, is_python=is_python))

    findings = _deduplicate_findings(raw_findings)
    stages_present = {f["stage"] for f in findings}

    # Base score from unique stages + capped per-finding contribution
    stage_weights = {"fetch": 20, "defer": 10, "decode": 15, "exec": 35}
    score = sum(stage_weights.get(st, 0) for st in stages_present)

    # Multi-stage correlation rules (core of PENT-15):
    # A solitary fetch or sleep is benign (e.g. an HTTP server or retry helper).
    # Only when remote fetch is paired with dynamic execution do we elevate to a dropper chain.
    if {"fetch", "exec"}.issubset(stages_present):
        first_fetch_line = min(f["line"] for f in findings if f["stage"] == "fetch")
        first_exec_line = min(f["line"] for f in findings if f["stage"] == "exec")
        score += 20
        findings.append(
            {
                "rule_id": "DROPPER_CHAIN_FETCH_EXEC",
                "stage": "chain",
                "severity": "CRITICAL",
                "weight": 20,
                "title": "Correlated two-stage dropper chain (remote fetch -> dynamic code execution)",
                "line": first_exec_line,
                "evidence": f"Remote fetch at line {first_fetch_line} flows into dynamic exec sink at line {first_exec_line}",
                "source": "correlation-engine",
            }
        )
        if {"defer", "decode"}.issubset(stages_present):
            score += 10
            findings.append(
                {
                    "rule_id": "DROPPER_FULL_FOUR_STAGE_CHAIN",
                    "stage": "chain",
                    "severity": "CRITICAL",
                    "weight": 10,
                    "title": "Full 4-stage clean dropper pattern (defer + remote fetch + decode + dynamic exec)",
                    "line": first_exec_line,
                    "evidence": "Matches clean-loader evasion gate + remote fetch + payload decode + runtime eval/exec",
                    "source": "correlation-engine",
                }
            )
    elif "exec" not in stages_present:
        # Without any dynamic execution sink, cap the score so ordinary servers/utilities stay CLEAN/LOW.
        score = min(score, 20)

    score = min(100, max(0, score))
    risk_level, classification = _classify_risk(score, stages_present)

    return {
        "file": str(filename).replace("\\", "/"),
        "sha256": hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest(),
        "lines": len(lines),
        "risk_score": score,
        "risk_level": risk_level,
        "classification": classification,
        "stages_detected": sorted(stages_present),
        "finding_count": len(findings),
        "findings": findings,
    }


def scan_file(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Read and scan a single file on disk."""
    p = pathlib.Path(path)
    content = p.read_text(encoding="utf-8", errors="replace")
    return scan_content(content, filename=str(p))


def scan_path(target: str | os.PathLike[str]) -> dict[str, Any]:
    """Scan a file or recursively scan a directory for two-stage dropper artifacts."""
    root_path = pathlib.Path(target)
    if not root_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")

    files_to_scan: list[pathlib.Path] = []
    if root_path.is_file():
        files_to_scan.append(root_path)
    else:
        for candidate in sorted(root_path.rglob("*")):
            if not candidate.is_file():
                continue
            if candidate.name == "__init__.py" or "__pycache__" in candidate.parts:
                continue
            if candidate.suffix.lower() in SUPPORTED_EXTENSIONS:
                files_to_scan.append(candidate)

    reports = [scan_file(f) for f in files_to_scan]
    dropper_files = [r for r in reports if r["classification"] == "TWO_STAGE_DROPPER"]
    high_or_critical = [r for r in reports if r["risk_level"] in {"HIGH", "CRITICAL"}]

    return {
        "task_id": "PENT-15",
        "scanner": "os-lab-dropper-detect/1.0",
        "target": str(root_path).replace("\\", "/"),
        "total_files_scanned": len(reports),
        "dropper_count": len(dropper_files),
        "high_or_critical_count": len(high_or_critical),
        "clean_count": sum(1 for r in reports if r["risk_level"] == "CLEAN"),
        "max_risk_score": max((r["risk_score"] for r in reports), default=0),
        "files": reports,
    }


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render a human-readable Markdown audit report from ``scan_path`` output."""
    lines = [
        "# PENT-15 — Two-Stage 'Clean Dropper' Detection Report",
        "",
        f"- **Target:** `{report['target']}`",
        f"- **Files Scanned:** `{report['total_files_scanned']}`",
        f"- **Two-Stage Droppers Flagged:** `{report['dropper_count']}`",
        f"- **Clean / Benign Files:** `{report['clean_count']}`",
        f"- **Peak Risk Score:** `{report['max_risk_score']} / 100`",
        "",
        "## Summary Table",
        "",
        "| File | Classification | Risk Level | Score | Stages Detected | Findings |",
        "| --- | --- | --- | :---: | --- | :---: |",
    ]
    for item in report.get("files", []):
        fname = os.path.basename(item["file"])
        stages = ", ".join(item["stages_detected"]) if item["stages_detected"] else "none"
        lines.append(
            f"| `{fname}` | `{item['classification']}` | **{item['risk_level']}** | "
            f"`{item['risk_score']}/100` | `{stages}` | {item['finding_count']} |"
        )

    lines.append("")
    lines.append("## Detailed Evidence")
    for item in report.get("files", []):
        lines.append("")
        lines.append(f"### `{item['file']}` (`{item['risk_level']}` — `{item['risk_score']}/100`)")
        lines.append(f"- **SHA-256:** `{item['sha256']}`")
        lines.append(f"- **Classification:** `{item['classification']}`")
        if not item["findings"]:
            lines.append("- No suspicious staging or dynamic execution indicators detected.")
            continue
        for f in item["findings"]:
            lines.append(
                f"- **[{f['severity']}] `{f['rule_id']}`** (line {f['line']}): {f['title']} — `{f['evidence']}`"
            )

    if "rehearsal" in report:
        reh = report["rehearsal"]
        lines.extend(
            [
                "",
                "## Isolated Loopback Rehearsal Telemetry (`127.0.0.1`)",
                "",
                f"- **Loopback Server:** `{reh['server_bind']}`",
                f"- **Stage-2 Endpoint:** `{reh['stage2_url']}`",
                f"- **Stage-2 Payload SHA-256:** `{reh['stage1_trace']['payload_sha256']}`",
                f"- **Sandbox Execution Marker:** `{reh['stage1_trace']['activation']['marker']}`",
            ]
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PENT-15: Static & behavioral detector for two-stage 'clean dropper' artifacts."
    )
    default_target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dropper_lab")
    parser.add_argument(
        "target",
        nargs="?",
        default=default_target,
        help="File or directory to scan (defaults to scripts/analysis/dropper_lab)",
    )
    parser.add_argument("--json", action="store_true", help="Emit structured JSON report")
    parser.add_argument("--markdown", action="store_true", help="Emit Markdown report")
    parser.add_argument(
        "--rehearse",
        action="store_true",
        help="Run the isolated 127.0.0.1 two-stage rehearsal before emitting the report",
    )
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Return exit code 1 when one or more HIGH/CRITICAL dropper files are detected",
    )
    args = parser.parse_args(argv)

    try:
        report = scan_path(args.target)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.rehearse:
        scripts_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        repo_root = os.path.dirname(scripts_dir)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from scripts.analysis.dropper_lab.stage2_server import run_lab_rehearsal

        report["rehearsal"] = run_lab_rehearsal(allow_exec=True)

    if args.markdown and not args.json:
        print(render_markdown_report(report), end="")
    else:
        print(json.dumps(report, indent=2))

    if args.fail_on_high and report["high_or_critical_count"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
