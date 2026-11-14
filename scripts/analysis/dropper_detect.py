#!/usr/bin/env python3
"""Two-Stage 'Clean Dropper' Static & Behavioral Detection Engine (PENT-15).

Detects the 'clean loader -> deferred cloud stage-2 payload' trojan pattern taught in
MYO062 (19.10 lecture):
  1. Stage-1 Remote Fetch (urllib / requests / fetch / XMLHttpRequest)
  2. Deferred Trigger / Evasion Gate (time.sleep / threading.Timer / setTimeout)
  3. Payload Decode / Unpack (base64.b64decode / atob / zlib.decompress / marshal)
  4. Stage-2 Dynamic Execution Sink (exec / eval / compile / new Function)

Rather than alerting on isolated network calls or unrelated functions, the engine
correlates data flow from remote fetch into dynamic execution sinks so benign
utilities and ordinary HTTP helpers remain CLEAN while multi-stage droppers are
flagged as HIGH / CRITICAL with line-level evidence.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import sys
import tokenize
from typing import Any

SUPPORTED_EXTENSIONS = {".py", ".js", ".mjs", ".cjs", ".ts", ".sh"}
DEFAULT_MAX_FILE_BYTES = 1_048_576  # 1 MiB per source artifact
DEFAULT_MAX_FILES = 2000

# Regex signature rules applied per line (comments & Python string literals stripped prior to matching).
LINE_SIGNATURES: list[dict[str, Any]] = [
    {
        "id": "STAGE1_REMOTE_FETCH",
        "stage": "fetch",
        "severity": "MEDIUM",
        "weight": 20,
        "title": "Remote stage payload fetch",
        "pattern": re.compile(
            r"\b(?:urllib\.request\.(?:urlopen|Request|build_opener)|requests\.(?:get|post|request)|"
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
    "urllib.request.build_opener": ("STAGE1_REMOTE_FETCH", "fetch", "MEDIUM", 20, "AST call to urllib.request.build_opener"),
    "http.client.HTTPConnection": ("STAGE1_REMOTE_FETCH", "fetch", "MEDIUM", 20, "AST call to http.client.HTTPConnection"),
    "http.client.HTTPSConnection": ("STAGE1_REMOTE_FETCH", "fetch", "MEDIUM", 20, "AST call to http.client.HTTPSConnection"),
    "requests.get": ("STAGE1_REMOTE_FETCH", "fetch", "MEDIUM", 20, "AST call to requests.get"),
    "requests.post": ("STAGE1_REMOTE_FETCH", "fetch", "MEDIUM", 20, "AST call to requests.post"),
    "requests.request": ("STAGE1_REMOTE_FETCH", "fetch", "MEDIUM", 20, "AST call to requests.request"),
    "time.sleep": ("STAGE_DEFERRED_TRIGGER", "defer", "LOW", 10, "AST call to time.sleep"),
    "threading.Timer": ("STAGE_DEFERRED_TRIGGER", "defer", "LOW", 10, "AST call to threading.Timer"),
    "base64.b64decode": ("STAGE_PAYLOAD_DECODE", "decode", "MEDIUM", 15, "AST call to base64.b64decode"),
    "zlib.decompress": ("STAGE_PAYLOAD_DECODE", "decode", "MEDIUM", 15, "AST call to zlib.decompress"),
    "marshal.loads": ("STAGE_PAYLOAD_DECODE", "decode", "MEDIUM", 15, "AST call to marshal.loads"),
    "exec": ("STAGE2_DYNAMIC_EXEC", "exec", "HIGH", 35, "AST dynamic code execution via exec()"),
    "builtins.exec": ("STAGE2_DYNAMIC_EXEC", "exec", "HIGH", 35, "AST dynamic code execution via builtins.exec()"),
    "eval": ("STAGE2_DYNAMIC_EXEC", "exec", "HIGH", 35, "AST dynamic code evaluation via eval()"),
    "builtins.eval": ("STAGE2_DYNAMIC_EXEC", "exec", "HIGH", 35, "AST dynamic code evaluation via builtins.eval()"),
    "compile": ("STAGE2_DYNAMIC_EXEC", "exec", "HIGH", 35, "AST runtime code compilation via compile()"),
    "builtins.compile": ("STAGE2_DYNAMIC_EXEC", "exec", "HIGH", 35, "AST runtime code compilation via builtins.compile()"),
}


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _collect_python_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local imported names and aliases back to canonical module/symbol names."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.asname:
                    aliases[item.asname] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name == "*":
                    continue
                local_name = item.asname or item.name
                aliases[local_name] = f"{node.module}.{item.name}"
    return aliases


def _resolve_python_call_name(node: ast.AST, aliases: dict[str, str]) -> str:
    raw = _dotted_name(node)
    if not raw:
        return ""
    head, *rest = raw.split(".", 1)
    if head in aliases:
        resolved = aliases[head]
        return f"{resolved}.{rest[0]}" if rest else resolved
    return raw


def _expr_references_names(node: ast.AST, names: set[str]) -> bool:
    if not names:
        return False
    return any(isinstance(sub, ast.Name) and sub.id in names for sub in ast.walk(node))


def _expr_has_fetch_call(
    node: ast.AST,
    aliases: dict[str, str],
    fetch_funcs: set[str],
) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            resolved = _resolve_python_call_name(sub.func, aliases)
            if resolved in PYTHON_AST_CALL_MAP and PYTHON_AST_CALL_MAP[resolved][1] == "fetch":
                return True
            if isinstance(sub.func, ast.Name) and sub.func.id in fetch_funcs:
                return True
    return False


def _stmt_taint_pass(
    stmts: list[ast.stmt],
    tainted: set[str],
    aliases: dict[str, str],
    fetch_funcs: set[str],
    passthrough_funcs: set[str],
    exec_funcs: dict[str, set[int]],
) -> tuple[bool, bool]:
    """Propagate taint within a flat/nested Python block; returns (sink_reached, returns_tainted)."""
    sink_reached = False
    returns_tainted = False

    def _is_expr_tainted(expr: ast.AST) -> bool:
        if _expr_references_names(expr, tainted):
            return True
        if _expr_has_fetch_call(expr, aliases, fetch_funcs):
            return True
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                if sub.func.id in passthrough_funcs and any(_is_expr_tainted(a) for a in sub.args):
                    return True
        return False

    def _check_calls(node: ast.AST) -> None:
        nonlocal sink_reached
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            resolved = _resolve_python_call_name(sub.func, aliases)
            if resolved in PYTHON_AST_CALL_MAP and PYTHON_AST_CALL_MAP[resolved][1] == "exec":
                if any(_is_expr_tainted(a) for a in sub.args) or any(
                    _is_expr_tainted(kw.value) for kw in sub.keywords
                ):
                    sink_reached = True
            if isinstance(sub.func, ast.Name) and sub.func.id in exec_funcs:
                param_indices = exec_funcs[sub.func.id]
                for idx in param_indices:
                    if idx < len(sub.args) and _is_expr_tainted(sub.args[idx]):
                        sink_reached = True

    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        _check_calls(stmt)
        if isinstance(stmt, ast.Assign):
            if _is_expr_tainted(stmt.value):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        tainted.add(target.id)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            if _is_expr_tainted(stmt.value) and isinstance(stmt.target, ast.Name):
                tainted.add(stmt.target.id)
        elif isinstance(stmt, ast.With):
            for item in stmt.items:
                _check_calls(item.context_expr)
                if item.optional_vars is not None and isinstance(item.optional_vars, ast.Name):
                    if _is_expr_tainted(item.context_expr):
                        tainted.add(item.optional_vars.id)
            s_hit, r_hit = _stmt_taint_pass(
                stmt.body, tainted, aliases, fetch_funcs, passthrough_funcs, exec_funcs
            )
            sink_reached = sink_reached or s_hit
            returns_tainted = returns_tainted or r_hit
        elif isinstance(stmt, ast.Return) and stmt.value is not None:
            if _is_expr_tainted(stmt.value):
                returns_tainted = True
        else:
            for child_attr in ("body", "orelse", "finalbody"):
                child = getattr(stmt, child_attr, None)
                if isinstance(child, list) and child and all(isinstance(x, ast.stmt) for x in child):
                    s_hit, r_hit = _stmt_taint_pass(
                        child, tainted, aliases, fetch_funcs, passthrough_funcs, exec_funcs
                    )
                    sink_reached = sink_reached or s_hit
                    returns_tainted = returns_tainted or r_hit
            handlers = getattr(stmt, "handlers", None)
            if isinstance(handlers, list):
                for h in handlers:
                    s_hit, r_hit = _stmt_taint_pass(
                        h.body, tainted, aliases, fetch_funcs, passthrough_funcs, exec_funcs
                    )
                    sink_reached = sink_reached or s_hit
                    returns_tainted = returns_tainted or r_hit
    return sink_reached, returns_tainted


def _python_has_fetch_to_exec_flow(tree: ast.Module, aliases: dict[str, str]) -> bool:
    """Confirm whether fetched data can reach a dynamic exec sink intra- or inter-procedurally."""
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    fetch_funcs: set[str] = set()
    passthrough_funcs: set[str] = set()
    exec_funcs: dict[str, set[int]] = {}

    # Pass 1: discover functions returning fetched values, passthrough transforms, and param->exec sinks.
    for fn in funcs:
        params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
        for idx, pname in enumerate(params):
            s_hit, r_hit = _stmt_taint_pass(fn.body, {pname}, aliases, set(), set(), {})
            if s_hit:
                exec_funcs.setdefault(fn.name, set()).add(idx)
            if r_hit:
                passthrough_funcs.add(fn.name)

    for _ in range(3):
        changed = False
        for fn in funcs:
            tainted: set[str] = set()
            s_hit, r_hit = _stmt_taint_pass(
                fn.body, tainted, aliases, fetch_funcs, passthrough_funcs, exec_funcs
            )
            if s_hit:
                return True
            if r_hit and fn.name not in fetch_funcs:
                fetch_funcs.add(fn.name)
                changed = True
        if not changed:
            break

    # Check top-level module statements as well.
    top_tainted: set[str] = set()
    s_hit, _ = _stmt_taint_pass(
        tree.body, top_tainted, aliases, fetch_funcs, passthrough_funcs, exec_funcs
    )
    return s_hit


def _analyze_python_ast(content: str, lines: list[str]) -> tuple[list[dict[str, Any]], bool, ast.Module | None]:
    """Extract call-site indicators and fetch->exec flow status from Python AST."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return [], False, None

    aliases = _collect_python_import_aliases(tree)
    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _resolve_python_call_name(node.func, aliases)
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
    has_flow = _python_has_fetch_to_exec_flow(tree, aliases)
    return findings, has_flow, tree


def _mask_python_comments_and_strings(content: str, lines: list[str]) -> list[str]:
    """Return lines with Python comments and string literals blanked so docstrings never trigger alerts."""
    grid = [list(ln) for ln in lines]
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(content).readline))
    except (tokenize.TokenError, IndentationError):
        return _strip_non_python_comments(lines)

    for tok in tokens:
        if tok.type not in {tokenize.COMMENT, tokenize.STRING}:
            continue
        s_row, s_col = tok.start
        e_row, e_col = tok.end
        for row_idx in range(s_row, min(e_row, len(grid)) + 1):
            line_chars = grid[row_idx - 1]
            c_start = s_col if row_idx == s_row else 0
            c_end = e_col if row_idx == e_row else len(line_chars)
            for pos in range(max(0, c_start), min(c_end, len(line_chars))):
                line_chars[pos] = " "
    return ["".join(chars) for chars in grid]


def _strip_non_python_comments(lines: list[str]) -> list[str]:
    """Strip //, /* ... */, and leading # comments while preserving strings such as URLs."""
    cleaned_lines: list[str] = []
    in_block_comment = False

    for raw in lines:
        out: list[str] = []
        i = 0
        n = len(raw)
        quote: str | None = None
        escaped = False
        stripped_leading = raw.lstrip()
        if not in_block_comment and stripped_leading.startswith("#") and not stripped_leading.startswith("#!/"):
            cleaned_lines.append("")
            continue

        while i < n:
            ch = raw[i]
            nxt = raw[i + 1] if i + 1 < n else ""

            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    out.extend((" ", " "))
                    i += 2
                else:
                    out.append(" ")
                    i += 1
                continue

            if quote is not None:
                out.append(ch)
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None
                i += 1
                continue

            if ch in {"'", '"', "`"}:
                quote = ch
                out.append(ch)
                i += 1
                continue

            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block_comment = True
                out.extend((" ", " "))
                i += 2
                continue
            if ch == "#":
                break

            out.append(ch)
            i += 1

        cleaned_lines.append("".join(out))
    return cleaned_lines


def _analyze_lines(raw_lines: list[str], sanitized_lines: list[str]) -> list[dict[str, Any]]:
    """Scan sanitized source lines with regex signatures while citing original source lines."""
    findings: list[dict[str, Any]] = []
    for idx, code_part in enumerate(sanitized_lines, start=1):
        if not code_part.strip():
            continue
        original = raw_lines[idx - 1].strip() if idx - 1 < len(raw_lines) else code_part.strip()
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
                        "evidence": original[:200],
                        "source": "line-signature",
                    }
                )
    return findings


def _js_has_fetch_to_exec_flow(sanitized_lines: list[str], findings: list[dict[str, Any]]) -> bool:
    """Confirm that a JS/shell fetch and exec share an enclosing function or top-level flow."""
    fetch_lines = [int(f["line"]) for f in findings if f["stage"] == "fetch"]
    exec_lines = [int(f["line"]) for f in findings if f["stage"] == "exec"]
    if not fetch_lines or not exec_lines:
        return False

    # Assign each line to a top-level function block id (0 = top-level script).
    scope_per_line: dict[int, int] = {}
    depth = 0
    scope_id = 0
    in_named_fn = False
    for idx, ln in enumerate(sanitized_lines, start=1):
        if depth == 0 and re.search(r"\b(?:async\s+)?function\b", ln):
            scope_id += 1
            in_named_fn = True
        current_scope = scope_id if in_named_fn else 0
        scope_per_line[idx] = current_scope
        depth += ln.count("{") - ln.count("}")
        if depth <= 0:
            depth = 0
            in_named_fn = False

    for fl in fetch_lines:
        for el in exec_lines:
            if scope_per_line.get(fl, 0) == scope_per_line.get(el, 0) and fl <= el:
                return True
    return False


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings by (rule_id, line), preferring AST-backed evidence."""
    by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for item in findings:
        key = (item["rule_id"], int(item["line"]))
        existing = by_key.get(key)
        if existing is None or (item.get("source") == "python-ast" and existing.get("source") != "python-ast"):
            by_key[key] = item
    return sorted(by_key.values(), key=lambda f: (int(f["line"]), f["rule_id"]))


def _classify_risk(score: int, stages_present: set[str], has_correlated_chain: bool) -> tuple[str, str]:
    """Return (risk_level, classification) based on correlated dropper stages and score."""
    if has_correlated_chain and score >= 75:
        return "CRITICAL", "TWO_STAGE_DROPPER"
    if has_correlated_chain:
        return "HIGH", "TWO_STAGE_DROPPER"
    if "exec" in stages_present and score >= 55:
        return "HIGH", "SUSPICIOUS_DYNAMIC_LOADER"
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
    parsed_tree: ast.Module | None = None
    py_flow = False
    if is_python:
        ast_findings, py_flow, parsed_tree = _analyze_python_ast(content, lines)
        raw_findings.extend(ast_findings)
        sanitized = (
            _mask_python_comments_and_strings(content, lines)
            if parsed_tree is not None
            else _strip_non_python_comments(lines)
        )
    else:
        sanitized = _strip_non_python_comments(lines)

    raw_findings.extend(_analyze_lines(lines, sanitized))
    findings = _deduplicate_findings(raw_findings)
    stages_present = {f["stage"] for f in findings}

    stage_weights = {"fetch": 20, "defer": 10, "decode": 15, "exec": 35}
    score = sum(stage_weights.get(st, 0) for st in stages_present)

    has_fetch_and_exec = {"fetch", "exec"}.issubset(stages_present)
    has_flow = (
        py_flow
        if (is_python and parsed_tree is not None)
        else _js_has_fetch_to_exec_flow(sanitized, findings)
    )
    has_correlated_chain = has_fetch_and_exec and has_flow

    if has_correlated_chain:
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
    risk_level, classification = _classify_risk(score, stages_present, has_correlated_chain)

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


def _open_scoped_bytes(
    target_path: pathlib.Path,
    scope_root: pathlib.Path | None,
    max_bytes: int,
) -> tuple[bytes | None, int]:
    """Safely read a regular non-symlink file within scope_root and max_bytes."""
    if target_path.is_symlink():
        raise ValueError(f"Refusing symlink target: {target_path}")

    real_target = pathlib.Path(os.path.realpath(target_path))
    if scope_root is not None:
        real_root = pathlib.Path(os.path.realpath(scope_root))
        if os.path.commonpath([str(real_root), str(real_target)]) != str(real_root):
            raise ValueError(f"Path {target_path} escapes scope root {scope_root}")
        # Check every intermediate component up to root for symlinks.
        rel_parts = target_path.resolve().relative_to(real_root).parts if target_path.is_absolute() else target_path.parts
        if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
            dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
            cur_fd = os.open(real_root, dir_flags)
            try:
                for part in rel_parts[:-1]:
                    nxt_fd = os.open(part, dir_flags, dir_fd=cur_fd)
                    os.close(cur_fd)
                    cur_fd = nxt_fd
                file_fd = os.open(rel_parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=cur_fd)
            finally:
                os.close(cur_fd)
            with os.fdopen(file_fd, "rb") as fh:
                st = os.fstat(fh.fileno())
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError(f"Target is not a regular file: {target_path}")
                if st.st_size > max_bytes:
                    return None, st.st_size
                return fh.read(max_bytes + 1), st.st_size

    st = target_path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError(f"Target is not a safe regular file: {target_path}")
    if st.st_size > max_bytes:
        return None, st.st_size
    with open(target_path, "rb") as fh:
        fst = os.fstat(fh.fileno())
        if fst.st_size > max_bytes:
            return None, fst.st_size
        return fh.read(max_bytes + 1), fst.st_size


def scan_file(
    path: str | os.PathLike[str],
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    scope_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Read and scan a single file on disk subject to symlink, scope, and size limits."""
    p = pathlib.Path(path)
    root_p = pathlib.Path(scope_root) if scope_root is not None else None
    raw_bytes, actual_size = _open_scoped_bytes(p, root_p, max_bytes=max_bytes)
    if raw_bytes is None or len(raw_bytes) > max_bytes:
        return {
            "file": str(p).replace("\\", "/"),
            "status": "skipped",
            "reason": f"exceeds max_bytes ({actual_size} > {max_bytes})",
            "sha256": "",
            "lines": 0,
            "risk_score": 0,
            "risk_level": "SKIPPED",
            "classification": "SKIPPED",
            "stages_detected": [],
            "finding_count": 0,
            "findings": [],
        }
    content = raw_bytes.decode("utf-8", errors="replace")
    return scan_content(content, filename=str(p))


def scan_path(
    target: str | os.PathLike[str],
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    scope_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Scan a file or recursively scan a directory for two-stage dropper artifacts."""
    root_path = pathlib.Path(target)
    if not root_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")
    if root_path.is_symlink():
        raise ValueError(f"Refusing symlink target: {target}")

    effective_scope = pathlib.Path(scope_root) if scope_root is not None else root_path
    files_to_scan: list[pathlib.Path] = []
    skipped_items: list[dict[str, str]] = []
    truncated = False

    if root_path.is_file():
        files_to_scan.append(root_path)
    else:
        real_scope = os.path.realpath(effective_scope)
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            # Do not descend into symlinks or __pycache__.
            dirnames[:] = sorted(
                d for d in dirnames
                if d != "__pycache__" and not pathlib.Path(dirpath, d).is_symlink()
            )
            for fname in sorted(filenames):
                if fname == "__init__.py":
                    continue
                candidate = pathlib.Path(dirpath, fname)
                if candidate.is_symlink():
                    skipped_items.append({"file": str(candidate).replace("\\", "/"), "reason": "symlink skipped"})
                    continue
                if candidate.suffix.lower() not in SUPPORTED_EXTENSIONS:
                    continue
                if os.path.commonpath([real_scope, os.path.realpath(candidate)]) != real_scope:
                    skipped_items.append({"file": str(candidate).replace("\\", "/"), "reason": "outside scope root"})
                    continue
                files_to_scan.append(candidate)
                if len(files_to_scan) >= max_files:
                    truncated = True
                    break
            if truncated:
                break

    reports: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for f in files_to_scan:
        try:
            res = scan_file(f, max_bytes=max_bytes, scope_root=effective_scope if root_path.is_dir() else scope_root)
        except (OSError, ValueError) as exc:
            errors.append({"file": str(f).replace("\\", "/"), "error": str(exc)})
            continue
        if res.get("status") == "skipped":
            skipped_items.append({"file": res["file"], "reason": str(res.get("reason", "skipped"))})
        else:
            reports.append(res)

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
        "skipped_count": len(skipped_items),
        "skipped_files": skipped_items,
        "error_count": len(errors),
        "errors": errors,
        "truncated": truncated,
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
    ]
    if report.get("skipped_count"):
        lines.append(f"- **Skipped Files:** `{report['skipped_count']}`")
    if report.get("error_count"):
        lines.append(f"- **Read Errors:** `{report['error_count']}`")
    lines.extend(
        [
            "",
            "## Summary Table",
            "",
            "| File | Classification | Risk Level | Score | Stages Detected | Findings |",
            "| --- | --- | --- | :---: | --- | :---: |",
        ]
    )
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
    except (FileNotFoundError, ValueError) as exc:
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
