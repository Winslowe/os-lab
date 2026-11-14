import json
import os
import stat
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from native_messaging_analyzer import main, scan_target


def write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def test_clean_extension_without_native_messaging(tmp_path: Path) -> None:
    ext = write_json(
        tmp_path / "ext_clean" / "manifest.json",
        {
            "manifest_version": 3,
            "name": "Safe Notes",
            "version": "1.0.0",
            "permissions": ["storage"],
        },
    )
    report = scan_target(ext)
    assert report.scanned_extension_manifests == 1
    assert report.findings == []
    assert report.risk_level == "LOW"


def test_high_risk_extension_native_messaging_with_all_urls(tmp_path: Path) -> None:
    ext = write_json(
        tmp_path / "ext_risky" / "manifest.json",
        {
            "manifest_version": 3,
            "name": "Bridge Helper",
            "version": "1.0.0",
            "permissions": ["nativeMessaging", "cookies"],
            "host_permissions": ["<all_urls>"],
        },
    )
    report = scan_target(ext)
    rule_ids = {f.rule_id for f in report.findings}
    assert "NM-EXT-CAPABILITY" in rule_ids
    assert "NM-EXT-BROAD-HOST" in rule_ids
    assert "NM-EXT-SENSITIVE-COMBO" in rule_ids
    assert report.risk_level == "HIGH"


def test_weak_csp_extension_flagged(tmp_path: Path) -> None:
    ext = write_json(
        tmp_path / "ext_csp" / "manifest.json",
        {
            "manifest_version": 2,
            "name": "Legacy Bridge",
            "version": "0.9",
            "permissions": ["nativeMessaging"],
            "content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'self'",
        },
    )
    report = scan_target(ext)
    assert any(f.rule_id == "NM-EXT-WEAK-CSP" for f in report.findings)


def test_safe_native_host_manifest(tmp_path: Path) -> None:
    host = write_json(
        tmp_path / "hosts" / "com.example.safe.json",
        {
            "name": "com.example.safe",
            "description": "Safe helper",
            "path": "/opt/example/bin/safe-helper",
            "type": "stdio",
            "allowed_origins": ["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"],
        },
    )
    report = scan_target(host, check_fs=False)
    assert report.scanned_host_manifests == 1
    assert report.findings == []
    assert report.risk_level == "LOW"


def test_host_exposing_shell_interpreter_is_critical(tmp_path: Path) -> None:
    host = write_json(
        tmp_path / "hosts" / "com.evil.shell.json",
        {
            "name": "com.evil.shell",
            "description": "Direct shell bridge",
            "path": "/bin/bash",
            "type": "stdio",
            "allowed_origins": ["chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/"],
        },
    )
    report = scan_target(host, check_fs=False)
    rule_ids = {f.rule_id for f in report.findings}
    assert "NM-HOST-INTERPRETER-BIN" in rule_ids
    assert report.risk_level == "CRITICAL"


def test_host_wildcard_origin_and_temp_dir_flagged(tmp_path: Path) -> None:
    host = write_json(
        tmp_path / "hosts" / "com.evil.wildcard.json",
        {
            "name": "com.evil.wildcard",
            "description": "Wildcard origin",
            "path": "/tmp/custom-agent",
            "type": "stdio",
            "allowed_origins": ["chrome-extension://*/"],
        },
    )
    report = scan_target(host, check_fs=False)
    rule_ids = {f.rule_id for f in report.findings}
    assert "NM-HOST-WILDCARD-ORIGIN" in rule_ids
    assert "NM-HOST-TEMP-DIR" in rule_ids
    assert report.risk_level == "CRITICAL"


def test_host_relative_path_and_missing_allowlist(tmp_path: Path) -> None:
    host = write_json(
        tmp_path / "hosts" / "com.bad.rel.json",
        {
            "name": "com.bad.rel",
            "description": "Relative binary",
            "path": "bin/helper.exe",
            "type": "stdio",
        },
    )
    report = scan_target(host, check_fs=False)
    rule_ids = {f.rule_id for f in report.findings}
    assert "NM-HOST-RELATIVE-PATH" in rule_ids
    assert "NM-HOST-NO-ALLOWLIST" in rule_ids


def test_world_writable_host_binary_detected(tmp_path: Path) -> None:
    binary = tmp_path / "opt" / "native-agent"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(binary, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

    host = write_json(
        tmp_path / "hosts" / "com.weak.perm.json",
        {
            "name": "com.weak.perm",
            "description": "World writable",
            "path": str(binary),
            "type": "stdio",
            "allowed_origins": ["chrome-extension://cccccccccccccccccccccccccccccccc/"],
        },
    )
    report = scan_target(host, check_fs=True)
    assert any(f.rule_id == "NM-HOST-WORLD-WRITABLE" for f in report.findings)
    assert report.risk_level == "CRITICAL"


def test_cli_json_and_fail_on_high_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_json(
        tmp_path / "com.evil.json",
        {
            "name": "com.evil",
            "description": "Test",
            "path": "/usr/bin/python3",
            "type": "stdio",
            "allowed_origins": ["chrome-extension://dddddddddddddddddddddddddddddddd/"],
        },
    )
    rc = main([str(tmp_path), "--json", "--fail-on-high", "--no-fs-check"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert rc == 2
    assert payload["task"] == "PENT-18"
    assert payload["risk_level"] == "CRITICAL"
