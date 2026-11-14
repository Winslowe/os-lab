"""Unit and loopback rehearsal tests for PENT-15 Two-Stage 'Clean Dropper' Detection Harness."""

from __future__ import annotations

import json
import os
import sys

import pytest

REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CONSOLE_DIR = os.path.join(REPO_ROOT, "console")
for _p in (REPO_ROOT, CONSOLE_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oslab  # noqa: E402
from scripts.analysis import dropper_detect  # noqa: E402
from scripts.analysis.dropper_lab import stage1_clean_loader, stage2_server  # noqa: E402

DROPPER_LAB_DIR = os.path.join(REPO_ROOT, "scripts", "analysis", "dropper_lab")


def test_benign_utility_is_classified_clean():
    report = dropper_detect.scan_file(os.path.join(DROPPER_LAB_DIR, "benign_utility.py"))
    assert report["risk_level"] == "CLEAN"
    assert report["classification"] == "BENIGN"
    assert report["risk_score"] == 0
    assert report["finding_count"] == 0
    assert report["stages_detected"] == []


def test_stage2_server_without_exec_sink_stays_clean():
    report = dropper_detect.scan_file(os.path.join(DROPPER_LAB_DIR, "stage2_server.py"))
    assert report["classification"] == "BENIGN"
    assert report["risk_level"] == "CLEAN"
    assert "exec" not in report["stages_detected"]


def test_python_stage1_clean_loader_detected_as_critical_dropper():
    report = dropper_detect.scan_file(os.path.join(DROPPER_LAB_DIR, "stage1_clean_loader.py"))
    assert report["classification"] == "TWO_STAGE_DROPPER"
    assert report["risk_level"] == "CRITICAL"
    assert report["risk_score"] == 100
    assert set(report["stages_detected"]) == {"fetch", "defer", "decode", "exec"}
    rule_ids = {f["rule_id"] for f in report["findings"]}
    assert "STAGE1_REMOTE_FETCH" in rule_ids
    assert "STAGE_DEFERRED_TRIGGER" in rule_ids
    assert "STAGE_PAYLOAD_DECODE" in rule_ids
    assert "STAGE2_DYNAMIC_EXEC" in rule_ids
    assert "DROPPER_CHAIN_FETCH_EXEC" in rule_ids
    assert "DROPPER_FULL_FOUR_STAGE_CHAIN" in rule_ids


def test_js_extension_loader_detected_as_critical_dropper():
    report = dropper_detect.scan_file(os.path.join(DROPPER_LAB_DIR, "stage1_extension_loader.js"))
    assert report["classification"] == "TWO_STAGE_DROPPER"
    assert report["risk_level"] == "CRITICAL"
    assert report["risk_score"] == 100
    rule_ids = {f["rule_id"] for f in report["findings"]}
    assert "STAGE1_REMOTE_FETCH" in rule_ids
    assert "STAGE_DEFERRED_TRIGGER" in rule_ids
    assert "STAGE_PAYLOAD_DECODE" in rule_ids
    assert "STAGE2_DYNAMIC_EXEC" in rule_ids
    assert "DROPPER_CHAIN_FETCH_EXEC" in rule_ids


def test_isolated_network_fetch_without_exec_is_not_flagged_as_dropper():
    ordinary_http_client = (
        "import time\n"
        "import urllib.request\n"
        "time.sleep(0.1)\n"
        "resp = urllib.request.urlopen('http://127.0.0.1:8000/status')\n"
    )
    report = dropper_detect.scan_content(ordinary_http_client, filename="http_poller.py")
    assert report["classification"] == "BENIGN"
    assert report["risk_level"] == "CLEAN"
    assert report["risk_score"] <= 20
    assert "DROPPER_CHAIN_FETCH_EXEC" not in {f["rule_id"] for f in report["findings"]}


def test_comments_do_not_trigger_false_positives():
    commented_only = (
        "# urllib.request.urlopen('http://127.0.0.1/stage2')\n"
        "# exec(base64.b64decode(payload))\n"
        "/* fetch('http://127.0.0.1/x').then(r => eval(atob(r))) */\n"
        "x = 42\n"
    )
    report = dropper_detect.scan_content(commented_only, filename="comments_only.py")
    assert report["risk_score"] == 0
    assert report["finding_count"] == 0
    assert report["risk_level"] == "CLEAN"


def test_loopback_scope_guard_refuses_non_loopback_targets():
    assert stage2_server.assert_loopback_host("127.0.0.1") == "127.0.0.1"
    assert stage2_server.assert_loopback_host("localhost") == "127.0.0.1"
    assert stage2_server.assert_loopback_host("::1") == "::1"
    assert stage1_clean_loader.assert_loopback_url("http://127.0.0.1:8765/stage2.json")

    for forbidden_host in ("0.0.0.0", "8.8.8.8", "192.168.1.10", "10.0.0.5", "example.com"):
        with pytest.raises(ValueError, match="loopback"):
            stage2_server.assert_loopback_host(forbidden_host)

    for forbidden_url in (
        "http://example.com/stage2.json",
        "https://127.0.0.1/stage2.json",
        "https://192.168.1.1/stage2.json",
        "ftp://127.0.0.1/stage2.json",
    ):
        with pytest.raises(ValueError):
            stage1_clean_loader.assert_loopback_url(forbidden_url)


def test_stage1_safety_controls_and_redirect_block():
    import base64

    packet = stage2_server.build_stage2_packet()
    # Default allow_exec must be False (fail-closed)
    res_dry = stage1_clean_loader.run_stage1(
        stage2_url="http://127.0.0.1:8765/stage2.json",
        delay_sec=0.0,
        opener=lambda _url: packet,
    )
    assert res_dry["activation"]["executed"] is False

    # Untrusted introspection / import payload must be refused before exec()
    evil_code = "import os\nSTAGE2_MARKER = os.name\n"
    evil_b64 = base64.b64encode(evil_code.encode("utf-8")).decode("ascii")
    with pytest.raises(ValueError, match="non-literal|unsafe"):
        stage1_clean_loader.run_stage1(
            stage2_url="http://127.0.0.1:8765/stage2.json",
            delay_sec=0.0,
            allow_exec=True,
            opener=lambda _url: {"payload_b64": evil_b64},
        )

    # HTTP redirects to non-loopback targets must be refused by the redirect handler
    handler = stage1_clean_loader._NoRedirectHandler()
    with pytest.raises(ValueError, match="redirect"):
        handler.redirect_request(None, None, 302, "Found", {}, "http://example.com/payload")


def test_stage2_js_endpoint_serves_valid_base64_and_ipv6_base_url():
    import base64
    import urllib.request

    with stage2_server.Stage2LabServer(host="127.0.0.1", port=0) as srv:
        with urllib.request.urlopen(f"{srv.base_url}/stage2.js", timeout=3.0) as resp:
            encoded = resp.read().decode("utf-8")
        decoded = base64.b64decode(encoded).decode("utf-8")
        assert decoded == stage2_server.BENIGN_STAGE2_JS

    ipv6_srv = stage2_server.Stage2LabServer(host="::1", port=8765)
    assert ipv6_srv.base_url == "http://[::1]:8765"


def test_detector_resists_evasion_and_false_positives(tmp_path):
    # Aliased Python imports with fetch -> exec flow must still be flagged CRITICAL
    aliased_py = (
        "import urllib.request as req\n"
        "from base64 import b64decode as dec\n"
        "from time import sleep as pause\n"
        "pause(1)\n"
        "blob = req.urlopen('http://127.0.0.1/s2').read()\n"
        "exec(dec(blob))\n"
    )
    aliased_report = dropper_detect.scan_content(aliased_py, filename="aliased.py")
    assert aliased_report["classification"] == "TWO_STAGE_DROPPER"
    assert aliased_report["risk_level"] == "CRITICAL"

    # Python docstrings containing example code must stay CLEAN
    docstring_py = (
        '"""Example docs:\n'
        "    urllib.request.urlopen('http://127.0.0.1/stage2')\n"
        "    exec(base64.b64decode(data))\n"
        '"""\n'
        "def helper():\n"
        "    return 1\n"
    )
    doc_report = dropper_detect.scan_content(docstring_py, filename="docs_example.py")
    assert doc_report["risk_level"] == "CLEAN"
    assert doc_report["finding_count"] == 0

    # JS inline block comment + http:// string literal must not hide eval(atob(...))
    js_tricky = (
        'const url = "http://127.0.0.1/stage2.js";\n'
        "setTimeout(async () => {\n"
        "  const r = await fetch(url);\n"
        "  const txt = await r.text();\n"
        "  /* keep inline comment */ eval(atob(txt));\n"
        "}, 1000);\n"
    )
    js_report = dropper_detect.scan_content(js_tricky, filename="tricky.js")
    assert js_report["classification"] == "TWO_STAGE_DROPPER"
    assert js_report["risk_level"] == "CRITICAL"

    # No-fetch code (defer + decode + exec only) must NOT be called TWO_STAGE_DROPPER
    no_fetch = (
        "import time, base64\n"
        "time.sleep(0.1)\n"
        "exec(base64.b64decode('eCA9IDE='))\n"
    )
    no_fetch_report = dropper_detect.scan_content(no_fetch, filename="local_loader.py")
    assert no_fetch_report["classification"] == "SUSPICIOUS_DYNAMIC_LOADER"

    # Unrelated fetch and exec functions with no data/call link must NOT trigger DROPPER_CHAIN
    unrelated_py = (
        "import urllib.request\n"
        "def check_health():\n"
        "    return urllib.request.urlopen('http://127.0.0.1/health').status\n"
        "def eval_math(expr):\n"
        "    return eval(expr)\n"
    )
    unrelated_report = dropper_detect.scan_content(unrelated_py, filename="unrelated.py")
    assert unrelated_report["classification"] != "TWO_STAGE_DROPPER"
    assert "DROPPER_CHAIN_FETCH_EXEC" not in {f["rule_id"] for f in unrelated_report["findings"]}

    # Oversized file must be skipped safely without aborting scan_path
    small_ok = tmp_path / "ok.py"
    small_ok.write_text("x = 1\n", encoding="utf-8")
    big_file = tmp_path / "huge.py"
    big_file.write_text("x = 1\n" * 500, encoding="utf-8")
    bounded_report = dropper_detect.scan_path(tmp_path, max_bytes=128)
    assert bounded_report["total_files_scanned"] == 1
    assert bounded_report["skipped_count"] == 1


def test_two_stage_loopback_rehearsal_end_to_end():
    rehearsal = stage2_server.run_lab_rehearsal(allow_exec=True)
    assert rehearsal["rehearsal"] == "PENT-15-two-stage-loopback"
    assert rehearsal["server_bind"].startswith("127.0.0.1:")
    assert len(rehearsal["server_requests"]) == 1
    assert rehearsal["server_requests"][0]["path"] == "/stage2.json"

    trace = rehearsal["stage1_trace"]
    assert trace["activation"]["executed"] is True
    assert trace["activation"]["marker"] == stage2_server.BENIGN_STAGE2_MARKER
    assert trace["activation"]["status"] == "verified-in-isolated-lab"


def test_scan_path_and_markdown_report_on_dropper_lab():
    summary = dropper_detect.scan_path(DROPPER_LAB_DIR)
    assert summary["task_id"] == "PENT-15"
    assert summary["total_files_scanned"] == 4
    assert summary["dropper_count"] == 2
    assert summary["high_or_critical_count"] == 2
    assert summary["clean_count"] == 2
    assert summary["max_risk_score"] == 100

    md = dropper_detect.render_markdown_report(summary)
    assert "# PENT-15 — Two-Stage 'Clean Dropper' Detection Report" in md
    assert "stage1_clean_loader.py" in md
    assert "stage1_extension_loader.js" in md
    assert "benign_utility.py" in md
    assert "DROPPER_CHAIN_FETCH_EXEC" in md


def test_cli_main_json_markdown_and_exit_codes(capsys):
    rc = dropper_detect.main([DROPPER_LAB_DIR, "--json", "--rehearse"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["dropper_count"] == 2
    assert payload["rehearsal"]["stage1_trace"]["activation"]["marker"] == stage2_server.BENIGN_STAGE2_MARKER

    rc_md = dropper_detect.main([DROPPER_LAB_DIR, "--markdown"])
    assert rc_md == 0
    assert "Summary Table" in capsys.readouterr().out

    rc_fail = dropper_detect.main([DROPPER_LAB_DIR, "--fail-on-high"])
    assert rc_fail == 1
    capsys.readouterr()

    rc_missing = dropper_detect.main([os.path.join(DROPPER_LAB_DIR, "does_not_exist.py")])
    assert rc_missing == 2
    capsys.readouterr()


def test_oslab_dropper_audit_integration_and_scope_guard():
    report = oslab.dropper_audit(REPO_ROOT, rehearse=True)
    assert report["task_id"] == "PENT-15"
    assert report["dropper_count"] == 2
    assert "rehearsal" in report

    with pytest.raises(oslab.PlanError, match="escapes"):
        oslab.dropper_audit(REPO_ROOT, target="../../outside")
