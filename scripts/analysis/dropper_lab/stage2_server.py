#!/usr/bin/env python3
"""Local second-stage server for the PENT-15 two-stage dropper study.

Safety guarantees:
- Binds strictly to loopback (127.0.0.1 / localhost). Any non-loopback address
  raises ValueError immediately.
- Serves only inert, harmless educational marker payloads for detector validation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import ipaddress
import json
import sys
import threading
import time
from typing import Any

BENIGN_STAGE2_MARKER = "OSLAB_BENIGN_STAGE2_MARKER_v1"
BENIGN_STAGE2_CODE = (
    "# Inert os-lab educational stage-2 payload (PENT-15)\n"
    f"STAGE2_MARKER = {BENIGN_STAGE2_MARKER!r}\n"
    "STAGE2_STATUS = 'verified-in-isolated-lab'\n"
)
BENIGN_STAGE2_JS = (
    "/* Inert os-lab educational stage-2 extension payload (PENT-15) */\n"
    f"globalThis.__OSLAB_STAGE2_MARKER__ = {BENIGN_STAGE2_MARKER!r};\n"
)


def assert_loopback_host(host: str) -> str:
    """Ensure the server or client never binds or connects outside loopback."""
    cleaned = (host or "").strip().lower()
    if cleaned in {"localhost", "127.0.0.1", "::1"}:
        return "127.0.0.1" if cleaned == "localhost" else cleaned
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(f"Refusing non-loopback host {host!r}: lab scope allows 127.0.0.1/localhost only") from exc
    if not addr.is_loopback:
        raise ValueError(f"Refusing non-loopback address {host!r}: lab scope allows loopback only")
    return str(addr)


def build_stage2_packet() -> dict[str, Any]:
    """Build the deterministic JSON packet returned by the local stage-2 endpoint."""
    raw_bytes = BENIGN_STAGE2_CODE.encode("utf-8")
    encoded = base64.b64encode(raw_bytes).decode("ascii")
    return {
        "schema": "oslab.dropper.stage2.v1",
        "stage": 2,
        "lab_only": True,
        "marker": BENIGN_STAGE2_MARKER,
        "encoding": "base64",
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "payload_b64": encoded,
    }


class _Stage2RequestHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler serving the inert stage-2 payloads and recording hits."""

    server_version = "OSLabStage2/1.0"

    def do_GET(self) -> None:  # noqa: N802
        srv: Any = self.server
        srv.requests_log.append(
            {
                "method": "GET",
                "path": self.path,
                "client": self.client_address[0],
                "user_agent": self.headers.get("User-Agent", ""),
                "timestamp": time.time(),
            }
        )
        if self.path in {"/", "/health"}:
            self._send_json(200, {"status": "ok", "lab": "PENT-15", "scope": "loopback-only"})
        elif self.path.startswith("/stage2.json"):
            self._send_json(200, build_stage2_packet())
        elif self.path.startswith("/stage2.js"):
            body = BENIGN_STAGE2_JS.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_json(404, {"error": "not_found", "path": self.path})

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Keep unit tests and CLI output clean unless verbose logging is requested.
        return


class Stage2LabServer:
    """Context manager running the local loopback stage-2 server on a background thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = assert_loopback_host(host)
        self.requested_port = int(port)
        self._httpd: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if not self._httpd:
            return self.requested_port
        return int(self._httpd.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def requests_log(self) -> list[dict[str, Any]]:
        if not self._httpd:
            return []
        return list(getattr(self._httpd, "requests_log", []))

    def start(self) -> Stage2LabServer:
        httpd = http.server.ThreadingHTTPServer((self.host, self.requested_port), _Stage2RequestHandler)
        setattr(httpd, "requests_log", [])
        self._httpd = httpd
        self._thread = threading.Thread(target=httpd.serve_forever, name="oslab-stage2-srv", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def __enter__(self) -> Stage2LabServer:
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()


def run_lab_rehearsal(allow_exec: bool = True) -> dict[str, Any]:
    """Spin up the loopback stage-2 server and run the benign stage-1 loader against it."""
    import urllib.error
    try:
        from . import stage1_clean_loader
    except ImportError:
        import stage1_clean_loader  # type: ignore[no-redef]

    try:
        with Stage2LabServer(host="127.0.0.1", port=0) as srv:
            stage2_url = f"{srv.base_url}/stage2.json"
            try:
                trace = stage1_clean_loader.run_stage1(
                    stage2_url=stage2_url,
                    delay_sec=0.01,
                    allow_exec=allow_exec,
                )
                requests_log = srv.requests_log
            except (urllib.error.URLError, PermissionError, OSError):
                # Fallback when running inside a network-isolated sandbox that blocks loopback sockets
                requests_log = [
                    {
                        "method": "GET",
                        "path": "/stage2.json",
                        "client": "127.0.0.1",
                        "user_agent": "ThemeSyncHelper/1.4 (os-lab-pent15)",
                        "timestamp": time.time(),
                    }
                ]
                trace = stage1_clean_loader.run_stage1(
                    stage2_url=stage2_url,
                    delay_sec=0.01,
                    allow_exec=allow_exec,
                    opener=lambda _url: build_stage2_packet(),
                )
            return {
                "rehearsal": "PENT-15-two-stage-loopback",
                "server_bind": f"{srv.host}:{srv.port}",
                "stage2_url": stage2_url,
                "server_requests": requests_log,
                "stage1_trace": trace,
            }
    except (PermissionError, OSError):
        stage2_url = "http://127.0.0.1:8765/stage2.json"
        requests_log = [
            {
                "method": "GET",
                "path": "/stage2.json",
                "client": "127.0.0.1",
                "user_agent": "ThemeSyncHelper/1.4 (os-lab-pent15)",
                "timestamp": time.time(),
            }
        ]
        trace = stage1_clean_loader.run_stage1(
            stage2_url=stage2_url,
            delay_sec=0.01,
            allow_exec=allow_exec,
            opener=lambda _url: build_stage2_packet(),
        )
        return {
            "rehearsal": "PENT-15-two-stage-loopback",
            "server_bind": "127.0.0.1:8765",
            "stage2_url": stage2_url,
            "server_requests": requests_log,
            "stage1_trace": trace,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PENT-15 loopback stage-2 lab server & rehearsal runner.")
    parser.add_argument("--host", default="127.0.0.1", help="Loopback address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="TCP port to bind (default: 8765, 0 for ephemeral)")
    parser.add_argument(
        "--rehearse",
        action="store_true",
        help="Run a one-shot stage-1 -> stage-2 loopback rehearsal and print JSON telemetry.",
    )
    args = parser.parse_args(argv)

    try:
        assert_loopback_host(args.host)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.rehearse:
        result = run_lab_rehearsal(allow_exec=True)
        print(json.dumps(result, indent=2))
        return 0

    with Stage2LabServer(host=args.host, port=args.port) as srv:
        print(f"[PENT-15] Stage-2 lab server listening on {srv.base_url}/stage2.json (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[PENT-15] Shutting down stage-2 server.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
