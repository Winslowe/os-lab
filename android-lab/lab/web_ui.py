#!/usr/bin/env python3
"""
os-lab web console: host overview, every lab's lifecycle, and the android-lab workbench.

The console detects this computer (OS, arch, KVM, WSL, tools), shows which labs it can
run, installs their dependencies and drives them with typed, previewed actions through
console/oslab.py (a port of the qLar PR #174 OS Lab runtime). The Android Lab workbench
implements the 6 UI phases from knowledge/segmentation.md: the 6 UI phases from knowledge/segmentation.md:
Phase 1: Lab Entry & Health Overview
Phase 2: Code & Target Providers (APK upload / ADB Bridge)
Phase 3: Workflows (WF1 Static, WF2 Dynamic, Fuzzing, Secrets, Patching)
Phase 4: Real-Time Execution Console & Telemetry Stream
Phase 5: Segmented Analytics & Interactive Reports Viewer
Phase 6: Component Sitemap & Attack Surface Explorer

The page itself lives in web/ (index.html, app.css, app.js) and follows the qLar
app-shell design: a grouped, collapsible sidebar, Spotlight search (Ctrl/Cmd+K),
a sticky top bar and the Android Lab accent. It needs no build step and no network.
"""

import sys
import os
import json
import subprocess
import shutil
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
from http.server import ThreadingHTTPServer

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.realpath(os.path.join(SCRIPT_DIR, "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "console"))
try:
    import oslab  # noqa: E402  (console/oslab.py)
except ImportError:  # a lone android-lab copy without the console module
    oslab = None
try:
    import content as content_packs  # noqa: E402  (console/content.py: signed content updates)
except ImportError:
    content_packs = None
try:
    import app_update as app_updates  # noqa: E402  (console/app_update.py: signed app releases)
except ImportError:
    app_updates = None
try:
    import source_api  # noqa: E402
    import source_artifacts  # noqa: E402  (console/source_artifacts.py: read-only Source Lab output)
except ImportError:
    source_artifacts = None
try:
    import cleanup_api  # noqa: E402  (console/cleanup_api.py: Cleanup Lab readiness and, later, scan/clean)
except ImportError:
    cleanup_api = None
ARTIFACTS_DIR = os.path.join(SCRIPT_DIR, "artifacts")
SCRIPTS_DIR = os.path.join(SCRIPT_DIR, "scripts")

CONSOLE_LOGS = []
COMMAND_RUNNING = False
CURRENT_PROC = None


def execute_background_command(cmd_args: list[str], title: str):
    global COMMAND_RUNNING, CONSOLE_LOGS, CURRENT_PROC
    COMMAND_RUNNING = True
    CONSOLE_LOGS.append(f"\n[+] === Executing: {title} ===")
    try:
        proc = subprocess.Popen(
            cmd_args,
            cwd=SCRIPT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            encoding="utf-8",
            errors="replace"
        )
        CURRENT_PROC = proc
        for line in proc.stdout:
            CONSOLE_LOGS.append(line.rstrip())
            if len(CONSOLE_LOGS) > 1000:
                CONSOLE_LOGS.pop(0)
        proc.wait()
        CONSOLE_LOGS.append(f"[+] Task finished with exit code {proc.returncode}\n")
    except Exception as e:
        CONSOLE_LOGS.append(f"[!] Error: {str(e)}\n")
    finally:
        CURRENT_PROC = None
        COMMAND_RUNNING = False


WEB_DIR = os.path.join(SCRIPT_DIR, "web")
# The Astro dashboard: dashboard/dist is the committed build, dashboard/build a local one made by
# the installers when Node is present. The newer of the two is served; with neither, "/" serves
# the self-contained console in web/, which is always reachable at /classic/.
DASHBOARD_BUILDS = [os.path.realpath(os.path.join(SCRIPT_DIR, "..", "..", "dashboard", name))
                    for name in ("build", "dist")]
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".json": "application/json",
    ".png": "image/png", ".ico": "image/x-icon", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8",
    ".webmanifest": "application/manifest+json",
}


def dashboard_dir():
    """The newest dashboard build (by its index.html), or None."""
    best, best_time = None, -1.0
    for folder in DASHBOARD_BUILDS:
        try:
            mtime = os.path.getmtime(os.path.join(folder, "index.html"))
        except OSError:
            continue
        if mtime > best_time:
            best, best_time = folder, mtime
    return best
# The console's static files; only these are served, so nothing else under web/ leaks
STATIC_FILES = {
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


def read_web_file(name: str) -> bytes:
    with open(os.path.join(WEB_DIR, name), "rb") as f:
        return f.read()


ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
HOST_CACHE = {"at": 0.0, "value": None}
HOST_LOCK = threading.Lock()
CONTENT = (content_packs.ContentStore(content_packs.default_content_dir(), REPO_ROOT)
           if content_packs else None)
APP = app_updates.AppUpdateStore() if app_updates else None
JOBS = oslab.JobService(REPO_ROOT) if oslab else None
SIGNER = oslab.PlanSigner() if oslab else None


def cached_host():
    """Host detection runs a few subprocesses; reuse it for a few seconds."""
    import time
    with HOST_LOCK:
        if HOST_CACHE["value"] is None or time.time() - HOST_CACHE["at"] > 5:
            HOST_CACHE["value"] = oslab.host_info(REPO_ROOT)
            HOST_CACHE["at"] = time.time()
        return HOST_CACHE["value"]


class LabHttpHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Polling is frequent; keep the terminal for errors
        if not self.path.startswith(("/api/logs", "/api/jobs", "/api/health", "/api/host", "/api/labs/", "/api/capabilities", "/api/cleanup")):
            super().log_message(fmt, *args)

    def _host_ok(self) -> bool:
        """Refuse DNS-rebinding requests: the Host header must name this machine."""
        try:
            host = urllib.parse.urlsplit("//" + (self.headers.get("Host") or "")).hostname or ""
        except ValueError:
            host = ""
        if host in ALLOWED_HOSTS:
            return True
        self._json(403, {"error": "Forbidden host"})
        return False

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length < 0 or length > 1_000_000:
            raise ValueError("Request too large")
        body = self.rfile.read(length) if length else b"{}"
        data = json.loads(body.decode("utf-8") or "{}")
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object")
        return data

    def do_GET(self):
        if not self._host_ok():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/source" or path.startswith("/api/source/"):
            self._source_get(path, urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
            return
        if path.startswith("/api/content"):
            self._content_get(path, urllib.parse.parse_qs(parsed.query))
            return
        if path.startswith("/api/cleanup"):
            self._cleanup_get(path, urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
            return
        if path.startswith("/api/app/update"):
            self._app_get(path)
            return
        if path.startswith(("/api/host", "/api/labs", "/api/jobs", "/api/capabilities")):
            if not oslab:
                self._json(501, {"error": "The console module (console/oslab.py) is not installed"})
                return
            try:
                self._lab_get(path)
            except oslab.PlanError as e:
                self._json(400, {"error": str(e)})
            return
        if path in ("/classic", "/classic/"):
            self._send_bytes(200, read_web_file("index.html"), "text/html; charset=utf-8")
            return
        root = dashboard_dir()
        if root and not path.startswith(("/api/", "/artifacts/", "/static/", "/healthz")):
            self._serve_dashboard(root, path)
            return
        self._android_get()

    def _source_reply(self, status, data, confirmation=False):
        if isinstance(data, source_api.Download):
            self.send_response(status)
            self.send_header("Content-Type", data.mime)
            self.send_header("Content-Disposition", f'attachment; filename="{data.name}"')
            self.send_header("Content-Length", str(len(data.content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data.content)
        else:
            safe = source_api.redact(REPO_ROOT, data)
            if confirmation and isinstance(data, dict) and "token" in data:
                safe["token"] = data["token"]
            body = json.dumps(safe, allow_nan=False).encode("utf-8")
            if len(body) > source_artifacts.MAX_TOTAL:
                raise source_artifacts.ArtifactError(413, "Source response exceeds the read limit")
            self._send_bytes(status, body, "application/json; charset=utf-8", cache="no-store")

    def _cleanup_get(self, path: str, query: dict):
        """Cleanup Lab: readiness, catalog and the scan jobs' progress and results (CLN-01…03)."""
        if cleanup_api is None:
            self._json(501, {"error": "Cleanup Lab console support is not installed"})
            return
        try:
            self._json(200, cleanup_api.CleanupAPI(REPO_ROOT).get(path, query))
        except cleanup_api.CleanupError as exc:
            self._json(exc.status, {"error": str(exc)})

    def _cleanup_post(self, path: str):
        """Cleanup Lab: typed actions only (start a scan, plan or clean job, cancel one)."""
        if cleanup_api is None:
            self._json(501, {"error": "Cleanup Lab console support is not installed"})
            return
        try:
            data = self._read_json()
            job = cleanup_api.CleanupAPI(REPO_ROOT).post(path, data)
            payload = job.to_dict() if hasattr(job, "to_dict") else job
            # 202: the job keeps running after the answer (the jobs endpoints poll it).
            self._json(
                202 if path in ("/api/cleanup/scan", "/api/cleanup/plan", "/api/cleanup/clean") else 200,
                payload,
            )
        except cleanup_api.CleanupError as exc:
            self._json(exc.status, {"error": str(exc)})
        except ValueError as e:
            self._json(400, {"error": str(e)})

    def _source_get(self, path: str, query: dict):
        if source_artifacts is None or not oslab:
            self._json(501, {"error": "Source Lab console support is not installed"})
            return
        try:
            self._source_reply(200, source_api.SourceAPI(REPO_ROOT, JOBS, SIGNER).get(path, query))
        except source_artifacts.ArtifactError as exc:
            self._source_reply(exc.status, {"error": str(exc)})
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            self._source_reply(400, {"error": "Invalid or unavailable Source Lab artifact"})

    def _source_mutate(self, path: str, method="POST"):
        if source_artifacts is None or not oslab:
            self._json(501, {"error": "Source Lab console support is not installed"})
            return
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) > 1:
                raise source_artifacts.ArtifactError(400, "Invalid request framing")
            length = int(lengths[0]) if lengths else 0
            if not 0 <= length <= 65536:
                raise source_artifacts.ArtifactError(413, "Source request exceeds the size limit")
            data = self._read_json()
            if urllib.parse.urlparse(self.path).query:
                raise source_artifacts.ArtifactError(400, "Mutation parameters belong in the JSON body")
            status, result = source_api.SourceAPI(REPO_ROOT, JOBS, SIGNER).mutate(path, data, method)
            self._source_reply(status, result, confirmation=True)
        except source_artifacts.ArtifactError as exc:
            self._source_reply(exc.status, {"error": str(exc)})
        except oslab.PlanError as exc:
            self._source_reply(409, {"error": str(exc)})
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            self._source_reply(400, {"error": "Invalid Source Lab request or unavailable private storage"})

    def do_DELETE(self):
        if not self._host_ok():
            return
        if self.headers.get("X-OSLab") != "1":
            self._json(403, {"error": "Missing X-OSLab header"})
            return
        self._source_mutate(urllib.parse.urlparse(self.path).path, "DELETE")

    def _send_bytes(self, status: int, body: bytes, content_type: str, cache: str = "no-cache"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _serve_dashboard(self, root: str, path: str):
        """Serve a built dashboard page or asset; directory routes map to their index.html."""
        rel = urllib.parse.unquote(path).lstrip("/")
        for candidate in (rel, os.path.join(rel, "index.html"), rel + ".html"):
            target = os.path.realpath(os.path.join(root, candidate))
            if os.path.commonpath([root, target]) != root or not os.path.isfile(target):
                continue
            with open(target, "rb") as f:
                body = f.read()
            ext = os.path.splitext(target)[1].lower()
            # Hashed build assets never change; pages must revalidate after a rebuild
            cache = "public, max-age=31536000, immutable" if rel.startswith("_astro/") else "no-cache"
            self._send_bytes(200, body, CONTENT_TYPES.get(ext, "application/octet-stream"), cache)
            return
        not_found = os.path.join(root, "404.html")
        body = open(not_found, "rb").read() if os.path.isfile(not_found) else b"Not found"
        self._send_bytes(404, body, "text/html; charset=utf-8")

    def _lab_get(self, path: str):
        parts = [p for p in path.split("/") if p]
        if path == "/api/host":
            host = cached_host()
            self._json(200, {"host": host, "labs": oslab.lab_catalog(REPO_ROOT, host)["labs"]})
        elif path == "/api/capabilities":
            self._json(200, oslab.capability_catalog())
        elif len(parts) == 4 and parts[:2] == ["api", "labs"] and parts[2] in oslab.LABS and parts[3] == "config":
            self._json(200, oslab.lab_config(REPO_ROOT, parts[2]))
        elif len(parts) == 4 and parts[:2] == ["api", "labs"] and parts[2] in oslab.LABS and parts[3] == "monitor":
            self._json(200, oslab.monitor(REPO_ROOT, parts[2], cached_host()))
        elif len(parts) == 4 and parts[:2] == ["api", "labs"] and parts[2] == "ios" and parts[3] == "simulator":
            self._json(200, oslab.ios_simulator(REPO_ROOT))
        elif len(parts) == 4 and parts[:2] == ["api", "labs"] and parts[2] == "ios" and parts[3] == "screenshot":
            self._send_bytes(200, oslab.ios_screenshot(), "image/png", cache="no-store")
        elif path == "/api/jobs":
            self._json(200, {"jobs": JOBS.list()})
        elif len(parts) == 3 and parts[:2] == ["api", "jobs"]:
            job = JOBS.get(parts[2])
            if job:
                self._json(200, job.to_dict(logs=True))
            else:
                self._json(404, {"error": "Job not found"})
        else:
            self._json(404, {"error": "Not found"})

    def do_POST(self):
        if not self._host_ok():
            return
        # Browsers cannot add a custom header cross-site without a CORS preflight, which this
        # server never approves, so other web pages cannot drive the lab.
        if self.headers.get("X-OSLab") != "1":
            self._json(403, {"error": "Missing X-OSLab header"})
            return
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/source" or path.startswith("/api/source/"):
            self._source_mutate(path)
            return
        if path.startswith("/api/content"):
            self._content_post(path)
            return
        if path.startswith("/api/app/update"):
            self._app_post(path)
            return
        if path.startswith("/api/cleanup"):
            self._cleanup_post(path)
            return
        if path.startswith(("/api/labs", "/api/jobs")):
            if not oslab:
                self._json(501, {"error": "The console module (console/oslab.py) is not installed"})
                return
            try:
                self._lab_post(path)
            except (oslab.PlanError, ValueError) as e:
                self._json(400, {"error": str(e)})
            return
        self._android_post()

    def _content_get(self, path: str, query: dict):
        """Content packs: what is installed, the companies, and the data files (see console/content.py)."""
        if not CONTENT:
            self._json(501, {"error": "The content module (console/content.py) is not installed"})
            return
        if path == "/api/content/status":
            self._json(200, CONTENT.state())
        elif path == "/api/content/companies":
            self._json(200, CONTENT.companies())
        elif path == "/api/content/file":
            text = CONTENT.read_text((query.get("path") or [""])[0])
            if text is None:
                self._json(404, {"error": "Not a content file"})
            else:
                self._send_bytes(200, text.encode("utf-8"), "text/plain; charset=utf-8")
        else:
            self._json(404, {"error": "Not found"})

    def _content_post(self, path: str):
        if not CONTENT:
            self._json(501, {"error": "The content module (console/content.py) is not installed"})
            return
        try:
            data = self._read_json()
            if path == "/api/content/check":
                self._json(200, CONTENT.check())
            elif path == "/api/content/update":
                # Hooks run inside other processes, so they are only installed when asked for, every time.
                self._json(200, CONTENT.update(include_hooks=data.get("hooks") is True))
            elif path == "/api/content/reset":
                self._json(200, CONTENT.reset())
            else:
                self._json(404, {"error": "Not found"})
        except content_packs.ContentError as e:
            self._json(400, {"error": str(e)})
        except ValueError as e:
            self._json(400, {"error": str(e)})

    def _app_get(self, path: str):
        """App updates: the newest signed release and any install in progress (see console/app_update.py)."""
        if not APP:
            self._json(501, {"error": "The app update module (console/app_update.py) is not installed"})
            return
        if path == "/api/app/update":
            self._json(200, APP.state())
        else:
            self._json(404, {"error": "Not found"})

    def _app_post(self, path: str):
        if not APP:
            self._json(501, {"error": "The app update module (console/app_update.py) is not installed"})
            return
        try:
            self._read_json()
            if path == "/api/app/update/check":
                self._json(200, APP.check())
            elif path == "/api/app/update/install":
                self._json(202, APP.install())
            else:
                self._json(404, {"error": "Not found"})
        except app_updates.AppUpdateError as e:
            self._json(400, {"error": str(e)})
        except ValueError as e:
            self._json(400, {"error": str(e)})

    def _lab_post(self, path: str):
        parts = [p for p in path.split("/") if p]
        if path == "/api/labs/plan":
            request = self._read_json().get("request") or {}
            plan = oslab.plan(REPO_ROOT, request, cached_host())
            self._json(200, {"plan": plan, "token": SIGNER.sign({"request": request, "plan": plan} if request.get("lab") == "source" else request)})
        elif path == "/api/labs/start":
            data = self._read_json()
            request = data.get("request") or {}
            plan = oslab.plan(REPO_ROOT, request, cached_host())
            signed = {"request": request, "plan": plan} if request.get("lab") == "source" else request
            if not SIGNER.verify(signed, data.get("token")):
                self._json(409, {"error": "Preview this action before running it"})
                return
            plan = oslab.plan(REPO_ROOT, request, cached_host())
            job = JOBS.start(plan)
            self._json(200, job.to_dict())
        elif len(parts) == 4 and parts[:2] == ["api", "jobs"] and parts[3] == "cancel":
            self._read_json()
            try:
                job = JOBS.cancel(parts[2])
            except KeyError:
                self._json(404, {"error": "Job not found"})
                return
            self._json(200, job.to_dict())
        else:
            self._json(404, {"error": "Not found"})

    def _android_get(self):
        url_parts = urllib.parse.urlparse(self.path)
        path = url_parts.path

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(read_web_file("index.html"))

        elif path in STATIC_FILES:
            name, content_type = STATIC_FILES[path]
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(read_web_file(name))

        elif path == "/api/health" or path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "app": "android-lab", "version": "1.0.0",
                                         "console": bool(oslab)}).encode("utf-8"))

        elif path == "/api/logs":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"logs": CONSOLE_LOGS, "running": COMMAND_RUNNING}).encode("utf-8"))

        elif path == "/api/devices":
            try:
                adb_out = subprocess.check_output(["adb", "devices"], text=True, stderr=subprocess.DEVNULL)
            except Exception:
                adb_out = "ADB not found or no device connected."
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"devices": adb_out}).encode("utf-8"))

        elif path == "/api/apks":
            found = []
            for folder in ("apks", "scripts"):
                base = os.path.join(SCRIPT_DIR, folder)
                if os.path.isdir(base):
                    for name in sorted(os.listdir(base)):
                        full = os.path.join(base, name)
                        if name.endswith(".apk") and os.path.isfile(full):
                            found.append({"name": name, "path": f"{folder}/{name}", "size": os.path.getsize(full)})
            self._json(200, {"apks": found})

        elif path == "/api/hooks":
            self._json(200, {"hooks": CONTENT.hooks() if CONTENT else []})

        elif path == "/api/reports":
            reports = []
            if os.path.exists(ARTIFACTS_DIR):
                for root, _, files in os.walk(ARTIFACTS_DIR):
                    for f in files:
                        if f.endswith(".html"):
                            rel_path = os.path.relpath(os.path.join(root, f), ARTIFACTS_DIR)
                            reports.append({
                                "name": rel_path,
                                "url": f"/artifacts/{rel_path.replace(os.sep, '/')}"
                            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"reports": reports}).encode("utf-8"))

        elif path.startswith("/artifacts/"):
            rel_file = urllib.parse.unquote(path[len("/artifacts/"):])
            root = os.path.realpath(ARTIFACTS_DIR)
            target_file = os.path.realpath(os.path.join(root, rel_file))
            # Serve only files inside artifacts/ (no ../ or symlink escapes)
            inside = os.path.commonpath([root, target_file]) == root
            if inside and os.path.isfile(target_file):
                self.send_response(200)
                if target_file.endswith(".html"):
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                else:
                    self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()
                with open(target_file, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def _json(self, status: int, payload: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def _android_post(self):
        if self.path == "/api/logs/clear":
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            CONSOLE_LOGS.clear()
            self._json(200, {"status": "cleared"})

        elif self.path == "/api/stop":
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            proc = CURRENT_PROC
            if proc is None or proc.poll() is not None:
                self._json(409, {"error": "No job is running"})
                return
            proc.terminate()
            CONSOLE_LOGS.append("[!] Stop requested from the web console")
            self._json(200, {"status": "stopping"})

        elif self.path == "/api/run":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            data = json.loads(body.decode("utf-8"))
            action = data.get("action")
            apk = data.get("apk", os.path.join("scripts", "vulnerable-test.apk"))

            cmd = []
            title = action
            if action == "preflight":
                cmd = [sys.executable, os.path.join(SCRIPT_DIR, "orchestrator.py"), "preflight"]
                title = "Pre-flight Verification"
            elif action == "create-sample":
                cmd = [sys.executable, os.path.join(SCRIPTS_DIR, "create_sample_apk.py")]
                title = "Generate Test Sample APK"
            elif action == "wf1":
                cmd = [sys.executable, os.path.join(SCRIPT_DIR, "orchestrator.py"), "wf1", "--apk", apk]
                title = f"WF1 Static Pipeline on {apk}"
            elif action == "scan-secrets":
                cmd = [sys.executable, os.path.join(SCRIPTS_DIR, "secret_scanner.py"), apk]
                title = f"Secret Scanner on {apk}"
            elif action == "fuzz":
                cmd = [sys.executable, os.path.join(SCRIPTS_DIR, "ipc_fuzzer.py"), "-p", "com.testlab.vulnerable"]
                title = "IPC Component Fuzzer"
            elif action == "patch":
                cmd = [sys.executable, os.path.join(SCRIPTS_DIR, "apk_patcher.py"), apk]
                title = f"Patch APK {apk}"
            elif action == "agentic":
                cmd = [sys.executable, os.path.join(SCRIPTS_DIR, "agentic_engine.py"), apk]
                title = f"Agentic Playbook on {apk}"
            elif action == "analyze":
                cmd = [sys.executable, os.path.join(SCRIPTS_DIR, "app_analyzer.py"), apk]
                title = f"App Analyzer on {apk}"

            if cmd:
                t = threading.Thread(target=execute_background_command, args=(cmd, title))
                t.daemon = True
                t.start()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "started", "title": title}).encode("utf-8"))

        elif self.path == "/api/upload":
            content_type = self.headers.get("Content-Type", "")
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)

            filename = "uploaded_app.apk"
            file_data = b""

            if "multipart/form-data" in content_type and "boundary=" in content_type:
                boundary = content_type.split("boundary=")[-1].strip()
                if boundary.startswith('"') and boundary.endswith('"'):
                    boundary = boundary[1:-1]
                parts = body.split(f"--{boundary}".encode("utf-8"))
                for part in parts:
                    if b'filename="' in part:
                        import re
                        m = re.search(rb'filename="([^"]+)"', part)
                        if m:
                            filename = os.path.basename(m.group(1).decode("utf-8", errors="ignore"))
                        header_and_body = part.split(b"\r\n\r\n", 1)
                        if len(header_and_body) > 1:
                            file_data = header_and_body[1].rstrip(b"\r\n--")
                        break
            else:
                filename = self.headers.get("X-Filename", "uploaded_app.apk")
                file_data = body

            if not file_data:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "No file uploaded or empty payload"}).encode("utf-8"))
                return

            apks_dir = os.path.join(SCRIPT_DIR, "apks")
            os.makedirs(apks_dir, exist_ok=True)
            if filename in ("", ".", ".."):
                filename = "uploaded_app.apk"
            save_path = os.path.join(apks_dir, filename)
            with open(save_path, "wb") as f:
                f.write(file_data)

            rel_path = os.path.relpath(save_path, SCRIPT_DIR).replace("\\", "/")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "filename": filename,
                "path": rel_path,
                "size": len(file_data)
            }).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5050
    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, LabHttpHandler)
    httpd.daemon_threads = True
    print(f"=== 🛡️ os-lab web console running ===")
    print(f"URL: http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb console stopped.")


if __name__ == "__main__":
    main()
