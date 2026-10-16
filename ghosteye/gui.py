"""
Local web interface for GhostEye (standard library only).
Listens on 127.0.0.1, rejects foreign Host/Origin headers.
"""

import json
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import analysis, report, triage

WEB = Path(__file__).resolve().parent / "web"
STATIC = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "application/javascript"),
          "/style.css": ("style.css", "text/css")}


class App:
    def __init__(self, backend):
        self.b = backend
        self.lock = threading.Lock()
        self.job = {"running": False, "done": 0, "total": 0, "label": "", "error": None}
        self.report = None

    def start_triage(self, check_hooks):
        with self.lock:
            if self.job["running"]:
                return False
            self.job = {"running": True, "done": 0, "total": 1, "label": "starting", "error": None,
                        "started": time.time()}

        def progress(done, total, label):
            self.job.update(done=done, total=total, label=label)

        def work():
            try:
                self.report = triage.run(self.b, check_hooks=check_hooks, progress=progress)
            except Exception as e:  # surface to the UI
                self.job["error"] = f"{type(e).__name__}: {e}"
            finally:
                self.job["running"] = False

        threading.Thread(target=work, daemon=True).start()
        return True

    def processes(self):
        if self.report:
            return self.report["processes"]
        return self.b.processes()

    def process_detail(self, pid):
        proc = next((p for p in self.processes() if p["pid"] == pid), None)
        if proc is None:
            raise KeyError(f"PID {pid} not found")
        root = analysis.system_root(self.b.system().get("root"))
        out = {"process": proc, "modules": [], "regions": [], "errors": [], "findings": []}
        try:
            mods = self.b.modules(pid)
            for m in mods:
                risk, why = analysis.path_risk(m["path"], root)
                m.update(risk=risk, why=why, vendor=analysis.vendor_of(m["path"]))
            out["modules"] = mods
        except OSError as e:
            out["errors"].append(f"Modules: {e}")
        try:
            regs = self.b.regions(pid)
            for r in regs:
                r.update(type_name=analysis.MEM_TYPES.get(r["type"], "?"), protect_name=analysis.protect_str(r["protect"]),
                         exec=analysis.is_exec(r["protect"]),
                         flag=("RWX" if r["protect"] & 0xFF == 0x40 else
                               "unbacked exec" if r["type"] == analysis.MEM_PRIVATE and analysis.is_exec(r["protect"]) else ""))
            out["regions"] = regs
        except OSError as e:
            out["errors"].append(f"Memory: {e}")
        if self.report:
            tag = f"({pid})"
            out["findings"] = [f for f in self.report["findings"] if f["pid"] == pid
                               or any(x.endswith(tag) for x in f["evidence"].get("processes", []))]
        return out

    def hooks(self, pid):
        proc = next(p for p in self.processes() if p["pid"] == pid)
        hs = self.b.scan_hooks(pid)
        return [dict(h, finding=analysis.hook_finding(proc, h)) for h in hs]

    def network(self):
        if self.report:
            return self.report["connections"]
        procs = {p["pid"]: p for p in self.b.processes()}
        conns = self.b.connections()
        for c in conns:
            c["process"] = procs.get(c["pid"], {}).get("name", "?")
            c["flags"] = [r for _, r, _ in analysis.connection_flags(c, c["process"])]
        return conns


def _jsonable(o):
    return json.dumps(o, default=str, ensure_ascii=False)


def make_handler(app, port):
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
            if not isinstance(body, (bytes, str)):
                body = _jsonable(body)
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def guard(self):
            if self.headers.get("Host") not in allowed:
                self.send(403, {"error": "forbidden host"})
                return False
            o = self.headers.get("Origin")
            if o and o.split("//", 1)[-1] not in allowed:
                self.send(403, {"error": "forbidden origin"})
                return False
            return True

        def do_GET(self):
            if not self.guard():
                return
            u = urlparse(self.path)
            q = {k: v[-1] for k, v in parse_qs(u.query).items()}
            parts = u.path.strip("/").split("/")
            try:
                if u.path in STATIC:
                    f, ct = STATIC[u.path]
                    return self.send(200, (WEB / f).read_bytes(), ct + "; charset=utf-8")
                if u.path == "/api/state":
                    return self.send(200, {"system": app.b.system(), "job": app.job, "report": app.report})
                if u.path == "/api/job":
                    return self.send(200, app.job)
                if u.path == "/api/processes":
                    return self.send(200, app.processes())
                if u.path == "/api/network":
                    return self.send(200, app.network())
                if len(parts) == 3 and parts[:2] == ["api", "process"]:
                    return self.send(200, app.process_detail(int(parts[2])))
                if len(parts) == 4 and parts[:2] == ["api", "process"] and parts[3] == "strings":
                    return self.send(200, triage.strings(app.b, int(parts[2]), int(q.get("min", 5)), q.get("q", ""),
                                                         q.get("tagged") == "1", int(q.get("limit", 3000))))
                if u.path in ("/api/export.json", "/api/export.html"):
                    if not app.report:
                        return self.send(409, {"error": "Run a triage first"})
                    name = "ghosteye_{}_{}".format(app.report["system"]["hostname"], app.report["started"][:10])
                    if u.path.endswith("json"):
                        return self.send(200, report.to_json(app.report), "application/json; charset=utf-8",
                                         {"Content-Disposition": f'attachment; filename="{name}.json"'})
                    return self.send(200, report.to_html(app.report), "text/html; charset=utf-8")
            except (KeyError, StopIteration) as e:
                return self.send(404, {"error": str(e)})
            except OSError as e:
                return self.send(403, {"error": f"{e}"})
            except Exception as e:
                return self.send(500, {"error": f"{type(e).__name__}: {e}"})
            self.send(404, {"error": "not found"})

        def do_POST(self):
            if not self.guard():
                return
            u = urlparse(self.path)
            parts = u.path.strip("/").split("/")
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            try:
                if u.path == "/api/triage":
                    started = app.start_triage(bool(body.get("hooks", True)))
                    return self.send(202 if started else 409, app.job)
                if len(parts) == 4 and parts[:2] == ["api", "process"] and parts[3] == "hooks":
                    return self.send(200, app.hooks(int(parts[2])))
            except (KeyError, StopIteration) as e:
                return self.send(404, {"error": str(e)})
            except OSError as e:
                return self.send(403, {"error": f"{e}"})
            except Exception as e:
                return self.send(500, {"error": f"{type(e).__name__}: {e}"})
            self.send(404, {"error": "not found"})

    return H


def run(backend, port=8770, open_browser=True):
    app = App(backend)
    server = None
    for p in range(port, port + 20):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", p), make_handler(app, p))
            port = p
            break
        except OSError:
            continue
    if not server:
        raise SystemExit("No free port")
    url = f"http://127.0.0.1:{port}/"
    print(f"\n  GhostEye ({backend.name} mode) → {url}\n  Ctrl+C to stop.\n", flush=True)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Bye.")
    finally:
        server.server_close()
