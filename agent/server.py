"""Small web backend for the agent UI. Standard library only.

    python -m agent serve                      # http://127.0.0.1:8080 (loopback only, no token needed)
    AGENT_UI_TOKEN=... python -m agent serve --host 0.0.0.0     # non-loopback REQUIRES a token

Security model (this is a control surface that clones and analyses code, so it is built defensively):
  * binds to loopback by default; a non-loopback bind without AGENT_UI_TOKEN is refused at start-up
  * only https URLs on allowlisted hosts; local filesystem paths are rejected (unless a dev flag is set)
  * consent is the person TYPING the repo name; trust (write access) is verified via GitHub metadata
  * POST requires JSON content-type, same-origin Origin header, small body; Host header checked on token-less servers
  * one job at a time, per-hour rate limit, bounded retention, fixed set of downloadable files, no path traversal
  * the UI never puts repo-derived text into HTML (textContent only); responses carry a strict CSP
"""
from __future__ import annotations

import hmac
import json
import os
import re
import shutil
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from . import __version__
from . import consent as consent_mod
from .orchestrator import Orchestrator, RunOptions
from .policy import load_policy
from .scanners import redact_text

WEB_DIR = Path(__file__).parent / "web"
STATIC_FILES = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
                "/agent-panel.js": ("agent-panel.js", "text/javascript; charset=utf-8")}
JOB_ID_RX = re.compile(r"^[0-9a-f]{12}$")
MODES = ("analyze", "verify", "open-pr")
STAGES = ["consent", "intake", "scan", "analyze", "baseline", "plan_and_change", "publish"]
MAX_BODY = 8 * 1024
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    out_dir: Path = Path("ui-runs")
    token: str | None = None
    sandbox: str = "auto"
    allow_unsafe_local: bool = False
    java_cache: str | None = None
    prefetch_network: bool = False
    docker_image: str = "auto"            # auto = pick maven/gradle/python image from the detected build tool
    java_version: str = "17"
    docker_memory: str = "3g"
    allow_local_paths: bool = False      # DEV ONLY: lets the API read local directories
    max_jobs_per_hour: int = 10
    max_kept: int = 20
    have_docker: bool | None = None      # None = detect


@dataclass
class Job:
    id: str
    slug: str
    repo_url: str
    mode: str
    who: str
    state: str = "queued"                # queued | running | done | failed | refused
    created: float = field(default_factory=time.time)
    finished: float | None = None
    stages: dict[str, str] = field(default_factory=lambda: {s: "pending" for s in STAGES})
    error: str = ""
    dir: Path | None = None
    run_dir: Path | None = None
    summary: dict | None = None

    def public(self, with_summary: bool = True) -> dict:
        d = {"id": self.id, "repo": self.slug, "mode": self.mode, "state": self.state, "created": self.created,
             "finished": self.finished, "stages": self.stages, "error": self.error, "who": self.who}
        if with_summary:
            d["summary"] = self.summary
        return d


def summarize(state: dict, run_dir: Path) -> dict:
    """Shape the orchestrator state for the UI (no giant maps; patch text is fetched separately)."""
    base = state.get("baseline") or {}
    patch_files = sorted((run_dir / "patches").glob("*.diff")) if (run_dir / "patches").is_dir() else []
    return {
        "status": state["status"], "languages": state.get("languages", []), "build_tool": state.get("build_tool", ""),
        "commit": state.get("commit", ""), "notes": state.get("notes", []),
        "consent": state.get("consent"),
        "counts": {"dead_code": len(state["findings"]["dead_code"]),
                   "dead_code_high": sum(1 for f in state["findings"]["dead_code"] if f["confidence"] == "high"),
                   "duplicates": len(state["findings"]["duplicates"]), "secrets": len(state["scan"]["secrets"]),
                   "injections": len(state["scan"]["injections"]), "files_scanned": state["scan"]["files_scanned"]},
        "findings": state["findings"],
        "security": {"secrets": state["scan"]["secrets"], "sensitive_files": state["scan"]["sensitive_files"],
                     "injections": state["scan"]["injections"]},
        "baseline": {k: base.get(k) for k in ("runs", "passed", "failed", "skipped", "green", "reason", "avg_duration",
                                               "output_tail")} if base else None,
        "change_sets": [{k: cs.get(k) for k in ("id", "type", "decision", "files", "added", "removed", "gates", "policy",
                                                 "findings", "skipped", "branch", "pr")} for cs in state["change_sets"]],
        "has_patch": bool(patch_files), "has_pr_text": (run_dir / "pr").is_dir() and any((run_dir / "pr").glob("*.md")),
        "audit_verified": state.get("audit_verified"),
    }


class JobManager:
    def __init__(self, cfg: ServerConfig, runner: Callable[[Job, ServerConfig, consent_mod.ConsentRecord], None] | None = None):
        self.cfg = cfg
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.starts: deque[float] = deque()
        self.runner = runner or self._default_runner
        cfg.out_dir.mkdir(parents=True, exist_ok=True)

    def submit(self, ref, mode: str, who: str, record: consent_mod.ConsentRecord) -> Job:
        with self.lock:
            if any(j.state in ("queued", "running") for j in self.jobs.values()):
                raise ApiError(429, "another job is running; wait for it to finish")
            now = time.time()
            while self.starts and now - self.starts[0] > 3600:
                self.starts.popleft()
            if len(self.starts) >= self.cfg.max_jobs_per_hour:
                raise ApiError(429, f"rate limit: at most {self.cfg.max_jobs_per_hour} jobs per hour")
            self.starts.append(now)
            job = Job(uuid.uuid4().hex[:12], ref.slug, ref.clone_url or str(ref.path), mode, who)
            job.dir = self.cfg.out_dir / job.id
            self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job, record), daemon=True).start()
        return job

    def _run(self, job: Job, record: consent_mod.ConsentRecord) -> None:
        job.state = "running"
        try:
            self.runner(job, self.cfg, record)
        except Exception as e:  # never leave a job hanging
            job.state, job.error = "failed", redact_text(f"{type(e).__name__}: {e}")[:300]
        finally:
            job.finished = time.time()
            self._prune()

    @staticmethod
    def _default_runner(job: Job, cfg: ServerConfig, record: consent_mod.ConsentRecord) -> None:
        def on_stage(name: str, phase: str) -> None:
            if name in job.stages:
                job.stages[name] = phase

        opts = RunOptions(
            repo=job.repo_url, out_dir=job.dir, run_tests=job.mode != "analyze", open_pr=job.mode == "open-pr",
            sandbox=cfg.sandbox, allow_unsafe_local=cfg.allow_unsafe_local, java_cache=cfg.java_cache,
            prefetch_network=cfg.prefetch_network, docker_image=cfg.docker_image, java_version=cfg.java_version,
            docker_memory=cfg.docker_memory,
            consent=record, on_stage=on_stage)
        orch = Orchestrator(opts)
        state = orch.run()
        job.run_dir = orch.out
        job.summary = summarize(state, orch.out)
        status = state["status"]
        job.state = "done" if status == "completed" else "refused" if status.startswith("refused") else "failed"
        if job.state != "done":
            job.error = redact_text(status)[:300]
        for s in STAGES:                      # stages that never ran stay 'pending'; mark skipped ones clearly
            if job.stages[s] == "running":
                job.stages[s] = "failed"

    def _prune(self) -> None:
        with self.lock:
            finished = sorted((j for j in self.jobs.values() if j.finished), key=lambda j: j.finished)
            for j in finished[:-self.cfg.max_kept] if len(finished) > self.cfg.max_kept else []:
                self.jobs.pop(j.id, None)
                if j.dir:
                    shutil.rmtree(j.dir, ignore_errors=True)

    def get(self, job_id: str) -> Job:
        if not JOB_ID_RX.match(job_id or "") or job_id not in self.jobs:
            raise ApiError(404, "no such job")
        return self.jobs[job_id]


def detect_docker() -> bool:
    import subprocess
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class App:
    def __init__(self, cfg: ServerConfig, runner=None):
        self.cfg = cfg
        self.policy = load_policy()
        self.jobs = JobManager(cfg, runner)
        self.docker = detect_docker() if cfg.have_docker is None else cfg.have_docker

    # ---- capability / validation helpers -------------------------------------------------------
    def capabilities(self) -> dict:
        local_ok = self.cfg.sandbox == "local" and self.cfg.allow_unsafe_local
        can_run = self.docker or local_ok
        write = bool(os.environ.get("AGENT_WRITE_TOKEN"))
        return {"version": __version__, "auth_required": bool(self.cfg.token), "docker": self.docker,
                "modes": {
                    "analyze": {"available": True, "label": "Analyze (read-only report; executes nothing)"},
                    "verify": {"available": can_run, "label": "Verify (run tests, generate a verified patch)",
                               "reason": "" if can_run else "needs Docker (or --sandbox local --allow-unsafe-local on the server)"},
                    "open-pr": {"available": can_run and write, "label": "Open PR (push an agent/* branch)",
                                "reason": "" if can_run and write else "needs a sandbox and AGENT_WRITE_TOKEN on the server"}}}

    def _resolve(self, repo_url: str, mode: str):
        if mode not in MODES:
            raise ApiError(400, f"mode must be one of: {', '.join(MODES)}")
        if not isinstance(repo_url, str) or len(repo_url) > 300:
            raise ApiError(400, "repo_url must be a string")
        try:
            ref = consent_mod.parse_repo_ref(repo_url, self.policy["consent"]["allowed_hosts"])
        except consent_mod.ConsentError as e:
            raise ApiError(400, str(e))
        if ref.kind == "local" and not self.cfg.allow_local_paths:
            raise ApiError(400, "only https GitHub URLs are accepted here (local paths are disabled)")
        cap = self.capabilities()["modes"][mode]
        if not cap["available"]:
            raise ApiError(400, f"mode '{mode}' is not available on this server: {cap['reason']}")
        scopes = consent_mod.needed_scopes(mode != "analyze", False, mode == "open-pr")
        info = consent_mod.fetch_repo_info(ref, os.environ.get("AGENT_READ_TOKEN"))
        if mode != "analyze" and info.trust != "trusted" and not self.docker:
            raise ApiError(403, "this repository is untrusted (no verified write access): its tests may only run in Docker")
        return ref, scopes, info

    def notice(self, body: dict) -> dict:
        ref, scopes, info = self._resolve(body.get("repo_url", ""), body.get("mode", "analyze"))
        try:
            _, text = self._notice_text(ref, scopes, info)
        except consent_mod.ConsentError as e:
            raise ApiError(403, str(e))
        return {"slug": ref.slug, "scopes": scopes, "scope_text": {s: consent_mod.SCOPES[s] for s in scopes},
                "trust": info.trust, "trust_reason": info.trust_reason, "visibility": info.visibility,
                "license": info.license, "notice": text}

    def _notice_text(self, ref, scopes, info):
        consent_mod._enforce_trust(scopes, info)
        text = consent_mod.render_notice(ref, scopes, info, "web user", "applies to THIS RUN only (after you type the name below)",
                                         self.policy["secrets"]["deny_read"], str(self.cfg.out_dir))
        return None, text

    def start_job(self, body: dict, client: str) -> Job:
        ref, scopes, info = self._resolve(body.get("repo_url", ""), body.get("mode", "analyze"))
        who = f"web-ui@{client}" + (" (token)" if self.cfg.token else "")
        try:
            record, _ = consent_mod.web_consent(ref, scopes, info, body.get("confirm", ""), who,
                                                self.policy["secrets"]["deny_read"], str(self.cfg.out_dir))
        except consent_mod.ConsentError as e:
            raise ApiError(403, str(e))
        return self.jobs.submit(ref, body["mode"], who, record)


def make_handler(app: App):
    cfg = app.cfg

    class Handler(BaseHTTPRequestHandler):
        server_version = "MaintenanceAgentUI"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):   # never log bodies/tokens; keep it quiet
            pass

        # ---- helpers ----
        def _headers(self, ctype: str, length: int, status: int, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()

        def _json(self, obj, status: int = 200) -> None:
            data = json.dumps(obj).encode()
            self._headers("application/json; charset=utf-8", len(data), status)
            self.wfile.write(data)

        def _text(self, text: str, ctype: str = "text/plain; charset=utf-8", status: int = 200, extra=None) -> None:
            data = text.encode()
            self._headers(ctype, len(data), status, extra)
            self.wfile.write(data)

        def _guard(self, post: bool) -> None:
            host = (self.headers.get("Host") or "").lower()
            hostname = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
            if not cfg.token and hostname not in LOOPBACK_HOSTS:         # DNS-rebinding protection for token-less servers
                raise ApiError(403, "unexpected Host header")
            if cfg.token:
                supplied = (self.headers.get("X-Agent-Token") or self.headers.get("Authorization", "").removeprefix("Bearer ")).strip()
                if not supplied or not hmac.compare_digest(supplied.encode(), cfg.token.encode()):
                    raise ApiError(401, "access token required")
            if post:
                if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
                    raise ApiError(415, "Content-Type must be application/json")
                origin = self.headers.get("Origin")
                if origin and urlsplit(origin).netloc.lower() != host:
                    raise ApiError(403, "cross-origin request refused")

        def _body(self) -> dict:
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise ApiError(400, "bad Content-Length")
            if n > MAX_BODY:
                raise ApiError(413, "request too large")
            try:
                obj = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, UnicodeDecodeError):
                raise ApiError(400, "invalid JSON")
            if not isinstance(obj, dict):
                raise ApiError(400, "JSON object expected")
            return obj

        def _client(self) -> str:
            return self.client_address[0]

        def _dispatch(self, fn) -> None:
            try:
                fn()
            except ApiError as e:
                self._json({"error": e.message}, e.status)
            except Exception as e:  # never leak internals
                self._json({"error": "internal error"}, 500)
                if os.environ.get("AGENT_UI_DEBUG"):
                    raise

        # ---- routes ----
        def do_GET(self) -> None:
            def go():
                path = urlsplit(self.path).path
                if path in STATIC_FILES:
                    name, ctype = STATIC_FILES[path]
                    self._text((WEB_DIR / name).read_text(encoding="utf-8"), ctype)
                    return
                if not path.startswith("/api/"):
                    raise ApiError(404, "not found")
                self._guard(post=False)
                parts = path.strip("/").split("/")
                if parts == ["api", "capabilities"]:
                    self._json(app.capabilities())
                elif parts == ["api", "jobs"]:
                    self._json([j.public(False) for j in sorted(app.jobs.jobs.values(), key=lambda j: -j.created)])
                elif len(parts) == 3 and parts[:2] == ["api", "jobs"]:
                    self._json(app.jobs.get(parts[2]).public())
                elif len(parts) == 4 and parts[:2] == ["api", "jobs"] and parts[3] in ("report", "patch", "pr"):
                    job = app.jobs.get(parts[2])
                    self._artifact(job, parts[3])
                else:
                    raise ApiError(404, "not found")
            self._dispatch(go)

        def _artifact(self, job: Job, kind: str) -> None:
            if not job.run_dir:
                raise ApiError(404, "not ready")
            if kind == "report":
                f, name = job.run_dir / "report.md", f"report-{job.id}.md"
            elif kind == "patch":
                files = sorted((job.run_dir / "patches").glob("*.diff")) if (job.run_dir / "patches").is_dir() else []
                if not files:
                    raise ApiError(404, "no patch was generated")
                f, name = files[0], f"{job.slug.replace('/', '__')}-{job.id}.diff"
            else:
                files = sorted((job.run_dir / "pr").glob("*.md")) if (job.run_dir / "pr").is_dir() else []
                if not files:
                    raise ApiError(404, "no PR text was generated")
                f, name = files[0], f"pr-{job.id}.md"
            if not f.is_file() or f.is_symlink():
                raise ApiError(404, "not found")
            text = f.read_text(encoding="utf-8", errors="replace")
            self._text(text[:2_000_000], extra={"Content-Disposition": f'inline; filename="{name}"'})

        def do_POST(self) -> None:
            def go():
                path = urlsplit(self.path).path
                self._guard(post=True)
                if path == "/api/notice":
                    self._json(app.notice(self._body()))
                elif path == "/api/jobs":
                    job = app.start_job(self._body(), self._client())
                    self._json({"id": job.id}, 202)
                else:
                    raise ApiError(404, "not found")
            self._dispatch(go)

    return Handler


def create_server(cfg: ServerConfig, runner=None) -> tuple[ThreadingHTTPServer, App]:
    if cfg.host not in ("127.0.0.1", "localhost", "::1") and not cfg.token:
        raise SystemExit("refusing to listen on a non-loopback address without an access token: set AGENT_UI_TOKEN")
    if cfg.token is not None and len(cfg.token) < 16:
        raise SystemExit("AGENT_UI_TOKEN must be at least 16 characters")
    app = App(cfg, runner)
    srv = ThreadingHTTPServer((cfg.host, cfg.port), make_handler(app))
    srv.daemon_threads = True
    return srv, app
