"""Drive the real web component in jsdom against a real server (skipped without node + jsdom)."""
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from agent.demo import create_demo_repo
from agent.server import STAGES, ServerConfig, create_server

HERE = Path(__file__).parent / "ui"


def _node_path() -> str | None:
    for cand in (os.environ.get("NODE_PATH", ""), str(HERE / "node_modules")):
        for c in filter(None, cand.split(os.pathsep)):
            if (Path(c) / "jsdom").is_dir():
                return c
    return None


pytestmark = pytest.mark.skipif(not shutil.which("node") or not _node_path(),
                                reason="needs node + jsdom (cd tests/ui && npm install)")

XSS = ["<img src=x onerror=window.__pwned=1>", "<script>window.__pwned=2</script>", "</pre><svg onload=window.__pwned=3>"]
PATCH = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,5 +1,3 @@\n keep\n-" + XSS[0] + "\n-def gone():\n-    pass\n+" + XSS[1] + "\n tail\n")


def hostile_runner(job, cfg, record):
    run = job.dir / "run"
    (run / "patches").mkdir(parents=True)
    (run / "pr").mkdir()
    (run / "patches" / "CS-001.diff").write_text(PATCH)
    (run / "pr" / "CS-001.md").write_text("## Summary\n" + XSS[0] + "\n")
    (run / "report.md").write_text("# Code maintenance report\n" + XSS[1])
    job.run_dir = run
    for s in STAGES:
        job.stages[s] = "done"
    finding = {"id": "DC-001", "type": "dead_code", "confidence": "high", "file": XSS[2], "line": 3, "end_line": 4,
               "symbol": XSS[0], "kind": "function", "evidence": [XSS[1]], "proposed_action": "remove", "risk": "low",
               "status": "included_in_pr", "col": 0, "related": []}
    job.summary = {
        "status": "completed", "languages": ["python"], "build_tool": "pytest", "commit": "abc", "notes": [XSS[0]],
        "consent": {"granted_by": XSS[1], "method": "web", "scopes": ["read"], "trust": "trusted"},
        "counts": {"dead_code": 1, "dead_code_high": 1, "duplicates": 1, "secrets": 1, "injections": 1, "files_scanned": 3},
        "findings": {"dead_code": [finding], "duplicates": [{"id": "DUP-001", "file": XSS[2], "line": 1, "end_line": 9, "confidence": "medium",
                                                             "evidence": [XSS[0]], "related": [{"file": XSS[1], "start": 2, "end": 10}]}]},
        "security": {"secrets": [{"kind": XSS[0], "file": XSS[2], "line": 1, "preview": XSS[1]}], "sensitive_files": [XSS[2]],
                     "injections": [{"kind": "x", "file": XSS[2], "line": 2, "excerpt": XSS[1]}]},
        "baseline": None, "has_patch": True, "has_pr_text": True, "audit_verified": True,
        "change_sets": [{"id": "CS-001", "type": "dead_code", "decision": "ready", "files": [XSS[2]], "added": 1, "removed": 3,
                         "gates": [{"name": XSS[0], "passed": True, "detail": XSS[1]}], "policy": {"allowed": True, "reasons": []},
                         "findings": [finding], "skipped": [], "branch": None, "pr": None}]}
    job.state = "done"


def run_node(base, env_extra, tmp_path):
    env = {**os.environ, "NODE_PATH": _node_path(), "BASE_URL": base, **env_extra}
    r = subprocess.run(["node", str(HERE / "ui_smoke.js")], env=env, capture_output=True, text=True, timeout=240)
    return r


def serve(tmp_path, runner=None):
    cfg = ServerConfig(port=0, out_dir=tmp_path / "ui", have_docker=False, allow_local_paths=True, sandbox="local", allow_unsafe_local=True)
    server, app = create_server(cfg, runner)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def test_real_end_to_end_flow_in_the_browser_component(tmp_path):
    demo = create_demo_repo(tmp_path / "demo-shop")
    server, base = serve(tmp_path)
    try:
        r = run_node(base, {"FLOW": "real", "REPO": str(demo), "CONFIRM": "demo-shop", "MODE": "verify"}, tmp_path)
    finally:
        server.shutdown()
    assert r.returncode == 0 and "UI-SMOKE-OK" in r.stdout, r.stdout + r.stderr


def test_hostile_repo_strings_render_as_text_only(tmp_path):
    demo = create_demo_repo(tmp_path / "demo-shop")
    server, base = serve(tmp_path, hostile_runner)
    try:
        r = run_node(base, {"FLOW": "hostile", "REPO": str(demo), "CONFIRM": "demo-shop", "MODE": "analyze"}, tmp_path)
    finally:
        server.shutdown()
    assert r.returncode == 0 and "UI-SMOKE-OK" in r.stdout, r.stdout + r.stderr
