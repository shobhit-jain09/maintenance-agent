"""Web backend: real HTTP against a real server on an ephemeral port."""
import http.client
import json
import re
import threading
import time
from pathlib import Path

import pytest

from agent import consent as C
from agent.consent import RepoInfo
from agent.demo import create_demo_repo
from agent.server import STAGES, ServerConfig, create_server

UNTRUSTED = RepoInfo(source="github_api", visibility="public", trust="untrusted", trust_reason="no write access")


class Client:
    def __init__(self, server, app):
        self.server, self.app, self.port = server, app, server.server_address[1]

    def req(self, method, path, body=None, headers=None, raw=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Host": host} if host else {}
        h.update(headers or {})
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        payload = r.read()
        conn.close()
        ctype = r.getheader("Content-Type", "")
        return r.status, r, (json.loads(payload) if "json" in ctype else payload.decode())

    def wait(self, job_id, timeout=120):
        end = time.time() + timeout
        while time.time() < end:
            st, _, j = self.req("GET", f"/api/jobs/{job_id}")
            if j["state"] in ("done", "failed", "refused"):
                return j
            time.sleep(0.3)
        raise AssertionError("job did not finish")


@pytest.fixture
def make(tmp_path):
    servers = []

    def _make(runner=None, **over):
        cfg = dict(port=0, out_dir=tmp_path / "ui", have_docker=False, allow_local_paths=True, sandbox="local",
                   allow_unsafe_local=True, max_jobs_per_hour=50)
        cfg.update(over)
        server, app = create_server(ServerConfig(**cfg), runner)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return Client(server, app)

    yield _make
    for s in servers:
        s.shutdown()
        s.server_close()


@pytest.fixture
def demo(tmp_path):
    return create_demo_repo(tmp_path / "demo-shop")


# ---- static assets and headers ----------------------------------------------------------------
def test_static_assets_and_security_headers(make):
    c = make()
    st, r, body = c.req("GET", "/")
    assert st == 200 and "<maintenance-agent-panel" in body
    csp = r.getheader("Content-Security-Policy")
    assert "script-src 'self'" in csp and "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert r.getheader("X-Frame-Options") == "DENY" and r.getheader("X-Content-Type-Options") == "nosniff"
    assert r.getheader("Cache-Control") == "no-store"
    st, r, js = c.req("GET", "/agent-panel.js")
    assert st == 200 and "javascript" in r.getheader("Content-Type") and "customElements.define" in js
    for bad in ("/../../etc/passwd", "/static/x", "/agent_panel.js", "/%2e%2e/%2e%2e/etc/passwd", "/api"):
        assert c.req("GET", bad)[0] == 404, bad


def test_ui_never_inserts_repo_text_as_html():
    js = (Path(__file__).parents[1] / "agent" / "web" / "agent-panel.js").read_text()
    code = re.sub(r"/\*.*?\*/", "", js, flags=re.S)           # ignore the explanatory comment block
    for sink in (r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"insertAdjacentHTML\(", r"document\.write\(", r"\beval\(", r"new Function\("):
        assert not re.search(sink, code), sink


# ---- startup guardrails --------------------------------------------------------------------------
def test_refuses_non_loopback_without_token_and_short_tokens(tmp_path):
    with pytest.raises(SystemExit, match="non-loopback"):
        create_server(ServerConfig(host="0.0.0.0", port=0, out_dir=tmp_path))
    with pytest.raises(SystemExit, match="16 characters"):
        create_server(ServerConfig(host="0.0.0.0", port=0, out_dir=tmp_path, token="short"))


# ---- authentication -----------------------------------------------------------------------------
def test_token_auth(make):
    c = make(token="correct-horse-battery-staple")
    assert c.req("GET", "/")[0] == 200                                           # the page itself is public
    assert c.req("GET", "/api/capabilities")[0] == 401
    assert c.req("GET", "/api/capabilities", headers={"X-Agent-Token": "wrong-wrong-wrong-wrong"})[0] == 401
    assert c.req("GET", "/api/capabilities", headers={"X-Agent-Token": "correct-horse-battery-staple"})[0] == 200
    assert c.req("GET", "/api/capabilities", headers={"Authorization": "Bearer correct-horse-battery-staple"})[0] == 200
    assert c.req("POST", "/api/jobs", body={"repo_url": "x"})[0] == 401


# ---- request hardening ----------------------------------------------------------------------------
def test_post_hardening(make):
    c = make()
    assert c.req("POST", "/api/notice", raw=b'{"repo_url":"x"}', headers={"Content-Type": "text/plain"})[0] == 415
    assert c.req("POST", "/api/notice", raw=b'{"repo_url":"x"}', headers={"Content-Type": "application/x-www-form-urlencoded"})[0] == 415
    assert c.req("POST", "/api/notice", raw=b"{not json", headers={"Content-Type": "application/json"})[0] == 400
    assert c.req("POST", "/api/notice", raw=b"[1,2]", headers={"Content-Type": "application/json"})[0] == 400
    assert c.req("POST", "/api/notice", raw=b"x" * 20000, headers={"Content-Type": "application/json"})[0] == 413
    st, _, j = c.req("POST", "/api/notice", body={"repo_url": "x"}, headers={"Origin": "https://evil.example"})
    assert st == 403 and "cross-origin" in j["error"]
    same = f"http://127.0.0.1:{c.port}"
    assert c.req("POST", "/api/notice", body={"repo_url": "x"}, headers={"Origin": same})[0] == 400   # allowed through, then validated


def test_dns_rebinding_protection_on_tokenless_servers(make):
    c = make()
    assert c.req("GET", "/api/capabilities", host="evil.example")[0] == 403
    assert c.req("GET", "/api/capabilities", host=f"localhost:{c.port}")[0] == 200


@pytest.mark.parametrize("url", [
    "--upload-pack=x", "ext::sh -c id", "https://u:tok@github.com/a/b", "http://github.com/a/b", "ssh://git@github.com/a/b",
    "https://evil.example/a/b", "file:///etc/passwd", "/etc", "", None, 123, "x" * 400])
def test_hostile_repo_values_rejected(make, url):
    c = make(allow_local_paths=False)
    st, _, j = c.req("POST", "/api/notice", body={"repo_url": url, "mode": "analyze"})
    assert st == 400 and "error" in j
    assert c.req("POST", "/api/jobs", body={"repo_url": url, "mode": "analyze", "confirm": "x"})[0] == 400


def test_local_paths_rejected_unless_dev_flag(make, demo):
    st, _, j = make(allow_local_paths=False).req("POST", "/api/notice", body={"repo_url": str(demo), "mode": "analyze"})
    assert st == 400 and "local paths are disabled" in j["error"]


# ---- capabilities / modes ---------------------------------------------------------------------------
def test_capabilities_reflect_the_server_setup(make, monkeypatch):
    monkeypatch.delenv("AGENT_WRITE_TOKEN", raising=False)
    caps = make().req("GET", "/api/capabilities")[2]
    assert caps["auth_required"] is False and caps["modes"]["analyze"]["available"] and caps["modes"]["verify"]["available"]
    assert not caps["modes"]["open-pr"]["available"] and "AGENT_WRITE_TOKEN" in caps["modes"]["open-pr"]["reason"]
    nosbx = make(allow_unsafe_local=False).req("GET", "/api/capabilities")[2]
    assert not nosbx["modes"]["verify"]["available"] and "Docker" in nosbx["modes"]["verify"]["reason"]
    monkeypatch.setenv("AGENT_WRITE_TOKEN", "x" * 20)
    assert make().req("GET", "/api/capabilities")[2]["modes"]["open-pr"]["available"]


def test_unavailable_or_unknown_mode_rejected(make, demo, monkeypatch):
    monkeypatch.delenv("AGENT_WRITE_TOKEN", raising=False)
    c = make()
    assert c.req("POST", "/api/notice", body={"repo_url": str(demo), "mode": "open-pr"})[0] == 400
    assert c.req("POST", "/api/notice", body={"repo_url": str(demo), "mode": "destroy"})[0] == 400
    assert make(allow_unsafe_local=False).req("POST", "/api/notice", body={"repo_url": str(demo), "mode": "verify"})[0] == 400


# ---- notice and consent ------------------------------------------------------------------------------
def test_notice_endpoint(make, demo):
    st, _, j = make().req("POST", "/api/notice", body={"repo_url": str(demo), "mode": "verify"})
    assert st == 200 and j["slug"] == "demo-shop" and j["scopes"] == ["read", "execute"] and j["trust"] == "trusted"
    assert "ACCESS NOTICE" in j["notice"] and "execute" in j["scope_text"]


@pytest.mark.parametrize("confirm", ["", "yes", "y", "demo", "Demo-Shop2", None, 5])
def test_wrong_confirmation_creates_no_job(make, demo, confirm):
    c = make()
    st, _, j = c.req("POST", "/api/jobs", body={"repo_url": str(demo), "mode": "analyze", "confirm": confirm})
    assert st == 403 and "not confirmed" in j["error"] and c.app.jobs.jobs == {}


def test_untrusted_repo_cannot_run_tests_without_docker(make, demo, monkeypatch):
    monkeypatch.setattr(C, "fetch_repo_info", lambda ref, token=None, timeout=10: UNTRUSTED)
    c = make()
    st, _, j = c.req("POST", "/api/jobs", body={"repo_url": str(demo), "mode": "verify", "confirm": "demo-shop"})
    assert st == 403 and "untrusted" in j["error"] and c.app.jobs.jobs == {}
    assert c.req("POST", "/api/notice", body={"repo_url": str(demo), "mode": "analyze"})[0] == 200      # analyze is fine


# ---- real jobs ---------------------------------------------------------------------------------------
def test_analyze_job_end_to_end(make, demo):
    c = make()
    st, _, j = c.req("POST", "/api/jobs", body={"repo_url": str(demo), "mode": "analyze", "confirm": "DEMO-SHOP"})
    assert st == 202
    job = c.wait(j["id"])
    assert job["state"] == "done", job
    s = job["summary"]
    assert s["counts"]["dead_code"] == 4 and s["counts"]["dead_code_high"] == 2 and s["counts"]["secrets"] == 1
    assert s["consent"]["method"] == "web" and s["consent"]["granted_by"].startswith("web-ui@") and s["consent"]["scopes"] == ["read"]
    assert job["stages"]["consent"] == "done" and job["stages"]["analyze"] == "done" and set(job["stages"]) == set(STAGES)
    assert not s["has_patch"] and s["change_sets"] == []
    st, r, report = c.req("GET", f"/api/jobs/{job['id']}/report")
    assert st == 200 and "## Authorisation" in report and "text/plain" in r.getheader("Content-Type")
    assert c.req("GET", f"/api/jobs/{job['id']}/patch")[0] == 404 and c.req("GET", f"/api/jobs/{job['id']}/pr")[0] == 404


def test_verify_job_generates_the_code_change(make, demo):
    c = make()
    j = c.req("POST", "/api/jobs", body={"repo_url": str(demo), "mode": "verify", "confirm": "demo-shop"})[2]
    job = c.wait(j["id"])
    assert job["state"] == "done", job
    cs = job["summary"]["change_sets"][0]
    assert cs["decision"] == "ready" and all(g["passed"] for g in cs["gates"]) and job["summary"]["baseline"]["green"]
    assert {f["symbol"] for f in cs["findings"]} == {"_legacy_discount", "_unused_helper"}
    st, r, patch = c.req("GET", f"/api/jobs/{job['id']}/patch")
    assert st == 200 and "-def _legacy_discount" in patch and "-def _unused_helper" in patch and "_handle_refund" not in patch
    assert "attachment" not in (r.getheader("Content-Disposition") or "") and ".diff" in r.getheader("Content-Disposition")
    pr = c.req("GET", f"/api/jobs/{job['id']}/pr")[2]
    assert "authorised by **web-ui@" in pr and "READY" not in pr
    # the demo repository itself was not modified
    import subprocess
    assert subprocess.run(["git", "status", "--porcelain"], cwd=demo, capture_output=True, text=True).stdout.strip() == ""


# ---- job manager controls -----------------------------------------------------------------------------
def fake_runner_factory(gate=None):
    def runner(job, cfg, record):
        if gate is not None:
            gate.wait(30)
        job.state = "done"
    return runner


def test_one_job_at_a_time_and_rate_limit(make, demo):
    gate = threading.Event()
    c = make(runner=fake_runner_factory(gate))
    body = {"repo_url": str(demo), "mode": "analyze", "confirm": "demo-shop"}
    first = c.req("POST", "/api/jobs", body=body)
    assert first[0] == 202
    st, _, j = c.req("POST", "/api/jobs", body=body)
    assert st == 429 and "running" in j["error"]
    gate.set()
    c.wait(first[2]["id"])
    c2 = make(runner=fake_runner_factory(), max_jobs_per_hour=2)
    for _ in range(2):
        r = c2.req("POST", "/api/jobs", body=body)
        assert r[0] == 202
        c2.wait(r[2]["id"])
    st, _, j = c2.req("POST", "/api/jobs", body=body)
    assert st == 429 and "rate limit" in j["error"]


def test_job_ids_and_artifact_paths_are_not_traversable(make, demo):
    c = make(runner=fake_runner_factory())
    for bad in ("/api/jobs/../../etc/passwd", "/api/jobs/zzzzzzzzzzzz", "/api/jobs/..%2f..%2fetc", "/api/jobs/0123456789ab/report",
                "/api/jobs/0123456789ab/../x", "/api/jobs/ABCDEF123456"):
        assert c.req("GET", bad)[0] == 404, bad
    jid = c.req("POST", "/api/jobs", body={"repo_url": str(demo), "mode": "analyze", "confirm": "demo-shop"})[2]["id"]
    c.wait(jid)
    assert c.req("GET", f"/api/jobs/{jid}/evil")[0] == 404 and c.req("GET", f"/api/jobs/{jid}/report")[0] == 404   # no run_dir yet


def test_old_jobs_are_pruned(make, demo):
    c = make(max_kept=1)
    ids = []
    for _ in range(3):
        j = c.req("POST", "/api/jobs", body={"repo_url": str(demo), "mode": "analyze", "confirm": "demo-shop"})[2]
        c.wait(j["id"])
        ids.append(j["id"])
        time.sleep(0.2)
    assert c.req("GET", f"/api/jobs/{ids[0]}")[0] == 404 and not (c.app.cfg.out_dir / ids[0]).exists()
    assert c.req("GET", f"/api/jobs/{ids[-1]}")[0] == 200


def test_runner_crash_marks_job_failed_without_leaking_secrets(make, demo):
    def boom(job, cfg, record):
        raise RuntimeError("token ghp_" + "A" * 36)
    c = make(runner=boom)
    jid = c.req("POST", "/api/jobs", body={"repo_url": str(demo), "mode": "analyze", "confirm": "demo-shop"})[2]["id"]
    job = c.wait(jid)
    assert job["state"] == "failed" and "AAAA" not in job["error"] and "REDACTED" in job["error"]


def test_sandbox_image_is_picked_from_the_build_tool():
    from agent.sandbox import pick_image
    assert pick_image("maven", "21") == "maven:3.9-eclipse-temurin-21"
    assert pick_image("gradle", "17") == "gradle:8-jdk17"
    assert pick_image("pytest") == "maintenance-agent-sandbox:latest" and pick_image("") == "maintenance-agent-sandbox:latest"
