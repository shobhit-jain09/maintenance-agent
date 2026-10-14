"""Consent gate: nothing is accessed until a person authorises exactly that, for exactly this repo."""
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from agent import consent as C
from agent import gitops
from agent.audit import AuditLog
from agent.cli import main
from agent.consent import ConsentError, RepoInfo, parse_repo_ref
from agent.demo import create_demo_repo
from agent.orchestrator import Orchestrator, RunOptions

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
TRUSTED = RepoInfo(source="github_api", visibility="private", trust="trusted", trust_reason="your token has write access")
UNTRUSTED = RepoInfo(source="github_api", visibility="public", trust="untrusted", trust_reason="no write access")
REF = parse_repo_ref("https://github.com/acme/shop.git")


# ---- repository URL guardrails ----------------------------------------------------------------
@pytest.mark.parametrize("value,slug", [
    ("https://github.com/acme/shop", "acme/shop"), ("https://github.com/acme/shop.git", "acme/shop"),
    ("https://GitHub.com/acme/shop/", "acme/shop"), ("https://github.com/acme/my.repo-1_x", "acme/my.repo-1_x")])
def test_valid_urls(value, slug):
    r = parse_repo_ref(value)
    assert r.slug == slug and r.kind == "url" and r.clone_url == f"https://github.com/{slug}.git"


@pytest.mark.parametrize("value", [
    "", "   ", "--upload-pack=touch /tmp/x", "-c core.sshCommand=evil", "ext::sh -c id", "ext::sh%20-c%20id",
    "http://github.com/a/b", "ssh://git@github.com/a/b", "git://github.com/a/b", "file:///etc/passwd",
    "https://user:tok@github.com/a/b", "https://tok@github.com/a/b", "https://evil.example/a/b",
    "https://github.com/a/b?x=1", "https://github.com/a/b#frag", "https://github.com:444/a/b", "https://github.com/a",
    "https://github.com/../b", "https://github.com/a/b c", "https://github.com/a/b\nx", "/definitely/not/here", "a/b"])
def test_hostile_or_malformed_values_rejected(value):
    with pytest.raises(ConsentError):
        parse_repo_ref(value)


def test_host_allowlist_is_configurable():
    assert parse_repo_ref("https://git.corp.example/a/b", ["git.corp.example"]).host == "git.corp.example"
    with pytest.raises(ConsentError):
        parse_repo_ref("https://gitlab.com/a/b")


def test_local_directory_ref(tmp_path):
    r = parse_repo_ref(str(tmp_path))
    assert r.kind == "local" and r.path == tmp_path.resolve() and r.canonical.startswith("local:")


def test_clone_treats_option_like_value_as_data_not_a_flag(tmp_path):
    marker = tmp_path / "pwned"
    with pytest.raises(gitops.GitError):
        gitops.clone(f"--upload-pack=touch {marker}", tmp_path / "d")
    assert not marker.exists()


def test_clone_blocks_exotic_transports(tmp_path):
    marker = tmp_path / "pwned"
    with pytest.raises(gitops.GitError):
        gitops.clone(f"ext::sh -c touch% {marker}", tmp_path / "d")
    assert not marker.exists()


# ---- scopes ------------------------------------------------------------------------------------
def test_needed_scopes():
    assert C.needed_scopes(False, False, False) == ["read"]
    assert C.needed_scopes(True, False, False) == ["read", "execute"]
    assert C.needed_scopes(True, True, True) == ["read", "execute", "llm", "write"]


# ---- one-run consent by flag --------------------------------------------------------------------
def test_flag_consent_ok_case_insensitive():
    rec, notice = C.obtain_consent(REF, ["read", "execute"], TRUSTED, consent_flag="ACME/Shop:execute,read", now=NOW)
    assert rec.method == "flag" and rec.scopes == ["read", "execute"] and rec.repo == "github.com/acme/shop"
    assert "ACCESS NOTICE" in notice and "RUN the repository's own tests" in notice


@pytest.mark.parametrize("flag,why", [
    ("acme/other:read", "names"), ("acme/shop:read", "needs permission"), ("acme/shop", "must look like"),
    ("acme/shop:read,hack", "unknown scope"), ("acme/shop:", "needs permission")])
def test_flag_consent_refusals(flag, why):
    with pytest.raises(ConsentError, match=why):
        C.obtain_consent(REF, ["read", "execute"], TRUSTED, consent_flag=flag, now=NOW)


def test_no_consent_means_refusal_with_instructions():
    with pytest.raises(ConsentError, match="consent required"):
        C.obtain_consent(REF, ["read"], TRUSTED, now=NOW)


# ---- interactive: type the repo name -------------------------------------------------------------
def test_interactive_requires_typing_the_repo_name():
    ok, _ = C.obtain_consent(REF, ["read"], TRUSTED, interactive=True, input_fn=lambda _: "acme/shop",
                             print_fn=lambda _: None, isatty=lambda: True, now=NOW)
    assert ok.method == "interactive"
    for wrong in ("y", "yes", "", "acme", "acme/shop2"):
        with pytest.raises(ConsentError, match="not confirmed"):
            C.obtain_consent(REF, ["read"], TRUSTED, interactive=True, input_fn=lambda _, w=wrong: w,
                             print_fn=lambda _: None, isatty=lambda: True, now=NOW)


def test_interactive_without_a_terminal_refuses_instead_of_hanging():
    with pytest.raises(ConsentError, match="not an interactive terminal"):
        C.obtain_consent(REF, ["read"], TRUSTED, interactive=True, isatty=lambda: False, now=NOW)


# ---- standing consent file ----------------------------------------------------------------------
def write_file(tmp_path, **over):
    body = {"repo": "acme/shop", "scopes": ["read", "execute"], "granted_by": "alice@example.com",
            "granted_at": "2026-10-01", "expires_at": "2026-10-31", "notice_version": C.NOTICE_VERSION} | over
    p = tmp_path / "c.yml"
    p.write_text(yaml.safe_dump({k: v for k, v in body.items() if v is not None}))
    return p


def test_standing_file_ok(tmp_path):
    rec, _ = C.obtain_consent(REF, ["read", "execute"], TRUSTED, consent_file=str(write_file(tmp_path)), now=NOW)
    assert rec.method == "file" and rec.granted_by == "alice@example.com" and rec.expires_at.startswith("2026-10-31")


@pytest.mark.parametrize("over,why", [
    ({"expires_at": "2026-10-05"}, "expired"), ({"expires_at": "2027-06-01"}, "at most"),
    ({"repo": "acme/other"}, "is for"), ({"notice_version": "0"}, "notice version"),
    ({"granted_by": ""}, "who granted"), ({"granted_by": None}, "who granted"),
    ({"granted_at": "2026-12-01", "expires_at": "2026-12-20"}, "future"), ({"scopes": ["read"]}, "not in the consent file"),
    ({"scopes": ["read", "root"]}, "invalid scopes"), ({"expires_at": None}, "invalid")])
def test_standing_file_refusals(tmp_path, over, why):
    with pytest.raises(ConsentError, match=why):
        C.obtain_consent(REF, ["read", "execute"], TRUSTED, consent_file=str(write_file(tmp_path, **over)), now=NOW)


def test_file_cannot_assert_its_own_trust(tmp_path):
    p = write_file(tmp_path, trust="trusted", scopes=["read"])
    rec, _ = C.obtain_consent(REF, ["read"], UNTRUSTED, consent_file=str(p), now=NOW)
    assert rec.trust == "untrusted"


def test_consent_file_inside_the_analysed_repo_is_refused(tmp_path):
    repo = tmp_path / "victim"
    repo.mkdir()
    (repo / "consent.yml").write_text(yaml.safe_dump({
        "repo": "victim", "scopes": ["read", "execute", "write"], "granted_by": "attacker", "granted_at": "2026-10-09",
        "expires_at": "2026-11-01", "notice_version": C.NOTICE_VERSION}))
    ref = parse_repo_ref(str(repo))
    with pytest.raises(ConsentError, match="inside the repository"):
        C.obtain_consent(ref, ["read"], TRUSTED, consent_file=str(repo / "consent.yml"), now=NOW)


def test_consent_file_symlink_refused(tmp_path):
    real = write_file(tmp_path)
    link = tmp_path / "link.yml"
    link.symlink_to(real)
    with pytest.raises(ConsentError, match="not found"):
        C.obtain_consent(REF, ["read", "execute"], TRUSTED, consent_file=str(link), now=NOW)


# ---- trust ----------------------------------------------------------------------------------------
def test_github_metadata_maps_to_trust():
    owner = C.info_from_github_json({"private": True, "owner": {"login": "me"}, "permissions": {"admin": True, "push": True, "pull": True}})
    third = C.info_from_github_json({"private": False, "license": {"spdx_id": "Apache-2.0"}, "permissions": {"pull": True}})
    none = C.info_from_github_json({"private": False})
    assert owner.trust == "trusted" and owner.visibility == "private"
    assert third.trust == "untrusted" and third.license == "Apache-2.0" and none.trust == "untrusted"


def test_write_cannot_be_granted_on_untrusted_repo():
    with pytest.raises(ConsentError, match="write access cannot be granted"):
        C.obtain_consent(REF, ["read", "execute", "write"], UNTRUSTED, consent_flag="acme/shop:read,execute,write", now=NOW)


def test_notice_states_what_will_and_will_not_happen():
    _, notice = C.obtain_consent(REF, ["read", "execute"], UNTRUSTED, consent_flag="acme/shop:read,execute",
                                 deny_read=[".env*", "*.pem"], now=NOW)
    for must in ("acme/shop", "UNTRUSTED", "READ its source files", "RUN the repository's own tests", "will NOT do",
                 ".env*", "outside the Docker sandbox", "'llm' permission is NOT requested", "METADATA"):
        assert must in notice, must
    assert "[write" not in notice


# ---- the gate inside the orchestrator --------------------------------------------------------------
@pytest.fixture
def demo(tmp_path):
    return create_demo_repo(tmp_path / "demo-shop")


def run_with(repo, tmp_path, **kw):
    orch = Orchestrator(RunOptions(repo=str(repo), out_dir=tmp_path / "out", sandbox="local", allow_unsafe_local=True, **kw))
    return orch, orch.run()


def test_without_consent_nothing_is_cloned_or_read(demo, tmp_path):
    orch, st = run_with(demo, tmp_path)
    assert st["status"].startswith("refused: consent required")
    assert not orch.work.exists()                                 # not even a clone happened
    assert st["consent"] is None and st["scan"]["files_scanned"] == 0 and st["findings"]["dead_code"] == []
    assert "No consent was recorded" in (orch.out / "report.md").read_text()
    events = [json.loads(l)["event"] for l in (orch.out / "audit.jsonl").read_text().splitlines()]
    assert "consent_refused" in events and "intake" not in events


def test_consent_for_another_repo_is_refused(demo, tmp_path):
    other = create_demo_repo(tmp_path / "other-shop")
    _, st = run_with(demo, tmp_path, consent=C.grant_all(str(other)))
    assert st["status"].startswith("refused") and "not" in st["status"] and st["scan"]["files_scanned"] == 0


def test_expired_record_refused(demo, tmp_path):
    rec = C.grant_all(str(demo))
    rec.expires_at = (NOW - timedelta(days=1)).isoformat()
    _, st = run_with(demo, tmp_path, consent=rec)
    assert st["status"].startswith("refused") and "expired" in st["status"]


def test_scope_missing_for_the_requested_action_is_refused(demo, tmp_path):
    rec = C.grant_all(str(demo))
    rec.scopes = ["read"]
    _, st = run_with(demo, tmp_path, consent=rec, run_tests=True)       # tests need 'execute'
    assert st["status"].startswith("refused") and "execute" in st["status"] and st["baseline"] is None
    _, st = run_with(demo, tmp_path, consent=rec, run_tests=False, open_pr=True)   # PR needs 'write'
    assert st["status"].startswith("refused") and "write" in st["status"]


def test_read_only_consent_runs_analysis_only(demo, tmp_path):
    rec = C.grant_all(str(demo))
    rec.scopes = ["read"]
    orch, st = run_with(demo, tmp_path, consent=rec, run_tests=False)
    assert st["status"] == "completed" and st["baseline"] is None and st["change_sets"] == []
    assert st["consent"]["scopes"] == ["read"]


def test_defence_in_depth_each_action_rechecks_its_scope(demo, tmp_path):
    rec = C.grant_all(str(demo))
    rec.scopes = ["read"]
    orch, st = run_with(demo, tmp_path, consent=rec, run_tests=False)
    for scope in ("execute", "llm", "write"):
        with pytest.raises(ConsentError):
            orch._require(scope)
    orch.consent_rec = None
    with pytest.raises(ConsentError):
        orch._require("read")


def test_untrusted_repo_tests_never_run_in_the_local_fallback(demo, tmp_path, monkeypatch):
    monkeypatch.setattr(C, "fetch_repo_info", lambda ref, token=None, timeout=10: UNTRUSTED)
    rec = C.grant_all(str(demo))
    rec.scopes = ["read", "execute"]
    orch, st = run_with(demo, tmp_path, consent=rec)
    assert st["status"].startswith("refused") and "untrusted" in st["status"] and "Docker" in st["status"]
    assert st["baseline"] is None and st["change_sets"] == []


def test_untrusted_repo_cannot_get_write_even_with_a_matching_record(demo, tmp_path, monkeypatch):
    monkeypatch.setattr(C, "fetch_repo_info", lambda ref, token=None, timeout=10: UNTRUSTED)
    _, st = run_with(demo, tmp_path, consent=C.grant_all(str(demo)), open_pr=True)
    assert st["status"].startswith("refused") and "write access cannot be granted" in st["status"]


def test_consent_is_recorded_in_artifacts_audit_report_and_pr(demo, tmp_path):
    orch, st = run_with(demo, tmp_path, consent=C.grant_all(str(demo), who="alice"), open_pr=True)
    assert st["status"] == "completed" and st["change_sets"][0]["decision"] == "ready"
    saved = json.loads((orch.out / "consent.json").read_text())
    assert saved["granted_by"] == "alice" and saved["scopes"] == ["read", "execute", "llm", "write"] and saved["trust"] == "trusted"
    assert (orch.out / "consent_notice.txt").exists()
    assert "## Authorisation" in (orch.out / "report.md").read_text()
    assert "authorised by **alice**" in (orch.out / "pr" / "CS-001.md").read_text()
    log = [json.loads(l) for l in (orch.out / "audit.jsonl").read_text().splitlines()]
    granted = [e for e in log if e["event"] == "consent_granted"]
    assert granted and granted[0]["data"]["by"] == "alice"
    assert [e["event"] for e in log].index("consent_granted") < [e["event"] for e in log].index("intake")
    assert AuditLog.verify(orch.out / "audit.jsonl")


# ---- command line -------------------------------------------------------------------------------
def test_cli_refuses_without_consent_exit_code_3(demo, tmp_path, capsys):
    assert main(["analyze", str(demo), "--out", str(tmp_path / "o")]) == 3
    assert "refused" in capsys.readouterr().out


def test_cli_flag_consent_and_standing_file_roundtrip(demo, tmp_path, capsys):
    assert main(["analyze", str(demo), "--out", str(tmp_path / "o1"), "--consent", "demo-shop:read"]) == 0
    cfile = tmp_path / "consents" / "demo.yml"
    assert main(["consent", "grant", str(demo), "--scopes", "read", "--days", "7", "--confirm", "demo-shop", "--out", str(cfile)]) == 0
    assert cfile.exists() and "expires_at" in cfile.read_text()
    assert main(["analyze", str(demo), "--out", str(tmp_path / "o2"), "--consent-file", str(cfile)]) == 0
    out = capsys.readouterr().out
    assert "completed" in out
    rec = json.loads(next((tmp_path / "o2").glob("*/consent.json")).read_text())
    assert rec["method"] == "file"


def test_cli_grant_needs_the_exact_name_and_refuses_write_on_untrusted(demo, tmp_path, monkeypatch):
    assert main(["consent", "grant", str(demo), "--confirm", "yes", "--out", str(tmp_path / "x.yml")]) == 3
    assert not (tmp_path / "x.yml").exists()
    monkeypatch.setattr(C, "fetch_repo_info", lambda ref, token=None, timeout=10: UNTRUSTED)
    assert main(["consent", "grant", str(demo), "--scopes", "read,write", "--confirm", "demo-shop", "--out", str(tmp_path / "y.yml")]) == 3
    assert main(["consent", "grant", str(demo), "--days", "400", "--confirm", "demo-shop", "--out", str(tmp_path / "z.yml")]) == 3
    assert not (tmp_path / "y.yml").exists() and not (tmp_path / "z.yml").exists()


def test_cli_notice_grants_nothing(demo, tmp_path, capsys):
    assert main(["consent", "notice", str(demo), "--scopes", "read,execute"]) == 0
    out = capsys.readouterr().out
    assert "ACCESS NOTICE" in out and "PREVIEW ONLY" in out


def test_cli_resolve_prints_slug_and_rejects_hostile_values(capsys):
    assert main(["consent", "resolve", "https://github.com/Acme/Shop.git"]) == 0
    assert capsys.readouterr().out.strip() == "Acme/Shop"
    for bad in ("https://u:tok@github.com/a/b", "https://evil.example/a/b", "http://github.com/a/b", "/no/such/dir"):
        assert main(["consent", "resolve", bad]) == 3
    assert main(["consent", "resolve", "--", "--upload-pack=x"]) == 3        # the workflow passes '--' first


def test_cli_trust_reports_trusted_or_untrusted(capsys, monkeypatch):
    monkeypatch.setattr(C, "fetch_repo_info", lambda ref, token=None, timeout=10: TRUSTED)
    assert main(["consent", "trust", "https://github.com/a/b"]) == 0
    assert capsys.readouterr().out.strip() == "trusted"
    monkeypatch.setattr(C, "fetch_repo_info", lambda ref, token=None, timeout=10: UNTRUSTED)
    assert main(["consent", "trust", "https://github.com/a/b"]) == 0
    assert capsys.readouterr().out.strip() == "untrusted"
