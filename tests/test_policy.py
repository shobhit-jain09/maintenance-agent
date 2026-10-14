import pytest

from agent.config import AgentConfig
from agent.policy import PolicyEngine


def patch(path, added=(), removed=(), extra_header=""):
    body = "".join(f"-{l}\n" for l in removed) + "".join(f"+{l}\n" for l in added)
    return (f"diff --git a/{path} b/{path}\n{extra_header}index 1..2 100644\n--- a/{path}\n+++ b/{path}\n@@ -1,3 +1,3 @@\n{body}")


@pytest.fixture
def pe():
    return PolicyEngine()


def test_clean_removal_allowed(pe):
    assert pe.check_patch(patch("shop/pricing.py", removed=["def _x(): pass"]))


@pytest.mark.parametrize("path", [
    ".github/workflows/ci.yml", "Dockerfile", "Makefile", "package.json", "requirements.txt",
    "tests/test_a.py", "pkg/test_b.py", "conftest.py", "sub/conftest.py", ".agent.yml", "CODEOWNERS",
    "infra/main.tf", "deploy/x.yml", ".env", "pyproject.toml"])
def test_protected_paths_denied(pe, path):
    d = pe.check_patch(patch(path, removed=["x"]))
    assert not d and any("protected path" in r for r in d.reasons)


def test_forbidden_pattern_in_added_line(pe):
    d = pe.check_patch(patch("shop/a.py", added=["import subprocess"]))
    assert not d


def test_new_url_forbidden(pe):
    assert not pe.check_patch(patch("shop/a.py", added=["X = 'https://evil.example'"]))


def test_secret_in_added_line(pe):
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    assert not pe.check_patch(patch("shop/a.py", added=[f"K = '{key}'"]))


def test_binary_and_mode_change_denied(pe):
    assert not pe.check_patch("diff --git a/a.py b/a.py\nBinary files a/a.py and b/a.py differ\n")
    assert not pe.check_patch(patch("run.sh", removed=["x"], extra_header="old mode 100644\nnew mode 100755\n"))


def test_new_file_and_rename_denied(pe):
    assert not pe.check_patch("diff --git a/n.py b/n.py\nnew file mode 100644\n--- /dev/null\n+++ b/n.py\n@@ -0,0 +1 @@\n+x = 1\n")
    assert not pe.check_patch("diff --git a/a.py b/b.py\nsimilarity index 100%\nrename from a.py\nrename to b.py\n")


def test_size_limits(pe):
    assert not pe.check_patch(patch("shop/a.py", removed=[f"l{i}" for i in range(400)]))


def test_empty_patch_denied(pe):
    assert not pe.check_patch("   \n")


@pytest.mark.parametrize("branch,ok", [
    ("agent/dead-code/20260101-abc123", True), ("main", False), ("agent/dead-code/x", False),
    ("feature/foo", False), ("agent/../main", False), ("release/1.0", False)])
def test_branch_policy(pe, branch, ok):
    assert bool(pe.check_branch(branch)) is ok


@pytest.mark.parametrize("path,ok", [
    ("shop/a.py", True), (".env", False), ("config/.env.local", False), ("keys/id_rsa", False),
    ("../etc/passwd", False), ("/etc/passwd", False), ("a/secrets/token.txt", False)])
def test_read_policy(pe, path, ok):
    assert bool(pe.check_read(path)) is ok


def test_command_policy(pe):
    assert pe.check_command(["python", "-m", "pytest"])
    assert not pe.check_command(["curl", "https://x"])
    assert not pe.check_command(["python", "-c", "x; rm -rf /"])
    assert not pe.check_command(["bash", "-c", "ls"])


def test_repo_config_can_only_tighten():
    cfg = AgentConfig.from_dict({"protected_modules": ["src/legacy/**"]})
    pe = PolicyEngine(repo_protected=cfg.protected_modules, repo_max_changed_lines=10)
    assert not pe.check_patch(patch("src/legacy/a.py", removed=["x"]))
    assert not pe.check_patch(patch("src/b.py", removed=[f"l{i}" for i in range(20)]))
    # a repo cannot un-protect anything: policy has no hook to remove entries
    assert not PolicyEngine(repo_protected=[]).check_patch(patch(".github/workflows/ci.yml", removed=["x"]))
