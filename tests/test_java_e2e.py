"""End-to-end Java: real javac + JUnit4 through Ant (the sandbox is the local fallback)."""
import shutil
import subprocess
from pathlib import Path

import pytest

from agent.analyzers.javacode import available
from agent.audit import AuditLog
from agent.consent import grant_all
from agent.demo import ANT_BUILD, create_java_demo_repo
from agent.orchestrator import Orchestrator, RunOptions

pytestmark = pytest.mark.skipif(not (available() and shutil.which("ant") and shutil.which("javac")
                                     and Path("/usr/share/java/junit4.jar").exists()),
                                reason="needs JDK, Ant and Ubuntu junit4 jars")
ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin"}


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, env=ENV, check=True).stdout.strip()


def run(repo, out, **kw):
    orch = Orchestrator(RunOptions(repo=str(repo), out_dir=out, sandbox="local", allow_unsafe_local=True,
                                   consent=grant_all(str(repo)), **kw))
    return orch, orch.run()


def commit_all(repo, msg="x"):
    git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", msg)


def test_java_happy_path(tmp_path):
    repo = create_java_demo_repo(tmp_path / "j", "ant")
    head = git(repo, "rev-parse", "main")
    orch, st = run(repo, tmp_path / "out", open_pr=True)
    assert st["status"] == "completed" and st["languages"] == ["java"]
    assert st["baseline"]["green"] and st["baseline"]["passed"] == 5
    cs = st["change_sets"][0]
    assert cs["decision"] == "ready" and all(g["passed"] for g in cs["gates"])
    assert {f["symbol"] for f in cs["findings"]} == {"Pricing.legacyDiscount", "Utils.cache", "Utils.unusedHelper"}
    assert git(repo, "rev-parse", "main") == head
    br = cs["branch"]["branch"]
    utils = git(repo, "show", f"{br}:src/main/java/com/shop/Utils.java")
    disp = git(repo, "show", f"{br}:src/main/java/com/shop/Dispatcher.java")
    assert "unusedHelper" not in utils and "registry" in utils and "handleRefund" in disp
    # independent proof: the PR branch really compiles and passes with a fresh checkout
    chk = tmp_path / "verify"
    git(tmp_path, "clone", "-q", str(repo), str(chk)); git(chk, "checkout", "-q", br)
    done = subprocess.run(["ant", "-q", "test"], cwd=chk, capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    assert AuditLog.verify(orch.out / "audit.jsonl")


def test_java_gates_catch_removal_that_breaks_a_test(tmp_path):
    """A private method invoked reflectively from a TEST file with a computed name: static analysis says 'dead'."""
    repo = create_java_demo_repo(tmp_path / "j", "ant")
    (repo / "src/main/java/com/shop/Secret.java").write_text(
        "package com.shop;\npublic class Secret {\n    private static int hidden() {\n        return 42;\n    }\n}\n")
    (repo / "src/test/java/com/shop/SecretTest.java").write_text(
        "package com.shop;\nimport static org.junit.Assert.assertEquals;\nimport org.junit.Test;\n"
        "public class SecretTest {\n    @Test public void viaReflection() throws Exception {\n"
        "        java.lang.reflect.Method m = Secret.class.getDeclaredMethod(\"hid\" + \"den\");\n"
        "        m.setAccessible(true);\n        assertEquals(42, m.invoke(null));\n    }\n}\n")
    commit_all(repo)
    _, st = run(repo, tmp_path / "out", open_pr=True)
    cs = st["change_sets"][0]
    assert cs["decision"] == "rejected_gates"
    failing = [g for g in cs["gates"] if not g["passed"]]
    assert [g["name"] for g in failing] == ["tests: no regressions"]            # exactly the test gate tripped
    assert "SecretTest::viaReflection: passed -> error" in failing[0]["detail"]  # and it names the broken test
    assert "agent/" not in git(repo, "branch", "-a")                              # nothing was pushed


def test_java_field_read_reflectively_from_a_test_is_caught(tmp_path):
    """Field 'cache' looks dead statically; a test reads it via a computed name. Gate must reject."""
    repo = create_java_demo_repo(tmp_path / "j", "ant")
    (repo / "src/test/java/com/shop/CacheTest.java").write_text(
        "package com.shop;\nimport org.junit.Test;\npublic class CacheTest {\n    @Test public void t() throws Exception {\n"
        "        Utils.class.getDeclaredField(\"ca\" + \"che\");\n    }\n}\n")
    commit_all(repo)
    _, st = run(repo, tmp_path / "out", open_pr=True)
    cs = st["change_sets"][0]
    assert cs["decision"] == "rejected_gates"
    assert any("CacheTest" in g["detail"] for g in cs["gates"] if not g["passed"])
    assert "agent/" not in git(repo, "branch", "-a")


def test_preshipped_fake_report_cannot_fake_a_green_baseline(tmp_path):
    repo = create_java_demo_repo(tmp_path / "j", "ant")
    (repo / "src/main/java/com/shop/Pricing.java").write_text("package com.shop;\npublic class Pricing { this does not compile }\n")
    rep = repo / "build" / "reports"; rep.mkdir(parents=True)
    (rep / "TEST-com.shop.ShopTest.xml").write_text(
        '<testsuite><testcase classname="com.shop.ShopTest" name="discount"/></testsuite>')
    git(repo, "add", "-Af"); git(repo, "commit", "-q", "-m", "broken")
    _, st = run(repo, tmp_path / "out", open_pr=True)
    assert st["baseline"]["green"] is False and st["change_sets"] == []


def test_java_changes_not_attempted_when_only_python_tests_verify(tmp_path):
    repo = create_java_demo_repo(tmp_path / "j", "ant")
    (repo / ".agent.yml").write_text(
        "languages: [java]\ntest:\n  command: [python, -m, pytest, -q, -p, no:cacheprovider]\n")
    (repo / "test_dummy.py").write_text("def test_ok():\n    assert True\n")
    commit_all(repo)
    _, st = run(repo, tmp_path / "out", open_pr=True)
    assert st["change_sets"] == [] and any("only verifies" in n for n in st["notes"])
    assert "agent/" not in git(repo, "branch", "-a")


def test_malicious_java_test_cannot_see_credentials_or_network(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_WRITE_TOKEN", "ghp_" + "A" * 36)
    repo = create_java_demo_repo(tmp_path / "j", "ant")
    (repo / "src/test/java/com/shop/EnvTest.java").write_text(
        "package com.shop;\nimport static org.junit.Assert.*;\nimport org.junit.Test;\n"
        "public class EnvTest {\n    @Test public void noSecrets() {\n"
        "        assertNull(System.getenv(\"AGENT_WRITE_TOKEN\"));\n    }\n"
        "    @Test public void noNetwork() {\n        try { new java.net.Socket(\"1.1.1.1\", 53); fail(\"reached network\"); }\n"
        "        catch (java.io.IOException expected) { }\n    }\n}\n")
    commit_all(repo)
    _, st = run(repo, tmp_path / "out")
    if not st["sandbox"]["network_isolated"]:
        pytest.skip("network namespace isolation unavailable")
    assert st["baseline"]["green"] is True and st["baseline"]["passed"] == 7, st["baseline"]
