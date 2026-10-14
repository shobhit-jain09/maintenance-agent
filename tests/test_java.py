"""Java support: analyser rules, patcher, config detection, report parsing."""
import subprocess

import pytest

from agent.analyzers.javacode import analyze_java_dead_code, available, is_java_test_file
from agent.analyzers.findings import Finding
from agent.config import AgentConfig
from agent.patcher import build_dead_code_patch
from agent.testrun import clean_reports, find_reports, parse_junit

pytestmark = pytest.mark.skipif(not available(), reason="tree-sitter-java not installed")


def write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def analyse(root):
    files = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    java = [f for f in files if f.endswith(".java")]
    res, failed, _ = analyze_java_dead_code(root, java, files)
    return {f.symbol: f for f in res}, failed


def test_tiers_and_traps(tmp_path):
    write(tmp_path, {
        "src/main/java/p/A.java": """package p;
import java.io.Serializable;
public class A implements Serializable {
    private static final long serialVersionUID = 1L;
    private void readObject(java.io.ObjectInputStream in) {}
    private int deadField = 3;
    private final Object sideEffect = new Object();
    private int a, b;
    private void deadPrivate() { }
    private void usedPrivate() { }
    @Deprecated private void deprecatedDead() { }
    @Registered private void wired() { }
    public void publicDead() { }
    protected void protDead() { }
    @Override public String toString() { return "A"; }
    private static class DeadNested { }
    private static class UsedNested { }
    public void go() { usedPrivate(); new UsedNested(); }
    private A() { }
    public static void main(String[] args) { }
}
@interface Registered { }
""",
        "src/main/java/p/B.java": "package p;\npublic class B { void m() { new A(); } }\n",
    })
    d, failed = analyse(tmp_path)
    assert not failed
    assert d["A.deadField"].confidence == "high"
    assert d["A.deadPrivate"].confidence == "high"
    assert d["A.deprecatedDead"].confidence == "high"          # @Deprecated is a safe annotation
    assert d["A.DeadNested"].confidence == "high"
    assert d["A.wired"].confidence == "low"                    # custom annotation => possible wiring
    assert d["A.publicDead"].confidence == "low"               # class implements a type => may be interface impl
    assert d["A.go"].confidence == "low"                       # reported, but never auto-removed
    assert d["A.sideEffect"].confidence == "medium"            # initialiser has side effects
    assert d["A.a"].confidence == "medium" and d["A.b"].confidence == "medium"   # multi-declarator
    for never in ("A.usedPrivate", "A.UsedNested", "A.toString", "A.readObject", "A.serialVersionUID", "A.main"):
        assert never not in d


def test_override_interface_and_abstract_never_flagged(tmp_path):
    write(tmp_path, {"src/main/java/p/I.java": "package p;\npublic interface I { void run(); default void d() {} }\n",
                     "src/main/java/p/C.java": "package p;\npublic abstract class C { abstract void hook(); }\n"})
    d, _ = analyse(tmp_path)
    assert "I.run" not in d and "I.d" not in d and "C.hook" not in d


def test_reflection_in_file_caps_confidence(tmp_path):
    write(tmp_path, {"src/main/java/p/R.java": """package p;
public class R {
    public Object call(String n) throws Exception { return getClass().getDeclaredMethod("do" + n).invoke(this); }

    private void doIt() {
    }
}
""", "src/main/java/p/UseR.java": "package p;\npublic class UseR { Object x() throws Exception { return new R().call(\"It\"); } }\n"})
    d, _ = analyse(tmp_path)
    assert d["R.doIt"].confidence == "medium"


def test_string_xml_and_spi_mentions_lower_confidence(tmp_path):
    write(tmp_path, {
        "src/main/java/p/S.java": "package p;\npublic class S {\n    private void viaString() {\n    }\n\n    private void viaXml() {\n    }\n\n"
                                  "    private void plain() {\n    }\n\n    void x() {\n        String s = \"viaString\";\n    }\n}\n",
        "src/main/java/p/UseS.java": "package p;\nclass UseS { void u() { new S().x(); } }\n",
        "src/main/resources/beans.xml": "<bean init-method=\"viaXml\"/>",
        "src/main/java/p/Plugin.java": "package p;\npublic class Plugin { }\n",
        "src/main/resources/META-INF/services/p.Api": "p.Plugin\n",
    })
    d, _ = analyse(tmp_path)
    assert d["S.viaString"].confidence == "low" and d["S.viaXml"].confidence == "low"
    assert d["S.plain"].confidence == "high"
    assert d["Plugin"].confidence in ("low", "medium") and d["Plugin"].confidence != "high"


def test_lombok_style_class_fields_are_low(tmp_path):
    write(tmp_path, {"src/main/java/p/Dto.java": "package p;\n@Data\npublic class Dto {\n    private String name;\n}\n",
                     "src/main/java/p/UseDto.java": "package p;\nclass UseDto { Dto d = new Dto(); }\n"})
    d, _ = analyse(tmp_path)
    assert d["Dto.name"].confidence == "low"


def test_unparseable_file_is_reported_and_references_kept_conservatively(tmp_path):
    write(tmp_path, {"src/main/java/p/Ok.java": "package p;\npublic class Ok { private void maybeUsed() { } }\n",
                     "src/main/java/p/Broken.java": "package p;\npublic class Broken { void m() { maybeUsed( } \n"})
    d, failed = analyse(tmp_path)
    assert failed == ["src/main/java/p/Broken.java"]
    assert "Ok.maybeUsed" not in d        # broken file mentions it, so it is not flagged


def test_test_files_are_not_analysed_but_count_as_references(tmp_path):
    write(tmp_path, {"src/main/java/p/M.java": "package p;\npublic class M {\n    void helperForTests() {\n    }\n\n    private void dead() {\n    }\n}\n",
                     "src/test/java/p/MTest.java": "package p;\nclass MTest {\n    void t() {\n        new M().helperForTests();\n    }\n\n    void orphan() {\n    }\n}\n"})
    d, _ = analyse(tmp_path)
    assert "M.helperForTests" not in d and "MTest.orphan" not in d and d["M.dead"].confidence == "high"
    assert is_java_test_file("src/test/java/p/X.java") and is_java_test_file("p/FooTest.java")


def _git(root):
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin"}
    for c in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "commit", "-q", "-m", "i"]):
        subprocess.run(c, cwd=root, check=True, env=env, capture_output=True)


def test_patcher_removes_javadoc_annotations_and_tidies_blank_lines(tmp_path):
    src = """package p;

public class P {
    public int keep() { return 1; }

    /**
     * Old helper.
     */
    @SuppressWarnings("unused")
    private int dead(int x) {
        return x;
    }

    public int keep2() { return 2; }
}
"""
    write(tmp_path, {"P.java": src, "UseP.java": "class UseP { Object o = new P(); }\n"})
    _git(tmp_path)
    files = ["P.java", "UseP.java"]
    res, _, _ = analyze_java_dead_code(tmp_path, files, files)
    out = build_dead_code_patch(tmp_path, [f for f in res if f.confidence == "high"])
    new = (tmp_path / "P.java").read_text()
    assert "dead" not in new and "Old helper" not in new and "SuppressWarnings" not in new
    assert "keep()" in new and "keep2()" in new
    assert "\n\n\n" not in new and len(out.applied) == 1


def test_patcher_refuses_file_that_already_fails_to_parse(tmp_path):
    write(tmp_path, {"Bad.java": "public class Bad { void m( { }\n"})
    _git(tmp_path)
    f = Finding("DC-1", "dead_code", "high", "Bad.java", 1, 1, "Bad.m", "method")
    res = build_dead_code_patch(tmp_path, [f])
    assert not res.applied and res.patch == ""


# ---- config / runner detection ------------------------------------------------------
def test_build_tool_detection(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>")
    c = AgentConfig(); c.resolve_runtime(tmp_path, ["a/B.java"])
    assert c.build_tool == "maven" and c.test_command[-1] == "test" and "-o" in c.test_command and c.test_covers == ["java"]
    (tmp_path / "pom.xml").unlink(); (tmp_path / "build.gradle").write_text("")
    (tmp_path / "gradlew").write_text("#!/bin/sh")
    c = AgentConfig(); c.resolve_runtime(tmp_path, ["a/B.java"])
    assert c.build_tool == "gradle" and c.test_command[0] == "./gradlew" and "--offline" in c.test_command


def test_mixed_repo_verifies_only_what_it_runs(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>")
    c = AgentConfig(); notes = c.resolve_runtime(tmp_path, ["a/B.java", "x.py"])
    assert c.test_covers == ["java"] and any("mixed repo" in n for n in notes)


def test_python_repo_defaults_unchanged(tmp_path):
    c = AgentConfig(); c.resolve_runtime(tmp_path, ["x.py"])
    assert c.build_tool == "pytest" and c.test_covers == ["python"] and "pytest" in " ".join(c.test_command)


def test_stale_and_preshipped_reports_are_deleted_before_run(tmp_path):
    rep = tmp_path / "target" / "surefire-reports"
    rep.mkdir(parents=True)
    (rep / "TEST-fake.xml").write_text('<testsuite><testcase classname="c" name="fake"/></testsuite>')
    globs = ["**/surefire-reports/TEST-*.xml"]
    assert [p.name for p in find_reports(tmp_path, globs)] == ["TEST-fake.xml"]
    assert clean_reports(tmp_path, globs) == 1 and find_reports(tmp_path, globs) == []


def test_report_symlinks_are_ignored(tmp_path):
    real = tmp_path / "real.xml"
    real.write_text('<testsuite><testcase classname="c" name="n"/></testsuite>')
    d = tmp_path / "build" / "reports"; d.mkdir(parents=True)
    (d / "TEST-x.xml").symlink_to(real)
    assert find_reports(tmp_path, ["build/reports/TEST-*.xml"]) == []


def test_missing_toolchain_gives_a_clear_error(tmp_path):
    import pytest as _pt
    from agent.sandbox import LocalSandbox, SandboxError
    with _pt.raises(SandboxError, match="not found in the sandbox"):
        LocalSandbox(["mvn"]).run(["mvn", "test"], tmp_path, 5)


def test_jvm_uses_the_per_run_home_not_the_hosts(tmp_path):
    """Regression: Java ignores $HOME; without JAVA_TOOL_OPTIONS Maven would read the host's ~/.m2."""
    import shutil as _sh
    if not _sh.which("java"):
        pytest.skip("java not installed")
    from agent.sandbox import LocalSandbox
    home = tmp_path / "h"; home.mkdir()
    r = LocalSandbox(["java"]).run(["java", "-XshowSettings:properties", "-version"], tmp_path, 30, home=home)
    assert f"user.home = {home}" in r.stderr + r.stdout


def test_java_cache_dir_shapes_are_normalised(tmp_path):
    from agent.orchestrator import Orchestrator, RunOptions
    for shape, expect in (("m2", ".m2"), ("gradle", ".gradle"), ("home", ".m2")):
        src = tmp_path / f"src_{shape}"
        if shape == "m2":
            (src / "repository" / "a").mkdir(parents=True)
        elif shape == "gradle":
            (src / "caches" / "x").mkdir(parents=True)
        else:
            (src / ".m2" / "repository").mkdir(parents=True)
        o = Orchestrator(RunOptions(repo="x", out_dir=tmp_path / f"out_{shape}", java_cache=str(src)))
        o.cfg.build_tool, o.cfg.test_command = "maven", ["mvn"]
        o.work.mkdir(parents=True, exist_ok=True)
        o._prefetch()
        assert (o.cache_dir / expect).is_dir(), shape


def test_doctor_runs_and_never_prints_secret_values(capsys, monkeypatch):
    from agent.cli import main
    monkeypatch.setenv("AGENT_WRITE_TOKEN", "ghp_" + "Z" * 36)
    rc = main(["doctor"])
    out = capsys.readouterr().out
    assert rc == 0 and "AGENT_WRITE_TOKEN" in out and "CAN push" in out
    assert "ZZZZ" not in out


def test_docker_sandbox_command_uses_configured_limits(tmp_path, monkeypatch):
    import subprocess as sp
    from agent.sandbox import DockerSandbox
    seen = {}

    def fake_run(cmd, **kw):
        if cmd[0] == "docker" and cmd[1] == "run":
            seen["cmd"] = cmd
        return sp.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr("agent.sandbox.subprocess.run", fake_run)
    home = tmp_path / "h"; home.mkdir()
    DockerSandbox(["mvn"], "img:1", memory="3g", cpus="2").run(["mvn", "test"], tmp_path, 5, home=home)
    c = seen["cmd"]
    assert c[c.index("--memory") + 1] == "3g" and c[c.index("--network") + 1] == "none"
    assert "--cap-drop" in c and "ALL" in c and "--read-only" in c and "65534:65534" in c
    assert any(x.startswith("JAVA_TOOL_OPTIONS=-Duser.home=/home/sandbox") for x in c)   # JVM home pinned
    assert not any("TOKEN" in x for x in c)                                             # no credentials passed
    assert c[-2:] == ["mvn", "test"] and c[-3] == "img:1"
