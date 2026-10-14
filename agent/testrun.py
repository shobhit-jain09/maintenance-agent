"""Run the repo's tests in the sandbox, build a baseline, and evaluate verification gates."""
from __future__ import annotations

import ast
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .config import AgentConfig
from .sandbox import BaseSandbox
from .util import iter_repo_files, match_any, read_text_safe

MAX_JUNIT_BYTES = 5_000_000
PASS, FAIL, ERROR, SKIP = "passed", "failed", "error", "skipped"


@dataclass
class TestRun:
    __test__ = False  # not a pytest class
    index: int
    returncode: int
    outcomes: dict[str, str]
    duration: float
    timed_out: bool
    parse_ok: bool
    isolation: dict = field(default_factory=dict)
    output_tail: str = ""


def parse_junit(path: Path) -> dict[str, str] | None:
    """Parse a JUnit XML file written by untrusted code. Size-capped, DTD/entities refused."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JUNIT_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    head = raw[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in raw.lower():
        return None
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    out: dict[str, str] = {}
    for tc in root.iter("testcase"):
        tid = f"{tc.get('classname', '')}::{tc.get('name', '')}"
        if tc.find("failure") is not None:
            out[tid] = FAIL
        elif tc.find("error") is not None:
            out[tid] = ERROR
        elif tc.find("skipped") is not None:
            out[tid] = SKIP
        else:
            out[tid] = PASS
    return out


def find_reports(workdir: Path, globs: list[str]) -> list[Path]:
    """Locate JUnit XML files the build tool wrote. Walks without following symlinks and does NOT
    apply the analysis ignore list (build/ and target/ are exactly where reports live)."""
    found: list[Path] = []
    root = Path(workdir)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git" and not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if match_any(rel, globs) and not full.is_symlink():
                found.append(full)
    return sorted(found)


def clean_reports(workdir: Path, globs: list[str]) -> int:
    """Delete stale/pre-shipped reports BEFORE a run so old results can never be mistaken for new ones."""
    n = 0
    for f in find_reports(workdir, globs):
        try:
            f.unlink()
            n += 1
        except OSError:
            pass
    return n


def run_tests(sandbox: BaseSandbox, workdir: Path, cfg: AgentConfig, index: int, home: Path | None = None) -> TestRun:
    cmd = list(cfg.test_command or [])
    is_pytest = any("pytest" in part for part in cmd)
    junit_name = f".agent_junit_{index}.xml"
    if is_pytest:
        cmd.append(f"--junitxml={junit_name}")
    else:
        clean_reports(workdir, cfg.test_reports or [])
    res = sandbox.run(cmd, workdir, cfg.test_timeout, home=home)
    outcomes: dict[str, str] | None = None
    if is_pytest:
        outcomes = parse_junit(Path(workdir) / junit_name)
    else:
        reports = find_reports(workdir, cfg.test_reports or [])
        parsed = [parse_junit(r) for r in reports]
        if reports and all(x is not None for x in parsed):
            outcomes = {}
            for x in parsed:
                outcomes.update(x)
    parse_ok = outcomes is not None
    if outcomes is None:
        outcomes = {"__suite__": PASS if res.returncode == 0 and not res.timed_out else FAIL}
    elif outcomes and res.returncode != 0 and not res.timed_out and not any(v in (FAIL, ERROR) for v in outcomes.values()):
        # build tool failed (compile error, plugin error...) even though recorded tests passed
        outcomes["__exit__"] = FAIL
    tail = (res.stdout + "\n" + res.stderr).strip().splitlines()[-15:]
    return TestRun(index, res.returncode, outcomes, res.duration, res.timed_out, parse_ok or not is_pytest,
                   res.isolation, "\n".join(tail))


@dataclass
class Baseline:
    runs: int
    stable: dict[str, str]
    flaky: list[str]
    passed: int
    failed: int
    skipped: int
    total: int
    green: bool
    reason: str
    avg_duration: float

    def to_dict(self) -> dict:
        return asdict(self)


def build_baseline(runs: list[TestRun]) -> Baseline:
    all_ids = sorted({t for r in runs for t in r.outcomes})
    stable: dict[str, str] = {}
    flaky: list[str] = []
    for t in all_ids:
        seen = {r.outcomes.get(t, "missing") for r in runs}
        if len(seen) == 1:
            stable[t] = seen.pop()
        else:
            flaky.append(t)
    passed = sum(1 for v in stable.values() if v == PASS)
    failed = sum(1 for v in stable.values() if v in (FAIL, ERROR))
    skipped = sum(1 for v in stable.values() if v == SKIP)
    reason = "ok"
    green = True
    if any(r.timed_out for r in runs):
        green, reason = False, "test run timed out"
    elif not all(r.parse_ok for r in runs):
        green, reason = False, "could not parse test results"
    elif not all_ids or (passed + failed) == 0:
        green, reason = False, "no tests collected: cannot prove changes are safe"
    elif failed:
        green, reason = False, f"baseline has {failed} failing test(s)"
    avg = sum(r.duration for r in runs) / max(1, len(runs))
    return Baseline(len(runs), stable, flaky, passed, failed, skipped, len(all_ids), green, reason, avg)


# ---- verification gates -------------------------------------------------------------
@dataclass
class Gate:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def syntax_gate(root: Path, cfg: AgentConfig) -> Gate:
    """'Build' gate: every Python (ast) and Java (tree-sitter) file must still parse.
    The real compile happens in the test run (mvn/gradle/ant); this is a fast pre-check."""
    from .analyzers import javacode
    bad: list[str] = []
    n_py = n_java = 0
    parser = None
    if javacode._LANG is not None:
        from tree_sitter import Parser
        parser = Parser(javacode._LANG)
    for rel in iter_repo_files(root, cfg.ignore_paths):
        if rel.endswith(".py"):
            n_py += 1
            try:
                ast.parse(read_text_safe(root, rel) or "")
            except SyntaxError as e:
                bad.append(f"{rel}:{e.lineno}")
        elif rel.endswith(".java") and parser is not None:
            n_java += 1
            text = read_text_safe(root, rel) or ""
            if parser.parse(text.encode("utf-8")).root_node.has_error:
                bad.append(rel)
    summary = f"{n_py} Python + {n_java} Java files parse"
    return Gate("build/syntax", not bad, summary if not bad else "syntax errors: " + ", ".join(bad[:5]))


def tests_gate(baseline: Baseline, after_runs: list[TestRun]) -> Gate:
    problems: list[str] = []
    if any(r.timed_out for r in after_runs):
        problems.append("test run timed out")
    if not all(r.parse_ok for r in after_runs):
        problems.append("could not parse test results")
    flaky = set(baseline.flaky)
    for test, outcome in baseline.stable.items():
        if outcome != PASS or test in flaky:
            continue
        for r in after_runs:
            got = r.outcomes.get(test, "missing")
            if got != PASS:
                problems.append(f"{test}: {outcome} -> {got}")
                break
    new_failures = sorted({t for r in after_runs for t, o in r.outcomes.items()
                           if o in (FAIL, ERROR) and t not in baseline.stable and t not in flaky})
    problems += [f"new failing test: {t}" for t in new_failures]
    after_passed = min(sum(1 for o in r.outcomes.values() if o == PASS) for r in after_runs) if after_runs else 0
    if after_passed < baseline.passed - len(flaky):
        problems.append(f"passed count dropped ({after_passed} < {baseline.passed})")
    detail = (f"{after_passed} passed vs baseline {baseline.passed}; flaky excluded: {len(flaky)}"
              if not problems else "; ".join(problems[:6]))
    return Gate("tests: no regressions", not problems, detail)


def command_gates(sandbox: BaseSandbox, workdir: Path, cfg: AgentConfig, home: Path | None = None) -> list[Gate]:
    gates = []
    for cmd in cfg.extra_verify_commands:
        res = sandbox.run(cmd, workdir, cfg.test_timeout, home=home)
        gates.append(Gate(f"command: {' '.join(cmd)[:60]}", res.returncode == 0 and not res.timed_out,
                          "exit 0" if res.returncode == 0 else f"exit {res.returncode}"))
    return gates
