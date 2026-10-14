"""Control-plane orchestrator: a deterministic state machine. The LLM (optional) is only
consulted for veto-only triage; it never decides what is executed, pushed or published."""
from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import consent as consent_mod
from . import gitops
from .analyzers.deadcode import analyze_dead_code, is_test_file
from .analyzers.javacode import analyze_java_dead_code, is_java_test_file
from .analyzers.duplicates import find_duplicates
from .audit import AuditLog
from .consent import ConsentError, ConsentRecord
from .config import CONFIDENCE_RANK, AgentConfig
from .llm import LLMGateway, apply_veto
from .patcher import build_dead_code_patch
from .policy import PolicyEngine, load_policy, parse_patch
from .report import render_pr_body, render_report
from .sandbox import SandboxError, pick_image, select_sandbox
from .scanners import redact_text, scan_repo, scan_text_for_secrets
from .sandbox import BaseSandbox
from .testrun import Gate, build_baseline, command_gates, run_tests, syntax_gate, tests_gate
from .util import iter_repo_files

AUTO_CHANGE_MIN_CONFIDENCE = "high"   # control-plane floor; repo config cannot lower it


class KillSwitchEngaged(Exception):
    pass


class RunTimeout(Exception):
    pass


@dataclass
class RunOptions:
    repo: str
    out_dir: Path
    sandbox: str = "auto"
    allow_unsafe_local: bool = False
    run_tests: bool = True
    open_pr: bool = False
    push: bool = True
    use_llm: bool = False
    policy_path: str | None = None
    keep_work: bool = False
    docker_image: str = "maintenance-agent-sandbox:latest"
    docker_memory: str = "2g"
    java_version: str = "17"             # used when docker_image == "auto"
    docker_cpus: str = "2"
    java_cache: str | None = None        # pre-populated offline ~/.m2 / ~/.gradle directory (copied per run)
    prefetch_network: bool = False       # allow ONE credential-less network phase to download dependencies
    # --- consent (nothing is accessed until one of these yields a valid record) ---
    consent: ConsentRecord | None = None  # for programs that manage consent themselves
    consent_flag: str | None = None       # "<owner/name>:<scopes>"
    consent_file: str | None = None       # standing consent file (outside the analysed repo)
    interactive: bool = False             # prompt the person (type the repo name)
    input_fn: object = None
    on_stage: object = None               # optional callable(stage_name, 'running'|'done'|'failed') for progress UIs


class Orchestrator:
    def __init__(self, opts: RunOptions):
        self.opts = opts
        self.run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        self.out = Path(opts.out_dir) / self.run_id
        self.work = self.out / "work"
        self.out.mkdir(parents=True, exist_ok=True)
        self.audit = AuditLog(self.out / "audit.jsonl", self.run_id)
        self.policy_dict = load_policy(opts.policy_path)
        self.started = time.time()
        self.policy: PolicyEngine = PolicyEngine(self.policy_dict)
        self.cfg = AgentConfig()
        self.dead: list = []
        self.dups: list = []
        self.sandbox: BaseSandbox | None = None
        self.cache_dir = None
        self.consent_rec: ConsentRecord | None = None
        self.ref = None
        self.remote_url = ""
        self.state: dict = {
            "run_id": self.run_id, "repo": opts.repo, "commit": "", "status": "running",
            "notes": [], "scan": {"secrets": [], "sensitive_files": [], "injections": [], "files_scanned": 0},
            "findings": {"dead_code": [], "duplicates": []}, "baseline": None, "change_sets": [],
            "llm": {"enabled": False, "calls": 0, "downgraded": 0}, "parse_failures": [], "languages": [], "build_tool": "",
            "audit_log": str(self.out / "audit.jsonl"), "consent": None,
        }

    # ---- safety rails ---------------------------------------------------------------
    def _check_limits(self) -> None:
        kill_file = os.environ.get("AGENT_KILL_FILE", str(Path.home() / ".maintenance-agent" / "KILL"))
        if os.environ.get("AGENT_KILL_SWITCH") == "1" or Path(kill_file).exists():
            raise KillSwitchEngaged("kill switch engaged")
        if self.consent_rec is not None and not self.consent_rec.is_valid():
            raise ConsentError("consent expired during the run")
        limit = self.policy_dict["limits"]["run_timeout_minutes"] * 60
        if time.time() - self.started > limit:
            raise RunTimeout("run exceeded time limit")

    def _require(self, scope: str) -> None:
        """Defence in depth: every sensitive action re-checks that the person granted exactly that."""
        if self.consent_rec is None or not self.consent_rec.covers([scope]):
            raise ConsentError(f"'{scope}' permission was not granted for this run")

    def _emit(self, stage: str, phase: str) -> None:
        if callable(self.opts.on_stage):
            try:
                self.opts.on_stage(stage, phase)
            except Exception:  # a broken progress listener must never affect the run
                pass

    def _stage(self, name: str, fn) -> None:
        self._check_limits()
        self.audit.log("stage_start", stage=name)
        self._emit(name, "running")
        t0 = time.time()
        try:
            fn()
        except BaseException:
            self._emit(name, "failed")
            raise
        self.audit.log("stage_end", stage=name, seconds=round(time.time() - t0, 2))
        self._emit(name, "done")

    def _note(self, msg: str) -> None:
        self.state["notes"].append(msg)
        self.audit.log("note", message=msg)

    def _copy(self, src: Path, name: str, with_git: bool) -> Path:
        dst = self.work / name
        ignore = None if with_git else shutil.ignore_patterns(".git")
        shutil.copytree(src, dst, symlinks=True, ignore=ignore)
        return dst

    # ---- stages ---------------------------------------------------------------------
    def consent_stage(self) -> None:
        """Runs BEFORE anything is cloned, read, executed or sent anywhere."""
        cpol = self.policy_dict.get("consent", {})
        self.ref = consent_mod.parse_repo_ref(self.opts.repo, cpol.get("allowed_hosts"))
        scopes = consent_mod.needed_scopes(self.opts.run_tests, self.opts.use_llm, self.opts.open_pr)
        info = consent_mod.fetch_repo_info(self.ref, os.environ.get("AGENT_READ_TOKEN"))
        rec, notice = consent_mod.obtain_consent(
            self.ref, scopes, info, record=self.opts.consent, consent_flag=self.opts.consent_flag,
            consent_file=self.opts.consent_file, interactive=self.opts.interactive, deny_read=self.policy.deny_read,
            out_dir=str(self.out), max_days=int(cpol.get("max_standing_days", 90)),
            input_fn=self.opts.input_fn or input)
        self.consent_rec = rec
        (self.out / "consent.json").write_text(json.dumps(rec.to_dict(), indent=2), encoding="utf-8")
        (self.out / "consent_notice.txt").write_text(notice + "\n", encoding="utf-8")
        self.state["consent"] = rec.to_dict()
        if rec.method in ("flag", "file"):
            print(notice)
        self.audit.log("consent_granted", repo=rec.repo, scopes=rec.scopes, by=rec.granted_by, method=rec.method,
                       expires=rec.expires_at, trust=rec.trust, notice_sha=rec.notice_sha256[:16], ci_run=rec.ci_run)

    def intake(self) -> None:
        self.work.mkdir(parents=True, exist_ok=True)
        snap = self.work / "snapshot"
        self._require("read")
        local = self.ref.kind == "local"
        self.state["commit"] = gitops.clone(str(self.ref.path) if local else self.ref.clone_url, snap,
                                            os.environ.get("AGENT_READ_TOKEN"), local=local)
        self.snap = snap
        self.cache_dir = None
        try:
            self.remote_url = gitops.git(["remote", "get-url", "origin"], cwd=snap)
        except gitops.GitError:
            self.remote_url = ""
        self.cfg = AgentConfig.load(snap)
        # repo config may only tighten policy
        self.policy = PolicyEngine(self.policy_dict, repo_protected=self.cfg.protected_modules)
        self.audit.log("intake", commit=self.state["commit"], languages=self.cfg.languages)
        if not self.cfg.enabled:
            raise RuntimeError("agent disabled by .agent.yml")

    def scan(self) -> None:
        self.files = list(iter_repo_files(self.snap, self.cfg.ignore_paths))
        for note in self.cfg.resolve_runtime(self.snap, self.files):
            self._note(note)
        self.state["languages"] = list(self.cfg.languages or [])
        self.state["build_tool"] = self.cfg.build_tool
        res = scan_repo(self.snap, self.files, self.policy.deny_read)
        self.state["scan"] = {
            "secrets": [s.to_dict() for s in res.secrets], "sensitive_files": res.sensitive_files,
            "injections": [i.to_dict() for i in res.injections], "files_scanned": res.files_scanned,
        }
        self.secret_files = {s.file for s in res.secrets}
        self.audit.log("scan", secrets=len(res.secrets), sensitive=len(res.sensitive_files), injections=len(res.injections))

    def analyze(self) -> None:
        readable = [f for f in self.files if self.policy.check_read(f)]
        langs = self.cfg.languages or []
        self.dead, parse_failures = [], []
        if "python" in langs:
            py = [f for f in readable if f.endswith(".py")]
            d, fails = analyze_dead_code(self.snap, py, readable) if py else ([], [])
            self.dead += d
            parse_failures += fails
        if "java" in langs:
            jv = [f for f in readable if f.endswith(".java")]
            if jv:
                d, fails, notes = analyze_java_dead_code(self.snap, jv, readable)
                self.dead += d
                parse_failures += fails
                for n in notes:
                    self._note(n)
        for i, f in enumerate(self.dead, 1):      # unique ids across languages
            f.id = f"DC-{i:03d}"
        self.state["parse_failures"] = parse_failures
        code = [f for f in readable if any(f.endswith(e) for e in self.cfg.extensions)
                and not is_test_file(f) and not is_java_test_file(f)]
        self.dups = find_duplicates(self.snap, code, self.cfg.dup_min_lines, self.cfg.dup_min_chars)

        llm = LLMGateway(self.opts.use_llm and self.consent_rec.covers(["llm"]), self.audit, self.policy_dict["limits"]["max_llm_calls"])
        downgraded = 0
        for f in self.dead:
            if f.file in self.secret_files and f.confidence == "high":
                f.confidence, f.proposed_action, f.risk = "medium", "report_only", "medium"
                f.evidence.append("file contains secret-like strings: excluded from automatic change")
                continue
            if f.confidence == "high":
                downgraded += apply_veto(f, llm.triage(self.snap, f))
        self.state["llm"] = {"enabled": llm.enabled, "calls": llm.calls, "downgraded": downgraded}
        self._sync_findings()
        self.audit.log("analyze", dead=len(self.dead), duplicates=len(self.dups))

    # ---- dependency cache (Maven/Gradle): copied per run so a hostile test can't poison later runs ----
    def _prefetch(self) -> None:
        self.cache_dir: Path | None = None
        if self.cfg.build_tool not in ("maven", "gradle"):
            return
        if not (self.opts.java_cache or self.opts.prefetch_network):
            self._note(f"{self.cfg.build_tool}: no --java-cache and no --prefetch-network; tests run fully offline "
                       "and will fail unless dependencies are baked into the sandbox image")
            return
        self.cache_dir = self.work / "depcache"
        if self.opts.java_cache and Path(self.opts.java_cache).is_dir():
            src = Path(self.opts.java_cache)
            # accept a '~/.m2' dir, a '~/.gradle' dir, or a HOME-like dir that contains them
            if (src / "repository").is_dir() and not (src / ".m2").exists():
                shutil.copytree(src, self.cache_dir / ".m2", symlinks=True)
            elif (src / "caches").is_dir() and not (src / ".gradle").exists():
                shutil.copytree(src, self.cache_dir / ".gradle", symlinks=True)
            else:
                shutil.copytree(src, self.cache_dir, symlinks=True)
        else:
            self.cache_dir.mkdir(parents=True)
        if self.opts.prefetch_network:
            tool = self.cfg.test_command[0]
            cmd = ([tool, "-B", "-q", "dependency:go-offline", "test-compile"] if self.cfg.build_tool == "maven"
                   else [tool, "--no-daemon", "-q", "testClasses"])
            pf_dir = self._copy(self.snap, "prefetch", with_git=False)
            res = self.sandbox.run(cmd, pf_dir, self.cfg.test_timeout, home=self.cache_dir, network=True)
            self.audit.log("prefetch", cmd=cmd, rc=res.returncode, network=True, credentials=False)
            self._note("dependency prefetch ran WITH network access (no credentials, repo copy only). "
                       "In production route it through an internal artifact mirror.")
            shutil.rmtree(pf_dir, ignore_errors=True)
            if res.returncode != 0:
                self._note(f"prefetch failed (rc={res.returncode}); offline test runs may fail")

    def _test_once(self, workdir: Path, idx: int):
        home = None
        if getattr(self, "cache_dir", None) is not None:
            home = self.work / f"home_{idx}"
            shutil.copytree(self.cache_dir, home, symlinks=True)
        try:
            return run_tests(self.sandbox, workdir, self.cfg, idx, home=home)
        finally:
            if home is not None:
                shutil.rmtree(home, ignore_errors=True)

    def baseline(self) -> None:
        if not self.opts.run_tests:
            return
        self._require("execute")
        if not self.cfg.test_command:
            self._note("no test command could be determined (set test.command in .agent.yml): no changes attempted")
            return
        self.sandbox = select_sandbox(self.opts.sandbox, self.opts.allow_unsafe_local,
                                      self.policy_dict["sandbox"]["allowed_executables"],
                                      pick_image(self.cfg.build_tool, self.opts.java_version) if self.opts.docker_image == "auto"
                                      else self.opts.docker_image, self.opts.docker_memory, self.opts.docker_cpus)
        if self.consent_rec.trust != "trusted" and self.sandbox.name != "docker":
            raise ConsentError("this repository is untrusted (no verified write access): its tests may only run in the "
                               "Docker sandbox, not the local fallback")
        decision = self.policy.check_command(self.cfg.test_command)
        if not decision:
            raise SandboxError("test command rejected: " + "; ".join(decision.reasons))
        self._prefetch()
        base_dir = self._copy(self.snap, "base", with_git=False)
        runs = []
        for i in range(self.cfg.baseline_runs):
            self._check_limits()
            runs.append(self._test_once(base_dir, i))
        b = build_baseline(runs)
        self.baseline_obj = b
        self.state["baseline"] = b.to_dict() | {"stable": None, "output_tail": "" if b.green else runs[0].output_tail,
                                                 "exit_code": runs[0].returncode}
        self.state["sandbox"] = runs[0].isolation
        self.audit.log("baseline", green=b.green, passed=b.passed, failed=b.failed, flaky=len(b.flaky), reason=b.reason,
                       isolation=runs[0].isolation)

    def plan_and_change(self) -> None:
        b = getattr(self, "baseline_obj", None)
        if not self.opts.run_tests:
            self._note("analysis-only mode: tests were not run, so no changes were attempted")
            return
        if not b or not b.green:
            self._note(f"no changes attempted: baseline not usable ({b.reason if b else 'not run'})")
            return
        if "dead_code" not in self.cfg.allowed_change_types or self.cfg.max_prs_per_run < 1:
            self._note("dead_code changes disabled by config")
            return
        floor = max(CONFIDENCE_RANK[self.cfg.min_confidence], CONFIDENCE_RANK[AUTO_CHANGE_MIN_CONFIDENCE])
        covers = set(self.cfg.test_covers or [])
        lang_of = lambda path: "java" if path.endswith(".java") else "python" if path.endswith(".py") else "other"  # noqa: E731
        eligible = [f for f in self.dead if CONFIDENCE_RANK[f.confidence] >= floor and f.proposed_action == "remove"
                    and lang_of(f.file) in covers]
        unverifiable = [f for f in self.dead if f.proposed_action == "remove" and lang_of(f.file) not in covers]
        if unverifiable:
            self._note(f"{len(unverifiable)} high-confidence finding(s) left unchanged: the test command only verifies "
                       f"{', '.join(sorted(covers)) or 'nothing'}")
        if not eligible:
            self._note("no high-confidence dead code eligible for automatic removal")
            return

        edit_dir = self._copy(self.snap, "edit", with_git=True)
        result = build_dead_code_patch(edit_dir, eligible)
        cs = {"id": "CS-001", "type": "dead_code", "findings": [f.to_dict() for f in result.applied],
              "skipped": [{"symbol": f.symbol, "reason": r} for f, r in result.skipped],
              "files": [], "added": 0, "removed": 0, "gates": [], "decision": "rejected",
              "policy": {"allowed": False, "reasons": []}}
        self.state["change_sets"].append(cs)
        if not result.applied or not result.patch.strip():
            cs["decision"] = "nothing_applicable"
            return
        info = parse_patch(result.patch)
        cs.update(files=info.files, added=info.added, removed=info.removed)
        patch_path = self.out / "patches" / "CS-001.diff"
        patch_path.parent.mkdir(parents=True, exist_ok=True)
        patch_path.write_text(result.patch, encoding="utf-8")
        cs["patch_file"] = str(patch_path)
        self.patch_text = result.patch

        decision = self.policy.check_patch(result.patch)
        cs["policy"] = {"allowed": decision.allowed, "reasons": decision.reasons}
        self.audit.log("policy_check", change_set="CS-001", allowed=decision.allowed, reasons=decision.reasons)
        if not decision:
            cs["decision"] = "rejected_policy"
            return

        # verify the PATCH in a fresh copy of the snapshot, as a reviewer's CI would
        after_dir = self._copy(self.snap, "after", with_git=True)
        gitops.apply_patch(after_dir, result.patch)
        gates: list[Gate] = [Gate("policy", True, "ALLOW (protected paths, size, patterns, secrets in diff)"),
                             syntax_gate(after_dir, self.cfg)]
        after_runs = []
        for i in range(self.cfg.baseline_runs):
            self._check_limits()
            after_runs.append(self._test_once(after_dir, 100 + i))
        gates.append(tests_gate(b, after_runs))
        gates += command_gates(self.sandbox, after_dir, self.cfg)
        cs["gates"] = [g.to_dict() for g in gates]
        cs["after_summary"] = {
            "passed": min(sum(1 for o in r.outcomes.values() if o == "passed") for r in after_runs),
            "failed": max(sum(1 for o in r.outcomes.values() if o in ("failed", "error")) for r in after_runs),
        }
        ok = all(g.passed for g in gates)
        cs["decision"] = "ready" if ok else "rejected_gates"
        for f in self.dead:
            if any(a.id == f.id for a in result.applied):
                f.status = "included_in_pr" if ok else "skipped"
        self.audit.log("verify", change_set="CS-001", passed=ok, gates=[g.name for g in gates if not g.passed])
        self._sync_findings()

    def publish(self) -> None:
        for cs in self.state["change_sets"]:
            if cs["decision"] != "ready":
                continue
            body = render_pr_body(cs, self.state)
            if scan_text_for_secrets(body):
                cs["decision"] = "blocked_secrets_in_output"
                self.audit.log("publish_blocked", change_set=cs["id"], reason="secret-like content in PR body")
                continue
            pr_dir = self.out / "pr"
            pr_dir.mkdir(exist_ok=True)
            (pr_dir / f"{cs['id']}.md").write_text(body, encoding="utf-8")
            if not self.opts.open_pr:
                cs["pr"] = {"dry_run": True, "reason": "--open-pr not set; patch and PR body saved locally"}
                continue
            self._require("write")
            branch = f"agent/dead-code/{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
            title = f"chore: remove {len(cs['findings'])} unused symbol(s) [agent]"
            cs["branch"] = gitops.create_branch_commit_push(
                self.snap, branch, self.patch_text, title + "\n\nAutomated change. See PR body for evidence.",
                self.policy, os.environ.get("AGENT_WRITE_TOKEN"), push=self.opts.push)
            cs["pr"] = gitops.open_github_pr(self.remote_url, branch, cs["branch"]["base"], title, body,
                                             os.environ.get("AGENT_WRITE_TOKEN"))
            self.audit.log("publish", change_set=cs["id"], branch=branch, pr=cs["pr"].get("url") or "dry-run")

    # ---- finish ---------------------------------------------------------------------
    def _sync_findings(self) -> None:
        self.state["findings"] = {"dead_code": [f.to_dict() for f in self.dead],
                                  "duplicates": [f.to_dict() for f in self.dups]}

    def run(self) -> dict:
        try:
            self._stage("consent", self.consent_stage)
            self._stage("intake", self.intake)
            self._stage("scan", self.scan)
            self._stage("analyze", self.analyze)
            self._stage("baseline", self.baseline)
            self._stage("plan_and_change", self.plan_and_change)
            self._stage("publish", self.publish)
            self.state["status"] = "completed"
        except ConsentError as e:
            self.state["status"] = f"refused: {e}"
            self.audit.log("consent_refused", reason=str(e)[:300])
        except KillSwitchEngaged as e:
            self.state["status"] = "aborted: " + str(e)
        except (RunTimeout, SandboxError, gitops.GitError, RuntimeError) as e:
            self.state["status"] = f"failed: {type(e).__name__}: {redact_text(str(e))[:200]}"
        except Exception as e:  # never crash without writing a report
            self.state["status"] = f"failed: unexpected {type(e).__name__}: {redact_text(str(e))[:200]}"
        finally:
            self._finish()
        return self.state

    def _finish(self) -> None:
        self.audit.log("run_end", status=self.state["status"])
        self.state["audit_verified"] = AuditLog.verify(self.out / "audit.jsonl")
        report = render_report(self.state)
        if scan_text_for_secrets(report):
            report = redact_text(report)
            self.state["notes"].append("report contained secret-like text and was redacted")
        (self.out / "report.md").write_text(report, encoding="utf-8")
        slim = json.loads(json.dumps(self.state, default=str))
        if slim.get("baseline"):
            slim["baseline"].pop("stable", None)
        (self.out / "report.json").write_text(json.dumps(slim, indent=2), encoding="utf-8")
        if not self.opts.keep_work:
            shutil.rmtree(self.work, ignore_errors=True)
        self.report_path = self.out / "report.md"
