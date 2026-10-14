"""Command line interface."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import consent as consent_mod
from .demo import create_demo_repo, create_java_demo_repo
from .orchestrator import Orchestrator, RunOptions
from .sandbox import SandboxError


def doctor() -> int:
    """Preflight: tell the deployer exactly what is and is not available. Never prints secret values."""
    import os
    import platform
    import shutil
    import subprocess

    rows: list[tuple[str, str, str]] = []

    def add(status: str, name: str, detail: str) -> None:
        rows.append((status, name, detail))

    def first_line(cmd: list[str]) -> str:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            return ((out.stdout or out.stderr).strip().splitlines() or ["?"])[0][:70]
        except (OSError, subprocess.SubprocessError):
            return "?"

    py = sys.version_info
    add("OK" if py >= (3, 10) else "FAIL", "python", f"{platform.python_version()} (need >= 3.10)")
    add("OK" if shutil.which("git") else "FAIL", "git", first_line(["git", "--version"]) if shutil.which("git") else "missing")
    try:
        import yaml  # noqa: F401
        add("OK", "pyyaml", "installed")
    except ImportError:
        add("FAIL", "pyyaml", "pip install -r requirements.txt")
    from .analyzers import javacode
    add("OK" if javacode.available() else "WARN", "tree-sitter-java",
        "installed" if javacode.available() else "missing: Java dead-code analysis disabled")
    if shutil.which("docker"):
        ok = subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
        add("OK" if ok else "WARN", "docker", "usable (strong sandbox available)" if ok else "installed but daemon not reachable")
    else:
        add("WARN", "docker", "missing: only the weaker local sandbox is available (--allow-unsafe-local)")
    for tool, cmd in (("java", ["java", "-version"]), ("javac", ["javac", "-version"]),
                      ("mvn", ["mvn", "-v"]), ("gradle", ["gradle", "-v"])):
        add("OK" if shutil.which(tool) else "INFO", tool, first_line(cmd) if shutil.which(tool) else "not on PATH (fine if tests run in Docker)")
    from .sandbox import _unshare_works
    add("OK" if _unshare_works() else "WARN", "network namespaces", "available" if _unshare_works() else "unavailable: local sandbox cannot cut network")
    read, write = bool(os.environ.get("AGENT_READ_TOKEN")), bool(os.environ.get("AGENT_WRITE_TOKEN"))
    add("OK" if read else "INFO", "AGENT_READ_TOKEN", "set" if read else "not set (fine for public repos)")
    add("INFO" if not write else "WARN", "AGENT_WRITE_TOKEN",
        "not set: runs cannot push or open PRs (safe default)" if not write else "set: runs CAN push agent/* branches and open PRs")
    killed = os.environ.get("AGENT_KILL_SWITCH") == "1" or Path(os.environ.get("AGENT_KILL_FILE", str(Path.home() / ".maintenance-agent" / "KILL"))).exists()
    add("WARN" if killed else "OK", "kill switch", "ENGAGED: runs will abort" if killed else "not engaged")
    width = max(len(r[1]) for r in rows)
    for status, name, detail in rows:
        print(f"[{status:<4}] {name:<{width}}  {detail}")
    return 1 if any(r[0] == "FAIL" for r in rows) else 0


def consent_command(args) -> int:
    import os
    from .policy import load_policy

    pol = load_policy()
    try:
        ref = consent_mod.parse_repo_ref(args.repo, pol["consent"]["allowed_hosts"])
        if args.consent_cmd == "resolve":
            print(ref.slug)
            return 0
        if args.consent_cmd == "trust":
            info = consent_mod.fetch_repo_info(ref, os.environ.get("AGENT_READ_TOKEN"))
            print(info.trust)
            print(f"{info.trust}: {info.trust_reason}", file=sys.stderr)
            return 0
        scopes = [x.strip() for x in args.scopes.split(",") if x.strip()]
        bad = [x for x in scopes if x not in consent_mod.SCOPES]
        if bad or not scopes:
            raise consent_mod.ConsentError(f"invalid scopes (valid: {', '.join(consent_mod.SCOPE_ORDER)})")
        if "read" not in scopes:
            scopes.insert(0, "read")
        info = consent_mod.fetch_repo_info(ref, os.environ.get("AGENT_READ_TOKEN"))
        if args.consent_cmd == "notice":
            print(consent_mod.render_notice(ref, scopes, info, consent_mod._identity(), "PREVIEW ONLY: showing this grants nothing",
                                            pol["secrets"]["deny_read"], "./agent-runs"))
            return 0
        consent_mod._enforce_trust(scopes, info)
        who = args.by or consent_mod._identity()
        print(consent_mod.render_notice(ref, scopes, info, who, f"standing consent for {args.days} day(s), then it expires",
                                        pol["secrets"]["deny_read"], "./agent-runs"))
        answer = args.confirm if args.confirm is not None else input(f"\nType the repository name ({ref.slug}) to grant this consent: ").strip()
        if answer.lower() != ref.slug.lower():
            print("Not granted: the repository name was not confirmed.", file=sys.stderr)
            return 3
        out = args.out or f"consents/{ref.slug.replace('/', '__')}.yml"
        path = consent_mod.write_consent_file(out, ref, scopes, who, args.days, max_days=pol["consent"]["max_standing_days"])
        print(f"Consent written to {path}. Keep it OUTSIDE the analysed repo; delete it to revoke; it expires in {args.days} day(s).")
        return 0
    except consent_mod.ConsentError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("repo", help="local path or clone URL of the repository")
    p.add_argument("--out", default="./agent-runs", help="output directory for reports/patches/audit logs")
    p.add_argument("--policy", default=None, help="optional control-plane policy.yml")
    p.add_argument("--llm", action="store_true", help="enable optional LLM triage (needs ANTHROPIC_API_KEY)")
    p.add_argument("--keep-work", action="store_true", help="keep scratch copies (debugging)")
    p.add_argument("--consent", default=None, metavar="REPO:SCOPES",
                   help="authorise THIS run non-interactively, e.g. acme/shop:read,execute (scopes: read,execute,llm,write)")
    p.add_argument("--consent-file", default=None, metavar="FILE",
                   help="standing consent file (create with 'consent grant'); must live outside the analysed repo")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agent", description="Code maintenance agent (report + PR, human merges)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="read-only analysis and report (no tests, no changes)")
    _common(a)

    r = sub.add_parser("run", help="analyse, run tests, propose a verified patch, optionally open a PR")
    _common(r)
    r.add_argument("--sandbox", choices=["auto", "docker", "local"], default="auto")
    r.add_argument("--allow-unsafe-local", action="store_true",
                   help="permit the weaker local sandbox (only for repos you trust)")
    r.add_argument("--open-pr", action="store_true", help="create the agent branch, push it and open a PR")
    r.add_argument("--no-push", action="store_true", help="with --open-pr: commit on the branch locally, do not push")
    r.add_argument("--java-cache", default=None, help="Maven/Gradle offline cache dir (~/.m2 contents); copied per run")
    r.add_argument("--prefetch-network", action="store_true",
                   help="allow one credential-less network phase to download Maven/Gradle dependencies")
    r.add_argument("--docker-image", default="maintenance-agent-sandbox:latest")
    r.add_argument("--sandbox-memory", default="2g", help="Docker memory limit for test runs (e.g. 3g for Spring Boot)")
    r.add_argument("--sandbox-cpus", default="2")

    sub.add_parser("doctor", help="preflight: check tools, sandbox options and which tokens are set")

    sv = sub.add_parser("serve", help="start the web UI + API (paste a GitHub URL in the browser)")
    sv.add_argument("--host", default="127.0.0.1", help="default loopback; any other host REQUIRES AGENT_UI_TOKEN")
    sv.add_argument("--port", type=int, default=8080)
    sv.add_argument("--out", default="./ui-runs", help="where job results are stored")
    sv.add_argument("--sandbox", choices=["auto", "docker", "local"], default="auto")
    sv.add_argument("--allow-unsafe-local", action="store_true", help="allow the weaker local sandbox for verify mode (trusted repos only)")
    sv.add_argument("--java-cache", default=None)
    sv.add_argument("--prefetch-network", action="store_true")
    sv.add_argument("--docker-image", default="auto", help="'auto' picks a maven/gradle/python image per repository")
    sv.add_argument("--java-version", default="17", help="JDK version for the auto-selected Maven/Gradle image")
    sv.add_argument("--sandbox-memory", default="3g")
    sv.add_argument("--max-jobs-per-hour", type=int, default=10)
    sv.add_argument("--allow-local-paths", action="store_true", help="DEV ONLY: accept local directories as repositories")

    c = sub.add_parser("consent", help="show the access notice, or create an expiring standing-consent file")
    csub = c.add_subparsers(dest="consent_cmd", required=True)
    cn = csub.add_parser("notice", help="print what the agent would ask permission for (grants nothing)")
    cn.add_argument("repo")
    cn.add_argument("--scopes", default="read", help="comma list of: read,execute,llm,write")
    cr = csub.add_parser("resolve", help="validate a repo URL and print owner/name (used by the workflow)")
    cr.add_argument("repo")
    ct = csub.add_parser("trust", help="print 'trusted' or 'untrusted' for this repo (GitHub metadata only)")
    ct.add_argument("repo")
    cg = csub.add_parser("grant", help="write a standing consent file after you confirm by typing the repo name")
    cg.add_argument("repo")
    cg.add_argument("--scopes", default="read", help="comma list of: read,execute,llm,write")
    cg.add_argument("--days", type=int, default=30, help="validity in days (max 90)")
    cg.add_argument("--by", default=None, help="who is granting (default: current user)")
    cg.add_argument("--out", default=None, help="file to write (default: consents/<owner>__<name>.yml)")
    cg.add_argument("--confirm", default=None, help="non-interactive confirmation: the exact repository name")

    d = sub.add_parser("demo", help="create a seeded demo repo to try the agent on")
    d.add_argument("dest", help="directory to create")
    d.add_argument("--lang", choices=["python", "java"], default="python")
    d.add_argument("--build", choices=["maven", "ant"], default="maven", help="java only: ant is for offline local testing")

    args = ap.parse_args(argv)
    if args.cmd == "doctor":
        return doctor()
    if args.cmd == "serve":
        from .server import ServerConfig, create_server
        cfg = ServerConfig(host=args.host, port=args.port, out_dir=Path(args.out), token=os.environ.get("AGENT_UI_TOKEN") or None,
                           sandbox=args.sandbox, allow_unsafe_local=args.allow_unsafe_local, java_cache=args.java_cache,
                           prefetch_network=args.prefetch_network, docker_image=args.docker_image, java_version=args.java_version,
                           docker_memory=args.sandbox_memory,
                           allow_local_paths=args.allow_local_paths, max_jobs_per_hour=args.max_jobs_per_hour)
        srv, app = create_server(cfg)
        caps = app.capabilities()["modes"]
        print(f"Code Maintenance Agent UI: http://{args.host}:{srv.server_address[1]}  "
              f"(auth: {'token' if cfg.token else 'none, loopback only'}; modes: "
              f"{', '.join(k for k, v in caps.items() if v['available'])})")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
        return 0
    if args.cmd == "consent":
        return consent_command(args)
    if args.cmd == "demo":
        made = (create_java_demo_repo(Path(args.dest), args.build) if args.lang == "java"
                else create_demo_repo(Path(args.dest)))
        print(f"Demo repo created at {made}")
        return 0

    opts = RunOptions(
        repo=args.repo, out_dir=Path(args.out), policy_path=args.policy, use_llm=args.llm, keep_work=args.keep_work,
        run_tests=(args.cmd == "run"),
        sandbox=getattr(args, "sandbox", "auto"), allow_unsafe_local=getattr(args, "allow_unsafe_local", False),
        open_pr=getattr(args, "open_pr", False), push=not getattr(args, "no_push", False),
        java_cache=getattr(args, "java_cache", None), prefetch_network=getattr(args, "prefetch_network", False),
        docker_image=getattr(args, "docker_image", "maintenance-agent-sandbox:latest"),
        docker_memory=getattr(args, "sandbox_memory", "2g"), docker_cpus=getattr(args, "sandbox_cpus", "2"),
        consent_flag=args.consent, consent_file=args.consent_file, interactive=sys.stdin.isatty(),
    )
    try:
        orch = Orchestrator(opts)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    state = orch.run()
    print(f"Run {state['run_id']}: {state['status']}")
    print(f"  dead code: {len(state['findings']['dead_code'])}  duplicates: {len(state['findings']['duplicates'])}  "
          f"secrets: {len(state['scan']['secrets'])}  injection-like text: {len(state['scan']['injections'])}")
    for cs in state["change_sets"]:
        print(f"  change set {cs['id']}: {cs['decision']}")
    print(f"  report: {orch.out / 'report.md'}")
    if state["status"].startswith("refused"):
        return 3
    return 0 if state["status"] == "completed" else 1
