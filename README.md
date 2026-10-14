# Code Maintenance Agent (MVP)

Analyses a **Python and/or Java** repository, reports **duplicate code**, **dead code** and **security-relevant
findings**, runs your **tests**, makes a **small verified change on a separate `agent/*` branch**, and opens a **PR**.
**A human reviews and merges. The agent never merges and never touches protected branches.**

Design rationale: [`docs/design.md`](docs/design.md).  
**Deploying for free (GitHub Actions): [`DEPLOY.md`](DEPLOY.md)** - paste a Git URL into the "Run workflow" form; ready-made workflow in `.github/workflows/`.

## Quick start

```bash
pip install -r requirements.txt

# 1. try it on a seeded demo repo (python or java)
python -m agent doctor                                  # preflight: tools, sandbox, which tokens are set
python -m agent demo /tmp/demo-shop
python -m agent demo /tmp/jshop --lang java            # Maven layout (pom.xml, JUnit 4)

# 2. read-only analysis (no code from the repo is executed)
python -m agent analyze /tmp/demo-shop --out ./agent-runs       # prompts you to type the repo name

# 3. full run: baseline tests -> patch -> verification gates -> branch (+ PR)
python -m agent run /tmp/demo-shop --out ./agent-runs --sandbox docker --open-pr --consent demo-shop:read,execute,write
#    no Docker? weaker fallback, only for repos you trust:
python -m agent run /tmp/demo-shop --sandbox local --allow-unsafe-local --open-pr --consent demo-shop:read,execute,write
```

Each run writes to `agent-runs/<run-id>/`: `report.md`, `report.json`, `patches/CS-001.diff`,
`pr/CS-001.md` (PR body), `audit.jsonl` (hash-chained audit log).

For a real GitHub repo: pass its clone URL, and set `AGENT_READ_TOKEN` (read-only) and
`AGENT_WRITE_TOKEN` (short-lived GitHub App installation token, `contents:write` + `pull_requests:write`).
Protect `main` with a ruleset so the bot can only create/update `agent/**` branches.

## Web UI

```bash
python -m agent serve            # open http://127.0.0.1:8080, paste a GitHub URL, type the repo name to consent
./scripts/serve_codespace.sh     # same, inside a GitHub Codespace (free quota); token-protected
```

A dependency-free Web Component (`agent/web/agent-panel.js`) + a stdlib backend (`agent/server.py`): URL box, access notice,
typed consent, live progress, findings, and the generated patch as a diff (copy / download / `git apply`). Loopback by default;
any other bind requires `AGENT_UI_TOKEN`. Details and free-hosting options: `DEPLOY.md` section 0b.

## Consent: nothing is accessed until a person authorises it

A URL alone grants nothing. Before any clone/read/execute/LLM/write, the agent shows an access notice and requires
explicit, scoped, expiring authorisation (type the repo name; or `--consent owner/name:read,execute`; or a standing
`--consent-file`). Untrusted repos (no verified write access) can never get `write` and only run tests in Docker.
Repo values are strictly validated (https + allowlisted hosts only). Details: `DEPLOY.md` section 3b.

```bash
python -m agent consent notice https://github.com/acme/shop.git --scopes read,execute     # preview, grants nothing
python -m agent consent grant  https://github.com/acme/shop.git --scopes read --days 30   # writes an expiring file
python -m agent analyze https://github.com/acme/shop.git                                   # prompts: type the repo name
python -m agent analyze https://github.com/acme/shop.git --consent acme/shop:read          # one automated run
```

## Java support

Languages and the test runner are **auto-detected** (`.java` files, `pom.xml` / `build.gradle[.kts]` / `build.xml`).

| Build tool | Default command | Reports parsed |
|---|---|---|
| Maven | `mvn -B -o -q test` (or `./mvnw`) | `**/surefire-reports/TEST-*.xml` |
| Gradle | `gradle --offline -q test` (or `./gradlew`) | `**/test-results/**/TEST-*.xml` |
| Ant / custom | set `test.command` and `test.reports` in `.agent.yml` | `**/TEST-*.xml` by default |

Dead-code rules for Java (tree-sitter, nothing is compiled or run during analysis):

* only **private** members and **private nested types** can reach `high` (auto-removable);
* `@Override`, interface/abstract methods, `main`, constructors, serialization hooks are never flagged;
* any non-safe **annotation** (Spring/JPA/Lombok/custom) or class-level framework annotation, a **string literal**,
  or an **XML/properties/META-INF** mention caps the finding at `low`;
* **reflection** (`getDeclared*`, `setAccessible`, `Class.forName`) anywhere in the same file caps it at `medium`;
* fields whose initialiser has side effects (`new ...`, method calls) and multi-declarator fields are `medium`;
* files that fail to parse are reported, never edited, and their identifiers still count as references.

Changes are only attempted in languages whose tests actually ran (`test.covers`). In a mixed repo with a
Maven/Gradle build, Python findings stay report-only unless you configure a command that covers both.

**Dependencies for Maven/Gradle.** Tests run with no network, so dependencies must be available offline:
pass `--java-cache <dir>` (a warmed `~/.m2` / `~/.gradle`, copied afresh for every run so a hostile test cannot
poison later runs) and/or `--prefetch-network` (one credential-less download phase; in production route it
through an internal mirror). Use `Dockerfile.sandbox.java` for the sandbox image.

## What is implemented

| Design-doc stage | Module | Status |
|---|---|---|
| Intake, pinned SHA, hooks disabled | `gitops.py` | done |
| Secret / injection scan, deny-read, no symlinks | `scanners.py`, `util.py` | done |
| Dead code, Python (AST, confidence tiers) | `analyzers/deadcode.py` | done |
| Dead code, Java (tree-sitter, confidence tiers) | `analyzers/javacode.py` | done |
| Duplicates (exact + structural) | `analyzers/duplicates.py` | done (report only) |
| Baseline tests, flaky detection | `testrun.py` | done: pytest, plus Maven/Gradle/Ant via JUnit XML (stale reports deleted first, `__exit__` guard) |
| Sandbox | `sandbox.py` | Docker (untested here: no Docker in dev box) + local fallback (tested with real javac/JUnit via Ant) |
| Patch builder with syntax validation | `patcher.py` | done (dead-code removal; Python via `ast`, Java via tree-sitter, javadoc removed with the method) |
| Policy engine | `policy.py` | done |
| Verification gates | `testrun.py` | build/syntax, tests, extra commands, policy. **Coverage gate not implemented yet** |
| Branch, commit, push, PR | `gitops.py` | done; GitHub PR API call is **untested** (needs a real token) |
| Report + PR body | `report.py` | done |
| LLM triage | `llm.py` | optional, **untested live** (needs API key); veto-only |
| Audit log, kill switch, time limit | `audit.py`, `orchestrator.py` | done |

### Honest status of the Java path

* **Verified here with real tools:** tree-sitter analysis, patching, policy, gates, and full end-to-end runs using
  `javac` + JUnit 4 through **Ant** (5 real tests executed, PR branch independently rebuilt and re-tested).
* **Written but NOT run here** (no Maven/Gradle/Docker/Central access in the dev box): the Maven/Gradle
  command lines and report globs, `--prefetch-network`, `--java-cache`, and `Dockerfile.sandbox.java`.
  Try them on one small repo first and tell me what breaks.

## Not yet implemented (roadmap)

1. Coverage gate and public-API diff gate.
2. Duplicate refactoring PRs and unused-dependency PRs (currently report-only / not present).
3. More languages (JS/TS via `knip`, Go via `staticcheck`, Kotlin). Java: no cross-module/call-graph resolution yet (name-based, conservative).
4. Signed commits (bot key in a signing service), PR labels/reviewers, CODEOWNERS lookup.
5. Retry-by-splitting when a change set fails a gate.
6. Dependency pre-build layer + internal package mirror for the sandbox.
7. Scheduler/webhook service, run store (DB), dashboard, SARIF output.
8. LLM-based characterization-test generation.

## Security model in one paragraph

Untrusted repo code only runs in the sandbox, with no credentials, no network, a scrubbed env and
resource limits. The sandbox produces a patch; the **control plane** validates it with the policy engine
(protected paths incl. CI files and tests, size/binary/mode limits, forbidden patterns, secrets) and only
then pushes to an `agent/*` branch with an explicit refspec (no force-push, no merge). Repo-supplied
`.agent.yml` can only tighten policy. The LLM is optional and can only *downgrade* a finding.
Everything is audit-logged in a tamper-evident hash chain.

**Honest limits:** the local sandbox is not a strong isolation boundary (use Docker/gVisor/Firecracker
for untrusted repos); the detectors are heuristic, so human review stays mandatory; prompt-injection
defence relies on the model having no authority, not on the model "resisting".

## Tests

```bash
python -m pytest -q      # 201 tests incl. adversarial end-to-end cases; Java e2e needs JDK + Ant + junit4; UI tests need node + jsdom: cd tests/ui && npm install (all auto-skipped otherwise)
```
