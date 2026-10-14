# Deploying the Code Maintenance Agent on a free tier (for a Spring Boot repo)

**Goal:** run the agent against your Spring Boot repository for **$0**, safely, and see a report plus (optionally)
a verified pull request that **you** review and merge.

**Recommended host: GitHub Actions.** Reasons: it is free for what we need, every run gets a fresh throw-away VM,
Docker is pre-installed (the agent uses it as the test sandbox), and Java/Maven/Gradle are available.

> Free-tier limits change. The numbers below were checked in October 2026 against GitHub's and Oracle's
> documentation. Re-check the linked pages before relying on them.

---

## 0. The 3-minute version (GitHub Actions): paste a Git URL, click Run

There is no server to keep running. GitHub's free cloud runs the agent **only when you press the button**, then throws the machine away.

1. Create a **private** GitHub repo, upload this project to it (step 1 below).
2. Add one secret, `AGENT_READ_TOKEN` (a read-only token for the repo you want checked; step 2).
3. Repo → **Actions → maintenance-agent → Run workflow**, then fill the form:
   * **repo_url**: `https://github.com/owner/name`
   * **mode**: `analyze` (read-only report; start here)
   * **confirm**: type `owner/name` again. That typed name is your consent.
4. Open the run: the report is in the summary, and the files are in the `agent-run` artifact.

Cost: **$0** while idle; each run uses free Actions minutes (an `analyze` run takes a few minutes). An always-on web page where
anyone pastes a URL is deliberately *not* offered: free web hosts cannot safely run Docker sandboxes or multi-minute builds,
and such a page would let strangers spend your minutes and point the agent at arbitrary code.

---

## 0b. Web UI: paste a URL in a browser, get findings and the generated code

There is also a small **web UI** (`<maintenance-agent-panel>`, a dependency-free Web Component) with a Python backend that runs the
agent. You paste a GitHub URL, read the access notice, type the repo name to consent, watch the stages run, then see the findings
and the **generated code change** as a colour-coded diff you can copy or download and apply with `git apply`.

```bash
pip install -r requirements.txt
python -m agent serve                 # http://127.0.0.1:8080  (loopback only, no token needed)
```

| Mode in the UI | Needs | What you get |
|---|---|---|
| Analyze | nothing (executes no code) | findings report |
| Verify | Docker on the server (or `--sandbox local --allow-unsafe-local` for repos you trust) | tests run in the sandbox + a verified patch (the generated code) |
| Open PR | Verify + `AGENT_WRITE_TOKEN` on the server + write access to the repo | also pushes an `agent/*` branch and opens a PR |

The UI shows only the modes the server can actually do and says why a mode is unavailable.

**Where to run it for free**

| Option | How | Notes |
|---|---|---|
| Your own machine | `python -m agent serve` | Free, private, simplest. Install Docker if you want Verify. |
| **GitHub Codespaces** | Open this repo in a Codespace, then `./scripts/serve_codespace.sh` | Personal Free accounts include 120 core-hours (about 60 hours on a 2-core machine) and 15 GB storage per month; use is blocked rather than billed when the quota runs out and no payment method is set ([docs](https://docs.github.com/en/billing/concepts/product-billing/github-codespaces)). The `.devcontainer/` gives you Python, Java 17, Maven and Docker-in-Docker, so Verify works. The forwarded port is private to your GitHub account **and** protected by a random token the script prints. Stop the Codespace when done. |
| GitHub Actions form (section 0) | Run workflow + paste URL | No UI, but nothing to host and nothing running while idle. |

**Not offered: a public always-on website.** Anyone who can reach the page can make the server clone arbitrary repos and spend your compute.
If you host it anywhere other than loopback, the server **refuses to start without `AGENT_UI_TOKEN`** (16+ characters), and you should
also keep the host's own access control (for example Codespaces' private port visibility) in front of it.

**Security model of the UI/backend** (all covered by tests):
- Binds to `127.0.0.1` by default; a token is mandatory for any other bind; token compared in constant time.
- Accepts only `https` URLs on allowlisted hosts. Local paths, credentials in URLs, `ext::`, `file://`, option-like strings are rejected.
- **Consent is typing the repository name**, re-validated on the server; the button in the page is only a convenience. Trust (do you have write
  access?) is checked against GitHub: untrusted repos never get `write`, and tests for them run only in Docker.
- POST requires `application/json`, a same-origin `Origin`, and a body under 8 KB; token-less servers also check the `Host` header (DNS-rebinding defence).
- One job at a time, 10 jobs per hour by default, last 20 jobs kept, job ids validated, a fixed set of downloadable files (no path access).
- The page has a strict Content-Security-Policy, and **no text from a repository is ever inserted as HTML** (a static test and a jsdom test with
  hostile strings enforce this).

Useful options: `--java-cache DIR` / `--prefetch-network` (Maven/Gradle dependencies for Verify), `--java-version 21`,
`--sandbox-memory 4g`, `--max-jobs-per-hour N`, `--out DIR`. The sandbox image is chosen automatically (Maven, Gradle or Python).
Embed the component in your own page with `<script src="/agent-panel.js"></script><maintenance-agent-panel api=""></maintenance-agent-panel>`
(same origin; for another origin you must add CORS and a token yourself, which is intentionally not enabled).

---

## 1. How it will look

```
 Your PRIVATE "agent repo"                          Your Spring Boot repo (TARGET_REPO)
 (this project + workflow file)                     (never modified except by an agent/* branch + PR)
        |                                                      ^
        |  Actions run (ubuntu VM, free)                       | read token (always)
        v                                                      | write token (ONLY in open-pr mode)
 [ agent: control plane ] --clone--> snapshot ---------------- +
        |
        | patch + test results only (no credentials cross this line)
        v
 [ Docker sandbox: maven:3.9-eclipse-temurin-17, --network none, read-only, no tokens ]
        |
        v
 report.md + patch + PR body + audit log  -> run summary & downloadable artifact
```

Three modes, use them **in this order**:

| Mode | What it does | Tokens used | Writes to your repo? |
|---|---|---|---|
| `analyze` | Read-only report: dead code, duplicates, secrets, instruction-injection text. **No code from your repo is executed.** | read | No |
| `verify` | Also runs your tests (baseline), builds a patch, re-runs tests on the patched copy. Output is a **patch file + PR text** you can apply yourself. | read | **No** |
| `open-pr` | Same as `verify`, then pushes an `agent/dead-code/...` branch and opens a PR. | read + write | Only that branch + PR |

---

## 2. Where to run it (free options)

| Option | Fit | Notes |
|---|---|---|
| **GitHub Actions** (this guide) | Best | Free plan: **public** repos have unlimited minutes on standard runners; **private** repos get 2,000 Linux minutes and 500 MB artifact storage per month, plus 10 GB cache per repo. [Billing docs](https://docs.github.com/en/billing/concepts/product-billing/github-actions) |
| Your own laptop / PC | Good for a first try | Needs Python 3.10+, Git, and (strongly recommended) Docker + the right JDK. See section 11. |
| Oracle Cloud "Always Free" Arm VM | Possible, more work | Arm VM allowance has historically been up to 4 OCPU / 24 GB, but capacity is often unavailable, idle VMs can be reclaimed, and the allowance has reportedly changed recently. [Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/resourceref.htm). Section 12. |
| Render / Railway / Fly / Heroku-style free web hosts | **Not suitable** | The agent needs a Docker sandbox, a JDK, hundreds of MB of dependency cache and several minutes of CPU. Free web tiers are small, sleep, and normally cannot run Docker-in-Docker. |

### Rough cost of a run
One run does about **5 test-suite executions** (1 cache warm-up + 2 baseline + 2 on the patched copy) plus ~5 minutes of overhead:
`minutes ≈ 5 × (test suite minutes) + 5`. A 3-minute suite is about 20 minutes per run, so a weekly schedule uses roughly
90 of your 2,000 monthly minutes. Set `test.runs_for_baseline: 1` in `.agent.yml` to cut this to about `3 × T + 5`
(you lose flaky-test detection).

---

## 3. Read this first: branch protection and private repos

GitHub's docs state that **rulesets are available in public repositories on GitHub Free, and in private repositories only on
Pro, Team or Enterprise** ([source](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)).
Branch protection behaves the same way on private free repos.

What this means for you:

* **Your Spring Boot repo is public:** enable a ruleset on `main` (require a pull request, block force pushes, block deletions). Then even a bug in the agent cannot change `main`.
* **Your Spring Boot repo is private on the Free plan:** GitHub cannot enforce that for you. The agent's code still only pushes one explicit `agent/*` ref and its policy engine refuses anything else, but that protection lives in the agent, not in GitHub. So:
  1. Stay in `analyze` and `verify` modes (the write token is never created). `verify` gives you a patch you apply yourself with `git apply`.
  2. Move to `open-pr` only if you accept that residual risk, and use a write token that expires in 30 days and is limited to that single repo.

---

## 3b. Consent: the agent never touches a repo until a person says so

Giving the agent a URL is **not** permission. Before anything is cloned, read, executed, sent to an LLM or written, the agent
shows an **access notice** (what it will do, what it will not do, where results go) and requires explicit authorisation:

| Situation | How you authorise |
|---|---|
| You run it in a terminal | The notice is shown and you must **type the repository name** (typing `y` or `yes` is refused) |
| One automated run | `--consent owner/name:read,execute` (names the repo and the permissions) |
| Scheduled / unattended | A **standing consent file** that names the repo, permissions and who granted it, and **expires** (max 90 days) |
| GitHub Actions, manual run | You type the repo name into the **`confirm`** box when you press *Run workflow*; the notice is printed in the log before any code is fetched |
| GitHub Actions, scheduled | `consents/target.yml` (create it with `python -m agent consent grant ...`; see `consents/README.md`) |

Permissions are separate, so consent to analyse is **not** consent to run tests or push:

| Scope | Meaning | Needed for |
|---|---|---|
| `read` | Clone and read the source (read-only) | every mode |
| `execute` | Run the repo's own tests in the isolated sandbox | `verify`, `open-pr` |
| `llm` | Send redacted snippets to an LLM provider | `--llm` |
| `write` | Push one `agent/*` branch and open a PR | `open-pr` |

Safeguards around the consent itself:
- A consent is bound to **one repository**; it cannot be reused for another, and it **expires** (one run = 1 hour).
- **Trust is verified, not claimed.** The agent asks GitHub (metadata only: visibility, your permission level, license). If you
  lack write access, the repo is **untrusted**: `write` can never be granted and tests may run **only in the Docker sandbox**.
  A consent file cannot declare itself trusted.
- A consent file found **inside the analysed repo** is refused (a repo cannot authorise itself).
- Repo values are validated: only `https://` URLs on allowlisted hosts (default `github.com`); credentials in the URL, `ext::`,
  `file://`, `ssh://`, option-like strings (`--upload-pack=...`) and whitespace are rejected before git is called.
- Each action re-checks its own permission at the moment of use, and the grantor, time, permissions and notice hash are written
  to `consent.json`, the report, the PR description and the tamper-evident audit log.
- If consent is missing the run is **refused** (exit code 3), nothing is cloned, and a report explains why.

Try it: `python -m agent consent notice https://github.com/<owner>/<repo>.git --scopes read,execute` (grants nothing).

---

## 4. Step by step

### Step 1: create the agent repo (private)
1. On GitHub create a new **private** repository, e.g. `maintenance-agent`.
2. Upload this project to it (unzip, then):
   ```bash
   cd maintenance-agent
   git init -b main && git add -A && git commit -m "Code maintenance agent"
   git remote add origin https://github.com/<you>/maintenance-agent.git
   git push -u origin main
   ```
   The workflow file is already included at `.github/workflows/maintenance-agent.yml`.

### Step 2: create the access tokens (fine-grained personal access tokens)
GitHub → your avatar → **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**.

**Read token** (needed for `verify`, and for `analyze` if the target is private). To check several repos, select all of them
under *Only select repositories* (avoid "All repositories"), or keep one token per repo and swap the secret. For a **public**
repo you do not own, `analyze` works, but it is classed *untrusted* so `verify`/`open-pr` are blocked by design:

| Field | Value |
|---|---|
| Name | `maintenance-agent-read` |
| Expiration | 30–90 days |
| Repository access | **Only select repositories** → your Spring Boot repo |
| Repository permissions | **Contents: Read-only** (Metadata read is added automatically) |

**Write token** (create it only when you are ready for `open-pr`):

| Field | Value |
|---|---|
| Name | `maintenance-agent-write` |
| Expiration | **30 days** |
| Repository access | **Only select repositories** → your Spring Boot repo |
| Repository permissions | **Contents: Read and write**, **Pull requests: Read and write** |

If the repo belongs to an organisation, an owner may have to approve the token.

### Step 3: store secrets and variables in the agent repo
Agent repo → **Settings → Secrets and variables → Actions**.

*Secrets* tab:

| Name | Value |
|---|---|
| `AGENT_READ_TOKEN` | the read token |
| `AGENT_WRITE_TOKEN` | the write token (add later, only for `open-pr`) |

*Variables* tab:

| Name | Value | Required |
|---|---|---|
| `TARGET_REPO` | `owner/name`: optional default repo, used by scheduled runs or when `repo_url` is left empty | no |
| `JAVA_VERSION` | `17` (Spring Boot 3.x needs 17+; older apps may need `11` or `8`) | no, default 17 |
| `SANDBOX_MEMORY` | e.g. `3g` (Spring Boot tests often need 2–3 GB) | no, default 3g |
| `SCHEDULED_MODE` | `analyze` or `verify` (used only by scheduled runs) | no, default analyze |
| `AGENT_ENABLED` | set to `false` to stop all runs (kill switch) | no |

### Step 4 (recommended): add `.agent.yml` to your Spring Boot repo
Commit this at the **root of the Spring Boot repo** (the agent can never modify this file):

```yaml
version: 1
languages: [java]
test:
  # Default is: mvn -B -o -q test   (or ./mvnw, or gradle --offline -q test).
  # If some tests need external services (database, Kafka, Redis, Testcontainers), skip them here, e.g.:
  # command: [./mvnw, -B, -o, -q, test, "-Dtest=!*IntegrationTest"]
  runs_for_baseline: 2
  timeout: 1200
analysis:
  ignore_paths: ["**/generated/**"]
protected_modules:          # extra paths the agent must never touch (this can only ADD protection)
  - "**/security/**"
  - "**/config/**"
  - "**/db/migration/**"
changes:
  allowed_types: [dead_code]
  min_confidence: high
limits:
  max_prs_per_run: 1
```

### Step 5: first run, `analyze` (zero risk)
Agent repo → **Actions → maintenance-agent → Run workflow → mode: analyze**, and type your repository name (`owner/name`) in the
**confirm** box (and your Git URL in **repo_url**). That typed name is your consent; a mismatch stops the run before anything is accessed.
When it finishes, open the run: the **summary** shows the report, and the `agent-run` **artifact** contains `report.md`,
`report.json` and the tamper-evident `audit.jsonl`.

Read the report in this order: *Security findings* → *Dead code* (focus on `high`) → *Duplicate code*.

### Step 6: `verify` (runs your tests, still writes nothing)
Run the workflow with **mode: verify**. The job:
1. checks out your repo and **warms the dependency cache** (one normal build with network, no secrets in that step),
2. pulls `maven:3.9-eclipse-temurin-<JAVA_VERSION>` (or the Gradle image),
3. runs the agent: baseline tests twice, builds a patch of high-confidence dead code, re-tests the patched copy twice.

Check the report's **Test baseline** and **Change sets** sections. A change set is `READY` only if every gate passed.
The patch is in the artifact (`patches/CS-001.diff`) and the PR text in `pr/CS-001.md`. To use it yourself:
```bash
git checkout -b agent/dead-code-manual
git apply CS-001.diff && git commit -am "chore: remove unused code (agent)"
```

If the baseline is **not green**, the agent stops by design (it cannot prove a change is safe). See the troubleshooting table.

### Step 7: `open-pr` (only after steps 5–6 look good)
1. Add the `AGENT_WRITE_TOKEN` secret.
2. Run with **mode: open-pr**.
3. The agent creates `agent/dead-code/<yyyymmdd>-<id>` and opens a PR with the evidence tables. **You** review and merge.
   Also check: unused imports left behind (run organise-imports), and that no consumer outside the repo uses the removed symbols.

### Step 8: schedule it (optional)
1. Create a standing consent (shows the notice, asks you to type the repo name, expires in 30 days):
   ```bash
   python -m agent consent grant https://github.com/<owner>/<repo> --scopes read,execute --days 30 --out consents/target.yml
   git add consents/target.yml && git commit -m "Grant maintenance-agent access for 30 days" && git push
   ```
2. Edit the workflow and uncomment the `schedule:` block (weekly is plenty). Scheduled runs use `SCHEDULED_MODE`;
   keep it at `analyze` or `verify` unless you really want unattended PRs. When the consent expires, scheduled runs
   stop until you grant again; that is intended.

---

## 5. What the agent will and won't do to a Spring Boot codebase

| Spring / Java construct | Result |
|---|---|
| `private` method/field with zero references, no annotation, no mention in strings or config | `high`, eligible for removal (after tests pass) |
| `@Component`, `@Service`, `@Repository`, `@RestController`, `@Configuration` classes | `low`, never removed |
| `@Bean`, `@Autowired`, `@Value`, `@Scheduled`, `@EventListener`, `@PostConstruct`, `@GetMapping`... | `low` (annotated = possible framework wiring) |
| Fields in `@Entity`, `@Data`, `@Getter`, Jackson DTOs | `low` |
| Names in `application.yml`, `*.properties`, `*.xml`, `META-INF/spring/*.imports`, `spring.factories` | `low` |
| Names inside strings (SpEL such as `@PreAuthorize("@svc.canAccess(#id)")`, `getBean("name")`) | `low` |
| Anything in a file that uses reflection (`getDeclared*`, `setAccessible`, `Class.forName`) | at most `medium` |
| Public / protected / package-private members | `medium` or `low`, **report only** |
| `@Override`, interface and abstract methods, `main`, constructors, serialization hooks | never flagged |
| Fields initialised with `new ...` or a method call | `medium`, report only |
| Test code, `pom.xml`, `build.gradle`, CI files, `src/test/**`, `application*.yml` | never modified (policy-protected) |

**Checked on real code:** the read-only analysis was run against the public Spring PetClinic app (121 files scanned). It reported 32 dead-code candidates, **all `low`** (every controller endpoint, `@InitBinder`, `@ModelAttribute` and `@Configuration` class), so it would have removed nothing, and 4 duplicate blocks in controller logic. That is the intended behaviour for annotation-heavy Spring code.

Expect the **medium/low lists to be long**: they are suggestions for a human, not actions. The agent only removes the small
`high` set, and only if your tests still pass.

Not covered: Kotlin/Groovy sources (only Java is analysed), template engines (Thymeleaf/JSP referencing getters; those are
public members and stay report-only), and callers outside the repo.

---

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Give a Git URL in the 'repo_url' box` | No URL typed and no `TARGET_REPO` default | Fill `repo_url` (`https://github.com/owner/name`) |
| `Not an accepted repository URL` | Not plain `https://github.com/owner/name` (credentials, other host, extra path/query are refused) | Use the plain URL; tokens go in the secret, never in the URL |
| `Consent not given. Type exactly ...` | `confirm` box empty or different from `owner/name` | Type the repository name exactly |
| `... is UNTRUSTED ... Only mode 'analyze' is allowed` | Your token has no write access to that repo (e.g. someone else's public repo) | Use `analyze`, or run against a repo you own/can push to |
| Checkout of the target fails (404/403) | Token not scoped to that repo, expired, or org approval pending | Recreate the read token (step 2) |
| *Baseline not usable: baseline has N failing tests* | Tests need a database, network or services; or Spring context fails offline | Run only unit tests via `test.command` in `.agent.yml`; use H2/embedded config; look at the "Last output" block in the report |
| *Baseline not usable: no tests collected* | No surefire tests found or wrong command | Check `test.command`; the agent refuses to change code it cannot test |
| Output mentions missing artifact / plugin in offline mode | Cache lacks something only needed at test time | Make sure the warm-up step succeeded (`verify` ran); for Gradle projects confirm the wrapper distribution is cached |
| Exit code 137 or "Killed" | Sandbox out of memory | Set variable `SANDBOX_MEMORY=4g` |
| Tests need Docker (Testcontainers) | The sandbox has no Docker socket **by design** | Exclude those tests with `-Dtest=!*IT` / profiles, or accept analyze-only for this repo |
| Tests need `localhost` ports | Fine in Docker (`--network none` keeps loopback) | n/a |
| Run takes too long | Big test suite × 5 runs | `runs_for_baseline: 1`, narrow `test.command`, or schedule less often |
| `docker pull` rate-limited | Docker Hub anonymous limit | Re-run later, or mirror the image to `ghcr.io` and change `SANDBOX_IMAGE` |
| PR creation says "dry-run" | Write token missing/expired or mode not `open-pr` | Step 7 |
| Report says *Java dead-code analysis skipped* | `tree-sitter` packages missing | `pip install -r requirements.txt` (the workflow does this) |

Run `python -m agent doctor` locally, or look at the **Preflight** step in the workflow log, to see what is available.

---

## 7. Security checklist for this deployment

- [ ] The agent repo is **private**; only you can edit the workflow.
- [ ] The **Trust check** step is intact: it is what stops the cache warm-up (which runs the target's own build on the runner) from being used on repos you do not have write access to.
- [ ] The workflow has **no** `pull_request`, `pull_request_target` or `issue_comment` triggers (only manual and optional schedule). Do not add them.
- [ ] `GITHUB_TOKEN` is read-only (`permissions: contents: read`).
- [ ] Fine-grained tokens are limited to **one repo**, expire in 30–90 days, and the write token exists only when needed.
- [ ] In `analyze`/`verify` modes the write token is **not present in the job environment at all**.
- [ ] The Docker sandbox runs with `--network none`, `--cap-drop ALL`, read-only root, non-root user, memory/CPU/process limits, and receives **no tokens**.
- [ ] Only use this deployment for repos you **own or trust**: the warm-up step runs the repo's own Maven/Gradle build once with network access.
- [ ] If your target is public, enable a ruleset on `main`. If private and on the Free plan, stay in `verify` or accept the residual risk (section 3).
- [ ] Optional hardening: pin the third-party actions (`actions/checkout`, `setup-python`, `setup-java`, `cache`, `upload-artifact`) to full commit SHAs.
- [ ] Review every agent PR as you would a contributor's PR, and keep your normal CI required.
- [ ] Standing consent files are committed to the **agent** repo (audit trail), never to the analysed repo, and have a short expiry.

**Stopping everything:** set variable `AGENT_ENABLED=false` (the job is skipped), disable the workflow, and revoke the tokens
(Settings → Developer settings → Fine-grained tokens → Delete).

---

## 8. Using Gradle instead of Maven
The workflow auto-detects `build.gradle` / `build.gradle.kts`. It caches `~/.gradle`, warms it with `./gradlew build`, runs tests
offline in the `gradle:8-jdk<JAVA_VERSION>` image and reads `build/test-results/**/TEST-*.xml`. If your project needs a different
Gradle major version, override the image by editing the `SANDBOX_IMAGE` line in the warm-up step.

## 9. Multi-module projects
`mvn test` at the root runs all modules, and the agent scans every `.java` file across modules for references, so cross-module usage
is respected. Keep `JAVA_VERSION` aligned with the parent POM.

## 10. What the agent does *not* do yet
Coverage gate, duplicate-refactoring PRs, unused-dependency PRs, signed commits, PR labels/reviewers, GitLab merge requests,
Kotlin analysis. See `README.md` roadmap.

---

## 11. Quick local trial (no cloud at all)
```bash
pip install -r requirements.txt
python -m agent doctor
python -m agent analyze /path/to/your/clone-of-the-spring-boot-repo        # read-only, executes nothing
# with Docker installed, full verification:
python -m agent run /path/to/clone --sandbox docker --docker-image maven:3.9-eclipse-temurin-17 \
       --prefetch-network --sandbox-memory 3g
```
`--prefetch-network` runs `mvn dependency:go-offline test-compile` once inside the sandbox with network access but without credentials.
If the offline test run then complains about a missing surefire provider, warm a cache with a normal `mvn verify`
and pass it with `--java-cache ~/.m2` instead (the agent copies it fresh for every run).

## 12. Optional: Oracle Always Free VM
1. Create an Always Free account (a card is needed for identity verification) and an **Ubuntu Arm (A1.Flex)** instance; if you get "out of capacity", retry later or in another availability domain.
2. `sudo apt update && sudo apt install -y git python3-pip python3-venv docker.io openjdk-17-jdk-headless && sudo usermod -aG docker $USER` (log out/in).
3. Clone the agent repo, `pip install -r requirements.txt`, run `python -m agent doctor`.
4. Use the Docker image `maven:3.9-eclipse-temurin-17` (multi-arch, includes Arm) and the commands from section 11.
5. A weekly `cron` entry can start it. Remember Oracle may reclaim VMs that sit idle.
6. Keep tokens in a root-only file (`chmod 600`) and export them only for the run; never commit them.

---

## 13. Send me your Spring Boot repo
* **Public GitHub URL:** I can run the read-only `analyze` pass on it from here and walk through the findings with you. Before I fetch anything I will show you the same access notice and wait for you to confirm the repository name. I cannot download Maven dependencies from this environment, so I cannot run its tests; `verify` has to happen on your Actions run.
* **Private repo:** run the workflow in `analyze` mode and share `report.md` (secrets are redacted in it), or send a zip of the source.
* Tell me the build tool (Maven or Gradle), the Spring Boot version / Java version, and whether tests need external services; I will tune `.agent.yml` for you.
