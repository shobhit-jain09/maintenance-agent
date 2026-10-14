"""Git operations. Runs ONLY in the control plane; the sandbox never sees these credentials.

Tokens are passed via GIT_CONFIG_* env vars (not argv), scoped per call, never logged.
There is deliberately no force-push, no merge, no tag, and no approve function here.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from .policy import PolicyEngine

BOT_NAME = "maintenance-agent[bot]"
BOT_EMAIL = "maintenance-agent@users.noreply.invalid"


class GitError(Exception):
    pass


def _auth_env(token: str | None, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "SSL_CERT_FILE")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env.update(extra or {})
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
                    "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}"})
    return env


def git(args: list[str], cwd: Path | None = None, token: str | None = None, check: bool = True,
        extra_env: dict[str, str] | None = None) -> str:
    cp = subprocess.run(["git", *args], cwd=str(cwd) if cwd else None, env=_auth_env(token, extra_env),
                        capture_output=True, text=True, errors="replace", timeout=300)
    if check and cp.returncode != 0:
        msg = (cp.stderr or cp.stdout).strip()
        raise GitError(f"git {args[0]} failed: {msg[:300]}")
    return cp.stdout.strip()


def clone(repo: str, dest: Path, read_token: str | None = None, local: bool = False) -> str:
    """Clone with hooks disabled. Returns the pinned HEAD sha.

    Hardening: only the https (or, for local paths, file) transport is allowed, so exotic transports such as
    ext:: cannot be used; '--' stops an option-looking value from being parsed as a git flag; the read token is
    never used for local clones.
    """
    git(["-c", "core.hooksPath=/dev/null", "clone", "--no-hardlinks", "--quiet", "--", repo, str(dest)],
        token=None if local else read_token, extra_env={"GIT_ALLOW_PROTOCOL": "file" if local else "https"})
    return git(["rev-parse", "HEAD"], cwd=dest)


def default_branch(repo_dir: Path) -> str:
    return git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_dir)


def apply_patch(repo_dir: Path, patch_text: str) -> None:
    p = subprocess.run(["git", "apply", "--whitespace=nowarn", "-"], cwd=repo_dir, input=patch_text,
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise GitError(f"patch does not apply: {p.stderr.strip()[:300]}")


def create_branch_commit_push(snapshot_dir: Path, branch: str, patch_text: str, message: str,
                              policy: PolicyEngine, write_token: str | None, push: bool = True) -> dict:
    decision = policy.check_branch(branch)
    if not decision:
        raise GitError("branch rejected by policy: " + "; ".join(decision.reasons))
    pd = policy.check_patch(patch_text)
    if not pd:
        raise GitError("patch rejected by policy: " + "; ".join(pd.reasons))
    base = default_branch(snapshot_dir)
    git(["checkout", "-b", branch], cwd=snapshot_dir)
    apply_patch(snapshot_dir, patch_text)
    git(["add", "-A"], cwd=snapshot_dir)
    git(["-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_EMAIL}", "-c", "commit.gpgsign=false",
         "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", message], cwd=snapshot_dir)
    sha = git(["rev-parse", "HEAD"], cwd=snapshot_dir)
    pushed = False
    if push:
        # explicit refspec: only this agent branch can be written. Never --force.
        git(["push", "origin", f"refs/heads/{branch}:refs/heads/{branch}"], cwd=snapshot_dir, token=write_token)
        pushed = True
    return {"branch": branch, "base": base, "commit": sha, "pushed": pushed}


def parse_github_slug(remote_url: str) -> str | None:
    m = re.search(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$", remote_url)
    return f"{m.group(1)}/{m.group(2)}" if m else None


def open_github_pr(remote_url: str, head: str, base: str, title: str, body: str, token: str | None) -> dict:
    """Create a PR through the GitHub API. Returns {'url':..} or {'dry_run': True, 'reason':..}."""
    slug = parse_github_slug(remote_url)
    if not slug or not token:
        return {"dry_run": True, "reason": "no GitHub remote/token configured; PR body saved locally"}
    req = urllib.request.Request(
        f"https://api.github.com/repos/{slug}/pulls", method="POST",
        data=json.dumps({"title": title, "head": head, "base": base, "body": body, "draft": False}).encode(),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode())
        return {"url": payload.get("html_url"), "number": payload.get("number")}
    except urllib.error.HTTPError as e:
        return {"dry_run": True, "reason": f"GitHub API error {e.code}"}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"dry_run": True, "reason": f"network error: {e}"}
