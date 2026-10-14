"""Deterministic policy engine. This, not the prompt, is the security boundary.

Every patch, branch name, file read and command is checked here before it is allowed.
Policy comes from the control plane (built-in defaults, optionally a policy.yml).
Repo-supplied config may only TIGHTEN policy.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import scanners
from .util import match_any

DEFAULT_POLICY: dict[str, Any] = {
    "git": {
        "allowed_branch_pattern": r"^agent/(dead-code|duplicates|unused-deps)/[0-9]{8}-[a-z0-9]{6}$",
        "protected_branches": ["main", "master", "develop", "release/*", "production"],
    },
    "patch": {
        "max_files": 15,
        "max_changed_lines": 300,
        "allow_binary": False,
        "allow_mode_change": False,
        "allow_new_files": False,
        "protected_paths": [
            ".github/**", ".gitlab-ci.yml", ".circleci/**", "Jenkinsfile", "azure-pipelines.yml",
            "CODEOWNERS", "**/CODEOWNERS", ".agent.yml", "policy.yml",
            "Dockerfile*", "docker-compose*.yml", "Makefile",
            "setup.py", "setup.cfg", "pyproject.toml", "tox.ini", "package.json", "package-lock.json",
            "yarn.lock", "poetry.lock", "Pipfile*", "requirements*.txt", "go.mod", "go.sum", "pom.xml",
            "infra/**", "terraform/**", "deploy/**", "**/*.tf",
            ".env*", "**/secrets/**", "*.pem", "*.key",
            "tests/**", "test/**", "**/test_*.py", "**/*_test.py", "**/conftest.py",
            "**/*.test.*", "**/*.spec.*", "pytest.ini",
            # Java / JVM
            "pom.xml", "**/pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
            "gradle/**", "gradle.properties", "gradlew", "gradlew.bat", "mvnw", "mvnw.cmd", ".mvn/**", "build.xml",
            "**/src/test/**", "**/*Test.java", "**/*Tests.java", "**/*IT.java", "**/*TestCase.java",
            "**/META-INF/**", "**/application*.properties", "**/application*.yml",
        ],
        "forbidden_added_patterns": [
            r"\beval\(", r"\bexec\(", r"\bos\.system\(", r"\bsubprocess\b", r"\bchild_process\b",
            r"\bbase64\b", r"__import__", r"\bsocket\b", r"\burllib\b", r"\brequests\.", r"https?://",
            r"\bRuntime\.getRuntime\b", r"\bProcessBuilder\b", r"\bURLClassLoader\b", r"\bClass\.forName\b",
            r"\bjava\.net\.", r"\bjavax\.script\b", r"\bSystem\.(?:exit|setProperty)\b",
        ],
    },
    "secrets": {
        "deny_read": [
            ".env*", "**/.env*", "*.pem", "*.key", "id_rsa*", "**/id_rsa*", "**/secrets/**",
            "**/credentials*", "*.p12", "*.pfx", ".npmrc", ".pypirc", ".netrc", "**/.aws/**", "**/.ssh/**",
        ],
    },
    "sandbox": {
        "allowed_executables": ["python", "python3", "pytest", "npm", "npx", "node", "go", "mvn", "mvnw", "gradle",
                                "gradlew", "ant", "cargo"],
    },
    "limits": {"max_llm_calls": 30, "max_retries": 2, "run_timeout_minutes": 45},
    "consent": {"allowed_hosts": ["github.com"], "max_standing_days": 90},
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_policy(path: str | Path | None = None) -> dict[str, Any]:
    if path and Path(path).is_file():
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return _deep_merge(DEFAULT_POLICY, raw)
    return copy.deepcopy(DEFAULT_POLICY)


@dataclass
class Decision:
    reasons: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return not self.reasons

    def __bool__(self) -> bool:
        return self.allowed


@dataclass
class PatchInfo:
    files: list[str] = field(default_factory=list)
    added_lines: list[tuple[str, str]] = field(default_factory=list)  # (file, text)
    added: int = 0
    removed: int = 0
    binary: bool = False
    mode_changes: list[str] = field(default_factory=list)
    new_files: list[str] = field(default_factory=list)
    renames: list[str] = field(default_factory=list)


def parse_patch(text: str) -> PatchInfo:
    info = PatchInfo()
    current: str | None = None
    in_hunk = False
    for line in text.splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
            m = re.match(r"diff --git a/(.+?) b/(.+)$", line)
            current = m.group(2) if m else None
            if current and current not in info.files:
                info.files.append(current)
            continue
        if line.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk:
            if line.startswith(("old mode", "new mode")):
                info.mode_changes.append(f"{current}: {line}")
            elif line.startswith("new file mode"):
                info.new_files.append(current or "?")
                if not line.endswith("100644"):
                    info.mode_changes.append(f"{current}: {line}")
            elif line.startswith(("rename from", "rename to", "copy from", "copy to")):
                info.renames.append(f"{current}: {line}")
            elif line.startswith(("Binary files", "GIT binary patch")):
                info.binary = True
            continue
        if line.startswith("+"):
            info.added += 1
            info.added_lines.append((current or "?", line[1:]))
        elif line.startswith("-"):
            info.removed += 1
    return info


class PolicyEngine:
    def __init__(self, policy: dict[str, Any] | None = None, repo_protected: list[str] | None = None,
                 repo_max_changed_lines: int | None = None):
        self.policy = policy or load_policy()
        patch = self.policy["patch"]
        self.protected_paths = list(patch["protected_paths"]) + list(repo_protected or [])
        self.max_files = int(patch["max_files"])
        self.max_changed_lines = int(patch["max_changed_lines"])
        if repo_max_changed_lines is not None:  # tighten only
            self.max_changed_lines = min(self.max_changed_lines, repo_max_changed_lines)
        self._branch_rx = re.compile(self.policy["git"]["allowed_branch_pattern"])
        self._forbidden = [re.compile(p) for p in patch["forbidden_added_patterns"]]

    # ---- branch -------------------------------------------------------------------
    def check_branch(self, name: str) -> Decision:
        d = Decision()
        if not self._branch_rx.match(name):
            d.reasons.append(f"branch '{name}' does not match allowed pattern")
        if match_any(name, self.policy["git"]["protected_branches"]):
            d.reasons.append(f"branch '{name}' is protected")
        return d

    # ---- reads --------------------------------------------------------------------
    def check_read(self, rel_path: str) -> Decision:
        d = Decision()
        if rel_path.startswith("/") or ".." in Path(rel_path).parts:
            d.reasons.append(f"path escapes snapshot: {rel_path}")
        if match_any(rel_path, self.policy["secrets"]["deny_read"]):
            d.reasons.append(f"read denied (sensitive path): {rel_path}")
        return d

    @property
    def deny_read(self) -> list[str]:
        return self.policy["secrets"]["deny_read"]

    # ---- commands -----------------------------------------------------------------
    def check_command(self, cmd: list[str]) -> Decision:
        d = Decision()
        if not cmd:
            d.reasons.append("empty command")
            return d
        exe = Path(cmd[0]).name
        if exe not in self.policy["sandbox"]["allowed_executables"]:
            d.reasons.append(f"executable '{exe}' is not allowlisted")
        if any(ch in a for a in cmd for ch in (";", "|", "&&", "`", "$(")):
            d.reasons.append("shell metacharacters are not allowed in commands")
        return d

    # ---- patch --------------------------------------------------------------------
    def check_patch(self, patch_text: str) -> Decision:
        d = Decision()
        if not patch_text.strip():
            d.reasons.append("empty patch")
            return d
        info = parse_patch(patch_text)
        p = self.policy["patch"]
        if len(info.files) > self.max_files:
            d.reasons.append(f"too many files changed ({len(info.files)} > {self.max_files})")
        if info.added + info.removed > self.max_changed_lines:
            d.reasons.append(f"diff too large ({info.added + info.removed} > {self.max_changed_lines} lines)")
        for f in info.files:
            if match_any(f, self.protected_paths):
                d.reasons.append(f"protected path modified: {f}")
        if info.binary and not p["allow_binary"]:
            d.reasons.append("binary changes are not allowed")
        if info.mode_changes and not p["allow_mode_change"]:
            d.reasons.append(f"file mode changes are not allowed: {info.mode_changes[0]}")
        if info.new_files and not p["allow_new_files"]:
            d.reasons.append(f"new files are not allowed: {info.new_files[0]}")
        if info.renames:
            d.reasons.append(f"renames/copies are not allowed: {info.renames[0]}")
        for file, line in info.added_lines:
            for rx in self._forbidden:
                if rx.search(line):
                    d.reasons.append(f"forbidden pattern /{rx.pattern}/ in added line of {file}")
                    break
        added_text = "\n".join(l for _, l in info.added_lines)
        if scanners.scan_text_for_secrets(added_text):
            d.reasons.append("possible secret in added lines")
        return d
