"""Per-repository configuration loaded from `.agent.yml`.

SECURITY NOTE: this file lives inside the repo being analysed, so it is UNTRUSTED input.
It can tune analysis and *tighten* policy (extra protected paths, lower limits), but it
can never loosen the control-plane policy (see policy.PolicyEngine).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
LANG_EXTENSIONS = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".mjs"],
    "typescript": [".ts", ".tsx"],
    "java": [".java"],
    "go": [".go"],
}
CONFIG_TEXT_EXTENSIONS = [".toml", ".cfg", ".ini", ".yaml", ".yml", ".json", ".xml", ".properties",
                          ".gradle", ".kts", ".factories", ".imports"]
DEFAULT_IGNORES = [
    "target/**", ".gradle/**", ".idea/**",
    ".git/**", ".venv/**", "venv/**", "node_modules/**", "build/**", "dist/**",
    "**/__pycache__/**", ".agent_junit_*.xml", "**/*.egg-info/**", ".tox/**", ".mypy_cache/**",
]


@dataclass
class AgentConfig:
    enabled: bool = True
    languages: list[str] | None = None            # None = auto-detect from file extensions
    test_command: list[str] | None = None          # None = auto-detect (pytest / maven / gradle / ant)
    test_reports: list[str] | None = None          # JUnit XML globs for non-pytest runners
    test_covers: list[str] | None = None           # languages whose changes this command can verify
    build_tool: str = ""                           # filled by resolve_runtime
    baseline_runs: int = 2
    test_timeout: int = 600
    dup_min_lines: int = 6
    dup_min_chars: int = 120
    ignore_paths: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORES))
    allowed_change_types: list[str] = field(default_factory=lambda: ["dead_code"])
    min_confidence: str = "high"
    protected_modules: list[str] = field(default_factory=list)
    max_prs_per_run: int = 3
    extra_verify_commands: list[list[str]] = field(default_factory=list)
    classification: str = "internal"

    @property
    def extensions(self) -> list[str]:
        exts: list[str] = []
        for lang in (self.languages or []):
            exts.extend(LANG_EXTENSIONS.get(lang, []))
        return exts

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AgentConfig":
        cfg = cls()
        if not isinstance(raw, dict):
            return cfg
        cfg.enabled = bool(raw.get("enabled", cfg.enabled))
        if isinstance(raw.get("languages"), list):
            cfg.languages = [str(x) for x in raw["languages"]]
        test = raw.get("test") or {}
        if isinstance(test.get("command"), list) and all(isinstance(x, str) for x in test["command"]):
            cfg.test_command = test["command"]
        if isinstance(test.get("reports"), list):
            cfg.test_reports = [str(x) for x in test["reports"]]
        if isinstance(test.get("covers"), list):
            cfg.test_covers = [str(x) for x in test["covers"]]
        cfg.baseline_runs = max(1, min(5, int(test.get("runs_for_baseline", cfg.baseline_runs))))
        cfg.test_timeout = max(10, min(3600, int(test.get("timeout", cfg.test_timeout))))
        dup = (raw.get("analysis") or {}).get("duplicates") or {}
        cfg.dup_min_lines = max(3, int(dup.get("min_lines", cfg.dup_min_lines)))
        cfg.dup_min_chars = max(40, int(dup.get("min_chars", cfg.dup_min_chars)))
        extra_ignore = (raw.get("analysis") or {}).get("ignore_paths") or []
        cfg.ignore_paths = list(DEFAULT_IGNORES) + [str(p) for p in extra_ignore]
        changes = raw.get("changes") or {}
        if isinstance(changes.get("allowed_types"), list):
            cfg.allowed_change_types = [str(x) for x in changes["allowed_types"]]
        if changes.get("min_confidence") in CONFIDENCE_RANK:
            cfg.min_confidence = changes["min_confidence"]
        cfg.protected_modules = [str(p) for p in (raw.get("protected_modules") or [])]
        cfg.max_prs_per_run = max(0, min(10, int((raw.get("limits") or {}).get("max_prs_per_run", cfg.max_prs_per_run))))
        verify = raw.get("verify") or {}
        cmds = verify.get("extra_commands") or []
        cfg.extra_verify_commands = [c for c in cmds if isinstance(c, list) and all(isinstance(x, str) for x in c)]
        cfg.classification = str(raw.get("classification", cfg.classification))
        return cfg

    @classmethod
    def load(cls, repo_root: Path) -> "AgentConfig":
        path = Path(repo_root) / ".agent.yml"
        if not path.is_file() or path.is_symlink():
            return cls()
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")[:100_000]) or {}
        except (yaml.YAMLError, OSError, ValueError):
            return cls()
        return cls.from_dict(raw)


DEFAULT_PYTEST = ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]


def detect_languages(files: list[str]) -> list[str]:
    found = []
    for lang, exts in LANG_EXTENSIONS.items():
        if any(f.endswith(tuple(exts)) for f in files):
            found.append(lang)
    return found


def _resolve(self: "AgentConfig", root: Path, files: list[str]) -> list[str]:
    """Fill in languages / test command / report globs. Returns human-readable notes."""
    notes: list[str] = []
    root = Path(root)
    if self.languages is None:
        self.languages = detect_languages(files) or []
        notes.append(f"languages auto-detected: {', '.join(self.languages) or 'none'}")
    has = lambda name: (root / name).is_file() and not (root / name).is_symlink()  # noqa: E731
    if has("pom.xml"):
        self.build_tool = "maven"
    elif has("build.gradle") or has("build.gradle.kts"):
        self.build_tool = "gradle"
    elif has("build.xml"):
        self.build_tool = "ant"
    elif "python" in self.languages:
        self.build_tool = "pytest"
    if self.test_command is None:
        java = "java" in self.languages
        if java and self.build_tool == "maven":
            self.test_command = [("./mvnw" if has("mvnw") else "mvn"), "-B", "-o", "-q", "test"]
        elif java and self.build_tool == "gradle":
            self.test_command = [("./gradlew" if has("gradlew") else "gradle"), "--offline", "-q", "test"]
        elif "python" in self.languages:
            self.test_command = list(DEFAULT_PYTEST)
            self.build_tool = "pytest"
        elif self.build_tool == "ant":
            self.test_command = ["ant", "test"]
        if self.test_command is not None and self.build_tool in ("maven", "gradle", "ant") and "python" in self.languages:
            notes.append(f"mixed repo: running {self.build_tool} tests only; Python changes will NOT be attempted "
                         "(set test.command and test.covers to verify both)")
        if self.test_command is not None:
            notes.append(f"test command auto-detected: {' '.join(self.test_command)}")
        custom = False
    else:
        custom = True
        if any("pytest" in p for p in self.test_command):
            self.build_tool = self.build_tool or "pytest"
    is_pytest = self.test_command is not None and any("pytest" in p for p in self.test_command)
    if self.test_reports is None and not is_pytest:
        self.test_reports = {"maven": ["**/surefire-reports/TEST-*.xml", "**/failsafe-reports/TEST-*.xml"],
                             "gradle": ["**/test-results/**/TEST-*.xml"]}.get(self.build_tool, ["**/TEST-*.xml"])
    if self.test_covers is None and self.test_command is not None:
        if custom and not is_pytest and self.build_tool == "":
            self.test_covers = list(self.languages)
        elif is_pytest:
            self.test_covers = ["python"]
        else:
            self.test_covers = ["java"]
    return notes


AgentConfig.resolve_runtime = _resolve  # type: ignore[attr-defined]
