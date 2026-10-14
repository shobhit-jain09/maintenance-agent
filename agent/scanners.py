"""Deterministic scanners: secrets, prompt-injection-like text. No LLM involved."""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

from .util import match_any, read_text_safe

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
    (
        "generic_secret",
        re.compile(
            r"""(?ix)\b(?:api[_-]?key|secret|token|passwd|password|pwd)\b["']?\s*[:=]\s*["'][^"'\s]{12,}["']"""
        ),
    ),
]

INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("override_instructions", re.compile(r"(?i)ignore (?:all |any |the )?(?:previous|prior|above|earlier) (?:instructions|rules|prompts?)")),
    ("disregard_system", re.compile(r"(?i)disregard (?:the |all )?(?:previous|above|system|safety)")),
    ("address_ai", re.compile(r"(?i)\b(?:note|message|instructions?|attention)\s+(?:to|for)\s+(?:the\s+)?(?:ai|llm|assistant|agent|claude|model|bot)\b")),
    ("exfiltrate", re.compile(r"(?i)\b(?:print|reveal|send|post|upload|exfiltrate|leak)\s+(?:\w+\s+){0,3}(?:all\s+)?(?:the\s+|your\s+)?(?:env(?:ironment)?(?:\s+variables?)?|secrets?|tokens?|credentials?|api[_ -]?keys?)\b.{0,40}\b(?:to|at|via)\b")),
    ("push_to_main", re.compile(r"(?i)\b(?:force[- ])?push\s+(?:\w+\s+)?(?:directly|immediately|straight|forcefully)\s+(?:to|into)\s+(?:the\s+)?(?:main|master|production)\b")),
    ("disable_guardrails", re.compile(r"(?i)\b(?:disable|skip|bypass|turn off)\s+(?:all\s+|the\s+|any\s+)?(?:tests?|security|policy|guardrails?|review|checks)\b")),
]


@dataclass
class SecretFinding:
    kind: str
    file: str
    line: int
    preview: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InjectionFinding:
    kind: str
    file: str
    line: int
    excerpt: str

    def to_dict(self) -> dict:
        return asdict(self)


def _mask(value: str) -> str:
    return (value[:4] + "****") if len(value) > 4 else "****"


def scan_text_for_secrets(text: str, file: str = "<text>") -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for kind, rx in SECRET_PATTERNS:
            m = rx.search(line)
            if m:
                findings.append(SecretFinding(kind, file, lineno, _mask(m.group(0).strip())))
                break
    return findings


def redact_text(text: str) -> str:
    """Replace anything that looks like a secret with a marker."""
    for kind, rx in SECRET_PATTERNS:
        text = rx.sub(f"[REDACTED:{kind}]", text)
    return text


def scan_text_for_injection(text: str, file: str = "<text>") -> list[InjectionFinding]:
    findings: list[InjectionFinding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for kind, rx in INJECTION_PATTERNS:
            if rx.search(line):
                excerpt = redact_text(line.strip())[:120]
                findings.append(InjectionFinding(kind, file, lineno, excerpt))
                break
    return findings


@dataclass
class ScanResult:
    secrets: list[SecretFinding]
    sensitive_files: list[str]
    injections: list[InjectionFinding]
    files_scanned: int


def scan_repo(root: Path, rel_files: Iterable[str], deny_read: Iterable[str]) -> ScanResult:
    """Scan files. Files matching deny_read are NEVER opened; they are only reported by name."""
    deny_read = list(deny_read)
    secrets: list[SecretFinding] = []
    injections: list[InjectionFinding] = []
    sensitive: list[str] = []
    n = 0
    for rel in rel_files:
        if match_any(rel, deny_read):
            sensitive.append(rel)
            continue
        text = read_text_safe(root, rel)
        if text is None:
            continue
        n += 1
        secrets.extend(scan_text_for_secrets(text, rel))
        injections.extend(scan_text_for_injection(text, rel))
    return ScanResult(secrets, sensitive, injections, n)
