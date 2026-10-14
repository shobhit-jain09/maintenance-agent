"""Build patches inside a scratch copy. Output is a unified diff (data), never a push."""
from __future__ import annotations

import ast
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .analyzers.findings import Finding
from .analyzers import javacode

try:
    from tree_sitter import Parser as _TSParser
except Exception:  # pragma: no cover
    _TSParser = None


@dataclass
class PatchResult:
    patch: str
    applied: list[Finding] = field(default_factory=list)
    skipped: list[tuple[Finding, str]] = field(default_factory=list)


def _blank(line: str) -> bool:
    return not line.strip()


def _extend_for_leading_comments(lines: list[str], start0: int) -> int:
    while start0 > 0 and lines[start0 - 1].lstrip().startswith("#") and (len(lines[start0 - 1]) - len(lines[start0 - 1].lstrip())) == (len(lines[start0]) - len(lines[start0].lstrip())):
        start0 -= 1
    return start0


def _tidy(lines: list[str], at: int, col: int) -> list[str]:
    """Normalise blank lines around the junction left by a removal."""
    i0 = at
    while i0 > 0 and _blank(lines[i0 - 1]):
        i0 -= 1
    i1 = at
    while i1 < len(lines) and _blank(lines[i1]):
        i1 += 1
    if i0 == 0 or i1 >= len(lines):
        keep = 0
    else:
        keep = 2 if col == 0 else 1
    out = lines[:i0] + ["\n"] * keep + lines[i1:]
    if out and not out[-1].endswith("\n"):
        out[-1] += "\n"
    return out


def _extend_leading_comments_java(lines: list[str], start0: int) -> int:
    """Include a javadoc/block comment or // comments sitting directly above the declaration."""
    i = start0
    while i > 0:
        prev = lines[i - 1].strip()
        if prev.startswith("//"):
            i -= 1
            continue
        if prev.endswith("*/"):
            j = i - 1
            while j >= 0 and "/*" not in lines[j]:
                j -= 1
            if j >= 0 and lines[j].strip().startswith("/*"):
                i = j
                continue
        break
    return i


def _tidy_java(lines: list[str], at: int) -> list[str]:
    """Keep exactly one blank line between members; none right after '{' or before '}'."""
    i0 = at
    while i0 > 0 and _blank(lines[i0 - 1]):
        i0 -= 1
    i1 = at
    while i1 < len(lines) and _blank(lines[i1]):
        i1 += 1
    if i0 == 0 or i1 >= len(lines):
        keep = 0
    elif lines[i0 - 1].rstrip().endswith("{") or lines[i1].lstrip().startswith("}"):
        keep = 0
    else:
        keep = 1
    out = lines[:i0] + ["\n"] * keep + lines[i1:]
    if out and not out[-1].endswith("\n"):
        out[-1] += "\n"
    return out


def _java_ok(parser, text: str) -> bool:
    return not parser.parse(text.encode("utf-8")).root_node.has_error


def _contained(f: Finding, others: list[Finding]) -> bool:
    return any(o is not f and o.file == f.file and o.line <= f.line and f.end_line <= o.end_line
               and (o.line, o.end_line) != (f.line, f.end_line) for o in others)


def build_dead_code_patch(snapshot_copy: Path, findings: list[Finding]) -> PatchResult:
    """Remove findings from `snapshot_copy` (a scratch git working tree) and return the diff."""
    result = PatchResult(patch="")
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if _contained(f, findings):
            result.skipped.append((f, "contained in another removed symbol"))
            continue
        by_file[f.file].append(f)

    for rel, items in by_file.items():
        path = snapshot_copy / rel
        if path.is_symlink() or not path.is_file():
            result.skipped.extend((f, "not a regular file") for f in items)
            continue
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        is_java = rel.endswith(".java")
        parser = None
        if is_java:
            if _TSParser is None or javacode._LANG is None or not _java_ok(_TSParser(javacode._LANG), "".join(lines)):
                result.skipped.extend((f, "cannot validate Java syntax for this file") for f in items)
                continue
            parser = _TSParser(javacode._LANG)
        changed = False
        for f in sorted(items, key=lambda x: -x.line):
            if is_java:
                start0 = _extend_leading_comments_java(lines, f.line - 1)
                candidate = _tidy_java(lines[:start0] + lines[f.end_line:], start0)
                if not _java_ok(parser, "".join(candidate)):
                    result.skipped.append((f, "removal would break Java syntax"))
                    continue
            else:
                start0 = _extend_for_leading_comments(lines, f.line - 1)
                candidate = _tidy(lines[:start0] + lines[f.end_line:], start0, f.col)
                try:
                    ast.parse("".join(candidate))
                except SyntaxError as exc:
                    result.skipped.append((f, f"removal would break syntax ({exc.msg})"))
                    continue
            lines = candidate
            result.applied.append(f)
            changed = True
        if changed:
            path.write_text("".join(lines), encoding="utf-8")

    diff = subprocess.run(["git", "diff", "--no-color", "-U3"], cwd=snapshot_copy, capture_output=True,
                          text=True, errors="replace")
    result.patch = diff.stdout
    return result
