"""Duplicate code detection (report only).

Line-window clone detection with optional structural normalisation, so renamed variables
and changed literals still match (Type-2 clones). Pure Python, no execution of repo code.
"""
from __future__ import annotations

import keyword
import re
from collections import defaultdict
from pathlib import Path

from ..util import read_text_safe
from .findings import Finding

_STR = re.compile(r"""'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*\"""")
_NUM = re.compile(r"\b\d+(?:\.\d+)?\b")
_ID = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_KEYWORDS = set(keyword.kwlist) | {
    "function", "const", "let", "var", "public", "private", "protected", "static", "void", "int", "func",
    "package", "import", "export", "class", "interface", "new", "this", "throw", "catch", "try", "finally",
    "double", "float", "long", "boolean", "char", "byte", "short", "throws", "extends", "implements", "switch",
    "case", "default", "break", "continue", "do", "abstract", "synchronized", "final", "instanceof", "enum",
}
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "*/")
MAX_GROUP = 12
# getter/setter/annotation boilerplate (after structural normalisation); blocks that are mostly this are noise
_TRIVIAL = [re.compile(x) for x in (
    r"^(?:public |protected |private )?(?:static )?(?:\w+ )?I\((?:I I)?\) \{$",   # accessor-style method header
    r"^return (?:this\.)?I;$", r"^this\.I = I;$", r"^@I(?:\(.*\))?$", r"^@Override$", r"^I = I;$",
)]


def _is_trivial(norm: str) -> bool:
    return any(rx.match(norm) for rx in _TRIVIAL)


def _normalize(line: str) -> str:
    s = _STR.sub("S", line)
    s = _NUM.sub("N", s)
    s = _ID.sub(lambda m: m.group(0) if m.group(0) in _KEYWORDS or m.group(0) in ("S", "N") else "I", s)
    return re.sub(r"\s+", " ", s).strip()


def _prepare(root: Path, rel: str) -> list[tuple[int, str, str]] | None:
    text = read_text_safe(root, rel)
    if text is None:
        return None
    rows = []
    for no, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES) or stripped in ("{", "}", ")", "]", "pass"):
            continue
        if stripped.startswith(("import ", "package ")) or (stripped.startswith("from ") and " import " in stripped):
            continue  # header boilerplate is not meaningful duplication
        rows.append((no, re.sub(r"\s+", " ", stripped), _normalize(stripped)))
    return rows


def find_duplicates(root: Path, files: list[str], min_lines: int = 6, min_chars: int = 120,
                    limit: int = 25) -> list[Finding]:
    data: dict[str, list[tuple[int, str, str]]] = {}
    for rel in files:
        rows = _prepare(root, rel)
        if rows and len(rows) >= min_lines:
            data[rel] = rows

    index: dict[tuple[str, ...], list[tuple[str, int]]] = defaultdict(list)
    for rel, rows in data.items():
        norms = [r[2] for r in rows]
        for i in range(len(rows) - min_lines + 1):
            window = tuple(norms[i : i + min_lines])
            if len(set(window)) < 3:
                continue
            if sum(_is_trivial(w) for w in window) / len(window) >= 0.8:
                continue  # getter/setter boilerplate
            if sum(len(r[1]) for r in rows[i : i + min_lines]) < min_chars:
                continue
            index[window].append((rel, i))

    covered: dict[tuple[str, str, int], list[tuple[int, int]]] = defaultdict(list)
    clones: list[tuple[int, str, int, str, int]] = []  # (length, fileA, idxA, fileB, idxB)
    for occ in index.values():
        if len(occ) < 2:
            continue
        occ = sorted(occ)[:MAX_GROUP]
        for x in range(len(occ)):
            for y in range(x + 1, len(occ)):
                (fa, ia), (fb, ib) = occ[x], occ[y]
                diag = (fa, fb, ia - ib)
                if any(s <= ia <= e for s, e in covered[diag]):
                    continue
                A, B = data[fa], data[fb]
                back = 0
                while ia - back - 1 >= 0 and ib - back - 1 >= 0 and A[ia - back - 1][2] == B[ib - back - 1][2]:
                    back += 1
                fwd = 0
                while ia + fwd < len(A) and ib + fwd < len(B) and A[ia + fwd][2] == B[ib + fwd][2]:
                    fwd += 1
                start_a, start_b, length = ia - back, ib - back, back + fwd
                covered[diag].append((start_a, start_a + length - 1))
                if fa == fb and abs(start_a - start_b) < length:
                    continue  # overlapping self-match
                if length >= min_lines:
                    clones.append((length, fa, start_a, fb, start_b))

    clones.sort(key=lambda c: -c[0])
    findings: list[Finding] = []
    for n, (length, fa, ia, fb, ib) in enumerate(clones[:limit], 1):
        A, B = data[fa], data[fb]
        exact = all(A[ia + k][1] == B[ib + k][1] for k in range(length))
        a_loc = {"file": fa, "start": A[ia][0], "end": A[ia + length - 1][0]}
        b_loc = {"file": fb, "start": B[ib][0], "end": B[ib + length - 1][0]}
        findings.append(Finding(
            id=f"DUP-{n:03d}", type="duplicate", confidence="high" if exact else "medium",
            file=fa, line=a_loc["start"], end_line=a_loc["end"], symbol="", kind="clone",
            evidence=[f"{length} matching lines ({'exact' if exact else 'structural: renamed identifiers/literals'})",
                      f"also at {fb}:{b_loc['start']}-{b_loc['end']}"],
            proposed_action="report_only (suggest extracting shared function)",
            risk="medium", related=[b_loc],
        ))
    return findings
