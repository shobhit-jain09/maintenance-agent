"""Dead code detection for Python (AST based, never executes repo code).

Conservative by design. A symbol is flagged only when its simple name has ZERO references
anywhere in the repo (excluding references inside its own body). Confidence tiers:

  high   : private (_name), undecorated, no string/config mentions, not an override candidate
  medium : public API or other ambiguity: report only
  low    : likely dynamic wiring (decorators, getattr/dispatch strings, config mentions)
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ..config import CONFIG_TEXT_EXTENSIONS
from ..util import read_text_safe
from .findings import Finding

SAFE_DECORATORS = {"staticmethod", "classmethod", "property", "cached_property", "lru_cache", "cache", "abstractmethod"}
IDENT_RX = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class Definition:
    name: str
    kind: str                # function | class | method
    file: str
    start: int
    end: int
    col: int
    decorators: list[str] = field(default_factory=list)
    class_bases: list[str] = field(default_factory=list)
    parent_class: str | None = None


def is_test_file(rel: str) -> bool:
    p = Path(rel)
    return (any(part in ("tests", "test") for part in p.parts) or p.name.startswith("test_")
            or p.name.endswith("_test.py") or p.name == "conftest.py")


def _dec_name(node: ast.expr) -> str:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return "<expr>"


def _base_name(node: ast.expr) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return "<expr>"


def _span(node: ast.AST) -> tuple[int, int]:
    start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
    return start, node.end_lineno or node.lineno


def _collect_defs(tree: ast.Module, rel: str) -> list[Definition]:
    defs: list[Definition] = []

    def visit_body(body: list[ast.stmt], parent: ast.ClassDef | None) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                s, e = _span(node)
                defs.append(Definition(node.name, "method" if parent else "function", rel, s, e, node.col_offset,
                                       [_dec_name(d) for d in node.decorator_list],
                                       [_base_name(b) for b in parent.bases] if parent else [],
                                       parent.name if parent else None))
            elif isinstance(node, ast.ClassDef):
                s, e = _span(node)
                defs.append(Definition(node.name, "class", rel, s, e, node.col_offset,
                                       [_dec_name(d) for d in node.decorator_list],
                                       [_base_name(b) for b in node.bases]))
                visit_body(node.body, node)
            elif isinstance(node, (ast.If, ast.Try)) and parent is None:
                visit_body(getattr(node, "body", []), None)  # defs under `if TYPE_CHECKING` etc.

    visit_body(tree.body, None)
    return defs


def analyze_dead_code(root: Path, py_files: list[str], all_files: list[str]) -> tuple[list[Finding], list[str]]:
    """Returns (findings, skipped_files_that_failed_to_parse)."""
    defs: list[Definition] = []
    refs: dict[str, list[tuple[str, int]]] = defaultdict(list)
    str_refs: set[str] = set()
    skipped: list[str] = []

    for rel in py_files:
        text = read_text_safe(root, rel)
        if text is None:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            skipped.append(rel)
            continue
        if not is_test_file(rel):
            defs.extend(_collect_defs(tree, rel))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                refs[node.id].append((rel, node.lineno))
            elif isinstance(node, ast.Attribute):
                refs[node.attr].append((rel, node.lineno))
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for a in node.names:
                    refs[a.name.split(".")[-1]].append((rel, node.lineno))
                    refs[a.name.split(".")[0]].append((rel, node.lineno))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) <= 120:
                for tok in IDENT_RX.findall(node.value):
                    str_refs.add(tok)

    text_tokens: set[str] = set()
    for rel in all_files:
        if any(rel.endswith(ext) for ext in CONFIG_TEXT_EXTENSIONS):
            t = read_text_safe(root, rel)
            if t:
                text_tokens.update(IDENT_RX.findall(t))

    findings: list[Finding] = []
    flagged_classes: dict[tuple[str, str], str] = {}
    n = 0
    # classes first so their members are not reported separately
    for d in sorted(defs, key=lambda x: (x.kind != "class", x.file, x.start)):
        if d.name.startswith("__") and d.name.endswith("__"):
            continue
        if d.name in ("main", "setup", "teardown", "setUp", "tearDown"):
            continue
        if d.kind == "method" and (d.file, d.parent_class or "") in flagged_classes:
            if flagged_classes[(d.file, d.parent_class or "")] == "high" or not d.name.startswith("_"):
                continue
        outside = [(f, ln) for f, ln in refs.get(d.name, []) if not (f == d.file and d.start <= ln <= d.end)]
        if outside:
            continue

        evidence = [f"0 references to '{d.name}' in {len(py_files)} Python files (AST, excluding own body)"]
        private = d.name.startswith("_")
        framework = [x for x in d.decorators if x not in SAFE_DECORATORS]
        non_trivial_bases = [b for b in d.class_bases if b not in ("object",)]
        if framework:
            conf = "low"
            evidence.append(f"decorated with {', '.join(framework)}: possible framework registration")
        elif d.name in str_refs:
            conf = "low"
            evidence.append("name appears inside a string literal: possible dynamic dispatch/getattr")
        elif d.name in text_tokens:
            conf = "low"
            evidence.append("name appears in a config/data file")
        elif d.kind == "method" and non_trivial_bases:
            conf = "medium"
            evidence.append(f"method of class with base classes ({', '.join(non_trivial_bases)}): may override/implement a hook")
        elif private:
            conf = "high"
            evidence.append("private (underscore) symbol; no string or config mentions")
        else:
            conf = "medium"
            evidence.append("public symbol: may be external API")

        n += 1
        if d.kind == "class":
            flagged_classes[(d.file, d.name)] = conf
        findings.append(Finding(
            id=f"DC-{n:03d}", type="dead_code", confidence=conf, file=d.file, line=d.start, end_line=d.end,
            symbol=(f"{d.parent_class}.{d.name}" if d.parent_class else d.name), kind=d.kind, evidence=evidence,
            proposed_action="remove" if conf == "high" else "report_only",
            risk="low" if conf == "high" else "medium", col=d.col,
        ))
    return findings, skipped
