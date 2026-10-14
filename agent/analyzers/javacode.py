"""Dead code detection for Java (tree-sitter based, never compiles or executes repo code).

Same conservative philosophy as the Python analyser: a symbol is flagged only when its simple
name has ZERO references in the repo (declaration names and references inside its own body are
excluded). Java-specific traps are handled explicitly:

  * reflection (getDeclaredMethod/setAccessible/Class.forName in the same file) -> capped at medium
  * annotations (Spring/JPA/Lombok/JUnit/...) -> low: possible framework wiring
  * @Override, interface/abstract methods, serialization hooks, main(), constructors -> never flagged
  * fields whose initialiser has side effects (new/method call) -> medium, never auto-removed
  * classes that extend/implement something, or appear in XML/properties/META-INF -> low
  * only PRIVATE members and PRIVATE nested types can reach 'high'
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ..config import CONFIG_TEXT_EXTENSIONS
from ..util import read_text_safe
from .findings import Finding

try:  # optional dependency: degrade gracefully with a clear note
    import tree_sitter_java
    from tree_sitter import Language, Parser

    _LANG = Language(tree_sitter_java.language())
except Exception:  # pragma: no cover - exercised only when the package is missing
    _LANG = None

TYPE_NODES = {"class_declaration": "class", "interface_declaration": "interface", "enum_declaration": "enum",
              "record_declaration": "record", "annotation_type_declaration": "annotation"}
SAFE_ANNOTATIONS = {"SuppressWarnings", "Deprecated", "SafeVarargs", "FunctionalInterface", "SuppressFBWarnings",
                    "VisibleForTesting", "Nullable", "NonNull", "NotNull"}
SERIALIZATION_HOOKS = {"readObject", "writeObject", "readResolve", "writeReplace", "readObjectNoData", "serialVersionUID"}
OBJECT_METHODS = {"toString", "equals", "hashCode", "compareTo", "clone", "finalize", "close"}
REFLECTION_RX = re.compile(r"getDeclared(?:Method|Field|Methods|Fields|Constructor)|setAccessible|Class\.forName|"
                           r"MethodHandles|\.getMethod\(|\.getField\(|ServiceLoader")
IDENT_RX = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SERVICE_FILE_RX = re.compile(r"(^|/)META-INF/(services|spring)/")


def available() -> bool:
    return _LANG is not None


def is_java_test_file(rel: str) -> bool:
    p = Path(rel)
    return (any(part in ("test", "tests", "it") for part in p.parts[:-1]) or p.name.endswith(("Test.java", "Tests.java", "IT.java", "TestCase.java"))
            or p.name.startswith("Test"))


@dataclass
class JDef:
    name: str
    kind: str                      # method | field | class | interface | enum | record | annotation
    file: str
    start: int
    end: int
    col: int
    modifiers: set[str] = field(default_factory=set)
    annotations: list[str] = field(default_factory=list)
    owner: str | None = None
    owner_annotations: list[str] = field(default_factory=list)
    owner_supertypes: list[str] = field(default_factory=list)
    owner_kind: str = ""
    nested: bool = False
    multi_declarator: bool = False
    side_effect_init: bool = False
    shares_line: bool = False
    is_abstract: bool = False


def _text(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _modifiers(src: bytes, node) -> tuple[set[str], list[str]]:
    mods: set[str] = set()
    anns: list[str] = []
    for c in node.children:
        if c.type == "modifiers":
            for m in c.children:
                if m.type in ("marker_annotation", "annotation"):
                    nm = m.child_by_field_name("name")
                    anns.append(_text(src, nm).split(".")[-1] if nm else "?")
                else:
                    mods.add(m.type)
    return mods, anns


def _supertypes(src: bytes, node) -> list[str]:
    out: list[str] = []
    for c in node.children:
        if c.type in ("superclass", "super_interfaces", "extends_interfaces"):
            out += [t for t in IDENT_RX.findall(_text(src, c)) if t not in ("extends", "implements")]
    return out


def _has_side_effects(node) -> bool:
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in ("method_invocation", "object_creation_expression", "assignment_expression",
                      "update_expression", "lambda_expression", "array_creation_expression"):
            return True
        stack.extend(n.children)
    return False


def _members(body):
    for c in body.children:
        if c.type == "enum_body_declarations":
            yield from c.children
        else:
            yield c


def _collect(src: bytes, tree, rel: str, lines: list[str]) -> tuple[list[JDef], set[int]]:
    defs: list[JDef] = []
    decl_name_pos: set[int] = set()

    def line_shared(node) -> bool:
        r0, c0 = node.start_point
        r1, c1 = node.end_point
        before = lines[r0][:c0].strip() if r0 < len(lines) else ""
        after = lines[r1][c1:].strip() if r1 < len(lines) else ""
        return bool(before) or bool(after)

    def visit_type(node, owner: str | None, owner_anns: list[str], nested: bool, outer_supers: list[str]) -> None:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return
        decl_name_pos.add(name_node.start_byte)
        mods, anns = _modifiers(src, node)
        name = _text(src, name_node)
        supers = _supertypes(src, node)
        qual = f"{owner}.{name}" if owner else name
        defs.append(JDef(name, TYPE_NODES[node.type], rel, node.start_point[0] + 1, node.end_point[0] + 1,
                         node.start_point[1], mods, anns, owner, owner_anns, supers, "", nested,
                         shares_line=line_shared(node)))
        body = node.child_by_field_name("body")
        if body is None:
            return
        for m in _members(body):
            if m.type in TYPE_NODES:
                visit_type(m, qual, anns, True, supers)
            elif m.type == "method_declaration":
                nn = m.child_by_field_name("name")
                if nn is None:
                    continue
                decl_name_pos.add(nn.start_byte)
                mmods, manns = _modifiers(src, m)
                defs.append(JDef(_text(src, nn), "method", rel, m.start_point[0] + 1, m.end_point[0] + 1,
                                 m.start_point[1], mmods, manns, qual, anns, supers, TYPE_NODES[node.type], False,
                                 shares_line=line_shared(m),
                                 is_abstract=("abstract" in mmods or m.child_by_field_name("body") is None)))
            elif m.type == "constructor_declaration":
                nn = m.child_by_field_name("name")
                if nn is not None:
                    decl_name_pos.add(nn.start_byte)
            elif m.type == "field_declaration":
                fmods, fanns = _modifiers(src, m)
                decls = [c for c in m.children if c.type == "variable_declarator"]
                for d in decls:
                    nn = d.child_by_field_name("name")
                    if nn is None:
                        continue
                    decl_name_pos.add(nn.start_byte)
                    init = d.child_by_field_name("value")
                    defs.append(JDef(_text(src, nn), "field", rel, m.start_point[0] + 1, m.end_point[0] + 1,
                                     m.start_point[1], fmods, fanns, qual, anns, supers, TYPE_NODES[node.type], False,
                                     multi_declarator=len(decls) > 1,
                                     side_effect_init=bool(init is not None and _has_side_effects(init)),
                                     shares_line=line_shared(m)))
            elif m.type == "enum_constant":
                nn = m.child_by_field_name("name")
                if nn is not None:
                    decl_name_pos.add(nn.start_byte)

    for top in tree.root_node.children:
        if top.type in TYPE_NODES:
            visit_type(top, None, [], False, [])
    return defs, decl_name_pos


def analyze_java_dead_code(root: Path, java_files: list[str], all_files: list[str]) -> tuple[list[Finding], list[str], list[str]]:
    """Returns (findings, files_that_failed_to_parse, notes)."""
    if _LANG is None:
        return [], [], ["Java dead-code analysis skipped: install 'tree-sitter' and 'tree-sitter-java'"]
    parser = Parser(_LANG)
    defs: list[JDef] = []
    refs: dict[str, list[tuple[str, int]]] = defaultdict(list)
    str_refs: set[str] = set()
    reflective_files: set[str] = set()
    failed: list[str] = []

    for rel in java_files:
        text = read_text_safe(root, rel)
        if text is None:
            continue
        src = text.encode("utf-8")
        tree = parser.parse(src)
        if tree.root_node.has_error:
            failed.append(rel)  # unparseable: neither analysed nor trusted as a source of references
            for tok in IDENT_RX.findall(text):   # but its identifiers still count as (conservative) references
                refs[tok].append((rel, 0))
            continue
        if REFLECTION_RX.search(text):
            reflective_files.add(rel)
        lines = text.splitlines()
        file_defs, decl_pos = _collect(src, tree, rel, lines)
        if not is_java_test_file(rel):
            defs.extend(file_defs)
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type in ("identifier", "type_identifier") and n.start_byte not in decl_pos:
                refs[_text(src, n)].append((rel, n.start_point[0] + 1))
            elif n.type in ("string_literal", "text_block") and n.end_byte - n.start_byte <= 200:
                str_refs.update(IDENT_RX.findall(_text(src, n)))
            stack.extend(n.children)

    text_tokens: set[str] = set()
    for rel in all_files:
        if any(rel.endswith(ext) for ext in CONFIG_TEXT_EXTENSIONS) or SERVICE_FILE_RX.search(rel):
            t = read_text_safe(root, rel)
            if t:
                text_tokens.update(IDENT_RX.findall(t))
            if SERVICE_FILE_RX.search(rel):
                text_tokens.update(IDENT_RX.findall(rel))

    findings: list[Finding] = []
    flagged_types: dict[tuple[str, str], str] = {}
    n = 0
    for d in sorted(defs, key=lambda x: (x.kind in ("method", "field"), x.file, x.start)):
        if d.name in SERIALIZATION_HOOKS or (d.kind == "method" and (d.name == "main" or d.name in OBJECT_METHODS)):
            continue
        if d.kind == "method" and ("Override" in d.annotations or d.is_abstract or d.owner_kind in ("interface", "annotation")):
            continue
        if d.kind == "field" and "private" not in d.modifiers:
            continue                         # only private fields are ever considered
        if d.kind == "field" and d.owner_kind in ("interface", "annotation"):
            continue
        owner_key = (d.file, (d.owner or "").split(".")[-1])
        if d.kind in ("method", "field") and owner_key in flagged_types:
            # class will be removed (high): members go with it. Otherwise the class finding already covers
            # its non-private members, but PRIVATE members are dead regardless of who uses the class.
            if flagged_types[owner_key] == "high" or "private" not in d.modifiers:
                continue
        outside = [(f, ln) for f, ln in refs.get(d.name, []) if not (f == d.file and d.start <= ln <= d.end)]
        if outside:
            continue

        evidence = [f"0 references to '{d.name}' in {len(java_files)} Java files (tree-sitter, declarations and own body excluded)"]
        private = "private" in d.modifiers
        protected = "protected" in d.modifiers
        framework = [a for a in d.annotations if a not in SAFE_ANNOTATIONS]
        owner_framework = [a for a in d.owner_annotations if a not in SAFE_ANNOTATIONS]
        is_type = d.kind not in ("method", "field")
        if framework:
            conf = "low"
            evidence.append(f"annotated @{', @'.join(framework)}: possible framework wiring")
        elif d.name in str_refs:
            conf = "low"
            evidence.append("name appears inside a string literal: possible reflection/dynamic lookup")
        elif d.name in text_tokens:
            conf = "low"
            evidence.append("name appears in a config/XML/properties/META-INF file")
        elif d.kind == "field" and owner_framework:
            conf = "low"
            evidence.append(f"field of class annotated @{', @'.join(owner_framework)} (Lombok/JPA/Jackson may use it implicitly)")
        elif is_type and d.owner is None and (d.owner_supertypes or owner_framework):
            conf = "low"
            evidence.append("class extends/implements a type: may be loaded via interface/SPI")
        elif is_type and d.owner is None:
            conf = "medium"
            evidence.append("top-level type: may be external API")
        elif is_type and d.nested and private:
            conf = "high"
            evidence.append("private nested type; no string or config mentions")
        elif is_type:
            conf = "medium"
            evidence.append("non-private type: may be used externally")
        elif d.kind == "method" and not private and d.owner_supertypes:
            conf = "low"
            evidence.append(f"non-private method of class with supertypes ({', '.join(d.owner_supertypes[:3])}): may implement an interface method")
        elif private:
            conf = "high"
            evidence.append(f"private {d.kind}; no string, config or annotation mentions")
        elif protected:
            conf = "medium"
            evidence.append("protected member: subclasses (possibly outside this repo) may use it")
        else:
            conf = "medium"
            evidence.append("non-private member: may be external API")

        # downgrades that apply to otherwise 'high' findings
        if conf == "high":
            if d.file in reflective_files:
                conf = "medium"
                evidence.append("file uses reflection (getDeclared*/setAccessible/Class.forName): members may be accessed dynamically")
            elif d.kind == "field" and d.side_effect_init:
                conf = "medium"
                evidence.append("initialiser has possible side effects (new/method call): needs human review")
            elif d.kind == "field" and d.multi_declarator:
                conf = "medium"
                evidence.append("declared together with other fields: manual cleanup")
            elif d.shares_line:
                conf = "medium"
                evidence.append("declaration shares a line with other code: not safe to cut by lines")

        n += 1
        if is_type:
            flagged_types[(d.file, d.name)] = conf
        sym = f"{d.owner}.{d.name}" if d.owner else d.name
        findings.append(Finding(
            id=f"DCJ-{n:03d}", type="dead_code", confidence=conf, file=d.file, line=d.start, end_line=d.end, symbol=sym,
            kind=d.kind, evidence=evidence, proposed_action="remove" if conf == "high" else "report_only",
            risk="low" if conf == "high" else "medium", col=d.col,
        ))
    return findings, failed, []
