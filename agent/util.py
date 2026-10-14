"""Small shared helpers: glob matching and safe repository traversal."""
from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator


@lru_cache(maxsize=2048)
def glob_to_regex(pattern: str) -> re.Pattern:
    """Translate a glob (supporting ** and *) into an anchored regex."""
    i, out = 0, ""
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i : i + 3] == "**/":
                out += "(?:.*/)?"
                i += 3
                continue
            if pattern[i : i + 2] == "**":
                out += ".*"
                i += 2
                continue
            out += "[^/]*"
        elif c == "?":
            out += "[^/]"
        else:
            out += re.escape(c)
        i += 1
    return re.compile("^" + out + "$")


def match_glob(path: str, pattern: str) -> bool:
    """Match a posix-style relative path. Patterns without '/' also match the basename."""
    rx = glob_to_regex(pattern)
    if rx.match(path):
        return True
    if "/" not in pattern:
        return bool(rx.match(path.rsplit("/", 1)[-1]))
    return False


def match_any(path: str, patterns: Iterable[str]) -> bool:
    return any(match_glob(path, p) for p in patterns)


def is_ignored(rel_path: str, ignore_globs: Iterable[str]) -> bool:
    return match_any(rel_path, ignore_globs)


def iter_repo_files(root: Path, ignore_globs: Iterable[str], max_bytes: int = 1_000_000) -> Iterator[str]:
    """Yield posix relative paths of regular files under root.

    Guardrails: never follows symlinks (prevents escaping the snapshot), skips ignored
    paths, skips files above max_bytes.
    """
    ignore_globs = list(ignore_globs)
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        kept = []
        for d in sorted(dirnames):
            probe = f"{rel_dir}/{d}/x".lstrip("/")
            if os.path.islink(os.path.join(dirpath, d)) or is_ignored(probe, ignore_globs):
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = f"{rel_dir}/{name}".lstrip("/")
            if os.path.islink(full) or is_ignored(rel, ignore_globs):
                continue
            try:
                if os.path.getsize(full) > max_bytes:
                    continue
            except OSError:
                continue
            yield rel


def read_text_safe(root: Path, rel: str, max_bytes: int = 1_000_000) -> str | None:
    """Read a text file inside root. Returns None for symlinks, escapes, binaries, errors."""
    root = Path(root).resolve()
    path = root / rel
    try:
        if path.is_symlink():
            return None
        resolved = path.resolve()
        if root not in resolved.parents and resolved != root:
            return None
        data = resolved.read_bytes()[: max_bytes + 1]
    except OSError:
        return None
    if len(data) > max_bytes or b"\0" in data[:2048]:
        return None
    return data.decode("utf-8", errors="replace")
