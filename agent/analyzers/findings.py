"""Shared finding model (matches the schema in the design doc)."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Finding:
    id: str
    type: str                      # dead_code | duplicate
    confidence: str                # high | medium | low
    file: str
    line: int
    end_line: int
    symbol: str = ""
    kind: str = ""                 # function | class | method | clone
    evidence: list[str] = field(default_factory=list)
    proposed_action: str = "report_only"
    risk: str = "low"
    status: str = "reported"       # reported | included_in_pr | skipped | downgraded_by_llm
    col: int = 0
    related: list[dict[str, Any]] = field(default_factory=list)   # other clone locations

    def to_dict(self) -> dict:
        return asdict(self)
