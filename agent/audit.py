"""Append-only, hash-chained audit log (tamper-evident). One JSON object per line."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from .scanners import redact_text

GENESIS = "0" * 64


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        value = redact_text(value)
        return value if len(value) <= 500 else value[:500] + "...[truncated]"
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(v) for v in value][:200]
    return value


def _digest(record: dict) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path, run_id: str):
        self.path = Path(path)
        self.run_id = run_id
        self._prev = GENESIS
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, **data: Any) -> None:
        record = {
            "ts": round(time.time(), 3),
            "run_id": self.run_id,
            "event": event,
            "data": _scrub(data),
            "prev": self._prev,
        }
        record["hash"] = _digest(record)
        self._prev = record["hash"]
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True, default=str) + "\n")

    @staticmethod
    def verify(path: Path) -> bool:
        prev = GENESIS
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            claimed = record.pop("hash", None)
            if record.get("prev") != prev or _digest(record) != claimed:
                return False
            prev = claimed
        return True
