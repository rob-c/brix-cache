"""Crash-safe append-only evidence journal with deterministic recovery."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Iterable, Mapping, Optional

from brixtest.evidence.model import canonical_json, utc_now


class EvidenceJournal:
    """Append one complete JSON event per fsynced line.

    A process crash can at worst leave one incomplete final line, which recovery
    intentionally ignores. The journal is never rewritten during a case.
    """

    def __init__(self, path: Path, *, attempt_id: str = "") -> None:
        self.path = Path(path)
        self.attempt_id = attempt_id
        self._lock = threading.Lock()
        self._sequence = 0

    def append(self, event: str, data: Mapping[str, object], *, elapsed: float = 0.0) -> dict:
        with self._lock:
            self._sequence += 1
            row = {
                "sequence": self._sequence,
                "event": event,
                "attempt_id": self.attempt_id,
                "timestamp": utc_now(),
                "at_seconds": round(max(0.0, float(elapsed)), 9),
                "data": dict(data),
            }
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                str(self.path), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600
            )
            try:
                os.write(descriptor, (canonical_json(row) + "\n").encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return row

    @staticmethod
    def recover(path: Path) -> list[dict]:
        rows = []
        try:
            handle = Path(path).open("rb")
        except OSError:
            return rows
        with handle:
            for line in handle:
                if not line.endswith(b"\n"):
                    break
                try:
                    value = json.loads(line)
                except (UnicodeDecodeError, ValueError, TypeError):
                    continue
                if isinstance(value, dict):
                    rows.append(value)
        return rows

    def events(self, event: Optional[str] = None) -> Iterable[dict]:
        rows = self.recover(self.path)
        return (row for row in rows if event is None or row.get("event") == event)
