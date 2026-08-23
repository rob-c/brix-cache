"""Append-only JSONL lifecycle events for test runs.

Every significant lifecycle event of a session is one line of
structured JSONL under the lane's log directory.  Emission must never
fail a run: any error inside ``emit`` is swallowed after a best-effort
fallback, because observability cannot become a new failure mode.

Schema v0 is explicitly unstable.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional

__all__ = ["Event", "configure", "emit", "event_log_path"]

SCHEMA_VERSION = 0

@dataclasses.dataclass
class _EventState:
    lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)
    sink: Optional[Path] = None
    lane: str = ""


_state = _EventState()


@dataclasses.dataclass(frozen=True)
class Event:
    ts: str
    kind: str
    spec: str
    lane: str
    data: Mapping[str, object]

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), sort_keys=True)


def configure(log_dir: Optional[Path], lane: str = "") -> None:
    """Point the stream at ``log_dir/events.jsonl`` (None disables it)."""
    with _state.lock:
        _state.sink = (Path(log_dir) / "events.jsonl") if log_dir else None
        _state.lane = lane


def event_log_path() -> Optional[Path]:
    return _state.sink


def _now() -> str:
    stamp = datetime.now(timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond // 1000:03d}Z"


def emit(kind: str, spec: str = "", **data: object) -> None:
    """Append one event line; errors are swallowed by contract."""
    sink = _state.sink
    if sink is None:
        return
    with contextlib.suppress(Exception):
        line = Event(_now(), kind, spec, _state.lane, data).to_json()
        with _state.lock:
            sink.parent.mkdir(parents=True, exist_ok=True)
            with sink.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
