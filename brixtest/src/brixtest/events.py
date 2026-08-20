"""Run observability: the append-only JSONL event stream (feature F15).

Every significant lifecycle event of a session is one line of
structured JSONL under the lane's log directory.  Emission must never
fail a run: any error inside ``emit`` is swallowed after a best-effort
fallback, because observability cannot become a new failure mode.

Schema is v0 and explicitly unstable; ``data`` payloads reuse the
emitting feature's existing structures.
"""

from __future__ import annotations

import dataclasses
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional

__all__ = ["Event", "configure", "emit", "event_log_path"]

SCHEMA_VERSION = 0

_lock = threading.Lock()
_sink: Optional[Path] = None
_lane: str = ""


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
    global _sink, _lane
    with _lock:
        _sink = (Path(log_dir) / "events.jsonl") if log_dir else None
        _lane = lane


def event_log_path() -> Optional[Path]:
    return _sink


def _now() -> str:
    stamp = datetime.now(timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond // 1000:03d}Z"


def emit(kind: str, spec: str = "", **data: object) -> None:
    """Append one event line; errors are swallowed by contract."""
    sink = _sink
    if sink is None:
        return
    try:
        line = Event(_now(), kind, spec, _lane, data).to_json()
        with _lock:
            sink.parent.mkdir(parents=True, exist_ok=True)
            with open(sink, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except Exception:
        pass
