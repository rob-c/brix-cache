"""Transport-neutral framed messages exchanged with managed test helpers."""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Mapping, Optional

CHANNEL_ENV = "BRIXTEST_HELPER_CHANNEL"
STDIO_CHANNEL = "stdio-v1"
FRAME_PREFIX = b"\x1eBRIXTEST/1 "
_KINDS = frozenset({"heartbeat", "result", "attachment", "log", "cancel"})
_WRITE_LOCK = threading.Lock()


def _atomic_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.parent.mkdir(parents=True, exist_ok=True)
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
    temporary.replace(path)


@dataclasses.dataclass(frozen=True)
class HelperMessage:
    """One versioned, JSON-safe helper control or result message."""

    kind: str
    payload: Mapping[str, object]
    sequence: int = 0
    emitted_at: float = 0.0

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise ValueError("unknown BriXTest helper message kind: %s" % self.kind)
        if not isinstance(self.payload, Mapping):
            raise TypeError("BriXTest helper message payload must be a mapping")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise TypeError("BriXTest helper message sequence must be an integer")
        if self.sequence < 0:
            raise ValueError("BriXTest helper message sequence cannot be negative")

    def as_dict(self) -> dict[str, object]:
        """Return the stable wire representation."""
        return {
            "schema": 1,
            "kind": self.kind,
            "sequence": self.sequence,
            "emitted_at": self.emitted_at or time.time(),
            "payload": dict(self.payload),
        }

    def frame(self) -> bytes:
        """Encode one newline-terminated frame safe for a mixed byte stream."""
        encoded = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        return FRAME_PREFIX + base64.b64encode(encoded) + b"\n"


def decode_frame(value: bytes) -> HelperMessage:
    """Decode and validate one frame, excluding unrelated output."""
    if not value.startswith(FRAME_PREFIX):
        raise ValueError("not a BriXTest helper frame")
    try:
        raw = base64.b64decode(value[len(FRAME_PREFIX):].strip(), validate=True)
        row = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ValueError("invalid BriXTest helper frame") from exc
    if not isinstance(row, dict) or row.get("schema") != 1:
        raise ValueError("unsupported BriXTest helper frame schema")
    payload = row.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("invalid BriXTest helper frame payload")
    emitted_at = row.get("emitted_at", 0.0)
    if isinstance(emitted_at, bool) or not isinstance(emitted_at, (int, float)):
        raise ValueError("invalid BriXTest helper frame timestamp")
    return HelperMessage(
        str(row.get("kind", "")), payload,
        sequence=row.get("sequence", 0), emitted_at=float(emitted_at),
    )


def publish(kind: str, payload: Mapping[str, object], *, sequence: int = 0) -> bool:
    """Publish a frame when the helper uses the stdio transport."""
    if os.environ.get(CHANNEL_ENV) != STDIO_CHANNEL:
        return False
    frame = HelperMessage(kind, payload, sequence=sequence).frame()
    with _WRITE_LOCK:
        output = getattr(sys.__stdout__, "buffer", sys.__stdout__)
        output.write(frame)
        output.flush()
    return True


class FrameDecoder:
    """Separate BriXTest frames from arbitrary streaming helper output."""

    def __init__(self, on_message: Callable[[HelperMessage], None]) -> None:
        self.on_message = on_message
        self._pending = b""

    def feed(self, block: bytes) -> bytes:
        """Consume bytes and return only ordinary helper output."""
        self._pending += block
        output = bytearray()
        while self._consume_one(output):
            pass
        return bytes(output)

    def close(self) -> bytes:
        """Flush an incomplete trailing frame as ordinary output."""
        pending, self._pending = self._pending, b""
        return pending

    def _consume_one(self, output: bytearray) -> bool:
        start = self._pending.find(FRAME_PREFIX)
        if start < 0:
            self._flush_safe_prefix(output)
            return False
        if start:
            output.extend(self._pending[:start])
            self._pending = self._pending[start:]
        end = self._pending.find(b"\n", len(FRAME_PREFIX))
        if end < 0:
            return False
        candidate = self._pending[:end + 1]
        self._pending = self._pending[end + 1:]
        try:
            message = decode_frame(candidate)
        except ValueError:
            output.extend(candidate)
        else:
            self.on_message(message)
        return True

    def _flush_safe_prefix(self, output: bytearray) -> None:
        retained = min(len(self._pending), len(FRAME_PREFIX) - 1)
        if len(self._pending) > retained:
            output.extend(self._pending[:-retained] if retained else self._pending)
            self._pending = self._pending[-retained:] if retained else b""


def apply_message(
    message: HelperMessage, *, heartbeat: Path, result: Path,
    journal: Optional[Path] = None,
) -> None:
    """Project a remote message onto the controller's durable file channel."""
    if message.kind == "heartbeat":
        _atomic_json(heartbeat, message.as_dict())
    elif message.kind == "result":
        _atomic_json(result, message.payload)
    if journal is not None:
        journal.parent.mkdir(parents=True, exist_ok=True)
        with journal.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(message.as_dict(), sort_keys=True) + "\n")


__all__ = [
    "CHANNEL_ENV", "FRAME_PREFIX", "STDIO_CHANNEL", "FrameDecoder",
    "HelperMessage", "apply_message", "decode_frame", "publish",
]
