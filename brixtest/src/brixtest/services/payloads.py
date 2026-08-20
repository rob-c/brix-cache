"""Deterministic test payloads (feature F20).

Transfer tests need files whose content can be *proven* intact on the
far side.  The grown suite mixed ``os.urandom`` (unreproducible —
a corrupt byte can't be diffed against what should have been there),
``dd`` subprocesses, and hand-rolled checksum loops.  Here a payload
is a pure function of ``(seed, size)``:

    payload = make_payload(workspace, size=8 * 1024 * 1024, seed=42)
    upload(payload.path); download(dest)
    verify_payload(dest, payload)     # raises with offset of first difference

Same seed, same bytes, on any host, any run — a failure five runs
later reproduces the exact bytes that failed.  Content is a SHAKE-256
counter stream (cheap, incompressible, no crypto claims), written and
verified in chunks so multi-GB payloads never sit in memory.
"""

from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path
from typing import Iterator, Optional

from brixtest.errors import SpecError

__all__ = ["Payload", "make_payload", "verify_payload"]

_CHUNK = 1 << 20  # 1 MiB


@dataclasses.dataclass(frozen=True)
class Payload:
    path: Path
    size: int
    seed: int
    sha256: str


def _stream(seed: int, size: int) -> Iterator[bytes]:
    """The (seed, size)-determined byte stream, one chunk at a time.
    SHAKE-256 as an extendable-output function: each chunk is a full-
    entropy expansion of (seed, chunk index) — C-speed, incompressible."""
    remaining = size
    counter = 0
    while remaining > 0:
        take = min(remaining, _CHUNK)
        yield hashlib.shake_256(b"%d:%d" % (seed, counter)).digest(take)
        remaining -= take
        counter += 1


def make_payload(
    directory: Path, *, size: int, seed: int = 0, name: Optional[str] = None
) -> Payload:
    if size < 0:
        raise SpecError("size", size, "payload size must be >= 0")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name or "payload-s%d-%d.bin" % (seed, size))
    digest = hashlib.sha256()
    with path.open("wb") as handle:
        for chunk in _stream(seed, size):
            handle.write(chunk)
            digest.update(chunk)
    return Payload(path=path, size=size, seed=seed, sha256=digest.hexdigest())


def verify_payload(path: Path, expected: Payload) -> None:
    """Byte-compare ``path`` against the payload's deterministic stream.
    Raises ``SpecError`` naming the offset of the first difference —
    the number a transfer bug report actually needs."""
    path = Path(path)
    try:
        actual_size = path.stat().st_size
    except OSError as exc:
        raise SpecError("payload copy", str(path), "unreadable: %s" % exc) from exc
    if actual_size != expected.size:
        raise SpecError(
            "payload copy", str(path),
            "size %d != expected %d" % (actual_size, expected.size),
        )
    offset = 0
    with path.open("rb") as handle:
        for want in _stream(expected.seed, expected.size):
            got = handle.read(len(want))
            if got != want:
                for i, (g, w) in enumerate(zip(got, want)):
                    if g != w:
                        offset += i
                        break
                else:
                    offset += min(len(got), len(want))
                raise SpecError(
                    "payload copy", str(path),
                    "content differs from seed=%d stream at offset %d"
                    % (expected.seed, offset),
                )
            offset += len(want)
