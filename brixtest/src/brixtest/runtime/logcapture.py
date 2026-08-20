"""Continuously drain process output into a bounded on-disk log."""

from __future__ import annotations

import threading
from pathlib import Path

_LIMIT_MARKER = b"\n[brixtest: log limit reached; later bytes omitted]\n"


class BoundedLogPump:
    """Drain one binary pipe without allowing its log file to grow unbounded."""

    def __init__(self, source: object, destination: Path, limit: int) -> None:
        self.source = source
        self.destination = Path(destination)
        self.limit = limit
        self._thread = threading.Thread(
            target=self._run, name="brixtest-log-%s" % self.destination.stem,
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float = 1.0) -> bool:
        self._thread.join(timeout=timeout)
        return not self._thread.is_alive()

    def _run(self) -> None:
        try:
            written = self.destination.stat().st_size
        except OSError:
            written = 0
        capped = written >= self.limit
        # ``BufferedReader.read(n)`` may wait for all ``n`` bytes while a
        # long-running server remains alive. ``read1`` returns bytes already
        # available from the pipe, so readiness and access lines become
        # observable immediately without changing the bounded drain model.
        read = getattr(self.source, "read1", self.source.read)
        try:
            with self.destination.open("ab") as output:
                while True:
                    block = read(64 << 10)
                    if not block:
                        return
                    if capped:
                        continue
                    remaining = self.limit - written
                    if len(block) <= remaining:
                        output.write(block)
                        written += len(block)
                    else:
                        body = max(0, remaining - len(_LIMIT_MARKER))
                        output.write(block[:body])
                        marker_room = self.limit - written - body
                        output.write(_LIMIT_MARKER[:marker_room])
                        written = self.limit
                        capped = True
                    output.flush()
        finally:
            self.source.close()


__all__ = ["BoundedLogPump"]
