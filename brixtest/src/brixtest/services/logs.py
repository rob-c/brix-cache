"""Addressed, rotation-aware service log views.

Use a mark to restrict reads to output produced after an operation::

    view = fleet.log_view("webdav")
    mark = view.mark()                    # before acting
    client.do_the_thing()
    line = view.wait_for("PUT /x", since=mark, timeout=5.0)

``mark()`` captures the current end of the log; ``since=mark`` scopes
every read to what this test caused. If the file
shrank below the mark (the server rotated or truncated), the view
reads from the top of the new file rather than silently returning
nothing. A failed ``wait_for`` includes the current tail.
"""

from __future__ import annotations

import dataclasses
import time
from pathlib import Path
from typing import Iterator, List, Optional, Pattern, Union

from brixtest.errors import LogWaitTimeout

__all__ = ["LogMark", "LogView"]

_POLL = 0.2
_TAIL_DEFAULT = 40


@dataclasses.dataclass(frozen=True)
class LogMark:
    """An opaque position: 'the end of the log when I looked'."""

    offset: int


class LogView:
    def __init__(self, name: str, path: Path) -> None:
        self.name = name
        self.path = Path(path)

    def mark(self) -> LogMark:
        try:
            return LogMark(self.path.stat().st_size)
        except OSError:
            return LogMark(0)

    def _read_since(self, mark: Optional[LogMark]) -> str:
        try:
            data = self.path.read_bytes()
        except OSError:
            return ""
        offset = mark.offset if mark else 0
        if offset > len(data):
            offset = 0  # rotation/truncation: the mark outlived the file
        return data[offset:].decode(errors="replace")

    def text(self, since: Optional[LogMark] = None) -> str:
        return self._read_since(since)

    def lines(self, since: Optional[LogMark] = None) -> List[str]:
        return self._read_since(since).splitlines()

    def tail(self, n: int = _TAIL_DEFAULT) -> str:
        return "\n".join(self.lines()[-n:])

    def grep(
        self, pattern: Union[str, Pattern[str]], since: Optional[LogMark] = None
    ) -> Iterator[str]:
        """Matching lines; a str pattern is a substring, not a regex —
        pass a compiled pattern when you mean one."""
        matcher = self._matcher(pattern)
        for line in self.lines(since):
            if matcher(line):
                yield line

    @staticmethod
    def _matcher(pattern: Union[str, Pattern[str]]):
        if isinstance(pattern, str):
            return lambda line: pattern in line
        return lambda line: pattern.search(line) is not None

    def wait_for(
        self,
        pattern: Union[str, Pattern[str]],
        *,
        since: Optional[LogMark] = None,
        timeout: float = 10.0,
        poll: float = _POLL,
    ) -> str:
        """Block until a line matching ``pattern`` appears after ``since``;
        returns the first matching line.  Monotonic clock only."""
        matcher = self._matcher(pattern)
        start = time.monotonic()
        scan_from = since or LogMark(0)
        while True:
            found = _first_match(self.lines(scan_from), matcher)
            if found is not None:
                return found
            waited = time.monotonic() - start
            if waited >= timeout:
                self._raise_timeout(pattern, waited)
            time.sleep(poll)

    def _raise_timeout(self, pattern, waited: float) -> None:
        shown = pattern if isinstance(pattern, str) else pattern.pattern
        raise LogWaitTimeout(self.name, shown, waited, log_tail=self.tail())

    def __repr__(self) -> str:
        return "LogView(%r, %s)" % (self.name, self.path)


def _first_match(lines, matcher):
    for line in lines:
        if matcher(line):
            return line
    return None
