"""Small nested-span API for correlating test actions with resource samples."""

from __future__ import annotations

import contextlib
import contextvars
import time
import uuid
from typing import Callable, Mapping, Optional

from brixtest.errors import SpecError

_ACTIVE = contextvars.ContextVar("brixtest_active_span", default="")


class SpanRecorder:
    def __init__(self, sink: Optional[Callable[[str, Mapping[str, object]], None]] = None) -> None:
        self._started = time.perf_counter()
        self._sink = sink
        self._rows: list[dict] = []

    @property
    def active_id(self) -> str:
        return str(_ACTIVE.get())

    @contextlib.contextmanager
    def span(self, name: str, **attributes: object):
        if not isinstance(name, str) or not name.strip() or len(name) > 128:
            raise SpecError("span name", name, "must be 1-128 characters")
        span_id = uuid.uuid4().hex[:16]
        parent_id = self.active_id
        started = time.perf_counter()
        token = _ACTIVE.set(span_id)
        error = ""
        try:
            yield span_id
        except BaseException as exc:
            error = "%s: %s" % (type(exc).__name__, exc)
            raise
        finally:
            _ACTIVE.reset(token)
            row = {
                "span_id": span_id,
                "parent_id": parent_id,
                "name": name,
                "start_seconds": round(started - self._started, 9),
                "duration_seconds": round(time.perf_counter() - started, 9),
                "status": "error" if error else "ok",
                "error": error,
                "attributes": {str(key): value for key, value in attributes.items()},
            }
            self._rows.append(row)
            if self._sink:
                self._sink("span", row)

    def snapshot(self) -> list[dict]:
        return [dict(row) for row in self._rows]
