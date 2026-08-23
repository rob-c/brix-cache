"""Bounded polling with monotonic deadlines and diagnostic failures.

Rules:

- ``time.monotonic()`` only; the wall clock never gates a wait;
- every wait names ``what`` it is for;
- the predicate's last observed value rides along in the error.
"""

from __future__ import annotations

import time
from typing import Callable, Optional, TypeVar

from brixtest.errors import WaitTimeout

__all__ = ["wait_until"]

T = TypeVar("T")


def wait_until(
    predicate: Callable[[], T],
    *,
    timeout: float,
    poll: float = 0.1,
    what: str = "condition",
    describe: Optional[Callable[[T], str]] = None,
) -> T:
    """Poll ``predicate`` until it returns a truthy value; return it.

    On timeout, raises ``WaitTimeout`` naming ``what`` and the last
    falsy observation (via ``describe`` when given, ``repr`` otherwise).
    A predicate that *raises* is a bug in the caller, not a falsy
    observation — exceptions propagate immediately.
    """
    start = time.monotonic()
    last: T = predicate()
    while True:
        if last:
            return last
        waited = time.monotonic() - start
        if waited >= timeout:
            shown = describe(last) if describe else repr(last)
            raise WaitTimeout(what, waited, last_state=shown)
        time.sleep(poll)
        last = predicate()
