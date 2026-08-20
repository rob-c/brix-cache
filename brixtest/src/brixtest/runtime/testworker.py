"""Execute managed test function bodies on a worker thread inside the helper."""

from __future__ import annotations

import queue
import threading
from typing import Callable


def execute(invoke: Callable[[], object]) -> None:
    """Run pytest's normal function-call hook chain on a helper-owned thread."""
    outcomes = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            result = invoke()
            if result is not None:
                raise TypeError(
                    "managed test functions must return None, not %s" % type(result).__name__
                )
            outcomes.put((None, None))
        except BaseException as exc:
            outcomes.put((exc, exc.__traceback__))

    worker = threading.Thread(
        target=run, name="brixtest-test-worker", daemon=True,
    )
    worker.start()
    worker.join()
    error, traceback = outcomes.get()
    if error is not None:
        raise error.with_traceback(traceback)
