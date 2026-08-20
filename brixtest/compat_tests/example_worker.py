"""The worker side of the example RPC (run by test_10, never collected).

``serve()`` reads JSON frames from stdin and answers on stdout; a
handler that raises becomes an error frame, not a dead worker — which
is exactly what test_10 demonstrates from the runner side.
"""

from __future__ import annotations

from brixtest.clients import serve


def add(a: int, b: int) -> int:
    return a + b


def boom() -> None:
    raise ValueError("deliberate failure for the error-frame demo")


if __name__ == "__main__":
    serve({"add": add, "boom": boom})
