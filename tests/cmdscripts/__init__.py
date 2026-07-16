"""Python command modules replacing former shell test entry points."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable, Sequence


def run(argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a real command-line client with captured text output.

    A default 120s timeout keeps a wedged client from hanging the whole
    pytest process; on expiry the caller sees rc=124 with the timeout noted
    in stderr, mirroring coreutils `timeout`.
    """
    kwargs.setdefault("timeout", 120)
    try:
        return subprocess.run(list(argv), capture_output=True, text=True, **kwargs)
    except subprocess.TimeoutExpired as exc:
        def _text(stream):
            if stream is None:
                return ""
            return stream.decode(errors="replace") if isinstance(stream, bytes) else stream
        return subprocess.CompletedProcess(
            list(argv), 124, stdout=_text(exc.stdout),
            stderr=_text(exc.stderr) + f"\n[timed out after {kwargs['timeout']}s]")


def main(entry: Callable[[list[str]], int | None] | None = None, argv: Sequence[str] | None = None) -> int:
    """Shared direct-execution helper for command-script modules."""
    args = list(sys.argv[1:] if argv is None else argv)
    if entry is None:
        return 0
    result = entry(args)
    return 0 if result is None else int(result)


__all__ = ["main", "run"]
