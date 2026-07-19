"""Python command modules replacing former shell test entry points."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Sequence


def _maybe_force_nginx_root_worker(argv: list[str]) -> list[str]:
    """Force `user root;` on a direct nginx *server* launch under the root harness.

    Live scenarios start their own nginx via ``run([nginx, "-p", .., "-c", ..])``.
    When the harness runs as root, the master starts as root but the workers
    default to ``nobody`` — which cannot read the root-owned test credentials or
    write the root-owned cache/data trees, so the fill/serve fails (often
    silently, with an empty object). LiveRun.start_nginx already injects
    ``-g "user root;"`` for exactly this reason; mirror it for the raw launches so
    the throwaway per-scenario workers run as root too. Only a genuine server
    start is rewritten (has ``-c``, not a ``-t`` config-test / ``-s`` signal /
    ``-v`` version probe), and never when the caller already set ``-g``.
    """
    if os.geteuid() != 0 or not argv:
        return argv
    first = str(argv[0])
    if not (first == "nginx" or first.endswith("/nginx")):
        return argv
    if "-c" not in argv or "-g" in argv:
        return argv
    if any(flag in argv for flag in ("-t", "-T", "-s", "-v", "-V")):
        return argv
    return argv + ["-g", "user root;"]


def run(argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a real command-line client with captured text output.

    A default 120s timeout keeps a wedged client from hanging the whole
    pytest process; on expiry the caller sees rc=124 with the timeout noted
    in stderr, mirroring coreutils `timeout`.
    """
    kwargs.setdefault("timeout", 120)
    argv = _maybe_force_nginx_root_worker(list(argv))
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
