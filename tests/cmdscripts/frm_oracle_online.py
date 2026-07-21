#!/usr/bin/env python3
"""Residency-oracle stub for the FRM phase-4 engine tests — always reports the
object as ONLINE (exit 0), the Python replacement for the one-line ``oracle.sh``.

The FRM engine consults ``$ORACLE_CMD`` to decide whether a recall is needed; a
0 exit means "already online, skip the copy". Install with :func:`install`.
"""

from __future__ import annotations

import os
import shutil
import sys


def main(argv: list[str] | None = None) -> int:
    return 0


def install(dest_dir, name: str = "oracle.py") -> str:
    """Copy this script into ``dest_dir`` (world-exec) and return its path."""
    dest = os.path.join(str(dest_dir), name)
    shutil.copyfile(os.path.realpath(__file__), dest)
    os.chmod(dest, 0o755)
    return dest


if __name__ == "__main__":
    raise SystemExit(main())
