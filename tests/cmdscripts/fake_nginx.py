#!/usr/bin/env python3
"""A stand-in ``nginx`` binary whose ``-v`` validation SUCCEEDS (exit 0) — the
committed-Python replacement for the shell exit-0 stub the freeze_nginx tests
used. Self-contained (no sidecar) because ``freeze_nginx`` COPIES the binary
before executing it, so config must live in the file itself. See
``fake_nginx_broken.py`` for the failing twin.
"""

from __future__ import annotations

import os


def install(dest_dir, name: str = "nginx") -> str:
    """Copy this script into ``dest_dir`` as ``name`` (world-exec); return its path."""
    from cmdscripts.scriptutil import install_script

    return install_script(os.path.realpath(__file__), os.path.join(str(dest_dir), name))


if __name__ == "__main__":
    raise SystemExit(0)
