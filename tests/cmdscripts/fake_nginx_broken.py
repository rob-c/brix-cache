#!/usr/bin/env python3
"""A stand-in ``nginx`` binary whose ``-v`` validation FAILS (exit 1) — models a
binary caught mid-relink that copies fine but must NOT be frozen. The
committed-Python replacement for the shell exit-1 stub. Self-contained (no
sidecar) because ``freeze_nginx`` copies the binary before executing it. See
``fake_nginx.py`` for the succeeding twin.
"""

from __future__ import annotations

import os


def install(dest_dir, name: str = "nginx") -> str:
    """Copy this script into ``dest_dir`` as ``name`` (world-exec); return its path."""
    from cmdscripts.scriptutil import install_script

    return install_script(os.path.realpath(__file__), os.path.join(str(dest_dir), name))


if __name__ == "__main__":
    raise SystemExit(1)
