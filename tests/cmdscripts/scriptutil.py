#!/usr/bin/env python3
"""Shared install helper for the committed fake-executable scripts.

Copies a helper script to a destination as an executable, pinning its shebang to
the running interpreter (``sys.executable``). Pinning an ABSOLUTE interpreter path
matters because some tests place the stub on a deliberately restricted ``$PATH``
(e.g. the ``xrd unmount`` fallback runs with ONLY the fake ``umount`` dir on PATH)
where a ``#!/usr/bin/env python3`` shebang could not resolve ``python3`` — the old
``#!/bin/sh`` stubs dodged this only because ``/bin/sh`` is itself absolute.
"""

from __future__ import annotations

import os
import sys


def install_script(src: str, dest: str) -> str:
    """Copy the committed helper at ``src`` to ``dest`` (mode 0755) with its
    shebang pinned to ``sys.executable``; return ``dest``."""
    with open(src, encoding="utf-8") as fh:
        lines = fh.readlines()
    if lines and lines[0].startswith("#!"):
        lines[0] = "#!%s\n" % sys.executable
    with open(dest, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    os.chmod(dest, 0o755)
    return dest
