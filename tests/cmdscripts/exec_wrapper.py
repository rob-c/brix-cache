#!/usr/bin/env python3
"""Exec shim — replace this process with a target binary, inserting fixed leading
arguments. The committed-Python replacement for a POSIX-shell wrapper of the
shape ``exec "$TARGET" <prepend...> "$@"`` (e.g. a ``brixcvmfs`` front that routes
to ``brixMount cvmfs``).

Config from a JSON sidecar next to the installed copy (``<script>.json``):
    target   (str)   absolute path of the binary to exec into
    prepend  (list)  fixed arguments inserted before the caller's argv
"""

from __future__ import annotations

import json
import os
import sys


def install(dest_dir, name: str, *, target, prepend=None) -> str:
    """Copy this shim into ``dest_dir`` as ``name`` (world-exec) with its sidecar
    and return the absolute path."""
    from cmdscripts.scriptutil import install_script

    dest = install_script(os.path.realpath(__file__), os.path.join(str(dest_dir), name))
    sidecar = dest + ".json"
    with open(sidecar, "w") as fh:
        json.dump({"target": str(target), "prepend": list(prepend or [])}, fh)
    os.chmod(sidecar, 0o644)
    return dest


def main() -> None:
    with open(os.path.realpath(__file__) + ".json") as fh:
        cfg = json.load(fh)
    target = cfg["target"]
    os.execv(target, [target, *cfg.get("prepend", []), *sys.argv[1:]])


if __name__ == "__main__":
    main()
