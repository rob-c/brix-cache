#!/usr/bin/env python3
"""Configurable fake executable — the committed-Python replacement for the
throwaway POSIX-shell stub binaries tests used to write to disk (fake tools on
``$PATH``, sandbox siblings, argv-capture mocks).

Behaviour is data, read from a JSON sidecar next to the installed copy
(``<script>.json``), so the executable file itself stays generic:

    exit            (int, default 0)  process exit status
    stdout          (str)  printed verbatim + a trailing newline, when set
    echo_tool_argv  (bool) print ``TOOL=<argv0 basename>`` then one ``ARG=<v>``
                           line per argument — argv capture via stdout
    log_args        (str)  write the space-joined arguments + newline to this
                           path (truncating) — argv capture via a file

Resolve the sidecar from ``__file__`` (the real script path the interpreter was
handed) rather than ``argv[0]`` so it works even when the tool is found via a
``$PATH`` search. Install a configured copy with :func:`install`.

NOTE: this reads its config from a sidecar, so it is for tools executed IN PLACE.
A binary that is COPIED elsewhere and then run (e.g. via ``freeze_nginx``) leaves
the sidecar behind — use a self-contained script for that (see ``fake_nginx.py``).
"""

from __future__ import annotations

import json
import os
import sys


def _config() -> dict:
    with open(os.path.realpath(__file__) + ".json") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None, cfg: dict | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if cfg is None:
        try:
            cfg = _config()
        except OSError:
            cfg = {}

    if cfg.get("echo_tool_argv"):
        sys.stdout.write("TOOL=%s\n" % os.path.basename(sys.argv[0]))
        for a in args:
            sys.stdout.write("ARG=%s\n" % a)
    if cfg.get("stdout") is not None:
        sys.stdout.write(cfg["stdout"] + "\n")
    log = cfg.get("log_args")
    if log:
        with open(log, "w") as fh:
            fh.write(" ".join(args) + "\n")

    return int(cfg.get("exit", 0))


def install(dest_dir, name: str, **cfg) -> str:
    """Copy this script into ``dest_dir`` as ``name`` (world-exec) with its JSON
    sidecar and return the absolute path."""
    from cmdscripts.scriptutil import install_script

    dest = install_script(os.path.realpath(__file__), os.path.join(str(dest_dir), name))
    sidecar = dest + ".json"
    with open(sidecar, "w") as fh:
        json.dump(cfg, fh)
    os.chmod(sidecar, 0o644)
    return dest


if __name__ == "__main__":
    raise SystemExit(main())
