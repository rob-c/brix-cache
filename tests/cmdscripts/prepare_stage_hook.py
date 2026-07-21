#!/usr/bin/env python3
"""``brix_prepare_command`` staging hook — the Python replacement for the
``stage_hook.sh`` heredoc the fleet used to generate.

nginx execs this with the staged logical paths as argv. It logs
``BRIX_PREPARE_COLOC`` (when the co-location env var is set — the prepare-command
role preserves the environment, unlike ``frm://exec``) followed by one line per
staged path to the log file named in the JSON sidecar (``<argv0>.json`` →
``{"log": "..."}``). The on-disk log contract is byte-for-byte identical to the
old shell hook: an optional ``COLOC=<v>`` line, then each path on its own line.
"""

from __future__ import annotations

import json
import os
import shutil
import sys


def _log_path(script_path: str) -> str:
    with open(script_path + ".json") as fh:
        return json.load(fh)["log"]


def main(argv: list[str] | None = None, log: str | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if log is None:
        log = _log_path(os.path.realpath(sys.argv[0]))
    with open(log, "a") as fh:
        coloc = os.environ.get("BRIX_PREPARE_COLOC")
        if coloc:
            fh.write(f"COLOC={coloc}\n")
        for path in args:
            fh.write(f"{path}\n")
    return 0


def install(dest_dir, name: str = "stage_hook.py", *, log: str) -> str:
    """Copy this hook into ``dest_dir`` (world-exec) with its ``{log}`` sidecar
    and return its path."""
    dest = os.path.join(str(dest_dir), name)
    shutil.copyfile(os.path.realpath(__file__), dest)
    os.chmod(dest, 0o755)
    sidecar = dest + ".json"
    with open(sidecar, "w") as fh:
        json.dump({"log": str(log)}, fh)
    os.chmod(sidecar, 0o644)
    return dest


if __name__ == "__main__":
    raise SystemExit(main())
