#!/usr/bin/env python3
"""Fake MSS stage command for ``frm://exec`` tests — the Python replacement for
the per-test ``stage.sh`` scripts that were assembled from shell string literals.

Contract (``$BRIX_FRM_STAGECMD <verb> <key> <online>``), verbs:
    exists   -> exit 0 if <key> is on tape, else 1 (residency probe)
    recall   -> copy tape/<key> -> <online>            (nearline -> online)
    migrate  -> copy <online>  -> tape/<key>            (online -> tape)
    purge    -> unlink <online>

Per-test configuration (tape dir, audit log, fail key, ...) is read from a JSON
sidecar written next to the executed script, NOT from the environment: nginx
rewrites its worker ``environ`` to reclaim space for the process title, so a
spawned command inherits only argv plus ``BRIX_FRM_STAGECMD`` itself. The sidecar
is resolved from ``os.path.realpath(argv[0]) + ".json"``, which survives the env
wipe. Install a configured copy with :func:`install`.

Paths are joined by string concatenation (``f"{tape}/{key}"``) to match the shell
``"$tape/$key"`` exactly, rather than ``os.path.join``/``pathlib`` (which would
discard ``tape`` on a leading-slash key).
"""

from __future__ import annotations

import json
import os
import shutil
import sys

# Config keys (all optional unless noted):
#   tape            (str, required) offline "tape" directory
#   audit           (str)  append one line per invocation here
#   audit_format    "verb_key_online" (default) | "verb_key"
#   audit_best_effort (bool) swallow audit-write errors (unprivileged worker)
#   recall_log      (str)  append "recall <key>" on the recall verb
#   failkey         (str)  recall of this key exits 1 (unrecallable object)
#   strip_slash     (bool, default True) drop one leading '/' from <key> (``${2#/}``)
#   unknown_exit    (int, default 0) exit code for an unrecognised verb
#   verbs           (list) if set, only these verbs are handled; any other
#                   verb takes the ``unknown_exit`` path (models a ``case`` with
#                   no purge arm falling through to ``*) exit N``)


def _load_config(script_path: str) -> dict:
    sidecar = script_path + ".json"
    try:
        with open(sidecar) as fh:
            return json.load(fh)
    except OSError:
        return {}


def main(argv: list[str] | None = None, cfg: dict | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if cfg is None:
        cfg = _load_config(os.path.realpath(sys.argv[0]))

    verb = args[0] if len(args) > 0 else ""
    key = args[1] if len(args) > 1 else ""
    online = args[2] if len(args) > 2 else ""
    if cfg.get("strip_slash", True) and key.startswith("/"):
        key = key[1:]

    tape_key = f"{cfg.get('tape', '')}/{key}"

    audit = cfg.get("audit")
    if audit:
        if cfg.get("audit_format", "verb_key_online") == "verb_key":
            line = f"{verb} {key}\n"
        else:
            line = f"{verb} {key} {online}\n"
        try:
            with open(audit, "a") as fh:
                fh.write(line)
        except OSError:
            if not cfg.get("audit_best_effort"):
                raise

    allowed = cfg.get("verbs")
    if allowed is not None and verb not in allowed:
        return int(cfg.get("unknown_exit", 0))

    if verb == "exists":
        return 0 if os.path.isfile(tape_key) else 1

    if verb == "recall":
        recall_log = cfg.get("recall_log")
        if recall_log:
            with open(recall_log, "a") as fh:
                fh.write(f"recall {key}\n")
        if cfg.get("failkey") and key == cfg["failkey"]:
            return 1
        try:
            parent = os.path.dirname(online)
            if parent:
                os.makedirs(parent, exist_ok=True)
            shutil.copyfile(tape_key, online)
        except OSError:
            return 1
        return 0

    if verb == "migrate":
        try:
            parent = os.path.dirname(tape_key)
            if parent:
                os.makedirs(parent, exist_ok=True)
            shutil.copyfile(online, tape_key)
        except OSError:
            return 1
        return 0

    if verb == "purge":
        try:
            os.unlink(online)
        except OSError:
            pass
        return 0

    return int(cfg.get("unknown_exit", 0))


def install(dest_dir, name: str = "stage.py", **cfg) -> str:
    """Copy this self-contained script into ``dest_dir`` and write its JSON
    sidecar. Returns the absolute path to hand to ``BRIX_FRM_STAGECMD``.

    The script + sidecar are made world-readable/executable so an unprivileged
    (``nobody``) nginx worker can exec and read them under seccomp tests.
    """
    dest = os.path.join(str(dest_dir), name)
    shutil.copyfile(os.path.realpath(__file__), dest)
    os.chmod(dest, 0o755)
    sidecar = dest + ".json"
    with open(sidecar, "w") as fh:
        json.dump(cfg, fh)
    os.chmod(sidecar, 0o644)
    return dest


if __name__ == "__main__":
    raise SystemExit(main())
