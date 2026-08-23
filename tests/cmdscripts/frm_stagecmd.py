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


def _arguments(argv):
    return list(sys.argv[1:] if argv is None else argv)


def _configuration(cfg):
    if cfg is None:
        return _load_config(os.path.realpath(sys.argv[0]))
    return cfg


def _argument(args, index):
    if index < len(args):
        return args[index]
    return ""


def _request(args, cfg):
    verb = _argument(args, 0)
    key = _argument(args, 1)
    online = _argument(args, 2)
    if cfg.get("strip_slash", True) and key.startswith("/"):
        key = key[1:]
    return verb, key, online


def _audit_line(cfg, verb, key, online):
    if cfg.get("audit_format", "verb_key_online") == "verb_key":
        return f"{verb} {key}\n"
    return f"{verb} {key} {online}\n"


def _write_audit(cfg, verb, key, online):
    audit = cfg.get("audit")
    if not audit:
        return
    try:
        with open(audit, "a") as fh:
            fh.write(_audit_line(cfg, verb, key, online))
    except OSError:
        if not cfg.get("audit_best_effort"):
            raise


def _ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def _recall(cfg, key, tape_key, online):
    recall_log = cfg.get("recall_log")
    if recall_log:
        with open(recall_log, "a") as fh:
            fh.write(f"recall {key}\n")
    if cfg.get("failkey") and key == cfg["failkey"]:
        return 1
    try:
        _ensure_parent(online)
        shutil.copyfile(tape_key, online)
    except OSError:
        return 1
    return 0


def _migrate(tape_key, online):
    try:
        _ensure_parent(tape_key)
        shutil.copyfile(online, tape_key)
    except OSError:
        return 1
    return 0


def _purge(online):
    try:
        os.unlink(online)
    except OSError:
        pass
    return 0


def _dispatch(cfg, verb, key, online, tape_key):
    if verb == "exists":
        return 0 if os.path.isfile(tape_key) else 1
    if verb == "recall":
        return _recall(cfg, key, tape_key, online)
    if verb == "migrate":
        return _migrate(tape_key, online)
    if verb == "purge":
        return _purge(online)
    return int(cfg.get("unknown_exit", 0))


def main(argv: list[str] | None = None, cfg: dict | None = None) -> int:
    cfg = _configuration(cfg)
    verb, key, online = _request(_arguments(argv), cfg)
    tape_key = f"{cfg.get('tape', '')}/{key}"
    _write_audit(cfg, verb, key, online)

    allowed = cfg.get("verbs")
    if allowed is not None and verb not in allowed:
        return int(cfg.get("unknown_exit", 0))
    return _dispatch(cfg, verb, key, online, tape_key)


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
