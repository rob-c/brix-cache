#!/usr/bin/env python3
"""Python port of tests/frm_fake_mss.sh."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import sys
import time


def _phase_main_1(audit, dest):
    if audit:
        with Path(audit).open("a") as fh:
            fh.write(f"stage {dest}\n")


def _expression_1(argv):
    return (
        list(sys.argv[1:] if argv is None else argv)
    )

def _expression_2(args):
    return (
        not args or not args[0]
    )


def _guard_main_1(latency_ms):
    if latency_ms > 0:
        time.sleep(latency_ms / 1000.0)


def main(argv: list[str] | None = None) -> int:
    args = _expression_1(argv)
    if _expression_2(args):
        return 64
    dest = Path(args[0])
    audit = os.environ.get("FRM_AUDIT_LOG")
    _phase_main_1(audit, dest)

    try:
        latency_ms = int(os.environ.get("FRM_LATENCY_MS", "0"))
    except ValueError:
        latency_ms = 0
    _guard_main_1(latency_ms)

    if os.environ.get("FRM_FAIL_MODE") == "permanent":
        return 1

    data_dir = Path(os.environ.get("FRM_DATA_DIR", ""))
    tape_dir = Path(os.environ.get("FRM_TAPE_DIR", ""))
    ref = Path(os.environ.get("FRM_LFN", str(dest)))
    try:
        rel = ref.relative_to(data_dir)
    except ValueError:
        rel = Path(str(ref).removeprefix(str(data_dir)).lstrip("/"))
    src = tape_dir / rel
    if not src.is_file():
        return 2
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
    except OSError:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
