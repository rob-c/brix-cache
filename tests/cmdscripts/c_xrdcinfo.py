"""Unit checks for client/bin/xrdcinfo JSON output."""

from __future__ import annotations

from pathlib import Path
import json
import os
import struct

from cmdscripts.compile_run import REPO_ROOT, result, run

XRDCINFO = REPO_ROOT / "client" / "bin" / "xrdcinfo"


def write_cinfo(path: Path, flags: int, size: int, nblocks: int, bitmap: int) -> None:
    header = struct.pack("<IHHIIQQQ", 0x58434931, 3, flags, 65536, 0, size, 0, nblocks)
    path.write_bytes(header + b"\x00" * 64 + bytes([bitmap]))


def run_json(path: Path) -> tuple[int, dict[str, object] | None, str]:
    proc = run([str(XRDCINFO), str(path)], cwd=REPO_ROOT)
    if proc.returncode != 0:
        return proc.returncode, None, proc.stderr or proc.stdout
    return 0, json.loads(proc.stdout), proc.stderr


def run_checks(base: Path) -> list[tuple[bool, str]]:
    if not os.access(XRDCINFO, os.X_OK):
        return [result(True, f"SKIP xrdcinfo not built: {XRDCINFO}")]
    partial = base / "p.cinfo"
    write_cinfo(partial, flags=0x2, size=300000, nblocks=5, bitmap=0b00000110)
    rc, data, output = run_json(partial)
    results = [
        result(rc == 0 and data is not None and data.get("flags") == ["PARTIAL"], f"PARTIAL flag ({output})"),
        result(rc == 0 and data is not None and data.get("present_blocks") == [1, 2], "present_blocks [1,2]"),
        result(rc == 0 and data is not None and data.get("complete") is False, "not complete"),
    ]
    complete = base / "c.cinfo"
    write_cinfo(complete, flags=0x1, size=150000, nblocks=3, bitmap=0b00000111)
    rc, data, output = run_json(complete)
    results.append(result(rc == 0 and data is not None and data.get("complete") is True, f"complete ({output})"))
    results.append(result(rc == 0 and data is not None and data.get("present_count") == 3, "count 3"))
    rc, data, output = run_json(base / "nope.cinfo")
    results.append(result(data is not None and data.get("absent") is True, f"absent json ({output})"))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="xrdcinfo.") as tmp:
        results = run_checks(Path(tmp))
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("test_xrdcinfo: ALL PASS")
        return 0
    print("test_xrdcinfo: FAIL")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
