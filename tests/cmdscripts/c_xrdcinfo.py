"""Unit checks for client/bin/xrdcinfo JSON output."""

from __future__ import annotations

from pathlib import Path
import json
import os
import struct

from cmdscripts.compile_run import REPO_ROOT, result, run
from _test_phase115_pgread_verify_helpers import crc32c

def _expression_1(rc, data, output):
    return (
        [
                result(rc == 0 and data is not None and data.get("flags") == ["PARTIAL"], f"PARTIAL flag ({output})"),
                result(rc == 0 and data is not None and data.get("present_blocks") == [1, 2], "present_blocks [1,2]"),
                result(rc == 0 and data is not None and data.get("complete") is False, "not complete"),
            ]
    )

def _expression_2(results, rc, data, output):
    return (
        results.append(result(rc == 0 and data is not None and data.get("complete") is True, f"complete ({output})"))
    )

def _expression_3(results, rc, data):
    return (
        results.append(result(rc == 0 and data is not None and data.get("present_count") == 3, "count 3"))
    )

def _expression_4(results, data, output):
    return (
        results.append(result(data is not None and data.get("absent") is True, f"absent json ({output})"))
    )


XRDCINFO = REPO_ROOT / "client" / "bin" / "xrdcinfo"


def write_cinfo(path: Path, size: int, bitmap: int) -> None:
    """Write the current stock-v4 prefix with genuine Store/bitmap checksums."""
    nblocks = (size + 65535) // 65536
    store = struct.pack("<qqqqQIi", 65536, size, 0, 0, 0, 0, 0)
    present = bitmap.to_bytes((nblocks + 7) // 8, "little")
    path.write_bytes(struct.pack("<i", 4) + store
                     + struct.pack("<I", crc32c(store)) + present
                     + struct.pack("<I", crc32c(present))
                     + struct.pack("<IHH", 0x31584358, 1, 0))


def run_json(path: Path) -> tuple[int, dict[str, object] | None, str]:
    proc = run([str(XRDCINFO), str(path)], cwd=REPO_ROOT)
    if not proc.stdout.strip():
        return proc.returncode, None, proc.stderr or proc.stdout
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return proc.returncode, None, proc.stderr or proc.stdout
    return proc.returncode, data, proc.stderr


def run_checks(base: Path) -> list[tuple[bool, str]]:
    if not os.access(XRDCINFO, os.X_OK):
        return [result(True, f"SKIP xrdcinfo not built: {XRDCINFO}")]
    partial = base / "p.cinfo"
    write_cinfo(partial, size=300000, bitmap=0b00000110)
    rc, data, output = run_json(partial)
    results = _expression_1(rc, data, output)
    complete = base / "c.cinfo"
    write_cinfo(complete, size=150000, bitmap=0b00000111)
    rc, data, output = run_json(complete)
    _expression_2(results, rc, data, output)
    _expression_3(results, rc, data)
    rc, data, output = run_json(base / "nope.cinfo")
    results.append(result(rc == 3, f"absent exit status 3 (got {rc})"))
    _expression_4(results, data, output)
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
