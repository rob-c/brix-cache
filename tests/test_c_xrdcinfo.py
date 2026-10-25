import os
import struct

import pytest

from cmdscripts.c_xrdcinfo import XRDCINFO, run_checks, run_json, write_cinfo


def test_c_xrdcinfo(tmp_path):
    results = run_checks(tmp_path)
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])
    assert all(ok for ok, _ in results), "\n".join(f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)


@pytest.mark.parametrize("damage", ["truncated", "huge-geometry"])
def test_c_xrdcinfo_rejects_malformed_records(tmp_path, damage):
    """Error/negative: incomplete records and hostile geometry fail closed."""
    if not os.access(XRDCINFO, os.X_OK):
        pytest.skip(f"xrdcinfo not built: {XRDCINFO}")
    path = tmp_path / "damaged.cinfo"
    write_cinfo(path, size=150000, bitmap=7)
    raw = bytearray(path.read_bytes())
    if damage == "truncated":
        raw = raw[:20]
    else:
        struct.pack_into("<q", raw, 4, 1)
        struct.pack_into("<q", raw, 12, (1 << 63) - 1)
    path.write_bytes(raw)
    rc, data, output = run_json(path)
    assert rc == 2, (rc, data, output)
