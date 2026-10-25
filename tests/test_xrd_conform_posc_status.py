"""POSC evidence starts initialized and preserves actual wire refusals."""

import pytest

import test_xrd_conform_pg_status as probes
from _test_phase115_pgread_verify_helpers import PgOrigin, error_frame


@pytest.mark.parametrize("owner", ["STA-011", "OPN-016"])
def test_successful_posc_wire_operations_have_an_empty_status(tmp_path, owner):
    """An incoherent POSC origin is rejected without exposing stack garbage."""
    result, rows = probes._run(tmp_path, "ok", owner[:3], owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"
    assert rows[owner]["received"] == "kxr=0 "


@pytest.mark.parametrize("code,name", [(3010, "NotAuthorized"), (3007, "IOError")])
def test_posc_open_refusal_retains_its_exact_wire_status(tmp_path, monkeypatch, code, name):
    """Initialization must not erase a server authorization or I/O refusal."""
    class RefusingPoscOrigin(PgOrigin):
        def _dispatch_open(self, conn, sid, hdr, body, authenticated):
            if b"brix-conform-open-posc" in body:
                conn.sendall(error_frame(sid, code, b"controlled POSC refusal"))
                return
            super()._dispatch_open(conn, sid, hdr, body, authenticated)

    monkeypatch.setattr(probes, "PgOrigin", RefusingPoscOrigin)
    result, rows = probes._run(tmp_path, "ok", "STA", "STA-011", "STA-011")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["STA-011"]["verdict"] == "divergent"
    assert rows["STA-011"]["received"] == f"kxr={code} controlled POSC refusal ({name})"
