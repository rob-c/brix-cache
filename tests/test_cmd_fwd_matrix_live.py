"""Collector for the credential-forwarding matrix live scenario ports.

Python ports of run_fwd_brix_brix.sh, run_fwd_brix_xrootd.sh,
run_fwd_xrootd_brix.sh, fwd_b_token_forward_probe.sh, and
run_transparent_relay.sh (tests/cmdscripts/fwd_matrix_live.py).  The live
scenarios spin up real nginx/xrootd fleets and run by default; set
PHASE81_RUN_LIVE_PORTS=0 to skip them.
"""

import os
from pathlib import Path

import pytest

from cmdscripts import fwd_matrix_live
from cmdscripts import _fwd_matrix_live_part2_mixinb as helpers


@pytest.mark.parametrize("relay_log,expected", [
    ('xrootd tap: {"op":"open"}', (True, False)),
    (r'message="xrootd tap: {\x22op\x22:\x22stat\x22}" truncated=0',
     (False, True)),
    (r'message="xrootd tap: {\x22op\x22:\x22read\x22}" truncated=0',
     (False, False)),
])
def test_relay_log_checks_accept_semantic_structured_records(
        tmp_path, relay_log, expected):
    from log_records import semantic_log_text

    payload = tmp_path / "payload"
    got = tmp_path / "got"
    payload.write_bytes(b"relay")
    got.write_bytes(b"relay")
    stat = type("Result", (), {"returncode": 0})()
    checks = fwd_matrix_live._relay_checks(
        got, payload, stat, semantic_log_text(relay_log))
    assert (checks[2][0], checks[3][0]) == expected


@pytest.mark.parametrize("record,identity,expected", [
    (r'message="GSI auth OK dn=\x22/C=UK/CN=Fwd\x20User\x20A\x22" truncated=0',
     "Fwd User A", True),
    (r'message="valid token sub=\x22fwd-user-a\x22" truncated=0',
     "fwd-user-a", True),
    (r'message="GSI auth OK dn=\x22/CN=localhost\x22" truncated=0',  # net-literal-allow: service identity is the negative-control subject
     "Fwd User A", False),
])
def test_backend_identity_accepts_structured_log_encoding(
        tmp_path, record, identity, expected):
    log = tmp_path / "error.log"
    log.write_text(record)
    assert helpers._ForwardHarnessMixinB.assert_backend_identity(
        "brix", log, identity) is expected

pytestmark = pytest.mark.xdist_group("cmd-fwd_matrix_live")


def test_fwd_matrix_live_is_importable():
    assert set(fwd_matrix_live.SCENARIOS) == {
        "fwd-brix-brix",
        "fwd-brix-xrootd",
        "fwd-xrootd-brix",
        "token-forward-probe",
        "transparent-relay",
    }


@pytest.mark.parametrize("available,returncode,expected", [
    (True, 0, "SUPPORTED"),
    (False, 0, "SKIP"),
    (True, 1, "SKIP"),
])
def test_token_origin_checks_namespace_access(monkeypatch, available, returncode, expected):
    from types import SimpleNamespace
    monkeypatch.setattr(helpers.shutil, "which", lambda name: "/usr/bin/bwrap" if available else None)
    calls = []

    def probe(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=returncode, stderr="uid map: Permission denied" if returncode else "")

    monkeypatch.setattr(helpers, "_call", probe)
    outcome, reason = helpers._ForwardHarnessMixinB._pairing_a_token_feasibility("root")
    assert outcome == expected
    assert bool(calls) == available
    if available and returncode:
        assert "Permission denied" in reason


@pytest.mark.optin
@pytest.mark.timeout(600)
@pytest.mark.parametrize(
    "scenario",
    [
        pytest.param(
            name,
            marks=pytest.mark.xfail(
                reason="inherited: the C HH token cell fails identically under the "
                "original run_fwd_brix_brix.sh (userA two-hop PUT/GET not byte-exact "
                "on the davs-front -> davs-back token wire) — product issue, not a "
                "port regression",
                strict=False,
            ),
        )
        if name == "fwd-brix-brix"
        else name
        for name in sorted(fwd_matrix_live.SCENARIOS)
    ],
)
def test_fwd_matrix_live_scenario(scenario: str):
    if os.environ.get("PHASE81_RUN_LIVE_PORTS") == "0":
        pytest.skip("set PHASE81_RUN_LIVE_PORTS=0 to skip live forwarding-matrix scenarios")
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    assert fwd_matrix_live.SCENARIOS[scenario](nginx) == 0
