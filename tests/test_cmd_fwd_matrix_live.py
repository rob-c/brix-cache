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
    from cmdscripts import _fwd_matrix_live_part2_mixinb as helpers

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
