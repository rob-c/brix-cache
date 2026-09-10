"""
test_phase116_recent_phases_nonregression.py — nothing recent broke or reverted.

WHAT: Re-runs, as subprocesses, the pure pin suites that phases 105–115 and
      the 2.0 readiness audit left behind, and re-asserts their binary-level
      facts directly: the removed directives stay removed, the phase-115
      purge knob stays accepted, the VFS mutation gate / VFS seam / DNS seam
      guards stay green.
WHY:  The user asked for explicit evidence that the phase-116 work — and
      the phase-115 work landing beside it — did not undo anything from the
      last month; a suite that only existed in CI history would not do.
HOW:  Each pin suite runs under `--noconftest` in its own interpreter so a
      collection error or a skip-as-pass in one cannot hide behind another;
      directive facts go through the audit-16n parse scaffold.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from _phase116_helpers import HAVE_NGINX, parse

pytestmark = [pytest.mark.timeout(900),
              pytest.mark.xdist_group("p116-nonregression")]

REPO = Path(__file__).resolve().parent.parent
TESTS = REPO / "tests"

PIN_SUITES = [
    "test_phase107_mutation_surface_closure.py",
    "test_phase107_cred_forward_audit.py",
    "test_phase108_n2n_directives.py",
    "test_phase111_register_integrity.py",
    "test_phase112_compatibility_closure.py",
    "test_phase112_consumer_surface_closure.py",
    "test_phase112_deprecation_contract_closure.py",
    "test_phase113_lock_offload_boundary.py",
    "test_phase114_credential_lifecycle_boundary.py",
    "test_release20_directive_surface.py",
    "test_release20_surface_pins.py",
    "test_port_ladder.py",
    "test_fleet_ports.py",
]

GUARDS = [
    ("check_vfs_mutation_gate.py", []),
    ("check_vfs_seam.py", []),
    ("check_dns_seam.py", []),
]


# The two ladder audits describe the SHAPE of the canonical port ladder — that
# the bands are contiguous, disjoint, and sit below the OS ephemeral floor.
# That shape is a property of the ladder definition, not of whichever lane the
# operator happens to run in: a second concurrent lane necessarily sits above
# the floor (only one full 18.7k-port lane fits under 32768), and inheriting
# its TEST_PORT_START would report the lane assignment as a phase-116
# regression.  Pin the canonical base for these two, so a real regression — a
# band edited above the floor, or an overlap — still reddens them here.
LADDER_SHAPE_AUDITS = frozenset({"test_port_ladder.py", "test_fleet_ports.py"})
CANONICAL_PORT_START = "10000"


@pytest.mark.parametrize("suite", PIN_SUITES)
def test_pin_suite_still_passes(suite):
    env = {**__import__("os").environ, "PYTHONPATH": str(TESTS)}
    if suite in LADDER_SHAPE_AUDITS:
        env["TEST_PORT_START"] = CANONICAL_PORT_START
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "--noconftest", "-p", "no:cacheprovider",
         "-q", "-x", str(TESTS / suite)],
        cwd=REPO, capture_output=True, text=True, timeout=600, env=env)
    tail = "\n".join(r.stdout.splitlines()[-15:])
    assert r.returncode == 0, f"{suite} failed:\n{tail}\n{r.stderr[-2000:]}"
    assert " passed" in tail, f"{suite} ran nothing:\n{tail}"
    assert " error" not in tail.lower(), tail


@pytest.mark.parametrize("guard, args", GUARDS)
def test_guard_is_green(guard, args):
    r = subprocess.run([sys.executable, str(REPO / "tools" / "ci" / guard), *args],
                       cwd=REPO, capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stdout + r.stderr


needs_nginx = pytest.mark.skipif(not HAVE_NGINX, reason="nginx binary unavailable")


@needs_nginx
@pytest.mark.parametrize("line", [
    "brix_pss_dca on;",
    "brix_backend_passthrough_persist on;",
])
def test_removed_directives_stay_removed(tmp_path, line):
    rc, out = parse(tmp_path, STREAM_KNOBS=line)
    assert rc != 0 and "unknown directive" in out, out


@needs_nginx
def test_phase115_purge_knob_stays_accepted(tmp_path):
    rc, out = parse(tmp_path, STREAM_KNOBS="brix_frm_purge_max_bytes 1m;")
    assert rc == 0, out


@needs_nginx
def test_phase116_directives_coexist_with_the_recent_surface(tmp_path):
    rc, out = parse(tmp_path,
                    STREAM_MAIN="brix_resolver auto; brix_dns_retry 200ms 1s; brix_dns_cache_max 64;",
                    STREAM_KNOBS="brix_frm_purge_max_bytes 1m;\nbrix_cms_manager manager.dead.test:1213;")
    assert rc == 0, out
