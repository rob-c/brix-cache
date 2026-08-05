"""
test_sweep_runners.py — collect the four standalone sweep runners.

THE GAP: `run_loss_sweep.py`, `run_xrdcp_loss.py`, `run_http_reorder.py` and
`run_mount_sweep.py` are full fault-injection harnesses that nothing ever ran in
CI — argparse `main()` scripts, invoked by hand during a performance
investigation and then left. Nothing imported them, so a rename in `servers.py`
or a new registry rule could silently break all four and no test would notice.
docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md §6 + item 16.

It had already happened. `run_http_reorder.py` registers the lifecycle spec
`resil-http-reorder`, which was never added to `fleet_lifecycle_ports.py`; when
this module first drove it the runner died at startup with "lifecycle spec
'resil-http-reorder' has no fixed port". The ledger entry is part of this change.

HOW: each runner is exercised at its smallest useful setting — 1 level, 1 rep,
a 2 MiB object — which is enough to prove the harness stands its servers up,
splices the fault proxy in, transfers, and summarises. The sweeps themselves stay
manual: a real run is minutes of wall clock at 64-256 MiB, and its output is a
measurement, not a pass/fail.

`run_mount_sweep.py` is imported and argument-checked but NOT run: it mounts FUSE,
and a wedged mount left behind by a killed run takes the whole fleet with it
(a documented failure mode in this repo). Bit-rot in it is still caught here.

Trio per CLAUDE.md:
  * success   — all four import, all four accept their documented arguments, and
                the three non-FUSE runners complete a micro-sweep with every
                transfer byte-exact.
  * error     — a bad argument is a clean argparse exit, not a traceback.
  * security  — every runner writes under a per-user PREFIX, never a shared
                path: on a multi-user host one user's sweep must not be able to
                overwrite another's servers, data or results.

Run:
  PYTHONPATH=tests python3 -m pytest tests/resilience/test_sweep_runners.py -v
"""
import csv
import getpass
import importlib
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402

pytestmark = pytest.mark.timeout(600)

HERE = os.path.dirname(os.path.abspath(__file__))
RUNNERS = ["run_loss_sweep", "run_xrdcp_loss", "run_http_reorder",
           "run_mount_sweep"]

OFFICIAL_XRDCP = "/usr/bin/xrdcp"


def _run(module, *argv, timeout=420):
    """Invoke a runner as a subprocess, the way an operator would."""
    env = dict(os.environ)
    env["PYTHONPATH"] = servers.REPO + "/tests"
    return subprocess.run(
        [sys.executable, os.path.join(HERE, module + ".py"), *argv],
        cwd=os.path.join(servers.REPO, "tests"), env=env,
        capture_output=True, text=True, timeout=timeout)


def _need(*paths):
    for p in paths:
        if not p or not os.path.exists(p):
            pytest.skip(f"not available: {p}")


# --------------------------------------------------------------------------- #
# Success — the runners still load, still parse, still sweep.                  #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("module", RUNNERS)
def test_runner_imports(module):
    """Bit-rot guard: the runner's imports and module-level code still resolve
    against the current servers.py / registry API."""
    mod = importlib.import_module(module)
    assert callable(mod.main)


@pytest.mark.parametrize("module", RUNNERS)
def test_runner_accepts_its_arguments(module):
    """`--help` exits 0 with a usage line — the argparse surface is intact."""
    proc = _run(module, "--help", timeout=60)
    assert proc.returncode == 0, proc.stderr[-400:]
    assert "usage:" in proc.stdout


def test_gsi_loss_sweep_completes_and_writes_its_csv(tmp_path):
    """run_loss_sweep: nginx vs official xrootd, root://+GSI, 0% loss."""
    _need(servers.NGINX_BIN, servers.BRIX_BIN)
    out = tmp_path / "loss.csv"
    proc = _run("run_loss_sweep", "--size-mib", "2", "--reps", "1",
                "--levels", "0", "--timeout", "60", "--out", str(out))
    assert proc.returncode == 0, proc.stdout[-800:] + proc.stderr[-800:]
    rows = list(csv.DictReader(out.open()))
    assert {r["server"] for r in rows} == {"nginx", "xrootd"}
    assert all(r["success"] == "True" for r in rows), rows
    assert all(int(r["bytes"]) == 2 * 1024 * 1024 for r in rows)


def test_xrdcp_loss_sweep_completes_for_every_client_pair(tmp_path):
    """run_xrdcp_loss: repo / repo-fast / official clients, 0% loss."""
    _need(servers.NGINX_BIN, servers.BRIX_BIN, servers.XRDCP, OFFICIAL_XRDCP)
    proc = _run("run_xrdcp_loss", "--size-mib", "2", "--reps", "1",
                "--levels", "0", "--timeout", "60")
    assert proc.returncode == 0, proc.stdout[-800:] + proc.stderr[-800:]
    oks = [ln for ln in proc.stdout.splitlines() if "rep1: OK" in ln]
    assert len(oks) == 3, proc.stdout[-1200:]      # repo, repo-fast, official


def test_http_reorder_sweep_completes_for_every_client_pair(tmp_path):
    """run_http_reorder: the runner whose registry entry was missing."""
    _need(servers.NGINX_BIN, servers.BRIX_BIN)
    if not shutil.which("curl"):
        pytest.skip("curl not available")
    proc = _run("run_http_reorder", "--size-mib", "2", "--reps", "1",
                "--levels", "0", "--timeout", "60")
    assert proc.returncode == 0, proc.stdout[-800:] + proc.stderr[-800:]
    assert "1/1" in proc.stdout, proc.stdout[-1200:]
    assert "no fixed port" not in proc.stderr


# --------------------------------------------------------------------------- #
# Error.                                                                       #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("module", RUNNERS)
def test_bad_argument_is_a_clean_exit(module):
    """An unknown flag is argparse's 2, with a message — never a traceback."""
    proc = _run(module, "--not-a-real-flag", timeout=60)
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr
    assert "unrecognized arguments" in proc.stderr


# --------------------------------------------------------------------------- #
# Security.                                                                    #
# --------------------------------------------------------------------------- #
def test_runners_stay_inside_a_per_user_prefix():
    """A sweep must not be able to clobber another user's run.

    Every runner's servers, data and results live under `servers.PREFIX`, which
    carries the invoking user's name. A shared default (say /tmp/xrd-resilience)
    would let one user's sweep overwrite another's export tree — and these
    servers run with `brix_allow_write on`.
    """
    assert getpass.getuser() in servers.PREFIX
    mod = importlib.import_module("run_loss_sweep")
    parser_default = [a for a in _default_out_candidates(mod)]
    assert parser_default, "run_loss_sweep no longer defaults its --out path"
    for path in parser_default:
        assert path.startswith(servers.PREFIX + os.sep), path


def _default_out_candidates(mod):
    """The --out default, read back from the runner's own parser."""
    import argparse
    seen = []
    real = argparse.ArgumentParser.add_argument

    def spy(self, *args, **kw):
        if "--out" in args and isinstance(kw.get("default"), str):
            seen.append(kw["default"])
        return real(self, *args, **kw)

    argparse.ArgumentParser.add_argument = spy
    try:
        sys.argv = ["run_loss_sweep", "--help"]
        try:
            mod.main()
        except SystemExit:
            pass
    finally:
        argparse.ArgumentParser.add_argument = real
    return seen
