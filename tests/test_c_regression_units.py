from pathlib import Path

import pytest

from cmdscripts.c_regression_units import run_checks


@pytest.mark.parametrize(
    "name",
    [
        "cache_lock_reclaim",
        "flush_deadletter",
        "shm_mutex_recovery",
        "ratelimit_gauge_reset",
        "delegation_store",
        "pblock",
        "mu_unit",
        "fd_kind",
        "stage_reconcile",
        "compression",
        "sreq_compat",
        "sd_remote_wrongkind",
    ],
)
# Each case compiles a C harness before running it (~10s alone); under a full
# -n 12 lane the compiler competes with 11 other workers for cores and the
# suite-wide 30s signal-timeout is not enough headroom (seen live: the
# delegation_store binary's communicate() cut off mid-run at 30s).
@pytest.mark.timeout(120)
def test_c_regression_shell_port(tmp_path: Path, name: str):
    results = run_checks(tmp_path, [name])
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)
