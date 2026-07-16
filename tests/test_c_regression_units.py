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
        "stage_reconcile",
        "compression",
        "sreq_compat",
        "sd_remote_wrongkind",
    ],
)
def test_c_regression_shell_port(tmp_path: Path, name: str):
    results = run_checks(tmp_path, [name])
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)
