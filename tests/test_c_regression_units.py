from pathlib import Path

import pytest

from cmdscripts.c_regression_units import RUNNERS, run_checks


# Parametrized from the runner table itself, never a hand-kept copy of it: a
# maintained list silently orphans every unit added to RUNNERS but forgotten
# here, and they then compile and run only when someone invokes the runner by
# hand. That is how the kXR_prepare packer went missing from sd_xroot_setattr's
# link closure with no red anywhere — 19 units were registered and unreachable.
# tests/test_c_object_units.py derives from its SPECS dict for the same reason.
@pytest.mark.parametrize("name", sorted(RUNNERS))
# Each case compiles a C harness before running it (~10s alone); under a full
# -n 12 lane the compiler competes with 11 other workers for cores and the
# suite-wide 30s signal-timeout is not enough headroom (seen live: the
# delegation_store binary's communicate() cut off mid-run at 30s).
@pytest.mark.suite_job
@pytest.mark.timeout(120)
def test_c_regression_shell_port(tmp_path: Path, name: str):
    results = run_checks(tmp_path, [name])
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)
