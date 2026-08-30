"""The SD driver slots closed in the storage-driver gap wave.

Each of these slots decides something the build cannot check and a live test
would not notice.  http and remote both answer "can these bytes be read right
now?" without paying for a retrieval: an unknown Tape REST locality must be an
ERROR (that vocabulary is closed, so an unfamiliar token means we are not
talking to the API at all) while an unknown S3 storage class must be ONLINE (AWS
adds them routinely and every one outside the archival list serves reads
directly), a completed restore is ONLINE rather than another retrieval, and a
residency call that was DENIED must never fall through to a billable recall.
block decides who may hold a bare descriptor: an extent based anywhere but
device offset 0 must never be offered for zero-copy, because its consumer
addresses that descriptor with logical offsets and would read the neighbouring
extent.  Each unit drives its driver through mocked delegates so every scenario
is deterministic; see tests/unit/test_sd_*.c.

Parametrised straight off cmdscripts.sd_slot_unit.UNITS so a unit that is added
to the runner cannot be silently left out of the suite.

Skips cleanly when no C toolchain is present.
"""
import shutil

import pytest

from cmdscripts.sd_slot_unit import UNITS, run_one


@pytest.mark.skipif(shutil.which("gcc") is None, reason="need gcc to build the C unit")
@pytest.mark.parametrize("name", sorted(UNITS))
def test_sd_slot_verdicts(tmp_path, name):
    results = run_one(tmp_path, name)
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
