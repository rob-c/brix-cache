"""Phase-96 S9 — official cvmfs2 client mounts a repotool-published repo.

The one lane where the verifier is NOT our own read stack: the official
CVMFS client (registry.cern.ch/cvmfs/service container) mounts the repo over
loopback HTTP through the full trust chain and its walk dump is compared to
the published tree (hardlinks, symlink, nested catalog, chunk reassembly).
Security negatives: wrong public key, tampered catalog object and tampered
whitelist each refuse to mount. Self-skips without a container runtime,
/dev/fuse or the image (see cmdscripts.cvmfs_official_client.preflight).
"""

import pytest

from cmdscripts.cvmfs_official_client import preflight, run_checks

pytestmark = [pytest.mark.timeout(900), pytest.mark.slow]


def test_cvmfs_official_client_live(tmp_path):
    reason = preflight()
    if reason:
        pytest.skip(reason)
    results = run_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
