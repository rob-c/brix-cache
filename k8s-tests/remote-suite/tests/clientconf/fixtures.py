"""
fixtures — session setup shared by every test_clientconf_* module.

Provides the ``clientconf_env`` session fixture which:
  * builds the project clients on demand (``make -C client``),
  * seeds the deterministic corpus under the shared data root, and
  * probes each endpoint ONCE with the stock client, returning the set of
    healthy endpoint keys so per-test runs SKIP (never fail) on a down
    server/credential.

Test modules import the fixture by name: ``from clientconf.fixtures import
clientconf_env``.
"""

import os
import shutil
import subprocess

import pytest

from settings import DATA_ROOT

from . import corpus
from . import endpoints as E
from . import diffcore


def _worker_id():
    return os.environ.get("PYTEST_XDIST_WORKER", "main")


def _build_our_clients():
    """Build the project clients if missing; return True on success."""
    repo = diffcore.REPO
    if os.path.exists(os.path.join(repo, "client", "bin", "xrdfs")):
        return True
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        return False
    proc = subprocess.run(["make", "-C", os.path.join(repo, "client")],
                          capture_output=True, text=True, timeout=300)
    return proc.returncode == 0


@pytest.fixture(scope="session")
def clientconf_env():
    """Seed corpus + discover healthy endpoints once per session."""
    if not _build_our_clients():
        pytest.skip("project clients could not be built")

    # Seed the corpus into the shared export (visible on every endpoint).
    try:
        corpus.seed(DATA_ROOT)
    except OSError as e:
        pytest.skip("cannot seed corpus under %s: %s" % (DATA_ROOT, e))

    stock = E.stock_xrdfs()
    healthy = set()
    for ep in E.ENDPOINTS:
        if ep.healthy(stock, probe=corpus.ROOT):
            healthy.add(ep.key)

    if not healthy:
        pytest.skip("no client-conformance endpoint is reachable")

    return {
        "healthy": healthy,
        "worker": _worker_id(),
        "stock_xrdfs": stock,
    }
