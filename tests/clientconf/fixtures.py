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
import tempfile
from contextlib import contextmanager
from brix_suite.client_build import client_make
from concurrent.futures import ThreadPoolExecutor

import pytest

from settings import DATA_ROOT

from . import corpus
from . import endpoints as E
from . import diffcore


def _guard_clientconf_env_1():
    if not _build_our_clients():
        pytest.skip("project clients could not be built")

def _guard_clientconf_env_3(healthy):
    if not healthy:
        pytest.skip("no client-conformance endpoint is reachable")

def _guard_clientconf_env_2(stock, ep, healthy):
    if ep.healthy(stock, probe=corpus.ROOT):
        healthy.add(ep.key)


def _worker_id():
    return os.environ.get("PYTEST_XDIST_WORKER", "main")


def _build_our_clients():
    """Build the project clients if missing; return True on success."""
    repo = diffcore.REPO
    if os.path.exists(os.path.join(repo, "client", "bin", "xrdfs")):
        return True
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        return False
    proc = client_make(os.path.join(repo, "client"), capture_output=True, text=True, timeout=300)
    return proc.returncode == 0


def _session_endpoints(private_directory):
    """Give stock ztn an owner-only client copy, not the worker-readable JWT.

    The shared fixture stays readable by nginx's de-escalated worker. Stock
    ztn correctly refuses that mode, so client credentials need a separate
    owner-only inode. Never chmod or reassign the shared server credential.
    """
    endpoints = dict(E.BY_KEY)
    if not os.path.isfile(E.TOKEN_FILE):
        return endpoints
    descriptor, filename = tempfile.mkstemp(prefix="bearer-", dir=private_directory)
    with os.fdopen(descriptor, "wb") as output, open(E.TOKEN_FILE, "rb") as source:
        shutil.copyfileobj(source, output)
    token = E.TOKEN
    auth = dict(token._auth, BEARER_TOKEN_FILE=filename)
    endpoints[token.key] = E.Endpoint(token.key, token.host, token.port,
                                     caps=token.caps, auth=auth, scheme=token.scheme)
    return endpoints


@contextmanager
def _client_credential_directory(tmp_path_factory):
    """Keep private copies in the credential fixture's own namespace.

    The optional external reference can read only the proven shared fixture
    tree, not the native server's separate pytest temp directory. A private
    0700 sibling directory retains that confinement and the token's 0600 mode.
    Missing fixture credentials stay missing; no ambient token is substituted.
    """
    parent = os.path.dirname(E.TOKEN_FILE) if os.path.isfile(E.TOKEN_FILE) \
        else tmp_path_factory.getbasetemp()
    with tempfile.TemporaryDirectory(prefix='clientconf-credentials-', dir=parent) as directory:
        yield directory


@pytest.fixture(scope="session")
def clientconf_env(tmp_path_factory):
    """Seed corpus + discover healthy endpoints once per session."""
    _guard_clientconf_env_1()

    # Seed the corpus into the shared export (visible on every endpoint).
    try:
        corpus.seed(DATA_ROOT)
    except OSError as e:
        pytest.skip("cannot seed corpus under %s: %s" % (DATA_ROOT, e))

    stock = E.stock_xrdfs()
    with _client_credential_directory(tmp_path_factory) as directory:
        endpoints = _session_endpoints(directory)
        healthy = set()
        for ep in endpoints.values():
            _guard_clientconf_env_2(stock, ep, healthy)

        _guard_clientconf_env_3(healthy)

        yield {
            "healthy": healthy,
            "worker": _worker_id(),
            "stock_xrdfs": stock,
            "endpoints": endpoints,
        }
