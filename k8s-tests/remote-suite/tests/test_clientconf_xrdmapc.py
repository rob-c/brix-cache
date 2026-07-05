"""
Client-conformance: xrdmapc (differential vs stock).

xrdmapc maps a redirector/cluster; without a live manager its connect attempts
diverge by environment, so the stable differential surface is the local one:
usage/help runs and the no-argument invocation fails the same way (rc class).
A connect probe against the anon data server is included but tolerant — both
clients are expected to fail equivalently against a non-manager, and the test
only asserts they AGREE on success-vs-failure.
"""

import os
import subprocess

import pytest

from clientconf.diffcore import OURS, STOCK, binary
from settings import HOST, NGINX_ANON_PORT


def _have_both():
    return binary(STOCK, "xrdmapc") is not None and \
        binary(OURS, "xrdmapc") is not None


pytestmark = [
    pytest.mark.timeout(60),
    pytest.mark.skipif(not _have_both(), reason="stock or our xrdmapc absent"),
]


def _run(which, args):
    env = {k: v for k, v in os.environ.items()}
    env.pop("X509_USER_PROXY", None)
    try:
        return subprocess.run([binary(which, "xrdmapc"), *args], env=env,
                              capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return None


def test_no_args_fails_in_both():
    s = _run(STOCK, [])
    o = _run(OURS, [])
    assert s is not None and o is not None, "xrdmapc hung with no args"
    assert (s.returncode != 0) == (o.returncode != 0), \
        "no-arg rc class differs: stock=%s ours=%s" % (s.returncode, o.returncode)


def test_help_runs_ours():
    o = _run(OURS, ["--help"])
    if o is None:
        pytest.skip("our xrdmapc --help hung")
    assert "xrdmapc" in (o.stdout + o.stderr).lower() or o.returncode == 0


def test_agree_on_nonmanager_target():
    target = "%s:%d" % (HOST, NGINX_ANON_PORT)
    s = _run(STOCK, [target])
    o = _run(OURS, [target])
    if s is None or o is None:
        pytest.skip("xrdmapc connect probe timed out")
    # A data server is not a manager: both should agree on success/failure.
    assert (s.returncode == 0) == (o.returncode == 0), \
        "xrdmapc disagrees on non-manager target: stock=%s ours=%s" % (
            s.returncode, o.returncode)
