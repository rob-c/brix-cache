"""Host-aware assertions for features that require sandboxed worker exec."""

import pytest

from brix_suite.host_caps import _worker_subprocess_supported


def require_worker_exec():
    """Call before opening any fixture listeners or starting helper threads."""
    if not _worker_subprocess_supported():
        pytest.skip("hardened workers cannot execute subprocesses on this host")


def assert_worker_exec_config(rc, output, *, diagnostic=None):
    """Supported hosts check grammar; other hosts must explicitly reject it."""
    if not _worker_subprocess_supported():
        assert rc != 0, "unsupported worker exec configuration was accepted"
        assert "hardened workers cannot execute subprocesses" in output, output
        return
    if diagnostic is None:
        assert rc == 0, output
    else:
        assert rc != 0 and diagnostic in output, output
