"""
Shadow ``XRootD`` package (tests-only).

This package deliberately SHADOWS the real pyxrootd/XrdCl bindings inside the
pytest interpreter.  Because ``tests/`` is on PYTHONPATH ahead of site-packages,
``import XRootD`` from a test resolves here instead of to the C-extension
bindings.

Nothing in this package imports the real bindings.  Every XrdCl operation is
forwarded to an out-of-process worker (tests/_xrdcl_worker.py) that hosts the
real bindings, so the deadlock-prone XrdCl poller threads never run inside
pytest.  See tests/_xrdcl_proxy.py for the rationale and protocol.
"""

from . import client  # noqa: F401
