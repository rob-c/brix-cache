"""Helpers for selecting the backend used by cross-compatible test modules.

``selected_backend_name()`` is a *process-wide* switch: a module reads it at
import time and binds its endpoint constants once, so a run covers one
implementation and the other needs a second `pytest` invocation with
``TEST_CROSS_BACKEND=xrootd``. Nothing in the repo ever sets that variable —
the 2026-08-04 coverage audit's finding — so a default `pytest tests/` run
exercised the nginx side only.

``BACKENDS`` / ``anon_url()`` are the per-*test* form of the same axis: both
implementations are reachable inside one process (they are always-on backbone
fleet members serving the same export), so a parametrized test compares them
directly instead of relying on two runs nobody launches. See
``test_cross_backend_parity.py``.
"""

import os
from urllib.parse import urlparse

from settings import (
    HOST,
    NGINX_ANON_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
)

#: The two root:// implementations under comparison. Both boot every session.
BACKENDS = ("nginx", "xrootd")


def selected_backend_name() -> str:
    """Return the backend selected for the current pytest process."""
    name = os.environ.get("TEST_CROSS_BACKEND", "nginx").strip().lower()
    if name not in set(BACKENDS):
        raise RuntimeError(
            "TEST_CROSS_BACKEND must be 'nginx' or 'xrootd', "
            f"got {name!r}"
        )
    return name


def anon_url(backend: str) -> str:
    """The anonymous root:// endpoint for `backend`, resolved per call.

    Both endpoints export the same shared data root (``fleet_specs.core_specs``
    gives ``main`` and ``ref-anon`` the same ``_data("data")``), which is what
    makes a byte-for-byte parity comparison meaningful: one seeded file, two
    servers, one expected answer.
    """
    if backend not in set(BACKENDS):
        raise RuntimeError(f"unknown backend {backend!r}; expected one of {BACKENDS}")
    if backend == "xrootd":
        return f"root://{HOST}:{REF_BRIX_PORT}"
    return f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"


def root_endpoint_parts(url: str, default_port: int = 1094) -> tuple[str, int]:
    """Parse a root:// style URL into host/port parts for raw-socket tests."""
    parsed = urlparse(url if "://" in url else f"root://{url}")
    return parsed.hostname or HOST, parsed.port or default_port
