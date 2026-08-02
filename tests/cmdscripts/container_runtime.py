"""Resolve a docker-CLI-compatible container runtime (docker or rootless podman).

Every live container lab in this tree (STS/MinIO, Ceph, gridftp-interop) was
first written against the ``docker`` CLI. In practice the dev boxes and CI
runners this project targets frequently ship only rootless ``podman``, which is
command-line compatible for the verbs the labs actually use
(``info``/``images``/``run``/``rm``/``exec``/``cp``). A hard ``shutil.which(
"docker")`` gate makes such a lab self-skip on a perfectly capable host, so the
"packaged live lab" never runs where it could.

``container_runtime()`` returns the first candidate that is both present on
``PATH`` *and* able to reach a working engine (``<rt> info`` exits 0 — this is
what catches a binary that exists but has no usable daemon/socket), or ``None``
when neither is usable. Set ``$BRIX_CONTAINER_RUNTIME`` to pin one explicitly
(e.g. force ``docker`` on a host that also has podman).
"""

from __future__ import annotations

import os
import shutil

from cmdscripts.compile_run import REPO_ROOT, run

# docker first so an operator who has both keeps the historical behaviour; a
# forced $BRIX_CONTAINER_RUNTIME overrides the order and the probe list alike.
_CANDIDATES = ("docker", "podman")


def container_runtime() -> str | None:
    """First working docker-compatible runtime, or None if none is usable."""
    forced = os.environ.get("BRIX_CONTAINER_RUNTIME")
    candidates = (forced,) if forced else _CANDIDATES
    for name in candidates:
        if name and shutil.which(name) and run([name, "info"], cwd=REPO_ROOT).returncode == 0:
            return name
    return None
