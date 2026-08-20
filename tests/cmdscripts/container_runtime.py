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

A lab that needs one particular engine's *CLI surface* rather than "a
container runtime" narrows the probe with ``candidates``: the phase-104 OCI
mirror oracle pulls through a cleartext registry, which podman trusts with a
per-invocation ``--tls-verify=false`` and docker only through daemon-level
``insecure-registries`` — editing ``/etc/docker/daemon.json`` and restarting
the engine is not something a test may do. Within a narrowed probe a forced
``$BRIX_CONTAINER_RUNTIME`` that is not one of the candidates yields ``None``:
pinning docker cannot make a podman-only lab run, it can only make it skip.
"""

from __future__ import annotations

import os
import shutil
from typing import Sequence

from cmdscripts.compile_run import REPO_ROOT, run

# docker first so an operator who has both keeps the historical behaviour; a
# forced $BRIX_CONTAINER_RUNTIME overrides the order and the probe list alike.
_CANDIDATES = ("docker", "podman")


def container_runtime(candidates: Sequence[str] | None = None) -> str | None:
    """First working docker-compatible runtime, or None if none is usable."""
    forced = os.environ.get("BRIX_CONTAINER_RUNTIME")
    probe: Sequence[str] = candidates if candidates is not None else _CANDIDATES
    if forced:
        if candidates is not None and forced not in candidates:
            return None
        probe = (forced,)
    for name in probe:
        if name and shutil.which(name) and run([name, "info"], cwd=REPO_ROOT).returncode == 0:
            return name
    return None
