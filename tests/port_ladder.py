"""Contiguous, relocatable ladder for central Python test infrastructure.

Set ``TEST_PORT_START`` to the number immediately below the first allocated
port.  For example, ``TEST_PORT_START=10000`` allocates 10001..11039.

The old values remain beside their owning constants/ledger entries in
``settings.py``, ``fleet_lifecycle_ports.py`` and ``fleet_ports.py``.  They are
the historical ports used while each test was developed; this module only
translates those named allocations onto a compact per-run lane.
"""

from __future__ import annotations

import os


PORT_START = int(os.environ.get("TEST_PORT_START", "10000"))

# Stable category offsets.  Width changes are intentional compatibility events:
# a caller uses PORT_COUNT to choose the next non-overlapping lane.
SETTINGS_OFFSET, SETTINGS_WIDTH = 0, 178
# 2026-08-09: 523 -> 531 for the CMS parity wave + HTTP redirect lifecycle
# subjects (test_cms_parity_wave.py: lc-cms-parity-mgr(+CMS_PORT)/-node;
# test_webdav_redirect_ds.py: lc-webdav-redirect-mgr(+HTTP+CMS)/-ds(+HTTP)).
LIFECYCLE_SHARED_OFFSET, LIFECYCLE_SHARED_WIDTH = 178, 531
# 2026-08-09: 137 -> 140 for the three audit-fix lifecycle subjects
# (test_audit_fixes_2026_08_09.py: only-if-cached, cold-purge, signing).
# Every offset below shifts by the same 3 — the ladder is packed, so a width
# change is an intentional compatibility event (see the note above).
LIFECYCLE_EXCLUSIVE_OFFSET, LIFECYCLE_EXCLUSIVE_WIDTH = 709, 140
CMDSCRIPTS_OFFSET, CMDSCRIPTS_WIDTH = 849, 205
CMS_MESH_OFFSET, CMS_MESH_WIDTH = 1054, 83
HYBRID_MESH_OFFSET, HYBRID_MESH_WIDTH = 1137, 23
PLACEHOLDERS_OFFSET, PLACEHOLDERS_WIDTH = 1160, 2
# CVMFS conformance mock-Stratum-1 + nginx port blocks (cvmfs/conformance_common.py
# PORT_BLOCKS): 26 files x a 20-port block.  Anchored into the ladder so every
# port stays within TEST_PORT_START+2000 and a second suite on a different
# TEST_PORT_START draws a disjoint range (replaces the old absolute 13100+ tiling).
# 27 file blocks x 20 ports = 540, plus a 48-port matrix sub-range for the
# concurrent fuse-trust mock origins (see conformance_common.matrix_port).
CVMFS_CONFORMANCE_OFFSET, CVMFS_CONFORMANCE_WIDTH = 1162, 588
# Differential-interop per-file fixed ports (official_interop_lib.worker_port):
# one slot per distinct conformance base (61 today), anchored here so they stay
# in the contiguous ladder within TEST_PORT_START+2000 instead of the old
# absolute 30000-49925 per-worker band.  The owning module is pinned to one xdist
# worker (conftest auto-xdist_group), so a fixed port per file suffices.
INTEROP_WORKER_OFFSET, INTEROP_WORKER_WIDTH = 1750, 61
PORT_COUNT = 1811
PORT_FIRST = PORT_START + 1
PORT_LAST = PORT_START + PORT_COUNT

if not 1024 <= PORT_FIRST <= PORT_LAST <= 65535:
    raise ValueError(
        f"TEST_PORT_START={PORT_START} yields invalid test port range "
        f"{PORT_FIRST}..{PORT_LAST}; choose a base whose complete "
        f"{PORT_COUNT}-port lane fits within 1024..65535"
    )


def _port(offset: int, index: int) -> int:
    return PORT_START + offset + index + 1


def rebase_settings(namespace: dict) -> None:
    """Rebase settings ``*_PORT`` constants in source-definition order.

    ``XRDHTTP_HTTPS_PORT`` was historically an alias of
    ``XRDHTTP_HTTP_PORT`` (original port 11113) and remains an alias rather than
    consuming a second socket slot.
    """
    names = [
        name for name, value in namespace.items()
        if "_PORT" in name
        and name != "TEST_PORT_START"
        and isinstance(value, int)
    ]
    aliases = {"XRDHTTP_HTTPS_PORT": "XRDHTTP_HTTP_PORT"}
    owners = [name for name in names if name not in aliases]
    if len(owners) != SETTINGS_WIDTH:
        raise RuntimeError(
            f"settings port ladder expected {SETTINGS_WIDTH} allocations, "
            f"found {len(owners)}; update port_ladder.py intentionally"
        )
    for index, name in enumerate(owners):
        namespace[name] = _port(SETTINGS_OFFSET, index)
    for alias, owner in aliases.items():
        namespace[alias] = namespace[owner]
    # Config renderers and non-Python helpers historically consume the
    # unprefixed names, while some subprocesses import settings through the
    # TEST_* compatibility variables.  Publish one centrally assigned value to
    # both spellings so every child receives the same lane.
    for name in names:
        value = str(namespace[name])
        os.environ[name] = value
        os.environ[f"TEST_{name}"] = value


def rebase_lifecycle_ledger(ledger: dict, *, shared: bool) -> None:
    """Rebase a lifecycle ledger while preserving its insertion order."""
    offset = LIFECYCLE_SHARED_OFFSET if shared else LIFECYCLE_EXCLUSIVE_OFFSET
    expected = LIFECYCLE_SHARED_WIDTH if shared else LIFECYCLE_EXCLUSIVE_WIDTH
    slots = []
    for entry in ledger.values():
        slots.append((entry, "port"))
        slots.extend((entry["extra"], key) for key in entry.get("extra", {}))
    if len(slots) != expected:
        kind = "shared" if shared else "exclusive"
        raise RuntimeError(
            f"{kind} lifecycle ladder expected {expected} allocations, "
            f"found {len(slots)}; update port_ladder.py intentionally"
        )
    for index, (container, key) in enumerate(slots):
        container[key] = _port(offset, index)


def rebase_cmdscripts(blocks: dict[str, tuple[int, int]]) -> dict[str, tuple[int, int]]:
    """Return command-suite blocks packed contiguously in declaration order."""
    total = sum(span for _original, span in blocks.values())
    if total != CMDSCRIPTS_WIDTH:
        raise RuntimeError(
            f"cmdscripts ladder expected {CMDSCRIPTS_WIDTH} allocations, found "
            f"{total}; update port_ladder.py intentionally"
        )
    rebased = {}
    index = 0
    for name, (_original, span) in blocks.items():
        rebased[name] = (_port(CMDSCRIPTS_OFFSET, index), span)
        index += span
    return rebased


def rebase_named_ports(ports: dict[str, int], *, category: str) -> dict[str, int]:
    """Pack a registry-owned external orchestrator's named listeners."""
    categories = {
        "cms-mesh": (CMS_MESH_OFFSET, CMS_MESH_WIDTH),
        "hybrid-mesh": (HYBRID_MESH_OFFSET, HYBRID_MESH_WIDTH),
    }
    offset, expected = categories[category]
    if len(ports) != expected or len(set(ports.values())) != expected:
        raise RuntimeError(
            f"{category} ladder expected {expected} unique allocations, found "
            f"{len(ports)} names/{len(set(ports.values()))} values; update "
            "port_ladder.py intentionally"
        )
    return {name: _port(offset, index) for index, name in enumerate(ports)}


def placeholder_port(index: int) -> int:
    if not 0 <= index < PLACEHOLDERS_WIDTH:
        raise IndexError(index)
    return _port(PLACEHOLDERS_OFFSET, index)
