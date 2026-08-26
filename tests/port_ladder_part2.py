# port_ladder_part2.py — the rebase/placeholder helpers, split off from
# port_ladder.py for the 600 logical-line cap. Exec'd into port_ladder's
# namespace by split_continuation.load, so `from port_ladder import <fn>`
# keeps resolving and the helpers still see the module's offset constants.

def _expression_1(shared):
    return (
        LIFECYCLE_SHARED_OFFSET if shared else LIFECYCLE_EXCLUSIVE_OFFSET
    )

def _expression_2(shared):
    return (
        LIFECYCLE_SHARED_WIDTH if shared else LIFECYCLE_EXCLUSIVE_WIDTH
    )

def _expression_3(shared):
    return (
        "shared" if shared else "exclusive"
    )

def _expression_4(namespace):
    return (
        [
                name for name, value in namespace.items()
                if "_PORT" in name
                and name != "TEST_PORT_START"
                and isinstance(value, int)
            ]
    )

def _expression_5(names, aliases):
    return (
        [name for name in names if name not in aliases]
    )


def _guard_rebase_settings_1(owners):
    if len(owners) != SETTINGS_WIDTH:
        raise RuntimeError(
            f"settings port ladder expected {SETTINGS_WIDTH} allocations, "
            f"found {len(owners)}; update port_ladder.py intentionally"
        )



# Stable category offsets.  Width changes are intentional compatibility events:
# a caller uses PORT_COUNT to choose the next non-overlapping lane.


def _port(offset: int, index: int) -> int:
    return PORT_START + offset + index + 1


def rebase_settings(namespace: dict) -> None:
    """Rebase settings ``*_PORT`` constants in source-definition order.

    ``XRDHTTP_HTTPS_PORT`` was historically an alias of
    ``XRDHTTP_HTTP_PORT`` (original port 11113) and remains an alias rather than
    consuming a second socket slot.
    """
    names = _expression_4(namespace)
    aliases = {"XRDHTTP_HTTPS_PORT": "XRDHTTP_HTTP_PORT"}
    owners = _expression_5(names, aliases)
    _guard_rebase_settings_1(owners)
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
    offset = _expression_1(shared)
    expected = _expression_2(shared)
    slots = []
    for entry in ledger.values():
        slots.append((entry, "port"))
        slots.extend((entry["extra"], key) for key in entry.get("extra", {}))
    if len(slots) != expected:
        kind = _expression_3(shared)
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
