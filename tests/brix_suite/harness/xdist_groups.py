"""Make xdist group markers authoritative for the load-group scheduler."""

from __future__ import annotations


def _marker_name(marker) -> str:
    if marker.args:
        return str(marker.args[0])
    return str(marker.kwargs.get("name", "default"))


def materialize_xdist_group(item) -> None:
    """Write the final xdist group set into the node id used by the scheduler.

    xdist normally performs this rewrite itself.  A conftest can add or replace
    groups after xdist's hook has run, though, and changing ``dist`` from
    ``load`` to ``loadgroup`` during configuration is also too late for some
    workers.  Rewriting once after this suite's collection policy has settled
    makes the marker effective in both cases.
    """
    forced = getattr(item, "_brix_xdist_group_override", None)
    names = ({forced} if forced else {
        _marker_name(marker) for marker in item.iter_markers("xdist_group")
    })
    names.discard(None)
    if not names:
        return
    base = item.nodeid.split("@", 1)[0]
    item._nodeid = f"{base}@{'_'.join(sorted(names))}"
