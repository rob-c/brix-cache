"""
tests/test_phase115_cms_locate_entry_types.py — Phase-115 W8.4 §2.18: the
entry-type character in a multi-server kXR_locate answer.

THE BUG
-------
`brix_srv_locate_all` (src/net/manager/registry_health.c) built every entry as

    snprintf(entry, ..., "%sS%c%s", sep, for_write ? 'w' : 'r', hostport);

— a hardcoded 'S'.  The registry knows each node's role (§2.9/§2.17 classify it
at login: "S" data server, "M" manager, "R" supervisor, "P" peer, "PS" proxy
server), and stock XRootD's locate vocabulary distinguishes them: uppercase
means confirmed, lowercase means "known, not currently confirmed", `S` means
"open your data here" and `M` means "ask this one".  Publishing a manager as `S`
tells a client to open a file against a node that holds no data.

This is not theoretical.  brix's own client already reads the character:
`client/lib/xfer/copy_xcp_sources.c` skips `M`/`m` entries when building an xcp
source set, so a mislabelled manager was being dialled as a data source by the
very client that shipped alongside it.

THE FIX, AND WHY IT IS SAFE BY DEFAULT
--------------------------------------
`srv_locate_type_char()` derives the character from the entry's role and
lowercases it when `brix_manager_stale_after` says the node has not been heard
from.  Both halves are inert unless something opts in: every node in the
existing corpus is role "S", and `brix_manager_stale_after` defaults to 0 (no
entry is ever stale), so `test_cms_affinity_multi.py`'s `Sr<host>:<port>`
fullmatch still holds byte for byte.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest \
        tests/test_phase115_cms_locate_entry_types.py -v
"""

import os
import time

import pytest

from _test_cms_parity_wave_helpers import (
    CMS_RR_PING,
    MODE_MANAGER,
    MODE_SERVER,
    FakeNode,
    _locate,
    _mgr,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(90),
              pytest.mark.xdist_group("lc-p115-cms-loctype")]

MGR = "lc-p115-cms-loctype-mgr"
kXR_ok = 0

# Role bits, as cms_srv_parse_login classifies them (server_recv_parse.c:321).
MODE_SUPERVISOR = MODE_MANAGER | MODE_SERVER      # -> role "R"


def _entries(root_port, path):
    """(status, {port: entry-token}) for one multi-server locate."""
    status, body = _locate(root_port, path)
    if status != kXR_ok:
        return status, {}
    text = body.rstrip(b"\x00").decode("ascii")
    out = {}
    for tok in text.split(" "):
        if tok:
            out[int(tok.rsplit(":", 1)[1])] = tok
    return status, out


def _wait_entries(root_port, path, want_ports, timeout=10.0):
    """Poll until every port in want_ports is listed; return the entry map."""
    deadline = time.time() + timeout
    seen = {}
    while time.time() < deadline:
        status, seen = _entries(root_port, path)
        if status == kXR_ok and want_ports <= set(seen):
            return seen
        time.sleep(0.2)
    raise AssertionError(f"locate never listed {sorted(want_ports)}: {seen}")


def _settle(*nodes):
    for node in nodes:
        assert node.wait_frame(CMS_RR_PING) is not None, \
            f"node {node.dport} never registered"


# ═══ success: the character is the role, not a constant ═══════════════════

def test_managers_and_supervisors_are_published_as_M_not_S(lifecycle):
    """success: three nodes, three roles, two distinct type characters.

    A pure manager (kYR_manager alone -> role "M") and a supervisor
    (kYR_manager|kYR_server -> role "R") both publish as `M`; only the plain
    data server publishes as `S`.  Asserting all three in one list is what
    separates "the role is read" from "the constant was swapped".
    """
    root_port, cms_port = _mgr(
        lifecycle, MGR, "brix_cms_locate_multi on;",
        "§2.18: locate entry type follows the registry role.")
    manager = FakeNode(cms_port, 42441, mode=MODE_MANAGER)
    supervisor = FakeNode(cms_port, 42442, mode=MODE_SUPERVISOR)
    server = FakeNode(cms_port, 42443, mode=MODE_SERVER)
    try:
        _settle(manager, supervisor, server)
        seen = _wait_entries(root_port, "/loctype/a.dat",
                             {42441, 42442, 42443})
        assert seen[42441][0] == "M", f"role M must publish M: {seen[42441]}"
        assert seen[42442][0] == "M", f"role R must publish M: {seen[42442]}"
        assert seen[42443][0] == "S", f"role S must publish S: {seen[42443]}"
        # The second character is unchanged: r for a read locate.
        for port, tok in seen.items():
            assert tok[1] == "r", f"read locate must emit 'r': {tok} ({port})"
    finally:
        manager.close()
        supervisor.close()
        server.close()


# ═══ success: an unheard-from entry is lowercased, not dropped ════════════

def test_a_stale_entry_is_lowercased_and_still_listed(lifecycle):
    """success: `brix_manager_stale_after` turns S/M into s/m in place.

    last_seen is refreshed by registration and by the kYR_load heartbeat, never
    by a PONG (registry.c) — so a node that logs in and then only answers pings
    goes stale on schedule while staying connected.  It must still be LISTED:
    lowercase means "known but unconfirmed", which is information, and dropping
    the entry instead would turn a slow heartbeat into a cluster-wide outage.
    """
    root_port, cms_port = _mgr(
        lifecycle, MGR,
        "brix_cms_locate_multi on; brix_manager_stale_after 2s;",
        "§2.18: stale entries lowercase their type character.")
    supervisor = FakeNode(cms_port, 42444, mode=MODE_SUPERVISOR)
    server = FakeNode(cms_port, 42445, mode=MODE_SERVER)
    try:
        _settle(supervisor, server)
        path = "/loctype/stale.dat"
        fresh = _wait_entries(root_port, path, {42444, 42445})
        assert (fresh[42444][0], fresh[42445][0]) == ("M", "S"), fresh

        # Neither node sends kYR_load, so both cross the 2 s line together.
        deadline = time.time() + 12
        while time.time() < deadline:
            seen = _wait_entries(root_port, path, {42444, 42445})
            if (seen[42444][0], seen[42445][0]) == ("m", "s"):
                break
            time.sleep(0.5)
        else:
            raise AssertionError(f"entries never went stale: {seen}")

        assert set(seen) == {42444, 42445}, \
            f"a stale node must stay listed, not vanish: {seen}"
    finally:
        supervisor.close()
        server.close()


# ═══ security-negative: the drain outranks the role ═══════════════════════

def test_a_drained_supervisor_is_named_by_no_locate_answer(lifecycle, tmp_path):
    """security-neg: publishing managers must not open a bypass around the
    operator blacklist.

    The §2.18 change added a second way for a node to appear in a client-facing
    list, so the drain filter has to hold on that path too.  The test proves it
    as a transition rather than an absence: with an EMPTY blacklist file the
    supervisor is listed as `M`, and after the file names its host — polled on
    the brix_cms_server_interval tick, mtime-bumped so the poll cannot miss it —
    the locate names it nowhere, in any case.

    A drained node that were still published would be worse than a missing one:
    the client would dial an address the operator has deliberately taken out of
    service, and (being an `M`) would treat it as authoritative about where the
    data is.
    """
    bl = tmp_path / "bl.txt"
    bl.write_text("")
    root_port, cms_port = _mgr(
        lifecycle, MGR, "brix_cms_locate_multi on;",
        "§2.18: the blacklist outranks the entry type.",
        srv_extra=f"brix_cms_blacklist_file {bl};")
    supervisor = FakeNode(cms_port, 42446, mode=MODE_SUPERVISOR)
    server = FakeNode(cms_port, 42447, mode=MODE_SERVER)
    try:
        _settle(supervisor, server)
        path = "/loctype/drain.dat"
        seen = _wait_entries(root_port, path, {42446, 42447})
        assert seen[42446][0] == "M", seen

        st = os.stat(bl)
        bl.write_text("127.0.0.*\n")   # net-literal-allow: pattern under test
        os.utime(bl, (st.st_atime, st.st_mtime + 2))

        deadline = time.time() + 12
        while time.time() < deadline:
            status, entries = _entries(root_port, path)
            if 42446 not in entries:
                break
            time.sleep(0.3)
        else:
            raise AssertionError(
                f"drained supervisor still listed: {entries}")

        # Not merely absent from this one answer — absent from every answer,
        # for the write form too (the 'w' branch shares the emit site).
        for _ in range(4):
            _status, entries = _entries(root_port, path)
            assert 42446 not in entries, \
                f"drained supervisor reappeared: {entries}"
            time.sleep(0.2)
    finally:
        supervisor.close()
        server.close()
