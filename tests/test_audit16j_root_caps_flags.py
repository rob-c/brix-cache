"""The five node-capability flags whose `off` arm was never written.

WHY THIS FILE EXISTS
--------------------
`ngx_conf_set_flag_slot` is the setter behind 128 directives, so the flag surface
is 256 (directive, value) pairs.  Re-running the audit's Method steps 1-2 at that
granularity leaves 92 directives with exactly ONE arm unwritten, and five of them
are one command table — `directives_caps.h`, the node's declaration of what it
IS:

    brix_metadata_only        on: nginx_meta_only.conf      off: NOWHERE
    brix_supervisor           on: nginx_supervisor.conf     off: NOWHERE
    brix_virtual_redirector   on: test_audit15b_*.py        off: NOWHERE
    brix_collapse_redir       on: nginx_collapse_redir.conf off: NOWHERE
    brix_recover_writes       on: nginx_rl_stream.conf      off: NOWHERE

All five are `NGX_STREAM_SRV_CONF | NGX_CONF_FLAG` into `caps.*`, and all five
merge to 0 (`brix_node_caps_conf_merge`, core/types/conf_structs.h:537-548), so
`off` and absent produce the same merged value.  No reading here can be a value
comparison; each arm is read as the observable its flag owns.

WHAT WAS ALREADY OWNED, AND WHAT WAS NOT
----------------------------------------
`test_protocol_flags.py` owns the whole kXR_protocol bit table for all five —
each bit asserted set on its role server and clear on a plain data server — and
this file borrows that module's own `_get_protocol_flags` rather than restating
the reading.  What the bit table cannot say is anything about the code BEHIND the
bit, and for four of the five the advertisement is the only thing anyone has ever
read:

*   `brix_supervisor` also deletes the local export
    (`brix_server_has_runtime_export`, core/config/runtime_server.c:25-29), sets
    the CMS registration role letter (net/cms/server_handler.c:310) and the
    stats role letter (net/cms/send.c:488).  The suite's only supervisor config
    writes `brix_manager_mode on` beside it, and manager_mode alone already
    makes that predicate false — so the flag's own effect has never been seen.
*   `brix_recover_writes` also arms a per-handle write journal
    (root/write/wrts_journal.c), which nothing has ever exercised.
*   `brix_collapse_redir` also gates a redirect cache
    (root/read/open_manager.c:116 and :164) reachable only under
    `brix_manager_mode`.
*   `brix_metadata_only`'s open refusal is conditional on `manager_map == NULL`
    (root/read/open_request.c:69); `test_protocol_flags.py` covers the refusal,
    nobody covered the other side of the conjunction.

THE FINDING — DEFECT CANDIDATE #83 (integrity, silent write loss)
-----------------------------------------------------------------
`brix_recover_writes on` arms a per-handle journal of committed (offset, length)
ranges.  A write whose range matches an entry is treated as a client's
post-disconnect replay: the `pwrite` is skipped and kXR_ok is returned
(root/write/write.c:120-134).  The match is on offset and length ALONE — not on
content, not on a generation the client supplied — and there is no reconnect
condition anywhere on the path.  Two consequences, both measured in §C:

1.  A legitimate client that rewrites the same range with DIFFERENT bytes on one
    open handle is answered kXR_ok and loses the second write.  The file keeps
    the first bytes; nothing is logged above debug level.
2.  The replay the journal exists to catch cannot reach it.  The journal lives
    in the open-file structure, so it dies with the handle, and the recovery path
    is a REOPEN.  A reopened handle starts with an empty journal, so the replayed
    write is executed — the double write the journal exists to prevent.

So the arm that advertises kXR_recoverWrts suppresses the writes it should keep
and executes the writes it should suppress.  §C asserts both halves and the
third mechanism that makes them worse: `kXR_sync` flushes the journal
(root/write/sync.c:92), so a client that syncs — which is what a client
establishing stable state does — loses the protection it was promised.

DEFECT CANDIDATE #84 — the collapse cache the only config for it cannot reach
----------------------------------------------------------------------------
The redirect cache `brix_collapse_redir` enables is consulted only inside
`brix_open_manager_dynamic`, which `brix_open_manager_redirect` calls only when
`conf->manager_mode` is set (root/read/open_manager.c:196-203).
`nginx_collapse_redir.conf` — the suite's only config that enables the flag —
sets a static `brix_manager_map` and NO `brix_manager_mode`, so its every open is
answered by the static-map branch (:207-215), which neither inserts into the
cache nor reads it.  The node advertises kXR_collapseRedir to clients the whole
time.  §E measures the cache working under manager_mode, and a static-map node
answering `"redirect"` and never `"redir-cache"` while advertising the bit.

DEFECT CANDIDATE #85 — `brix_virtual_redirector off` cannot clear the bit
------------------------------------------------------------------------
`kXR_attrVirtRdr` is set by `caps.virtual_redirector || (manager_map != NULL &&
cms.addr == NULL)` (session/protocol.c:81-83).  The second disjunct is how the
suite's `nginx_virtual_redir.conf` earns the bit — it never writes the directive
at all — and it means the `off` arm is not a way to say no: a static-map node
with no CMS advertises the redirector role however emphatically the config
denies it.  §D pins that, and pins that the flag remains the only route on a
node with no map, so this is an unconditional disjunct and not a broken flag.

DEFECT CANDIDATE #86 — the flag switches off a directive's syntax check
----------------------------------------------------------------------
The backend URL is parsed inside the export setup that
`brix_server_has_runtime_export()` gates, so `brix_supervisor on` does not merely
ignore `brix_storage_backend` at runtime (§B) — it stops nginx checking the
value at all.  `brix_storage_backend root://host:port/` (one trailing slash too
many) is an `nginx -t` failure on a data server, is silently accepted on a
supervisor, and is a failure again the moment the flag is written `off`.  §H
measures all three, which makes the arm the audit says nobody ever wrote the arm
that RESTORES a config-time check.

OBSERVATION — two spellings of "supervisor", neither implying the other
----------------------------------------------------------------------
`brix_supervisor` (a flag, into `caps.supervisor`) and `brix_cms_role supervisor`
(an enum token, into `cms.role`) are read by disjoint code.  The flag produces
kXR_attrSuper, removes the export and stamps a role letter; the token produces
the supervisor login Mode word and nothing else.  §G measures a node with the
token and not the flag: it keeps its export and advertises no attrSuper.
`test_audit15t_cms_role.py` owns the Mode word; the contribution here is that
the two are independent.

OBSERVATION — the merge inherits from a context the directives cannot occupy
---------------------------------------------------------------------------
`brix_node_caps_conf_merge` takes `prev` and applies parent-then-default for all
five, but every one of them is declared `NGX_STREAM_SRV_CONF` and nothing else,
so `stream{}` refuses the line and the parent slot can never hold a written
value.  The inheritance arm of that merge is unreachable, which §H measures as a
placement matrix rather than asserting from the header.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
The `on` arms' advertised bits belong to `test_protocol_flags.py`; the CMS login
Mode word and dispatch class to `test_audit15t_cms_role.py`; the
virtual-redirector role bits to `test_audit15b_virtual_redirector.py`; the mesh
registration handshake to the `cms_mesh_lib.py` topologies.  Each appears here
only as the control an `off` arm is read against.
"""

import os
import re
import time
from pathlib import Path

import pytest

from _test_conf_write_helpers import (_close, _connect, _login, _open,
                                      _open_handle, _read, _sync, _write,
                                      kXR_delete, kXR_new, kXR_ok,
                                      kXR_open_read, kXR_open_updt)
from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
# The flags word and the redirect body are read by the modules that own them.
from test_audit15m_stream_coresidency import _redirect_target
from test_protocol_flags import _get_protocol_flags

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16j-caps")]

NAME = "lc-audit16j-caps"
_L = LIFECYCLE_SHARED_PORTS[NAME]
PORT = _L["port"]
OFF_PORT = _L["extra"]["OFF_PORT"]
SUPER_PORT = _L["extra"]["SUPER_PORT"]
WRTS_PORT = _L["extra"]["WRTS_PORT"]
MAP_PORT = _L["extra"]["MAP_PORT"]
COLLON_PORT = _L["extra"]["COLLON_PORT"]
COLLOFF_PORT = _L["extra"]["COLLOFF_PORT"]
CMS_PORT = _L["extra"]["CMS_PORT"]
DS_PORT = _L["extra"]["DS_PORT"]
ROLE_PORT = _L["extra"]["ROLE_PORT"]

# The five, in the order directives_caps.h declares them.
FLAGS = ("brix_metadata_only", "brix_supervisor", "brix_virtual_redirector",
         "brix_collapse_redir", "brix_recover_writes")

# ServerProtocolBody.flags bits (src/protocols/root/protocol/flags.h), named
# here only for the five a flag in FLAGS can set plus the two role bits two of
# them imply; test_protocol_flags.py holds the full table.
KXR_ISSERVER = 0x00000001
KXR_ISMANAGER = 0x00000002
KXR_ATTRMETA = 0x00000100
KXR_ATTRSUPER = 0x00000400
KXR_ATTRVIRTRDR = 0x00000800
KXR_RECOVERWRTS = 0x00001000
KXR_COLLAPSEREDIR = 0x00002000

# The bit each flag owns, which is what makes ONE all-five-`off` server a
# per-flag reading: the flags word is a pure OR of independent bits, so a word
# that differs from the reference names the flag whose bit moved.
OWNED_BIT = {"brix_metadata_only": KXR_ATTRMETA,
             "brix_supervisor": KXR_ATTRSUPER,
             "brix_virtual_redirector": KXR_ATTRVIRTRDR,
             "brix_collapse_redir": KXR_COLLAPSEREDIR,
             "brix_recover_writes": KXR_RECOVERWRTS}

OWNED_BITS = (KXR_ATTRMETA | KXR_ATTRSUPER | KXR_ATTRVIRTRDR
              | KXR_RECOVERWRTS | KXR_COLLAPSEREDIR)

KXR_REDIRECT = 4004

SEED = b"caps-16j-reference-payload\n"
DS_SEED = b"caps-16j-data-server-payload\n"


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

class _Caps:
    """The ten-server instance, addressed by port.

    Every accessor takes a port rather than a name so a test reads as "this
    server answered this way" — the arms differ only in the directive lines the
    template writes, so the port IS the arm.
    """

    def __init__(self, endpoint, trees):
        self.endpoint = endpoint
        self.trees = trees

    def _logs(self):
        return Path(self.endpoint.prefix) / "logs"

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        log = self._logs() / "error.log"
        return log.read_text(errors="replace") if log.exists() else ""

    def access(self, which):
        """One server's brix access log, or "" before it has written a line."""
        log = self._logs() / f"{which}-access.log"
        return log.read_text(errors="replace") if log.exists() else ""

    def tree(self, which):
        return self.trees[which]


@pytest.fixture()
def caps(lifecycle, tmp_path):
    """Ten stream servers in one process, six trees seeded identically.

    The trees are seeded with the same bytes so a read that differs between two
    servers cannot be explained by their contents.  MAP_PORT, COLLON_PORT,
    COLLOFF_PORT and CMS_PORT get no tree on purpose: a manager owns no files,
    and giving one an export would let a fall-through serve locally and read as
    "the redirect did not happen" (open_manager.c:226 makes that explicit — a
    manager with an export serves the file itself).
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    trees = {}
    for which, seed in (("ref", SEED), ("off", SEED), ("super", SEED),
                        ("wrts", SEED), ("role", SEED), ("ds", DS_SEED)):
        tree = tmp_path / which
        tree.mkdir()
        (tree / "seed.bin").write_bytes(seed)
        trees[which] = tree

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16j_caps.conf",
        data_root=str(trees["ref"]),
        template_values={
            "BIND_HOST": BIND_HOST,
            "REF_DATA": str(trees["ref"]),
            "OFF_DATA": str(trees["off"]),
            "SUPER_DATA": str(trees["super"]),
            "WRTS_DATA": str(trees["wrts"]),
            "ROLE_DATA": str(trees["role"]),
            "DS_DATA": str(trees["ds"]),
        },
        reason="audit-16j the five node-capability flags at value granularity"))
    return _Caps(endpoint, trees)


# --------------------------------------------------------------------------- #
# Wire helpers — framing comes from the modules that own it                    #
# --------------------------------------------------------------------------- #

def _flags(port):
    return _get_protocol_flags(HOST, port)


def _session(port):
    """An anonymous logged-in session on one of the ten servers."""
    s = _connect(HOST, port)
    _login(s)
    return s


def _open_read(port, path="/seed.bin"):
    """Open for read and return (status, body) with the session closed.

    The redirect and refusal sections need the OPEN verdict and nothing after
    it, and a session left open holds a worker slot for the rest of the file.
    """
    s = _session(port)
    try:
        return _open(s, path, kXR_open_read)
    finally:
        s.close()


def _read_back(port, path, length):
    """Read `length` bytes of `path` through a fresh handle.

    Fresh because the question every §C case asks is what the SERVER stored, not
    what the writing handle believes it stored.
    """
    s = _session(port)
    try:
        handle = _open_handle(s, path, kXR_open_read)
        status, data = _read(s, handle, 0, length)
        _close(s, handle)
        return status, data
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# §A — written-`off` against absent, for all five at once                      #
# --------------------------------------------------------------------------- #

class TestWritingOffChangesNothingTheClientCanSee:
    """The audit's literal subject: the token nobody had written.

    All five merge to 0, so this section can only ever confirm equality — and
    that is worth measuring rather than assuming, because it is the claim every
    other section's `absent` control silently rests on.  One server carrying all
    five `off` is a per-flag reading, not a combined one: the flags word is an OR
    of independent bits, so if any single `off` set its bit the word would differ
    and name it.
    """

    def test_the_reference_server_advertises_none_of_the_five_bits(self, caps):
        """The control.  Without it an equal pair of words proves only that two
        servers agree, not that they agree on the value the flags decide."""
        flags = _flags(PORT)
        assert flags & OWNED_BITS == 0, (
            f"a server writing none of the five advertises {flags & OWNED_BITS:#x} "
            f"of them (word {flags:#010x}) — the `absent` arm every section below "
            f"uses as its control is not clean")
        assert flags & KXR_ISSERVER, (
            f"the reference is not advertising kXR_isServer (word {flags:#010x}); "
            f"it is not the plain data server the rest of the file assumes")

    def test_written_off_is_byte_identical_to_absent(self, caps):
        """The whole word, not five bits: a flag that reached some OTHER bit
        would pass a five-bit check and fail this one."""
        off, ref = _flags(OFF_PORT), _flags(PORT)
        assert off == ref, (
            f"all five written `off` gives {off:#010x} where absent gives "
            f"{ref:#010x}; `off` and absent share a merged value "
            f"(conf_structs.h:537-548), so the words must be identical")

    @pytest.mark.parametrize("flag", FLAGS)
    def test_no_off_arm_sets_the_bit_its_flag_owns(self, caps, flag):
        """Per-flag attribution of the previous test's single word."""
        bit, flags = OWNED_BIT[flag], _flags(OFF_PORT)
        assert flags & bit == 0, (
            f"{flag} off sets {bit:#x}, the bit it owns (word {flags:#010x})")

    def test_the_off_server_still_serves_its_export(self, caps):
        """Five `off` lines must not cost the server its ordinary function —
        the reading that says the previous three measured a live server."""
        status, data = _read_back(OFF_PORT, "/seed.bin", len(SEED))
        assert status == kXR_ok and data == SEED, (status, data, caps.errlog())


# --------------------------------------------------------------------------- #
# §B — brix_supervisor, isolated from brix_manager_mode                        #
# --------------------------------------------------------------------------- #

def _banner_block(log, needle):
    """One server's `root:// endpoint ready` line plus its annotation lines.

    The banner is written once per process (master and worker both log it), and
    every copy is byte-identical apart from the pid — so the FIRST block naming
    an export is the whole reading.  A block ends at the next banner or at the
    first line that is not one of the indented `brix:   ` annotations.
    """
    lines = log.splitlines()
    for i, line in enumerate(lines):
        if "root:// endpoint ready" not in line or needle not in line:
            continue
        block = [line]
        for nxt in lines[i + 1:]:
            if "root:// endpoint ready" in nxt or "brix:   " not in nxt:
                break
            block.append(nxt)
        return block
    return []


class TestTheSupervisorFlagDeletesTheExport:
    """`brix_server_has_runtime_export()` is false when `caps.supervisor` is set
    (runtime_server.c:25-29), which skips the export setup (:190) — so
    `root_canon` stays empty and the export fd is never opened.  The suite's only
    other supervisor writes `brix_manager_mode` beside the flag, and manager_mode
    alone already makes that predicate false; this server writes the flag ALONE,
    over a `brix_storage_backend` it asks for by path.
    """

    def test_the_supervisor_advertises_the_role_it_claims(self, caps):
        """Not a new reading — the control that says this server really is the
        arm, before the rest of the section concludes things from what it
        refuses."""
        flags = _flags(SUPER_PORT)
        want = KXR_ISMANAGER | KXR_ATTRSUPER
        assert flags & want == want, (
            f"word {flags:#010x} is missing kXR_isManager|kXR_attrSuper; "
            f"brix_supervisor on did not take effect at all")

    def test_the_supervisor_cannot_serve_the_file_in_its_own_export(self, caps):
        """The finding this section exists for: the export directive is accepted,
        the tree exists, the file is there, and the open fails — because the
        flag removed the export before it was ever prepared."""
        status, body = _open_read(SUPER_PORT)
        assert status != kXR_ok, (
            f"a brix_supervisor server opened /seed.bin out of its configured "
            f"brix_storage_backend; brix_server_has_runtime_export() is supposed "
            f"to have skipped the export setup entirely (body={body!r})")

    def test_the_same_export_serves_when_the_flag_is_the_only_difference(
            self, caps):
        """Attribution.  REF and SUPER differ in one line and in two trees
        seeded with the same bytes, so the refusal above is the flag's."""
        status, data = _read_back(PORT, "/seed.bin", len(SEED))
        assert status == kXR_ok and data == SEED, (status, data, caps.errlog())

    def test_the_dropped_backend_is_never_named_in_the_error_log(self, caps):
        """What makes it a finding rather than a documented mode: the export the
        config asked for is not mentioned once — no warning, and no line in the
        startup banner that names every OTHER server's export.

        If this ever fails, the honest response is to retire the claim: a
        diagnostic naming brix_supervisor beside the path it ignored is the fix.
        """
        log = caps.errlog()
        assert f'export "{caps.tree("ref")}"' in log, (
            "the startup banner no longer names configured exports, so the "
            "silence measured below is not attributable to the flag")
        assert f'export "{caps.tree("super")}"' not in log, (
            "brix_supervisor's ignored backend is now named in the log — the "
            "silence this test pins may have been fixed")

    def test_the_supervisor_banner_claims_a_writable_root_export(self, caps):
        """The sharper half of the same finding: the banner does not go quiet,
        it says something else.  With no export prepared `root_canon` is empty
        and the line renders `export "/" (read-write)` — the one shape an
        operator reads as "the whole filesystem, writable" — and unlike the two
        manager_mode blocks it carries no `mode:` annotation naming the role
        that removed the export.

        Attribution without counting: SUPER is the only server here that writes
        `brix_allow_write on` and ends up with no export, so a read-WRITE banner
        for `/` can only be its own (MAP, COLLON and COLLOFF also report `/`,
        but read-only).
        """
        block = _banner_block(caps.errlog(), 'export "/" (read-write)')
        assert block, (
            "no writable `/` banner: the supervisor's empty export root no "
            f"longer renders as one\n{caps.errlog()}")
        assert not any("mode:" in ln or "supervisor" in ln for ln in block[1:]), (
            f"the supervisor banner now annotates its role: {block}")


# --------------------------------------------------------------------------- #
# §C — brix_recover_writes: the journal (DEFECT CANDIDATE #83)                  #
# --------------------------------------------------------------------------- #

def _rewrite_probe(port, path, sync_between=False):
    """Write A then B over the SAME (offset, length); return what the file holds.

    Both statuses are returned so a caller can tell "refused" from "accepted and
    discarded" — the whole distinction #83 rests on.
    """
    s = _session(port)
    try:
        handle = _open_handle(s, path, kXR_new | kXR_open_updt | kXR_delete)
        first = _write(s, handle, 0, b"AAAA")
        if sync_between:
            _sync(s, handle)
        second = _write(s, handle, 0, b"BBBB")
        _close(s, handle)
    finally:
        s.close()
    status, data = _read_back(port, path, 4)
    return first, second, status, data


class TestTheWriteRecoveryJournal:
    """The replay detector matches on (offset, length) alone — no content, no
    client-supplied generation — and the write path consults it on every write
    with no reconnect condition (write.c:120-134).  Both halves of that are
    measured here.
    """

    def test_the_journal_swallows_a_legitimate_rewrite(self, caps):
        """DEFECT CANDIDATE #83, first half.  Same offset, same length, DIFFERENT
        bytes, one handle, no disconnect: the server answers kXR_ok and keeps the
        first bytes."""
        first, second, status, data = _rewrite_probe(WRTS_PORT, "/rewrite.bin")
        assert first[0] == kXR_ok, (first, caps.errlog())
        assert second[0] == kXR_ok, (
            f"the second write was refused ({second}); the finding is that it is "
            f"ACCEPTED and discarded, so a refusal would be a different bug")
        assert status == kXR_ok, (status, data)
        assert data == b"AAAA", (
            f"read back {data!r}; if this is now b'BBBB' the replay detector has "
            f"gained a content or generation check and #83's first half is fixed")

    def test_the_same_rewrite_lands_when_the_flag_is_off(self, caps):
        """Attribution: the identical sequence against the all-`off` server,
        which differs from WRTS only in this flag."""
        first, second, status, data = _rewrite_probe(OFF_PORT, "/rewrite.bin")
        assert (first[0], second[0], status) == (kXR_ok, kXR_ok, kXR_ok), (
            first, second, status, caps.errlog())
        assert data == b"BBBB", (
            f"read back {data!r} from a server with brix_recover_writes off; "
            f"the journal is not supposed to exist there at all")

    def test_the_same_rewrite_lands_on_the_absent_arm(self, caps):
        """The third arm.  `off` and absent share a merged value, so a
        difference between this and the previous test would mean the merge is
        not what conf_structs.h says."""
        _first, _second, status, data = _rewrite_probe(PORT, "/rewrite.bin")
        assert status == kXR_ok and data == b"BBBB", (status, data)

    def test_a_sync_between_the_writes_restores_the_lost_one(self, caps):
        """The third mechanism: kXR_sync flushes the journal (sync.c:92), so the
        protection the flag advertises is exactly as durable as the client's
        habit of not syncing — and the write that vanishes without a sync lands
        with one."""
        _first, _second, status, data = _rewrite_probe(WRTS_PORT, "/synced.bin",
                                                       sync_between=True)
        assert status == kXR_ok, (status, data)
        assert data == b"BBBB", (
            f"read back {data!r} after a kXR_sync between the two writes; the "
            f"journal was supposed to have been flushed")

    def test_a_different_length_at_the_same_offset_is_not_a_replay(self, caps):
        """The bound on #83: the match is exact on both fields, so a 2-byte write
        over a 4-byte one lands.  The defect is the equal-length case, not "the
        journal swallows overwrites"."""
        s = _session(WRTS_PORT)
        try:
            handle = _open_handle(s, "/partial.bin",
                                  kXR_new | kXR_open_updt | kXR_delete)
            assert _write(s, handle, 0, b"AAAA")[0] == kXR_ok
            assert _write(s, handle, 0, b"BB")[0] == kXR_ok
            _close(s, handle)
        finally:
            s.close()
        status, data = _read_back(WRTS_PORT, "/partial.bin", 4)
        assert status == kXR_ok and data == b"BBAA", (
            f"read back {data!r}, want b'BBAA' — a shorter write at a journalled "
            f"offset must not be taken for a replay")

    def test_the_replay_the_journal_exists_for_is_executed_anyway(self, caps):
        """DEFECT CANDIDATE #83, second half.  The journal is per-handle and the
        recovery path is a REOPEN, so the replayed write arrives at an empty
        journal and is executed — the double write the feature exists to
        prevent.  Measured with different bytes, because identical bytes written
        twice to a POSIX file are indistinguishable from one write."""
        s = _session(WRTS_PORT)
        try:
            handle = _open_handle(s, "/replay.bin",
                                  kXR_new | kXR_open_updt | kXR_delete)
            assert _write(s, handle, 0, b"AAAA")[0] == kXR_ok
            _close(s, handle)
        finally:
            s.close()

        # The reopen a recovering client performs, then the "replay".
        s = _session(WRTS_PORT)
        try:
            handle = _open_handle(s, "/replay.bin", kXR_open_updt)
            assert _write(s, handle, 0, b"BBBB")[0] == kXR_ok
            _close(s, handle)
        finally:
            s.close()

        status, data = _read_back(WRTS_PORT, "/replay.bin", 4)
        assert status == kXR_ok and data == b"BBBB", (
            f"read back {data!r} — if this is now b'AAAA' the journal has learnt "
            f"to survive a reopen and #83's second half is fixed")

    def test_the_journalling_server_advertises_the_recovery_it_offers(self, caps):
        """The control the two halves are read against: this server does tell
        clients to replay, which is what makes the journal's behaviour a
        promise rather than an internal detail."""
        flags = _flags(WRTS_PORT)
        assert flags & KXR_RECOVERWRTS, (
            f"word {flags:#010x} lacks kXR_recoverWrts; the journal is armed but "
            f"no client is being told to replay into it")


# --------------------------------------------------------------------------- #
# §D — brix_virtual_redirector off (DEFECT CANDIDATE #85)                      #
# --------------------------------------------------------------------------- #

class TestTheRedirectorRoleTheFlagCannotDeny:
    """`caps.virtual_redirector || (manager_map != NULL && cms.addr == NULL)`
    (session/protocol.c:81-83).  MAP_PORT writes the flag `off` and carries a
    static map with no CMS, so the second disjunct holds.
    """

    def test_off_does_not_clear_the_bit_when_a_map_supplies_it(self, caps):
        """DEFECT CANDIDATE #85: the arm nobody had written turns out not to be
        an arm — this config denies the role and advertises it."""
        flags = _flags(MAP_PORT)
        assert flags & KXR_ATTRVIRTRDR, (
            f"word {flags:#010x} — if kXR_attrVirtRdr is now clear on a static-map "
            f"node that writes brix_virtual_redirector off, the disjunct has "
            f"gained a way to say no and #85 is fixed")

    def test_the_role_bit_brings_the_manager_bit_with_it(self, caps):
        """The disjunct sets kXR_isManager alongside, so an `off` flag also
        cannot stop the node being counted as a manager."""
        flags = _flags(MAP_PORT)
        assert flags & KXR_ISMANAGER, (
            f"word {flags:#010x} advertises attrVirtRdr without isManager, which "
            f"protocol.c:81-83 emits as one expression")

    def test_a_node_with_no_map_takes_the_flag_at_its_word(self, caps):
        """The bound: this is an unconditional disjunct, not a broken flag.  The
        all-`off` server has no map, and its bit is clear."""
        flags = _flags(OFF_PORT)
        assert flags & KXR_ATTRVIRTRDR == 0, (
            f"word {flags:#010x} sets attrVirtRdr with no manager_map and the flag "
            f"written off; #85 would then be a defect in the flag rather than in "
            f"the disjunct")


# --------------------------------------------------------------------------- #
# §E — brix_collapse_redir: the cache (DEFECT CANDIDATE #84)                    #
# --------------------------------------------------------------------------- #

def _await_registration(caps, timeout=25.0):
    """Wait until the data node has registered with the CMS listener.

    The manager registry is process-global and populated by the data node's own
    upward login on a `brix_cms_interval 2` timer — so §E's subject does not
    exist for the first seconds of the instance's life.  The readable proof that
    it does is a redirect: until the registry holds a server the dynamic path
    declines and the manager answers kXR_noserver (open_manager.c:226-230).

    The wait lives here rather than in the fixture so only §E pays for it.
    """
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        status, body = _open_read(COLLOFF_PORT, "/registered.bin")
        if status == KXR_REDIRECT:
            return
        last = (status, body)
        time.sleep(0.5)
    pytest.fail(f"no data server registered with the manager within {timeout}s; "
                f"last open answered {last} — the collapse-cache arms have no "
                f"registry to select out of.\n{caps.errlog()}")


def _open_details(caps, which, path, count, timeout=5.0):
    """The DETAIL field of every access-log line for `path` on one server.

    The line format is byte-frozen (`brix_access_format_line`,
    observability/accesslog/access_log.c:296-315): `"VERB PATH DETAIL"`.  The
    detail is where a redirect names its SOURCE, which is the only place the
    collapse cache is observable from outside the process.

    Polls for `count` lines because the log write trails the redirect that is
    already on the wire: a read that races it sees only the PREVIOUS open and
    answers a different question than the one asked.  Measured — the two-open
    cache reading below failed exactly that way once, reporting the first open's
    `registry` as the second's.  On a shortfall the list is returned short so
    the caller's own assertion reports what it saw.
    """
    pattern = r'"OPEN ' + re.escape(path) + r' ([^"]+)"'
    deadline = time.time() + timeout
    while True:
        hits = re.findall(pattern, caps.access(which))
        if len(hits) >= count or time.time() >= deadline:
            return hits
        time.sleep(0.05)


def _open_detail(caps, which, path, nth=1):
    """The DETAIL of the `nth` (1-based) logged open of `path` on one server."""
    hits = _open_details(caps, which, path, nth)
    return hits[nth - 1] if len(hits) >= nth else None


class TestTheCollapseRedirectCache:
    """The cache is consulted only inside `brix_open_manager_dynamic`, which the
    redirect entry point enters only under `conf->manager_mode`
    (open_manager.c:196-203).  Both arms here set manager_mode, so the only
    variable is the flag.

    The cache is process-global (`brix_redir_cache_insert` takes no conf), so
    each arm drives its own path — a path warmed by the `on` arm would be in the
    cache when the `off` arm asked, and the `off` arm's reading would be about
    the gate rather than about the cache.
    """

    def test_the_first_open_is_answered_from_the_registry(self, caps):
        """The control both arms start from: a cold path is a registry select on
        either arm, so the difference measured next is the SECOND open."""
        _await_registration(caps)
        status, body = _open_read(COLLON_PORT, "/cold-on.bin")
        assert status == KXR_REDIRECT, (status, body, caps.errlog())
        detail = _open_detail(caps, "collon", "/cold-on.bin")
        assert detail == "registry", (
            f"first open on the `on` arm was answered from {detail!r}, not the "
            f"registry")

    def test_the_second_open_is_answered_from_the_cache(self, caps):
        """The flag's actual effect, and the only reading in the suite that
        shows the cache being used: the same path again skips the registry."""
        _await_registration(caps)
        assert _open_read(COLLON_PORT, "/warm-on.bin")[0] == KXR_REDIRECT
        assert _open_read(COLLON_PORT, "/warm-on.bin")[0] == KXR_REDIRECT
        details = _open_details(caps, "collon", "/warm-on.bin", 2)
        assert details == ["registry", "redir-cache"], (
            f"the two opens were answered from {details}; the `on` arm inserts "
            f"at open_manager.c:117 and must read at :164")

    def test_the_off_arm_asks_the_registry_every_time(self, caps):
        """The `off` arm nobody had written: same manager_mode, same registry,
        same path twice, and the cache is never consulted."""
        _await_registration(caps)
        assert _open_read(COLLOFF_PORT, "/warm-off.bin")[0] == KXR_REDIRECT
        assert _open_read(COLLOFF_PORT, "/warm-off.bin")[0] == KXR_REDIRECT
        details = _open_details(caps, "colloff", "/warm-off.bin", 2)
        assert details == ["registry", "registry"], (
            f"the two opens were answered from {details}; with the flag off the "
            f"lookup at open_manager.c:164 must not run")

    def test_both_arms_redirect_to_the_registered_data_server(self, caps):
        """Attribution: the flag changes where the ANSWER came from, not what
        the answer is.  A client cannot tell the arms apart."""
        _await_registration(caps)
        _open_read(COLLON_PORT, "/target.bin")
        on_body = _open_read(COLLON_PORT, "/target.bin")[1]
        off_body = _open_read(COLLOFF_PORT, "/target-off.bin")[1]
        assert _redirect_target(on_body)[1] == DS_PORT, _redirect_target(on_body)
        assert _redirect_target(off_body)[1] == DS_PORT, \
            _redirect_target(off_body)

    def test_the_off_arm_does_not_advertise_the_collapse_bit(self, caps):
        """The wire half of the `off` arm, for the client that decides whether
        to trust a cached redirect."""
        flags = _flags(COLLOFF_PORT)
        assert flags & KXR_COLLAPSEREDIR == 0, (
            f"word {flags:#010x} advertises kXR_collapseRedir with the flag "
            f"written off")

    def test_the_on_arm_advertises_it(self, caps):
        flags = _flags(COLLON_PORT)
        assert flags & KXR_COLLAPSEREDIR, (
            f"word {flags:#010x} lacks kXR_collapseRedir with the flag on")


class TestTheDocumentedShapeCannotReachTheCache:
    """DEFECT CANDIDATE #84.  `nginx_collapse_redir.conf` is the suite's only
    config that enables the flag: a static `brix_manager_map`, no
    `brix_manager_mode`.  Every open there is answered by the static-map branch
    (open_manager.c:207-215), which neither inserts into the cache nor reads it.

    MAP_PORT has that shape, so the answer is measured there; the tracked config
    is only READ, to check that the premise still holds.
    """

    def test_the_static_map_shape_answers_from_the_map_not_the_cache(self, caps):
        """Two opens of one path on a static-map node, and neither is a cache
        hit — the detail is the static branch's own word, `redirect`."""
        for _ in range(2):
            status, body = _open_read(MAP_PORT, "/mapped.bin")
            assert status == KXR_REDIRECT, (status, body, caps.errlog())
        details = _open_details(caps, "map", "/mapped.bin", 2)
        assert details == ["redirect", "redirect"], (
            f"the two opens were answered from {details}; a static-map node "
            f"cannot reach open_manager.c:117/:164 at all, so neither "
            f"`registry` nor `redir-cache` is available to it")

    def test_the_shape_that_enables_the_flag_has_no_manager_mode(self, caps):
        """The premise, read off the tracked config rather than asserted.

        If this fails the finding is stale — the config gained the directive that
        makes its cache reachable — and #84 should be retired rather than the
        assertion loosened.
        """
        tracked = (Path(__file__).resolve().parent / "configs"
                   / "nginx_collapse_redir.conf").read_text()
        assert "brix_collapse_redir" in tracked, tracked
        assert "brix_manager_mode" not in tracked, (
            "nginx_collapse_redir.conf now sets brix_manager_mode — #84's "
            "premise has changed")

    def test_the_shape_still_advertises_the_collapse_bit(self, caps):
        """The half that makes #84 a defect rather than a dead branch: the
        advertisement does not depend on the cache being reachable, because the
        flags word reads `caps.collapse_redir` and nothing else
        (session/protocol.c:121).

        COLLON_PORT proves the bit follows the flag; MAP_PORT proves the answer
        does not.  Together they say a static-map node with the flag promises a
        client something no code path in it can deliver.
        """
        assert _flags(COLLON_PORT) & KXR_COLLAPSEREDIR
        assert _open_read(MAP_PORT, "/promised.bin")[0] == KXR_REDIRECT
        assert _open_read(MAP_PORT, "/promised.bin")[0] == KXR_REDIRECT
        assert _open_details(caps, "map", "/promised.bin", 2) \
            == ["redirect", "redirect"], caps.access("map")


# --------------------------------------------------------------------------- #
# §F — brix_metadata_only's other conjunct                                     #
# --------------------------------------------------------------------------- #

class TestTheMetadataOnlyRefusalIsConditional:
    """`caps.metadata_only && manager_map == NULL` (open_request.c:69).
    `test_protocol_flags.py` covers the refusal, which is the left conjunct with
    the right one true.  MAP_PORT is the same flag with a map, where the branch
    is skipped and the open is redirected instead.
    """

    def test_the_flag_with_a_map_redirects_instead_of_refusing(self, caps):
        """The untested half of the conjunction: metadata-only stops meaning
        "no file I/O here" the moment the node has somewhere to send you."""
        status, body = _open_read(MAP_PORT, "/mapped-meta.bin")
        assert status == KXR_REDIRECT, (
            f"status {status}, body {body!r} — a metadata_only node WITH a "
            f"manager_map is supposed to skip the refusal at open_request.c:69 "
            f"and redirect")

    def test_the_flag_still_advertises_the_metadata_role(self, caps):
        """The advertisement does not follow the conjunction: attrMeta is set
        from `caps.metadata_only` alone, so a client is told "metadata only" by a
        node that will happily redirect it to data."""
        flags = _flags(MAP_PORT)
        assert flags & KXR_ATTRMETA, (
            f"word {flags:#010x} lacks kXR_attrMeta with the flag on")

    def test_the_off_arm_neither_refuses_nor_advertises(self, caps):
        """The arm nobody had written, on the server with no map — where the
        refusal WOULD fire if the flag were on."""
        assert _flags(OFF_PORT) & KXR_ATTRMETA == 0
        status, body = _open_read(OFF_PORT)
        assert status == kXR_ok, (status, body, caps.errlog())


# --------------------------------------------------------------------------- #
# §G — the two spellings of "supervisor"                                       #
# --------------------------------------------------------------------------- #

class TestTheOtherSpellingOfSupervisor:
    """`brix_supervisor` writes `caps.supervisor`; `brix_cms_role supervisor`
    writes `cms.role`.  Nothing in `src/` assigns one from the other — the
    readers of `caps.supervisor` are session/protocol.c, runtime_server.c,
    net/cms/server_handler.c and net/cms/send.c, and none of them consults
    `cms.role`.  ROLE_PORT writes the token and not the flag.
    """

    def test_the_token_does_not_advertise_the_supervisor_bit(self, caps):
        """An operator who wrote `brix_cms_role supervisor` has not told any
        root:// client that this node is a supervisor."""
        flags = _flags(ROLE_PORT)
        assert flags & KXR_ATTRSUPER == 0, (
            f"word {flags:#010x} sets kXR_attrSuper from brix_cms_role alone; "
            f"the two spellings would then be linked and this section is moot")

    def test_the_token_leaves_the_export_alone(self, caps):
        """The sharp half: the flag deletes the export (§B) and the token does
        not, so the two spellings differ in whether the node holds files."""
        status, data = _read_back(ROLE_PORT, "/seed.bin", len(SEED))
        assert status == kXR_ok and data == SEED, (
            f"a brix_cms_role supervisor node could not read its own export "
            f"({status}, {data!r}); only caps.supervisor is supposed to reach "
            f"brix_server_has_runtime_export()\n{caps.errlog()}")

    def test_the_flag_arm_is_the_contrast(self, caps):
        """Both halves of the pair in one assertion, so the difference is not
        assembled out of two tests that could drift apart."""
        role, flag = _flags(ROLE_PORT), _flags(SUPER_PORT)
        assert flag & KXR_ATTRSUPER and role & KXR_ATTRSUPER == 0, (
            f"brix_supervisor gives {flag:#010x} and brix_cms_role supervisor "
            f"gives {role:#010x}; the pair is the finding")


# --------------------------------------------------------------------------- #
# §H — the parse tier                                                          #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, **slots):
    """`nginx -t` on the 16j scaffold with the named slots filled.

    Every slot defaults to empty so a case names only what it is about; the
    scaffold writes none of the five itself, so a negative about one of them is
    never answered by a duplicate diagnostic first.
    """
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "PORT2": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "BACKEND": f"posix:{data}",
              "KNOBS": "", "STREAM_KNOBS": "", "HTTP_KNOBS": "",
              "LOC_KNOBS": "", "OUTER": "", "EXTRA": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16jparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _diagnostics(out):
    """Only the lines nginx itself flagged.

    A tmp_path name can contain the token under test, so a substring search over
    the whole output would match the temp directory rather than a diagnostic.
    """
    return [ln for ln in out.splitlines()
            if any(tag in ln for tag in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


class TestTheParseTier:
    """Values, arity, duplicates and — the part that carries a finding — the
    placement matrix that says the merge's inheritance arm is unreachable."""

    @pytest.mark.parametrize("arm", ("on", "off"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_both_arms_are_accepted_in_a_stream_server(self, tmp_path, flag,
                                                       arm):
        """The audit's step-1 question for all ten pairs, asked where the
        directive is legal."""
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("token", ("ON", "Off", "oN"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_arms_are_case_insensitive(self, tmp_path, flag, token):
        """`ngx_conf_set_flag_slot` compares with ngx_strcasecmp, which is what
        makes the audit's step-2 grep for `flag on` / `flag off` sound only
        because no config in the corpus spells it any other way."""
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {token};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("value", ("yes", "1", "true", "enabled", ""))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_value_outside_the_two_arms_is_refused(self, tmp_path, flag,
                                                     value):
        """A flag has exactly two tokens; "1" and "true" are the spellings an
        operator brings from other config languages."""
        line = f"        {flag} {value};\n" if value else f"        {flag};\n"
        rc, out = _parse(tmp_path, KNOBS=line)
        assert rc != 0, f"{flag} {value!r} was accepted: {out}"

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, flag):
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} on off;\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_duplicate_is_refused(self, tmp_path, flag):
        rc, out = _parse(tmp_path,
                         KNOBS=f"        {flag} on;\n        {flag} off;\n")
        assert rc != 0, out
        assert "duplicate" in out, out

    @pytest.mark.parametrize("slot", ("STREAM_KNOBS", "HTTP_KNOBS",
                                      "LOC_KNOBS", "OUTER"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_directive_is_refused_everywhere_but_a_stream_server(
            self, tmp_path, flag, slot):
        """The matrix that makes the merge's inheritance arm unreachable rather
        than untested: `stream{}` is a refusal, so `prev` can never hold a
        written value for any of the five.

        The refusal must be a placement one.  `unknown directive` would mean the
        stream module was not loaded and the case measured nothing.
        """
        rc, out = _parse(tmp_path, **{slot: f"    {flag} on;\n"})
        assert rc != 0, out
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_one_server_arm_does_not_reach_a_sibling(self, tmp_path, flag):
        """Two stream servers, one carrying the flag: the config loads, which is
        the parse-tier half of "the scope is per-server"."""
        extra = ("    server {\n"
                 f"        listen {PARSE_PLACEHOLDER_PORT + 2};\n"
                 "        brix_root on;\n"
                 "        brix_auth none;\n"
                 "    }\n")
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} on;\n", EXTRA=extra)
        assert rc == 0, out

    def test_all_five_off_arms_load_together(self, tmp_path):
        """The config §A runs, at parse level: five `off` lines in one server is
        not a combination the parser objects to."""
        knobs = "".join(f"        {flag} off;\n" for flag in FLAGS)
        rc, out = _parse(tmp_path, KNOBS=knobs)
        assert rc == 0, out

    def test_no_off_arm_is_diagnosed_at_all(self, tmp_path):
        """Silence is part of the subject: writing `off` on a flag that merges
        to 0 must not produce an advisory, or the audit's "never written" would
        have been noticed as noise long ago."""
        knobs = "".join(f"        {flag} off;\n" for flag in FLAGS)
        rc, out = _parse(tmp_path, KNOBS=knobs)
        assert _diagnostics(out) == [], out
        assert rc == 0, out


# A syntactically valid remote origin, and the same URL with the trailing slash
# the parser rejects (vfs_backend_config_s3.c:260-275 splits on the last colon
# and requires the tail to be a port).  `nginx -t` never connects to either.
REMOTE_OK = f"root://{HOST}:{DS_PORT}"
REMOTE_BAD = f"root://{HOST}:{DS_PORT}/"

# One authorization rule, in the spelling that needs no auth mode and no file:
# brix_authdb parses its file at config time and brix_require_vo demands
# `brix_auth gsi|token|both`, either of which would put a second directive's
# diagnostic ahead of the one being measured.
GROUP_RULE = "        brix_inherit_parent_group /cms;\n"


class TestTheSupervisorFlagSkipsBackendValidation:
    """DEFECT CANDIDATE #86.  `brix_supervisor on` makes
    `brix_server_has_runtime_export()` false (runtime_server.c:27), and the
    backend URL is parsed inside the export setup that predicate gates — so the
    flag does not merely ignore `brix_storage_backend` at runtime (§B), it
    switches OFF that directive's config-time syntax check.  A typo in the
    origin URL is an `nginx -t` failure on a data server and silence on a
    supervisor.

    This is the sharpest reading in the file for the audit's own question,
    because the `off` arm — the token nobody had ever written — is the arm that
    RESTORES a validation the `on` arm removes.
    """

    def test_the_invalid_origin_is_refused_without_the_flag(self, tmp_path):
        """The control: the parser does have an opinion about this URL."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_BAD)
        assert rc != 0, out
        assert "invalid remote origin host:port" in out, out

    def test_the_flag_makes_the_same_invalid_origin_load(self, tmp_path):
        """The finding.  One flag, and a URL nginx rejects becomes a URL nginx
        accepts."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_BAD,
                         KNOBS="        brix_supervisor on;\n")
        assert rc == 0, (
            f"the invalid origin is now refused with brix_supervisor on — #86 is "
            f"fixed and this class should be retired: {out}")

    def test_the_off_arm_restores_the_validation(self, tmp_path):
        """The arm nobody had written, doing the only thing it can do here:
        putting the config-time check back."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_BAD,
                         KNOBS="        brix_supervisor off;\n")
        assert rc != 0, out
        assert "invalid remote origin host:port" in out, out

    def test_the_accepted_config_never_mentions_the_backend_it_ignored(
            self, tmp_path):
        """Why #86 is a defect and not a documented mode: the accepted run says
        nothing about the directive whose value it stopped reading.

        A warning naming the ignored backend is the fix; if this fails, retire
        the claim rather than loosening it.
        """
        rc, out = _parse(tmp_path, BACKEND=REMOTE_BAD,
                         KNOBS="        brix_supervisor on;\n")
        assert rc == 0, out
        assert REMOTE_BAD not in out, (
            f"the accepted run now names the ignored backend — the silence this "
            f"test pins may be fixed: {out}")


class TestTheRemoteAuthzGuardOnlyArmsWithTheFlag:
    """`brix_server_guard_remote_authz()` (runtime_server.c:66-98) refuses the
    combination of a remote-origin backend, authorization rules, and a server
    mode with no runtime export — and `caps.supervisor` is one of the four ways
    into that mode.  So writing the flag turns a config that loads into one that
    is refused, and the `off` arm skips the guard entirely.

    Both facts about the guard are read as a triple with the flag as the only
    variable, and the last case bounds it: the guard needs BOTH conditions, so a
    posix backend keeps the same rules legal.
    """

    def test_the_combination_loads_without_the_flag(self, tmp_path):
        """The control.  A data server may pair a remote origin with authz rules
        because its export setup runs and aligns both sides of the path join."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_OK, KNOBS=GROUP_RULE)
        assert rc == 0, out

    def test_the_flag_turns_the_same_config_into_a_refusal(self, tmp_path):
        """One line added, and a config that loaded no longer does."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_OK,
                         KNOBS=GROUP_RULE + "        brix_supervisor on;\n")
        assert rc != 0, (
            "brix_supervisor on over a remote backend with authz rules was "
            f"accepted; runtime_server.c:72-97 is supposed to refuse it: {out}")

    def test_the_refusal_explains_the_mechanism_and_names_the_mode(
            self, tmp_path):
        """The message is the reason this is a guardrail rather than a trap: it
        names the mode class, the `//path` vs `/path` mismatch and the fix."""
        _rc, out = _parse(tmp_path, BACKEND=REMOTE_OK,
                          KNOBS=GROUP_RULE + "        brix_supervisor on;\n")
        for needle in ("requires a runtime export", "supervisor", "brix_export"):
            assert needle in out, (needle, out)

    def test_the_off_arm_skips_the_guard(self, tmp_path):
        """The arm nobody had written: `off` restores the runtime export, and
        with it the exemption."""
        rc, out = _parse(tmp_path, BACKEND=REMOTE_OK,
                         KNOBS=GROUP_RULE + "        brix_supervisor off;\n")
        assert rc == 0, out

    def test_a_local_backend_keeps_the_same_rules_legal(self, tmp_path):
        """The bound: the guard is about the pair, so the flag alone does not
        make authorization rules illegal."""
        rc, out = _parse(tmp_path,
                         KNOBS=GROUP_RULE + "        brix_supervisor on;\n")
        assert rc == 0, out
