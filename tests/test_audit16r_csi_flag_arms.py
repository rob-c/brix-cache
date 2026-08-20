"""The two CSI integrity flags of the stream plane at VALUE granularity — audit
§Method, 16th tranche, file 18.

WHY THIS FILE EXISTS
--------------------
Re-running the audit's Method (steps 1-2) per (directive, VALUE) rather than per
directive NAME leaves a residue of flags whose second arm no config, test or
document in the tree has ever written.  File 17 closed the stream plane's three
acc-engine flags.  Two more sit twelve lines apart in the same header::

    { ngx_string("brix_csi_require"),                 directives_auth.h:331
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, csi.require),
      NULL },

``brix_csi_trust_fs`` (:338) differs only in the field.  Both merge to 0
(core/types/conf_structs.h, brix_csi_conf_merge), the corpus writes ``on`` for
each of them, and before this file it wrote ``off`` for neither.

The one place in the tree that exercises these two at all is
``cmdscripts/gsi_trust_live.py::csi_trust`` — a LIVE script, gated on a built
native ``xrdcp``, that spells three ``on`` arms and writes its control arm as
ABSENCE.  It also already puts a require-plus-trust acceptor on the wire and
records "require+trust reads untagged" as an expected row.  That row is §C's
finding; measuring it is not the same as reading it, and absence is not ``off``.

WHAT THE OBSERVABLE IS
----------------------
Both flags decide what happens when a handle is opened for READ against a file
whose at-rest integrity record is in a known state, so the reading is one
kXR_open + kXR_read against a file the test has put into that state on purpose::

    brix_open_attach_csi   read/open_resolved_file_finalize.c:57-98
        if (conf->csi.enable && S_ISREG(...) && !(conf->csi.trust_fs && !is_write))
            crc = brix_csi_open(...)
            if (crc != BRIX_CSI_OK)
                if (!is_write && crc == BRIX_CSI_NOTAGS && conf->csi.require)
                    -> kXR_ChkSumErr "integrity record missing"

Three file states cover both flags between them:

    clean      written through the export, record intact       every arm serves it
    corrupt    record intact, a data byte flipped underneath   trust_fs decides
    untagged   bytes only, no record at all                    require decides

and four acceptors in ONE worker hold four arms at once, which is also the
control that says these two flags — unlike file 17's ``brix_acc_pgo`` — really
are per-server.

WHAT THE SECTIONS ESTABLISH
---------------------------
§A  ``brix_csi_trust_fs``: ``off``, ``on`` and absent.  ``off`` and absent reach
    the same verdict through two different routes (NGX_CONF_UNSET and 0); ``on``
    is not a tuning knob but a change of failure mode — the acceptor serves the
    corrupted bytes, byte-for-byte, with no error and no log line.  Writes still
    tag under every arm, so ``on`` cannot be read as "the engine is off".

§B  ``brix_csi_require``: ``off``, ``on`` and absent, against an untagged file.
    ``on`` refuses with kXR_ChkSumErr and the refusal is distinguishable from a
    missing file (kXR_NotFound), from an authorization refusal, and from a
    corrupt read.  It gates READS only: an open-for-write of the same untagged
    file is granted, which is what lets an untagged export ever become tagged.

§C  THE FIRST FINDING (defect candidate #93).  The two flags are not
    independent: ``brix_csi_trust_fs on`` skips the engine for reads, and the
    ``require`` test lives INSIDE the branch it skips.  An acceptor that writes
    both gets neither — the fail-closed control is silently disabled by the
    performance one, with no diagnostic at ``nginx -t``, no startup notice, and
    no mention of CSI in the endpoint-ready banner at all.

§D  THE SECOND FINDING (defect candidate #94).  When the engine DOES catch
    at-rest corruption, the client is told kXR_IOError (3007), never
    kXR_ChkSumErr (3019).  ``brix_vfs_job_t`` carries a ``csi_mismatch`` OUT bit
    whose declared purpose (vfs_io_core.h:85) and whose own comment
    (vfs_io_core.c:147-148, "so the handler maps it to kXR_ChkSumErr instead of
    serving corrupt data") describe a mapping that does not exist: nothing in
    ``src/`` ever reads the bit, and read_buffered.c:361 hard-codes kXR_IOError.
    The same feature reports "no record" as kXR_ChkSumErr and "the record says
    these bytes are wrong" as a generic disk error — backwards.

§E  The coverage rule, which bounds what either arm can promise: verification
    covers only blocks the read buffer FULLY spans (csi_verify.c:47-53).  A read
    straddling the granule serves a byte the record knows is wrong, and does so
    under ``trust_fs off`` — the arm an operator writes to be sure.  Measured
    here so §A's guarantee is not read wider than it is.

§F  The parse tier: both arms at the declared scope, every scope the mask does
    not name, values, case, arity and duplicates.

§G  The declarations, the initialisers, the merges, the read-path gate and the
    corpus census every reading above rests on.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
Nothing here says CSI is the right way to carry at-rest integrity, or that a
1 MiB default granule is well chosen.  §E is a limitation of the design as
written, not an accusation; §C and §D are about a control that does not do what
its own configuration and its own comments say.  The background scrub
(``brix_csi_scrub_interval``, and the one metric this feature exports,
``brix_csi_scrub_mismatch_total``) is a different subject and is untouched.

Ledger: lc-audit16r-csi — four root:// ports over one export, one nginx.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=. TEST_PORT_START=25000 \
        pytest test_audit16r_csi_flag_arms.py -q -p no:randomly
"""

import os
import shutil
import struct
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
# The diagnostic filter belongs to tranche file 10; a substring search over the
# whole `nginx -t` output would match the temp directory rather than a message.
from test_audit16j_root_caps_flags import _diagnostics
from test_audit15i_staged_writev import _write
from test_pgwrite_checksum import (
    _close,
    _handshake_login,
    _open_for_write,
    _read_response,
    kXR_ok,
)
from test_unix_auth_wire import _open_read, kXR_read

pytestmark = [pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16r-csi")]

NAME = "lc-audit16r-csi"
TEMPLATE = "nginx_audit16r_csi.conf"

ROOT = Path(__file__).resolve().parents[1]
DIRECTIVES_H = ROOT / "src/protocols/root/stream/directives_auth.h"
CONF_STRUCTS_H = ROOT / "src/core/types/conf_structs.h"
OPEN_FINALIZE_C = ROOT / "src/protocols/root/read/open_resolved_file_finalize.c"
READ_BUFFERED_C = ROOT / "src/protocols/root/read/read_buffered.c"
READ_SENDFILE_C = ROOT / "src/protocols/root/read/read_sendfile.c"
VFS_IO_CORE_C = ROOT / "src/fs/vfs/vfs_io_core.c"
VFS_IO_CORE_H = ROOT / "src/fs/vfs/vfs_io_core.h"
CSI_VERIFY_C = ROOT / "src/fs/backend/csi_verify.c"
POSTCONF_C = ROOT / "src/core/config/postconfiguration.c"
SRC_DIR = ROOT / "src"
CONFIGS_DIR = Path(__file__).resolve().parent / "configs"

# The two subjects, and the conf field each one's value lands in.
SUBJECTS = {"brix_csi_require": "require",
            "brix_csi_trust_fs": "trust_fs"}

# The arms, spelled out as literals rather than assembled from a name and a
# value: the audit's own step-1/step-2 measurement is a grep for
# `<directive> <value>;` over the tree, so a token this file only ever built at
# runtime would leave the gap exactly where it was found.
REQUIRE_ON = "brix_csi_require on;"
REQUIRE_OFF = "brix_csi_require off;"
TRUST_ON = "brix_csi_trust_fs on;"
TRUST_OFF = "brix_csi_trust_fs off;"

OFF_ARMS = (REQUIRE_OFF, TRUST_OFF)

# kXR codes.  Telling them apart is most of the point of this file: three of the
# four are ways for one read of one file to fail, and they mean different things
# to a client deciding whether to retry, to re-fetch, or to give up on a replica.
KXR_IO_ERROR = 3007        # "the disk is broken"    (error_mapping.c)
KXR_NOT_AUTHORIZED = 3010
KXR_NOT_FOUND = 3011
KXR_CHKSUM_ERR = 3019      # "this replica is corrupt"
GRANTED = "granted"

# 12288 bytes = exactly three whole blocks at the granule pinned below, so a
# whole-file read covers every block fully and the coverage rule (§E) is a
# property the test chooses rather than one it stumbles into.
BLOCK = 4096
PAYLOAD = bytes(range(256)) * 48
CORRUPT_AT = 5000          # inside block 1 of 3
CINFO = "user.xrd.cinfo"   # the xmeta record's xattr name (fs/meta/xmeta_path.c)

_needs_nginx = pytest.mark.skipif(not os.access(NGINX_BIN, os.X_OK),
                                  reason=f"nginx not executable: {NGINX_BIN}")


def _csi_block(*arms, enable=True):
    """One server's whole CSI block.

    ``brix_csi_block`` is pinned in every block: the granule sizes new records
    and existing records keep their own, so leaving it to the merge would make
    a file tagged by one acceptor and read by another a measurement of the
    granule rather than of the arm.
    """
    if not enable:
        return "brix_csi off;"
    return "\n        ".join(["brix_csi on;", f"brix_csi_block {BLOCK};", *arms])


def _read_at(sock, fhandle, offset, length):
    """One kXR_read at an explicit offset.

    ``test_unix_auth_wire._read`` pins offset 0; §E turns on WHICH byte range a
    read covers, so the offset has to be a parameter.  Same 24-byte frame.
    """
    sock.sendall(struct.pack("!2sH4sqiI", b"\x00\x05", kXR_read,
                             fhandle, offset, length, 0))
    return _read_response(sock)


class _Farm:
    """Four root:// acceptors over one export, and the file states the test puts
    into it."""

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.ports = {"A": endpoint.port,
                      "B": endpoint.extra_ports["B_PORT"],
                      "C": endpoint.extra_ports["C_PORT"],
                      "D": endpoint.extra_ports["D_PORT"]}
        self.root = Path(endpoint.data_root)
        self.logs = Path(endpoint.prefix) / "logs"

    # -- putting the export into a known state ----------------------------- #

    def purge(self):
        """Empty the export before a case seeds it.

        The data root belongs to the INSTANCE NAME, not to the test, so it
        outlives the function-scoped nginx — and the integrity record lives in
        an xattr, which ``Path.write_bytes`` does not clear.  A file left behind
        by an earlier case would hand the next one a file it believes is
        untagged and the server sees as recorded, which is exactly the
        distinction §B turns on.  (It is also a real-world trap: rewriting an
        exported file out of band keeps the OLD record, and whether the read
        then fails depends on whether the new bytes happen to match it.)
        """
        for path in self.root.iterdir():
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()

    def put(self, server, name, data=PAYLOAD):
        """Write `name` through an acceptor, which is what folds the record."""
        sock = _handshake_login(HOST, self.ports[server])
        try:
            fhandle = _open_for_write(sock, ("/" + name).encode())
            _sid, status, _body = _write(sock, fhandle, 0, data)
            _close(sock, fhandle)
            return status
        finally:
            sock.close()

    def corrupt(self, name, at=CORRUPT_AT):
        """Flip one byte UNDER an intact record; returns the new bytes."""
        raw = bytearray((self.root / name).read_bytes())
        raw[at] ^= 0xFF
        (self.root / name).write_bytes(bytes(raw))
        return bytes(raw)

    def seed_untagged(self, name, data=PAYLOAD):
        """Bytes with no record at all — the export as it looks before CSI, and
        after any copy that did not go through the server."""
        (self.root / name).write_bytes(data)

    def tagged(self, name):
        try:
            os.getxattr(self.root / name, CINFO)
            return True
        except OSError:
            return False

    # -- asking an acceptor about it --------------------------------------- #

    def read(self, server, name, offset=0, length=len(PAYLOAD)):
        """(GRANTED, bytes) or (kXR code, message).

        The open and the read are both here because either can be the refusal:
        ``require`` fails the OPEN and a verify mismatch fails the READ, and a
        test that only looked at one of them would miss whichever arm it was
        not watching.
        """
        sock = _handshake_login(HOST, self.ports[server])
        try:
            status, body = _open_read(sock, ("/" + name).encode())
            if status != kXR_ok:
                return self._failure(body)
            status, body = _read_at(sock, body[:4], offset, length)
            if status != kXR_ok:
                return self._failure(body)
            return GRANTED, body
        finally:
            sock.close()

    def open_for_write(self, server, name):
        """(GRANTED, "") or (kXR code, message) for an open-for-write."""
        sock = _handshake_login(HOST, self.ports[server])
        try:
            fhandle = _open_for_write_or_error(sock, ("/" + name).encode())
            if isinstance(fhandle, tuple):
                return fhandle
            _close(sock, fhandle)
            return GRANTED, ""
        finally:
            sock.close()

    @staticmethod
    def _failure(body):
        code = struct.unpack("!I", body[:4])[0] if len(body) >= 4 else None
        return code, body[4:].decode(errors="replace").rstrip("\x00")

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        try:
            return (self.logs / "error.log").read_text(errors="replace")
        except OSError:                          # pragma: no cover - diagnostic
            return "(error log unavailable)"


def _open_for_write_or_error(sock, path):
    """``_open_for_write`` without its assert — §B needs the refusal, not a
    fixture error."""
    from test_pgwrite_checksum import kXR_delete, kXR_open, kXR_open_updt

    sock.sendall(struct.pack("!2sHHH2s6s4sI", b"\x00\x02", kXR_open,
                             0o644, kXR_open_updt | kXR_delete,
                             b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                             len(path)) + path)
    status, body = _read_response(sock)
    if status != kXR_ok:
        return _Farm._failure(body)
    return body[:4]


@pytest.fixture
def farm(lifecycle):
    """A factory for one nginx carrying whichever four CSI blocks a case names.

    Every acceptor exports the same data root, so a verdict that differs between
    two of them cannot be explained by anything but the arm.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    def _start(reason, a, b, c, d):
        started = _Farm(lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template=TEMPLATE,
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST,
                             "A_CSI": a, "B_CSI": b, "C_CSI": c, "D_CSI": d},
            reason=reason)))
        started.purge()
        return started
    return _start


# The two layouts almost every runtime case below uses.  Naming them keeps the
# four acceptors' meaning in one place, and keeps a case's own body down to the
# file state it creates and the verdict it asks for.
#
#   TRUST_LAYOUT   A verifies (both flags absent)   the control
#                  B trusts                          the arm the corpus writes
#                  C trusts, written off             the arm it never wrote
#                  D requires                        the other subject, for §D
#
#   REQUIRE_LAYOUT A requires, written off           the arm it never wrote
#                  B requires AND trusts             §C's finding
#                  C requires and trusts, off        the composition that works
#                  D no engine at all                the floor
TRUST_LAYOUT = dict(a=_csi_block(),
                    b=_csi_block(TRUST_ON),
                    c=_csi_block(TRUST_OFF),
                    d=_csi_block(REQUIRE_ON))
REQUIRE_LAYOUT = dict(a=_csi_block(REQUIRE_OFF),
                      b=_csi_block(REQUIRE_ON, TRUST_ON),
                      c=_csi_block(REQUIRE_ON, TRUST_OFF),
                      d=_csi_block(enable=False))


# --------------------------------------------------------------------------- #
# §A — brix_csi_trust_fs, three arms in one worker                            #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheTrustFsArms:
    """What the flag decides is not how fast a read is; it is whether a read of
    known-corrupt bytes succeeds."""

    def test_a_clean_file_reads_byte_exact_through_every_arm(self, farm):
        """The floor.  Before any arm can be said to change a verdict, all four
        acceptors have to agree about an undamaged file — otherwise §A would be
        measuring the export, the granule or the write path."""
        f = farm("audit-16r §A clean baseline", **TRUST_LAYOUT)
        assert f.put("A", "clean.bin") == kXR_ok, f.errlog()
        assert f.tagged("clean.bin"), "the write left no integrity record"
        for server in "ABCD":
            verdict, body = f.read(server, "clean.bin")
            assert verdict == GRANTED, f"{server}: {verdict} {body}"
            assert body == PAYLOAD, f"{server} served different bytes"

    def test_the_absent_arm_refuses_a_corrupt_read(self, farm):
        """Acceptor A writes neither flag.  The merge default is 0, so the
        engine attaches on reads and the damaged block fails — this is the
        behaviour the two `off` arms below have to reproduce."""
        f = farm("audit-16r §A absent vs corrupt", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        f.corrupt("clean.bin")
        verdict, message = f.read("A", "clean.bin")
        assert verdict != GRANTED, "corrupt bytes were served"
        assert verdict == KXR_IO_ERROR, (verdict, message)

    def test_the_off_arm_refuses_the_same_read(self, farm):
        """The arm the corpus never wrote, reaching the merge as 0 through the
        other route.  Absence and ``off`` are the same configuration measured
        two ways, and this is the case that says so rather than assuming it."""
        f = farm("audit-16r §A off vs corrupt", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        f.corrupt("clean.bin")
        assert f.read("C", "clean.bin")[0] == KXR_IO_ERROR

    def test_the_on_arm_serves_the_corrupt_bytes(self, farm):
        """Not a no-op in the other direction: the trusting acceptor hands back
        exactly what is on disk, including the flipped byte, with kXR_ok.  A
        client cannot tell this read from a good one."""
        f = farm("audit-16r §A on vs corrupt", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        damaged = f.corrupt("clean.bin")
        verdict, body = f.read("B", "clean.bin")
        assert verdict == GRANTED, (verdict, body)
        assert body == damaged
        assert body != PAYLOAD, "the fixture did not actually damage the file"

    def test_the_three_arms_disagree_in_one_worker(self, farm):
        """The attribution control.  One process, one export, one file, three
        verdicts — so the flag is read per server on every open, and none of §A
        is an artefact of restarting nginx between arms.  (File 17's
        ``brix_acc_pgo``, declared at the same scope in the same header, fails
        exactly this test; #92.)"""
        f = farm("audit-16r §A per-server control", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        f.corrupt("clean.bin")
        verdicts = {s: f.read(s, "clean.bin")[0] for s in "ABC"}
        assert verdicts == {"A": KXR_IO_ERROR,
                            "B": GRANTED,
                            "C": KXR_IO_ERROR}, verdicts

    def test_a_trusting_acceptor_still_writes_the_record(self, farm):
        """``on`` skips the engine for READS only — the branch is
        ``!(trust_fs && !is_write)``.  A trusted export therefore keeps
        producing records for everyone else to verify against, which is what
        makes the flag a read-side policy rather than an opt-out."""
        f = farm("audit-16r §A trusted write still tags", **TRUST_LAYOUT)
        assert f.put("B", "viaTrust.bin") == kXR_ok
        assert f.tagged("viaTrust.bin")
        # And a verifying acceptor accepts what the trusting one wrote.
        assert f.read("A", "viaTrust.bin") == (GRANTED, PAYLOAD)

    def test_the_engine_master_switch_is_a_different_thing(self, farm):
        """``brix_csi off`` and ``brix_csi_trust_fs on`` reach the same read
        verdict by different routes, and are not interchangeable: the first
        stops recording, the second keeps recording and stops checking.  An
        operator who reads them as synonyms silently stops producing the records
        every other acceptor depends on."""
        f = farm("audit-16r §A master switch", **REQUIRE_LAYOUT)
        f.put("A", "clean.bin")
        damaged = f.corrupt("clean.bin")
        assert f.read("D", "clean.bin") == (GRANTED, damaged)
        assert f.put("D", "viaOff.bin") == kXR_ok
        assert not f.tagged("viaOff.bin"), "brix_csi off still recorded"


# --------------------------------------------------------------------------- #
# §B — brix_csi_require, three arms in one worker                             #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheRequireArms:
    """What the flag decides is whether an UNTAGGED file may be read at all."""

    def test_the_absent_arm_serves_an_untagged_file(self, farm):
        """The merge default is 0 and the code calls it fail-open: an
        unrecorded read proceeds without CSI.  Every export that predates the
        feature depends on this."""
        f = farm("audit-16r §B absent vs untagged", **TRUST_LAYOUT)
        f.seed_untagged("untagged.bin")
        assert not f.tagged("untagged.bin")
        assert f.read("A", "untagged.bin") == (GRANTED, PAYLOAD)

    def test_the_off_arm_serves_it_too(self, farm):
        """The arm the corpus never wrote, reaching the same 0 explicitly."""
        f = farm("audit-16r §B off vs untagged", **REQUIRE_LAYOUT)
        f.seed_untagged("untagged.bin")
        assert f.read("A", "untagged.bin") == (GRANTED, PAYLOAD)

    def test_the_on_arm_refuses_it_with_chksumerr(self, farm):
        """The refusal, and its wording.  This is the ONE place on the read path
        that produces kXR_ChkSumErr — §D is about the place that does not."""
        f = farm("audit-16r §B on vs untagged", **TRUST_LAYOUT)
        f.seed_untagged("untagged.bin")
        verdict, message = f.read("D", "untagged.bin")
        assert verdict == KXR_CHKSUM_ERR, (verdict, message)
        assert message == "integrity record missing", message

    def test_the_refusal_is_not_a_missing_file(self, farm):
        """The attribution control for §B.  An export with no record and an
        export with no file must not be the same reading, or every row above
        could be a seeding slip."""
        f = farm("audit-16r §B refusal vs not-found", **TRUST_LAYOUT)
        f.seed_untagged("untagged.bin")
        assert f.read("D", "untagged.bin")[0] == KXR_CHKSUM_ERR
        assert f.read("D", "nosuch.bin")[0] == KXR_NOT_FOUND
        assert f.read("D", "untagged.bin")[0] != KXR_NOT_AUTHORIZED

    def test_a_tagged_file_passes_the_requirement(self, farm):
        """``require on`` is a requirement about the RECORD, not a refusal of
        the export: the same acceptor serves a file that has one."""
        f = farm("audit-16r §B on vs tagged", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        assert f.read("D", "clean.bin") == (GRANTED, PAYLOAD)

    def test_it_gates_reads_only(self, farm):
        """``!is_write`` in the condition.  An open-for-write of an untagged
        file is granted — otherwise a require-on export could never be brought
        into compliance, since only a write creates the record it demands."""
        f = farm("audit-16r §B write open of an untagged file", **TRUST_LAYOUT)
        f.seed_untagged("untagged.bin")
        assert f.read("D", "untagged.bin")[0] == KXR_CHKSUM_ERR
        assert f.open_for_write("D", "untagged.bin") == (GRANTED, "")
        assert f.put("D", "untagged.bin") == kXR_ok
        assert f.tagged("untagged.bin")
        assert f.read("D", "untagged.bin") == (GRANTED, PAYLOAD)

    def test_the_three_arms_disagree_in_one_worker(self, farm):
        """The per-server control for §B: one untagged file, three verdicts, one
        process."""
        f = farm("audit-16r §B per-server control", **REQUIRE_LAYOUT)
        f.seed_untagged("untagged.bin")
        verdicts = {s: f.read(s, "untagged.bin")[0] for s in "ACD"}
        assert verdicts == {"A": GRANTED,          # require off
                            "C": KXR_CHKSUM_ERR,   # require on, trust off
                            "D": GRANTED}, verdicts  # no engine


# --------------------------------------------------------------------------- #
# §C — DEFECT CANDIDATE #93: the two flags are not independent                #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheArmsCompose:
    """``brix_csi_require on`` is silently inert under ``brix_csi_trust_fs on``.

    Both are declared as plain per-server flags with nothing to suggest an
    ordering between them, and an operator writing both is asking for the strict
    reading of both: record every file, refuse anything unrecorded, and skip the
    per-read CRC because the filesystem already checksums.  What they get is the
    skip and not the refusal — the ``require`` test is nested inside the branch
    that ``trust_fs`` turns off.
    """

    def test_require_on_is_inert_under_trust_on(self, farm):
        """The finding.  Acceptor B writes both arms and serves the file that
        acceptor C — the same two directives, one of them ``off`` — refuses."""
        f = farm("audit-16r §C require under trust", **REQUIRE_LAYOUT)
        f.seed_untagged("untagged.bin")
        assert f.read("B", "untagged.bin") == (GRANTED, PAYLOAD), \
            "DEFECT CANDIDATE #93 has been FIXED: require now survives " \
            "trust_fs.  Flip this expectation to kXR_ChkSumErr and strike #93."
        assert f.read("C", "untagged.bin")[0] == KXR_CHKSUM_ERR

    def test_it_also_loses_the_corruption_check(self, farm):
        """Both halves at once, so the loss is not read as a trade.  The same
        acceptor that stopped requiring a record also stopped checking the
        records it has: B serves corrupt bytes AND unrecorded bytes."""
        f = farm("audit-16r §C both halves", **REQUIRE_LAYOUT)
        f.put("C", "clean.bin")
        damaged = f.corrupt("clean.bin")
        f.seed_untagged("untagged.bin")
        assert f.read("B", "clean.bin") == (GRANTED, damaged)
        assert f.read("B", "untagged.bin") == (GRANTED, PAYLOAD)
        assert f.read("C", "clean.bin")[0] == KXR_IO_ERROR
        assert f.read("C", "untagged.bin")[0] == KXR_CHKSUM_ERR

    def test_nothing_at_config_time_says_so(self, farm):
        """The half that makes this a defect rather than a documented
        interaction.  ``nginx -t`` accepts the pair without a word, and the
        worker's startup log — which does announce the export, the mode and the
        auth scheme — never mentions CSI at all."""
        f = farm("audit-16r §C silence", **REQUIRE_LAYOUT)
        log = f.errlog()
        assert "endpoint ready" in log, log[-2000:]
        offending = [line for line in log.splitlines()
                     if "csi" in line.lower()
                     and ("[warn]" in line or "[error]" in line
                          or "[emerg]" in line)]
        assert offending == [], offending

    def test_nginx_t_accepts_the_pair_in_silence(self, tmp_path):
        """The same silence at the parse tier, where a merge-time diagnostic
        would live.  Written as a parse case so it stays true for a
        configuration that never starts."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS=f"        brix_csi on;\n"
                                      f"        {REQUIRE_ON}\n"
                                      f"        {TRUST_ON}\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    def test_the_gate_in_the_source_is_the_reason(self, farm):
        """The one line of C the whole section rests on: the ``require`` test is
        inside the ``if`` that ``trust_fs`` short-circuits, so no ordering of
        the two directives in a config can change the outcome."""
        squashed = _squashed(OPEN_FINALIZE_C)
        assert ("if (conf->csi.enable && S_ISREG(st->st_mode) "
                "&& !(conf->csi.trust_fs && !is_write))") in squashed
        assert ("if (!is_write && crc == BRIX_CSI_NOTAGS "
                "&& conf->csi.require)") in squashed
        gate = squashed.index("!(conf->csi.trust_fs && !is_write)")
        require = squashed.index("&& conf->csi.require)")
        assert gate < require, "the require test is no longer nested"
        # Reversing the order in the config cannot matter, and this is the
        # measurement that says the source reading is the operative one.
        f = farm("audit-16r §C order is irrelevant",
                 a=_csi_block(TRUST_ON, REQUIRE_ON),
                 b=_csi_block(REQUIRE_ON, TRUST_ON),
                 c=_csi_block(REQUIRE_ON),
                 d=_csi_block())
        f.seed_untagged("untagged.bin")
        assert f.read("A", "untagged.bin")[0] == GRANTED
        assert f.read("B", "untagged.bin")[0] == GRANTED
        assert f.read("C", "untagged.bin")[0] == KXR_CHKSUM_ERR


# --------------------------------------------------------------------------- #
# §D — DEFECT CANDIDATE #94: the mismatch never reaches the wire as one       #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheMismatchErrorCode:
    """At-rest corruption is reported as a disk error, not a checksum error.

    The distinction is not cosmetic.  kXR_IOError tells a client the server had
    trouble reading; kXR_ChkSumErr tells it this replica's bytes are wrong.  A
    federation client retries the first elsewhere and can be told to quarantine
    the second — and the scrub metric that would otherwise surface it
    (``brix_csi_scrub_mismatch_total``) counts only the background scrub, never
    a read.
    """

    def test_a_verify_mismatch_reports_ioerror(self, farm):
        """The measurement.  Same file, same byte, two acceptors that both
        verify — both say 3007."""
        f = farm("audit-16r §D the code on the wire", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        f.corrupt("clean.bin")
        for server in ("A", "C"):
            verdict, message = f.read(server, "clean.bin")
            assert verdict == KXR_IO_ERROR, \
                ("DEFECT CANDIDATE #94 has been FIXED: a CSI verify mismatch "
                 "now reports kXR_ChkSumErr.  Flip this expectation and strike "
                 f"#94 from the audit.  Got {verdict}: {message}")
            assert message == "Input/output error", message

    def test_the_same_feature_reports_a_missing_record_as_chksumerr(self, farm):
        """The inconsistency, in one process.  'No record at all' is a checksum
        error; 'the record says these bytes are wrong' is a disk error.  If
        either code is right, it is not this way round."""
        f = farm("audit-16r §D the two codes side by side", **TRUST_LAYOUT)
        f.put("A", "clean.bin")
        f.corrupt("clean.bin")
        f.seed_untagged("untagged.bin")
        assert f.read("A", "clean.bin")[0] == KXR_IO_ERROR
        assert f.read("D", "untagged.bin")[0] == KXR_CHKSUM_ERR

    def test_the_out_bit_that_would_have_carried_it_is_set(self):
        """The job struct does carry the distinction — one bit, declared for
        exactly this, and written on every mismatch."""
        assert ("unsigned csi_mismatch:1; "
                "/* OUT: a page failed CSI verify (W2) */") in \
            _squashed(VFS_IO_CORE_H)
        squashed = _squashed(VFS_IO_CORE_C)
        assert "job->csi_mismatch = 1;" in squashed
        assert ("maps it to kXR_ChkSumErr instead of serving corrupt data.") \
            in squashed

    def test_and_nothing_in_src_ever_reads_it(self):
        """The defect itself: one write, zero reads, in the whole of ``src/``.
        The bit is set, documented as the mechanism for a specific mapping, and
        dropped on the floor."""
        writes, reads = [], []
        for path in sorted(SRC_DIR.rglob("*")):
            if path.suffix not in (".c", ".h") or not path.is_file():
                continue
            for number, line in enumerate(
                    path.read_text(errors="replace").splitlines(), 1):
                if "csi_mismatch" not in line:
                    continue
                stripped = line.strip()
                where = f"{path.relative_to(ROOT)}:{number}"
                if stripped.startswith("*") or stripped.startswith("/*"):
                    continue                     # prose about the bit
                if "csi_mismatch = 1" in stripped:
                    writes.append(where)
                elif "csi_mismatch:1;" in stripped:
                    continue                     # the declaration
                else:
                    reads.append(where)
        assert writes == ["src/fs/vfs/vfs_io_core.c:155"], writes
        assert reads == [], \
            ("DEFECT CANDIDATE #94 has been FIXED: something now reads "
             f"csi_mismatch.  Re-read §D and strike #94.  Readers: {reads}")

    def test_the_hard_coded_code_is_the_one_on_the_wire(self):
        """And the site that answers instead, which is why the reading above
        surfaces as 3007: a literal, on the path both the warm-hit and the
        synchronous fill converge on."""
        squashed = _squashed(READ_BUFFERED_C)
        assert "kXR_IOError, strerror(errno));" in squashed
        assert "mismatch surfaces here as EIO (job.csi_mismatch set);" in squashed
        assert "kXR_ChkSumErr" not in squashed

    def test_an_integrity_checked_handle_never_takes_the_sendfile_path(self):
        """The control on the two findings above: neither is "the read skipped
        the engine".  A handle with a CSI engine is excluded from zero-copy by
        the gate itself, so every verifying read really does run through the
        buffered path that §D measures."""
        assert "&& ctx->files[idx].csi == NULL" in _squashed(READ_SENDFILE_C)


# --------------------------------------------------------------------------- #
# §E — what verification covers, and what it does not                         #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheCoverageRule:
    """Verification is per BLOCK and only for blocks the read buffer fully
    spans.  That is a deliberate fail-open on coverage (csi_verify.c), and it
    bounds what ``trust_fs off`` can be said to guarantee."""

    def test_a_read_of_the_damaged_block_fails(self, farm):
        f = farm("audit-16r §E aligned block reads", **TRUST_LAYOUT)
        f.put("A", "big.bin")
        f.corrupt("big.bin")
        assert f.read("A", "big.bin", 1 * BLOCK, BLOCK)[0] == KXR_IO_ERROR

    @pytest.mark.parametrize("block", (0, 2))
    def test_a_read_of_an_undamaged_block_succeeds(self, farm, block):
        """The other two blocks of the same file are unaffected — the granule
        is the unit, so damage does not poison the whole object."""
        f = farm("audit-16r §E intact blocks", **TRUST_LAYOUT)
        f.put("A", "big.bin")
        f.corrupt("big.bin")
        verdict, body = f.read("A", "big.bin", block * BLOCK, BLOCK)
        assert verdict == GRANTED, (verdict, body)
        assert body == PAYLOAD[block * BLOCK:(block + 1) * BLOCK]

    def test_a_straddling_read_serves_the_corrupt_byte(self, farm):
        """The limitation, measured rather than inferred.  A read of
        [2048, 6144) contains the flipped byte at 5000 and covers NO block
        fully — block 0 starts before it and block 1 ends after it — so the loop
        verifies nothing and the corruption is served, under ``trust_fs off``,
        with kXR_ok.  An operator who writes ``off`` gets per-block detection,
        not per-byte detection, and nothing in the configuration says so."""
        f = farm("audit-16r §E straddling read", **TRUST_LAYOUT)
        f.put("A", "big.bin")
        damaged = f.corrupt("big.bin")
        verdict, body = f.read("C", "big.bin", 2048, BLOCK)
        assert verdict == GRANTED, (verdict, body)
        assert body == damaged[2048:2048 + BLOCK]
        assert body != PAYLOAD[2048:2048 + BLOCK]

    def test_the_coverage_rule_is_where_the_source_says(self):
        """Pinned so the reading above cannot quietly become wrong: the loop
        breaks out on the first block the buffer does not fully span."""
        squashed = _squashed(CSI_VERIFY_C)
        assert "break; /* not fully covered by this read */" in squashed
        assert "if (len == 0 || c->trust_fs) { return BRIX_CSI_OK;" in squashed


# --------------------------------------------------------------------------- #
# §F — the parse tier                                                         #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, **slots):
    """`nginx -t` on file 14's scaffold with the named slots filled.

    Every slot defaults to empty so a case names only what it is about: the
    scaffold writes nothing about CSI, so a negative is never answered by a
    duplicate diagnostic first.
    """
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "STREAM_PORT": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "DATA": str(data),
              "LOC_KNOBS": "", "SRV_KNOBS": "", "HTTP_KNOBS": "",
              "OUTER": "", "STREAM_KNOBS": "", "STREAM_MAIN": "",
              "EXTRA_LOC": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16nparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


# The one scope the mask names, and every placement it does not.  Unlike file
# 17's subjects these two names exist on the stream plane only — there is no
# http twin to measure, which is itself worth pinning (§G).
WRONG_SCOPES = ("SRV_KNOBS", "HTTP_KNOBS", "LOC_KNOBS", "OUTER", "STREAM_MAIN")


@_needs_nginx
class TestTheParseTier:
    """Values, arity, duplicates and the placement matrix, asked with nothing
    else in the file that could answer instead."""

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_a_stream_server(self, tmp_path, arm,
                                                       directive):
        """The audit's step-1 question at the declared scope.  Two of these four
        cases are the arm the corpus never wrote, and none of them advises
        anything: turning an integrity knob off is a decision, not a
        misconfiguration — which is exactly why §C's silence is a defect and
        this silence is not."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=f"        {directive} {arm};\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("arm", ("ON", "Off"))
    def test_the_arms_are_case_insensitive(self, tmp_path, arm, directive):
        """``ngx_conf_set_flag_slot`` compares case-insensitively, so a config
        that shouts is the same configuration.  Pinned because §G's corpus
        census greps for the lower-case spelling and would miss a shouted arm."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=f"        {directive} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("value", ("1", "0", "yes", "true", "enabled"))
    def test_anything_else_is_refused_by_name(self, tmp_path, value, directive):
        """The refusal names the directive and both legal arms — the one piece
        of config-time feedback these two directives do give."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=f"        {directive} {value};\n")
        assert rc != 0, out
        assert (f'invalid value "{value}" in "{directive}" directive, '
                'it must be "on" or "off"') in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("body", ("", " on off"))
    def test_the_arity_is_exactly_one(self, tmp_path, body, directive):
        rc, out = _parse(tmp_path, STREAM_KNOBS=f"        {directive}{body};\n")
        assert rc != 0, out
        assert (f'invalid number of arguments in "{directive}" directive') \
            in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_a_second_write_in_one_server_is_refused(self, tmp_path, directive):
        """``ngx_conf_set_flag_slot`` refuses a repeated write, so an operator
        cannot end up with two arms in one server and no idea which won."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS=f"        {directive} on;\n"
                                      f"        {directive} off;\n")
        assert rc != 0, out
        assert f'"{directive}" directive is duplicate' in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    @pytest.mark.parametrize("slot", WRONG_SCOPES)
    def test_every_other_placement_is_refused(self, tmp_path, slot, directive):
        """NGX_STREAM_SRV_CONF alone — not http, not a location, not stream
        main, not the top level.  ``is not allowed here`` and never ``unknown
        directive``: the name is always known, and only the placement is
        wrong."""
        rc, out = _parse(tmp_path, **{slot: f"    {directive} off;\n"})
        assert rc != 0, out
        assert f'"{directive}" directive is not allowed here' in out, out
        assert "unknown directive" not in out, out

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_both_arms_parse_without_the_master_switch(self, tmp_path,
                                                       directive):
        """``brix_csi off`` plus a written arm is accepted in silence too: the
        flag has no effect at all with the engine off, and nothing says so.
        The same shape as §C, one level up."""
        rc, out = _parse(tmp_path,
                         STREAM_KNOBS=f"        brix_csi off;\n"
                                      f"        {directive} on;\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out


# --------------------------------------------------------------------------- #
# §G — the declarations, the merges and the corpus                            #
# --------------------------------------------------------------------------- #

def _squashed(path):
    return " ".join(path.read_text().split())


# Where the audit's step-1/step-2 grep looks, and the suffixes it counts.  As in
# file 17, these directives are configured from test sources and documented in
# prose rather than from a rendered template, so a census restricted to
# `configs/` would report a gap that is not there and miss the one that is.
CORPUS_ROOTS = (ROOT / "tests", ROOT / "docs", ROOT / "k8s-tests")
CORPUS_SUFFIXES = (".py", ".conf", ".md", ".sh")


def _corpus_writes(token):
    """Every file OUTSIDE this one that spells `token` literally."""
    here = Path(__file__).resolve()
    hits = []
    for root in CORPUS_ROOTS:
        for path in root.rglob("*"):
            if path.suffix not in CORPUS_SUFFIXES or not path.is_file():
                continue
            if path.resolve() == here:
                continue
            try:
                if token in path.read_text(errors="replace"):
                    hits.append(str(path.relative_to(ROOT)))
            except OSError:                      # pragma: no cover - diagnostic
                continue
    return sorted(hits)


class TestTheDeclarationsAndTheCorpus:
    """Every reading above is an inference from a handful of lines of C and from
    what the corpus does not contain.  If either changes, the tests would keep
    passing while measuring something else."""

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_the_declaration_is_a_server_scoped_flag_slot(self, directive):
        """One scope, ``ngx_conf_set_flag_slot``, NGX_STREAM_SRV_CONF_OFFSET —
        the shape §F measures and the promise §A's per-server control keeps."""
        text = DIRECTIVES_H.read_text()
        marker = f'{{ ngx_string("{directive}"),'
        assert marker in text, directive
        # splitlines()[0] is the tail of the marker's own line, which is empty.
        lines = [ln.strip() for ln in text.split(marker, 1)[1].splitlines()[1:5]]
        assert lines[0] == "NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,", lines
        assert lines[1] == "ngx_conf_set_flag_slot,", lines
        assert lines[2] == "NGX_STREAM_SRV_CONF_OFFSET,", lines
        assert lines[3] == ("offsetof(ngx_stream_brix_srv_conf_t, "
                            f"csi.{SUBJECTS[directive]}),"), lines

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_it_is_declared_on_the_stream_plane_only(self, directive):
        """Unlike file 17's three, these two names have no http twin anywhere in
        ``src/`` — so a WebDAV or S3 export has no way to ask for either
        behaviour, and §F has one plane to measure rather than two."""
        elsewhere = [str(path.relative_to(ROOT))
                     for path in sorted(SRC_DIR.rglob("*.c"))
                     if f'ngx_string("{directive}")' in
                     path.read_text(errors="replace")]
        assert elsewhere == [], elsewhere

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_it_initialises_unset_and_merges_to_zero(self, directive):
        """The two routes to the same value that §A and §B each measure: absence
        arrives as NGX_CONF_UNSET and is merged to 0, which is what makes ``off``
        the arm nobody needed to write and ``on`` the arm everybody did."""
        field = SUBJECTS[directive]
        squashed = _squashed(CONF_STRUCTS_H)
        assert f"c->{field} = NGX_CONF_UNSET;" in squashed
        assert f"ngx_conf_merge_value(c->{field}, p->{field}, 0);" in squashed

    def test_the_master_switch_defaults_the_other_way(self):
        """``brix_csi`` merges to 1 while both subjects merge to 0 — the engine
        runs by default and neither policy is on by default.  This asymmetry is
        why the corpus wrote ``on`` for the subjects and why §A's floor is a
        recording export rather than a bare one."""
        assert "ngx_conf_merge_value(c->enable, p->enable, 1);" in \
            _squashed(CONF_STRUCTS_H)

    def test_the_read_path_is_the_only_reader_of_either_field(self):
        """Both flags are consulted in one function, on the open path, and
        nowhere else in ``src/`` — which is why §A and §B can each hold three
        arms in one worker, and why §C's nesting is the whole story."""
        readers = set()
        for path in sorted(SRC_DIR.rglob("*")):
            if path.suffix not in (".c", ".h") or not path.is_file():
                continue
            text = path.read_text(errors="replace")
            if "conf->csi.require" in text or "conf->csi.trust_fs" in text:
                readers.add(str(path.relative_to(ROOT)))
        assert readers == {
            "src/protocols/root/read/open_resolved_file_finalize.c"}, readers

    def test_the_endpoint_banner_says_nothing_about_integrity(self):
        """The source behind §C's silence: the startup census that names the
        export, the mode and the auth scheme has no CSI branch at all."""
        text = POSTCONF_C.read_text()
        assert "root:// endpoint ready" in text
        assert "csi" not in text.lower()

    @pytest.mark.parametrize("directive", sorted(SUBJECTS))
    def test_the_corpus_writes_the_on_arm_and_never_the_off_arm(self,
                                                               directive):
        """Steps 1 and 2 of the audit's own measurement, as this file found
        them.  If another file starts writing ``off``, re-run the gap table
        rather than relaxing this."""
        assert _corpus_writes(f"{directive} on;"), \
            f"{directive} is written nowhere at all"
        assert _corpus_writes(f"{directive} off;") == []

    @pytest.mark.parametrize("arm", OFF_ARMS)
    def test_this_file_writes_every_off_arm_literally(self, arm):
        """The closure itself.  The audit greps the tree for
        ``<directive> <value>;``, so an arm assembled at runtime from a name and
        a token would leave the gap open while the tests passed."""
        assert arm in Path(__file__).read_text()

    def test_the_only_other_exerciser_is_a_gated_live_script(self):
        """Why this file exists next to ``gsi_trust_live.py``: that script needs
        a built native ``xrdcp``, is not collected by pytest, and writes its
        control arm as absence.  Pinned so a future reader does not delete one
        as a duplicate of the other."""
        script = ROOT / "tests/cmdscripts/gsi_trust_live.py"
        text = script.read_text()
        assert "brix_csi_trust_fs on;" in text
        assert "brix_csi_require on;" in text
        assert "brix_csi_trust_fs off;" not in text
        assert "brix_csi_require off;" not in text
        assert "native xrdcp not built" in text

    def test_the_template_carries_four_csi_slots_and_writes_no_arm(self):
        """The template offers a whole CSI block per listener and takes no
        position on either subject: four root:// servers, one export, and not
        one of the four arms written in the file itself."""
        text = (CONFIGS_DIR / TEMPLATE).read_text()
        for slot in ("{A_CSI}", "{B_CSI}", "{C_CSI}", "{D_CSI}"):
            assert slot in text, slot
        squashed = " ".join(text.split())
        for directive in SUBJECTS:
            assert f"{directive} on;" not in squashed, directive
            assert f"{directive} off;" not in squashed, directive
        assert squashed.count("brix_root on;") == 4
        assert squashed.count("brix_auth none;") == 4
        assert squashed.count("{DATA_ROOT}") == 4

    def test_the_ledger_owns_one_port_per_listener(self):
        """Four sockets, four ledger allocations, all distinct.  Four acceptors
        rather than one restarted four times is what makes §A's and §B's
        per-server controls possible at all."""
        slot = LIFECYCLE_SHARED_PORTS[NAME]
        ports = [slot["port"], *slot["extra"].values()]
        assert sorted(slot["extra"]) == ["B_PORT", "C_PORT", "D_PORT"]
        assert len(set(ports)) == 4, ports
