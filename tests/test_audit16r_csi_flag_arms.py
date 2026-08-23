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

from split_continuation import load as _load_continuations
_load_continuations(
    globals(), __file__,
    "_test_audit16r_csi_flag_arms_part2.py",
    "_test_audit16r_csi_flag_arms_part3.py",
    "_test_audit16r_csi_flag_arms_part4.py",
)
