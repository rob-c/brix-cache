"""tests/test_audit16ae_gridftp_gate_off_arms.py — audit tranche 16, file 31.

WHY THIS FILE EXISTS
    The GridFTP gateway carries three flag gates, and no config in this tree has
    ever written the DISARMING arm of any of them:

        brix_gridftp_verify_write       `on` in nginx_gridftp_verify_{posix,pblock}.conf
        brix_gridftp_require_allo_size  `on` rendered by test_gridftp_allo_truncation.py
        brix_gridftp_gsi                `on` in the four gsiftp configs

    Both existing files name their control arm "off" and render ABSENCE for it —
    test_gridftp_allo_truncation.py literally writes

        extra = "brix_gridftp_require_allo_size on;" if require else ""

    and calls the result `gw_lenient`.  That is the shape this tranche keeps
    finding: a corpus that believes it covers both arms of a flag while only
    ever having measured one arm against a config that omits the line.  The
    equality is very probably true — all three merge to 0 at
    ftp_module_merge.c:160,161,164 — but "probably true by reading the merge" is
    what a test is for, and the merge is the one thing a written `off` exercises
    that an omission cannot: `ngx_conf_merge_value` is only reached with the
    slot still NGX_CONF_UNSET, so the two paths through it are different code.

    §A and §B write the missing arms.  What writing them turned out to be worth
    is everything after.

THE FINDINGS
    DEFECT CANDIDATE #111 — `brix_gridftp_gsi on` offers GSI; it never
    requires it.  The gateway configured exactly as docs/05-operations/gridftp.md
    §3 shows it ("The production form: an RFC 2228 GSI control channel
    authenticated by an X.509 (proxy) certificate") answers `230 Login
    successful` to `USER anonymous` / `PASS anything` and then serves a full
    read-write session.  ev_grp_login (ftp_ev_dispatch.c:226-233) sets
    `fc->authed = 1` on ANY `PASS`, unconditionally — `fc->conf->gsi` is not
    consulted there and there is no directive anywhere in the gridftp command
    table (ftp_module.c:208-341) that requires the security layer.  The
    published mitigation, `brix_gridftp_require_vo`, is a per-PATH ACL applied
    after resolution (ftp_ev_path.c:117-125) and is allow-all when no rule
    covers the path, so §3's example — which has no VO rules — has no gate at
    all.  §F measures it.

    DEFECT CANDIDATE #112 — `brix_gridftp_verify_write on` is switched off, per
    transfer, by a client-chosen `REST`.  ftp_ev_xfer.c:374 computes

        *verify = (fc->conf->verify_write && *start == 0);

    so any `REST > 0` before the STOR silently disables the operator's integrity
    check for that transfer.  The peer decides whether the server verifies.  §D
    measures it as a POSITIVE: a 100-byte file survives a `REST 10` STOR of 20
    bytes with `226`, which is only possible if the verifier never ran —
    brix_vfs_wverify_check (vfs_wverify.c) compares the accumulator's total
    length against the reopened file and unlinks the object on a mismatch, so a
    verifier that had run would have destroyed it.

    DEFECT CANDIDATE #113 — a `require_allo_size` refusal leaves the rejected
    object on disk, complete-looking and readable.  After a `550`, `SIZE`
    answers `213 2500` for the short case and RETR serves the 2500 bytes; the
    over-long case leaves 5000 bytes, which is LONGER than the `ALLO 4000` the
    refusal was based on.  The header's own contract for the flag
    (ftp_gateway.h:57-64) is "never a truncated object committed as complete",
    and leaving the truncation readable under its final name is the same
    outcome by a different route — the next client to GET it cannot tell.  The
    prefix is left deliberately, for REST-resume (the doc comment says so), but
    nothing marks it as partial and nothing distinguishes it from the whole
    file.  §E measures it.

    DEFECT CANDIDATE #114 — four `%ll` conversions are handed to nginx's own
    formatter, which implements `%L`/`%O` and not `%lld`/`%llu`.  One of them is
    on the wire: `REST 10` is answered `350 Restart position accepted (10ld)`.
    §I measures that one and names the other three.

WHAT THIS FILE DOES NOT CLAIM
    Not that `verify_write` should have caught the truncations in §C.  Its own
    doc comment (ftp_gateway.h:39-45) is honest about its scope — "STORAGE-
    persistence check, not wire" — so a plane with `verify_write on` and
    `require_allo_size off` answering 226 to a truncated upload is the
    documented behaviour and gets no number.  It is still worth measuring and
    stating plainly, because the flag named for verification is not the flag
    that catches a truncated write, and an operator reading the two names would
    guess the other way round.

    Nor that anonymous cleartext FTP is itself wrong — §2 of the operator doc
    offers exactly that, deliberately.  #111 is that arming GSI does not take it
    away, on the very config the doc presents as the secured one.

HOW THE PLANES WORK
    All three directives are NGX_STREAM_SRV_CONF, so a plane is a `listen` and
    not a location, and the config (configs/nginx_audit16ae_gridftp_gates.conf)
    stands eight of them in one process over one shared export.  Five write
    planes — both tokens written, neither written, both armed, and the two
    crosses — and three GSI planes that all carry the SAME certificate, key and
    CA so that the flag is measured apart from its material.  That last part is
    the point of G_OFF: without the PKI directives beside it, `gsi off` and "no
    GSI configured" are the same server, because ftp_module_merge.c:142 only
    demands a certificate when `enable && gsi`.
"""

import ftplib
import os
import socket
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN, PKI_DIR, SERVER_HOST

def _phase_dialogue_1(commands, fh, out):
    for cmd in commands:
        fh.write((cmd + "\r\n").encode())
        fh.flush()
        out.append(_read_reply(fh))


NAME = "lc-audit16ae-ftpgates"
_L = LIFECYCLE_SHARED_PORTS[NAME]

# The five write planes.  W_OFF and W_ABS are the pair the file was opened for:
# the written disarming tokens against their omission.
W_OFF = _L["port"]
W_ABS = _L["extra"]["ABS_PORT"]
W_ON = _L["extra"]["ON_PORT"]
W_VONLY = _L["extra"]["VONLY_PORT"]
W_AONLY = _L["extra"]["AONLY_PORT"]

# The three GSI planes, identical but for the flag.
G_OFF = _L["extra"]["GOFF_PORT"]
G_ABS = _L["extra"]["GABS_PORT"]
G_ON = _L["extra"]["GON_PORT"]

# The pair every §A/§B cell is a comparison of, and the name each is known by in
# a parametrize id.
DISARMED = (("off", W_OFF), ("absent", W_ABS))
ALL_WRITE = (("off", W_OFF), ("absent", W_ABS), ("both-on", W_ON),
             ("verify-only", W_VONLY), ("allo-only", W_AONLY))
GSI_DISARMED = (("off", G_OFF), ("absent", G_ABS))
ALL_GSI = (("off", G_OFF), ("absent", G_ABS), ("on", G_ON))

SERVER_CERT = os.path.join(PKI_DIR, "server", "hostcert.pem")
SERVER_KEY = os.path.join(PKI_DIR, "server", "hostkey.pem")
CA_DIR = os.path.join(PKI_DIR, "ca")

TIMEOUT = 30

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

class _Gates:
    """Eight gateways, one export, addressed by port."""

    def __init__(self, instance, root):
        self.instance = instance
        self.root = Path(root)

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        log = Path(self.instance.prefix) / "logs" / "error.log"
        return log.read_text(errors="replace") if log.exists() else ""

    def disk(self, name):
        """The on-disk path a STOR lands on.  One export under all eight planes,
        so this is also how a cell proves a write went to the plane it was
        addressed to and not to a neighbour."""
        return self.root / name

    def size(self, name):
        p = self.disk(name)
        return p.stat().st_size if p.exists() else None


@pytest.fixture(scope="module")
def gates(tmp_path_factory):
    """MODULE-scoped with its own harness, for the reason files 27-30 give: the
    ports are fixed by the ledger, so a per-test start/stop races the OS
    releasing them.  Every cell owns its own file name, so the shared export
    never collides."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    for p in (SERVER_CERT, SERVER_KEY, CA_DIR):
        if not os.path.exists(p):
            pytest.skip(f"test PKI incomplete: missing {p}")

    root = tmp_path_factory.mktemp("audit16ae") / "export"
    root.mkdir()

    harness = LifecycleHarness()
    try:
        instance = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16ae_gridftp_gates.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(root),
            template_values={"BIND_HOST": BIND_HOST,
                             "SERVER_CERT": SERVER_CERT,
                             "SERVER_KEY": SERVER_KEY,
                             "CA_DIR": CA_DIR},
            reason="audit-16ae the three gridftp gates whose disarming arm no "
                   "config had written: brix_gridftp_verify_write, "
                   "_require_allo_size and _gsi, each against its omission."))
        yield _Gates(instance, root)
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# FTP helpers — the dialogue is a real client's, not ftplib's convenience API   #
# --------------------------------------------------------------------------- #

def _final_code(ftp):
    """The completion reply after a data transfer, as an int.

    ftplib raises on 4xx/5xx, and every cell here has a 550 case, so the code is
    what the helpers return rather than an exception the caller must re-derive.
    """
    try:
        return int(ftp.getresp()[:3])
    except (ftplib.error_temp, ftplib.error_perm) as exc:
        return int(str(exc)[:3])


def _connect(port):
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, port, timeout=TIMEOUT)
    ftp.login()
    ftp.sendcmd("TYPE I")
    return ftp


def _stor(port, name, payload, allo=None, rest=None):
    """ALLO (optionally), REST (optionally), then a stream-mode STOR closing the
    data channel after exactly len(payload) bytes.

    A raw PASV socket rather than ftplib.storbinary, for the reason
    test_gridftp_allo_truncation.py gives: the completion signal under test IS
    the close, so the close has to be the test's to make.  A payload shorter
    than `allo` is a mid-flight truncation; longer is an over-delivery.
    """
    ftp = _connect(port)
    try:
        if allo is not None:
            ftp.sendcmd(f"ALLO {allo}")
        if rest is not None:
            ftp.sendcmd(f"REST {rest}")
        host, dport = ftp.makepasv()
        data = socket.create_connection((host, dport), timeout=TIMEOUT)
        try:
            ftp.putcmd("STOR " + name)
            resp = ftp.getresp()
            assert resp.startswith("150"), f"expected 150 before data: {resp}"
            data.sendall(payload)
            data.shutdown(socket.SHUT_WR)
            return _final_code(ftp)
        finally:
            data.close()
    finally:
        ftp.close()


def _retr(port, name):
    """RETR to EOF.  Returns (completion code, bytes)."""
    ftp = _connect(port)
    try:
        host, dport = ftp.makepasv()
        data = socket.create_connection((host, dport), timeout=TIMEOUT)
        try:
            ftp.putcmd("RETR " + name)
            try:
                resp = ftp.getresp()
            except (ftplib.error_temp, ftplib.error_perm) as exc:
                return int(str(exc)[:3]), b""      # refused before any data
            if not resp.startswith("150"):
                return int(resp[:3]), b""
            buf = b""
            while True:
                chunk = data.recv(65536)
                if not chunk:
                    break
                buf += chunk
            return _final_code(ftp), buf
        finally:
            data.close()
    finally:
        ftp.close()


def _size(port, name):
    """`SIZE <name>` as a raw reply string, or the error reply if it is one."""
    ftp = _connect(port)
    try:
        try:
            return ftp.sendcmd("SIZE " + name)
        except ftplib.Error as exc:
            return str(exc)
    finally:
        ftp.close()


def _read_reply(stream):
    lines = []
    while True:
        line = stream.readline().decode(errors="replace").rstrip("\r\n")
        if not line:
            return lines
        lines.append(line)
        if len(line) >= 4 and line[3] == " " and line[:3].isdigit():
            return lines


def _login_dialogue(stream):
    for command in ("USER anonymous", "PASS x@example.org"):
        stream.write((command + "\r\n").encode())
        stream.flush()
        _read_reply(stream)


def _dialogue(port, commands, login=False):
    """Send `commands` on a raw control connection and collect each reply.

    Raw rather than ftplib because §F asks about AUTH/ADAT/PBSZ before any
    login, and about replies ftplib would raise on.  Returns a list of reply
    line-lists, one per command, banner excluded.
    """
    sock = socket.create_connection((SERVER_HOST, port), timeout=TIMEOUT)
    fh = sock.makefile("rwb")

    try:
        _read_reply(fh)
        if login:
            _login_dialogue(fh)
        out = []
        _phase_dialogue_1(commands, fh, out)
        return out
    finally:
        fh.close()
        sock.close()


def _reply(lines):
    """The completion line of a reply — the one carrying the code."""
    return lines[-1]


def _uid(request):
    """A file name unique to the calling test, so the module needs no cleanup
    and a rerun cannot read the previous run's bytes."""
    return request.node.name.replace("[", "_").replace("]", "").replace("/", "_")


# --------------------------------------------------------------------------- #
# A. brix_gridftp_require_allo_size — the written `off` against its omission    #
# --------------------------------------------------------------------------- #

# (label, declared ALLO, bytes actually delivered).  The four shapes an ALLO
# gate can be asked about; `noallo` is the one the header says is unaffected
# either way, and is here so the equality claims cover the un-gated path too.
ALLO_SHAPES = (("short", 4000, 2500),
               ("exact", 4000, 4000),
               ("over", 4000, 5000),
               ("noallo", None, 2500))


@pytest.mark.parametrize("shape,allo,sent", ALLO_SHAPES)
class TestTheWrittenAlloOffEqualsItsOmission:
    """`brix_gridftp_require_allo_size off` written out, against the same server
    with the line deleted.

    This is the claim test_gridftp_allo_truncation.py's `gw_lenient` fixture
    rests on and does not make: it calls its control arm "off" and renders
    nothing.  Four ALLO shapes × two planes, and every cell must agree on the
    completion code AND on the bytes that reached the disk — a plane that
    accepted the transfer but committed something different would pass a
    code-only comparison.
    """

    def test_the_two_disarmed_planes_answer_identically(self, gates, request,
                                                        shape, allo, sent):
        codes = {}
        sizes = {}
        for label, port in DISARMED:
            name = f"{_uid(request)}-{label}.bin"
            codes[label] = _stor(port, name, os.urandom(sent), allo=allo)
            sizes[label] = gates.size(name)
        assert codes["off"] == codes["absent"], codes
        assert sizes["off"] == sizes["absent"] == sent, sizes

    def test_a_disarmed_plane_accepts_every_shape(self, gates, request,
                                                  shape, allo, sent):
        """The positive half, stated separately so a regression that made BOTH
        disarmed planes refuse would fail here rather than silently satisfying
        the equality above."""
        for label, port in DISARMED:
            name = f"{_uid(request)}-{label}.bin"
            code = _stor(port, name, os.urandom(sent), allo=allo)
            assert code == 226, f"{label}/{shape}: {code}"


class TestTheArmedAlloGateStillFires:
    """The armed arm, in the same process, so the equality above is a statement
    about the flag and not about the build.

    Overlaps test_gridftp_allo_truncation.py deliberately: that file proves the
    guard exists, this one proves the two disarmed spellings are the same thing
    the guard is being compared against.
    """

    @pytest.mark.parametrize("port,plane", ((W_ON, "both-on"),
                                            (W_AONLY, "allo-only")))
    @pytest.mark.parametrize("shape,allo,sent", (("short", 4000, 2500),
                                                 ("over", 4000, 5000)))
    def test_a_mismatched_length_is_refused(self, gates, request, port, plane,
                                            shape, allo, sent):
        name = f"{_uid(request)}.bin"
        assert _stor(port, name, os.urandom(sent), allo=allo) == 550

    @pytest.mark.parametrize("port,plane", ((W_ON, "both-on"),
                                            (W_AONLY, "allo-only")))
    def test_an_exact_length_still_commits(self, gates, request, port, plane):
        """No false positive, and the cell that makes the two refusals above
        mean something."""
        payload = os.urandom(4000)
        name = f"{_uid(request)}.bin"
        assert _stor(port, name, payload, allo=4000) == 226
        assert gates.disk(name).read_bytes() == payload

    @pytest.mark.parametrize("port,plane", ((W_ON, "both-on"),
                                            (W_AONLY, "allo-only")))
    def test_a_stor_with_no_allo_is_unaffected(self, gates, request, port,
                                               plane):
        """ftp_gateway.h:63-64 — "A STOR with no preceding ALLO is unaffected
        either way".  The armed planes are the only place that sentence can be
        measured, and it is the sentence that keeps the flag from being a
        blanket refusal of clients that do not send ALLO."""
        payload = os.urandom(2500)
        name = f"{_uid(request)}.bin"
        assert _stor(port, name, payload) == 226
        assert gates.disk(name).read_bytes() == payload


# --------------------------------------------------------------------------- #
# B. brix_gridftp_verify_write — the written `off` against its omission         #
# --------------------------------------------------------------------------- #

class TestTheWrittenVerifyOffEqualsItsOmission:
    """The second never-written token, measured the same way.

    `verify_write` reads each STOR back through the driver and CRC-checks it
    (ftp_gateway.h:39-45), so on a clean transfer every arm must agree — the
    check passing is indistinguishable from the check not running, which is
    exactly why the interesting cells are §C and §D and not here.  What is here
    is the equality the corpus assumes.
    """

    @pytest.mark.parametrize("size", (0, 1, 1234, 200000))
    def test_a_clean_stor_round_trips_on_every_write_plane(self, gates, request,
                                                           size):
        """Including zero bytes, which is the shape a verifier is most likely to
        get wrong: an empty accumulator's CRC and an empty file's are both
        trivially equal, but the length comparison in brix_vfs_wverify_check is
        against a file that must exist at all."""
        payload = os.urandom(size)
        for label, port in ALL_WRITE:
            name = f"{_uid(request)}-{label}.bin"
            code = _stor(port, name, payload)
            assert code == 226, f"{label}: {code}"
            assert gates.disk(name).read_bytes() == payload, label

    def test_the_two_disarmed_planes_are_byte_identical(self, gates, request):
        payload = os.urandom(48000)
        stored = {}
        for label, port in DISARMED:
            name = f"{_uid(request)}-{label}.bin"
            assert _stor(port, name, payload) == 226
            stored[label] = gates.disk(name).read_bytes()
        assert stored["off"] == stored["absent"] == payload

    def test_an_overwrite_of_an_existing_object_agrees_across_the_arms(
            self, gates, request):
        """A STOR onto a name that already holds bytes: the verifier reopens the
        object it just wrote, so a stale-length or append-instead-of-truncate
        bug would show here and only here."""
        for label, port in ALL_WRITE:
            name = f"{_uid(request)}-{label}.bin"
            assert _stor(port, name, b"A" * 5000) == 226
            assert _stor(port, name, b"B" * 300) == 226
            assert gates.disk(name).read_bytes() == b"B" * 300, label


# --------------------------------------------------------------------------- #
# C. The composition — the flag named for verification is not the one that      #
#    catches a truncated write                                                  #
# --------------------------------------------------------------------------- #

class TestTheTwoGatesAnswerForDifferentFailures:
    """W_VONLY and W_AONLY differ from each other by exactly two lines, and are
    the two configurations an operator would reach for after reading the names.

    No defect number: ftp_gateway.h:39-45 says plainly that `verify_write` is a
    STORAGE-persistence check and not a wire check, so it declining to notice a
    short delivery is the documented behaviour.  It is recorded because the
    documentation that says so is a C header comment, and the two directive
    names alone point the other way.
    """

    def test_verify_only_accepts_a_truncated_upload(self, gates, request):
        """`verify_write on`, `require_allo_size off`: the client declared 4000
        bytes, delivered 2500, and got 226 with the short object committed
        under its final name.  The read-back verified what was written, which
        is not what was promised."""
        name = f"{_uid(request)}.bin"
        assert _stor(W_VONLY, name, os.urandom(2500), allo=4000) == 226
        assert gates.size(name) == 2500

    def test_allo_only_refuses_the_same_upload(self, gates, request):
        """The mirror image, two lines different: `verify_write off`,
        `require_allo_size on` → 550."""
        name = f"{_uid(request)}.bin"
        assert _stor(W_AONLY, name, os.urandom(2500), allo=4000) == 550

    def test_the_two_crosses_disagree_on_the_same_bytes(self, gates, request):
        """Both statements in one cell, on one payload, so the difference cannot
        be blamed on the data."""
        payload = os.urandom(2500)
        vonly = f"{_uid(request)}-vonly.bin"
        aonly = f"{_uid(request)}-aonly.bin"
        assert _stor(W_VONLY, vonly, payload, allo=4000) == 226
        assert _stor(W_AONLY, aonly, payload, allo=4000) == 550
        assert gates.disk(vonly).read_bytes() == payload

    def test_verify_only_matches_the_fully_disarmed_planes(self, gates,
                                                           request):
        """And the sharper form: on a truncated upload, the plane with the
        integrity check armed is indistinguishable from the plane with nothing
        armed at all."""
        codes = {}
        for label, port in (("verify-only", W_VONLY),) + DISARMED:
            name = f"{_uid(request)}-{label}.bin"
            codes[label] = _stor(port, name, os.urandom(2500), allo=4000)
        assert codes["verify-only"] == codes["off"] == codes["absent"] == 226, \
            codes


# --------------------------------------------------------------------------- #
# D. DEFECT CANDIDATE #112 — a client-chosen REST turns verify_write off        #
# --------------------------------------------------------------------------- #

class TestARestOffsetDisablesTheOperatorsVerification:
    """ftp_ev_xfer.c:374:

        *verify = (fc->conf->verify_write && *start == 0);

    `*start` is the REST offset the CLIENT sent.  The operator's directive is
    ANDed with a value under the peer's control, so `REST 1` before every STOR
    is a complete, silent opt-out of the integrity check on a server configured
    to require it.

    THE MEASUREMENT IS A POSITIVE, NOT AN ABSENCE.  A cell asserting "no verify
    happened" by asserting nothing went wrong would pass under any
    implementation.  This one is built so that a verifier which HAD run would
    have destroyed the evidence: brix_vfs_wverify_check compares the
    accumulator's total against `brix_vfs_file_size(rfh)` and returns NGX_ERROR
    on a mismatch, which unlinks the object and fails the transfer.  After
    `REST 10` and 20 delivered bytes the accumulator holds 20 while the file
    holds 100 — so the file still being there, still 100 bytes, still answering
    226, is proof the comparison never happened.
    """

    @pytest.mark.parametrize("label,port", ALL_WRITE)
    def test_a_rest_stor_is_accepted_and_leaves_the_object_intact(
            self, gates, request, label, port):
        name = f"{_uid(request)}.bin"
        assert _stor(port, name, b"X" * 100) == 226
        assert gates.size(name) == 100
        code = _stor(port, name, b"Y" * 20, rest=10)
        assert code == 226, f"{label}: {code}"
        assert gates.size(name) == 100, (
            f"{label}: the object changed size, so the write path is not the "
            f"one this cell reasons about")

    def test_the_verifying_plane_is_indistinguishable_from_the_disarmed_ones(
            self, gates, request):
        """The finding in one sentence: with `REST 10` in front of it, the plane
        with `verify_write on` behaves exactly like the plane with
        `verify_write off` and exactly like the plane that never wrote the
        line."""
        results = {}
        for label, port in ALL_WRITE:
            name = f"{_uid(request)}-{label}.bin"
            _stor(port, name, b"X" * 100)
            results[label] = (_stor(port, name, b"Y" * 20, rest=10),
                              gates.size(name))
        assert results["both-on"] == results["off"] == results["absent"] == \
            (226, 100), results

    @pytest.mark.parametrize("label,port", ALL_WRITE)
    def test_rest_zero_is_the_control_and_writes_from_the_start(
            self, gates, request, label, port):
        """`REST 0` satisfies `*start == 0`, so the verifier DOES run — and the
        write is an ordinary truncating STOR.  Without this control, "the file
        was unchanged" could be read as "REST always no-ops", which would make
        the cells above say nothing."""
        name = f"{_uid(request)}.bin"
        assert _stor(port, name, b"X" * 100) == 226
        assert _stor(port, name, b"Y" * 20, rest=0) == 226
        assert gates.size(name) == 20, label
        assert gates.disk(name).read_bytes() == b"Y" * 20

    @pytest.mark.parametrize("argument", ("-1", "abc", ""))
    def test_a_negative_or_unparseable_rest_is_refused(self, gates, argument):
        """The gate that keeps the offset a non-negative integer
        (ftp_ev_dispatch.c:168-171).  It holds for the cases it covers — the
        finding above is not that REST is unvalidated, it is that a VALID REST
        disables an unrelated control."""
        reply = _reply(_dialogue(W_ON, [f"REST {argument}".rstrip()],
                                 login=True)[0])
        assert reply.startswith("501"), (argument, reply)


class TestTheRestOffsetParserIsLax:
    """What the same three lines do NOT reject, measured because §D leans on
    them and because the shape is the one that hides an off-by-one.

        long long off = strtoll(arg, &endp, 10);
        if (arg[0] == '\0' || endp == arg || off < 0) ... 501

    `endp == arg` catches "no digits at all"; nothing catches "digits followed
    by something else", and nothing checks errno for ERANGE.  No defect number:
    RFC 959 does not say a server must refuse a trailing byte, every observed
    outcome is a refusal or a correct prefix, and the saturating case fails the
    transfer rather than committing anything.  It is recorded so that a future
    change to this parser is a change to a measured behaviour.
    """

    @pytest.mark.parametrize("argument,offset", (("9x", "9"),
                                                 ("10abc", "10"),
                                                 ("0x10", "0"),
                                                 ("+5", "5"),
                                                 ("-0", "0"),
                                                 ("-0.5", "0"),
                                                 (" 12", "12")))
    def test_a_trailing_or_signed_argument_is_accepted_as_its_prefix(
            self, gates, argument, offset):
        """`0x10` is the sharpest: a client that wrote a hex offset is told
        `350` and gets offset 0, which is a silent restart from the beginning
        rather than a refusal."""
        reply = _reply(_dialogue(W_ON, [f"REST {argument}"], login=True)[0])
        assert reply.startswith(f"350 Restart position accepted ({offset}"), \
            (argument, reply)

    def test_an_out_of_range_offset_saturates_rather_than_failing(self, gates):
        """strtoll clamps to LLONG_MAX and sets ERANGE; errno is not read, so
        the reply is a 350 for an offset the client never asked for."""
        reply = _reply(_dialogue(W_ON, ["REST 99999999999999999999999999"],
                                 login=True)[0])
        assert reply.startswith("350 Restart position accepted "
                                "(9223372036854775807"), reply

    def test_a_stor_at_the_saturated_offset_fails_but_leaves_an_empty_object(
            self, gates, request):
        """The one consequence worth stating: the transfer is refused 550, and
        the name is left holding a zero-byte file.  Same shape as §E — the
        refusal is on the control channel and the object is already gone."""
        name = f"{_uid(request)}.bin"
        assert _stor(W_ON, name, b"Z" * 10,
                     rest="99999999999999999999999999") == 550
        assert gates.size(name) == 0, gates.size(name)


# --------------------------------------------------------------------------- #
# E. DEFECT CANDIDATE #113 — the refused object is left readable                #
# --------------------------------------------------------------------------- #

class TestARefusedUploadStaysOnDiskAndServes:
    """A 550 from the ALLO gate is a refusal on the control channel only.

    The object keeps its final name, its bytes, and its readability: SIZE
    reports it, RETR serves it, and nothing about it says "partial".  The doc
    comment says the prefix is left in place deliberately, for a REST-resume,
    and that is a defensible choice — but a resume story needs a way to tell a
    resumable prefix from a complete file, and there is none.  The over-long
    case is worse than the short one: the object left behind is LONGER than the
    ALLO the refusal was based on.
    """

    @pytest.mark.parametrize("shape,allo,sent", (("short", 4000, 2500),
                                                 ("over", 4000, 5000)))
    def test_the_refused_bytes_are_still_on_disk(self, gates, request, shape,
                                                 allo, sent):
        name = f"{_uid(request)}.bin"
        assert _stor(W_ON, name, os.urandom(sent), allo=allo) == 550
        assert gates.size(name) == sent, (
            f"{shape}: refused {sent} bytes, disk holds {gates.size(name)}")

    @pytest.mark.parametrize("shape,allo,sent", (("short", 4000, 2500),
                                                 ("over", 4000, 5000)))
    def test_size_reports_the_refused_object_as_an_ordinary_file(
            self, gates, request, shape, allo, sent):
        """`SIZE` is the command a client uses to decide whether it already has
        the file.  It answers 213 with the partial length — the same reply
        shape a complete file of that length would draw."""
        name = f"{_uid(request)}.bin"
        assert _stor(W_ON, name, os.urandom(sent), allo=allo) == 550
        assert _size(W_ON, name) == f"213 {sent}", _size(W_ON, name)

    @pytest.mark.parametrize("shape,allo,sent", (("short", 4000, 2500),
                                                 ("over", 4000, 5000)))
    def test_retr_serves_the_refused_object_in_full(self, gates, request,
                                                    shape, allo, sent):
        """And the consequence: the next client to GET the name is served the
        rejected bytes with a 226, with no way to know the upload that produced
        them was refused."""
        payload = os.urandom(sent)
        name = f"{_uid(request)}.bin"
        assert _stor(W_ON, name, payload, allo=allo) == 550
        code, body = _retr(W_ON, name)
        assert code == 226, code
        assert body == payload

    def test_the_refusal_does_not_disturb_a_previous_complete_object(
            self, gates, request):
        """The other half of the same fact, and the one that decides how bad it
        is: a refused STOR overwrites what was there.  A client that re-uploads
        a file it already has, and is truncated mid-flight, ends with the
        partial — the 550 does not restore the previous contents."""
        name = f"{_uid(request)}.bin"
        assert _stor(W_ON, name, b"C" * 4000, allo=4000) == 226
        assert _stor(W_ON, name, b"D" * 2500, allo=4000) == 550
        assert gates.disk(name).read_bytes() == b"D" * 2500

    def test_a_disarmed_plane_leaves_the_same_bytes_with_a_226(self, gates,
                                                               request):
        """The comparison that says what the flag actually buys: on the
        disarmed planes the identical truncation leaves the identical file and
        answers 226 instead of 550.  The whole difference the operator paid for
        is the reply code — the disk is the same either way."""
        payload = os.urandom(2500)
        armed = f"{_uid(request)}-armed.bin"
        assert _stor(W_ON, armed, payload, allo=4000) == 550
        for label, port in DISARMED:
            name = f"{_uid(request)}-{label}.bin"
            assert _stor(port, name, payload, allo=4000) == 226
            assert gates.disk(name).read_bytes() == \
                gates.disk(armed).read_bytes(), label


# --------------------------------------------------------------------------- #
# F. brix_gridftp_gsi — the written `off`, and DEFECT CANDIDATE #111            #
# --------------------------------------------------------------------------- #

class TestTheWrittenGsiOffEqualsItsOmission:
    """G_OFF carries `brix_gridftp_gsi off` BESIDE a certificate, key and CA;
    G_ABS carries the same three PKI directives and no flag.

    The material is what makes this a measurement of the flag rather than of
    the deployment: ftp_module_merge.c:142 only builds a GSI context when
    `enable && gsi`, so without the certificate present on both planes, `off`
    and "no GSI configured" would be the same server and the equality would be
    trivially true for the wrong reason.
    """

    @pytest.mark.parametrize("command", ("FEAT", "AUTH GSSAPI", "AUTH TLS",
                                         "AUTH XYZ", "PBSZ 0", "PROT C",
                                         "PROT P", "ADAT AAAA"))
    def test_the_two_disarmed_planes_answer_identically(self, gates, command):
        off = _dialogue(G_OFF, [command])[0]
        absent = _dialogue(G_ABS, [command])[0]
        assert off == absent, (command, off, absent)

    def test_the_disarmed_planes_advertise_no_security_extensions(self, gates):
        """FEAT is the only place the flag is visible to a client that has not
        tried to authenticate, so it is the one that decides whether a peer can
        discover the arm before committing to it."""
        for label, port in GSI_DISARMED:
            feat = _dialogue(port, ["FEAT"])[0]
            text = " ".join(feat)
            assert "AUTH GSSAPI" not in text, (label, feat)
            assert " DCAU" not in text, (label, feat)
            assert "SIZE" in text and "REST STREAM" in text, (label, feat)

    @pytest.mark.parametrize("mechanism", ("GSSAPI", "TLS", "XYZ"))
    def test_every_auth_mechanism_is_refused_on_a_disarmed_plane(self, gates,
                                                                 mechanism):
        """534 for all three, including the one the server would understand if
        the flag were on — a disarmed plane does not distinguish "unknown
        mechanism" from "mechanism not offered", which is the right answer."""
        for label, port in GSI_DISARMED:
            reply = _reply(_dialogue(port, [f"AUTH {mechanism}"])[0])
            assert reply.startswith("534"), (label, mechanism, reply)

    def test_adat_before_auth_is_refused_on_every_plane(self, gates):
        """The state machine's floor, and the same on all three arms: ADAT is
        meaningless without an accepted AUTH, and the armed plane does not
        relax it."""
        for label, port in ALL_GSI:
            reply = _reply(_dialogue(port, ["ADAT AAAA"])[0])
            assert reply.startswith("503"), (label, reply)


class TestTheArmedGsiPlaneDiffersExactlyThere:
    """The other side of the equality: G_ON is G_OFF plus one line, and these
    are all the observable consequences of it before a login."""

    def test_feat_advertises_the_security_extensions(self, gates):
        feat = " ".join(_dialogue(G_ON, ["FEAT"])[0])
        for token in ("AUTH GSSAPI", "PBSZ", "PROT", "DCAU"):
            assert token in feat, (token, feat)

    def test_auth_gssapi_is_accepted(self, gates):
        assert _reply(_dialogue(G_ON, ["AUTH GSSAPI"])[0]).startswith("334")

    def test_an_unknown_mechanism_is_504_rather_than_534(self, gates):
        """The armed plane HAS a mechanism list, so it answers "unknown
        mechanism"; the disarmed planes have none and answer "not available".
        The two codes are how a client tells the arms apart, and `AUTH TLS` is
        the sharpest case — a real mechanism name, refused for two different
        reasons by two servers that differ by one line."""
        for mechanism in ("TLS", "XYZ"):
            armed = _reply(_dialogue(G_ON, [f"AUTH {mechanism}"])[0])
            disarmed = _reply(_dialogue(G_OFF, [f"AUTH {mechanism}"])[0])
            assert armed.startswith("504"), (mechanism, armed)
            assert disarmed.startswith("534"), (mechanism, disarmed)

    def test_a_garbage_adat_token_never_authenticates(self, gates):
        """The security negative of the arm: a well-formed base64 blob that is
        not a GSSAPI token draws a 335 continuation and then 535, and the
        session is no more logged in than before — PWD and PASV still answer
        530."""
        replies = _dialogue(G_ON, ["AUTH GSSAPI", "ADAT AAAA", "ADAT AAAA",
                                   "PWD", "PASV"])
        assert _reply(replies[0]).startswith("334"), replies[0]
        assert _reply(replies[2]).startswith("535"), replies[2]
        assert _reply(replies[3]).startswith("530"), replies[3]
        assert _reply(replies[4]).startswith("530"), replies[4]

    def test_a_malformed_adat_token_is_rejected_as_malformed(self, gates):
        """Not base64 at all → 501 rather than 535: the decoder refuses before
        the mechanism sees anything, which is the boundary that keeps arbitrary
        client bytes out of the GSSAPI accept path."""
        replies = _dialogue(G_ON, ["AUTH GSSAPI", "ADAT !!!not-base64!!!"])
        assert _reply(replies[1]).startswith("501"), replies[1]

    def test_pbsz_answers_200_on_a_plane_that_refuses_every_auth(self, gates):
        """Worth stating on its own.  `PBSZ 0` is answered `200 PBSZ=0` by all
        three planes — including the two that have just refused every AUTH with
        534.  A client probing PBSZ to decide whether the server speaks RFC 2228
        is told yes by a server that does not."""
        for label, port in ALL_GSI:
            assert _reply(_dialogue(port, ["PBSZ 0"])[0]).startswith("200"), \
                label

    def test_prot_p_is_refused_on_every_plane_including_the_armed_one(self,
                                                                      gates):
        """PROT P needs a security context, and none of these three sessions has
        one — the armed plane offers GSSAPI but this cell never completes it.
        All three answer 536, which is the arm-independent half of the data
        channel surface."""
        for label, port in ALL_GSI:
            assert _reply(_dialogue(port, ["PROT P"])[0]).startswith("536"), \
                label
            assert _reply(_dialogue(port, ["PROT C"])[0]).startswith("200"), \
                label


class TestArmingGsiDoesNotRequireIt:
    """DEFECT CANDIDATE #111.

    G_ON is the operator doc's §3 config: `brix_gridftp_gsi on` with a host
    certificate, key and CA, presented as "the production form: an RFC 2228 GSI
    control channel authenticated by an X.509 (proxy) certificate".  Every cell
    below runs against that plane with no certificate, no proxy, and no AUTH at
    all.

    ev_grp_login (ftp_ev_dispatch.c:226-233) sets `fc->authed = 1` on any PASS
    and does not look at `fc->conf->gsi`.  Nothing in the gridftp command table
    requires the security layer, and `brix_gridftp_require_vo` — the only
    directive that could — is a per-PATH ACL evaluated after resolution
    (ftp_ev_path.c:117-125) which is allow-all when no rule covers the path.
    """

    def test_an_anonymous_cleartext_login_succeeds_on_the_armed_plane(self,
                                                                      gates):
        replies = _dialogue(G_ON, ["USER anonymous", "PASS x@example.org",
                                   "PWD"])
        assert _reply(replies[0]).startswith("331"), replies[0]
        assert _reply(replies[1]).startswith("230"), replies[1]
        assert _reply(replies[2]).startswith("257"), replies[2]

    def test_any_password_at_all_is_accepted(self, gates):
        """PASS is not checked against anything — the point is not that
        anonymous is allowed but that the branch which sets `authed` has no
        condition on it."""
        for password in ("", "wrong", "../../etc/shadow", "x" * 200):
            replies = _dialogue(G_ON, ["USER someone", f"PASS {password}"])
            assert _reply(replies[1]).startswith("230"), (password, replies)

    def test_the_cleartext_session_can_write_through_the_armed_plane(self,
                                                                     gates,
                                                                     request):
        """The consequence, and the reason this is a security finding and not a
        curiosity: the unauthenticated session gets the export's full
        read-write surface."""
        payload = os.urandom(777)
        name = f"{_uid(request)}.bin"
        assert _stor(G_ON, name, payload) == 226
        assert gates.disk(name).read_bytes() == payload
        code, body = _retr(G_ON, name)
        assert code == 226 and body == payload

    def test_the_armed_plane_is_indistinguishable_from_the_disarmed_ones_here(
            self, gates, request):
        """The equality that makes the size of the finding legible: for a client
        that simply never sends AUTH, all three GSI planes are the same server.
        Arming GSI adds a mechanism; it removes nothing."""
        payload = os.urandom(512)
        for label, port in ALL_GSI:
            name = f"{_uid(request)}-{label}.bin"
            assert _stor(port, name, payload) == 226, label
            assert gates.disk(name).read_bytes() == payload, label

    def test_the_path_confinement_still_holds_for_the_cleartext_session(
            self, gates):
        """What DOES still gate the anonymous session, stated so the finding is
        bounded: invariant 4's resolve_path is upstream of authentication, so an
        escape above the export is refused whether or not anyone logged in
        meaningfully."""
        for escape in ("../../../../etc/passwd", "/etc/passwd",
                       "..%2f..%2f..%2fetc%2fpasswd", "....//etc/passwd"):
            code, body = _retr(G_ON, escape)
            assert code in (550, 553), (escape, code)
            assert b"root:x:" not in body, escape


# --------------------------------------------------------------------------- #
# G. Parse tier                                                                #
# --------------------------------------------------------------------------- #

FLAGS = ("brix_gridftp_verify_write",
         "brix_gridftp_require_allo_size",
         "brix_gridftp_gsi")


def _parse(tmp_path, **slots):
    """`nginx -t` on the shared parse scaffold.

    configs/nginx_audit16jparse.conf is reused rather than copied, for the
    reason files 29 and 30 give: it writes none of the three flags itself, so a
    duplicate negative can be sure the duplicate it is shown is the one it
    wrote.
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
    """Only the lines nginx itself flagged: a tmp_path name can contain the
    token under test, so a substring search over the whole output would match
    the temp directory rather than a diagnostic."""
    return [ln for ln in out.splitlines()
            if any(tag in ln for tag in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


class TestBothArmsOfAllThreeFlagsParse:
    """The parse half of the same claim, in the scope the directives declare."""

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_is_accepted_in_a_stream_server(self, tmp_path, flag, arm):
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_draws_no_diagnostic(self, tmp_path, flag, arm):
        """Accepted is not enough — the claim in §A/§B is that a written `off`
        is a normal thing to write, and a NOTICE saying the line is redundant
        would be a different (and better) world."""
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {arm};\n")
        assert rc == 0 and _diagnostics(out) == [], _diagnostics(out)

    @pytest.mark.parametrize("flag", FLAGS)
    def test_all_three_disarming_tokens_together_are_accepted(self, tmp_path,
                                                              flag):
        """The W_OFF plane's shape, at parse time: nothing cross-validates the
        three against each other or against `brix_gridftp` being off."""
        rc, out = _parse(tmp_path, KNOBS="".join(
            f"        {f} off;\n" for f in FLAGS))
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)


class TestTheFlagsRefuseWhatIsNotAFlag:
    """Arity and value, per flag.  `ngx_conf_set_flag_slot` produces both
    messages, and the negatives are what neither existing gridftp file has —
    both only ever render well-formed arms."""

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("value", ("yes", "no", "1", "0", "ON", "OFF",
                                       "true", '""'))
    def test_a_non_flag_value_is_refused_and_named(self, tmp_path, flag, value):
        """`ON`/`OFF` are in the list because ngx_conf_set_flag_slot's match is
        case-INSENSITIVE, unlike the parameter tokens file 30 found in the
        open-file-cache setter — the same codebase does both, and only a test
        that writes them says which is which."""
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {value};\n")
        if value in ("ON", "OFF"):
            assert rc == 0, out
            return
        assert rc != 0, out
        assert any(f'invalid value "{value.strip(chr(34))}" in "{flag}"' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("args", ("", "on off", "on on on"))
    def test_a_wrong_argument_count_is_refused(self, tmp_path, flag, args):
        line = f"        {flag}{' ' + args if args else ''};\n"
        rc, out = _parse(tmp_path, KNOBS=line)
        assert rc != 0, out
        assert any(f'invalid number of arguments in "{flag}"' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_same_flag_twice_in_one_server_is_a_duplicate(self, tmp_path,
                                                              flag):
        rc, out = _parse(tmp_path,
                         KNOBS=f"        {flag} on;\n        {flag} off;\n")
        assert rc != 0, out
        assert any(f'"{flag}" directive is duplicate' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)


class TestTheFlagsAreStreamServerOnly:
    """All three are declared NGX_STREAM_SRV_CONF and nothing else
    (ftp_module.c:258,279,286), so every other placement must be refused —
    including `stream{}` itself, where a reader might expect a site-wide
    default to be writable.  brix_ftp_merge_conf implements parent inheritance
    for all three (ftp_module_merge.c:160,161,164); this class is what says
    that inheritance arm is unreachable rather than untested.
    """

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("slot", ("STREAM_KNOBS", "HTTP_KNOBS",
                                      "LOC_KNOBS", "OUTER"))
    def test_the_flag_is_refused_outside_a_stream_server(self, tmp_path, flag,
                                                         slot):
        rc, out = _parse(tmp_path, **{slot: f"    {flag} on;\n"})
        assert rc != 0, out
        assert any(f'"{flag}" directive is not allowed here' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_sibling_server_may_write_its_own_arm(self, tmp_path, flag):
        """Scope: the arms are per-block, so two servers in one stream{} may
        disagree — which is what the eight-plane instance above depends on."""
        extra = ("    server {\n"
                 f"        listen {PARSE_PLACEHOLDER_PORT + 2};\n"
                 "        brix_root on;\n"
                 "        brix_auth none;\n"
                 f"        {flag} off;\n"
                 "    }\n")
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} on;\n", EXTRA=extra)
        assert rc == 0, out


class TestTheGsiFlagIsTheOnlyOneWithAPrerequisite:
    """`brix_gridftp_gsi on` demands a certificate, key and CA
    (ftp_module_gsi.c:47-54) — and only when the gateway is enabled, because
    brix_ftp_merge_tls (ftp_module_merge.c:142) guards the build with
    `enable && gsi`.  Both halves matter: the second is why G_ABS can carry PKI
    material with no flag, and why a stray `brix_gridftp_gsi on` in a block that
    is not a gateway is silently harmless.
    """

    def _gateway(self, tmp_path, extra):
        data = tmp_path / "ftp-export"
        data.mkdir(exist_ok=True)
        return ("        brix_gridftp        on;\n"
                f"        brix_gridftp_export {data};\n" + extra)

    def test_gsi_on_without_a_certificate_is_refused(self, tmp_path):
        rc, out = _parse(tmp_path, KNOBS=self._gateway(
            tmp_path, "        brix_gridftp_gsi on;\n"))
        assert rc != 0, out
        assert any("brix_gridftp_gsi requires brix_gridftp_certificate" in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("arm", ("        brix_gridftp_gsi off;\n", ""))
    def test_the_disarmed_gateway_needs_no_certificate(self, tmp_path, arm):
        """The written `off` and its omission agree at parse time too — and
        this is the cell that shows the prerequisite is attached to the flag
        rather than to the gateway."""
        rc, out = _parse(tmp_path, KNOBS=self._gateway(tmp_path, arm))
        assert rc == 0, out

    def test_gsi_on_in_a_block_that_is_not_a_gateway_is_accepted(self,
                                                                 tmp_path):
        """`brix_gridftp` off (the default), so `enable && gsi` is false and the
        context is never built — the flag is inert rather than refused.  Worth
        a cell because it is the one way to write `brix_gridftp_gsi on` and get
        no GSI and no complaint."""
        rc, out = _parse(tmp_path, KNOBS="        brix_gridftp_gsi on;\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)

    def test_a_partial_certificate_set_is_refused(self, tmp_path):
        """One of the three is not enough, and the message names all three —
        an operator who set the certificate and forgot the CA gets told what is
        missing rather than a TLS failure at runtime."""
        rc, out = _parse(tmp_path, KNOBS=self._gateway(
            tmp_path,
            "        brix_gridftp_gsi on;\n"
            f"        brix_gridftp_certificate {SERVER_CERT};\n"))
        assert rc != 0, out
        assert any("brix_gridftp_trusted_ca" in ln
                   for ln in _diagnostics(out)), _diagnostics(out)


# --------------------------------------------------------------------------- #
# H. The instance said nothing about any of it                                 #
# --------------------------------------------------------------------------- #

class TestNothingIsLoggedAboutTheDisarmedGates:
    """Eight gateways, five of them writing a disarming token, and the startup
    log names none of the three directives.

    An operator who wrote `brix_gridftp_verify_write off` on a plane that also
    accepts REST (§D), or `brix_gridftp_gsi on` on a plane that still takes
    anonymous logins (§F), gets no line saying so.  That silence is what makes
    #111 and #112 findings rather than documented trade-offs.
    """

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_startup_log_never_names_the_flag(self, gates, flag):
        offenders = [ln for ln in gates.errlog().splitlines() if flag in ln]
        assert offenders == [], offenders

    def test_the_armed_gsi_plane_logs_no_warning_about_cleartext_logins(
            self, gates):
        """The specific silence behind #111: nothing anywhere says the GSI
        gateway also accepts USER/PASS."""
        log = gates.errlog().lower()
        for token in ("cleartext login", "unauthenticated", "gsi not required"):
            assert token not in log, token

    def test_the_instance_started_clean(self, gates):
        """Eight gateways is a configuration a real deployment could hold, and
        "the disarming arms are accepted" means accepted without complaint.

        Request-scoped lines are excluded by their `client:` field rather than
        by a whitelist of texts — §E and §F deliberately ask for refusals, and
        an [error] per refused transfer is the server working.
        """
        bad = [ln for ln in gates.errlog().splitlines()
               if any(tag in ln for tag in ("[emerg]", "[alert]", "[error]"))
               and "client:" not in ln]
        assert bad == [], bad


# --------------------------------------------------------------------------- #
# I. DEFECT CANDIDATE #114 — %ll handed to nginx's own formatter                #
# --------------------------------------------------------------------------- #

class TestTheRestReplyIsMalformed:
    """`brix_ftp_ev_reply` formats through ngx_vslprintf (ftp_ev_reply.c:107),
    which implements `%L` and `%O` and has no `%lld`.  ftp_ev_dispatch.c:173
    writes

        "350 Restart position accepted (%lld)\\r\\n"

    so the value comes out right on LP64 — `%l` consumes the argument as a long
    — and the trailing `ld` is emitted as literal text.  This is the one of the
    four sites that reaches a client.

    The other three are log lines and are named here rather than measured,
    because a WARN nobody can provoke on demand is not a cell:
      * protocols/root/session/signing.c:43   `%llu` × 2, sigver replay WARN
      * protocols/root/query/set.c:78         `%llu` × 3, cms.space INFO
      * fs/cache/directives.c:231             `%llu`, config-time NOTICE

    The hazard is latent rather than live: on an ILP32 or LLP64 target `%l`
    would consume the wrong width and the values would be wrong too.
    """

    @pytest.mark.parametrize("offset", ("0", "10", "4294967296"))
    def test_the_reply_carries_a_literal_ld(self, gates, offset):
        reply = _reply(_dialogue(W_ON, [f"REST {offset}"], login=True)[0])
        assert reply == f"350 Restart position accepted ({offset}ld)", reply

    @pytest.mark.parametrize("label,port", ALL_WRITE + ALL_GSI)
    def test_every_plane_emits_the_same_malformed_reply(self, gates, label,
                                                        port):
        """It is the formatter and not the configuration: all eight gateways
        answer identically, so no arm of any of the three flags is involved."""
        reply = _reply(_dialogue(port, ["REST 10"], login=True)[0])
        assert reply == "350 Restart position accepted (10ld)", (label, reply)

    def test_the_value_itself_is_correct(self, gates):
        """The half that keeps this a formatting defect rather than a
        correctness one: the offset is echoed exactly, so a client that parses
        the number and ignores the tail is unharmed — which is why it has
        survived."""
        for offset in ("0", "1", "10", "4294967296", "9223372036854775807"):
            reply = _reply(_dialogue(W_ON, [f"REST {offset}"], login=True)[0])
            assert reply.startswith(f"350 Restart position accepted ({offset}"), \
                reply
