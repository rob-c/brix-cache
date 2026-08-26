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

