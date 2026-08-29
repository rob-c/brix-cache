"""tests/test_audit16ai_gridftp_write_gate.py — audit tranche 16, file 35.

WHY THIS FILE EXISTS
    `brix_allow_write` is the fourth GridFTP gate and the one file 31
    (test_audit16ae_gridftp_gate_off_arms.py) left behind.  It is written `on` by
    THIRTY-ONE configs in this tree.  The token `off` is written by NONE of them.

    The two places in the corpus that mean to be a read-only export are both
    absences, and one of them says otherwise:

        configs/nginx_gridftp_plain_ev_ro.conf  deletes the line, and its header
                                                says it deletes the line
        configs/nginx_gridftp_metrics.conf      its header says the RO_PORT
                                                gateway writes
                                                `brix_allow_write off`
                                                — the server block below writes
                                                no such line

    So the disarming arm has never been written, and the only live probe of a
    disabled gate anywhere in the suite is a single STOR
    (test_gridftp_metrics.py::test_read_only_export_refuses_stor_as_forbidden).
    One verb, on one of the seven the gate governs, on the plane whose
    read-onliness is an omission.

    §A writes the missing token and compares it, verb by verb, against the
    omission it has always stood in for.  The equality holds — the merge default
    is 0 at ftp_module_merge.c:159 — and, as in files 31-34, what writing the
    arm turned out to be worth is everything after it.

THE GATE'S SHAPE
    Seven verbs, four call sites, and they do not behave alike:

        ev_xfer_guards          ftp_ev_xfer.c:333   STOR, APPE
        ftp_ev_ns_mutate        ftp_ev_cmd.c:177    MKD/XMKD, DELE, RMD/XRMD
        brix_ftp_ev_cmd_rnfr    ftp_ev_cmd.c:406    RNFR
        brix_ftp_ev_cmd_rnto    ftp_ev_cmd.c:431    RNTO

    Only the first meters anything.  Its own comment says why it meters what it
    meters — "Only the permission verdict is metered: it is an authorization
    outcome for the requested op" — and the other three call sites, which are
    also permission verdicts for a requested op, meter nothing.

THE FINDINGS
    DEFECT CANDIDATE #133 — the tree's one config that claims to write
    `brix_allow_write off` does not write it.
    configs/nginx_gridftp_metrics.conf:11 documents its RO_PORT gateway as
    "brix_allow_write off, the security-negative path"; the block at
    :48-52 carries `brix_gridftp` and `brix_export` and nothing else.
    The gateway is read-only anyway — by merge, not by the line — so the test
    that rests on it passes, which is exactly why the mismatch survived.  §K
    reads both files and states it as a measurement rather than a claim about a
    comment.

    DEFECT CANDIDATE #134 — five of the seven gated verbs refuse in total
    silence.  A client that issues MKD, XMKD, DELE, RMD, XRMD, RNFR and RNTO
    against a read-only export gets seven refusals, and afterwards:

        * no `brix_io_ops_total` row moved at all — not `forbidden`, not
          anything.  The only counter that moved in the whole scrape was
          `brix_auth_total{proto="gridftp",method="none",status="ok"}`, from the
          login;
        * the error log gained three lines, and all three are session lifecycle
          (connect, session start, session end).  Not one names a refusal, at
          any level, with `error_log ... info` — the most verbose setting an
          operator can practically run.

    A refused STOR books `brix_io_ops_total{proto="gridftp",op="write",
    status="forbidden"}`, so the plane is not that the gateway cannot meter
    refusals; it is that six of the seven do not.  §D and §E measure it.

    DEFECT CANDIDATE #135 — RNTO's own permission check is unreachable.
    brix_ftp_ev_cmd_rnto tests `fc->rnfr_set` first and CONSUMES it ("single-shot
    pairing", :430) before it tests `allow_write` at :431.  `rnfr_set` is set in
    exactly one place — the tail of brix_ftp_ev_cmd_rnfr — which is itself behind
    the same gate.  On a read-only export `rnfr_set` is therefore always 0, RNTO
    always answers `503 RNFR required first`, and the `550 Permission denied
    (read-only)` two lines below it can never be emitted.  §F measures the
    reachability, not the reading.

    DEFECT CANDIDATE #136 — `SITE` answers `200 OK` to every subcommand,
    including ones the gateway does not implement and would refuse if it did.
    ev_grp_session (ftp_ev_dispatch.c:259) is a bare `return brix_ftp_ev_reply(fc,
    "200 OK\\r\\n")` with the argument unread, so `SITE CHMOD 000 /seed.txt` on a
    READ-ONLY export is answered `200 OK` and the file's mode is unchanged.  The
    gate is not bypassed — nothing happened — but a client is told a mutation
    succeeded on an export that refuses mutations.  §H measures both halves: the
    reply, and the unchanged mode on disk.

    DEFECT CANDIDATE #137 — `brix_verify_write on` beside
    `brix_allow_write off` parses clean and draws no diagnostic.  It is
    the inert-companion shape #101 and #102 found on other planes: an integrity
    knob armed on a server that can never write, which is a configuration that
    can only be a mistake and which nothing in the merge cross-validates.  §I
    measures it on the wire and §L at parse time.

WHAT THIS FILE DOES NOT CLAIM
    Not that the gate leaks.  It does not: across four faces and every verb
    behind it, nothing on a disabled face reached the disk — no directory
    created, no file deleted, no rename, no mode change, no byte written.  §A
    and §B are as much a proof of that as they are of the equality.

    Not that `503 RNFR required first` is the wrong reply to a bare RNTO — it is
    the right one.  #135 is that the reply BELOW it is dead, and a reader of
    brix_ftp_ev_cmd_rnto would reasonably believe a read-only export answers 550
    to a paired RNTO.

    Not that a refusal must be logged at `[error]`.  #134 is that it is logged at
    NO level: the file's measurement is against `info`, which is what
    configs/nginx_audit16ai_gridftp_write_gate.conf sets.

HOW THE PLANES WORK
    The directive is NGX_STREAM_SRV_CONF|NGX_CONF_FLAG (ftp_module.c:222), so a
    plane is a `listen` and not a location, and
    configs/nginx_audit16ai_gridftp_write_gate.conf stands four of them plus one
    HTTP /metrics face in one process:

        G_ON   `allow_write on`     the control — every gated verb must succeed
        G_OFF  `allow_write off`    the never-written token
        G_ABS  the line deleted     what nginx_gridftp_plain_ev_ro.conf renders
        G_VER  `off` + `verify_write on`   the inert companion, §I

    Each has its OWN export subtree.  The gate is the only thing between a
    client and the tree, so a shared root would make one face's refused mutation
    indistinguishable from another face's successful one — and the whole file is
    about which face let what through.

    The metrics zone is process-wide, so the HTTP face reads the counters all
    four gateways feed; that is the only way to see #134's asymmetry inside one
    scrape.
"""

import ftplib
import os
import re
import socket
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from metrics_helpers import value as metric_value
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN, SERVER_HOST

NAME = "lc-audit16ai-ftpwrite"
_L = LIFECYCLE_SHARED_PORTS[NAME]

G_ON = _L["port"]
G_OFF = _L["extra"]["OFF_PORT"]
G_ABS = _L["extra"]["ABS_PORT"]
G_VER = _L["extra"]["VER_PORT"]
HTTP_PORT = _L["extra"]["HTTP_PORT"]

# The export subtree each face is rooted at, by the name the face is known by.
SUBTREE = {"on": "on", "off": "off", "absent": "abs", "verify": "ver"}

# The pair §A exists to compare: the written token against the omission it has
# always stood in for.
DISARMED = (("off", G_OFF), ("absent", G_ABS))

# Every disabled face, including the one carrying the inert companion — §A's
# equality is worth stating three-wide, because a companion knob that changed a
# refusal would be a different bug from a companion knob that did nothing.
ALL_DISARMED = DISARMED + (("verify", G_VER),)

TIMEOUT = 30

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

class _Gateways:
    """Four gateways over four exports plus one /metrics face, by port."""

    def __init__(self, instance, root):
        self.instance = instance
        self.root = Path(root)
        self.metrics_url = f"http://{SERVER_HOST}:{HTTP_PORT}/metrics"

    def export(self, face):
        """The on-disk root the named face serves."""
        return self.root / SUBTREE[face]

    def errlog_path(self):
        return Path(self.instance.prefix) / "logs" / "error.log"

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        log = self.errlog_path()
        return log.read_text(errors="replace") if log.exists() else ""

    def errlog_size(self):
        log = self.errlog_path()
        return log.stat().st_size if log.exists() else 0

    def errlog_since(self, offset):
        """The bytes appended since `offset` — the whole of what a cell's own
        dialogue caused the server to say."""
        log = self.errlog_path()
        if not log.exists():
            return ""
        with log.open(errors="replace") as fh:
            fh.seek(offset)
            return fh.read()

    def scrape(self):
        """Raw /metrics text.

        metrics_helpers.fetch() is pinned to the session fleet's exporter; this
        instance owns its own, so only the GET is local — the parsing is the
        shared metrics_helpers.value.
        """
        import urllib.request
        with urllib.request.urlopen(self.metrics_url, timeout=TIMEOUT) as resp:
            return resp.read().decode()

    def ops(self, text, op, status):
        return metric_value(text, "brix_io_ops_total",
                            {"proto": "gridftp", "op": op, "status": status})

    def gridftp_rows(self, text):
        """Every {proto="gridftp"} sample as {series: value}.

        §D's claim is about the WHOLE plane — "no op row moved" — so it needs the
        set of series, not a named one.
        """
        rows = {}
        for line in text.splitlines():
            if line.startswith("#") or 'proto="gridftp"' not in line:
                continue
            series, _, value = line.rpartition(" ")
            rows[series] = value
        return rows


@pytest.fixture(scope="module")
def gw(tmp_path_factory):
    """MODULE-scoped with its own harness, for the reason files 27-34 give: the
    ports are fixed by the ledger, so a per-test start/stop races the OS
    releasing them.

    Every cell seeds its own fixtures under its own face's export and names them
    after itself, so the four subtrees need no cleanup between cells and a rerun
    cannot read the previous run's bytes.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("audit16ai") / "exports"
    for sub in SUBTREE.values():
        (root / sub).mkdir(parents=True)

    harness = LifecycleHarness()
    try:
        instance = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16ai_gridftp_write_gate.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(root),
            template_values={"BIND_HOST": BIND_HOST},
            reason="audit-16ai brix_allow_write — the write gate whose "
                   "disarming token no config in the tree writes, against the "
                   "omission that has always stood in for it."))
        yield _Gateways(instance, root)
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# FTP helpers — a real client's dialogue, not ftplib's convenience API          #
# --------------------------------------------------------------------------- #

def _connect(port):
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, port, timeout=TIMEOUT)
    ftp.login()
    ftp.sendcmd("TYPE I")
    return ftp


def _cmd(ftp, command):
    """One command, one reply, as the raw reply string.

    ftplib raises on 4xx/5xx and every cell here has a refusal case, so the reply
    is what the helper returns rather than an exception the caller re-derives.
    """
    try:
        return ftp.sendcmd(command)
    except ftplib.Error as exc:
        return str(exc)


def _code(reply):
    return int(reply[:3])


def _one(port, command):
    """A command on its own connection.  Used wherever a cell's claim is about a
    verb in isolation and a preceding verb could have changed the answer."""
    ftp = _connect(port)
    try:
        return _cmd(ftp, command)
    finally:
        ftp.close()


def _sequence(port, commands):
    """Several commands on ONE control connection, replies in order.

    RNFR/RNTO is a pairing carried on the connection, so the two cannot be split
    across sockets and still be the thing under test.
    """
    ftp = _connect(port)
    try:
        return [_cmd(ftp, c) for c in commands]
    finally:
        ftp.close()


def _stor(port, name, payload, verb="STOR"):
    """A stream-mode STOR (or APPE) closing the data channel after exactly
    len(payload) bytes.

    A raw PASV socket rather than ftplib.storbinary, for the reason file 31
    gives: the completion signal IS the close, so the close has to be the test's
    to make.  Returns the completion code — or the refusal code, when the verb
    never got as far as a data channel.
    """
    ftp = _connect(port)
    try:
        host, dport = ftp.makepasv()
        data = socket.create_connection((host, dport), timeout=TIMEOUT)
        try:
            ftp.putcmd(f"{verb} {name}")
            try:
                resp = ftp.getresp()
            except ftplib.Error as exc:
                return int(str(exc)[:3])        # refused before any data
            if not resp.startswith("150"):
                return int(resp[:3])
            data.sendall(payload)
            data.shutdown(socket.SHUT_WR)
            try:
                return int(ftp.getresp()[:3])
            except ftplib.Error as exc:
                return int(str(exc)[:3])
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
            except ftplib.Error as exc:
                return int(str(exc)[:3]), b""
            if not resp.startswith("150"):
                return int(resp[:3]), b""
            buf = b""
            while True:
                chunk = data.recv(65536)
                if not chunk:
                    break
                buf += chunk
            try:
                return int(ftp.getresp()[:3]), buf
            except ftplib.Error as exc:
                return int(str(exc)[:3]), buf
        finally:
            data.close()
    finally:
        ftp.close()


def _uid(request):
    """A name unique to the calling cell, so no cleanup is needed and a rerun
    cannot see the previous run's tree."""
    return (request.node.name.replace("[", "_").replace("]", "")
            .replace("/", "_").replace(" ", "_"))


def _seed_file(gw, face, name, body=b"gridftp write-gate payload\n"):
    path = gw.export(face) / name
    path.write_bytes(body)
    os.chmod(path, 0o644)
    return path


def _seed_dir(gw, face, name):
    path = gw.export(face) / name
    path.mkdir()
    return path


# The seven verbs the gate governs, as (label, how to seed, how to fire, the
# refusal a disabled face gives).  The refusal strings are the C's, verbatim:
# ftp_ev_cmd.c's three ns_mutate verbs and RNFR share one, RNTO is the 503 #135
# is about, and ev_xfer_guards has its own.
NS_VERBS = (
    ("MKD", "none", "MKD /{n}", "550 Permission denied (read-only)"),
    ("XMKD", "none", "XMKD /{n}", "550 Permission denied (read-only)"),
    ("DELE", "file", "DELE /{n}", "550 Permission denied (read-only)"),
    ("RMD", "dir", "RMD /{n}", "550 Permission denied (read-only)"),
    ("XRMD", "dir", "XRMD /{n}", "550 Permission denied (read-only)"),
    ("RNFR", "file", "RNFR /{n}", "550 Permission denied (read-only)"),
)


def _seed_for(gw, face, kind, name):
    if kind == "file":
        _seed_file(gw, face, name)
    elif kind == "dir":
        _seed_dir(gw, face, name)


# --------------------------------------------------------------------------- #
# A. The written `off` against its omission                                    #
# --------------------------------------------------------------------------- #

