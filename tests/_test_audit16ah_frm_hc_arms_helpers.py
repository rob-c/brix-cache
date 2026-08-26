# tests/test_audit16ah_frm_hc_arms.py — the 16th audit tranche, file 34.
#
# SUBJECT: the three NGX_STREAM_SRV_CONF flags whose CONTROL arm no config in
# this tree has ever written.
#
#   brix_health_check       `on` in configs/nginx_hc_parse.conf,
#       nginx_hc_cluster.conf, nginx_hc_tls_cluster.conf and in
#       test_phase22_health_check.py's HC_KNOBS; `off` in NOTHING.  The
#       "health checks are not running" control that suite already has is an
#       EMPTY knob slot — the same absence-for-a-control shape files 32 and 33
#       found in the OCI lane and on the WAF, on the cluster plane this time.
#   brix_frm                `on` in fourteen configs; `off` in NOTHING.
#   brix_frm_async_recall   `on` in nginx_lc_frm_async.conf, in its dead
#       pre-lifecycle twin (backlogged in tools/ci/template_refs_backlog.txt —
#       deliberately not named here, since that guard counts a bare mention as a
#       reference and would retire it on the strength of this comment) and in
#       _test_evil_actor_v3_helpers_b.py; `off` in NOTHING.
#
# The three are one file because they are one merge boundary: all three are
# stream-server-scoped flags that default to 0, all three gate a subsystem that
# is started once per worker, and two of the three gate the SAME subsystem —
# which is how the file ends up measuring what `brix_frm on` is actually worth
# when the field the runtime needs was never written.
#
# WHAT THE CORPUS ALREADY OWNS, AND WHAT THIS FILE IS NOT RE-MEASURING
#   test_phase22_health_check.py owns the health-check accept-parse, the bad
#   `brix_health_check_type`, the enabled manager's startup notice against an
#   empty-knob control, and the live manager probing a registered data server.
#   test_frm_queue.py / test_frm_owner.py / test_cms_prepadd.py own the durable
#   registry's own behaviour once it exists, and test_frm_directive_pin.py owns
#   the directive surface's arity and unknown-knob negatives.  None of that is
#   repeated here.  This file is about the three flags' OWN arms, and every
#   finding below lives in a state none of those files builds.
#
# WHAT THE FILE FOUND
#   #126  `brix_health_check on` with `brix_health_check_interval 0` passes
#         `nginx -t` and starts nothing: brix_hc_manager_start returns at its
#         first line (health_check.c:416).  No config-time warning, no runtime
#         notice, no metric — the enabled-and-inert server is indistinguishable
#         from the disabled one in every observable the module has, and the
#         difference between them is a zero an operator can type by accident.
#   #127  The manager's one startup notice prints milliseconds with a literal
#         `s` suffix (health_check.c:438-443, "interval=%Ms" where %M is the
#         msec specifier).  A 2-second interval is logged as `interval=2000s`.
#         The only human-readable record of what the health checker is doing
#         overstates all three of its durations by a factor of a thousand.
#   #128  `brix_frm on` with the queue path — the only thing the load-time check
#         demands — and no `brix_frm_control_dir` passes `nginx -t` and is
#         cell-for-cell the DISABLED server on the wire.  The stage registry is
#         initialised only from the control dir (process_server_init.c:132), so
#         every runtime consumer's `frm.enable && singleton() != NULL` is false:
#         a kXR_stage prepare returns the legacy `"0"` handle instead of a
#         durable request-id and QPrep rejects every id as "owned by an unknown
#         server".  The diagnostic that refuses the incomplete config names the
#         field that does not matter.
#   #129  `brix_frm_queue_path` is that field.  It is the ONE frm string the
#         load-time check requires and the ONE it validates for absoluteness
#         (tape_stage_conf.c:78-88) — and no code outside its own merge ever
#         reads it.  Nothing opens it, creates it, or writes to it.  Under
#         `brix_frm off` even the validation is skipped, so a relative queue path
#         passes `nginx -t` on the config with staging disabled and fails on the
#         one-word change that enables it.
#   #130  The stage registry is a PROCESS singleton (stage_request_registry.c:407).
#         A server block with `brix_frm on` and no control dir of its own is
#         therefore silently joined to whatever journal another server block in
#         the same process stood up: it hands out durable request-ids, its
#         exports' LFNs land in a store its configuration never names, and it
#         answers QPrep for request-ids issued by the other server.
#   #131  brix_stage_registry_init returns early on `reg->inited` (:412) and logs
#         nothing, so the second and every later `brix_frm_control_dir` in a
#         process is discarded in silence.  The directory the operator named
#         stays empty and no diagnostic ever mentions it.
#   #132  All three flags are declared NGX_STREAM_SRV_CONF with no
#         NGX_STREAM_MAIN_CONF bit, so `stream { brix_health_check on; }` is
#         refused outright.  That makes `prev` in all three of their merges
#         permanently NGX_CONF_UNSET — the parent-to-child inheritance
#         ngx_conf_merge_value spells out in tape_stage_conf.c:47,56 and
#         server_conf_merge_cluster.c:154 cannot be reached from any
#         configuration that loads.
#
# Ports: the lc-audit16ah-frmhc (eight) and lc-audit16ah-frmreg (four) ledger
# rows.  TWO instances, because #130 and #131 are properties of a process: a
# first-wins singleton cannot be both absent and present in one nginx.
# Configs: configs/nginx_audit16ah_frm_hc_arms.conf and
# configs/nginx_audit16ah_frm_registry.conf, rendered by this file and no other.
# Parse tier: configs/nginx_audit16hparse.conf, REUSED — it writes none of the
# three itself, and its STREAM_KNOBS/STREAM_MAIN/KNOBS/OUTER slots are exactly
# the four placements a stream-only directive has to be asked about.
import os
import re
import socket
import struct
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

def _guard_fleet_1():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


PLAIN = "lc-audit16ah-frmhc"
REGISTRY = "lc-audit16ah-frmreg"
_P = LIFECYCLE_SHARED_PORTS[PLAIN]
_R = LIFECYCLE_SHARED_PORTS[REGISTRY]

#: face name -> listener, for the registryless process.  The face name is also
#: the basename of that face's export subtree, which is how a journal record —
#: the registry stores the LFN — says which face wrote it.
PLAIN_PORTS = {
    "hcoff": _P["port"],
    "hcabs": _P["extra"]["HCABS_PORT"],
    "hcon": _P["extra"]["HCON_PORT"],
    "hczero": _P["extra"]["HCZERO_PORT"],
    "frmoff": _P["extra"]["FRMOFF_PORT"],
    "frmabs": _P["extra"]["FRMABS_PORT"],
    "frmnoc": _P["extra"]["FRMNOC_PORT"],
    "asyncnofrm": _P["extra"]["ASYNC_PORT"],
}

#: face name -> listener, for the process that has a registry.
REG_PORTS = {
    "reg": _R["port"],
    "bleed": _R["extra"]["BLEED_PORT"],
    "second": _R["extra"]["SECOND_PORT"],
    "abs": _R["extra"]["ABS_PORT"],
}

#: The handle a kXR_stage prepare returns when NOTHING enqueued it.  prepare.c
#: :311-313 picks the durable request-id only when the enqueue happened and the
#: registry gave one back; otherwise it sends this, which is what the server sent
#: before the registry existed at all.
LEGACY_HANDLE = b"0"

#: What a durable handle looks like: `<seq>.<pid>@<host>`.  The exact text is
#: the registry's business — what matters to this file is that the two are never
#: confusable, so the pattern is anchored rather than the string pinned.
DURABLE = re.compile(rb"^\d+\.\d+@\S+$")

# XRootD wire constants (XProtocol.hh).
kXR_ok, kXR_error = 0, 4003
kXR_login, kXR_protocol = 3007, 3006
kXR_open, kXR_stat = 3010, 3017
kXR_query, kXR_prepare = 3001, 3021
kXR_QPrep = 2
kXR_stage = 8
kXR_ArgInvalid = 3000

TIMEOUT = 8

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(PLAIN)]


# --------------------------------------------------------------------------- #
# The wire                                                                     #
# --------------------------------------------------------------------------- #
#
# The suite's existing kXR_prepare/kXR_QPrep wire client lives in
# _test_prepare_staging_helpers.py, which imports pyxrootd at module scope for a
# different test's needs.  Importing it here would make every measurement below
# skip on a host without the stock toolchain — and none of them needs it — so
# the four frames this file sends are built here instead.

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("server closed the connection mid-response")
        buf += chunk
    return buf


def _response(sock):
    """One XRootD response: 8-byte header, then dlen bytes of body."""
    header = _recv_exact(sock, 8)
    status = struct.unpack(">H", header[2:4])[0]
    dlen = struct.unpack(">I", header[4:8])[0]
    return status, (_recv_exact(sock, dlen) if dlen else b"")


class Session:
    """A logged-in anonymous XRootD session on one port.

    Every face runs `brix_auth none`, so the login is the three-frame minimum:
    the 20-byte handshake, kXR_protocol, and a kXR_login whose username field is
    exactly eight bytes."""

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(TIMEOUT)
        self.sock.connect((HOST, port))
        self.sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        _recv_exact(self.sock, 16)
        self.sock.sendall(struct.pack(">BBHIBB10xI", 0, 1, kXR_protocol,
                                      0x00000520, 0x02, 0x03, 0))
        assert _response(self.sock)[0] == kXR_ok
        self.sock.sendall(struct.pack(">2sH", b"\x00\x01", kXR_login)
                          + struct.pack(">I", 0) + b"anon\x00\x00\x00\x00"
                          + struct.pack(">BBBBI", 0, 0, 5, 0, 0))
        assert _response(self.sock)[0] == kXR_ok

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def prepare(self, paths, options=kXR_stage, optionx=0):
        """kXR_prepare over a newline-separated path list → (status, handle)."""
        payload = ("\n".join(paths) + "\n").encode()
        body = (struct.pack(">BBH", options, 0, 0)
                + struct.pack(">H", optionx) + b"\x00" * 10)
        self.sock.sendall(struct.pack(">2sH", b"\x00\x01", kXR_prepare) + body
                          + struct.pack(">I", len(payload)) + payload)
        return _response(self.sock)

    def qprep(self, reqid, paths=()):
        """kXR_query/kXR_QPrep: a request-id line, then an optional path list.

        With paths the server answers per path from stat + registry; WITHOUT
        them it has only the request-id to go on, which is the form that asks
        whether this server knows the id at all (prepare_qprep.c:145-160)."""
        payload = (reqid + "\n").encode()
        if paths:
            payload += ("\n".join(paths) + "\n").encode()
        self.sock.sendall(
            struct.pack(">2sHHH4s8sI", b"\x00\x01", kXR_query, kXR_QPrep, 0,
                        b"\x00" * 4, b"\x00" * 8, len(payload)) + payload)
        return _response(self.sock)

    def open(self, path):
        raw = path.encode()
        self.sock.sendall(struct.pack(">2sHHH12xI", b"\x00\x01", kXR_open,
                                      0, 0, len(raw)) + raw)
        return _response(self.sock)[0]

    def stat(self, path):
        raw = path.encode()
        self.sock.sendall(struct.pack(">2sHB11x4xI", b"\x00\x01", kXR_stat,
                                      0, len(raw)) + raw)
        return _response(self.sock)[0]


# --------------------------------------------------------------------------- #
# The two instances                                                            #
# --------------------------------------------------------------------------- #

class _Fleet:
    """Both processes, addressed by face name.  A face name is unique across the
    two, so `port()` needs no instance argument and no test has to name one."""

    def __init__(self, plain, registry, dirs):
        self.plain = plain
        self.registry = registry
        self.dirs = dirs

    def port(self, face):
        return PLAIN_PORTS.get(face) or REG_PORTS[face]

    def session(self, face):
        return Session(self.port(face))

    def errlog(self, which="plain"):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        prefix = self.plain.prefix if which == "plain" else self.registry.prefix
        log = Path(prefix) / "logs" / "error.log"
        return log.read_text(errors="replace") if log.exists() else ""

    def hc_notices(self):
        return [line.split("] ", 1)[-1]
                for line in self.errlog().splitlines()
                if "health check manager started" in line]

    def journal(self, which="ctrl"):
        return self.dirs[which] / "stage_requests.dat"

    def stage_handle(self, face, path="/seed.txt"):
        """Fire one kXR_stage prepare at a face and return its handle."""
        with self.session(face) as session:
            status, handle = session.prepare([path])
            assert status == kXR_ok, (face, status, handle)
            return handle.strip()


@pytest.fixture(scope="module")
def fleet(tmp_path_factory):
    """MODULE-scoped with its own harness, for the reason files 27-33 give: the
    twelve ports are fixed by the ledger, so a per-test start/stop races the OS
    releasing them.  The registry journal only ever grows, so tests that count
    take their own baseline instead of expecting an empty store."""
    _guard_fleet_1()

    base = tmp_path_factory.mktemp("audit16ah")
    plain_root = base / "plain"
    reg_root = base / "registry"
    dirs = {
        "plain_queue": base / "plain-queue",
        "off_ctrl": base / "off-ctrl",
        "reg_queue": base / "reg-queue",
        "ctrl": base / "ctrl",
        "second_ctrl": base / "second-ctrl",
    }
    for directory in dirs.values():
        directory.mkdir(parents=True)
    # One export subtree per face, each with the same seed file: the journal
    # records the LFN, so two faces sharing an export would write byte-identical
    # records and no measurement could say which of them enqueued one.
    for face in PLAIN_PORTS:
        (plain_root / face).mkdir(parents=True)
        (plain_root / face / "seed.txt").write_text("frm-hc payload\n")
    for face in REG_PORTS:
        (reg_root / face).mkdir(parents=True)
        (reg_root / face / "seed.txt").write_text("frm-registry payload\n")

    harness = LifecycleHarness()
    try:
        plain = harness.start(NginxInstanceSpec(
            name=PLAIN,
            template="nginx_audit16ah_frm_hc_arms.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(plain_root),
            template_values={"BIND_HOST": BIND_HOST,
                             "QUEUE_DIR": str(dirs["plain_queue"]),
                             "OFF_CTRL_DIR": str(dirs["off_ctrl"])},
            reason="audit-16ah the three stream flags whose control arm no "
                   "config writes: brix_health_check off and brix_frm off "
                   "against the absence every control in the tree uses "
                   "instead, in the process where no server block ever names "
                   "a brix_frm_control_dir."))
        registry = harness.start(NginxInstanceSpec(
            name=REGISTRY,
            template="nginx_audit16ah_frm_registry.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(reg_root),
            template_values={"BIND_HOST": BIND_HOST,
                             "QUEUE_DIR": str(dirs["reg_queue"]),
                             "CTRL_DIR": str(dirs["ctrl"]),
                             "SECOND_CTRL_DIR": str(dirs["second_ctrl"])},
            reason="audit-16ah the same FRM fronts in a process where one "
                   "server block stands the first-wins stage-registry "
                   "singleton up, which is what makes the other blocks' "
                   "brix_frm mean something they never configured."))
        yield _Fleet(plain, registry, dirs)
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# §A  The health-check `off` nobody writes, against the absence that stands in  #
# --------------------------------------------------------------------------- #

