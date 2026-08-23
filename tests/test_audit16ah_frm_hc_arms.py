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

class TestTheWrittenHealthCheckOffAndItsOmission:
    """hcoff and hcabs are the same server twice, one `brix_health_check off;`
    apart: both carry all five companion knobs, both name an export, and only
    one of them says out loud that health checking is disabled.  Three configs
    in this tree turn health checks on and none turns them off, so every "not
    running" control the corpus has is the second of these two."""

    def test_neither_starts_a_manager(self, fleet):
        """The observable is brix_hc_manager_start's own NOTICE.  There is one
        notice in the whole process and it belongs to hcon, so neither of these
        two produced one — and the count is asserted rather than a substring,
        because a substring would pass on a log with three."""
        assert len(fleet.hc_notices()) == 1, fleet.errlog()

    def test_the_one_notice_is_not_theirs(self, fleet):
        """hcoff and hcabs configure interval 7s / timeout 3s; the sole notice
        names neither number.  The notice prints no server address, so its
        durations are the only thing that says which block logged it."""
        notice = fleet.hc_notices()[0]

        assert "interval=7000" not in notice, notice

    def test_both_still_serve(self, fleet):
        """A disabled health checker must not be a disabled server.  The
        agreement above would also hold for two blocks that failed to start."""
        for face in ("hcoff", "hcabs"):
            with fleet.session(face) as session:
                assert session.stat("/seed.txt") == kXR_ok, face
                assert session.open("/seed.txt") == kXR_ok, face

    def test_the_comparison_is_not_vacuous(self, fleet):
        """The pair agree because the flag is off in both, not because the
        health-check manager is dead in this build: the enabled face DID log."""
        assert fleet.hc_notices(), fleet.errlog()


# --------------------------------------------------------------------------- #
# §B  #126 — enabled and inert                                                 #
# --------------------------------------------------------------------------- #

class TestAnEnabledHealthCheckerThatNeverStarts:
    """hczero writes `brix_health_check on` and `brix_health_check_interval 0`.
    brix_hc_manager_start's first statement is
    `if (!conf->hc.enabled || conf->hc.interval_ms == 0) return;`
    (health_check.c:416), so the second half of that condition throws the
    configuration away as completely as the first — and says nothing."""

    def test_it_logs_no_notice(self, fleet):
        """Same evidence as §A: one notice in the process, and hczero's timeout
        of 3s is not in it."""
        notices = fleet.hc_notices()

        assert len(notices) == 1, fleet.errlog()
        assert "timeout=3000" not in notices[0], notices[0]

    def test_it_is_indistinguishable_from_the_disabled_face(self, fleet):
        """Every observable the module has, side by side: no notice from either,
        and both serve.  The difference between the two configurations is the
        word `on` and a zero, and nothing anywhere reports it."""
        for face in ("hczero", "hcoff"):
            with fleet.session(face) as session:
                assert session.stat("/seed.txt") == kXR_ok, face

    def test_nothing_warns_at_config_time(self, tmp_path):
        """Not a runtime-only silence: `nginx -t` accepts the pair outright.  An
        interval of 0 is a legal msec value and no merge or postconfiguration
        step looks at it against hc.enabled."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream(
            "brix_health_check on;", "brix_health_check_interval 0;"))

        assert rc == 0, out
        assert not _diagnostics(out), out

    def test_the_interval_is_what_makes_the_difference(self, tmp_path):
        """A non-zero interval on the same two lines is the configuration that
        DOES start a manager — hcon proves it at runtime, and this proves the
        only thing separating them parses identically."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream(
            "brix_health_check on;", "brix_health_check_interval 2s;"))

        assert rc == 0, out


# --------------------------------------------------------------------------- #
# §C  #127 — the notice's own units                                            #
# --------------------------------------------------------------------------- #

class TestTheStartupNoticeOverstatesEveryDuration:
    """hcon configures `interval 2s` and `timeout 1s`.  The notice is built with
    "(interval=%Ms timeout=%Ms scan=%Ms)" (health_check.c:438-443): %M is
    nginx's msec specifier and the `s` after it is a literal, so every duration
    is printed as a millisecond count wearing a seconds suffix."""

    def test_the_notice_exists_and_names_this_face(self, fleet):
        notice = fleet.hc_notices()[0]

        assert "interval=2000" in notice, notice
        assert "timeout=1000" in notice, notice

    def test_a_two_second_interval_is_reported_as_two_thousand_seconds(self, fleet):
        """Read as written, the notice claims a probe every 33 minutes on a
        server probing every 2 seconds.  This is the module's only human-facing
        statement of what it is doing."""
        notice = fleet.hc_notices()[0]

        assert "interval=2000s" in notice, notice
        assert "timeout=1000s" in notice, notice
        assert "interval=2s" not in notice, notice


# --------------------------------------------------------------------------- #
# §D  The FRM `off` nobody writes, against the absence that stands in          #
# --------------------------------------------------------------------------- #

class TestTheWrittenFrmOffAndItsOmission:
    """frmoff writes `brix_frm off` and then names a queue path, a control dir
    and a stage TTL — the shape of a config an operator disabled without
    deleting.  frmabs writes no brix_frm* line at all.  Fourteen configs in this
    tree turn brix_frm on and none turns it off."""

    def test_both_hand_back_the_legacy_handle(self, fleet):
        """A kXR_stage prepare returns the durable request-id only when the
        enqueue happened (prepare.c:311-313).  Neither of these enqueued."""
        assert fleet.stage_handle("frmoff") == LEGACY_HANDLE
        assert fleet.stage_handle("frmabs") == LEGACY_HANDLE

    def test_neither_knows_a_request_id(self, fleet):
        """qprep with no path list has only the id to go on, and a server with
        no registry rejects every id it did not itself issue."""
        for face in ("frmoff", "frmabs"):
            with fleet.session(face) as session:
                status, body = session.qprep("1.1@nowhere")

            assert status == kXR_error, (face, status, body)
            assert b"unknown server" in body, (face, body)

    def test_the_named_control_dir_of_a_disabled_frm_stays_empty(self, fleet):
        """frmoff names a control dir.  brix_init_server_stage_registry is
        gated on frm.enable BEFORE it looks at the dir, so the directory the
        operator named is never opened — no journal, no lock file."""
        assert sorted(p.name for p in fleet.dirs["off_ctrl"].iterdir()) == []

    def test_both_still_serve(self, fleet):
        for face in ("frmoff", "frmabs"):
            with fleet.session(face) as session:
                assert session.open("/seed.txt") == kXR_ok, face
                assert session.open("/missing.txt") == kXR_error, face


# --------------------------------------------------------------------------- #
# §E  #128 — enabled, validated, and registryless                              #
# --------------------------------------------------------------------------- #

class TestAnEnabledFrmWithNothingBehindIt:
    """frmnoc is the configuration `nginx -t` blesses: `brix_frm on` plus the
    absolute `brix_frm_queue_path` the load-time check insists on.  It names no
    control dir, and the control dir is the only thing brix_init_server_stage_registry
    looks at after the flag (process_server_init.c:132).  No server in this
    process names one, so the singleton is NULL for all eight faces."""

    def test_it_hands_back_the_legacy_handle(self, fleet):
        assert fleet.stage_handle("frmnoc") == LEGACY_HANDLE

    def test_it_is_cell_for_cell_the_disabled_face(self, fleet):
        """The whole comparison in one place: the enabled face, the face that
        wrote `off`, and the face that wrote nothing all answer identically."""
        columns = {face: fleet.stage_handle(face)
                   for face in ("frmnoc", "frmoff", "frmabs")}

        assert len(set(columns.values())) == 1, columns

    def test_it_knows_no_request_id_either(self, fleet):
        with fleet.session("frmnoc") as session:
            status, body = session.qprep("1.1@nowhere")

        assert status == kXR_error
        assert b"unknown server" in body

    def test_the_flag_with_no_owner_is_the_same_column(self, fleet):
        """asyncnofrm writes `brix_frm_async_recall on` and no brix_frm.  The
        field is parsed, merged and read at exactly one site — the read-open
        residency gate, behind frm.enable and a live registry
        (open_request_resolve.c:184) — so on this face it is a flag with no
        owner: accepted by nginx -t, and reachable by nothing."""
        assert fleet.stage_handle("asyncnofrm") == LEGACY_HANDLE

        with fleet.session("asyncnofrm") as session:
            assert session.open("/seed.txt") == kXR_ok

    def test_the_incomplete_config_is_accepted(self, tmp_path):
        """The security shape of #128: the deployment that does nothing is the
        one that loads clean."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream(
            "brix_frm on;", "brix_frm_queue_path /var/tmp/audit16ah.q;"))

        assert rc == 0, out
        assert not _diagnostics(out), out

    def test_the_diagnostic_names_the_field_that_does_not_matter(self, tmp_path):
        """Drop the queue path and the load fails, naming it.  Drop the control
        dir — the field the registry is actually built from — and nothing is
        said at all.  The two omissions are the wrong way round."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream("brix_frm on;"))

        assert rc != 0, out
        assert "brix_frm on requires brix_frm_queue_path" in out, out
        assert "control_dir" not in out, out


# --------------------------------------------------------------------------- #
# §F  #129 — the queue path is demanded, validated, and read by nothing        #
# --------------------------------------------------------------------------- #

class TestTheQueuePathIsNeverOpened:
    """brix_frm_queue_path is the one frm string the load-time check requires
    and the one it validates for absoluteness (tape_stage_conf.c:78-88).  Its
    own header calls it "accepted"."""

    def test_no_queue_file_is_ever_created(self, fleet):
        """Two faces in the registryless process name a queue path under this
        directory and one of them has brix_frm ON.  Both have been through a
        kXR_stage prepare by now, and the directory is still empty."""
        fleet.stage_handle("frmnoc")
        fleet.stage_handle("frmoff")

        assert sorted(p.name for p in fleet.dirs["plain_queue"].iterdir()) == []

    def test_not_even_in_the_process_that_has_a_registry(self, fleet):
        """The registry face names a queue path too, and enqueues for real —
        into the CONTROL dir's journal.  The queue path is untouched there as
        well, so this is a property of the field and not of the process."""
        fleet.stage_handle("reg")

        assert sorted(p.name for p in fleet.dirs["reg_queue"].iterdir()) == []

    def test_off_skips_the_validation_that_on_enforces(self, tmp_path):
        """The same shape file 33 found at #124, on a different module: the
        securing arm is the only one whose companion fields are checked, so
        `nginx -t` is green on the config that stages nothing and red on the
        one-word change that turns staging on."""
        relative = "brix_frm_queue_path relative/audit16ah.q;"

        rc_off, out_off = _parse(tmp_path / "off",
                                 STREAM_KNOBS=_stream("brix_frm off;", relative))
        rc_on, out_on = _parse(tmp_path / "on",
                               STREAM_KNOBS=_stream("brix_frm on;", relative))

        assert rc_off == 0, out_off
        assert rc_on != 0, out_on
        assert "must be an absolute path" in out_on, out_on


# --------------------------------------------------------------------------- #
# §G  #130 — a sibling's registry                                              #
# --------------------------------------------------------------------------- #

class TestTheRegistryReachesServersThatNeverNamedIt:
    """The second process differs from the first by one line: its FIRST server
    block names a brix_frm_control_dir.  `bleed` is byte for byte the frmnoc
    front — `brix_frm on`, its own queue path, no control dir — and here it is
    live, because brix_stage_registry_init writes into a `static` singleton
    (stage_request_registry.c:407) that every server block in the process reads
    through brix_stage_registry_singleton()."""

    def test_the_configured_face_is_live(self, fleet):
        """The control: the block that named the dir gets a durable handle."""
        assert DURABLE.match(fleet.stage_handle("reg")), fleet.errlog("registry")

    def test_the_face_that_named_nothing_is_live_too(self, fleet):
        """Same configuration as frmnoc, opposite outcome — and the only thing
        that changed is a sibling server block."""
        assert DURABLE.match(fleet.stage_handle("bleed")), fleet.errlog("registry")

    def test_its_exports_land_in_a_store_it_never_names(self, fleet):
        """The journal records the LFN, and every face has its own export
        subtree, so the bytes say which face enqueued.  `bleed`'s export appears
        in a file named only by `reg`."""
        fleet.stage_handle("bleed")
        journal = fleet.journal().read_bytes()

        assert b"/bleed/seed.txt" in journal
        assert b"/reg/seed.txt" in journal

    def test_it_answers_for_request_ids_it_did_not_issue(self, fleet):
        """The store is shared, so the id is too: `bleed` accepts an id `reg`
        handed out, while the face with no brix_frm — in the SAME process,
        reading the SAME singleton — rejects it as owned by an unknown server.
        Knowability follows the asking block's flag, not the store."""
        handle = fleet.stage_handle("reg").decode()

        with fleet.session("bleed") as session:
            assert session.qprep(handle) == (kXR_ok, b"")
        with fleet.session("abs") as session:
            status, body = session.qprep(handle)

        assert status == kXR_error
        assert b"unknown server" in body

    def test_a_block_without_the_flag_stays_out(self, fleet):
        """The bleed is not "every server in the process": `abs` writes no
        brix_frm line, and both halves of `frm.enable && singleton() != NULL`
        have to hold."""
        assert fleet.stage_handle("abs") == LEGACY_HANDLE
        assert b"/abs/seed.txt" not in fleet.journal().read_bytes()


# --------------------------------------------------------------------------- #
# §H  #131 — the second control dir, discarded in silence                      #
# --------------------------------------------------------------------------- #

class TestOnlyTheFirstControlDirIsEverUsed:
    """`second` writes `brix_frm on` and a brix_frm_control_dir of its own,
    different from `reg`'s.  brix_stage_registry_init returns NGX_OK at its
    first statement when the singleton is already inited
    (stage_request_registry.c:412) and logs nothing on the way out."""

    def test_the_first_dir_has_the_journal(self, fleet):
        fleet.stage_handle("reg")
        names = sorted(p.name for p in fleet.dirs["ctrl"].iterdir())

        assert "stage_requests.dat" in names, names

    def test_the_second_dir_is_empty(self, fleet):
        """The directory the operator named, after that block has enqueued."""
        fleet.stage_handle("second")

        assert sorted(p.name for p in fleet.dirs["second_ctrl"].iterdir()) == []

    def test_its_records_went_to_the_other_directory(self, fleet):
        """Not merely "the second dir is unused" — the requests are elsewhere,
        in a file whose path appears nowhere in that server block."""
        fleet.stage_handle("second")

        assert b"/second/seed.txt" in fleet.journal().read_bytes()

    def test_nothing_in_the_log_mentions_the_discarded_directory(self, fleet):
        """The whole error log of that process, checked for the path it threw
        away.  Silence is the finding."""
        assert str(fleet.dirs["second_ctrl"]) not in fleet.errlog("registry")


# --------------------------------------------------------------------------- #
# §I  The async arms, which this plane cannot tell apart — by construction     #
# --------------------------------------------------------------------------- #

class TestTheAsyncRecallArmsOnAPosixExport:
    """`reg` writes `brix_frm_async_recall on` and `bleed` writes the literal
    `off` — the arm no config in this tree has.  The field is read at exactly
    one site: the read-open residency gate, and only after the VFS has
    classified the object NEARLINE (open_request_resolve.c:184).  A posix export
    is never NEARLINE, so the two arms are indistinguishable here.  That is the
    measurement: on the posix backend every brix_frm config in this tree exports
    from, neither arm of brix_frm_async_recall can be observed to do anything."""

    def test_a_read_open_is_answered_the_same_on_both(self, fleet):
        for face in ("reg", "bleed"):
            with fleet.session(face) as session:
                assert session.open("/seed.txt") == kXR_ok, face

    def test_neither_parks_the_client(self, fleet):
        """Async recall's whole effect is to answer kXR_waitresp instead of
        kXR_wait.  Both faces answer kXR_ok, which is neither."""
        for face in ("reg", "bleed"):
            with fleet.session(face) as session:
                assert session.open("/seed.txt") == kXR_ok, face
                assert session.stat("/seed.txt") == kXR_ok, face

    def test_both_still_enqueue(self, fleet):
        """The arm is not gating staging itself: both faces are live against the
        registry, so the indistinguishability above is about the recall path and
        not about brix_frm having failed on one of them."""
        assert DURABLE.match(fleet.stage_handle("reg"))
        assert DURABLE.match(fleet.stage_handle("bleed"))


# --------------------------------------------------------------------------- #
# §J  Parse tier                                                               #
# --------------------------------------------------------------------------- #

def _stream(*lines):
    return "".join(f"        {line}\n" for line in lines)


def _parse(root, **slots):
    """`nginx -t` on the shared parse scaffold.

    configs/nginx_audit16hparse.conf is REUSED rather than copied, for the
    reason files 29-33 give: it writes none of the three flags itself, so a
    duplicate negative can be sure the duplicate it is shown is the one it
    wrote.  Its STREAM_KNOBS slot is the one legal placement these three have,
    and its STREAM_MAIN / KNOBS / OUTER slots are the three illegal ones."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(exist_ok=True)
    data = root / "data"
    data.mkdir(exist_ok=True)
    values = {"OUTER": "", "HTTP_KNOBS": "", "SRV_KNOBS": "", "KNOBS": "",
              "STREAM_KNOBS": "", "STREAM_MAIN": "", "SUBJECT": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16hparse.conf", root,
                     PORT=PARSE_PLACEHOLDER_PORT,
                     SUBJ_PORT=PARSE_PLACEHOLDER_PORT + 1,
                     STREAM_PORT=PARSE_PLACEHOLDER_PORT + 2,
                     LOG_DIR=str(root / "logs"), DATA=str(data), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _diagnostics(out):
    """Only the lines nginx itself flagged: a tmp_path name can contain the
    token under test, so a substring search over the whole output would match
    the temp directory rather than a diagnostic."""
    return [line for line in out.splitlines()
            if any(tag in line for tag in ("[warn]", "[error]", "[crit]",
                                           "[emerg]"))]


FLAGS = ("brix_health_check", "brix_frm", "brix_frm_async_recall")


class TestBothArmsOfAllThreeFlagsParse:
    """Six lines; the corpus writes three of them.  A flag whose unwritten arm
    had never been through `nginx -t` is a flag whose unwritten arm might not
    parse at all, which would make every behavioural measurement above moot."""

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_the_arm_is_accepted_in_a_stream_server(self, tmp_path, flag, arm):
        # brix_frm on is the one arm with a companion requirement.
        extra = ("brix_frm_queue_path /var/tmp/audit16ah.q;",) \
            if (flag == "brix_frm" and arm == "on") else ()
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream(f"{flag} {arm};", *extra))

        assert rc == 0, out
        assert not _diagnostics(out), out


class TestTheFlagsRefuseWhatIsNotAFlag:
    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_third_value_is_refused(self, tmp_path, flag):
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream(f"{flag} maybe;"))

        assert rc != 0, out
        assert 'it must be "on" or "off"' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_no_value_is_refused(self, tmp_path, flag):
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream(f"{flag};"))

        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_two_arms_cannot_both_be_written(self, tmp_path, flag):
        """ngx_conf_set_flag_slot refuses a second occurrence in one block, so
        there is no configuration in which both arms are visible at once — the
        thing that makes an arm-vs-arm comparison need two server blocks."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream(f"{flag} on;",
                                                        f"{flag} off;"))

        assert rc != 0, out
        assert "is duplicate" in out, out


class TestTheFlagsAreStreamServerOnly:
    """#132's evidence.  Every one of these refusals is "directive is not
    allowed here" and never "unknown directive": nginx searches every module's
    command table before it checks the context."""

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_stream_main_context_refuses_it(self, tmp_path, flag):
        rc, out = _parse(tmp_path, STREAM_MAIN=f"    {flag} on;\n")

        assert rc != 0, out
        assert f'"{flag}" directive is not allowed here' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_an_http_location_refuses_it(self, tmp_path, flag):
        rc, out = _parse(tmp_path, KNOBS=f"            {flag} on;\n")

        assert rc != 0, out
        assert f'"{flag}" directive is not allowed here' in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_main_context_refuses_it(self, tmp_path, flag):
        rc, out = _parse(tmp_path, OUTER=f"{flag} on;\n")

        assert rc != 0, out
        assert f'"{flag}" directive is not allowed here' in out, out


class TestTheInheritanceTheMergeSpellsOutIsUnreachable:
    """#132.  Each of the three merges reads a parent value —
    ngx_conf_merge_value(conf->hc.enabled, prev->hc.enabled, 0) and its two frm
    counterparts — and `prev` is the stream{} main-level srv conf.  Nothing can
    write into it, so the parent branch of all three merges is dead code and the
    literal default is the only outcome the tree has."""

    def test_a_parent_value_cannot_be_written(self, tmp_path):
        """The three refusals above, restated as the one property they add up
        to: there is no accepted configuration in which a stream server inherits
        any of these three from its parent."""
        for flag in FLAGS:
            rc, out = _parse(tmp_path / flag, STREAM_MAIN=f"    {flag} off;\n")

            assert rc != 0, (flag, out)

    def test_a_server_level_arm_is_the_only_placement(self, tmp_path):
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream(
            "brix_health_check off;", "brix_frm off;",
            "brix_frm_async_recall off;"))

        assert rc == 0, out

    def test_two_server_blocks_do_not_see_each_other(self, fleet):
        """The runtime half of the same property: eight server blocks in the
        registryless process, one of them (frmnoc) with brix_frm on, and the
        seven others are unaffected — an inherited value would have carried."""
        for face in ("frmoff", "frmabs", "asyncnofrm", "hcon"):
            assert fleet.stage_handle(face) == LEGACY_HANDLE, face


class TestTheCompanionKnobsAreAcceptedUnderEitherArm:
    """The five health-check knobs and the frm strings are validated against
    nothing but their own types, so a disabled subsystem carries a full,
    unchecked configuration.  This is what makes the frmoff face a realistic
    shape rather than a contrived one."""

    def test_every_health_check_knob_parses_under_off(self, tmp_path):
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream(
            "brix_health_check off;",
            "brix_health_check_interval 7s;",
            "brix_health_check_timeout 3s;",
            "brix_health_check_threshold 2;",
            "brix_health_check_blacklist 11s;",
            "brix_health_check_type stat;"))

        assert rc == 0, out
        assert not _diagnostics(out), out

    def test_a_bad_probe_type_is_still_refused_under_off(self, tmp_path):
        """The enum setter runs at parse time and does not consult the flag, so
        this one companion IS checked under `off` — which is the asymmetry:
        brix_health_check_type is validated by its own setter and
        brix_frm_queue_path by the merge, and only the merge can be skipped.

        The diagnostic is ngx_conf_set_enum_slot's, which names the VALUE and
        not the directive — unlike ngx_conf_set_flag_slot's, which names both.
        On a stream server carrying six health-check lines, `invalid value
        "bogus"` and a line number is the whole of what the operator is told."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream(
            "brix_health_check off;", "brix_health_check_type bogus;"))

        assert rc != 0, out
        assert 'invalid value "bogus"' in out, out
        assert "brix_health_check_type" not in out, out

    def test_a_control_dir_under_off_is_accepted_unchecked(self, tmp_path):
        """The frmoff face, at parse time: a control dir that does not exist,
        under a disabled brix_frm, is accepted without a word."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=_stream(
            "brix_frm off;",
            "brix_frm_queue_path /var/tmp/audit16ah.q;",
            "brix_frm_control_dir /nonexistent/audit16ah;"))

        assert rc == 0, out
        assert not _diagnostics(out), out

    def test_async_recall_is_accepted_with_no_owner(self, tmp_path):
        """The asyncnofrm face, at parse time.  Nothing relates the flag to
        brix_frm at config time, which is why it can be written alone."""
        for arm in ("on", "off"):
            rc, out = _parse(tmp_path / arm,
                             STREAM_KNOBS=_stream(f"brix_frm_async_recall {arm};"))

            assert rc == 0, (arm, out)
            assert not _diagnostics(out), (arm, out)
