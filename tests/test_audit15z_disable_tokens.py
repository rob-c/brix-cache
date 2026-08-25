"""Tranche 15, file 8 — the token that turns it off.

WHY THIS FILE EXISTS
--------------------
The tranche counts coverage at VALUE granularity: not "is this directive
written somewhere in the suite" but "is each token in its ``ngx_conf_enum_t``
table written".  Five tokens came out of that count never written at all, and
they are all the same kind of token — the one that disables the feature:

    brix_cns             off      (emit x5, collect x2, off x0)
    brix_gsi_signed_dh   off      (require x11, auto x1, off x0)
    brix_io_uring        off      (on x6, auto x1, off x0)
    brix_min_sec_level   none     (compat, intense, "banana"; none x0)
    brix_seccomp         off      (enforce x3, audit x1, off x0)

They are unwritten for an understandable reason: every one of them is also the
merged default, so a config that wants the feature off writes nothing.  The
suite's own templates say so out loud — ``nginx_gsi_handshake_root.conf``
advertises that it "covers every signed-DH policy (off/auto/require)" and then
spells ``off`` by leaving the directive out.

That is a reasonable habit and a bad measurement.  "Writing the token" and "not
writing the directive" are two configurations, and nothing in the suite had
ever checked they are the same one.  This file checks it, and the checking
turned up three defects.

WHAT THE TOKEN SELECTS
----------------------
Four of the five land in a per-server field the request path reads:

    min_sec_level  -> handshake/policy.c:47   (session posture floor)
    cns_mode       -> cms/cns_emit.c:24 + the write path (name-space records)
    gsi_signed_dh  -> session/login.c:187     (advertised GSI version)
    io_uring       -> aio/uring_probe.c:143   (per-worker ring bring-up)

The fifth, ``seccomp``, lands in a field nothing reads: the effect comes from a
process-global the setter bumps on the side (DEFECT CANDIDATE #60).

WHAT THE TABLE ESTABLISHES
--------------------------
Measured, one nginx process, three servers (see the config header):

  brix_min_sec_level — HONESTLY PER-SERVER.  Same process, two anonymous
  cleartext listeners:

      server A            server B          A stat        B stat
      compat              none              kXR_error     kXR_ok
      compat              (nothing)         kXR_error     kXR_ok
      none                compat            kXR_ok        kXR_error

  So ``none`` == silence, the floor is decided per session by the server the
  session landed on, and the ordering does not matter.  This is the honest
  counterexample to tranche-15 file 7's finding — a per-server directive that
  really is per-server.

  brix_gsi_signed_dh — the advertised version, read straight off the kXR_login
  sec token before any certificate is exchanged:

      brix_gsi_signed_dh off        &P=gsi,v:10000,...
      (nothing)                     &P=gsi,v:10000,...
      brix_gsi_signed_dh auto       &P=gsi,v:10600,...

  So ``off`` == silence, and 10000 is a signal rather than a constant.

  brix_seccomp — NOT per-server.  Counting the one-per-worker install NOTICE:

      server A            server B          "filter active" lines
      (nothing)           (nothing)         0
      off                 off               0
      audit               off               1  (mode=audit)
      audit               (nothing)         1  (mode=audit)

  The last two rows are the finding in one line: an operator who writes
  ``brix_seccomp off`` on server B changes nothing, because the setter only
  ever ratchets the process-global UP (seccomp.c:66, ``if (value > global)``)
  and ``off`` is 0.

FINDING — DEFECT CANDIDATE #59 (brix_seccomp duplicate guard is order-dependent)
-------------------------------------------------------------------------------
``brix_seccomp`` does not use ``ngx_conf_set_enum_slot``; it has a hand-written
setter, and that setter's duplicate guard is (seccomp.c:57):

    if (*field != NGX_CONF_UNSET_UINT && *field != BRIX_SECCOMP_OFF)
        return "is duplicate";

``BRIX_SECCOMP_OFF`` is 0, so the guard cannot tell "the operator has not
written this directive" from "the operator wrote ``off``".  Measured with
``nginx -t``:

    brix_seccomp off;    brix_seccomp off;      ACCEPTED
    brix_seccomp off;    brix_seccomp audit;    ACCEPTED   (global := audit)
    brix_seccomp audit;  brix_seccomp audit;    refused    "directive is duplicate"
    brix_seccomp audit;  brix_seccomp off;      refused    "directive is duplicate"

The same two lines are a fatal config error in one order and a valid
configuration in the other.  The control is exact: ``brix_min_sec_level none``
is also value 0 and also the merged default, and doubling it IS refused —
because the stock enum slot tests against ``NGX_CONF_UNSET_UINT``, which is what
"unset" actually means.  Only the hand-rolled setter conflated the two.

FINDING — DEFECT CANDIDATE #60 (the per-server seccomp field is write-only)
--------------------------------------------------------------------------
``ngx_stream_brix_srv_conf_t.seccomp`` is initialised (server_conf.c:132),
merged (server_conf_merge_security.c:464), addressed by two directive tables and
written by the setter — and read by nothing in ``src/``.  The merge is dead: its
result cannot reach any decision.  ``brix_seccomp`` is declared
``NGX_STREAM_SRV_CONF|BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1``, i.e. per-server, but
is in fact a process-global directive.  Unlike file 7's two globals this one is
at least documented at the declaration ("also bumps the process-global
strictest") — but the documentation says the field is *also* used, and it is not.

FINDING — DEFECT CANDIDATE #61 (brix_io_uring's documented default is stale)
---------------------------------------------------------------------------
The default was deliberately flipped ``auto -> off`` (recorded as fix ``-9`` in
docs/09-developer-guide/postmortem-origin-credential-shadowing.md, kept as
"correct hardening"), and the merge carries the reasoning: io_uring "is a
performance option, not a correctness feature, so it must be an explicit,
operator-verified ``brix_io_uring on`` — never silently engaged".

The flip did not reach three sites that still promise ``auto``:

  * src/protocols/root/stream/directives_cache.h, the directive's own comment;
  * docs/10-reference/comparison/.../04-data-plane-and-performance.md, prose;
  * the same file's feature table, "Default" column.

So the reference an operator reads says io_uring is best-effort-on out of the
box when it is off, and ``brix_io_uring off`` — the token this file is about —
looks like a change when it is a no-op.  The ``on``-without-liburing error even
recommends ``auto`` "to allow silent fallback", reinforcing the wrong model.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
It does not re-measure what the disabled features do when ENABLED: seccomp
enforce/audit belong to test_seccomp_enforce.py, the compat/intense floors and
their kXR error codes to test_min_sec_level.py, signed-DH handshakes to the GSI
suite, CNS emit/collect to the CMS suite, and io_uring bring-up to
test_audit15e_*.  The arms here use an enabling token only as a control, to
prove the "off" observation is a signal and not a constant.

``brix_cns off`` has no runtime arm: emitting a name-space record needs a CMS
manager and a write path, and the off/silence pair is not separable from the
merged-default fact this file already pins statically.  It is covered at the
static and parse tiers only, and that gap is recorded in the audit doc.
"""

import os
import re
import shutil
import socket
import struct
import subprocess
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import (
    LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT, SHARED_PARSE_PLACEHOLDER_PORT,
)
from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST, NGINX_BIN
from test_min_sec_level import _send_initial, _send_protocol
from _test_phase25_ratelimit_helpers import _xrd_recv_status, _xrd_stat, KXR_OK

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15z-disable")]

NAME = "lc-audit15z-disable"
SECOND_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["SECOND_PORT"]
GSI_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["GSI_PORT"]
ROOT = Path(__file__).resolve().parents[1]

KXR_ERROR = 4003
FILTER_ACTIVE = "worker syscall filter active"
# The whole install NOTICE, so the two brix_seccomp arms are compared on the
# message rather than on its existence.  The counts are build-determined and
# must match between the arms; they are matched as digits so an allowlist edit
# does not need this test edited too.
FILTER_LINE = re.compile(
    r"brix_seccomp: worker syscall filter active "
    r"\(mode=audit, exec=allowed, \d+ allowed, \d+ denied\)$")

# (directive, disabling token, the field it writes, the merge unit, the default
#  constant that unit merges to).  min_sec_level merges to a bare 0 because its
# enum table spells the levels as literals rather than BRIX_MIN_SEC_* constants.
TOKENS = (
    ("brix_cns", "off", "cns_mode",
     "src/core/config/server_conf_merge_cluster.c", "BRIX_CNS_OFF"),
    ("brix_gsi_signed_dh", "off", "gsi_signed_dh",
     "src/core/config/server_conf_merge_security.c", "BRIX_GSI_SDH_OFF"),
    ("brix_io_uring", "off", "io_uring",
     "src/core/config/server_conf_merge_security.c", "BRIX_IO_URING_OFF"),
    ("brix_min_sec_level", "none", "min_sec_level",
     "src/core/config/server_conf_merge_security.c", "0"),
    ("brix_seccomp", "off", "seccomp",
     "src/core/config/server_conf_merge_security.c", "BRIX_SECCOMP_OFF"),
)
TOKEN_IDS = [t[0] for t in TOKENS]

# The four whose per-server field the request path actually reads; seccomp is
# deliberately absent — DEFECT CANDIDATE #60 owns it.
READ_FIELDS = ("cns_mode", "gsi_signed_dh", "io_uring", "min_sec_level")

# DEFECT CANDIDATE #61: the sites that still document `auto` as the default,
# each pinned by the exact fragment that says so.  A heuristic scan is the wrong
# tool here — "default" and "auto" appear all over both files for other reasons,
# and the two doc sites do not even spell it the same way (the table carries the
# default in a column, with no word "default" on the row at all).
DATA_PLANE_DOC = ("docs/10-reference/comparison/xrootd-vs-nginx/"
                  "04-data-plane-and-performance.md")
STALE_AUTO_SITES = (
    ("directive-comment", "src/protocols/root/stream/directives_cache.h",
     "(off/auto/on; default auto)"),
    ("reference-prose", DATA_PLANE_DOC,
     "Directive `brix_io_uring off|on|auto` (default `auto`,"),
    ("reference-table", DATA_PLANE_DOC,
     "| `brix_io_uring off\\|on\\|auto` | `auto` |"),
)


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A throwaway self-signed cert used as its own trust store.

    The GSI arm reads the version advertised in the login sec token, which is
    emitted before a client presents anything, so no Grid PKI and no proxy are
    needed — only a certificate the server can load.  A self-signed leaf builds
    a one-element chain, so brix_gsi_compute_ca_hashes falls through to the
    leaf's issuer-name hash; that hash is derived from this cert and is
    therefore never asserted on.
    """
    if shutil.which("openssl") is None:
        pytest.skip("openssl not installed")
    out = tmp_path_factory.mktemp("audit15z-pki")
    cert, key = str(out / "self.pem"), str(out / "self.key")
    result = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=audit15z"],
        capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip(f"openssl could not forge a test cert: {result.stderr}")
    return cert, key


def _knob(*lines):
    return "".join(f"        {line}\n" for line in lines)


def _start(lifecycle, tmp_path, pki_pair, *, a=(), b=(), c=()):
    """Start the three-server instance; a/b/c are the three directive slots."""
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "real.dat").write_text("present\n")
    cert, key = pki_pair
    return lifecycle.start(NginxInstanceSpec(
        name=NAME, template="nginx_audit15z_disable.conf", data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "CERT": cert, "KEY": key,
                         "CA": cert, "KNOBS_A": _knob(*a),
                         "KNOBS_B": _knob(*b), "KNOBS_C": _knob(*c)},
        reason="audit-15z the five never-written disabling tokens"))


def _login(port):
    """Anonymous kXR_login; returns (socket, status, body).

    The reply BODY is the point for the GSI arm — it carries the sec token —
    so this cannot use test_min_sec_level's _login_plain, which drains it.  The
    handshake and kXR_protocol steps are imported rather than restated.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((HOST, port))
    _send_initial(sock)
    _send_protocol(sock)
    sock.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                             b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    status, body = _xrd_recv_status(sock)
    return sock, status, body


def _stat_status(port):
    """kXR_stat a file that really exists, so the only thing that can refuse
    it is policy."""
    sock, _, _ = _login(port)
    try:
        status, _ = _xrd_stat(sock, "/real.dat")
    finally:
        sock.close()
    return status


def _sec_token(port):
    """The sec token from a login reply: 16-byte session id, then a C string."""
    sock, status, body = _login(port)
    sock.close()
    assert status == KXR_OK, ("gsi login must succeed before it advertises",
                              status)
    return body[16:].split(b"\x00")[0].decode(errors="replace")


def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(endpoint.prefix, "logs", "error.log")) as handle:
            return handle.read()
    except OSError:
        return "(error log unavailable)"


def _filter_lines(endpoint):
    return [ln for ln in _errlog(endpoint).splitlines() if FILTER_ACTIVE in ln]


def _source(relative):
    return (ROOT / relative).read_text(errors="replace")


def _merge_default(unit, field):
    """The default constant the merge unit folds `field` to."""
    flat = re.sub(r"\s+", " ", _source(unit))
    match = re.search(
        rf"ngx_conf_merge_uint_value\( ?conf->{field}, ?prev->{field}, ?(\w+) ?\)",
        flat)
    assert match, f"no ngx_conf_merge_uint_value for conf->{field} in {unit}"
    return match.group(1)


def _field_sites(field):
    """Every source line naming `->field` or `.field`, minus the lines that are
    storage rather than use: the UNSET initialiser, the merge, the directive
    tables' offsetof(), and prose in comments."""
    result = subprocess.run(
        ["grep", "-rnE", rf"(->|\.){field}([^_a-zA-Z0-9]|$)", "src/"],
        cwd=ROOT, capture_output=True, text=True)
    keep = []
    for line in result.stdout.splitlines():
        path, _, code = line.split(":", 2)
        if "server_conf.c" in path or "server_conf_merge" in path:
            continue
        stripped = code.strip()
        if stripped.startswith(("*", "/*", "//")) or "offsetof(" in stripped:
            continue
        keep.append(line)
    return keep


def _parse(tmp_path, knobs="", second="", http_lines="", outer=""):
    """Render the parse scaffold and return (returncode, combined output)."""
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit15z_disableparse.conf", tmp_path,
                     LOG_DIR=str(tmp_path), DATA_ROOT=str(data),
                     PORT=PARSE_PLACEHOLDER_PORT,
                     SECOND_PORT=SHARED_PARSE_PLACEHOLDER_PORT,
                     HTTP_PORT=PARSE_PLACEHOLDER_PORT,
                     KNOBS=knobs, SECOND=second,
                     HTTP_LINES=http_lines, OUTER=outer)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


# --------------------------------------------------------------------------- #
# A. every disabling token is the merged default — which is why none is written
# --------------------------------------------------------------------------- #
class TestTheTokensAreAllTheDefault:

    @pytest.mark.parametrize("directive,token,field,unit,default",
                             TOKENS, ids=TOKEN_IDS)
    def test_the_merge_folds_the_field_to_the_disabling_value(
            self, directive, token, field, unit, default):
        got = _merge_default(unit, field)
        assert got == default, (
            f"{directive}: the merge default moved from {default} to {got}; "
            "the premise of this whole file — that writing the disabling token "
            "is writing the default — no longer holds, so re-measure before "
            "editing the assertions", unit)

    @pytest.mark.parametrize("directive,token,field,unit,default",
                             TOKENS, ids=TOKEN_IDS)
    def test_the_token_is_spelled_in_the_enum_table(
            self, directive, token, field, unit, default):
        """The token has to be in the table, or the operator cannot write the
        default even when they want it stated explicitly in the config."""
        table = _source("src/protocols/root/stream/module_enums.c")
        flat = re.sub(r"\s+", " ", table)
        assert f'{{ ngx_string("{token}"), {default} }}' in flat, (
            f'{directive}: no enum entry mapping "{token}" to {default}', )

    def test_no_disabling_token_is_written_by_any_shipped_config(self):
        """The audit's count, re-derived rather than quoted: none of the five
        appears in tests/configs/ (which is what made them unwritten values in
        the first place).  A future test that DOES write one should be here, in
        this file, so update the exception list rather than deleting this."""
        allowed = {"nginx_audit15z_disable.conf",
                   "nginx_audit15z_disableparse.conf"}
        offenders = []
        for conf in sorted((ROOT / "tests/configs").glob("*.conf")):
            if conf.name in allowed:
                continue
            text = conf.read_text(errors="replace")
            for directive, token, _, _, _ in TOKENS:
                if re.search(rf"^\s*{directive}\s+{token}\s*;", text, re.M):
                    offenders.append(f"{conf.name}: {directive} {token}")
        assert not offenders, (
            "a shipped config now writes a disabling token — good, but this "
            "file's premise changed; fold the new coverage in", offenders)


# --------------------------------------------------------------------------- #
# B. brix_min_sec_level none — the floor really is per-server
# --------------------------------------------------------------------------- #
class TestTheSessionPostureFloor:

    def test_none_serves_what_compat_refuses(self, lifecycle, tmp_path, pki):
        endpoint = _start(lifecycle, tmp_path, pki,
                          a=("brix_min_sec_level compat;",),
                          b=("brix_min_sec_level none;",))
        assert _stat_status(endpoint.port) == KXR_ERROR, (
            "a cleartext anonymous session is below the compat floor",
            _errlog(endpoint))
        assert _stat_status(SECOND_PORT) == KXR_OK, (
            "the same session at `none` must be served", _errlog(endpoint))

    def test_writing_none_is_indistinguishable_from_writing_nothing(
            self, lifecycle, tmp_path, pki):
        endpoint = _start(lifecycle, tmp_path, pki,
                          a=("brix_min_sec_level compat;",), b=())
        assert _stat_status(endpoint.port) == KXR_ERROR, _errlog(endpoint)
        assert _stat_status(SECOND_PORT) == KXR_OK, (
            "silence must behave exactly as `none` did", _errlog(endpoint))

    def test_the_floor_is_not_decided_by_declaration_order(
            self, lifecycle, tmp_path, pki):
        """The mirror image of the first case.  A directive whose merge wrote a
        process-global would give the same answer on both ports here; this one
        swaps with the config, so it is decided per server."""
        endpoint = _start(lifecycle, tmp_path, pki,
                          a=("brix_min_sec_level none;",),
                          b=("brix_min_sec_level compat;",))
        assert _stat_status(endpoint.port) == KXR_OK, _errlog(endpoint)
        assert _stat_status(SECOND_PORT) == KXR_ERROR, _errlog(endpoint)


# --------------------------------------------------------------------------- #
# C. brix_gsi_signed_dh off — read off the advertised login sec token
# --------------------------------------------------------------------------- #
class TestTheAdvertisedGsiVersion:

    def test_off_advertises_the_universally_compatible_version(
            self, lifecycle, tmp_path, pki):
        endpoint = _start(lifecycle, tmp_path, pki,
                          c=("brix_gsi_signed_dh off;",))
        token = _sec_token(GSI_PORT)
        assert token.startswith("&P=gsi,"), (token, _errlog(endpoint))
        assert "v:10000" in token, (
            "off must advertise the unsigned-DH version", token)

    def test_silence_advertises_the_same_version_as_off(
            self, lifecycle, tmp_path, pki):
        endpoint = _start(lifecycle, tmp_path, pki, c=())
        token = _sec_token(GSI_PORT)
        assert "v:10000" in token, (
            "writing nothing must advertise exactly what `off` advertised",
            token, _errlog(endpoint))

    def test_auto_advertises_the_signed_dh_version(
            self, lifecycle, tmp_path, pki):
        """The control: 10000 is a choice, not a constant."""
        endpoint = _start(lifecycle, tmp_path, pki,
                          c=("brix_gsi_signed_dh auto;",))
        token = _sec_token(GSI_PORT)
        assert "v:10600" in token, (
            "auto must advertise the signed-DH-capable version",
            token, _errlog(endpoint))


# --------------------------------------------------------------------------- #
# D. brix_seccomp off — the token that cannot turn anything off
# --------------------------------------------------------------------------- #
def _worker_settled(endpoint):
    """A completed login proves the worker finished init_process: the worker
    answers requests only from its event loop, which it enters after every
    init hook — the seccomp install and its NOTICE included — has run.  The
    harness's TCP readiness proves only that the MASTER bound the listener,
    so reading the error log straight after lifecycle.start races the
    worker's first write (and loses on a warm back-to-back restart)."""
    sock, status, _ = _login(endpoint.port)
    sock.close()
    assert status == KXR_OK, ("login while settling the worker", status)
    return endpoint


class TestTheSeccompRatchet:

    def test_silence_everywhere_installs_no_filter(
            self, lifecycle, tmp_path, pki):
        endpoint = _worker_settled(_start(lifecycle, tmp_path, pki))
        assert _filter_lines(endpoint) == [], _errlog(endpoint)

    def test_off_everywhere_installs_no_filter(self, lifecycle, tmp_path, pki):
        endpoint = _worker_settled(_start(
            lifecycle, tmp_path, pki,
            a=("brix_seccomp off;",), b=("brix_seccomp off;",)))
        assert _filter_lines(endpoint) == [], (
            "`off` must not be more than silence", _errlog(endpoint))

    def _assert_one_audit_notice(self, endpoint):
        """The two cases below differ only in whether server B writes `off`,
        and the finding is that they are the same run.  One spec name can be
        registered once per test, so the two configurations cannot be started
        side by side; holding both to this one expectation — the whole message,
        counts included, not merely "a filter appeared" — is what makes the
        comparison a comparison rather than two loose assertions."""
        lines = [FILTER_LINE.search(ln) for ln in _filter_lines(endpoint)]
        assert len(lines) == 1, (
            "one worker installs the filter once, so one NOTICE",
            _filter_lines(endpoint), _errlog(endpoint))
        assert lines[0] is not None, (
            "the install NOTICE changed shape — re-measure both arms",
            _filter_lines(endpoint))

    def test_off_cannot_lower_a_sibling_servers_filter(
            self, lifecycle, tmp_path, pki):
        """DEFECT CANDIDATE #60, the operator-visible half: server B says off
        and gets the filter anyway, because the mode is a process-global that
        only ratchets up (0 is never greater than audit)."""
        self._assert_one_audit_notice(_worker_settled(_start(
            lifecycle, tmp_path, pki,
            a=("brix_seccomp audit;",), b=("brix_seccomp off;",))))

    def test_not_writing_off_beside_audit_is_the_same_run(
            self, lifecycle, tmp_path, pki):
        """The other half of the pair: delete server B's `off` line and nothing
        about the process changes.  The edit an operator would make to take the
        filter off their own server is inert."""
        self._assert_one_audit_notice(_worker_settled(_start(
            lifecycle, tmp_path, pki, a=("brix_seccomp audit;",), b=())))


# --------------------------------------------------------------------------- #
# E. where the token lands — DEFECT CANDIDATE #60
# --------------------------------------------------------------------------- #
class TestWhereTheValueLands:

    @pytest.mark.parametrize("field", READ_FIELDS)
    def test_the_per_server_field_has_a_reader(self, field):
        sites = _field_sites(field)
        assert sites, (
            f"conf->{field} is written by its directive and read by nothing — "
            "if this fired, a fifth directive just joined DEFECT CANDIDATE #60")

    def test_the_seccomp_field_is_written_and_never_read(self):
        """DEFECT CANDIDATE #60.  brix_seccomp is declared per-server in two
        directive tables and merged like a per-server value, but the merged
        value cannot reach any decision: the effect comes entirely from the
        process-global the setter bumps."""
        sites = _field_sites("seccomp")
        assert sites == [], (
            "conf->seccomp now has a reader — DEFECT CANDIDATE #60 may be "
            "fixed; re-measure and retire this assertion", sites)

    def test_the_setter_bumps_a_process_global_instead(self):
        source = _source("src/core/seccomp/seccomp.c")
        assert "brix_seccomp_worker_mode = e[i].value;" in source, source[:400]
        assert "if (e[i].value > brix_seccomp_worker_mode)" in source, (
            "the ratchet is what makes `off` inert: 0 is never greater than a "
            "mode another server already requested")


# --------------------------------------------------------------------------- #
# F. the duplicate guard — DEFECT CANDIDATE #59
# --------------------------------------------------------------------------- #
class TestTheDuplicateGuard:

    def test_the_guard_treats_off_as_unset(self):
        source = _source("src/core/seccomp/seccomp.c")
        flat = re.sub(r"\s+", " ", source)
        assert ("if (*field != NGX_CONF_UNSET_UINT && *field != "
                "BRIX_SECCOMP_OFF) { return \"is duplicate\"; }") in flat, (
            "DEFECT CANDIDATE #59's guard changed shape — re-measure the "
            "four order cases below before trusting them")

    def test_seccomp_off_twice_is_accepted(self, tmp_path):
        rc, out = _parse(tmp_path, knobs=_knob("brix_seccomp off;",
                                               "brix_seccomp off;"))
        assert rc == 0, (
            "pinned defect: the guard cannot see a repeated `off`", out)

    def test_seccomp_off_then_audit_is_accepted(self, tmp_path):
        rc, out = _parse(tmp_path, knobs=_knob("brix_seccomp off;",
                                               "brix_seccomp audit;"))
        assert rc == 0, ("pinned defect: `off` leaves the slot looking unset",
                         out)

    def test_seccomp_audit_then_off_is_refused(self, tmp_path):
        rc, out = _parse(tmp_path, knobs=_knob("brix_seccomp audit;",
                                               "brix_seccomp off;"))
        assert rc != 0, ("the same two lines, reversed, are a config error", out)
        assert '"brix_seccomp" directive is duplicate' in out, out

    def test_seccomp_audit_twice_is_refused(self, tmp_path):
        rc, out = _parse(tmp_path, knobs=_knob("brix_seccomp audit;",
                                               "brix_seccomp audit;"))
        assert rc != 0, out
        assert '"brix_seccomp" directive is duplicate' in out, out

    @pytest.mark.parametrize("directive,token", [
        (d, t) for d, t, _, _, _ in TOKENS if d != "brix_seccomp"],
        ids=[d for d, _, _, _, _ in TOKENS if d != "brix_seccomp"])
    def test_the_stock_enum_slot_catches_its_own_default_token(
            self, tmp_path, directive, token):
        """The control for DEFECT CANDIDATE #59.  These tokens are the merged
        default too, and every one of them is still diagnosed when doubled —
        ngx_conf_set_enum_slot tests against NGX_CONF_UNSET_UINT, which is what
        "the operator did not write this" actually means."""
        rc, out = _parse(tmp_path, knobs=_knob(f"{directive} {token};",
                                               f"{directive} {token};"))
        assert rc != 0, (f"{directive} {token} doubled must be refused", out)
        assert f'"{directive}" directive is duplicate' in out, out


# --------------------------------------------------------------------------- #
# G. brix_io_uring — DEFECT CANDIDATE #61
# --------------------------------------------------------------------------- #
class TestTheIoUringDefault:

    def test_the_merge_default_is_off(self):
        assert _merge_default("src/core/config/server_conf_merge_security.c",
                              "io_uring") == "BRIX_IO_URING_OFF"

    @pytest.mark.parametrize("site,fragment",
                             [(s, f) for _, s, f in STALE_AUTO_SITES],
                             ids=[i for i, _, _ in STALE_AUTO_SITES])
    def test_the_documented_default_still_says_auto(self, site, fragment):
        """DEFECT CANDIDATE #61.  Pinned as a contradiction, not as a wish: the
        C is right and the prose is stale.  Each of these fragments is a place
        that tells the reader io_uring is best-effort-on out of the box, which
        it has not been since the auto->off flip.  When one is corrected this
        case fails — that is the signal to strike the site from the list, and
        when the last one goes, to close #61."""
        assert fragment in _source(site), (
            f"{site} no longer carries the stale `auto` default — DEFECT "
            f"CANDIDATE #61 is partly or wholly fixed; drop this entry",
            fragment)

    def test_off_and_auto_both_parse(self, tmp_path):
        for token in ("off", "auto"):
            rc, out = _parse(tmp_path, knobs=_knob(f"brix_io_uring {token};"))
            assert rc == 0, (f"brix_io_uring {token} must always parse — it "
                             "asks for nothing the build may lack", out)

    def test_on_is_the_only_token_a_build_can_refuse(self, tmp_path):
        """`on` is a hard requirement, so its verdict depends on the build.
        Both outcomes are correct; what must not happen is a silent accept that
        leaves the operator believing a ring is up."""
        rc, out = _parse(tmp_path, knobs=_knob("brix_io_uring on;"))
        if rc != 0:
            assert "requires a build with liburing" in out, out
        else:
            assert "brix_io_uring" not in out, (
                "an accepted `on` must not also be complaining about itself",
                out)


# --------------------------------------------------------------------------- #
# H. the parse tier — placement and spelling
# --------------------------------------------------------------------------- #
class TestTheParseTier:

    @pytest.mark.parametrize("directive,token", [(d, t) for d, t, _, _, _ in TOKENS],
                             ids=TOKEN_IDS)
    def test_the_token_parses_where_the_directive_is_declared(
            self, tmp_path, directive, token):
        rc, out = _parse(tmp_path, knobs=_knob(f"{directive} {token};"))
        assert rc == 0, out

    @pytest.mark.parametrize("directive,token", [(d, t) for d, t, _, _, _ in TOKENS],
                             ids=TOKEN_IDS)
    def test_the_token_is_matched_case_insensitively(
            self, tmp_path, directive, token):
        """Both setters compare with ngx_strcasecmp, so the audit has to count
        tokens from the enum table rather than from the spelling in a config."""
        rc, out = _parse(tmp_path, knobs=_knob(f"{directive} {token.upper()};"))
        assert rc == 0, (f"{directive} {token.upper()} must be the same token",
                         out)

    @pytest.mark.parametrize("directive,token", [(d, t) for d, t, _, _, _ in TOKENS],
                             ids=TOKEN_IDS)
    def test_the_directive_is_refused_in_the_main_context(
            self, tmp_path, directive, token):
        rc, out = _parse(tmp_path, outer=f"{directive} {token};\n")
        assert rc != 0, (f"{directive} at the top of the file must be refused, "
                         "not silently ignored", out)
        assert directive in out, out

    @pytest.mark.parametrize("directive", [d for d, _, _, _, _ in TOKENS
                                           if d != "brix_seccomp"])
    def test_the_stream_only_directives_are_refused_in_http(
            self, tmp_path, directive):
        token = dict((d, t) for d, t, _, _, _ in TOKENS)[directive]
        rc, out = _parse(tmp_path, http_lines=_knob(f"{directive} {token};"))
        assert rc != 0, (f"{directive} is NGX_STREAM_SRV_CONF only", out)
        assert directive in out, out

    def test_seccomp_off_is_accepted_in_an_http_server(self, tmp_path):
        """brix_seccomp is the one of the five declared for the http contexts
        as well (BRIX_HTTP_ALL_CONF) — an http-only WebDAV/S3 worker gets the
        same filter, so it must be spellable there."""
        rc, out = _parse(tmp_path, http_lines=_knob("brix_seccomp off;"))
        assert rc == 0, out

    @pytest.mark.parametrize("directive", TOKEN_IDS)
    def test_an_unknown_token_is_refused(self, tmp_path, directive):
        rc, out = _parse(tmp_path, knobs=_knob(f"{directive} banana;"))
        assert rc != 0, (f"{directive} must not accept an unknown token", out)
        assert "invalid value" in out, out

    def test_the_two_servers_may_disagree_without_a_diagnostic(self, tmp_path):
        """Recorded, not endorsed: two servers asking for different seccomp
        modes parse cleanly even though only one of them can win.  Nothing at
        parse time tells the operator which."""
        rc, out = _parse(tmp_path, knobs=_knob("brix_seccomp enforce;"),
                         second=_knob("brix_seccomp off;"))
        assert rc == 0, out
        assert "seccomp" not in out.lower(), (
            "a diagnostic appeared — the disagreement is now reported, which "
            "would be an improvement worth folding into this file", out)
