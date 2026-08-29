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
     "src/core/config/server_conf_merge_storage.c", "BRIX_IO_URING_OFF"),
    ("brix_min_sec_level", "none", "min_sec_level",
     "src/core/config/server_conf_merge_security.c", "0"),
    ("brix_seccomp", "off", "seccomp",
     "src/core/config/server_conf_merge_storage.c", "BRIX_SECCOMP_OFF"),
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

