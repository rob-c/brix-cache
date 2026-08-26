"""
tests/test_audit16v_tpc_off_arms.py — audit tranche 16, file 22: the seven
``root/stream/directives_tpc.h`` flags whose DISARMING arm the corpus has never
spelled.

THE GAP
-------
The audit's Method counts directive NAMES, and a flag's name is answered by ONE
of its two tokens.  Re-run steps 1-2 at *(directive, value)* granularity over the
``ngx_conf_set_flag_slot`` rows and ``src/protocols/root/stream/directives_tpc.h``
is the densest file in the census — SEVEN flags with an arm written nowhere in
``tests/`` ``conf/`` ``client/`` ``k8s-tests/``, and it is the same arm every
time: the one that opens the gate.

    brix_tpc_allow_local          off      brix_tpc_outbound_tls         off
    brix_tpc_source_guard         off      brix_tpc_require_source_size  off
    brix_require_pgwrite          off      brix_tpc_delegate             off
    brix_tpc_outbound_passthrough on       (default-ON flag: `on` is its arm)

Twenty-odd configs write ``brix_tpc_allow_local on``; not one writes ``off``.
``nginx_tpc_harden.conf`` writes ``brix_tpc_require_source_size on`` and drives a
whole fault-proxy suite through it; nothing anywhere asks what the operator who
leaves it off actually keeps.  ``nginx_root_require_pgwrite.conf`` is the sharpest
case: it carries a plane whose comment says the directive is "deliberately
omitted (default off)" and tests the permissive behaviour there — so the OFF
behaviour is covered while the OFF TOKEN is not, and the equivalence of the two
is an assumption the corpus states and never measures.

WHAT THE SEVEN ARMS ACTUALLY BUY
--------------------------------
Four of them are decided before a single source byte moves:

  * ``brix_tpc_source_guard`` — ``brix_tpc_source_guard_check`` at
    ``src/tpc/engine/launch_prepare.c:284``, a STRING match against
    ``brix_tpc_source_allow`` that runs BEFORE any resolution.
  * ``brix_tpc_allow_local`` — ``brix_tpc_check_src_policy`` at ``:303``, which
    resolves and range-checks, refusing with a message that prints the merged
    values: ``host <h> resolves to a prohibited address (allow_local=%d
    allow_private=%d)``.
  * ``brix_require_pgwrite`` — ``brix_write_require_pgwrite``
    (``src/protocols/root/write/write.c:232``), which refuses a data-carrying
    cleartext ``kXR_write``/``kXR_writev`` with ``kXR_Unsupported``.
  * ``brix_tpc_delegate`` — read at pull launch, but ALSO rewritten at
    postconfiguration (§I below), which is the file's one defect finding.

Three only exist mid-transfer, on the destination's own pull leg:

  * ``brix_tpc_require_source_size`` — ``source_stream.c:318``: when the source
    declares no size, refuse rather than commit something unverifiable.
  * ``brix_tpc_outbound_tls`` — ``bootstrap.c:87``: a source answering
    ``kXR_gotoTLS`` is refused outright rather than continued in cleartext.
  * ``brix_tpc_outbound_passthrough`` — ``launch_prepare.c:440``: the default-on
    opportunistic ``passthrough-opt`` token mode.

The three are reachable because the destination's pull leg tags its own requests
(``streamid[1]`` = 1 protocol/login, 2 open/close, 3 read, 4 stat, 5 query), so a
splice between destination and source can answer ONE of them untruthfully and
leave the rest alone.  ``test_tpc_pull_integrity.py`` already faults tag 3 that
way; this file subclasses its proxy for tags 4 and 1.  Nothing here goes through
xrdcp — every pull is driven over the raw wire by the ssrf module's TPC driver,
so the destination's refusal TEXT is read off the response body rather than
guessed from an exit status.

WHY SIX PLANES
--------------
All seven directives are ``NGX_STREAM_SRV_CONF | NGX_CONF_FLAG`` with no
``NGX_STREAM_MAIN_CONF`` bit, so ``server {}`` is the only scope that can hold a
value and there is no inheritance to override — the question is per-server
independence and what each arm does, not what beats what.  Six acceptors in one
worker over one export:

    ARMED     every guard in the arm the corpus already writes
    DISARMED  the seven tokens nothing had ever written
    ABSENT    none of the seven written — the merge defaults
    PULLING   disarmed, except ``allow_local on`` so it can reach a loopback
              source at all; the destination for every live transfer here
    ORDERING  naming gate armed, address gate closed — the only plane where both
              would refuse, so its message says which ran first
    OVERRIDE  an explicit ``brix_tpc_delegate off`` beside a GSI tap proxy

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
Nothing here argues the defaults are wrong.  Four of the seven disarming arms ARE
the compiled default, which is why ABSENT exists: the file measures that the
token and the omission agree before attributing anything to either.  Nor does it
argue the fail-closed arms should be default-on — it measures what a site that
deliberately opens each gate is left holding, which for two of them is a
completed copy nobody can prove is the source's.

Run:
    PYTHONPATH=tests pytest tests/test_audit16v_tpc_off_arms.py -v
"""

import os
import re
import struct
import uuid
from pathlib import Path

import pytest

from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

# The wire is imported, never rebuilt.  The TPC driver (handshake → login →
# kXR_open with a tpc.* opaque → the kXR_sync arm/run two-step) is the ssrf
# module's; the cleartext-write ops are the require_pgwrite module's; the
# pgwrite session helpers are the shared pgwrite ones.
from test_tpc_ssrf_policy import _tpc_attempt, kXR_OK, kXR_error
from test_tpc_pull_integrity import _KxrPullFaultProxy, _port_up, kXR_ok
from test_root_require_pgwrite import _write, _writev, kXR_Unsupported
from _test_pgwrite_cse_helpers import (
    _close,
    _handshake_login,
    _open,
    build_payload,
    kXR_status,
    send_pgwrite,
)
# The corpus census is file 20's; the gap this file closes is a fact about the
# corpus and is asserted with the same three functions that closed that one.
from test_audit16t_compress_flag_arms import _corpus_writers, _source, _writes

pytestmark = [pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16v-tpcoff")]

NAME = "lc-audit16v-tpcoff"
_EXTRA = LIFECYCLE_SHARED_PORTS[NAME]["extra"]

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = Path(__file__).resolve().parent / "configs"
TEMPLATE = CONFIGS / "nginx_audit16v_tpc_off_arms.conf"

PREPARE_C = ROOT / "src/tpc/engine/launch_prepare.c"
BOOTSTRAP_C = ROOT / "src/tpc/outbound/bootstrap.c"
STREAM_C = ROOT / "src/tpc/outbound/source_stream.c"
GUARD_C = ROOT / "src/tpc/common/egress_guard.c"
RUNTIME_C = ROOT / "src/core/config/runtime_server.c"
POSTCONF_C = ROOT / "src/core/config/postconfiguration.c"
AUTH_CERT_C = ROOT / "src/auth/gsi/auth_cert.c"
DIRECTIVES_H = ROOT / "src/protocols/root/stream/directives_tpc.h"

# The seven rows of the census: directive -> the arm the corpus never wrote.
DISARMING_ARM = {
    "brix_tpc_allow_local": "off",
    "brix_tpc_source_guard": "off",
    "brix_require_pgwrite": "off",
    "brix_tpc_outbound_tls": "off",
    "brix_tpc_require_source_size": "off",
    "brix_tpc_delegate": "off",
    "brix_tpc_outbound_passthrough": "on",
}
ARMING_ARM = {d: ("off" if v == "on" else "on")
              for d, v in DISARMING_ARM.items()}

# The destination's own pull-leg tags (src/tpc/outbound: bootstrap.c's
# tpc_bootstrap_streamid = {0,1}; tpc_stat_source sets streamid[1]=4).
PROTOCOL_TAG = 1
STAT_TAG = 4

# ClientOpenRequest options: a plain read open, which is what the client's half
# of the source rendezvous is (_Planes.register).
kXR_open_read = 0x0010

# kXR_gotoTLS (src/protocols/root/protocol/flags.h) in the ServerProtocolBody
# { pval[4], flags[4] } the destination reads at bootstrap.
kXR_gotoTLS = 0x40000000

# A kXR_stat reply body whose second whitespace token is not numeric, so
# tpc_stat_parse_size fails and the destination is left with src_size_known=0 —
# exactly the "source will not declare a size" case the gate exists for.  The
# reply is otherwise a well-formed kXR_ok frame: this is a source that answers,
# not one that errors.
NO_SIZE_STAT = b"0 nosize 0 0\x00"

PAYLOAD = bytes(range(256)) * 32          # 8192 bytes, no run-length luck


def _with_goto_tls(body):
    """The same protocol reply with kXR_gotoTLS forced into its flags word."""
    buf = bytearray(body.ljust(8, b"\x00"))
    flags = struct.unpack("!I", bytes(buf[4:8]))[0] | kXR_gotoTLS
    buf[4:8] = struct.pack("!I", flags)
    return bytes(buf)


class _TpcGateFaultProxy(_KxrPullFaultProxy):
    """The pull-leg splice, widened from read replies to the two frames the
    transfer-time arms are decided on.

    The base class faults ``streamid[1]==3`` (read) and frames everything else
    truthfully; both faults here are one-shot and tag-scoped, so a pull carries
    at most one lie and every other reply — including the source's real data —
    is the source's own:

      * ``nosize``  — the tag-4 ``kXR_stat`` reply body is replaced with one that
                      declares no parseable size.  ``brix_tpc_require_source_size``
                      is the only thing that then stands between the destination
                      and an unverifiable copy.
      * ``gototls`` — the FIRST tag-1 reply (``kXR_protocol``; the login shares the
                      tag and must not be touched) comes back with kXR_gotoTLS
                      set, which is a source demanding TLS.  ``brix_tpc_outbound_tls``
                      decides between refusing and being dragged into a handshake.

    ``truncate`` rides along from the base class so "no declared size" and "fewer
    bytes than the source had" can be armed together — which is the shape of the
    silent poison the off arm permits.
    """

    def __init__(self, target_host, target_port):
        super().__init__(target_host, target_port)
        self._nosize = False
        self._gototls = False
        self._protocol_replies = 0

    def arm_gate(self, nosize=False, gototls=False, truncate=False):
        with self._lock:
            self._nosize = nosize
            self._gototls = gototls
            self._protocol_replies = 0
        # The read leg is the base class's business; arm/disarm through it so
        # its one-shot bookkeeping stays the only copy.
        if truncate:
            self.arm("truncate")
        else:
            self.disarm()

    def disarm_gate(self):
        with self._lock:
            self._nosize = False
            self._gototls = False
            self._protocol_replies = 0
        self.disarm()

    def _fault_frame(self, streamid, status, body):
        tag = streamid[1]
        if tag == STAT_TAG:
            with self._lock:
                nosize = self._nosize
            if nosize and status == kXR_ok:
                return status, NO_SIZE_STAT
        elif tag == PROTOCOL_TAG:
            with self._lock:
                first = self._gototls and self._protocol_replies == 0
                if first:
                    self._protocol_replies = 1
            if first:
                return status, _with_goto_tls(body)
        return super()._fault_frame(streamid, status, body)


class _Planes:
    """The six acceptors, the one export they share, and the splice in front of
    the plane every pull reads from."""

    def __init__(self, endpoint, proxy):
        self.endpoint = endpoint
        self.proxy = proxy
        self.data_root = Path(endpoint.data_root)
        self.log_dir = Path(endpoint.prefix) / "logs"
        # Read the embedded listeners back off the started endpoint rather than
        # out of the ledger dict, so a plane the launcher resolved differently
        # fails here rather than silently testing the wrong server.
        extra = endpoint.extra_ports
        self.ports = {"armed": endpoint.port,
                      "disarmed": extra["OFF_PORT"],
                      "absent": extra["ABSENT_PORT"],
                      "pulling": extra["PULL_PORT"],
                      "ordering": extra["ORDER_PORT"],
                      "override": extra["DELEG_PORT"]}

    def port(self, plane):
        return self.ports[plane]

    def pull(self, plane, src_url, extra_opaque="", source_name=None):
        """Drive a TPC pull to ``plane`` and return (status, error text, dst).

        A unique destination per call: the export is shared by all six planes, so
        a name reused across cases would let one test's committed bytes answer
        another's question.

        ``source_name`` names the seeded file when the source is REAL, and with it
        this does the client's half of the rendezvous first.  Native TPC is two
        steps and the client owns the first: XrdCl opens the source with
        tpc.key+tpc.dst (``brix_tpc_key_register``,
        ``src/protocols/root/read/open_tpc.c:165``) and only then opens the
        destination, whose pull leg reopens the source with tpc.key+tpc.org and
        CONSUMES that entry.  Without the first step the source answers the
        destination "TPC authorization missing or expired" — a refusal about the
        key, not about the arm any of these tests is measuring.  Cases refused
        before the destination ever dials a source pass no ``source_name``: there
        is nothing to register a key against, and the gate answers first.
        """
        dst = f"/audit16v_dst_{uuid.uuid4().hex}.bin"
        # Single-use: brix_tpc_key_consume zeroes the slot, so a key is worth one
        # transfer and every call mints its own.
        key = uuid.uuid4().hex
        if source_name is not None:
            self.register(source_name, key, dst)
        status, err = _tpc_attempt(self.ports[plane], src_url, dst,
                                   extra_opaque=extra_opaque, key=key)
        return status, err, dst

    def register(self, source_name, key, dst):
        """Register ``key`` on the source the way the initiating client does.

        Straight at the ABSENT plane, not through the splice: the registry is one
        shared-memory table for the whole worker (``key_registry.c``), so the
        rendezvous is established wherever it is asked for, and keeping this leg
        off the splice leaves every faulted frame the destination's own.
        """
        sock = _handshake_login(HOST, self.ports["absent"])
        try:
            path = ("/%s?tpc.key=%s&tpc.dst=root://%s:%d//%s"
                    % (source_name.lstrip("/"), key, HOST,
                       self.ports["pulling"], dst.lstrip("/"))).encode()
            _close(sock, _open(sock, path + b"\x00", flags=kXR_open_read))
        finally:
            sock.close()

    def source_url(self, name, host=None, port=None):
        """A source URL pointing through the splice at the ABSENT plane."""
        return "root://%s:%d//%s" % (host or BIND_HOST,
                                     port if port is not None
                                     else self.proxy.listen,
                                     name.lstrip("/"))

    def seed(self, content=PAYLOAD):
        name = f"audit16v_src_{uuid.uuid4().hex}.bin"
        (self.data_root / name).write_bytes(content)
        return name

    def disk(self, remote):
        return self.data_root / remote.lstrip("/")

    def errorlog(self):
        try:
            return (self.log_dir / "error.log").read_text(encoding="utf-8",
                                                          errors="replace")
        except FileNotFoundError:
            return ""


@pytest.fixture(scope="module")
def planes(tmp_path_factory):
    """One instance, six planes, one splice — module-scoped because every plane
    is a static arm of a config, not a per-test variable."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    data = tmp_path_factory.mktemp("a16v_export")
    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16v_tpc_off_arms.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST},
        reason="audit-16v the seven directives_tpc.h flags whose disarming arm "
               "the corpus never wrote"))

    # The pull source is the ABSENT plane, reached only through the splice: the
    # planes under test never see the source socket directly, so every reply the
    # transfer-time gates read is one this file can rewrite.
    proxy = _TpcGateFaultProxy(HOST, endpoint.extra_ports["ABSENT_PORT"])
    proxy.start()
    if not _port_up(HOST, proxy.listen):
        proxy.stop()
        harness.close()
        pytest.fail("the pull-leg splice never listened")

    yield _Planes(endpoint, proxy)

    proxy.stop()
    harness.close()


@pytest.fixture
def clean_proxy(planes):
    """Every case states its own fault; none inherits the last one's."""
    planes.proxy.disarm_gate()
    yield planes.proxy
    planes.proxy.disarm_gate()


def _unresolvable():
    """A name the resolver must answer NXDOMAIN for (RFC 6761 .invalid)."""
    return f"audit16v-{uuid.uuid4().hex}.invalid"


def _assert_no_poison(planes, dst, content=PAYLOAD):
    """A refused pull must never leave a complete-looking copy behind.

    ``tpc_done_sync_fail`` unlinks the partial destination, but only when no
    writer plugin holds the handle — the same hedge ``test_tpc_pull_integrity``
    makes.  What must hold on every path is the weaker, sharper claim: whatever
    survives is not the source's file.
    """
    path = planes.disk(dst)
    if path.exists():
        assert path.read_bytes() != content, (
            "a refused pull left a complete copy at %s" % path)

