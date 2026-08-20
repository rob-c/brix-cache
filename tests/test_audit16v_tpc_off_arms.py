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


# --------------------------------------------------------------------------- #
# A — brix_tpc_allow_local off: the address gate, and whether the token and the
#     omission are the same zero
# --------------------------------------------------------------------------- #
class TestTheAddressGateArm:

    def test_the_disarmed_plane_refuses_a_loopback_source(self, planes):
        """[error] The token, doing the thing no config had ever asked it to."""
        status, err, _dst = planes.pull("disarmed", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        assert status == kXR_error, status
        assert "resolves to a prohibited address" in err, err
        assert "allow_local=0" in err, err

    def test_the_absent_plane_refuses_it_identically(self, planes):
        """The claim the corpus has been resting on, measured.

        Four of the seven disarming arms are also the compiled default, and
        every existing test of them reads the default off a plane that writes
        nothing.  If the token and the omission ever diverged, everything those
        tests prove would be about a configuration no operator wrote.  Same
        refusal, same printed merge value, is what makes them interchangeable.
        """
        status, err, _dst = planes.pull("absent", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        assert status == kXR_error, status
        assert "resolves to a prohibited address" in err, err
        assert "allow_local=0" in err, err

    def test_the_armed_plane_admits_the_same_source(self, planes):
        """[success] The control: on with the same URL, the address gate is not
        what answers.  Some later leg may still fail — nothing is listening on
        the default TPC port — but not this one."""
        status, err, _dst = planes.pull("armed", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        assert status == kXR_error, status
        assert "prohibited" not in err, err

    def test_the_pulling_plane_admits_it_too(self, planes):
        """PULLING carries the ARMED value of this one directive; that is the
        whole reason it can measure the other six."""
        status, err, _dst = planes.pull("pulling", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        assert status == kXR_error, status
        assert "prohibited" not in err, err

    def test_link_local_follows_the_same_arm(self, planes):
        """The flag covers loopback AND link-local; the arm must not be read as
        "127/8 only"."""
        status, err, _dst = planes.pull("disarmed", "root://169.254.0.1//x.dat")
        assert status == kXR_error, status
        assert "resolves to a prohibited address" in err, err
        status, err, _dst = planes.pull("pulling", "root://169.254.0.1//x.dat")
        assert status == kXR_error, status
        assert "prohibited" not in err, err

    def test_the_arm_does_not_reach_private_ranges(self, planes):
        """[security-neg, inverted] A disarming arm that refused MORE than it
        governs would look like a working gate while breaking unrelated pulls.
        RFC-1918 is brix_tpc_allow_private's business (default on, deliberately
        untouched by this config), so it must pass the same plane that just
        refused loopback."""
        status, err, _dst = planes.pull("disarmed", "root://10.255.255.1//x.dat")
        assert status == kXR_error, status
        assert "prohibited" not in err, (
            "allow_local off must not close the private ranges: %r" % err)

    def test_the_refusal_prints_the_merged_value(self, planes):
        """Why this arm is measurable at all rather than inferred.

        ``net_target_dns.c`` formats both flags into the refusal, so "the
        explicit off produced the same merged value as the omission" is read off
        the wire instead of argued from the merge function.
        """
        _s, off_err, _d = planes.pull("disarmed", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        _s, absent_err, _d = planes.pull("absent", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arm under test governs
        assert "allow_local=0 allow_private=1" in off_err, off_err
        assert "allow_local=0 allow_private=1" in absent_err, absent_err


# --------------------------------------------------------------------------- #
# B — brix_tpc_source_guard off: the naming gate
# --------------------------------------------------------------------------- #
class TestTheNamingGateArm:

    # A loopback literal on NEITHER allowlist: the guard matches the string the
    # client asked for, so 127.0.0.2 and 127.0.0.1 are two different hosts even
    # though one machine answers both.
    UNLISTED = "127.0.0.2"  # net-literal-allow: an unlisted loopback literal is the point

    def test_the_armed_plane_refuses_a_host_off_the_allowlist(self, planes):
        """[error] The arm the corpus writes, refusing by NAME."""
        status, err, _dst = planes.pull(
            "armed", f"root://{self.UNLISTED}//x.dat")
        assert status == kXR_error, status
        assert "TPC source host not permitted" in err, err
        assert self.UNLISTED in err, err

    def test_the_pulling_plane_admits_it(self, planes):
        """The token nothing had written: the guard is off, so the name is not
        consulted and the pull proceeds to the gates that follow."""
        status, err, _dst = planes.pull(
            "pulling", f"root://{self.UNLISTED}//x.dat")
        assert status == kXR_error, status
        assert "not permitted" not in err, err

    def test_the_absent_plane_matches_the_explicit_off(self, planes):
        """ABSENT writes neither guard, and this plane also leaves allow_local
        unset — so the refusal it gives is the ADDRESS gate's, which is itself
        the proof that the naming gate stayed silent."""
        status, err, _dst = planes.pull(
            "absent", f"root://{self.UNLISTED}//x.dat")
        assert status == kXR_error, status
        assert "not permitted" not in err, err
        assert "resolves to a prohibited address" in err, err

    def test_the_two_gates_are_distinguishable_on_one_url(self, planes):
        """One source, four answers — which is what makes the messages evidence.

        ARMED refuses by name; DISARMED (guard off, allow_local off) refuses by
        address; PULLING refuses by neither; ORDERING has both armed and answers
        with the naming gate, which is §C's subject.
        """
        url = f"root://{self.UNLISTED}//x.dat"
        _s, armed, _d = planes.pull("armed", url)
        _s, disarmed, _d = planes.pull("disarmed", url)
        _s, pulling, _d = planes.pull("pulling", url)
        assert "not permitted" in armed and "prohibited" not in armed, armed
        assert "prohibited" in disarmed and "not permitted" not in disarmed, \
            disarmed
        assert "not permitted" not in pulling and "prohibited" not in pulling, \
            pulling

    def test_the_allowlist_admits_the_names_it_lists(self, planes):
        """[success] The guard is an allowlist, not a blocklist: the two entries
        ARMED does write must pass it."""
        # net-literal-allow: the allowlist entries under test are loopback names
        for host in ("localhost", BIND_HOST):  # net-literal-allow: as above
            status, err, _dst = planes.pull("armed", f"root://{host}//x.dat")
            assert status == kXR_error, status
            assert "not permitted" not in err, (host, err)


# --------------------------------------------------------------------------- #
# C — the order of the two gates, which is a security property of its own
# --------------------------------------------------------------------------- #
class TestWhichGateAnswersFirst:

    def test_a_loopback_literal_gets_the_naming_refusal(self, planes):
        """ORDERING has the naming gate armed and the address gate closed, so
        both would refuse.  The one that answers is the one that ran first."""
        status, err, _dst = planes.pull("ordering", "root://127.0.0.2//x.dat")  # net-literal-allow: an unlisted loopback literal both gates would refuse
        assert status == kXR_error, status
        assert "TPC source host not permitted" in err, err
        assert "prohibited" not in err, err

    def test_an_unresolvable_name_is_refused_without_a_lookup(self, planes):
        """[security-neg] The guard must not be a DNS oracle.

        A host the operator never allowlisted is refused on its NAME, so an
        attacker cannot use a TPC request to make the server resolve arbitrary
        names.  ``net_resolve_host`` has its own distinct message; seeing the
        guard's instead is what proves no lookup happened.
        """
        status, err, _dst = planes.pull(
            "ordering", f"root://{_unresolvable()}//x.dat")
        assert status == kXR_error, status
        assert "TPC source host not permitted" in err, err
        assert "DNS resolution failed" not in err, err

    def test_a_listed_name_then_meets_the_address_gate(self, planes):
        """Both gates are live on this plane — otherwise the test above would
        pass on a server whose address gate was simply broken."""
        status, err, _dst = planes.pull("ordering", "root://localhost//x.dat")  # net-literal-allow: the ORDERING allowlist entry is a loopback name
        assert status == kXR_error, status
        assert "not permitted" not in err, err
        assert "prohibited" in err and "allow_local=0" in err, err

    def test_a_guardless_plane_does_reach_the_resolver(self, planes):
        """The other half: with the guard off the same unresolvable name gets a
        DNS failure, so the silence on ORDERING was the guard's doing and not a
        resolver that never answers."""
        status, err, _dst = planes.pull(
            "pulling", f"root://{_unresolvable()}//x.dat")
        assert status == kXR_error, status
        assert "DNS resolution failed" in err, err

    def test_the_c_runs_the_guard_before_the_policy(self):
        """The source pin behind the whole section."""
        text = _source(PREPARE_C)
        guard = text.index("brix_tpc_source_guard_check(")
        policy = text.index("brix_tpc_check_src_policy(", guard)
        assert guard < policy, "the naming gate no longer precedes the address gate"
        assert "without a DNS lookup" in text[:policy], (
            "the ordering is no longer documented as deliberate")
        assert "TPC source host not permitted" in _source(GUARD_C)


# --------------------------------------------------------------------------- #
# D — brix_require_pgwrite off: the wire-integrity gate on native uploads
# --------------------------------------------------------------------------- #
class TestTheCleartextWriteArm:

    def _upload(self, planes, plane, remote, data):
        sock = _handshake_login(HOST, planes.port(plane))
        try:
            fh = _open(sock, remote.encode())
            status, err = _write(sock, fh, 0, data)
            if status == kXR_OK:
                _close(sock, fh)
            return status, err
        finally:
            sock.close()

    def test_the_armed_plane_refuses_a_cleartext_write(self, planes):
        """[error] The arm the corpus writes."""
        remote = f"/audit16v_pgw_on_{uuid.uuid4().hex}.bin"
        status, err = self._upload(planes, "armed", remote, os.urandom(4096))
        assert status == kXR_error, status
        assert err == kXR_Unsupported, err
        path = planes.disk(remote)
        assert not path.exists() or path.stat().st_size == 0, \
            "a refused cleartext write must not commit bytes"

    def test_the_disarmed_plane_accepts_it(self, planes):
        """[the token] What ``brix_require_pgwrite off`` buys: the stock upload
        op, back."""
        remote = f"/audit16v_pgw_off_{uuid.uuid4().hex}.bin"
        data = os.urandom(4096)
        status, err = self._upload(planes, "disarmed", remote, data)
        assert status == kXR_OK, (status, err)
        assert planes.disk(remote).read_bytes() == data

    def test_the_absent_plane_accepts_it_identically(self, planes):
        """``nginx_root_require_pgwrite.conf`` says of its OFF_PORT plane that
        the directive is "deliberately omitted (default off)" and tests the
        permissive path there.  This is the assertion that entitles it to."""
        remote = f"/audit16v_pgw_absent_{uuid.uuid4().hex}.bin"
        data = os.urandom(4096)
        status, err = self._upload(planes, "absent", remote, data)
        assert status == kXR_OK, (status, err)
        assert planes.disk(remote).read_bytes() == data

    def test_the_armed_plane_refuses_writev_too(self, planes):
        """[security-neg] kXR_writev is the sibling op with no CRC; a gate that
        only closed kXR_write would be trivially side-stepped."""
        remote = f"/audit16v_pgw_wv_{uuid.uuid4().hex}.bin"
        sock = _handshake_login(HOST, planes.port("armed"))
        try:
            fh = _open(sock, remote.encode())
            status, err = _writev(sock, [(fh, 0, os.urandom(2048))])
        finally:
            sock.close()
        assert status == kXR_error, status
        assert err == kXR_Unsupported, err
        path = planes.disk(remote)
        assert not path.exists() or path.stat().st_size == 0

    def test_the_armed_plane_still_takes_a_pgwrite(self, planes):
        """[success / no false positive] The gate names the path it wants; the
        arm is only meaningful if that path still works beside all six of the
        TPC directives this plane also carries."""
        remote = f"/audit16v_pgw_ok_{uuid.uuid4().hex}.bin"
        data = os.urandom(6000)
        sock = _handshake_login(HOST, planes.port("armed"))
        try:
            fh = _open(sock, remote.encode())
            status, _off, cse = send_pgwrite(sock, fh, 0,
                                             build_payload(data, 0))
            assert status == kXR_status and cse == b"", (status, cse)
            status, err = _close(sock, fh)
            assert status == kXR_OK, (status, err)
        finally:
            sock.close()
        assert planes.disk(remote).read_bytes() == data


# --------------------------------------------------------------------------- #
# E — per-server independence: one worker, six answers
# --------------------------------------------------------------------------- #
class TestPerServerIndependence:

    def test_one_worker_holds_every_arm_at_once(self, planes):
        """None of the seven has a MAIN-level arm, so ``server {}`` is the only
        scope that can hold a value and the planes are the only unit of
        difference.  A shared bit anywhere — a merge that wrote through to the
        wrong conf, a slot offset transposed in the header — collapses this.

        Five planes, four distinct verdicts on ONE url.  ORDERING's is the odd
        one: its allowlist holds ``localhost`` alone, so the literal never
        reaches the address gate at all and it answers with the naming refusal —
        which is the §C ordering, restated here as a per-server fact.
        """
        url = "root://127.0.0.1//x.dat"  # net-literal-allow: the loopback source the arms govern
        verdicts = {}
        for plane in ("armed", "disarmed", "absent", "pulling", "ordering"):
            _s, err, _d = planes.pull(plane, url)
            verdicts[plane] = err
        assert "prohibited" in verdicts["disarmed"], verdicts
        assert "prohibited" in verdicts["absent"], verdicts
        assert "not permitted" in verdicts["ordering"], verdicts
        assert "prohibited" not in verdicts["ordering"], verdicts
        assert "prohibited" not in verdicts["armed"], verdicts
        assert "prohibited" not in verdicts["pulling"], verdicts

    def test_a_refusal_on_one_plane_does_not_follow_the_next(self, planes):
        """Sequenced deliberately: the refusing plane is asked first, so a
        verdict cached anywhere process-wide would be visible here."""
        _s, refused, _d = planes.pull("disarmed", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arms govern
        assert "prohibited" in refused, refused
        _s, allowed, _d = planes.pull("pulling", "root://127.0.0.1//x.dat")  # net-literal-allow: the loopback source the arms govern
        assert "prohibited" not in allowed, allowed

    def test_the_write_arms_are_independent_too(self, planes):
        """The same, on the directive that lives in ``common`` rather than in
        the TPC block: a refusal on ARMED and an acceptance on PULLING, over one
        export, in one process."""
        refused = f"/audit16v_ind_on_{uuid.uuid4().hex}.bin"
        sock = _handshake_login(HOST, planes.port("armed"))
        try:
            status, err = _write(sock, _open(sock, refused.encode()), 0,
                                 os.urandom(1024))
        finally:
            sock.close()
        assert status == kXR_error and err == kXR_Unsupported, (status, err)

        allowed = f"/audit16v_ind_off_{uuid.uuid4().hex}.bin"
        data = os.urandom(1024)
        sock = _handshake_login(HOST, planes.port("pulling"))
        try:
            fh = _open(sock, allowed.encode())
            status, err = _write(sock, fh, 0, data)
            assert status == kXR_OK, (status, err)
            _close(sock, fh)
        finally:
            sock.close()
        assert planes.disk(allowed).read_bytes() == data


# --------------------------------------------------------------------------- #
# F — brix_tpc_require_source_size off: what an unverifiable copy is worth
# --------------------------------------------------------------------------- #
class TestTheSourceSizeArm:

    def test_a_clean_pull_completes_on_the_pulling_plane(self, planes,
                                                         clean_proxy):
        """[success] The floor everything below stands on: with no fault armed,
        the splice is a wire and the disarmed plane copies byte-exact."""
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_a_clean_pull_completes_on_the_armed_plane_too(self, planes,
                                                           clean_proxy):
        """[no false positive] ``require_source_size on`` must not cost a pull
        from a source that does declare one — which every brix source does."""
        name = planes.seed()
        status, err, dst = planes.pull("armed", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_the_armed_plane_refuses_a_source_that_declares_no_size(
            self, planes, clean_proxy):
        """[error] The gate doing its job: a source that answers the stat but
        will not say how big the file is leaves the destination with nothing to
        check the copy against, so the copy is refused."""
        clean_proxy.arm_gate(nosize=True)
        name = planes.seed()
        status, err, dst = planes.pull("armed", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_error, (status, err)
        assert "source declared no size" in err, err
        assert "brix_tpc_require_source_size is on" in err, err
        _assert_no_poison(planes, dst)

    def test_the_disarmed_arm_commits_the_unverifiable_copy(self, planes,
                                                            clean_proxy):
        """[the token] The same source, the same lie, the arm nobody wrote: the
        pull succeeds.  The bytes happen to be right — nothing on the
        destination knows that."""
        clean_proxy.arm_gate(nosize=True)
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_the_disarmed_arm_commits_a_short_copy_as_complete(self, planes,
                                                               clean_proxy):
        """[security-neg] What the off arm actually costs.

        The size gate is otherwise ALWAYS on — a delivered byte count that
        disagrees with the stat fails closed on every server.  Take the declared
        size away and that gate has nothing to compare against, so a truncated
        stream — half a frame and a forged EOF, a perfectly valid frame
        sequence — commits as a complete file.  This is the poison
        ``brix_tpc_require_source_size on`` exists to refuse, and the reason the
        arm is not merely a matter of taste.
        """
        clean_proxy.arm_gate(nosize=True, truncate=True)
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        committed = planes.disk(dst).read_bytes()
        assert len(committed) < len(PAYLOAD), (
            "the splice did not truncate; this case proves nothing otherwise")
        assert committed == PAYLOAD[:len(committed)]

    def test_the_always_on_gate_still_catches_truncation(self, planes,
                                                         clean_proxy):
        """The boundary of the finding above: ``off`` disables the DECLARATION
        requirement, never the comparison.  Truncate a pull whose source did
        declare its size and the disarmed plane fails it closed like any
        other."""
        clean_proxy.arm_gate(truncate=True)
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_error, (status, err)
        assert "TPC pull truncated" in err, err
        _assert_no_poison(planes, dst)

    def test_the_gate_is_one_branch_of_the_completion_check(self):
        """Source pin: the two arms are the two branches of one ``if``."""
        text = _source(STREAM_C)
        assert "if (t->src_size_known) {" in text, text[:0]
        assert "} else if (t->conf != NULL && t->conf->tpc_require_source_size)" \
            in text
        assert "brix_tpc_require_source_size is on" in text


# --------------------------------------------------------------------------- #
# G — brix_tpc_outbound_tls off: refusing to be dragged into TLS
# --------------------------------------------------------------------------- #
class TestTheOutboundTlsArm:

    def test_the_disarmed_arm_refuses_a_tls_demanding_source(self, planes,
                                                             clean_proxy):
        """[the token, and it is the fail-CLOSED one] Uniquely among the seven,
        this arm's ``off`` refuses where ``on`` continues: a source that answers
        kXR_gotoTLS is telling the destination that everything after the
        protocol reply must ride TLS, and a destination that cannot do that must
        stop rather than keep talking in cleartext."""
        clean_proxy.arm_gate(gototls=True)
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_error, (status, err)
        assert "TPC source requires TLS" in err, err
        assert "set brix_tpc_outbound_tls on" in err, err
        _assert_no_poison(planes, dst)

    def test_the_armed_arm_attempts_the_upgrade_instead(self, planes,
                                                        clean_proxy):
        """The other side of the same frame: with the directive on the
        destination honours the demand and starts a handshake.  The splice is
        not a TLS endpoint, so the pull still fails — but on the handshake, not
        on the policy, and the two are told apart by the message."""
        clean_proxy.arm_gate(gototls=True)
        name = planes.seed()
        status, err, dst = planes.pull("armed", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_error, (status, err)
        assert "set brix_tpc_outbound_tls on" not in err, err
        _assert_no_poison(planes, dst)

    def test_a_clean_source_is_unaffected_by_either_arm(self, planes,
                                                        clean_proxy):
        """[no false positive] Neither arm changes a pull from a source that
        never asks for TLS — which is what keeps the armed plane's clean pull in
        §F honest."""
        name = planes.seed()
        for plane in ("armed", "pulling"):
            status, err, dst = planes.pull(plane, planes.source_url(name),
                                           source_name=name)
            assert status == kXR_OK, (plane, status, err)
            assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_the_advertisement_is_gated_by_the_same_flag(self):
        """Source pin: the flag decides both what is advertised and what is done
        with the answer, which is why an off destination normally never sees a
        gotoTLS at all and the splice has to forge one."""
        text = _source(BOOTSTRAP_C)
        assert "t->conf->tpc_outbound_tls ? kXR_ableTLS : 0" in text
        assert "if (!t->conf->tpc_outbound_tls) {" in text
        assert "TPC source requires TLS; set brix_tpc_outbound_tls on" in text


# --------------------------------------------------------------------------- #
# H — brix_tpc_outbound_passthrough on: a default-on flag that must never deny
# --------------------------------------------------------------------------- #
class TestTheOutboundPassthroughArm:

    def test_the_on_arm_never_denies_an_anonymous_pull(self, planes,
                                                       clean_proxy):
        """The property the default exists to preserve: an anonymous pull that
        worked before the flag became default-on still works, because the
        opportunistic mode treats a missing inbound token as "nothing to
        forward" rather than as a refusal."""
        name = planes.seed()
        status, err, dst = planes.pull("pulling", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_the_off_arm_does_not_deny_one_either(self, planes, clean_proxy):
        """And the arm the corpus writes costs nothing here — the difference
        between the two is which token is FORWARDED, not who is admitted."""
        name = planes.seed()
        status, err, dst = planes.pull("armed", planes.source_url(name),
                                       source_name=name)
        assert status == kXR_OK, (status, err)
        assert planes.disk(dst).read_bytes() == PAYLOAD

    def test_an_explicit_passthrough_is_refused_on_the_on_arm(self, planes,
                                                              clean_proxy):
        """[security-neg] The distinction the default-on flag must not blur: a
        CLIENT that explicitly asks for ``tpc.token_mode=passthrough`` gets
        strict, fail-closed semantics, and the server-side default does not
        quietly downgrade that request to the opportunistic mode."""
        name = planes.seed()
        status, err, dst = planes.pull(
            "pulling", planes.source_url(name), source_name=name,
            extra_opaque="tpc.token_mode=passthrough")
        assert status == kXR_error, (status, err)
        assert "passthrough requested but no inbound bearer" in err, err
        _assert_no_poison(planes, dst)

    def test_an_explicit_passthrough_is_refused_on_the_off_arm_too(
            self, planes, clean_proxy):
        """Neither arm rescues it: the client's own field wins verbatim, which
        is what makes the flag's two arms a choice about the DEFAULT and not
        about what a client may ask for."""
        name = planes.seed()
        status, err, dst = planes.pull(
            "armed", planes.source_url(name), source_name=name,
            extra_opaque="tpc.token_mode=passthrough")
        assert status == kXR_error, (status, err)
        assert "passthrough requested but no inbound bearer" in err, err
        _assert_no_poison(planes, dst)

    def test_the_three_way_decision_is_in_one_place(self):
        """Source pin.  The behavioural cases above cannot separate "flag off"
        from "flag on with no inbound token" — both leave nothing to forward —
        so what the arms differ in is pinned to the C that decides it."""
        text = _source(PREPARE_C)
        idx = text.index("if (tpc->has_token_mode && tpc->token_mode[0]")
        window = text[idx:idx + 600]
        assert "} else if (conf->tpc_outbound_passthrough) {" in window, window
        assert '"passthrough-opt"' in window, window
        assert "file->tpc_token_mode[0] = '\\0';" in window, window


# --------------------------------------------------------------------------- #
# I — brix_tpc_delegate off, and the postconfiguration that ignores it
# --------------------------------------------------------------------------- #
class TestTheDelegationArmAndItsOverride:
    """DEFECT CANDIDATE #99.

    ``brix_config_prepare_server`` (``runtime_server.c:441-448``) turns delegation
    back ON whenever a tap proxy authenticates with GSI, guarded by
    ``!xcf->tpc_delegate``.  It runs from ``postconfiguration``, i.e. AFTER the
    merge — and after the merge an explicit ``off`` and an unwritten directive
    are the same zero.  So the operator who deliberately wrote
    ``brix_tpc_delegate off`` beside a GSI tap proxy gets delegation enabled
    anyway, and the NOTICE that reports it reads as though nothing was
    overridden.  The upgrade may well be the right default; being unable to
    decline it is the finding.
    """

    NOTICE = "brix_tap_proxy_auth gsi: enabling GSI proxy delegation capture"

    def test_the_override_plane_reports_the_upgrade(self, planes):
        """The OVERRIDE plane writes ``off`` and the server says it enabled it."""
        assert self.NOTICE in planes.errorlog(), (
            "the tap-proxy delegation upgrade no longer reports itself; if it "
            "now honours the explicit off, this file's finding is fixed and the "
            "section should say so")

    def test_no_other_plane_reports_it(self, planes):
        """One plane per LOAD, which is the only form the claim can take.

        The upgrade is decided at configuration time and the config is loaded
        more than once into one error.log (the launcher validates the file, then
        starts it), so a bare count over the log counts loads rather than planes.
        The line nginx cites cannot separate them either — postconfiguration runs
        after the parse, so every conf-time notice cites the last line of the
        file.  What does separate them is that each plane announces its own access
        log once per load: count the announcements of a plane that has NO tap
        proxy and that is the load count, and the NOTICE must appear exactly that
        often.  Five planes write or omit ``brix_tpc_delegate`` without a proxy
        and none of them is reported, so the upgrade follows the proxy rather
        than the directive.
        """
        log = planes.errorlog()
        loads = log.count('/armed.log" registered')
        assert loads >= 1, log
        assert log.count(self.NOTICE) == loads, log

    def test_the_c_cannot_tell_an_explicit_off_from_an_omission(self):
        """Why the operator has no way to decline: by the time the test runs,
        the value it inspects has already been merged."""
        text = _source(RUNTIME_C)
        idx = text.index("BRIX_PROXY_AUTH_GSI")
        window = text[idx:idx + 400]
        assert "!xcf->tpc_delegate" in window, window
        assert "xcf->tpc_delegate = 1;" in window, window
        assert "brix_config_prepare_server" in _source(POSTCONF_C), (
            "the upgrade is no longer reached from postconfiguration; recheck "
            "whether it still runs after the merge")

    def test_the_directive_has_no_third_state(self):
        """``ngx_conf_set_flag_slot`` stores 0 or 1 and ``NGX_CONF_UNSET`` is
        gone after the merge — so "the operator said off" is not recoverable
        later even in principle.  Any fix has to record the write, not re-read
        the value."""
        text = _source(DIRECTIVES_H)
        block = text.split('ngx_string("brix_tpc_delegate")')[1][:300]
        assert "ngx_conf_set_flag_slot" in block, block
        assert "NGX_CONF_FLAG" in block, block

    def test_the_arm_governs_a_login_round_and_not_only_a_pull(self):
        """Source pin: what the operator is unable to decline.

        The overridden flag is not read only at pull launch.  It also decides
        whether a VERIFIED GSI login is completed or answered with kXGS_pxyreq —
        an extra handshake round demanded of every GSI client on the server
        (``auth/gsi/auth_cert.c``), where a client that cannot sign the
        delegated proxy is refused kXR_NotAuthorized.  So an operator who writes
        ``off`` beside a GSI tap proxy is silently opted back in to a change in
        what logging in REQUIRES, which is why the override is a finding rather
        than a note about a default.
        """
        text = _source(AUTH_CERT_C)
        idx = text.index("if (conf->tpc_delegate && !ctx->gsi.deleg_await")
        window = text[idx:idx + 500]
        assert "brix_gsi_begin_delegation" in window, window
        assert "GSI proxy delegation failed" in window, window
        assert "kXR_NotAuthorized" in window, window


# --------------------------------------------------------------------------- #
# J — the census: the gap is a fact about the corpus, so it is asserted there
# --------------------------------------------------------------------------- #
class TestTheArmsAtConfigTime:

    def test_this_file_is_the_only_writer_of_the_disarming_arms(self):
        """All seven rows of the census, in one assertion.

        If another config starts writing one of these arms, this is where that
        becomes visible — either the new writer covers it and a plane here is
        redundant, or it is a placeholder rendering and the census is being
        satisfied by something ungreppable.
        """
        for directive, value in sorted(DISARMING_ARM.items()):
            writers = _corpus_writers(directive, value)
            assert writers == ["nginx_audit16v_tpc_off_arms.conf"], (
                f"{directive} {value} is written by {writers}")

    def test_the_arming_arm_was_already_written(self):
        """The asymmetry that IS the gap: every one of the seven had its other
        arm spelled somewhere before this file existed."""
        for directive, value in sorted(ARMING_ARM.items()):
            writers = [w for w in _corpus_writers(directive, value)
                       if w != "nginx_audit16v_tpc_off_arms.conf"]
            assert writers, f"{directive} {value} was never written either"

    def test_the_template_spells_every_arm_literally(self):
        """Not through a placeholder.  The audit counts an arm as covered only
        when ``<directive> <value>;`` is greppable, so a ``{SLOT}`` that renders
        to ``off`` would exercise the path and leave the next census reporting
        the same gap."""
        text = _source(TEMPLATE)
        for directive, value in sorted(DISARMING_ARM.items()):
            assert _writes(text, directive, value), \
                f"{directive} {value}; is not spelled literally"
            assert _writes(text, directive, ARMING_ARM[directive]), \
                f"{directive} {ARMING_ARM[directive]}; is not spelled literally"

    def test_the_template_writes_each_arm_the_expected_number_of_times(self):
        """A whole-line scan, not a substring count — the file's own header
        names all seven directives repeatedly, and counting those would let a
        config that writes nothing at all look fully armed."""
        text = _source(TEMPLATE)
        expected = {
            # ARMED, DISARMED, PULLING, ORDERING
            "brix_tpc_allow_local": ["on", "off", "on", "off"],
            # ARMED, DISARMED, PULLING, ORDERING
            "brix_tpc_source_guard": ["on", "off", "off", "on"],
            # ARMED, DISARMED, PULLING
            "brix_require_pgwrite": ["on", "off", "off"],
            "brix_tpc_outbound_tls": ["on", "off", "off"],
            "brix_tpc_require_source_size": ["on", "off", "off"],
            "brix_tpc_outbound_passthrough": ["off", "on", "on"],
            # ARMED, DISARMED, PULLING, OVERRIDE
            "brix_tpc_delegate": ["on", "off", "off", "off"],
        }
        for directive, arms in sorted(expected.items()):
            found = re.findall(rf"^\s*{directive}\s+(on|off)\s*;\s*$",
                               text, re.MULTILINE)
            assert found == arms, (directive, found)

    def test_the_absent_plane_writes_none_of_the_seven(self):
        """The plane that measures the defaults must not accidentally set one."""
        text = _source(TEMPLATE)
        block = text.split("ABSENT:")[1].split("PULLING:")[0]
        for directive in sorted(DISARMING_ARM):
            assert directive not in block, (directive, block)

    def test_the_ledger_names_every_plane_the_file_uses(self):
        """The instance is shared-port; a plane the ledger does not know about
        is a port nothing reserves.  Read back from the config rather than from
        this module's own constants, so a listener added to the template without
        a ledger slot fails here."""
        text = _source(TEMPLATE)
        placeholders = set(re.findall(r"listen \{(\w+)\}", text))
        assert placeholders == {"PORT"} | set(_EXTRA), (placeholders,
                                                        set(_EXTRA))
        assert len(set(_EXTRA.values())) == len(_EXTRA), _EXTRA
        assert LIFECYCLE_SHARED_PORTS[NAME]["port"] not in _EXTRA.values()

    def test_every_directive_is_a_server_scoped_flag(self):
        """Why the file has six planes and no ``stream {}``-level case: not one
        of the seven carries ``NGX_STREAM_MAIN_CONF``, so a plane is the only
        thing that can hold a value and there is no inheritance to override."""
        text = _source(DIRECTIVES_H)
        for directive in sorted(DISARMING_ARM):
            block = text.split(f'ngx_string("{directive}")')[1][:300]
            assert "NGX_STREAM_SRV_CONF | NGX_CONF_FLAG" in block, \
                (directive, block)
            assert "NGX_STREAM_MAIN_CONF" not in block, (directive, block)
            assert "ngx_conf_set_flag_slot" in block, (directive, block)
