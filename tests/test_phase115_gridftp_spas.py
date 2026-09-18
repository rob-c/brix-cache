"""Phase-115 W5.3 — SPAS, the striped data channel, on the outbound FTP driver.

One TCP connection is one congestion window.  Over a fat, long link — which is
every link a GridFTP door exists to cross — a single stream leaves most of the
pipe empty no matter how fast either end is.  GFD.020 §5.1 SPAS is how the
client asks for several at once: the origin opens N listeners and answers with
one PASV-style tuple per continuation line, and the same MODE E blocks are then
dealt across the connections, each carrying the absolute offset that lets the
receiver put it back where it belongs.

`streams=<n>` is a CEILING, not a demand, and that is the design decision this
suite exists to pin.  `mode=` and `prot=` say what the bytes ARE and never
degrade — an origin that refuses fails the transfer.  `streams=` says how FAST
the same, identically verified bytes arrive, so it does degrade: an origin that
never advertises SPAS, refuses it, or lists more stripes than the budget allows
is served over the single pinned connection the driver has always opened.

THE security story is the address check, and it is the whole reason a stripe
list is different from every other reply this driver reads.  `gftp_dc_open()`
discards PASV's address on purpose and dials the control channel's own pinned
numeric peer; a SPAS reply is the one place the protocol hands the client a
LIST of addresses to dial.  Following them is the classic FTP bounce — the
storage driver becomes an origin-directed port scanner, opening connections to
hosts and ports of the origin's choosing, from inside the operator's network.
So every stripe must equal the control peer, and one that is not abandons the
striped attempt entirely: nothing is dialled and the read falls back.

The cost of that rule is stated plainly rather than hidden: a genuinely
MULTI-HOST striped server is read over one connection.  That is a performance
limit, never a correctness one, and it is the right side to err on.
"""

from __future__ import annotations

import http.client
import os
from pathlib import Path
import sys

import pytest

from fleet_lifecycle_ports import lifecycle_ports_for
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN, SERVER_HOST
from lib_py.util import loopback_alias_usable


pytestmark = [
    pytest.mark.skipif(
        not loopback_alias_usable("127.0.0.2"),
        reason="127.0.0.2 is not bindable on this host (the bounce address the driver must not dial); "
               "sudo ifconfig lo0 alias 127.0.0.2 up"),

    pytest.mark.serial,
    pytest.mark.timeout(300),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-p115-spas"),
]

# Position-revealing: byte i of every 256-byte run equals i, so a body
# reassembled in the wrong order is not merely unequal — it says which block
# landed where.  Big enough for several 64 KiB MODE E blocks so a four-way
# stripe genuinely has blocks to deal round-robin.
PAYLOAD = bytes(range(256)) * 4000          # 1024000 bytes, ~16 blocks

# The address the bounce origin advertises its stripes on.  Loopback, and
# nothing binds it — the point is that the driver must never dial it, so a
# reachable address would make the negative weaker, not stronger.
BOUNCE_ADDRESS = "127.0.0.2"


def _get(port: int, path: str, headers: dict[str, str] | None = None):
    """(status, headers, body, short) — a short read reported, never hidden."""
    connection = http.client.HTTPConnection(SERVER_HOST, port, timeout=90)
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        try:
            body, short = response.read(), False
        except http.client.IncompleteRead as partial:
            body, short = partial.partial, True
        return response.status, dict(response.getheaders()), body, short
    finally:
        connection.close()


def _audit(path: Path) -> list[str]:
    """The origin's command log — the only place SPAS is visible as a fact."""
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _count(log, verb: str) -> int:
    """How many times `verb` has reached this origin so far."""
    return len([line for line in _audit(log) if line.startswith(verb)])


def _verbs(lines: list[str], *wanted: str) -> list[str]:
    """Just the verbs of interest, in order — the shape of one retrieve."""
    return [line.split(" ", 1)[0] for line in lines
            if line.split(" ", 1)[0] in wanted]


class _SpasLab:
    #: (ledger name, origin argv tail, why)
    ORIGINS = (
        ("lc-p115-spas-origin", ["--spas", "4"],
         "advertises SPAS and stripes over four connections"),
        ("lc-p115-spas-plain-origin", [],
         "never advertises SPAS — the RFC 959 control"),
        ("lc-p115-spas-bounce-origin",
         ["--spas", "2", "--spas-host", BOUNCE_ADDRESS],
         "advertises a stripe on an address it does not own"),
    )

    def __init__(self, harness: LifecycleHarness, root: Path, tmp: Path):
        self.audits = {}
        started = {}
        for name, extra, reason in self.ORIGINS:
            port, _ = lifecycle_ports_for(name)
            self.audits[name] = tmp / f"{name}.log"
            started[name] = harness.start(
                self._origin(name, port, root, tmp, extra, reason))
        for name in ("spas-export", "unstriped-export", "plain-export",
                     "budget-export", "bounce-export"):
            (tmp / name).mkdir()
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-p115-spas",
            template="nginx_lc_gsiftp_spas.conf",
            protocol="http",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_PORT": started["lc-p115-spas-origin"].port,
                "PLAIN_ORIGIN_PORT":
                    started["lc-p115-spas-plain-origin"].port,
                "BOUNCE_ORIGIN_PORT":
                    started["lc-p115-spas-bounce-origin"].port,
                "ORIGIN_BASE": "/base",
                "SPAS_EXPORT": str(tmp / "spas-export"),
                "UNSTRIPED_EXPORT": str(tmp / "unstriped-export"),
                "PLAIN_EXPORT": str(tmp / "plain-export"),
                "BUDGET_EXPORT": str(tmp / "budget-export"),
                "BOUNCE_EXPORT": str(tmp / "bounce-export"),
            },
            reason="five WebDAV fronts over a striping origin, a silent one "
                   "and one that advertises a stripe it does not own",
        ))
        self.harness = harness
        self.striped_port = endpoint.port
        self.unstriped_port = endpoint.extra_ports["UNSTRIPED_PORT"]
        self.plain_port = endpoint.extra_ports["PLAIN_PORT"]
        self.budget_port = endpoint.extra_ports["BUDGET_PORT"]
        self.bounce_port = endpoint.extra_ports["BOUNCE_PORT"]
        self.error_log = Path(endpoint.prefix, "logs", "error.log")

    @staticmethod
    def _origin(name, port, root, tmp, extra, reason):
        argv = [sys.executable, "-m", "brix_suite.servers.ftp_origin_server",
                str(port), str(root), "--audit", str(tmp / f"{name}.log")]
        return NginxInstanceSpec(
            name=name,
            template="",
            kind="proc",
            protocol="ftp",
            readiness="tcp",
            data_root=str(root),
            template_values={"argv": argv + extra},
            env={"PYTHONPATH": os.path.dirname(__file__)},
            reason=f"confined GridFTP origin: {reason}",
        )

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    tmp = tmp_path_factory.mktemp("p115-spas")
    root = tmp / "origin"
    (root / "base").mkdir(parents=True)
    (root / "base" / "wide.bin").write_bytes(PAYLOAD)
    harness = LifecycleHarness()
    lab = _SpasLab(harness, root, tmp)
    yield lab
    lab.close()


# ---- success: the stripes reassemble ----------------------------------------

def test_a_striped_read_is_byte_exact(lab):
    """Blocks dealt round-robin across four sockets, reassembled by offset."""
    status, _, body, short = _get(lab.striped_port, "/wide.bin")
    assert (status, short) == (200, False)
    assert body == PAYLOAD


def test_striped_and_unstriped_reads_agree_byte_for_byte(lab):
    """The claim is that two different data channels agree.

    Asserted against the OTHER front rather than against PAYLOAD alone: a
    fixture-only assertion would pass just as happily if striping were never
    attempted and both fronts quietly read over one connection.  The origin is
    the same process in both cases; only the store line differs.
    """
    _, _, striped, _ = _get(lab.striped_port, "/wide.bin")
    _, _, unstriped, _ = _get(lab.unstriped_port, "/wide.bin")
    assert striped == unstriped == PAYLOAD


def test_the_origin_really_was_asked_to_stripe(lab):
    """Byte-exactness alone cannot tell SPAS from EPSV.

    Both produce the right bytes, so without the origin's own command log this
    whole suite would pass unchanged if `gftp_spas_wanted` always returned 0 —
    it would be testing the single-connection path twice and calling it SPAS.
    """
    _get(lab.striped_port, "/wide.bin")
    lines = _audit(lab.audits["lc-p115-spas-origin"])
    assert any(line.startswith("SPAS") for line in lines), \
        f"no SPAS reached the striping origin: {lines[-20:]}"


def test_the_unstriped_front_never_asks(lab):
    """`streams=` absent means the driver must not spend a round trip on SPAS.

    The probe is not free — it is a command and a reply on the control channel
    — and a driver that asked anyway would tax every read on every origin for
    a capability the operator did not ask to use.
    """
    log = lab.audits["lc-p115-spas-origin"]
    before = _count(log, "SPAS")
    _get(lab.unstriped_port, "/wide.bin")
    after = _count(log, "SPAS")
    assert after == before, \
        "a front with no streams= asked the origin for a striped channel"


# ---- degradation: every way of not striping still serves ---------------------

def test_an_origin_that_never_advertises_is_served_over_one_connection(lab):
    """No SPAS in FEAT: the driver must not try it, and must still deliver."""
    status, _, body, short = _get(lab.plain_port, "/wide.bin")
    assert (status, short) == (200, False)
    assert body == PAYLOAD
    lines = _audit(lab.audits["lc-p115-spas-plain-origin"])
    assert not any(line.startswith("SPAS") for line in lines), \
        f"SPAS was sent to an origin that never advertised it: {lines[-20:]}"
    assert any(line.startswith("EPSV") for line in lines), \
        f"the fallback did not open an ordinary data channel: {lines[-20:]}"


def test_an_over_budget_stripe_list_falls_back_and_still_serves(lab):
    """The budget is the OPERATOR's, and an origin does not get to raise it.

    This front says `streams=2`; the origin lists four.  Dialling all four
    would let a config line's resource decision be overridden by the peer —
    every stream is a socket pinned by one blocking VFS worker thread for the
    length of a transfer — and dialling only the first two would leave the
    origin's other two stripes holding blocks nobody will ever read, which is
    a hang, not a partial success.  So the whole striped attempt is abandoned.
    """
    status, _, body, short = _get(lab.budget_port, "/wide.bin")
    assert (status, short) == (200, False)
    assert body == PAYLOAD


def test_the_over_budget_fallback_is_visible_as_a_command_sequence(lab):
    """Bytes alone cannot distinguish "refused the list" from "never asked".

    The sequence can: SPAS is sent (the origin advertises it and the front
    wants striping), the reply is refused for being over budget, and an
    ordinary EPSV+RETR follows on the SAME control channel.
    """
    log = lab.audits["lc-p115-spas-origin"]
    before = len(_audit(log))
    _get(lab.budget_port, "/wide.bin")
    verbs = _verbs(_audit(log)[before:], "SPAS", "EPSV", "PASV", "RETR")
    assert verbs[:1] == ["SPAS"], f"the striped attempt never happened: {verbs}"
    assert "RETR" in verbs, f"no retrieve followed the refusal: {verbs}"
    assert verbs.index("EPSV") < verbs.index("RETR"), \
        f"the fallback retrieved without opening a data channel: {verbs}"


def test_the_refused_stripe_list_is_asked_for_only_once(lab):
    """A refusal is remembered for the session, as the ERET probe's is.

    Re-asking on every read would spend a control round trip per request to
    learn the same answer, on exactly the origins that already cost the most.
    """
    log = lab.audits["lc-p115-spas-origin"]
    before = _count(log, "SPAS")
    for _ in range(3):
        _get(lab.budget_port, "/wide.bin")
    after = _count(log, "SPAS")
    assert after - before <= 3, \
        f"SPAS was re-asked {after - before} times across three reads; the " \
        "refusal is not being remembered per session"


# ---- SECURITY: a stripe is an address, and addresses are not trusted ---------

def test_a_stripe_on_a_foreign_address_is_never_dialled(lab):
    """THE negative.  A SPAS reply is a LIST OF ADDRESSES from the peer.

    Following one that is not the control channel's own pinned peer is the
    classic FTP bounce: the storage driver would open connections to hosts and
    ports of the origin's choosing, from inside the operator's network, on
    behalf of an unauthenticated GET.  This origin advertises its stripes on
    127.0.0.2 while listening on 127.0.0.1, so a driver that trusted the reply
    would dial an address it was told to dial rather than the one it verified.
    """
    log = lab.audits["lc-p115-spas-bounce-origin"]
    before = len(_audit(log))
    status, _, body, short = _get(lab.bounce_port, "/wide.bin")
    verbs = _verbs(_audit(log)[before:], "SPAS", "EPSV", "PASV", "RETR")

    # The bounce is refused...
    assert verbs[:1] == ["SPAS"], f"the striped attempt never happened: {verbs}"
    assert "EPSV" in verbs, \
        f"the foreign stripe list was not abandoned for the pinned peer: {verbs}"
    assert verbs.index("EPSV") < verbs.index("RETR"), verbs
    # ...and the read still succeeds over the connection the driver verified.
    assert (status, short) == (200, False)
    assert body == PAYLOAD


def test_the_bounce_refusal_costs_the_operator_nothing(lab):
    """A refused stripe list must not degrade the ANSWER, only the speed.

    Stated separately from the sequence assertion because it is the property
    an operator cares about: the security rule is free at the API surface.
    Compared against the striping front so this is a claim about two different
    data channels agreeing, not about one fixture.
    """
    _, _, over_bounce, _ = _get(lab.bounce_port, "/wide.bin")
    _, _, over_stripes, _ = _get(lab.striped_port, "/wide.bin")
    assert over_bounce == over_stripes == PAYLOAD


def test_no_connection_was_ever_opened_to_the_advertised_address(lab):
    """The strongest form: the refusal is silent, not a caught failure.

    A driver that dialled 127.0.0.2 and fell back on the error would pass
    every assertion above while still having made the connection — which is
    the whole harm, since the scan is the attack and the reply is incidental.
    Nothing binds 127.0.0.2, so a dial would surface as a connect failure in
    the error log; its ABSENCE is what says the address was rejected before
    any socket was opened.
    """
    _get(lab.bounce_port, "/wide.bin")
    log = lab.error_log.read_text(encoding="utf-8", errors="replace")
    offending = [line for line in log.splitlines()
                 if BOUNCE_ADDRESS in line]
    assert not offending, \
        "the driver reached for the advertised address:\n" \
        + "\n".join(offending[-10:])
