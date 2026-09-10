"""
tests/test_phase115_ssi_client.py — the native SSI client (phase-115 W8.6).

Until this row, the SSI plane's only wire client was C++ libXrdSsi
(``tests/test_ssi_wire.py::TestSsiRealClient``, which builds against the stock
XRootD stack and skips wherever that stack is absent). The pure-C client could
not reach its own server's SSI surface at all. ``client/lib/protocols/ssi/``
closes that: this suite drives ``client/bin/ssi_client_smoke``, whose whole
point is that ``ldd`` shows no libXrdSsi / libXrdCl / libXrdSec anywhere.

WHAT THIS PINS — the three things the implementation discovered:

1. **One control word, two carriers.** ``XrdSsiRRInfo`` rides the *offset field*
   of kXR_read/kXR_write and the *payload* of kXR_query. Putting it in the wrong
   place must be refused, not decoded from whatever happens to sit there
   (:class:`TestSsiClientSecurity`).

2. **Two reply paths the caller must not be able to tell apart.** A synchronous
   service answers a PULL (``kXR_query(Rwt)`` → ``kXR_ok``); a deferring service
   answers ``kXR_waitresp`` and then PUSHES ``kXR_attn(asynresp)`` frames. Both
   carry the identical ``[RRInfoAttn 16][metadata][data]`` envelope, and
   ``src/protocols/root/response/async.c`` builds the same envelope for an alert
   and for the terminal response — so ``body[0]``, the tag, is the *only*
   discriminator. ``echo`` vs ``echo-async`` is the compat statement.

3. **The data length is stated nowhere on the wire.** It is recoverable only as
   ``total - pfx_len - md_len`` (exactly what ``XrdSsiTaskReal::GetResp()``
   does), which is why ``brix_ssi_attn_decode`` lives in the shared codec rather
   than being hand-rolled at the read site: the two halves get swapped there.
   The ``meta`` service proves the split, because both halves are non-empty.

Run:
    TEST_ROOT=/tmp/xrd-p115w86 TEST_PORT_START=25000 PYTHONPATH=tests \
        pytest tests/test_phase115_ssi_client.py -v -p no:randomly
"""

import os
from pathlib import Path
import shutil
import subprocess
from brix_suite.client_build import client_make

import pytest

from settings import HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-ssi-client")]

REPO = Path(__file__).resolve().parent.parent
CLIENT_DIR = REPO / "client"
DRIVER = CLIENT_DIR / "bin" / "ssi_client_smoke"

REQUEST = "hello ssi world"
STREAM_BODY = b"part-A|part-B|part-C"      # svc_stream's three chunks

# src/protocols/ssi/ssi_service.c's built-in table, in declaration order.
SERVICES = ("echo", "meta", "stream", "err",
            "echo-async", "stream-async", "alert-async")

kXR_ArgInvalid = 3000     # XProtocol's first error code; errno 22 maps here


# --------------------------------------------------------------------------- #
# driving the C driver                                                          #
# --------------------------------------------------------------------------- #

def _ensure_driver():
    """Build the driver on demand; skip when it cannot be built."""
    if DRIVER.exists():
        return
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler / ssi_client_smoke not built")
    client_make(str(CLIENT_DIR), "ssi-client-smoke", capture_output=True, text=True, timeout=300)
    if not DRIVER.exists():
        pytest.skip("ssi_client_smoke build failed "
                    "(make -C client ssi-client-smoke)")


def _drive(port, service, request=REQUEST, mode="run"):
    """Run one driver invocation; return (rc, stdout lines, stderr).

    The driver's stdout is a CONTRACT, not debug output: every payload is hex so
    it can never be confused with a delimiter or mangled by shell quoting.
    """
    _ensure_driver()
    proc = subprocess.run(
        [str(DRIVER), f"root://{HOST}:{port}", service, request, mode],
        capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stdout.splitlines(), proc.stderr


def _field(line, key):
    """Value of the ``key=<v>`` token in a transcript line."""
    for token in line.split(" "):
        if token.startswith(key + "="):
            return token[len(key) + 1:]
    raise AssertionError(f"no {key}= in {line!r}")


def _events(lines):
    """``[(ev, metadata, data)]`` for every ``ev=`` line, in arrival order."""
    return [(_field(line, "ev"),
             bytes.fromhex(_field(line, "meta")),
             bytes.fromhex(_field(line, "data")))
            for line in lines if line.startswith("ev=")]


def _reads(lines):
    """Every ``read n=`` line's bytes, concatenated — the pulled body."""
    return b"".join(bytes.fromhex(_field(line, "data"))
                    for line in lines if line.startswith("read n="))


def _deferred(lines):
    """1 when the submit was acked with kXR_waitresp, 0 when answered inline."""
    for line in lines:
        if line.startswith("submit deferred="):
            return int(_field(line, "deferred"))
    raise AssertionError("the driver never reported the submit disposition")


@pytest.fixture()
def ssi_port(lifecycle):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-p115-ssi-client",
        template="nginx_lc_ssi.conf",
        protocol="root",
        template_values={
            "BIND_HOST": HOST,
            # `brix_ssi_service` is deliberately ABSENT — see
            # test_builtin_services_need_no_service_directive.
            "SSI_DIRECTIVES": "        brix_ssi on;",
        },
        reason="phase-115 W8.6 native SSI client (no libXrdSsi in the link)"))
    return ep.port


# --------------------------------------------------------------------------- #
# success                                                                       #
# --------------------------------------------------------------------------- #

class TestSsiClientSuccess:

    def test_sync_and_deferred_carriers_return_identical_payloads(self,
                                                                  ssi_port):
        """The compat statement: `echo` is answered inline and pulled with
        kXR_query(Rwt); `echo-async` is acked with kXR_waitresp and pushed as
        kXR_attn(asynresp). Two carriers, one reply — a caller of the client API
        must not be able to tell which one it got, and the ONLY difference the
        API exposes is the `deferred` flag it reports for its own bookkeeping."""
        rc_sync, sync, err_sync = _drive(ssi_port, "echo")
        rc_defer, defer, err_defer = _drive(ssi_port, "echo-async")

        assert rc_sync == 0, err_sync
        assert rc_defer == 0, err_defer
        assert _deferred(sync) == 0, "echo answered out of line"
        assert _deferred(defer) == 1, "echo-async answered inline"

        assert _events(sync) == [("response", b"", REQUEST.encode())]
        assert _events(defer) == _events(sync), (
            "the deferred carrier delivered a different reply than the "
            "synchronous one — the two paths have diverged")

    def test_metadata_and_data_are_split_not_swapped(self, ssi_port):
        """The reply is `[attn pfx_len][metadata md_len][data]` and the data
        length appears NOWHERE on the wire: it is only `total - pfx - md`. The
        `meta` service is the one built-in whose halves are both non-empty, so
        it is the only test that can catch the two being swapped or the data
        being truncated by a wrong prefix length."""
        rc, out, err = _drive(ssi_port, "meta")

        assert rc == 0, err
        assert _events(out) == [("response", b"ssi-meta", REQUEST.encode())]

    def test_streaming_service_pulls_its_body_through_read(self, ssi_port):
        """A streaming service answers with the PEND tag and no inline body; the
        bytes come from kXR_read on the same handle, terminated by an explicit
        zero-length read rather than by a timeout."""
        rc, out, err = _drive(ssi_port, "stream")

        assert rc == 0, err
        assert [ev for ev, _, _ in _events(out)] == ["pending"]
        assert _reads(out) == STREAM_BODY
        assert "read n=0 data=" in out, (
            "the stream never ended with an explicit EOF read: " + repr(out))

    def test_deferred_streaming_matches_synchronous_streaming(self, ssi_port):
        """The second carrier pair: `stream-async` defers the PEND tag itself,
        then the body is pulled exactly as in the synchronous case."""
        rc_sync, sync, err_sync = _drive(ssi_port, "stream")
        rc_defer, defer, err_defer = _drive(ssi_port, "stream-async")

        assert rc_sync == 0, err_sync
        assert rc_defer == 0, err_defer
        assert _deferred(defer) == 1
        assert [ev for ev, _, _ in _events(defer)] == ["pending"]
        assert _reads(defer) == _reads(sync) == STREAM_BODY

    def test_alerts_precede_the_terminal_response_on_one_carrier(self,
                                                                ssi_port):
        """`src/protocols/root/response/async.c` builds a BYTE-IDENTICAL
        envelope for an alert and for a terminal response, so the transport
        cannot distinguish them — only the RRInfoAttn tag can ('!' ALRT vs ':'
        FULL). If the client used frame shape as the discriminator it would
        stop at the first alert and report "progress-1" as the answer."""
        rc, out, err = _drive(ssi_port, "alert-async")

        assert rc == 0, err
        assert _deferred(out) == 1
        assert _events(out) == [("alert", b"", b"progress-1"),
                                ("alert", b"", b"progress-2"),
                                ("response", b"", b"done")]

    def test_builtin_services_need_no_service_directive(self, ssi_port):
        """`brix_ssi_service` gates ONLY the CTA tape service (it exposes a
        storage-control surface); the built-in reference services always
        resolve. The fixture configures `brix_ssi on;` alone, so every open
        succeeding here IS that statement — a future directive that started
        gating the built-ins would redden this instead of silently narrowing
        what a bare `brix_ssi on;` can reach."""
        for service in SERVICES:
            _rc, out, err = _drive(ssi_port, service)
            assert "open ok" in out, f"{service}: open refused: {err}"

    def test_cancel_is_accepted_on_a_deferred_request(self, ssi_port):
        """RRInfo command 2 (Can) on the query carrier withdraws a request the
        service has not yet answered. Only the deferred path can be cancelled at
        all — a synchronous service has already replied by the time submit
        returns."""
        rc, out, err = _drive(ssi_port, "echo-async", mode="cancel")

        assert rc == 0, err
        assert _deferred(out) == 1
        assert "cancel ok" in out
        assert out[-1] == "close ok", (
            "the session did not survive its own cancel: " + repr(out))


# --------------------------------------------------------------------------- #
# errors                                                                        #
# --------------------------------------------------------------------------- #

class TestSsiClientErrors:

    def test_service_error_is_surfaced_and_the_session_still_closes(self,
                                                                   ssi_port):
        """`err` fails every request with errno 22 and a fixed text. The client
        must surface the SERVER's message (not a generic transport error) and
        must leave the session closable — an error reply ends one request, not
        the connection."""
        rc, out, err = _drive(ssi_port, "err")

        assert rc == 1, f"the failing service reported success: {out}"
        assert "ssi service rejected the request" in err, err
        assert "ArgInvalid" in err, (
            "errno 22 did not reach the caller as kXR_ArgInvalid: " + err)
        assert _deferred(out) == 0
        assert out[-1] == "close ok", (
            "the session was unusable after a service error: " + repr(out))

    def test_unknown_service_fails_the_open(self, ssi_port):
        """An unregistered name is refused at open — before any request is
        submitted — with kXR_NotFound. A client that let the open through would
        block in await() on a reply no service will ever produce."""
        rc, out, err = _drive(ssi_port, "nosuchsvc")

        assert rc == 1, f"an unknown service opened: {out}"
        assert "unknown SSI service" in err, err
        assert "NotFound" in err, err
        assert out == [], f"work happened after a refused open: {out}"


# --------------------------------------------------------------------------- #
# security negatives                                                            #
# --------------------------------------------------------------------------- #

class TestSsiClientSecurity:

    def test_control_word_on_the_wrong_carrier_is_refused(self, ssi_port):
        """THE carrier negative. The RRInfo belongs in the kXR_query PAYLOAD; on
        the read/write carrier it rides the offset field instead. The driver
        deliberately writes it into the query body's reserved tail — the
        read/write position — and leaves the payload empty.

        The server must REFUSE (`brix_ssi_query` rejects a payload shorter than
        the control word) rather than decode whatever eight bytes happen to sit
        at the payload offset as a command: an attacker who can steer that decode
        chooses between Rxq (submit), Rwt (fetch another request's reply) and Can
        (cancel it) on a handle they hold. The negative is hand-built in C
        because `ssi_client.c` cannot express it — it is correct by
        construction, which is exactly why the refusal needs its own test."""
        rc, out, err = _drive(ssi_port, "echo", mode="badcarrier")

        assert rc == 0, f"the misplaced control word was not refused: {err}"
        refusals = [line for line in out if line.startswith("badcarrier ")]
        assert refusals, f"no refusal in the transcript: {out}"
        assert "short SSI control" in refusals[0], refusals[0]
        assert int(_field(refusals[0], "kxr")) == kXR_ArgInvalid, refusals[0]


# --------------------------------------------------------------------------- #
# structure — the design choices that have no wire signature                    #
# --------------------------------------------------------------------------- #

class TestSsiClientStructure:

    def test_the_deferred_reply_flag_has_one_name(self):
        """`brix_conn.tpc_coord_defer` was renamed `defer_surfaces` because TWO
        unrelated protocols want the same one behaviour: the TPC coordinator
        open needs a surfaced kXR_waitresp or it deadlocks, and SSI submit needs
        it or `recv_after_waitresp` swallows the first pushed alert. A second
        flag meaning the same thing would only grow frame.c an `||`, so the old
        name must not come back anywhere."""
        stale = subprocess.run(
            ["grep", "-rIl", "tpc_coord_defer",
             str(REPO / "client"), str(REPO / "src")],
            capture_output=True, text=True).stdout.split()

        assert stale == [], (
            "the old TPC-only name is back — one behaviour, one flag: " +
            repr(stale))
        net_h = (CLIENT_DIR / "lib" / "brix_net.h").read_text()
        assert "defer_surfaces;" in net_h, "the flag lost its declaration"

    def test_the_defer_flag_is_scoped_to_the_submit_exchange(self):
        """The connection is BORROWED by the SSI session and `await()` pulls the
        pushed frames itself, so the flag must not outlive the submit. That means
        an unconditional restore with no return between arming and restoring —
        an early return there would leave a caller's connection permanently
        surfacing waitresp acks it does not expect."""
        source = (CLIENT_DIR / "lib" / "protocols" / "ssi"
                  / "ssi_client.c").read_text()
        body = source.split("\nbrix_ssi_submit(")[1].split("\n}\n")[0]

        assert body.count("s->conn->defer_surfaces = ") == 2, (
            "expected exactly an arm and a restore in brix_ssi_submit")
        armed = body.split("s->conn->defer_surfaces = 1;")[1]
        exchange = armed.split("s->conn->defer_surfaces = saved;")[0]
        assert "return" not in exchange, (
            "a return between arming and restoring defer_surfaces leaks the "
            "flag onto the caller's connection: " + exchange)

    def test_the_driver_links_no_xrootd_library(self):
        """The reason W8.6 exists. `tests/test_ssi_wire.py::TestSsiRealClient`
        proves interop WITH the stock stack and skips where it is absent; this
        driver must reach the same surface with none of it linked in."""
        _ensure_driver()
        linked = subprocess.run(["ldd", str(DRIVER)],
                                capture_output=True, text=True).stdout

        for library in ("libXrdSsi", "libXrdCl", "libXrdSec", "libXrdUtils"):
            assert library not in linked, (
                f"{library} is linked into the native SSI driver:\n{linked}")
