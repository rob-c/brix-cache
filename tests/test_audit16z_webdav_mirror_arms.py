"""Audit 16z — the WebDAV mirror's auth policy and its divergence NOTICE.

`src/protocols/webdav/directives_net.h` declares the Phase-24 mirror controls,
and the coverage census names two of them as arm-gaps: `brix_mirror_strip_auth`
is written `on` and never `off`, and `brix_mirror_log_diverge` is never written
at all.  Both gaps are on the security side of the flag.  `strip_auth off` is
the arm that forwards the client's `Authorization` header, verbatim, to a second
host the client never addressed and cannot see; `log_diverge` is the only reason
an operator ever learns that the shadow disagreed with the primary.

`test_phase24_mirror.py` proves the stripping arm against the fleet's shared
`mirror-shadow` mock.  That mock answers one status and its capture is global
session state, so neither the forwarding arm nor a divergence can be produced
against it — a divergence is a mismatch of status CLASS between primary and
shadow, so it takes two shadows that disagree by construction.  This file brings
its own pair (`_test_audit16z_helpers.RecordingShadow`) and seven locations one
directive apart on a single listen, since all three directives are
NGX_HTTP_LOC_CONF.

What the wire says that the source did not:

  * the forwarded credential is the client's, unmodified and complete — a
    900-character bearer arrives whole, so the mirror is a full credential
    replay to a second host and not a truncated echo of one (the opt-out is
    doing exactly what it says, which is the point of measuring it);
  * `brix_mirror_token` wins over `strip_auth off` rather than joining it: the
    shadow receives exactly one `Authorization`, the configured one, and the
    client's own never leaves the process on that arm;
  * `brix_mirror_log_diverge` cannot be observed at all, because the divergence
    it gates is never declared.  The primary's status is stamped in the LOG
    phase (`brix_http_mirror_log_handler`) and read in the shadow subrequest's
    finalize, but a background subrequest holds the main request open until it
    completes — so the finalize always runs first and always sees
    `primary_status == 0`.  The armed arm, the unwritten arm and an agreeing
    shadow are indistinguishable, and `brix_mirror_divergence_total{surface=
    "http"}` stays at zero while `brix_mirror_requests_total` counts the very
    replay that disagreed (#105).  The stream surface, which stamps its primary status inline, does
    detect it — `test_phase24_mirror.py` proves that one.
"""

import os
import re
import socket
import time

import pytest

from _test_audit16z_helpers import LOOP_GUARD, RecordingShadow, headers_named
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

NAME = "lc-audit16z-mirror"
_EXTRA = LIFECYCLE_SHARED_PORTS[NAME]["extra"]

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]

#: What the /token-off/ arm is configured to inject, whatever the client sent.
TOKEN = "mirror-injected-bearer-16z"
#: A credential no arm is configured to know about; when the shadow has it, the
#: primary forwarded it.
CLIENT_AUTH = "Bearer client-secret-16z"
#: The NOTICE this file is here for (net/mirror/http_mirror_request.c).
DIVERGE_RE = re.compile(
    r"xrootd mirror divergence: primary=(\d+) shadow=(\d+) uri=(\S+)")


# --------------------------------------------------------------------------- #
# One nginx, seven locations, two shadows that disagree by construction.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def mirror(tmp_path_factory):
    root = tmp_path_factory.mktemp("a16z")
    data = root / "data"
    data.mkdir()

    shadows = {
        "ok": RecordingShadow(BIND_HOST, _EXTRA["SHADOW_OK_PORT"], status=200),
        "miss": RecordingShadow(BIND_HOST, _EXTRA["SHADOW_MISS_PORT"],
                                status=404),
    }

    harness = LifecycleHarness()
    try:
        endpoint = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16z_webdav_mirror_arms.conf",
            protocol="http", readiness="tcp", data_root=str(data),
            template_values={"BIND_HOST": BIND_HOST, "SHADOW_HOST": HOST,
                             "TOKEN": TOKEN},
            reason="audit-16z the never-written arms of brix_mirror_strip_auth "
                   "and brix_mirror_log_diverge, driven against two shadows"))
        yield {"port": endpoint.port, "shadows": shadows, "data": data,
               "log_dir": os.path.join(endpoint.prefix, "logs")}
    finally:
        harness.close()
        for shadow in shadows.values():
            shadow.close()


def _seed(mirror, uri, body=b"primary body\n"):
    """Create the file the primary will serve for `uri`, so the primary's own
    status is 200 and any divergence is the shadow's doing."""
    path = mirror["data"].joinpath(uri.lstrip("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return uri


def _get(mirror, uri, auth=None):
    """GET `uri` from the primary and return (status, body).

    The mirror subrequest holds the client connection open until it finishes, so
    the trailing FIN is deferred; read exactly Content-Length and stop rather
    than reading to close."""
    request = f"GET {uri} HTTP/1.1\r\nHost: primary\r\n"
    if auth is not None:
        request += f"Authorization: {auth}\r\n"
    request += "Connection: close\r\n\r\n"
    with socket.create_connection((HOST, mirror["port"]), timeout=8) as sock:
        sock.settimeout(8)
        sock.sendall(request.encode())
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        head, _, rest = raw.partition(b"\r\n\r\n")
        status = int(head.split(b"\r\n", 1)[0].split()[1])
        match = re.search(rb"[Cc]ontent-[Ll]ength: (\d+)", head)
        want = int(match.group(1)) if match else 0
        while len(rest) < want:
            chunk = sock.recv(4096)
            if not chunk:
                break
            rest += chunk
    return status, rest[:want]


def _drive(mirror, arm, name, shadow="ok", auth=None):
    """Serve one fresh URI through `arm` and return the client's answer next to
    the shadow's record of the replay (None when no replay arrived)."""
    uri = _seed(mirror, f"{arm}{name}")
    status, body = _get(mirror, uri, auth=auth)
    return uri, status, body, mirror["shadows"][shadow].wait_for(uri)


def _errlog(mirror):
    with open(os.path.join(mirror["log_dir"], "error.log"),
              encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _metric(mirror, name):
    """One `brix_*{surface="http"}` counter, read from this instance's own
    /metrics — the detector's account of itself, not its log."""
    status, body = _get(mirror, "/metrics")
    assert status == 200, f"/metrics answered {status}"
    match = re.search(rf'^{re.escape(name)}{{surface="http"}} (\d+)$',
                      body.decode(), re.M)
    assert match is not None, f"{name} missing from /metrics"
    return int(match.group(1))


def _diverge_lines(mirror, uri):
    return [line for line in _errlog(mirror).splitlines()
            if "mirror divergence" in line and f"uri={uri}" in line]


def _wait_diverge(mirror, uri, timeout=8.0):
    """The NOTICE is emitted from `mirror_finalize_request`, which runs after
    nginx has read the shadow's RESPONSE — strictly later than the shadow's own
    record of the request, so the log has to be waited for separately."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = _diverge_lines(mirror, uri)
        if lines:
            return lines
        time.sleep(0.05)
    return []


def _quiet_diverge(mirror, uri, seconds=2.0):
    """The absence of the NOTICE has to be waited for as well, or it only says
    that the subrequest had not finished yet."""
    time.sleep(seconds)
    return _diverge_lines(mirror, uri)


# --------------------------------------------------------------------------- #
# The merge default: the credential stops here.
# --------------------------------------------------------------------------- #
class TestTheDefaultStripsTheCredential:

    def test_the_client_is_served_by_the_primary(self, mirror):
        _, status, body, _ = _drive(mirror, "/strip-default/", "served.txt",
                                    auth=CLIENT_AUTH)
        assert status == 200
        assert body == b"primary body\n"

    def test_the_shadow_receives_the_replay(self, mirror):
        uri, _, _, seen = _drive(mirror, "/strip-default/", "replay.txt",
                                 auth=CLIENT_AUTH)
        assert seen is not None, "the mirror never dialled the shadow"
        assert seen["method"] == "GET"
        assert seen["path"] == uri

    def test_the_shadow_never_sees_the_credential(self, mirror):
        _, _, _, seen = _drive(mirror, "/strip-default/", "stripped.txt",
                               auth=CLIENT_AUTH)
        assert seen is not None
        assert headers_named(seen, "Authorization") == [], \
            "the unwritten default must strip the client's Authorization"

    def test_the_replay_carries_the_loop_guard(self, mirror):
        _, _, _, seen = _drive(mirror, "/strip-default/", "guard.txt")
        assert seen is not None
        assert headers_named(seen, LOOP_GUARD) == ["1"]

    def test_the_shadow_is_addressed_as_itself(self, mirror):
        _, _, _, seen = _drive(mirror, "/strip-default/", "host.txt")
        assert seen is not None
        assert headers_named(seen, "Host") == \
            [f"{HOST}:{_EXTRA['SHADOW_OK_PORT']}"], \
            "the replay must carry the shadow's authority, not the client's"


# --------------------------------------------------------------------------- #
# The arm no test has written: the credential is replayed to a second host.
# --------------------------------------------------------------------------- #
class TestTheOptOutForwardsTheCredential:

    def test_the_client_is_still_served(self, mirror):
        _, status, body, _ = _drive(mirror, "/strip-off/", "served.txt",
                                    auth=CLIENT_AUTH)
        assert status == 200
        assert body == b"primary body\n"

    def test_the_shadow_receives_the_credential(self, mirror):
        _, _, _, seen = _drive(mirror, "/strip-off/", "forwarded.txt",
                               auth=CLIENT_AUTH)
        assert seen is not None
        assert headers_named(seen, "Authorization") != [], \
            "strip_auth off must forward the client's Authorization"

    def test_it_is_forwarded_verbatim(self, mirror):
        _, _, _, seen = _drive(mirror, "/strip-off/", "verbatim.txt",
                               auth=CLIENT_AUTH)
        assert headers_named(seen, "Authorization") == [CLIENT_AUTH], \
            "the forwarded value must be the client's own bytes"

    def test_exactly_one_authorization_reaches_the_shadow(self, mirror):
        _, _, _, seen = _drive(mirror, "/strip-off/", "single.txt",
                               auth=CLIENT_AUTH)
        assert len(headers_named(seen, "Authorization")) == 1

    def test_no_credential_means_no_header(self, mirror):
        _, _, _, seen = _drive(mirror, "/strip-off/", "absent.txt")
        assert seen is not None
        assert headers_named(seen, "Authorization") == [], \
            "the opt-out forwards a credential; it must not invent one"

    def test_a_long_credential_is_not_truncated(self, mirror):
        long_auth = "Bearer " + "z" * 900
        _, status, _, seen = _drive(mirror, "/strip-off/", "long.txt",
                                    auth=long_auth)
        assert status == 200
        assert headers_named(seen, "Authorization") == [long_auth], \
            "the replay is a whole credential, not a truncated echo of one"


# --------------------------------------------------------------------------- #
# The equality the corpus assumes everywhere and has never measured.
# --------------------------------------------------------------------------- #
class TestTheOmissionAndTheWrittenOnAgree:

    def _pair(self, mirror, name):
        seen = {}
        for arm in ("/strip-default/", "/strip-on/"):
            uri, status, body, record = _drive(mirror, arm, name,
                                               auth=CLIENT_AUTH)
            seen[arm] = (uri, status, body, record)
        return seen

    def test_both_arms_serve_the_client(self, mirror):
        pair = self._pair(mirror, "pair-served.txt")
        assert [v[1] for v in pair.values()] == [200, 200]

    def test_both_arms_replay_to_the_shadow(self, mirror):
        pair = self._pair(mirror, "pair-replay.txt")
        for uri, _, _, record in pair.values():
            assert record is not None and record["path"] == uri

    def test_neither_arm_forwards_the_credential(self, mirror):
        pair = self._pair(mirror, "pair-stripped.txt")
        for _, _, _, record in pair.values():
            assert headers_named(record, "Authorization") == []

    def test_the_two_replays_are_the_same_request(self, mirror):
        pair = self._pair(mirror, "pair-identical.txt")
        blocks = [record["headers"] for _, _, _, record in pair.values()]
        assert blocks[0] == blocks[1], \
            "written `on` and the omission must produce one wire, not two"


# --------------------------------------------------------------------------- #
# A configured token outranks either arm of strip_auth.
# --------------------------------------------------------------------------- #
class TestTheConfiguredTokenWins:

    def test_the_shadow_receives_the_configured_token(self, mirror):
        _, _, _, seen = _drive(mirror, "/token-off/", "token.txt",
                               auth=CLIENT_AUTH)
        assert seen is not None
        assert headers_named(seen, "Authorization") == [f"Bearer {TOKEN}"]

    def test_the_clients_credential_is_not_forwarded_alongside(self, mirror):
        _, _, _, seen = _drive(mirror, "/token-off/", "alongside.txt",
                               auth=CLIENT_AUTH)
        values = headers_named(seen, "Authorization")
        assert len(values) == 1, "the shadow must not be offered two identities"
        assert CLIENT_AUTH not in values, \
            "the token replaces the client's credential; it does not join it"

    def test_the_token_is_injected_with_no_client_credential(self, mirror):
        _, _, _, seen = _drive(mirror, "/token-off/", "unauthed.txt")
        assert headers_named(seen, "Authorization") == [f"Bearer {TOKEN}"]

    def test_the_client_leg_is_unaffected(self, mirror):
        _, status, body, _ = _drive(mirror, "/token-off/", "client.txt",
                                    auth=CLIENT_AUTH)
        assert (status, body) == (200, b"primary body\n")

    def test_the_replay_still_carries_the_loop_guard(self, mirror):
        _, _, _, seen = _drive(mirror, "/token-off/", "guard.txt")
        assert headers_named(seen, LOOP_GUARD) == ["1"]


# --------------------------------------------------------------------------- #
# brix_mirror_log_diverge — the only way an operator hears about disagreement.
# --------------------------------------------------------------------------- #
class TestTheDivergenceThatIsNeverDeclared:

    def test_the_shadow_really_does_disagree(self, mirror):
        """The premise, established on the wire: the primary answers 200 and the
        shadow answers 404 for the same URI, which is a class mismatch."""
        uri, status, _, seen = _drive(mirror, "/diverge-on/", "premise.txt",
                                      shadow="miss")
        assert status == 200
        assert seen is not None and seen["path"] == uri
        with socket.create_connection(
                (HOST, _EXTRA["SHADOW_MISS_PORT"]), timeout=4) as sock:
            sock.sendall(f"GET {uri} HTTP/1.1\r\nHost: s\r\n"
                         "Connection: close\r\n\r\n".encode())
            assert int(sock.recv(64).split()[1]) == 404

    def test_the_mirror_leg_completed(self, mirror):
        """`brix_mirror_requests_total` counts a shadow that answered, and it
        moves — so `mirror_finalize_request` did run for the replay that
        disagreed, which is what makes the frozen divergence counter a finding
        rather than a leg that never ran."""
        before = _metric(mirror, "brix_mirror_requests_total")
        uri, _, _, seen = _drive(mirror, "/diverge-on/", "counted.txt",
                                 shadow="miss")
        assert seen is not None
        assert _metric(mirror, "brix_mirror_requests_total") == before + 1

    def test_the_divergence_counter_never_moves(self, mirror):
        before = _metric(mirror, "brix_mirror_divergence_total")
        uri, _, _, seen = _drive(mirror, "/diverge-on/", "uncounted.txt",
                                 shadow="miss")
        assert seen is not None
        _quiet_diverge(mirror, uri)
        assert _metric(mirror, "brix_mirror_divergence_total") == before, \
            "the detector reads a primary status the LOG phase has not " \
            "stamped yet, so a 404 against a 200 is never a divergence (#105)"

    def test_the_armed_flag_logs_nothing(self, mirror):
        uri, _, _, seen = _drive(mirror, "/diverge-on/", "armed.txt",
                                 shadow="miss")
        assert seen is not None
        assert _quiet_diverge(mirror, uri) == [], \
            "brix_mirror_log_diverge on gates a NOTICE that cannot be reached"

    def test_the_unwritten_flag_is_indistinguishable(self, mirror):
        uri, status, _, seen = _drive(mirror, "/diverge-default/", "quiet.txt",
                                      shadow="miss")
        assert status == 200
        assert seen is not None and seen["path"] == uri
        assert _quiet_diverge(mirror, uri) == [], \
            "written `on` and the omission produce the same nothing"

    def test_an_agreeing_shadow_is_no_different(self, mirror):
        uri, _, _, seen = _drive(mirror, "/agree-on/", "agreed.txt")
        assert seen is not None
        assert _quiet_diverge(mirror, uri) == [], \
            "the third arm too: matching classes and mismatching classes are " \
            "reported alike, which is why the flag has no observable effect"

    def test_the_client_never_learns_of_it(self, mirror):
        _, status, body, _ = _drive(mirror, "/diverge-on/", "silent.txt",
                                    shadow="miss")
        assert (status, body) == (200, b"primary body\n"), \
            "a disagreeing shadow is an operator's problem, not the client's"


# --------------------------------------------------------------------------- #
# Seven arms, one worker, two peers.
# --------------------------------------------------------------------------- #
class TestSevenArmsOneServer:

    def test_the_unmirrored_location_dials_nobody(self, mirror):
        uri = _seed(mirror, "/plain/alone.txt")
        status, _ = _get(mirror, uri, auth=CLIENT_AUTH)
        assert status == 200
        for shadow in mirror["shadows"].values():
            assert uri not in [e["path"] for e in shadow.settle(0.5)], \
                "a location with no brix_mirror_url must mirror nothing"

    def test_the_two_shadows_are_distinct_peers(self, mirror):
        ok_paths = mirror["shadows"]["ok"].paths()
        miss_paths = mirror["shadows"]["miss"].paths()
        assert not [p for p in ok_paths if p.startswith("/diverge")]
        assert not [p for p in miss_paths if not p.startswith("/diverge")]

    def test_the_counter_matches_the_wire(self, mirror):
        """Every replay both shadows answered is one
        `brix_mirror_requests_total`: the seven locations share one worker and
        one SHM, so the counter and the two capture logs are two views of the
        same set of requests."""
        replayed = sum(1 for shadow in mirror["shadows"].values()
                       for entry in shadow.settle(1.0)
                       if headers_named(entry, LOOP_GUARD) == ["1"])
        answered = _metric(mirror, "brix_mirror_requests_total")
        failed = _metric(mirror, "brix_mirror_errors_total")
        assert answered + failed == replayed, (
            f"{replayed} replays reached a shadow but the SHM accounts for "
            f"{answered} answered + {failed} failed")

    def test_no_arm_logged_an_error(self, mirror):
        bad = [line for line in _errlog(mirror).splitlines()
               if "[emerg]" in line or "[alert]" in line or "[crit]" in line
               or ("[error]" in line and "mirror" in line)]
        assert bad == [], f"unexpected error output: {bad[:3]}"
