"""audit-16x — the last arm-gaps in `root/stream/directives_security.h`.

The tranche's census counts a flag as covered when a config writes ONE of its
two tokens.  Re-run per (directive, VALUE), four flags in this header still have
an arm the corpus has never written in any form:

    brix_ztn_cleartext     off   — 18 configs write `on`, none writes `off`
    brix_zip_access        off   —  8 write `on`, none writes `off`
    brix_zip_force_scratch off   —  2 write `on`, none writes `off`
    brix_tls               off   — 63 write `on`, none writes `off`

All four merge to 0 (`server_conf_merge_security.c:249/251/312/316`), so each
unwritten token spells the compiled default.  That is the reason to write it,
not a reason to skip it: every existing test of these four says "off" in its
prose and writes ABSENCE in its config, so "the token and the omission agree" is
an assumption the corpus leans on everywhere and has measured nowhere.  This
file measures it, on twelve listeners in ONE worker over ONE export — the
directives are all `NGX_STREAM_SRV_CONF`, so a `server {}` is the smallest unit
that can hold a value, and each flag buys three of them (written off, omitted,
armed control).

What entering the off arms turns up is mostly not a code fault but a SHAPE:

  * `brix_zip_access off` does not refuse a member request — it stops looking at
    the opaque, so the client that asked for one member of an archive is handed
    the whole archive with an ok status, and the traversal check that the armed
    arm runs on the member name (`open_request_opaque.c:166-170`) does not run
    at all;
  * `brix_zip_force_scratch off` beside a CONFIGURED `brix_zip_stage_dir` is a
    cell no config has ever held — the existing off arm omits both directives,
    so "the stage dir is ignored because the flag is off" and "there is no stage
    dir" have never been told apart;
  * `brix_ztn_cleartext off` is enforced TWICE, and only the first of the two
    has ever been reached by a test: the login parms drop the ztn block
    (`session/login.c:323-325`), and a client that sends a ztn credential anyway
    is refused at the kXR_auth gate (`auth/gsi/auth.c:222`).  A token-only
    listener never reaches the second gate, because the cleartext login has
    nothing left to advertise and is refused outright.  These planes say
    `brix_auth both` so the login SUCCEEDS on gsi and the second gate is
    reachable;
  * `brix_tls off` with a certificate configured is the only way to ask whether
    the flag or the material is what arms the upgrade — `offer_tls` is the AND
    of the two (`session/protocol.c:65-66`).

`brix_opaque_strict` is NOT in this file although a literal grep calls both its
arms unwritten.  It reaches `nginx_opaque_strict.conf` through a `{STRICT}`
placeholder that `test_opaque_strict.py` fills with both tokens and reads
behaviourally, exactly as `brix_cms_state_relay` does in tranche 16's file 11 —
the grep is what is wrong there, not the coverage.
"""

import os
import ssl
import struct
import zipfile

import pytest

from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, CA_CERT, HOST, NGINX_BIN, SERVER_CERT, SERVER_KEY

# The wire is imported, never rebuilt: the zip member client is
# test_zip_member.py's, the token/auth framing is the conformance library's.
from test_zip_member import _open, _read_all, _session, kXR_ok
from lib.tokenconf import (_raw_handshake, _read_response, _send_auth_ztn,
                           _send_login, _send_stat, kXR_error)
from utils.make_token import TokenIssuer

NAME = "lc-audit16x-secoff"
_EXTRA = LIFECYCLE_SHARED_PORTS[NAME]["extra"]

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]

kXR_ArgInvalid = 3000
kXR_NotFound = 3011
kXR_NotAuthorized = 3010
kXR_TLSRequired = 3028

# ServerProtocolBody.flags (protocol/flags.h) and the client capability byte.
kXR_haveTLS = 0x80000000
kXR_gotoTLS = 0x40000000
kXR_secreqs = 0x01
kXR_ableTLS = 0x02
kXR_wantTLS = 0x04

STORED = b"audit16x stored member payload\n"
OTHER = b"audit16x second member, a different length\n"


# --------------------------------------------------------------------------- #
# The instance: twelve planes, one worker, one export
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def secoff(tmp_path_factory):
    """One nginx holding all twelve planes.  Module-scoped because the subject
    is a static arm of a config, not a per-test variable, and because twelve
    listeners are exactly the thing a per-test start would pay for twelve times.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    for path in (SERVER_CERT, SERVER_KEY, CA_CERT):
        if not os.path.exists(path):
            pytest.skip(f"fleet PKI material missing: {path}")

    base = tmp_path_factory.mktemp("a16x")
    export = base / "export"
    export.mkdir()
    _seed_archive(export / "a.zip")
    (export / "plain.dat").write_bytes(b"audit16x plain object\n")

    stages = {}
    for arm in ("off", "abs", "on"):
        d = base / f"stage_{arm}"
        d.mkdir()
        stages[arm] = str(d)

    tok = base / "tok"
    tok.mkdir()
    issuer = TokenIssuer(str(tok))
    issuer.init_keys()

    harness = LifecycleHarness()
    ep = harness.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16x_stream_security_off_arms.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(export),
        template_values={"BIND_HOST": BIND_HOST,
                         "CERT": SERVER_CERT, "KEY": SERVER_KEY,
                         "CA": CA_CERT, "JWKS": issuer.jwks_path,
                         "STAGE_OFF": stages["off"],
                         "STAGE_ABS": stages["abs"],
                         "STAGE_ON": stages["on"]},
        reason="audit-16x the four directives_security.h flags whose second "
               "arm the corpus never wrote"))
    try:
        yield {"ep": ep, "export": export, "issuer": issuer,
               "ports": _ports(ep), "stages": stages,
               "log_dir": os.path.join(ep.prefix, "logs")}
    finally:
        harness.close()


def _seed_archive(path):
    """A two-member STORED archive.  Stored members are what the server can
    serve by offset translation (deflate is refused pending streaming inflate),
    and two of them make "the whole archive" measurably longer than "the member"
    on every plane below."""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("stored.txt", STORED, compress_type=zipfile.ZIP_STORED)
        z.writestr("second.txt", OTHER, compress_type=zipfile.ZIP_STORED)


def _ports(ep):
    x = ep.extra_ports
    return {"zip_off": ep.port,
            "zip_abs": x["ZIP_ABS_PORT"],
            "zip_on": x["ZIP_ON_PORT"],
            "scr_off": x["SCR_OFF_PORT"],
            "scr_abs": x["SCR_ABS_PORT"],
            "scr_on": x["SCR_ON_PORT"],
            "ztn_off": x["ZTN_OFF_PORT"],
            "ztn_abs": x["ZTN_ABS_PORT"],
            "ztn_on": x["ZTN_ON_PORT"],
            "tls_off": x["TLS_OFF_PORT"],
            "tls_abs": x["TLS_ABS_PORT"],
            "tls_on": x["TLS_ON_PORT"]}


# --------------------------------------------------------------------------- #
# Wire helpers.  The raw client comes from test_zip_member (zip) and
# test_tls_require's ancestors (protocol/login/auth); only the two shapes those
# files do not have — a kXR_protocol with a chosen capability byte, and an
# anonymous login that returns its body — are written here.
# --------------------------------------------------------------------------- #

def _protocol(sock, client_flags):
    """kXR_protocol carrying `client_flags` in the capability byte.

    tokenconf's `_send_protocol` hard-codes kXR_secreqs; the TLS class below
    needs kXR_ableTLS and kXR_wantTLS, which is the whole subject of §D, so the
    one request that varies is packed here and the response is read with the
    library's framing.  Returns the raw (status, body) so a refusal is a result
    rather than an assertion.
    """
    sock.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006,
                             0x00000520, client_flags, 0x03, 0))
    return _read_response(sock)


def _flags_word(body):
    """ServerResponseBody_Protocol: pval[4] then flags[4]."""
    return struct.unpack(">I", body[4:8])[0]


def _errcode(body):
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


def _read_object(port, path):
    """Open `path` and read it whole; returns (open status, bytes)."""
    s = _session(port)
    try:
        st, body = _open(s, path)
        if st != kXR_ok:
            return st, body
        st2, data = _read_all(s, body[:4], 1 << 20)
        return st2, data
    finally:
        s.close()


def _errlog(secoff):
    return os.path.join(secoff["log_dir"], "error.log")


def _log_size(secoff):
    p = _errlog(secoff)
    return os.path.getsize(p) if os.path.exists(p) else 0


def _log_since(secoff, offset):
    p = _errlog(secoff)
    if not os.path.exists(p):
        return ""
    with open(p, "r", errors="replace") as fh:
        fh.seek(offset)
        return fh.read()


_STAGED = "archive staged to scratch"


# --------------------------------------------------------------------------- #
# brix_zip_access — the flag does not refuse a member, it stops looking
# --------------------------------------------------------------------------- #

class TestZipMemberAccessWhenTheFlagIsOff:
    """`brix_zip_access` gates ONE branch of the read-open resolver
    (`read/open_request_resolve.c:264`).  With the flag off the branch is
    skipped, so `?xrdcl.unzip=` is not an unsupported request — it is an
    unread one, and the open falls through to the ordinary whole-file path."""

    def test_the_armed_arm_serves_the_member(self, secoff):
        """The control the other three tests are read against."""
        st, data = _read_object(secoff["ports"]["zip_on"],
                                "/a.zip?xrdcl.unzip=stored.txt")
        assert st == kXR_ok, st
        assert data == STORED, data[:80]

    def test_the_written_off_arm_serves_the_whole_archive(self, secoff):
        """The shape worth writing down: the client asked for one member and got
        an ok status and the ARCHIVE.  Nothing in the exchange says the request
        was not honoured."""
        archive = (secoff["export"] / "a.zip").read_bytes()
        st, data = _read_object(secoff["ports"]["zip_off"],
                                "/a.zip?xrdcl.unzip=stored.txt")
        assert st == kXR_ok, st
        assert data == archive, (len(data), len(archive))
        assert data != STORED

    def test_omitting_the_directive_is_the_same_verdict(self, secoff):
        """The equality the corpus assumes: written `off` and no directive at
        all must produce the same bytes, or neither reading is attributable to
        the token."""
        written = _read_object(secoff["ports"]["zip_off"],
                               "/a.zip?xrdcl.unzip=stored.txt")
        omitted = _read_object(secoff["ports"]["zip_abs"],
                               "/a.zip?xrdcl.unzip=stored.txt")
        assert written == omitted

    def test_a_member_that_does_not_exist_is_an_error_only_when_armed(
            self, secoff):
        """Armed, a missing member is kXR_NotFound (`zip_member.c:345`).  Off,
        the same request is answered with the archive — so a client cannot use
        the status to learn whether the member existed."""
        s = _session(secoff["ports"]["zip_on"])
        try:
            st, body = _open(s, "/a.zip?xrdcl.unzip=nosuch.txt")
        finally:
            s.close()
        assert st == kXR_error, st
        assert _errcode(body) == kXR_NotFound, _errcode(body)

        st_off, data = _read_object(secoff["ports"]["zip_off"],
                                    "/a.zip?xrdcl.unzip=nosuch.txt")
        assert st_off == kXR_ok, st_off
        assert data == (secoff["export"] / "a.zip").read_bytes()

    def test_the_traversal_check_runs_only_in_the_armed_arm(self, secoff):
        """Security-negative.  `open_extract_zip_member` treats a `..` member
        name as an explicit error rather than a fall-through, deliberately — but
        it is called only under the armed flag, so the same name reaches no
        check at all on the two planes that do not arm it."""
        s = _session(secoff["ports"]["zip_on"])
        try:
            st, body = _open(s, "/a.zip?xrdcl.unzip=../../etc/passwd")
        finally:
            s.close()
        assert st == kXR_error, st
        assert _errcode(body) == kXR_ArgInvalid, _errcode(body)

        for plane in ("zip_off", "zip_abs"):
            st_off, data = _read_object(secoff["ports"][plane],
                                        "/a.zip?xrdcl.unzip=../../etc/passwd")
            assert st_off == kXR_ok, (plane, st_off)
            assert data == (secoff["export"] / "a.zip").read_bytes(), plane

    def test_a_plain_object_is_unaffected_by_either_arm(self, secoff):
        """Non-vacuity for the pair: the flag changes what an archive request
        means and nothing else, so an ordinary object reads identically on all
        three planes."""
        want = (secoff["export"] / "plain.dat").read_bytes()
        for plane in ("zip_on", "zip_off", "zip_abs"):
            st, data = _read_object(secoff["ports"][plane], "/plain.dat")
            assert st == kXR_ok, (plane, st)
            assert data == want, plane

    def test_the_armed_arm_serves_the_second_member_too(self, secoff):
        """The archive really does hold two members, which is what makes "the
        whole archive" above a different length from either of them."""
        st, data = _read_object(secoff["ports"]["zip_on"],
                                "/a.zip?xrdcl.unzip=second.txt")
        assert st == kXR_ok, st
        assert data == OTHER, data[:80]


# --------------------------------------------------------------------------- #
# brix_zip_force_scratch — a stage dir that is configured and not used
# --------------------------------------------------------------------------- #

class TestForcingTheArchiveThroughScratch:
    """`zip_stage_archive_maybe` (`zip/zip_member.c:302-307`) declines to stage
    when the flag is off OR no stage dir is set.  Existing coverage takes the
    second exit — its off arm omits both directives — so the first exit, the one
    the token names, has never been configured.  The observable is the INFO line
    the staging path logs, because the scratch copy is unlinked the instant it
    is made (`vfs_core.c:177`): an empty stage directory is what BOTH arms leave
    behind."""

    def test_the_armed_arm_stages_the_archive(self, secoff):
        off = _log_size(secoff)
        st, data = _read_object(secoff["ports"]["scr_on"],
                                "/a.zip?xrdcl.unzip=stored.txt")
        assert st == kXR_ok, st
        assert data == STORED
        assert _STAGED in _log_since(secoff, off)

    def test_the_written_off_arm_ignores_a_configured_stage_dir(self, secoff):
        """The cell nothing had configured: the stage dir is present and legal,
        and the flag alone is what keeps the archive on its own fd."""
        off = _log_size(secoff)
        st, data = _read_object(secoff["ports"]["scr_off"],
                                "/a.zip?xrdcl.unzip=stored.txt")
        assert st == kXR_ok, st
        assert data == STORED
        assert _STAGED not in _log_since(secoff, off)

    def test_omitting_the_directive_is_the_same_verdict(self, secoff):
        off = _log_size(secoff)
        st, data = _read_object(secoff["ports"]["scr_abs"],
                                "/a.zip?xrdcl.unzip=stored.txt")
        assert st == kXR_ok, st
        assert data == STORED
        assert _STAGED not in _log_since(secoff, off)

    def test_staging_is_transparent_to_the_member_bytes(self, secoff):
        """The two arms differ in one line of log and in nothing the client can
        see, which is the property that makes the flag safe to turn on."""
        staged = _read_object(secoff["ports"]["scr_on"],
                              "/a.zip?xrdcl.unzip=second.txt")
        in_place = _read_object(secoff["ports"]["scr_off"],
                                "/a.zip?xrdcl.unzip=second.txt")
        assert staged == in_place
        assert staged[1] == OTHER

    def test_neither_arm_leaves_the_scratch_copy_behind(self, secoff):
        """Both stage directories stay empty — the armed arm because the copy is
        unlinked immediately, the disarmed one because it never made a copy.
        Asserted so a future change that stops unlinking is caught here rather
        than by a full disk."""
        _read_object(secoff["ports"]["scr_on"], "/a.zip?xrdcl.unzip=stored.txt")
        _read_object(secoff["ports"]["scr_off"], "/a.zip?xrdcl.unzip=stored.txt")
        for arm in ("on", "off", "abs"):
            assert os.listdir(secoff["stages"][arm]) == [], arm

    def test_the_flag_does_not_arm_member_access_by_itself(self, secoff):
        """Ordering: staging happens INSIDE the member path, so a plane with the
        force flag but no member access is not a thing this file can build — and
        the reverse, member access without staging, is exactly the disarmed
        plane above.  The check that the two flags are independent is that the
        zip-off planes never stage anything either."""
        off = _log_size(secoff)
        _read_object(secoff["ports"]["zip_off"], "/a.zip?xrdcl.unzip=stored.txt")
        assert _STAGED not in _log_since(secoff, off)


# --------------------------------------------------------------------------- #
# brix_ztn_cleartext — the gate that has never been reached
# --------------------------------------------------------------------------- #

class TestBearerTokensOnACleartextConnection:
    """Stock XRootD refuses to carry a ztn bearer token on an unencrypted
    connection, and BriX matches it in two places.  Only the first has ever been
    tested, and only through absence.  These planes write the token, and say
    `brix_auth both` so the login survives losing ztn and the SECOND gate — the
    kXR_auth credential check at `auth/gsi/auth.c:222` — is reachable."""

    def _login_body(self, port):
        s = _raw_handshake(HOST, port)
        try:
            _protocol(s, kXR_secreqs)
            st, body = _send_login(s)
            return st, body
        finally:
            s.close()

    def test_the_armed_arm_advertises_ztn_over_cleartext(self, secoff):
        st, body = self._login_body(secoff["ports"]["ztn_on"])
        assert st == kXR_ok, (st, body[:80])
        assert b"ztn" in body, body[:200]

    def test_the_written_off_arm_withholds_ztn_but_still_logs_in(self, secoff):
        """The first gate: the parms lose the ztn block and keep gsi, so the
        login succeeds and the client simply has no bearer protocol on offer."""
        st, body = self._login_body(secoff["ports"]["ztn_off"])
        assert st == kXR_ok, (st, body[:80])
        assert b"ztn" not in body, body[:200]
        assert b"gsi" in body, body[:200]

    def test_omitting_the_directive_withholds_ztn_the_same_way(self, secoff):
        written = self._login_body(secoff["ports"]["ztn_off"])
        omitted = self._login_body(secoff["ports"]["ztn_abs"])
        assert (b"ztn" in written[1]) == (b"ztn" in omitted[1]) is False
        assert written[0] == omitted[0] == kXR_ok

    def test_a_valid_token_sent_anyway_is_refused_by_the_second_gate(
            self, secoff):
        """The cell nothing had reached.  The client ignores the advertised
        list and puts a ztn credential on the wire; the refusal is about the
        TRANSPORT, so the token is valid and it makes no difference."""
        token = secoff["issuer"].generate(sub="alice")
        s = _raw_handshake(HOST, secoff["ports"]["ztn_off"])
        try:
            _protocol(s, kXR_secreqs)
            st_login, _ = _send_login(s)
            assert st_login == kXR_ok, st_login
            st, body = _send_auth_ztn(s, token)
        finally:
            s.close()
        assert st == kXR_error, st
        assert _errcode(body) == kXR_TLSRequired, _errcode(body)
        assert b"TLS" in body, body[:200]

    def test_the_omission_refuses_the_same_credential_identically(self, secoff):
        token = secoff["issuer"].generate(sub="alice")
        s = _raw_handshake(HOST, secoff["ports"]["ztn_abs"])
        try:
            _protocol(s, kXR_secreqs)
            assert _send_login(s)[0] == kXR_ok
            st, body = _send_auth_ztn(s, token)
        finally:
            s.close()
        assert (st, _errcode(body)) == (kXR_error, kXR_TLSRequired)

    def test_the_opt_in_accepts_the_same_credential(self, secoff):
        """Non-vacuity for the whole class: the identical token on the identical
        cleartext socket authenticates once the operator opts in, so the two
        refusals above are about the flag and not about the token."""
        token = secoff["issuer"].generate(sub="alice")
        s = _raw_handshake(HOST, secoff["ports"]["ztn_on"])
        try:
            _protocol(s, kXR_secreqs)
            assert _send_login(s)[0] == kXR_ok
            st, body = _send_auth_ztn(s, token)
            assert st == kXR_ok, (st, body[:200])
            st_stat, _ = _send_stat(s, "/plain.dat")
            assert st_stat == kXR_ok, st_stat
        finally:
            s.close()

    def test_the_opt_in_is_not_an_authentication_bypass(self, secoff):
        """Security-negative on the armed arm: `on` restores the transport, not
        the verdict — a token this issuer did not sign is still refused."""
        bad = secoff["issuer"].generate_bad_signature(sub="mallory")
        s = _raw_handshake(HOST, secoff["ports"]["ztn_on"])
        try:
            _protocol(s, kXR_secreqs)
            assert _send_login(s)[0] == kXR_ok
            st, body = _send_auth_ztn(s, bad)
        finally:
            s.close()
        assert st == kXR_error, st
        assert _errcode(body) == kXR_NotAuthorized, _errcode(body)
        assert b"token validation failed" in body, body[:200]

    def test_a_refused_credential_leaves_the_session_unauthenticated(
            self, secoff):
        """The refusal is not a downgrade: after the second gate says no, the
        session has no identity and a data op cannot proceed as though it had."""
        token = secoff["issuer"].generate(sub="alice")
        s = _raw_handshake(HOST, secoff["ports"]["ztn_off"])
        try:
            _protocol(s, kXR_secreqs)
            assert _send_login(s)[0] == kXR_ok
            assert _send_auth_ztn(s, token)[0] == kXR_error
            st_stat, body = _send_stat(s, "/plain.dat")
        finally:
            s.close()
        assert st_stat == kXR_error, (st_stat, body[:120])
        assert _errcode(body) == kXR_NotAuthorized, _errcode(body)


# --------------------------------------------------------------------------- #
# brix_tls — the flag and the material are two halves of one AND
# --------------------------------------------------------------------------- #

class TestTheInProtocolTlsUpgrade:
    """`want->offer_tls = conf->tls && conf->tls_ctx != NULL && client asked`
    (`session/protocol.c:65-66`).  Every plane here carries the certificate and
    key, so the second term is true on all three and the flag is the only
    variable — which is the arrangement a config that writes only `on` can never
    produce."""

    def _flags(self, port, client_flags=kXR_ableTLS | kXR_secreqs):
        s = _raw_handshake(HOST, port)
        try:
            return _protocol(s, client_flags)
        finally:
            s.close()

    def test_the_armed_arm_advertises_the_upgrade(self, secoff):
        st, body = self._flags(secoff["ports"]["tls_on"])
        assert st == kXR_ok, st
        flags = _flags_word(body)
        assert flags & kXR_haveTLS, hex(flags)
        assert flags & kXR_gotoTLS, hex(flags)

    def test_the_written_off_arm_advertises_neither_bit(self, secoff):
        """The certificate is configured on this listener; the token alone is
        what withdraws the offer."""
        st, body = self._flags(secoff["ports"]["tls_off"])
        assert st == kXR_ok, st
        flags = _flags_word(body)
        assert flags & (kXR_haveTLS | kXR_gotoTLS) == 0, hex(flags)

    def test_omitting_the_directive_is_the_same_advertisement(self, secoff):
        written = self._flags(secoff["ports"]["tls_off"])
        omitted = self._flags(secoff["ports"]["tls_abs"])
        assert written[0] == omitted[0] == kXR_ok
        assert _flags_word(written[1]) == _flags_word(omitted[1])

    def test_a_client_that_requires_tls_is_refused_on_the_off_arm(self, secoff):
        """Security-negative, and the one place the off arm produces an error
        rather than a silence: kXR_wantTLS means the client will not continue
        without TLS, and `brix_handle_protocol` refuses it up front rather than
        letting the session proceed in the clear."""
        for plane in ("tls_off", "tls_abs"):
            st, body = self._flags(secoff["ports"][plane],
                                   kXR_ableTLS | kXR_wantTLS)
            assert st == kXR_error, (plane, st)
            assert _errcode(body) == kXR_TLSRequired, (plane, _errcode(body))

    def test_the_armed_arm_accepts_a_client_that_requires_tls(self, secoff):
        st, body = self._flags(secoff["ports"]["tls_on"],
                               kXR_ableTLS | kXR_wantTLS)
        assert st == kXR_ok, (st, body[:80])
        assert _flags_word(body) & kXR_gotoTLS, hex(_flags_word(body))

    def test_the_off_arm_still_serves_cleartext(self, secoff):
        """What the flag does NOT do: it withdraws the upgrade, not the
        listener, so an ordinary cleartext session is unaffected."""
        for plane in ("tls_off", "tls_abs"):
            st, data = _read_object(secoff["ports"][plane], "/plain.dat")
            assert st == kXR_ok, (plane, st)
            assert data == (secoff["export"] / "plain.dat").read_bytes()

    def test_the_upgrade_completes_on_the_armed_arm(self, secoff):
        """The end-to-end control: gotoTLS is followed, the handshake completes
        against the same certificate the off planes also carry, and the session
        works after it."""
        s = _raw_handshake(HOST, secoff["ports"]["tls_on"])
        try:
            st, body = _protocol(s, kXR_ableTLS | kXR_secreqs)
            assert st == kXR_ok and _flags_word(body) & kXR_gotoTLS
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls = ctx.wrap_socket(s, server_hostname=HOST)
            try:
                assert _send_login(tls)[0] == kXR_ok
                st_stat, _ = _send_stat(tls, "/plain.dat")
                assert st_stat == kXR_ok, st_stat
            finally:
                tls.close()
        finally:
            s.close()

    def test_a_client_that_cannot_upgrade_is_told_nothing(self, secoff):
        """The bits are an answer to the client's capability byte, not a static
        property of the listener: a client that advertises neither ableTLS nor
        wantTLS gets no gotoTLS even from the armed plane."""
        st, body = self._flags(secoff["ports"]["tls_on"], kXR_secreqs)
        assert st == kXR_ok, st
        assert _flags_word(body) & kXR_gotoTLS == 0, hex(_flags_word(body))


# --------------------------------------------------------------------------- #
# The harness control
# --------------------------------------------------------------------------- #

class TestTwelvePlanesOneWorker:
    """Every claim above is a claim about a flag only if the planes differ in
    nothing else.  These three check that: one export behind all twelve
    listeners, and one process holding all twelve merged confs."""

    def test_the_nine_open_planes_serve_the_same_export(self, secoff):
        """The zip, scratch and TLS planes are `brix_auth none`, so the object
        is readable on each and any difference between them is the flag."""
        want = (secoff["export"] / "plain.dat").read_bytes()
        for plane, port in secoff["ports"].items():
            if plane.startswith("ztn_"):
                continue
            st, data = _read_object(port, "/plain.dat")
            assert st == kXR_ok, (plane, st)
            assert data == want, plane

    def test_the_three_token_planes_are_the_same_server_behind_auth(
            self, secoff):
        """The ztn planes say `brix_auth both` (the config header explains why),
        so the same export is there but a credential is the price of it.  Both
        halves are asserted: the login is accepted on all three, and an
        unauthenticated open is refused on all three — which is what makes the
        §C refusals statements about the ztn gate rather than about a listener
        that was never serving anything."""
        for plane in ("ztn_off", "ztn_abs", "ztn_on"):
            s = _raw_handshake(HOST, secoff["ports"][plane])
            try:
                _protocol(s, kXR_secreqs)
                st_login, body = _send_login(s)
                assert st_login == kXR_ok, (plane, st_login)
                assert b"gsi" in body, (plane, body[:200])
                st_open, open_body = _open(s, "/plain.dat")
            finally:
                s.close()
            assert st_open == kXR_error, (plane, st_open)
            assert _errcode(open_body) == kXR_NotAuthorized, plane

    def test_the_planes_are_one_process(self, secoff):
        """One pid file, twelve listeners: the per-server independence every
        assertion above rests on is a property of one worker's merged confs, not
        of twelve processes that could each have been configured differently."""
        pid_file = secoff["ep"].pidfile
        assert os.path.exists(pid_file), pid_file
        pid = int(open(pid_file).read().strip())
        assert os.path.exists(f"/proc/{pid}"), pid
