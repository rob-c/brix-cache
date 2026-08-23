"""
test_audit15r_webdav_tpc_cadir.py — the TPC leg's trust anchor
(testsuite-combinatorial-coverage-audit 2026-08-15, §Method step 2 sharpened).

WHY THIS FILE EXISTS

Step 2 originally counted a directive covered when its name occurred anywhere in
the corpus.  Re-asked as "is there a test whose verdict changes when this
directive changes?", `brix_webdav_tpc_cadir` was the last of the thirteen
survivors still unplaced.  Its sibling `brix_webdav_tpc_cafile` is exercised by
every audit-15f TPC template — they all hand the mock source's PEM to it — but
the DIRECTORY form has no occurrence at all, in any template or any assertion.
Nothing selects a trust anchor with it, nothing provokes its config-time
validation, and nothing observes the cross-field fallback that fills it in from
`brix_webdav_cadir` (tpc_config.c:130) — a line whose whole purpose is to change
what an operator's TPC leg trusts without them naming the TPC directive.

WHAT MAKES A TRUST ANCHOR OBSERVABLE

A pull leg always verifies peer and host (CURLOPT_SSL_VERIFYPEER/VERIFYHOST,
tpc_curl_setup.c:42-43), and the mock source's certificate is self-signed, so it
appears in no system bundle.  That collapses the COPY's return code onto exactly
one question: did THIS location's anchor set contain the CA that signed the
source?  Two OpenSSL-hashed directories are prepared — `good/` holding the CA
the source actually presents, `wrong/` holding an unrelated CA — and the eight
locations differ only in which of them they are pointed at and through which
directive.  201 means the anchor matched; 502 means it did not.

The two CAs are minted with the SAME subject, so they hash to the same
`<hash>.0` filename.  That is deliberate: the wrong directory is not a lookup
MISS, it is a lookup HIT on the wrong key material.  A cadir that was being
ignored entirely — the failure mode this file exists to rule out — would be
indistinguishable from a miss but is plainly distinguishable from a hit that
fails to verify.

WHAT THE TABLE ESTABLISHES

  location        brix_webdav_cadir  brix_webdav_tpc_cadir  pull   claim
  /nocadir/       -                  -                      502    attribution
  /capath/        -                  good                   201    the directive
  /capathwrong/   -                  wrong                  502    ... decides
  /capathempty/   -                  empty dir              502    valid != trusted
  /inherit/       good               -                      201    the fallback
  /inheritwrong/  wrong              -                      502    ... carries it
  /override/      wrong              good                   201    explicit wins
  /both/          -                  wrong (+ tpc_cafile)   201    CAPATH is additive

/nocadir/ is what makes every 201 above attributable: with no anchor configured
at all the same pull of the same object from the same source is refused.

A FACT THE PARSE TIER PINS

`webdav_validate_tpc_paths` checks `brix_webdav_tpc_cadir` for exactly the kind
and access mode (`WEBDAV_PATH_DIRECTORY`, `R_OK | X_OK`, config_merge.c:504)
that `webdav_validate_ca_paths` has already applied to `brix_webdav_cadir`
(config_merge.c:376), and the general check runs first and unconditionally
(:535 before :538).  So for an INHERITED value the TPC check can never fire —
anything that would fail it has already been refused under the other label.  The
TPC check is reachable only for an explicitly written directive, which is what
§D asserts from both sides.

No defect candidates: every claim above is the documented behaviour, and the
fallback, the override precedence and the additive store all hold.
"""

import os
import shutil
import ssl
import subprocess

import pytest
import requests

from _test_audit15f_helpers import (CapturingSource, gets, mint_localhost_cert,
                                    serve)
from _test_phase25_ratelimit_helpers import _http_values, _parse_fail
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST

def _guard_tpccadir_1():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

def _guard_tpccadir_2():
    if shutil.which("openssl") is None:
        pytest.skip("openssl not found — cannot mint the trust material")


pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15r-tpccadir")]

MOCK_PORT = LIFECYCLE_SHARED_PORTS["lc-audit15r-tpccadir"]["extra"]["MOCK_PORT"]

PAYLOAD = b"audit15r-tpc-cadir-payload-" * 64
OBJECT = "/obj.bin"

# The eight planes and whether their configured anchor set contains the CA the
# source presents.  This table IS the subject: every entry differs from its
# neighbours only in which directory it trusts and how it was told to.
SERVED = ("capath", "inherit", "override", "both")
REFUSED = ("nocadir", "capathwrong", "capathempty", "inheritwrong")
PLANES = SERVED + REFUSED

# curl's errbuf for a chain that cannot be built or cannot be verified.  Both
# spellings occur across OpenSSL versions; the point of the assertion is that
# the refusal is about the CERTIFICATE and not about the transport.
CERT_PHRASES = ("certificate", "SSL", "TLS")

SKIP_ROOT = pytest.mark.skipif(
    os.geteuid() == 0,
    reason="root bypasses the R_OK|X_OK access() check the refusal relies on")


# ── fixtures ────────────────────────────────────────────────────────────── #

def _hashed_capath(directory, cert):
    """An OpenSSL CAPATH: a directory whose members are named for the SUBJECT
    HASH of the certificate they hold.  A bare copy of a PEM into a directory
    is not a trust store — the verifier looks the issuer up by hash and never
    reads anything else — so building this by hand is part of the subject."""
    directory.mkdir(parents=True, exist_ok=True)
    digest = subprocess.run(
        ["openssl", "x509", "-hash", "-noout", "-in", str(cert)],
        check=True, capture_output=True, text=True).stdout.strip()
    # A copy rather than a symlink: c_rehash conventionally symlinks, but the
    # verifier only ever opens the name, and a copy cannot be broken by the
    # tmp_path teardown order.
    shutil.copyfile(str(cert), str(directory / f"{digest}.0"))
    return directory


@pytest.fixture()
def tpccadir(lifecycle, tmp_path):
    _guard_tpccadir_1()
    _guard_tpccadir_2()

    cert, key = mint_localhost_cert(tmp_path, stem="source-ca")
    # Same subject, different key: the wrong directory is a hash HIT that fails
    # to verify, not a miss.
    other_cert, _other_key = mint_localhost_cert(tmp_path, stem="other-ca")

    good = _hashed_capath(tmp_path / "ca-good", cert)
    wrong = _hashed_capath(tmp_path / "ca-wrong", other_cert)
    empty = tmp_path / "ca-empty"
    empty.mkdir()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    source = serve(CapturingSource, MOCK_PORT, tls=ctx, payload=PAYLOAD)

    export = tmp_path / "export"
    for plane in PLANES:
        _plane_dir(export, plane).mkdir(parents=True)
    for path in (tmp_path, export, *(export / p for p in PLANES),
                 *(_plane_dir(export, p) for p in PLANES)):
        os.chmod(path, 0o777)

    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name="lc-audit15r-tpccadir",
            template="nginx_audit15r_tpccadir.conf",
            protocol="webdav",
            data_root=str(export),
            template_values={"BIND_HOST": BIND_HOST,
                             "EXPORT_ROOT": str(export),
                             "CAPATH_GOOD": str(good),
                             "CAPATH_WRONG": str(wrong),
                             "CAPATH_EMPTY": str(empty),
                             "CA_PEM": str(cert)},
            reason="audit-15r webdav TPC trust anchor"))
        yield ep, export, source.recorded
    finally:
        source.shutdown()
        source.server_close()


@pytest.fixture(scope="module")
def anchors(tmp_path_factory):
    """Parse-tier trust material, minted once: a valid hashed directory, a
    regular file, and an unreadable directory."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not found — cannot mint the trust material")
    root = tmp_path_factory.mktemp("audit15r-anchors")
    cert, _key = mint_localhost_cert(root, stem="parse-ca")
    good = _hashed_capath(root / "good", cert)
    locked = root / "locked"
    locked.mkdir()
    os.chmod(locked, 0o000)
    try:
        yield {"good": str(good), "file": str(cert),
               "missing": str(root / "no-such-directory"),
               "locked": str(locked)}
    finally:
        os.chmod(locked, 0o700)


# ── helpers ─────────────────────────────────────────────────────────────── #

def _plane_dir(export, plane):
    """Each location has its own export root and the wire path keeps the
    location prefix, so plane P's objects land under <root-of-P>/P/."""
    return export / plane / plane


def _copy(ep, plane, name, timeout=45):
    return requests.request(
        "COPY", f"http://{HOST}:{ep.port}/{plane}/{name}",
        headers={"Source": f"https://{HOST}:{MOCK_PORT}{OBJECT}"},
        timeout=timeout)


def _landed(export, plane, name):
    path = _plane_dir(export, plane) / name
    return path.read_bytes() if path.exists() else None


def _errlog(ep):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(ep.prefix, "logs", "error.log")) as fh:
            return fh.read()[-6000:]
    except FileNotFoundError:
        return ""


def _cadir_knobs(*lines):
    return "".join(f"            {line}\n" for line in lines)


def _parse(tmp_path, *lines):
    return _parse_fail(tmp_path, "nginx_rl_http.conf",
                       _http_values(_cadir_knobs(*lines)))


# ── §A the configured directory decides the pull ────────────────────────── #

class TestTheAnchorDecides:
    """Eight locations, one source, one object.  The only thing that varies is
    which CA directory the destination was pointed at."""

    @pytest.mark.parametrize("plane", PLANES)
    def test_the_pull_verdict_follows_the_configured_anchor(self, tpccadir,
                                                            plane):
        ep, export, _source = tpccadir
        r = _copy(ep, plane, "verdict.bin")
        if plane in SERVED:
            assert r.status_code == 201, (plane, r.status_code, r.text[:400],
                                          _errlog(ep))
            assert _landed(export, plane, "verdict.bin") == PAYLOAD, plane
        else:
            assert r.status_code == 502, (plane, r.status_code, r.text[:400],
                                          _errlog(ep))
            assert _landed(export, plane, "verdict.bin") is None, plane

    def test_the_unanchored_pull_is_refused_and_attributes_every_success(
            self, tpccadir):
        """/nocadir/ is /capath/ minus the directive.  Same source, same
        object, same everything else — and it cannot complete.  Without this,
        a 201 elsewhere would prove nothing about the directive."""
        ep, export, _source = tpccadir
        r = _copy(ep, "nocadir", "control.bin")
        assert r.status_code == 502, (r.status_code, r.text[:400], _errlog(ep))
        assert _landed(export, "nocadir", "control.bin") is None

        served = _copy(ep, "capath", "control.bin")
        assert served.status_code == 201, (served.status_code, _errlog(ep))
        assert _landed(export, "capath", "control.bin") == PAYLOAD

    def test_the_refusal_is_a_certificate_refusal(self, tpccadir):
        """502 alone would also be a connection refusal or a 404 at the source.
        tpc_core_perform() logs curl's errbuf verbatim (tpc_curl.c:298), so the
        reason is readable: the chain, not the transport."""
        ep, _export, _source = tpccadir
        r = _copy(ep, "capathwrong", "reason.bin")
        assert r.status_code == 502, (r.status_code, _errlog(ep))
        log = _errlog(ep)
        assert "HTTP-TPC pull failed" in log, log[-1500:]
        tail = log[log.rindex("HTTP-TPC pull failed"):]
        assert any(phrase in tail for phrase in CERT_PHRASES), tail[:400]

    def test_a_refused_pull_never_reaches_the_sources_http_layer(self,
                                                                tpccadir):
        """Verification fails during the handshake, so the source records no
        request at all — which is the difference between "the destination
        distrusted the certificate" and "the destination asked and was told
        no"."""
        ep, _export, source = tpccadir
        before = len(source)
        r = _copy(ep, "inheritwrong", "silent.bin")
        assert r.status_code == 502, (r.status_code, _errlog(ep))
        assert source[before:] == [], source[before:]

    def test_a_served_pull_is_one_get_of_the_source_bytes(self, tpccadir):
        ep, export, source = tpccadir
        before = len(source)
        r = _copy(ep, "capath", "bytes.bin")
        assert r.status_code == 201, (r.status_code, _errlog(ep))
        assert _landed(export, "capath", "bytes.bin") == PAYLOAD
        assert len(gets(source[before:], OBJECT)) == 1, source[before:]


# ── §B the cross-field fallback (tpc_config.c:130) ──────────────────────── #

class TestTheFallbackFromTheGeneralCadir:
    """`if (conf->tpc_cadir.len == 0 && conf->cadir.len > 0)` — three tests,
    because the line makes three separate claims."""

    def test_the_general_cadir_is_inherited_when_the_tpc_one_is_unset(
            self, tpccadir):
        """/inherit/ names no TPC directive at all and still verifies the
        source, which only the fallback can explain — /nocadir/ is the same
        location without the general directive and cannot."""
        ep, export, _source = tpccadir
        r = _copy(ep, "inherit", "fallback.bin")
        assert r.status_code == 201, (r.status_code, r.text[:400], _errlog(ep))
        assert _landed(export, "inherit", "fallback.bin") == PAYLOAD

    def test_the_inherited_value_is_the_configured_one(self, tpccadir):
        """The fallback carries the operator's directory, not merely "some
        store": the same inheritance with the WRONG directory refuses.  Without
        this half, /inherit/'s 201 would also be explained by a leg that had
        quietly kept a default trust store."""
        ep, export, _source = tpccadir
        r = _copy(ep, "inheritwrong", "fallback.bin")
        assert r.status_code == 502, (r.status_code, r.text[:400], _errlog(ep))
        assert _landed(export, "inheritwrong", "fallback.bin") is None

    def test_the_tpc_directive_overrides_the_general_one(self, tpccadir):
        """/override/ carries both, and the wrong one is the general one.  The
        fallback is a fill-in for an UNSET field, not a merge — so the explicit
        TPC directive is what the leg uses."""
        ep, export, _source = tpccadir
        r = _copy(ep, "override", "precedence.bin")
        assert r.status_code == 201, (r.status_code, r.text[:400], _errlog(ep))
        assert _landed(export, "override", "precedence.bin") == PAYLOAD


# ── §C what the directory is, and is not ────────────────────────────────── #

class TestTheStoreIsAdditive:

    def test_a_wrong_directory_does_not_veto_a_right_cafile(self, tpccadir):
        """CAPATH and CAINFO are two anchor SOURCES, not an override pair
        (tpc_curl_setup.c:190-195 sets both unconditionally).  /both/ is handed
        the wrong directory and the right file and serves — so an operator
        adding a cadir cannot lose an anchor they already had."""
        ep, export, _source = tpccadir
        r = _copy(ep, "both", "additive.bin")
        assert r.status_code == 201, (r.status_code, r.text[:400], _errlog(ep))
        assert _landed(export, "both", "additive.bin") == PAYLOAD

    def test_a_readable_but_empty_directory_anchors_nothing(self, tpccadir):
        """/capathempty/ passes every config-time check the directive has — it
        exists, it is a directory, it is readable and searchable — and trusts
        nobody.  Config validation proves the path is usable, never that it
        contains a usable anchor; the instance booted, which is half the
        assertion."""
        ep, export, _source = tpccadir
        r = _copy(ep, "capathempty", "empty.bin")
        assert r.status_code == 502, (r.status_code, r.text[:400], _errlog(ep))
        assert _landed(export, "capathempty", "empty.bin") is None


# ── §D the config-time validation, and when it is reachable ─────────────── #

class TestTheValidationIsGatedOnTpc:

    def test_a_hashed_directory_is_accepted(self, tmp_path, anchors):
        """The success arm: without it, every refusal below could be the TPC
        block refusing to parse rather than the path being judged."""
        rc, out = _parse(tmp_path, "brix_webdav_tpc on;",
                         f"brix_webdav_tpc_cadir {anchors['good']};")
        assert rc == 0, out

    def test_a_regular_file_is_refused_as_the_cadir(self, tmp_path, anchors):
        rc, out = _parse(tmp_path, "brix_webdav_tpc on;",
                         f"brix_webdav_tpc_cadir {anchors['file']};")
        assert rc != 0, out
        assert "brix_webdav_tpc_cadir" in out, out
        assert "must be a directory" in out, out

    def test_a_missing_directory_is_refused(self, tmp_path, anchors):
        rc, out = _parse(tmp_path, "brix_webdav_tpc on;",
                         f"brix_webdav_tpc_cadir {anchors['missing']};")
        assert rc != 0, out
        assert "brix_webdav_tpc_cadir" in out, out
        assert "is not accessible" in out, out

    @SKIP_ROOT
    def test_an_unreadable_directory_is_refused(self, tmp_path, anchors):
        """A mode-0 directory stats fine and IS a directory: only the
        R_OK|X_OK access() check catches it, which is the reason the validator
        takes an access mode at all."""
        rc, out = _parse(tmp_path, "brix_webdav_tpc on;",
                         f"brix_webdav_tpc_cadir {anchors['locked']};")
        assert rc != 0, out
        assert "brix_webdav_tpc_cadir" in out, out
        assert "failed permission check" in out, out

    def test_the_cadir_is_unvalidated_while_tpc_is_off(self, tmp_path,
                                                       anchors):
        """SECURITY-NEGATIVE / asymmetry: webdav_validate_tpc_paths()
        early-returns on `!conf->tpc` (config_merge.c:495), so a path that is
        refused above is accepted here.  An operator who stages a TPC config
        with the feature off gets no warning that the anchor does not exist —
        and turning `brix_webdav_tpc on` later is what fails the reload."""
        rc, out = _parse(tmp_path, "brix_webdav_tpc off;",
                         f"brix_webdav_tpc_cadir {anchors['missing']};")
        assert rc == 0, out

        armed, armed_out = _parse(
            tmp_path, "brix_webdav_tpc on;",
            f"brix_webdav_tpc_cadir {anchors['missing']};")
        assert armed != 0, armed_out

    def test_a_bad_general_cadir_is_reported_under_its_own_label(
            self, tmp_path, anchors):
        """ATTRIBUTION: the general directive is validated first and
        unconditionally (config_merge.c:535 before :538) with the same kind and
        access mode, so the fallback can never hand the TPC check a value that
        fails it — an operator's typo is named where they wrote it, and the TPC
        check is reachable only for an explicitly written directive."""
        rc, out = _parse(tmp_path, "brix_webdav_tpc on;",
                         f"brix_webdav_cadir {anchors['missing']};")
        assert rc != 0, out
        assert "brix_webdav_cadir" in out, out
        assert "brix_webdav_tpc_cadir" not in out, out
