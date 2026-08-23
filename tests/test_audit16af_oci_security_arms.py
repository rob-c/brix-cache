# tests/test_audit16af_oci_security_arms.py — the 16th audit tranche, file 32.
#
# SUBJECT: the two `protocols/oci` flags whose SECURING arm no config in this
# tree has ever written, and what the load-time gate that stands in front of
# them actually proves.
#
#   brix_oci_registry_allow_anonymous  configs/oci_registry.conf renders `on`
#       through its ANON_LINES slot.  The authenticating leg — the one the
#       whole D4.5 authorization suite runs against — calls registry_lane's
#       `registry_spec(..., anonymous=False)`, and that renders the slot EMPTY.
#       So the corpus names this arm "off" in a keyword argument and has never
#       once written the token.
#   brix_oci_mirror_insecure           `on` in oci_mirror.conf ("the ONE place
#       in the tree that does", by its own comment) and in oci_compose.conf.
#       Nowhere `off`, and nowhere absent beside a mirror.
#
# Both merge to 0 (oci_merge.c:72,75), so the omission and the written token
# are supposed to be the same configuration.  §A and §H measure that, and it
# holds — every cell of it.  The file exists because measuring it required
# building four registries the corpus never builds, and three of them answer
# questions the corpus never asks.
#
# WHY THE TWO FLAGS ARE ONE FILE
#   They are the same shape of decision — an operator typing a word that turns
#   a supply-chain protection off — and they are enforced in the same function
#   pair, twelve lines apart (oci_merge.c:117 and :176).  But only one of them
#   has a runtime arm: `up->insecure` (oci_merge.c:312) is the only place the
#   mirror flag's merged value is ever copied to, and nothing reads it again.
#   Its whole subject is therefore `nginx -t`, which is why it costs no port
#   and lives in §H beside the parse tier of the other.
#
# WHAT THE FILE FOUND
#   #115  An issuer table BESIDE `allow_anonymous on` — a composition
#         configs/oci_registry.conf has always permitted, its two slots being
#         independent — admits a bearer the issuer table REJECTED.  A forged
#         token publishes a complete, pullable image; the error log carries the
#         signature failure and the guard audit carries nothing at all.
#   #116  `ssl_verify_client optional_no_ca` satisfies oci_ssl_verifies_client(),
#         so a registry naming no issuer table and no anonymity directive loads
#         — and then admits a client certificate nobody signed as an
#         authenticated pusher.
#   #117  Every refusal the authorization gate emits is audited `op=write`,
#         including refused GETs and HEADs.  GUARD_OP_READ exists.
#   #118  The `WWW-Authenticate` challenge names a realm without the port it is
#         listening on, and names an endpoint the registry does not implement.
#   #119  `principal` is filled by brix_oci_registry_authz() and dropped by its
#         only caller.  No log names who pushed, and the "anonymous" identity
#         the flag's own comment says the access log distinguishes never
#         reaches any log.
#   #120  Once the mirror upstream is `https://`, brix_oci_mirror_insecure has
#         no effect in either arm — the black-box shadow of the dead field.
#
# Ports: the lc-audit16af-ociarms ledger row.  Config:
# configs/nginx_audit16af_oci_arms.conf, rendered by this file and no other.
import datetime
import hashlib
import http.client
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import (BIND_HOST, CA_CERT, NGINX_BIN, SERVER_CERT,
                      SERVER_KEY, USER_CERT, USER_KEY)

def _expression_1(arms):
    return (
        [n for n in arms.files("off") if not n.startswith("stg_")]
    )

def _expression_2(arms):
    return (
        [n for n in arms.files("abs") if not n.startswith("stg_")]
    )


def _check_test_the_two_stores_hold_the_same_objects_2(off, absent):
    assert off == absent, f"off={off} absent={absent}"

def _check_test_the_two_stores_hold_the_same_objects_1(call, arm):
    assert _push_image(call, f"same/{arm}", "v1")[0] == 201

def _check_test_the_guard_audit_never_hears_about_it_4(audited):
    assert audited == [], audited

def _check_test_the_guard_audit_never_hears_about_it_3(call, n):
    assert _put_blob(call, f"forged/quiet{n}",
                     LAYER + str(n).encode())


try:
    from tokenforge import TokenForge, write_scitokens_cfg
    _HAVE_TOKENFORGE = True
except Exception:                    # noqa: BLE001 — cryptography is optional
    _HAVE_TOKENFORGE = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    _HAVE_CRYPTO = True
except Exception:                    # noqa: BLE001 — same optional dependency
    _HAVE_CRYPTO = False

NAME = "lc-audit16af-ociarms"
_L = LIFECYCLE_SHARED_PORTS[NAME]

# The four cleartext planes.  R_OFF and R_ABS are the pair the file was opened
# for: the written token against its omission.
R_ANON = _L["port"]
R_OFF = _L["extra"]["OFF_PORT"]
R_ABS = _L["extra"]["ABS_PORT"]
R_BOTH = _L["extra"]["BOTH_PORT"]

# The three TLS planes, identical but for ssl_verify_client.
R_VON = _L["extra"]["VON_PORT"]
R_VOPT = _L["extra"]["VOPT_PORT"]
R_TLS = _L["extra"]["TLS_PORT"]

AUTHENTICATING = (("off", R_OFF), ("absent", R_ABS))
VERIFY_MODES = (("on", R_VON), ("optional", R_VOPT), ("optional_no_ca", R_TLS))

#: The scope the write gate reads.  `storage.read` alone is the read-only
#: credential, and the existing D4.5 suite already measures that distinction —
#: nothing here re-measures it, because it is not what these planes differ by.
PUSH_SCOPE = "storage.read:/ storage.create:/ storage.modify:/"

#: A `sub` no other test, fixture or PKI file in the tree contains, so that
#: "nothing logged it" in §G is a search over the whole instance rather than a
#: search that a common word could satisfy by accident.
PUSHER = "alice-16af-the-pusher"

LAYER = b"a plausible layer, gzipped in spirit only\n" * 64
CONFIG = b'{"architecture":"amd64","os":"linux"}'

TIMEOUT = 30

pytestmark = [pytest.mark.timeout(420),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

class _Arms:
    """Seven registry fronts, seven stores, addressed by port."""

    def __init__(self, instance, root, forge, issuers):
        self.instance = instance
        self.root = Path(root)
        self.forge = forge
        self.issuers = issuers      #: the scitokens.cfg the token planes name

    def logdir(self):
        return Path(self.instance.prefix) / "logs"

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        log = self.logdir() / "error.log"
        return log.read_text(errors="replace") if log.exists() else ""

    def await_log(self, name, needle, timeout=5.0):
        """Read one log until `needle` shows up, or the deadline passes.

        nginx finalizes a request — and only then runs the log handler — after
        the response has left for the client, so a log read that follows the
        urlopen return by microseconds can be one line short of what the
        client already has.  Every §E/§G cell reads a log about a request it
        just made, so the wait belongs here rather than in each of them."""
        path = self.logdir() / name
        deadline = time.monotonic() + timeout
        text = ""
        while time.monotonic() < deadline:
            text = path.read_text(errors="replace") if path.exists() else ""
            if needle in text:
                return text
            time.sleep(0.05)
        return text

    def logs(self):
        """Every log line the instance wrote, from every file it wrote one to.

        §G's claim is about the whole instance and not about one file, so the
        search has to be over the whole instance."""
        out = []
        for path in sorted(self.logdir().glob("*.log")):
            out.append(path.read_text(errors="replace"))
        return "".join(out)

    def store(self, plane):
        return self.root / plane

    def files(self, plane):
        return sorted(p.name for p in self.store(plane).rglob("*") if p.is_file())

    def token(self, scope=PUSH_SCOPE, sub=PUSHER):
        return self.forge.generate(sub=sub, scope=scope)

    def forged(self, scope=PUSH_SCOPE, sub=PUSHER):
        """A token whose signature does not check out and whose every other
        claim is exactly right — the issuer, audience, scopes and expiry a valid
        push token carries.  So what the issuer table refuses is the signature
        and only the signature."""
        return self.forge.generate_bad_signature(sub=sub, scope=scope)


@pytest.fixture(scope="module")
def pki():
    """The three files every TLS plane and every load-gate parse cell needs.

    PKI_DIR hangs off TEST_ROOT, so a lane started against a fresh root has no
    certificates and the answer is a skip rather than an `nginx -t` failure
    about a missing file — which would look like the gate refusing."""
    for path in (SERVER_CERT, SERVER_KEY, CA_CERT):
        if not os.path.exists(path):
            pytest.skip(f"test PKI incomplete: missing {path}")


@pytest.fixture(scope="module")
def arms(tmp_path_factory, pki):
    """MODULE-scoped with its own harness, for the reason files 27-31 give: the
    ports are fixed by the ledger, so a per-test start/stop races the OS
    releasing them.  Every cell owns its own repository name, so the seven
    stores never collide within a plane either."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not _HAVE_TOKENFORGE:
        pytest.skip("tokenforge (cryptography) unavailable")

    base = tmp_path_factory.mktemp("audit16af")
    root = base / "stores"
    for plane in ("anon", "off", "abs", "both", "von", "vopt", "tls"):
        (root / plane).mkdir(parents=True)

    # The issuer table has to exist before the config that names it is rendered,
    # because brix_token_registry_build() reads it at merge and a missing file
    # is an nginx -t failure rather than a per-push one.
    mint = base / "mint"
    forge = TokenForge(str(mint))
    forge.init_keys()
    issuers = mint / "scitokens.cfg"
    write_scitokens_cfg(str(issuers), [{
        "name": "oci-16af", "issuer": forge.issuer,
        "audience": forge.audience, "base_paths": ["/"],
        "jwks_path": forge.jwks_path, "strategy": "capability"}])

    harness = LifecycleHarness()
    try:
        instance = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16af_oci_arms.conf",
            protocol="http",
            readiness="tcp",
            data_root=str(root),
            template_values={"BIND_HOST": BIND_HOST,
                             "ISSUERS": str(issuers),
                             "SERVER_CERT": SERVER_CERT,
                             "SERVER_KEY": SERVER_KEY,
                             "CA_CERT": CA_CERT},
            reason="audit-16af the two OCI flags whose securing arm no config "
                   "had written: brix_oci_registry_allow_anonymous against its "
                   "omission, and what the three ssl_verify_client modes the "
                   "load gate accepts as one are each actually worth."))
        yield _Arms(instance, root, forge, str(issuers))
    finally:
        harness.close()


@pytest.fixture(scope="module")
def stranger(tmp_path_factory):
    """A client certificate NOBODY signed — self-issued, self-signed, and
    chaining to no CA this tree or any other trusts.

    It is the whole of §D's question: `ssl_verify_client optional_no_ca` asks a
    client for a certificate and validates nothing about it, so this is what an
    attacker brings."""
    if not _HAVE_CRYPTO:
        pytest.skip("cryptography unavailable")

    out = tmp_path_factory.mktemp("audit16af-stranger")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    who = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                        "nobody-signed-this-16af")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(who).issuer_name(who)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .sign(key, hashes.SHA256()))
    (out / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (out / "key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return str(out / "cert.pem"), str(out / "key.pem")


# --------------------------------------------------------------------------- #
# Registry helpers — the dialogue is podman's, not a convenience wrapper's      #
# --------------------------------------------------------------------------- #

def _digest(payload):
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _err(body):
    """The OCI error code out of an error envelope ('' if unparsable)."""
    try:
        return json.loads(body)["errors"][0]["code"]
    except Exception:                # noqa: BLE001 — the shape IS the assertion
        return ""


def _plain(port, headers=None):
    """A caller that speaks cleartext to one plane, carrying fixed headers."""
    fixed = dict(headers or {})

    def call(method, path, body=None, extra=None):
        merged = dict(fixed)
        merged.update(extra or {})
        request = urllib.request.Request(
            f"http://{BIND_HOST}:{port}{path}", method=method, data=body,
            headers=merged)
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    return call


def _over_tls(port, cert=None, key=None):
    """A caller that speaks TLS to one plane, optionally presenting a client
    certificate.

    Server verification is off on purpose: the subject is what the SERVER
    proves about the CLIENT, and a client that also validated the server would
    make a handshake failure ambiguous between the two directions."""
    def call(method, path, body=None, extra=None):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if cert is not None:
            ctx.load_cert_chain(cert, key)
        conn = http.client.HTTPSConnection(BIND_HOST, port, context=ctx,
                                           timeout=TIMEOUT)
        try:
            conn.request(method, path, body=body, headers=extra or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    return call


def _start_upload(call, repo):
    return call("POST", f"/v2/{repo}/blobs/uploads/")


def _put_blob(call, repo, payload):
    """POST → PUT one blob monolithically.  Returns the digest, or raises with
    the refusal that stopped it."""
    status, headers, body = _start_upload(call, repo)
    assert status == 202, f"upload start refused: {status} {body[:120]}"
    location = headers["Location"]
    joiner = "&" if "?" in location else "?"
    status, _, body = call("PUT",
                           f"{location}{joiner}digest={_digest(payload)}",
                           body=payload)
    assert status == 201, f"seal refused: {status} {body[:120]}"
    return _digest(payload)


def _push_image(call, repo, tag):
    """The whole podman-push shape.  Returns (status, body) of the manifest PUT
    — the request that makes the image exist under a name."""
    _put_blob(call, repo, LAYER)
    _put_blob(call, repo, CONFIG)
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "size": len(CONFIG), "digest": _digest(CONFIG)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "size": len(LAYER), "digest": _digest(LAYER)}],
    }).encode()
    status, _, body = call(
        "PUT", f"/v2/{repo}/manifests/{tag}", body=manifest,
        extra={"Content-Type":
               "application/vnd.oci.image.manifest.v1+json"})
    return status, body


#: The eight request shapes the whole registry surface is reachable through.
#: A file about an authorization flag has to ask about every route past it, not
#: only the one the flag's own comment talks about.
PROBES = (
    ("POST", "/v2/lab/app/blobs/uploads/"),
    ("GET", "/v2/lab/app/manifests/latest"),
    ("HEAD", "/v2/lab/app/blobs/sha256:" + "0" * 64),
    ("GET", "/v2/lab/app/tags/list"),
    ("DELETE", "/v2/lab/app/manifests/sha256:" + "0" * 64),
    ("PATCH", "/v2/lab/app/blobs/uploads/nosuchsession"),
    ("GET", "/v2/lab/app/referrers/sha256:" + "0" * 64),
    ("GET", "/v2/"),
)


# --------------------------------------------------------------------------- #
# §A  The written `off` and its omission                                       #
# --------------------------------------------------------------------------- #

class TestTheWrittenOffEqualsItsOmission:
    """The claim the corpus leans on: registry_lane's `anonymous=False` renders
    nothing, and the D4.5 suite treats that as having written `off`.

    Every cell here compares the two planes rather than asserting a constant,
    because the subject is the EQUALITY and not the value — a change that moved
    both planes together would leave a constant-asserting test green while
    breaking nothing the corpus depends on."""

    @pytest.mark.parametrize("method,path", PROBES,
                             ids=[f"{m}{p}" for m, p in PROBES])
    def test_both_planes_answer_a_credentialless_request_identically(
            self, arms, method, path):
        off = _plain(R_OFF)(method, path)
        absent = _plain(R_ABS)(method, path)

        assert off[0] == absent[0], f"off={off[0]} absent={absent[0]}"
        assert off[2] == absent[2], f"off={off[2][:120]} absent={absent[2][:120]}"

    @pytest.mark.parametrize("method,path", PROBES[:-1],
                             ids=[f"{m}{p}" for m, p in PROBES[:-1]])
    def test_both_planes_challenge_with_the_same_header(self, arms, method,
                                                        path):
        """The 401's shape is the part `podman login` reads, so an equality
        that held on the status code and not on the challenge would not be the
        equality anyone is relying on."""
        off = _plain(R_OFF)(method, path)
        absent = _plain(R_ABS)(method, path)

        assert off[0] == 401
        assert off[1].get("WWW-Authenticate") == absent[1].get(
            "WWW-Authenticate")

    @pytest.mark.parametrize("arm,port", AUTHENTICATING)
    def test_a_credentialless_write_is_refused_on_both(self, arms, arm, port):
        status, headers, body = _plain(port)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 401
        assert _err(body) == "UNAUTHORIZED"
        assert "Bearer realm=" in headers.get("WWW-Authenticate", "")

    @pytest.mark.parametrize("arm,port", AUTHENTICATING)
    def test_a_scoped_token_publishes_a_pullable_image_on_both(self, arms, arm,
                                                               port):
        """The other half of the equality: what the token plane lets THROUGH is
        the same on both, byte for byte, all the way to the store."""
        call = _plain(port, {"Authorization": "Bearer " + arms.token()})
        repo = f"eq/{arm}"

        status, body = _push_image(call, repo, "v1")
        assert status == 201, f"{status} {body[:150]}"

        status, headers, blob = call("GET", f"/v2/{repo}/blobs/{_digest(LAYER)}")
        assert status == 200
        assert blob == LAYER

    def test_the_two_stores_hold_the_same_objects(self, arms):
        """Content addressing makes this the strongest form of "the same": the
        two planes wrote to two different roots and the file NAMES agree,
        because the names are the digests of what was written."""
        for arm, port in AUTHENTICATING:
            call = _plain(port, {"Authorization": "Bearer " + arms.token()})
            _check_test_the_two_stores_hold_the_same_objects_1(call, arm)

        off = _expression_1(arms)
        absent = _expression_2(arms)
        _check_test_the_two_stores_hold_the_same_objects_2(off, absent)

    @pytest.mark.parametrize("arm,port", AUTHENTICATING)
    def test_neither_plane_says_anything_about_the_flag(self, arms, arm, port):
        """A written `off` that drew a notice the omission did not would be a
        difference too, and a better world than this one — so it is measured
        rather than assumed away."""
        _plain(port)("POST", "/v2/lab/app/blobs/uploads/")

        noisy = [ln for ln in arms.errlog().splitlines()
                 if "allow_anonymous" in ln and "[emerg]" not in ln
                 and "detail" not in ln]
        assert noisy == [], noisy


# --------------------------------------------------------------------------- #
# §B  The open registry, which is the control for everything in §C             #
# --------------------------------------------------------------------------- #

class TestTheOpenRegistryIsOpenToEveryone:
    """`allow_anonymous on` with no issuer table — configs/oci_registry.conf's
    own lab leg.  Nothing here is a defect; it is the reference the composition
    in §C is measured against."""

    @pytest.mark.parametrize("tag,headers", [
        ("none", {}),
        ("garbage-bearer", {"Authorization": "Bearer not.a.jwt"}),
        ("basic", {"Authorization": "Basic YWxpY2U6cHc="}),
    ])
    def test_any_credential_or_none_may_start_an_upload(self, arms, tag,
                                                        headers):
        status, _, body = _plain(R_ANON, headers)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 202, f"{status} {body[:120]}"

    def test_an_anonymous_client_publishes_a_pullable_image(self, arms):
        status, body = _push_image(_plain(R_ANON), "open/app", "v1")
        assert status == 201, f"{status} {body[:150]}"

        status, _, blob = _plain(R_ANON)(
            "GET", f"/v2/open/app/blobs/{_digest(LAYER)}")
        assert status == 200 and blob == LAYER

    def test_no_challenge_is_ever_issued(self, arms):
        """An open registry never sends a client into a login it cannot do."""
        for method, path in PROBES:
            _, headers, _ = _plain(R_ANON)(method, path)
            assert "WWW-Authenticate" not in headers, (method, path)


# --------------------------------------------------------------------------- #
# §C  An issuer table beside an open door  (DEFECT #115)                       #
# --------------------------------------------------------------------------- #

class TestAnIssuerTableBesideAnOpenDoor:
    """DEFECT #115 — a bearer the issuer table REJECTED is admitted anonymously.

    oci_authz_bearer() returns NGX_DECLINED both when no bearer was presented
    and when every configured issuer refused the one that was
    (oci_authz.c:135,175).  brix_oci_registry_authz() then reaches
    `lcf->registry_anon` and admits.  A rejected credential is therefore
    indistinguishable from an absent one, and on a plane carrying both
    directives the token plane is decorative.

    configs/oci_registry.conf has always permitted this composition — its
    ANON_LINES and ISSUER_LINES slots are independent — and no lane builds it,
    which is why nothing had noticed."""

    @pytest.mark.parametrize("tag", ["forged", "garbage", "none"])
    def test_a_rejected_bearer_starts_an_upload(self, arms, tag):
        creds = {"forged": {"Authorization": "Bearer " + arms.forged()},
                 "garbage": {"Authorization": "Bearer not.a.jwt"},
                 "none": {}}[tag]

        status, _, body = _plain(R_BOTH, creds)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 202, f"{status} {body[:120]}"

    def test_the_same_bearer_is_refused_where_the_door_is_shut(self, arms):
        """The bound on #115: the forged token is not weak, and the issuer
        table is not broken.  Both other authenticating planes refuse it."""
        creds = {"Authorization": "Bearer " + arms.forged()}

        for arm, port in AUTHENTICATING:
            status, _, body = _plain(port, creds)(
                "POST", "/v2/lab/app/blobs/uploads/")
            assert status == 401, f"{arm}: {status} {body[:120]}"

    def test_a_forged_token_publishes_a_complete_pullable_image(self, arms):
        """The consequence, stated as what an attacker gets: not a status code
        but a published image every node that pulls the tag will run."""
        call = _plain(R_BOTH,
                      {"Authorization": "Bearer " + arms.forged()})

        status, body = _push_image(call, "forged/app", "v1")
        assert status == 201, f"{status} {body[:150]}"

        status, headers, manifest = call("GET", "/v2/forged/app/manifests/v1")
        assert status == 200
        assert headers["Docker-Content-Digest"].startswith("sha256:")
        assert json.loads(manifest)["layers"][0]["digest"] == _digest(LAYER)

    def test_the_log_records_the_rejection_the_registry_then_ignored(self,
                                                                     arms):
        """Both halves in one request: the token layer says the signature did
        not verify, and the object is on disk anyway.  The two lines are the
        defect written out in the server's own words."""
        call = _plain(R_BOTH,
                      {"Authorization": "Bearer " + arms.forged()})

        digest = _put_blob(call, "forged/logged", LAYER)

        assert "JWT signature verification failed" in arms.errlog()
        status, _, blob = call("GET", f"/v2/forged/logged/blobs/{digest}")
        assert status == 200 and blob == LAYER

    def test_the_guard_audit_never_hears_about_it(self, arms):
        """The sharpest form of #115.  Nothing was refused, so no `authfail`
        line is written — the [brix-oci-push] fail2ban jail sees a clean
        registry while forged credentials publish through it.

        Filtered by the plane's own port, because the other planes in this
        process are supposed to be emitting exactly this line."""
        call = _plain(R_BOTH,
                      {"Authorization": "Bearer " + arms.forged()})
        for n in range(3):
            _check_test_the_guard_audit_never_hears_about_it_3(call, n)

        audited = [ln for ln in arms.errlog().splitlines()
                   if "signal=authfail" in ln and f":{R_BOTH}\"" in ln]
        _check_test_the_guard_audit_never_hears_about_it_4(audited)

    def test_the_open_plane_and_the_composed_plane_are_indistinguishable(
            self, arms):
        """Which is the operator's real problem: the plane that names an issuer
        table answers a rejected credential exactly as the plane that names no
        token plane at all does."""
        creds = {"Authorization": "Bearer " + arms.forged()}

        opened = _plain(R_ANON, creds)("POST", "/v2/lab/app/blobs/uploads/")
        composed = _plain(R_BOTH, creds)("POST", "/v2/lab/app/blobs/uploads/")

        assert opened[0] == composed[0] == 202
        assert ("WWW-Authenticate" in opened[1]) == (
            "WWW-Authenticate" in composed[1])

    def test_a_valid_token_still_works_there(self, arms):
        """The composition is not broken in the other direction — which is why
        an operator who wrote it would see nothing wrong."""
        call = _plain(R_BOTH, {"Authorization": "Bearer " + arms.token()})

        assert _push_image(call, "composed/valid", "v1")[0] == 201


# --------------------------------------------------------------------------- #
# §D  What the load gate's third route is worth  (DEFECT #116)                 #
# --------------------------------------------------------------------------- #

class TestTheLoadGateAcceptsThreeVerifyModesAsOne:
    """oci_ssl_verifies_client() is `sslcf->verify != 0` (oci_merge.c:147), and
    nginx spells four modes into that field.  Three of them are non-zero."""

    @pytest.mark.parametrize("mode", ["on", "optional", "optional_no_ca"])
    def test_every_non_off_mode_satisfies_the_authenticated_context(
            self, tmp_path, pki, mode):
        rc, out = _parse(tmp_path, LOC_KNOBS=_REGISTRY,
                         HTTP_KNOBS=_tls_server(mode))

        assert rc == 0, out

    def test_only_off_is_refused(self, tmp_path, pki):
        rc, out = _parse(tmp_path, LOC_KNOBS=_REGISTRY,
                         HTTP_KNOBS=_tls_server("off"))

        assert rc != 0
        assert "without an authenticated context" in out


class TestWhatEachVerifyModeIsActuallyWorth:
    """DEFECT #116 — `optional_no_ca` asks a client for a certificate and
    validates nothing about it, so brix_oci_registry_authz()'s TLS branch
    (oci_authz.c:206-220, which asks only that ngx_ssl_get_subject_dn succeed)
    admits a certificate the client signed for itself.

    The other two modes are safe, and safe for a reason that is not brix's:
    nginx's own chain validation refuses the request before the OCI module is
    reached.  So the module's TLS identity branch is correct only where nginx
    was already going to be."""

    @pytest.mark.parametrize("mode,port", VERIFY_MODES)
    def test_a_client_with_no_certificate_never_gets_in(self, arms, mode,
                                                        port):
        """The common floor: none of the three is an open registry."""
        status, _, _ = _over_tls(port)("POST", "/v2/lab/app/blobs/uploads/")

        assert status in (400, 401), status

    @pytest.mark.parametrize("mode,port", [("on", R_VON),
                                           ("optional", R_VOPT)])
    def test_a_self_signed_certificate_is_refused_by_the_two_validating_modes(
            self, arms, stranger, mode, port):
        cert, key = stranger

        status, _, body = _over_tls(port, cert, key)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 400, f"{status} {body[:120]}"
        assert b"SSL certificate error" in body

    def test_a_self_signed_certificate_is_admitted_by_optional_no_ca(
            self, arms, stranger):
        cert, key = stranger

        status, _, body = _over_tls(R_TLS, cert, key)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 202, f"{status} {body[:120]}"

    def test_the_stranger_publishes_a_complete_pullable_image(self, arms,
                                                              stranger):
        """#116 stated as what it costs: a registry the operator was told had
        an authenticated context serves an image nobody authenticated."""
        cert, key = stranger
        call = _over_tls(R_TLS, cert, key)

        status, body = _push_image(call, "stranger/app", "v1")
        assert status == 201, f"{status} {body[:150]}"

        status, _, manifest = call("GET", "/v2/stranger/app/manifests/v1")
        assert status == 200
        assert json.loads(manifest)["layers"][0]["digest"] == _digest(LAYER)

    @pytest.mark.parametrize("mode,port", VERIFY_MODES)
    def test_a_ca_signed_certificate_is_admitted_everywhere(self, arms, mode,
                                                            port):
        """The bound: the three modes agree about the client the tree's own CA
        signed, so #116 is about what `optional_no_ca` ADDS and not about the
        route being broken."""
        if not os.path.exists(USER_CERT) or not os.path.exists(USER_KEY):
            pytest.skip("test PKI has no user certificate")

        status, _, body = _over_tls(port, USER_CERT, USER_KEY)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 202, f"{mode}: {status} {body[:120]}"

    @pytest.mark.parametrize("evil", ["../abs/app", "lab/../../abs/app",
                                      "lab/%2e%2e%2f%2e%2e/app"])
    def test_a_traversal_that_climbs_out_never_reaches_the_registry(
            self, arms, stranger, evil):
        """The first half of the security-negative.  A `..` that leaves `/v2/`
        leaves the LOCATION, so nginx's own normalization answers it and the
        registry is never asked — the request is out of the module's reach
        rather than refused by it."""
        cert, key = stranger

        status, _, _ = _over_tls(R_TLS, cert, key)(
            "POST", f"/v2/{evil}/blobs/uploads/")

        assert status == 404, f"{evil}: {status}"

    @pytest.mark.parametrize("evil,seen", [("lab/%2e%2e/app", "app"),
                                           ("lab/..%2fapp", "app"),
                                           ("/etc/passwd", "etc/passwd")])
    def test_a_traversal_that_normalizes_arrives_as_an_ordinary_name(
            self, arms, stranger, evil, seen):
        """The second half, and the one worth writing down: a percent-encoded
        `..` IS decoded and collapsed, so the registry receives a name with no
        `..` left in it.  The Location it hands back is the proof of which name
        that was — an assertion on the status alone could not tell a refusal
        from a rewrite."""
        cert, key = stranger

        status, headers, _ = _over_tls(R_TLS, cert, key)(
            "POST", f"/v2/{evil}/blobs/uploads/")

        assert status == 202, f"{evil}: {status}"
        assert headers["Location"].startswith(f"/v2/{seen}/blobs/uploads/"), \
            headers["Location"]
        assert ".." not in headers["Location"]

    def test_nothing_the_stranger_wrote_left_its_own_store(self, arms,
                                                           stranger):
        """INVARIANT #4 under the hole #116 opens: the stranger is an
        authenticated pusher on ONE plane, and a name that normalized to
        something legal is still resolved under that plane's own root.  The six
        other stores are the measurement — a plane sharing a process is exactly
        what an escape would land in."""
        cert, key = stranger
        before = {p: arms.files(p) for p in ("anon", "off", "abs", "both",
                                             "von", "vopt")}

        assert _push_image(_over_tls(R_TLS, cert, key),
                           "lab/%2e%2e/escapee", "v1")[0] == 201

        assert {p: arms.files(p) for p in before} == before
        assert any(n for n in arms.files("tls"))


# --------------------------------------------------------------------------- #
# §E  Every refusal is a write  (DEFECT #117)                                  #
# --------------------------------------------------------------------------- #

class TestEveryRefusalIsAuditedAsAWrite:
    """DEFECT #117 — oci_challenge() and oci_deny() pass GUARD_OP_WRITE
    unconditionally (oci_authz.c:97,111), and so does the read-only refusal at
    :195.  GUARD_OP_READ exists (guard.h:21) and this module never emits it, so
    a refused pull and a refused push are one event to the audit trail and to
    every jail keyed on it."""

    def _audit(self, arms, port, needle):
        text = arms.await_log("error.log", needle)
        return [ln for ln in text.splitlines()
                if "signal=authfail" in ln and f":{port}\"" in ln
                and needle in ln]

    def test_a_refused_read_is_recorded_as_a_write(self, arms):
        path = "/v2/audit/read16af/manifests/latest"

        status, _, _ = _plain(R_OFF)("GET", path)
        assert status == 401

        lines = self._audit(arms, R_OFF, "read16af")
        assert lines, arms.errlog()[-1500:]
        assert all("op=write" in ln for ln in lines), lines

    def test_a_refused_head_is_recorded_as_a_write_too(self, arms):
        path = "/v2/audit/head16af/blobs/sha256:" + "0" * 64

        assert _plain(R_ABS)("HEAD", path)[0] == 401

        lines = self._audit(arms, R_ABS, "head16af")
        assert lines and all("op=write" in ln for ln in lines), lines

    def test_a_refused_write_is_recorded_the_same_way(self, arms):
        """Which is the point: the two are indistinguishable, so neither the
        operator nor the jail can tell an enumeration attempt from a push
        attempt."""
        assert _plain(R_OFF)(
            "POST", "/v2/audit/write16af/blobs/uploads/")[0] == 401

        reads = self._audit(arms, R_OFF, "read16af")
        writes = self._audit(arms, R_OFF, "write16af")
        assert reads and writes
        assert ({ln.split("op=")[1].split()[0] for ln in reads}
                == {ln.split("op=")[1].split()[0] for ln in writes})

    def test_the_audit_line_still_carries_what_it_promises(self, arms):
        """The bound: everything else in the line is right, which is why the
        one wrong field is worth naming rather than rewriting the emitter."""
        assert _plain(R_OFF)(
            "GET", "/v2/audit/shape16af/tags/list")[0] == 401

        lines = self._audit(arms, R_OFF, "shape16af")
        assert lines
        line = lines[-1]
        assert "proto=oci" in line
        assert "signal=authfail" in line
        assert "status=401" in line
        assert 'path="/v2/audit/shape16af/tags/list"' in line


# --------------------------------------------------------------------------- #
# §F  The challenge a client cannot follow  (DEFECT #118)                      #
# --------------------------------------------------------------------------- #

class TestTheChallengeCannotBeFollowed:
    """DEFECT #118 — oci_authz.c:85-88 builds the realm from
    `r->headers_in.server`, which nginx parses out of the Host header WITHOUT
    the port.  A registry on any port but 80 therefore advertises a realm on
    the wrong one, and the endpoint it names is not implemented at all.

    The module says this matters in its own words: "`podman login` only works
    against a registry that answers an unauthenticated request with a challenge
    it can follow, so the header is part of the contract, not decoration."
    """

    def _challenge(self, port):
        _, headers, _ = _plain(port)("POST", "/v2/lab/app/blobs/uploads/")
        return headers.get("WWW-Authenticate", "")

    @pytest.mark.parametrize("arm,port", AUTHENTICATING)
    def test_the_realm_drops_the_port_the_request_arrived_on(self, arms, arm,
                                                             port):
        challenge = self._challenge(port)

        assert "Bearer realm=" in challenge
        assert f":{port}" not in challenge, challenge

    @pytest.mark.parametrize("arm,port", AUTHENTICATING)
    def test_the_service_drops_it_as_well(self, arms, arm, port):
        """Both fields come from the same span, so a client that reconstructed
        the endpoint from `service` instead lands in the same place."""
        challenge = self._challenge(port)

        service = challenge.split('service="', 1)[1].rstrip('"')
        assert service == BIND_HOST, service

    def test_the_advertised_endpoint_is_not_implemented(self, arms):
        """Following the realm — port and all — reaches the registry's own
        grammar, which reads `token` as a repository name."""
        status, _, body = _plain(R_OFF)("GET", "/v2/token")

        assert status == 404
        assert _err(body) == "NAME_UNKNOWN"

    def test_the_challenge_is_otherwise_well_formed(self, arms):
        """The bound: the header is a syntactically valid Bearer challenge and
        every client will parse it.  It parses to the wrong place, which is the
        harder failure to notice."""
        challenge = self._challenge(R_OFF)

        assert challenge.startswith('Bearer realm="')
        assert '",service="' in challenge
        assert challenge.count('"') == 4


# --------------------------------------------------------------------------- #
# §G  Nobody is recorded  (DEFECT #119)                                        #
# --------------------------------------------------------------------------- #

class TestNoLogNamesWhoPushed:
    """DEFECT #119 — brix_oci_registry_authz() fills `principal` and its only
    caller (oci_registry.c:290,318) declares it on the stack, passes it in, and
    never reads it back.  The anonymous branch's own comment says the identity
    is "Recorded as such in the identity so the access log distinguishes
    'nobody authenticated' from 'somebody did, and it was anonymous'"
    (oci_authz.c:222-224).  Neither string reaches any log.

    This template turns `access_log` ON at http level, which no other OCI
    config does, so that the absence measured here is the module's and not the
    fixture's."""

    def test_the_instance_does_write_an_access_log(self, arms):
        """The precondition, asserted rather than assumed: an absence proved
        against a log that was never written proves nothing."""
        _plain(R_ANON)("GET", "/v2/")

        assert "GET /v2/" in arms.logs()

    def test_an_authenticated_push_names_nobody_in_the_access_log(self, arms):
        call = _plain(R_OFF, {"Authorization": "Bearer " + arms.token()})
        assert _push_image(call, "who/authed", "v1")[0] == 201

        access = arms.await_log("access.log", "who/authed/manifests")
        assert PUSHER not in access, [ln for ln in access.splitlines()
                                      if PUSHER in ln]

    def test_an_anonymous_push_is_never_called_anonymous(self, arms):
        """The half the comment is explicitly about.  The string does not occur
        anywhere in anything the instance wrote."""
        assert _push_image(_plain(R_ANON), "who/anon", "v1")[0] == 201

        assert "anonymous" not in arms.logs()

    def test_the_two_pushes_are_indistinguishable_in_the_access_log(self,
                                                                    arms):
        """Which is what "no identity is recorded" costs: the manifest PUT that
        a scoped token authorised and the one nobody authorised are the same
        line but for the port."""
        token = {"Authorization": "Bearer " + arms.token()}
        assert _push_image(_plain(R_OFF, token), "who/pair-a", "v1")[0] == 201
        assert _push_image(_plain(R_ANON), "who/pair-b", "v1")[0] == 201

        access = arms.await_log("access.log", "who/pair-b/manifests")

        def shape(needle):
            line = [ln for ln in access.splitlines() if needle in ln][-1]
            return line.split(" - ")[0], line.split('"')[1].split()[0]

        assert shape("who/pair-a/manifests") == shape("who/pair-b/manifests")

    def test_the_subject_only_survives_where_the_token_layer_logged_it(self,
                                                                       arms):
        """The bound, and the reason this is a defect about the registry rather
        than about tokens: the `sub` IS in the error log — put there by
        brix_token's own validation line, at info level, with no mention of
        what it was then allowed to do.  The registry contributes nothing."""
        call = _plain(R_ABS, {"Authorization": "Bearer " + arms.token()})
        assert _push_image(call, "who/traced", "v1")[0] == 201

        named = [ln for ln in arms.errlog().splitlines() if PUSHER in ln]
        def _assert_test_the_subject_only_survives_where_the_token_layer_logged_it_1():
            assert named, "the token layer logged nothing either"
            assert all("brix_token:" in ln for ln in named), named

        _assert_test_the_subject_only_survives_where_the_token_layer_logged_it_1()
        assert not any("who/traced" in ln and "principal" in ln
                       for ln in named)


# --------------------------------------------------------------------------- #
# §H  The parse tier, and the flag with no runtime at all                      #
# --------------------------------------------------------------------------- #

ANON = "brix_oci_registry_allow_anonymous"
INSECURE = "brix_oci_mirror_insecure"

_REGISTRY = ("            brix_oci_registry      on;\n"
             "            brix_oci_registry_root {STORE};\n"
             "            brix_allow_write       on;\n")


def _tls_server(mode):
    return (f"        ssl_certificate        {SERVER_CERT};\n"
            f"        ssl_certificate_key    {SERVER_KEY};\n"
            f"        ssl_client_certificate {CA_CERT};\n"
            f"        ssl_verify_client      {mode};\n")


def _mirror(url, arm=None):
    line = "" if arm is None else f"            {INSECURE} {arm};\n"
    return (f"            brix_oci_mirror  {url};\n"
            f"{line}"
            "            brix_cache_store posix:{STORE};\n")


def _parse(tmp_path, **slots):
    """`nginx -t` on the shared parse scaffold.

    configs/nginx_audit16jparse.conf is reused rather than copied, for the
    reason files 29-31 give: it writes neither flag itself, so a duplicate
    negative can be sure the duplicate it is shown is the one it wrote.  Its
    LOC_KNOBS slot is an http location, which is the only context either
    directive declares."""
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    store = tmp_path / "parse-store"
    store.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "PORT2": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "BACKEND": f"posix:{data}",
              "KNOBS": "", "STREAM_KNOBS": "", "HTTP_KNOBS": "",
              "LOC_KNOBS": "", "OUTER": "", "EXTRA": ""}
    values.update({k: v.replace("{STORE}", str(store)) if isinstance(v, str)
                   else v for k, v in slots.items()})
    result = nginx_t("nginx_audit16jparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _diagnostics(out):
    """Only the lines nginx itself flagged: a tmp_path name can contain the
    token under test, so a substring search over the whole output would match
    the temp directory rather than a diagnostic."""
    return [ln for ln in out.splitlines()
            if any(tag in ln for tag in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


class TestBothArmsOfBothFlagsParse:

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_is_accepted_in_an_http_location(self, tmp_path, flag, arm):
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {arm};\n")

        assert rc == 0, out

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_an_arm_draws_no_diagnostic(self, tmp_path, flag, arm):
        """Accepted is not enough — §A's claim is that a written `off` is a
        normal thing to write, and a NOTICE saying the line is redundant would
        be a different (and better) world."""
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {arm};\n")

        assert rc == 0 and _diagnostics(out) == [], _diagnostics(out)

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    def test_an_arm_alone_needs_no_surface_to_belong_to(self, tmp_path, flag):
        """Neither flag is cross-validated against the surface it configures,
        so both are accepted in a location that has neither a registry nor a
        mirror — the arm merges and is never consulted."""
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} off;\n")

        assert rc == 0, out


class TestTheAnonymityFlagIsTheRegistrysOnlyWayToSayOpen:

    def test_the_written_off_is_refused_exactly_as_its_omission_is(self,
                                                                   tmp_path):
        """The parse half of §A, and the one that matters most: a registry with
        `off` and a registry with nothing must fail the same way, or the corpus
        has been asserting a refusal it never provoked."""
        off = _parse(tmp_path / "off", LOC_KNOBS=_REGISTRY + f"            {ANON} off;\n")
        absent = _parse(tmp_path / "abs", LOC_KNOBS=_REGISTRY)

        assert off[0] == absent[0] != 0
        assert _diagnostics(off[1])[0].split(": ", 1)[1].split(" in ")[0] == \
            _diagnostics(absent[1])[0].split(": ", 1)[1].split(" in ")[0]

    def test_the_refusal_names_all_three_ways_out(self, tmp_path):
        rc, out = _parse(tmp_path, LOC_KNOBS=_REGISTRY)

        assert rc != 0
        for way in ("brix_oci_token_issuers", "ssl_verify_client",
                    "brix_oci_registry_allow_anonymous on"):
            assert way in out, way

    def test_the_written_on_is_what_makes_it_load(self, tmp_path):
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=_REGISTRY + f"            {ANON} on;\n")

        assert rc == 0, out

    def test_an_issuer_table_makes_it_load_without_the_flag(self, tmp_path,
                                                            arms):
        """The second route, which is the one registry_lane's authenticating
        leg takes."""
        rc, out = _parse(
            tmp_path,
            LOC_KNOBS=_REGISTRY
            + f"            brix_oci_token_issuers {arms.issuers};\n")

        assert rc == 0, out


class TestTheMirrorFlagIsOnlyEverAboutCleartext:
    """DEFECT #120 — `up->insecure` (oci_merge.c:312) is the only thing the
    merged value is copied to and nothing reads it again, so the flag's entire
    effect is the cleartext permit at oci_merge.c:117.  The black-box shadow of
    that dead field is here: once the upstream is `https://`, both arms and the
    omission are the same configuration."""

    @pytest.mark.parametrize("arm", ("off", None), ids=("off", "absent"))
    def test_a_cleartext_upstream_is_refused_by_the_written_off_and_by_its_omission(
            self, tmp_path, arm):
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=_mirror("http://mirror.invalid", arm))

        assert rc != 0
        assert "a cleartext upstream would hand every pulled token" in out

    def test_the_written_on_is_what_permits_it(self, tmp_path):
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=_mirror("http://mirror.invalid", "on"))

        assert rc == 0, out

    @pytest.mark.parametrize("arm", ("on", "off", None),
                             ids=("on", "off", "absent"))
    def test_an_https_upstream_loads_under_every_arm(self, tmp_path, arm):
        """#120 as a measurement.  If the flag meant what its name says it
        would have something to do here, and it does not: all three are one
        configuration."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=_mirror("https://registry.invalid", arm))

        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)

    def test_the_flag_cannot_open_a_registry_instead(self, tmp_path):
        """The bound: it is a mirror-only permit and the two surfaces stay
        refused as a pair, so #120 is about a dead field and not about a
        confusable one."""
        rc, out = _parse(
            tmp_path,
            LOC_KNOBS=_REGISTRY + f"            {INSECURE} on;\n")

        assert rc != 0
        assert "without an authenticated context" in out


class TestTheFlagsRefuseWhatIsNotAFlag:

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("value", ("yes", "true", "1", "of", "0",
                                       "enabled"))
    def test_a_value_that_is_not_an_arm_is_refused(self, tmp_path, flag,
                                                   value):
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {value};\n")

        assert rc != 0
        assert 'it must be "on" or "off"' in out or \
            "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("spelling", ("ON", "On", '"on"', "'on'"))
    def test_the_arm_is_case_insensitive_and_quote_transparent(self, tmp_path,
                                                               flag,
                                                               spelling):
        """Not a defect and not a nicety either: `brix_oci_registry_allow_
        anonymous ON` opens a registry to the world, and an operator grepping
        the corpus for the lower-case token would not find it.  Both flags
        inherit this from ngx_conf_set_flag_slot's ngx_strcasecmp and from the
        parser stripping quotes before the setter sees the value, so it is the
        spelling surface an audit of either flag actually has."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=f"            {flag} {spelling};\n")

        assert rc == 0, out

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("line", ("{flag};", "{flag} on off;",
                                      "{flag} on on;"))
    def test_an_arity_other_than_one_is_refused(self, tmp_path, flag, line):
        rc, out = _parse(tmp_path,
                         LOC_KNOBS="            " + line.format(flag=flag)
                         + "\n")

        assert rc != 0
        assert "invalid number of arguments" in out

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    def test_writing_it_twice_is_refused(self, tmp_path, flag):
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=f"            {flag} on;\n"
                                   f"            {flag} off;\n")

        assert rc != 0
        assert "directive is duplicate" in out


class TestTheFlagsAreHttpLocationOnly:
    """Both are declared NGX_HTTP_LOC_CONF and nothing else
    (directives_registry.h:36-42, directives_mirror.h:56-62), which is a
    narrower scope than most of the module — brix_oci_max_blob_size and
    brix_oci_token_issuers are MAIN|SRV|LOC.  A flag that cannot be written in
    a parent has no parent value to inherit, so the merge's inheritance arm for
    both (oci_merge.c:72,75) is unreachable rather than untested."""

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    @pytest.mark.parametrize("slot,indent", [("HTTP_KNOBS", "        "),
                                             ("STREAM_KNOBS", "    "),
                                             ("KNOBS", "        "),
                                             ("OUTER", "")])
    def test_every_other_placement_is_refused(self, tmp_path, flag, slot,
                                              indent):
        rc, out = _parse(tmp_path, **{slot: f"{indent}{flag} on;\n"})

        assert rc != 0
        assert f'"{flag}" directive is not allowed here' in out, out

    @pytest.mark.parametrize("flag", (ANON, INSECURE))
    def test_a_sibling_location_does_not_reach_this_one(self, tmp_path, flag):
        """Two locations in one server, one flag written: the scaffold's own
        EXTRA slot is a stream server, so the sibling question is asked with a
        second location instead."""
        rc, out = _parse(
            tmp_path,
            LOC_KNOBS=f"            {flag} on;\n"
                      "        }\n"
                      "        location /other/ {\n")

        assert rc == 0, out
