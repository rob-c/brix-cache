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

