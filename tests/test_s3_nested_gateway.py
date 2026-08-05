"""test_s3_nested_gateway.py — `brix_s3 on` in FRONT of `brix_storage_backend
s3://`, the nested-S3-gateway cell.

Every other S3 test puts a *different* protocol in front of the object store: a
WebDAV front over s3:// (`nginx_ce_driver_s3.conf`), a GridFTP front over s3://
(`nginx_gridftp_s3.conf`), root:// over s3:// (`nginx_root_s3_staged.conf`).
S3-in-front-of-S3 — the shape an operator gets when a site gateway re-exports a
bucket — had no config and no test at any level.  `nginx_ce_driver_s3.conf`
records why it was skipped: "a separate, pre-existing whole-object staged-open
failure that also breaks a plain identity PUT".

That failure was not in the staged-open path at all.  A worker serves every
`brix_s3` block in the configuration, and the worker-local SigV4 signing-key
cache (`protocols/s3/auth_sigv4_verify_crypto.c`) was keyed on **date+region
only** — not on the secret it was derived from.  Whichever block signed first
captured the one slot, and from then on, for the rest of the calendar day:

  * a request to the *other* block forged with the FIRST block's secret (and the
    other block's access key id, which is an identifier, not a secret) was
    **accepted** — a cross-tenant authentication bypass; and
  * that block's own legitimate credential was **rejected**, because the cache
    hit path never re-derives.

Both directions are pinned below.  The cache now carries a SHA-256 of the secret
as part of its key (a digest, so the static holds no key material).

Coverage (success + error + security-negative):
  * success           — PUT/GET/HEAD/LIST/DELETE through the front; the object
    comes to rest byte-exact in the ORIGIN's bucket and never in the front's
    export root, and a key written directly at the origin reads back through the
    front (proving the front really is a gateway, not local storage);
  * error             — a missing key is 404 NoSuchKey through the front, and a
    delete of a missing key stays a refusal, not a 5xx;
  * security-negative — unsigned and wrong-secret requests are 403 and leave
    nothing at the origin; a request to the front signed with the ORIGIN's secret
    is 403 and the origin's own credential keeps working (the cache-isolation
    regression); and a `..` key cannot write above either root.

Run:
  PYTHONPATH=tests pytest tests/test_s3_nested_gateway.py -v
"""

import datetime as dt
import hashlib
import hmac
import os
import pathlib
import urllib.error
import urllib.request
from urllib.parse import quote

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN
from official_interop_lib import worker_reachable
from server_registry import NginxInstanceSpec

pytestmark = [
    pytest.mark.serial,
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-s3-nested"),
]

NAME = "lc-s3-nested"
BUCKET = "testbucket"
REGION = "us-east-1"

FRONT_AK, FRONT_SK = "FRONTKEYAAAAAAAAAAAA", "front-secret-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ORIGIN_AK, ORIGIN_SK = "ORIGKEYBBBBBBBBBBBBB", "origin-secret-bbbbbbbbbbbbbbbbbbbbbbbbbb"

SEEDED = "seeded-at-origin.bin"
SEEDED_BYTES = b"ORIGIN-SEEDED" * 16


def _sigv4(method, host, port, path, access_key, secret_key):
    """Header-auth SigV4 over host;x-amz-date with UNSIGNED-PAYLOAD — the same
    canonicalization the server freezes in auth_sigv4_verify_crypto.c."""
    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    canonical = (f"{method}\n"
                 f"{quote(path, safe='/-_.~')}\n"
                 "\n"
                 f"host:{host}:{port}\n"
                 f"x-amz-date:{amz_date}\n"
                 "\n"
                 "host;x-amz-date\n"
                 "UNSIGNED-PAYLOAD")
    sts = ("AWS4-HMAC-SHA256\n"
           f"{amz_date}\n"
           f"{day}/{REGION}/s3/aws4_request\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    k = hmac.new(f"AWS4{secret_key}".encode(), day.encode(), hashlib.sha256).digest()
    for part in (REGION, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    return {
        "x-amz-date": amz_date,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{day}/{REGION}/s3/aws4_request, "
            f"SignedHeaders=host;x-amz-date, Signature={sig}"),
    }


def _call(port, method, path, access_key=None, secret_key=None, data=None):
    """(status, body) — HTTP errors are outcomes here, never exceptions.  With no
    key pair the request goes out unsigned."""
    headers = ({} if access_key is None
               else _sigv4(method, HOST, port, path, access_key, secret_key))
    req = urllib.request.Request(f"http://{HOST}:{port}{path}", data=data,
                                 method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class _Nested:
    """The S3 front, the co-hosted s3:// origin behind it, and their key pairs."""

    def __init__(self, lifecycle, tmp_path):
        self._lifecycle = lifecycle
        self.origin_dir = pathlib.Path(tmp_path) / "origin"
        self.front_export = pathlib.Path(tmp_path) / "front-export"
        for d in (self.origin_dir, self.front_export):
            d.mkdir(parents=True, exist_ok=True)
        worker_reachable(self.origin_dir, self.front_export)
        self.port = self.origin_port = None

    def start(self):
        ep = self._lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_lc_s3_nested.conf",
            protocol="s3",
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_DIR": str(self.origin_dir),
                "FRONT_EXPORT": str(self.front_export),
                "FRONT_ACCESS_KEY": FRONT_AK,
                "FRONT_SECRET_KEY": FRONT_SK,
                "ORIGIN_ACCESS_KEY": ORIGIN_AK,
                "ORIGIN_SECRET_KEY": ORIGIN_SK,
            },
            reason="an S3 gateway whose storage backend is another S3 endpoint — "
                   "the nested-S3 cell, and the cross-block SigV4 key isolation "
                   "it is the only topology to exercise",
        ))
        self.port = ep.port
        self.origin_port = ep.extra_ports["ORIGIN_PORT"]
        return self

    # Front leg (client credential) and origin leg (service credential).
    def front(self, method, key, data=None, ak=FRONT_AK, sk=FRONT_SK):
        return _call(self.port, method, f"/{BUCKET}/{key}", ak, sk, data)

    def at_origin(self, method, key, data=None, ak=ORIGIN_AK, sk=ORIGIN_SK):
        return _call(self.origin_port, method, f"/{BUCKET}/{key}", ak, sk, data)

    def stored(self, key):
        return self.origin_dir / key

    def front_local_files(self):
        """Non-dotfile content under the front's export root (dotfiles are the
        server's own bookkeeping, e.g. the checkpoint-recovery lock)."""
        return sorted(p.name for p in self.front_export.rglob("*")
                      if p.is_file() and not p.name.startswith("."))


@pytest.fixture()
def nested(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    srv = _Nested(lifecycle, tmp_path).start()
    (srv.origin_dir / SEEDED).write_bytes(SEEDED_BYTES)
    return srv


# --------------------------------------------------------------------------- #
# Success — a full object lifecycle traverses both S3 hops                      #
# --------------------------------------------------------------------------- #

def test_put_through_the_front_lands_in_the_origin_bucket(nested):
    """The client's PUT is terminated by the front, re-signed with the service
    credential, and committed at the origin — byte-exact, and with nothing left
    behind in the front's own export root (a local copy would mean the gateway
    quietly became the storage)."""
    payload = b"NESTED-S3-PAYLOAD" * 64
    status, body = nested.front("PUT", "nested.bin", payload)
    assert status == 200, f"PUT through the nested gateway failed: {status} {body[:200]}"

    assert nested.stored("nested.bin").read_bytes() == payload, \
        "the object at the origin does not match what the client sent"
    assert nested.front_local_files() == [], \
        f"the front kept a local copy: {nested.front_local_files()}"


def test_get_head_and_list_read_through_to_the_origin(nested):
    """A key written straight into the origin's bucket — never through the front —
    is readable, statable and listable through the front."""
    status, body = nested.front("GET", SEEDED)
    assert status == 200, f"GET through the gateway failed: {status} {body[:200]}"
    assert body == SEEDED_BYTES

    status, _ = nested.front("HEAD", SEEDED)
    assert status == 200

    status, listing = _call(nested.port, "GET", f"/{BUCKET}/", FRONT_AK, FRONT_SK)
    assert status == 200, f"ListObjects through the gateway failed: {status}"
    assert SEEDED.encode() in listing, \
        f"the origin's key is missing from the front's listing: {listing[:400]}"


def test_delete_through_the_front_removes_the_origin_object(nested):
    """DELETE is a mutation that must reach the backend: a 204 with the object
    still at the origin would be a silent data-visibility split."""
    status, _ = nested.front("DELETE", SEEDED)
    assert status in (200, 204), f"DELETE through the gateway failed: {status}"
    assert not nested.stored(SEEDED).exists(), \
        "the front answered success but the origin still holds the object"


# --------------------------------------------------------------------------- #
# Error — misses stay honest S3 errors across the extra hop                     #
# --------------------------------------------------------------------------- #

def test_missing_key_is_a_clean_not_found(nested):
    """A miss at the origin must surface as 404 NoSuchKey through the front, not
    as a backend I/O error — the extra hop must not turn absence into failure."""
    status, body = nested.front("GET", "no-such-object.bin")
    assert status == 404, f"expected 404 for a missing key, got {status} {body[:200]}"
    assert b"NoSuchKey" in body or b"<Error>" in body, body[:200]

    status, _ = nested.front("HEAD", "no-such-object.bin")
    assert status == 404


def test_delete_of_a_missing_key_is_not_a_server_error(nested):
    """Deleting what is not there is either the S3 idempotent 204 or an honest
    404 — never a 5xx from the gateway's own backend leg."""
    status, body = nested.front("DELETE", "never-existed.bin")
    assert status in (204, 200, 404), \
        f"delete of a missing key answered {status}: {body[:200]}"


# --------------------------------------------------------------------------- #
# Security-negative                                                             #
# --------------------------------------------------------------------------- #

def test_unsigned_and_wrong_secret_writes_are_refused(nested):
    """The front terminates auth: neither an unsigned PUT nor one signed with a
    bad secret may reach the backend leg."""
    for label, ak, sk in (("unsigned", None, None),
                          ("wrong secret", FRONT_AK, "not-the-front-secret")):
        status, _ = nested.front("PUT", "forged.bin", b"x" * 32, ak=ak, sk=sk)
        assert status == 403, f"{label} PUT answered {status}, expected 403"

    assert not nested.stored("forged.bin").exists(), \
        "a refused PUT still created the object at the origin"


def test_front_does_not_accept_the_origins_credential(nested):
    """Cross-block SigV4 isolation: one worker verifies for every `brix_s3` block,
    and the signing-key cache used to be keyed on date+region alone — so whichever
    block signed first captured the slot and the other block both accepted
    forgeries made with the first block's secret and rejected its own credential.

    Alternating the two blocks is what makes the pin bite: each round warms the
    cache with a real origin request, then offers the front the origin's secret
    under the front's own (public) access key id, then re-checks that the front's
    real credential still works.  Rounds cover both workers."""
    for round_no in range(6):
        status, _ = nested.at_origin("GET", SEEDED)
        assert status == 200, \
            f"round {round_no}: the origin rejected its own credential ({status})"

        status, _ = nested.front("GET", SEEDED, ak=FRONT_AK, sk=ORIGIN_SK)
        assert status == 403, \
            (f"round {round_no}: the front accepted a request signed with the "
             f"ORIGIN's secret ({status}) — cross-block signing-key leak")

        status, _ = nested.front("GET", SEEDED)
        assert status == 200, \
            (f"round {round_no}: the front rejected its own credential ({status}) "
             "— its signing key was displaced by another block's")


def test_traversal_key_cannot_escape_either_root(nested):
    """A `..` key is refused, and writes nothing above the origin's bucket root or
    the front's export — confinement must hold on both hops, not just the one
    that terminates the client."""
    above_origin = nested.origin_dir.parent / "s3_nested_escape.bin"
    status, _ = _call(nested.port, "PUT", f"/{BUCKET}/../s3_nested_escape.bin",
                      FRONT_AK, FRONT_SK, b"escaped")

    assert status >= 400, f"a traversal key was accepted with {status}"
    assert not above_origin.exists(), "the traversal wrote above the origin root"
    assert not (nested.front_export.parent / "s3_nested_escape.bin").exists(), \
        "the traversal wrote above the front's export root"
