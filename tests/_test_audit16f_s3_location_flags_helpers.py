"""The five S3 location flags at VALUE granularity — audit §Method, 16th tranche.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running it per
(directive, VALUE) over the 128 ``ngx_conf_set_flag_slot`` directives turned 256
pairs into 94 that are written nowhere in the corpus, in any form.  Five of them
belong to one module and share one shape: the ``on`` arm is configured
somewhere, the merge default is 0, and the word ``off`` had never been written
for any of them.

    brix_s3_verify_chunk_signatures        module_merge.c:89   default 0
    brix_s3_allow_unsigned_session_token   module_merge.c:87   default 0
    brix_s3_token                          module_merge.c:128  default 0
    brix_s3_list_cache                     module_merge.c:91   default 0
    brix_zip_access                     module_merge.c:96   default 0

A flag whose ``off`` arm is never written is not the same as a flag that is
covered: every "off" claim the suite makes about these five is really a claim
about the merge default, and no test could tell an operator's explicit refusal
from an absent directive.  The two are the same behaviour here — that is the
result, not the assumption, and it is what §B/§D/§F assert per arm.

WHAT THE VALUES SELECT — the measured table
-------------------------------------------
Fifteen buckets on one listener, one access key, one region.  Every row below
was measured against a live server before it was written down::

  directive / arm    probe                              verdict
  ------------------------------------------------------------------------
  verify on          aws-chunked PUT, one chunk forged  403 SignatureDoesNotMatch
  verify off         same                               200, the bytes stored
  verify absent      same                               200, the bytes stored
  verify any         the SEED signature forged          403 SignatureDoesNotMatch
  ------------------------------------------------------------------------
  ust on             signed request, SIGNED token       200
  ust on             signed request, UNSIGNED token     403 InvalidRequest
  ust off            signed request, either token       403 AccessDenied
  ust absent         signed request, either token       403 AccessDenied
  ust any            no session token at all            200
  ------------------------------------------------------------------------
  token on           Bearer                             200
  token on           SigV4                              200
  token on           neither                            403 AccessDenied
  token off/absent   Bearer                             403 InvalidRequest
  token off/absent   neither                            403 InvalidRequest
  ------------------------------------------------------------------------
  list on            list, write sub/K, list            K missing (stale)
  list on            then write /K2, list               both appear
  list off/absent    list, write sub/K, list            K present
  ------------------------------------------------------------------------
  zip on             GET ?xrdcl.unzip=inner.txt         the member, 13 bytes
  zip on             GET ?xrdcl.unzip=absent            404 NoSuchKey
  zip on             GET with no parameter              the whole archive
  zip off/absent     GET ?xrdcl.unzip=inner.txt         the whole archive

Two of those rows are worth naming.  ``brix_s3_token on`` does not only ADD a
transport, it makes the location token-ONLY: an anonymous request is refused
with a different error code than the same request one location away (§D).  And
``brix_s3_list_cache on`` is stale rather than wrong — the cache keys on the
export root's own mtime, so a write into a subdirectory is invisible while a
write into the root is not (§E).

FINDING — DEFECT CANDIDATE #71
------------------------------
``brix_s3`` is the one directive on this plane whose setter does more than fill
a slot: ``ngx_http_s3_set()`` (module.c:189-203) installs ``clcf->handler``
after parsing the flag.  A handler is not inherited by a NESTED location the way
the merged location conf is, so::

    location /vcon/ {
        brix_s3 on;  brix_s3_bucket vcon;  ...          # served by S3
        location /vcon/sub/ {
            brix_s3_verify_chunk_signatures off;        # served by nothing
        }
    }

the nested location inherits the bucket, the credentials, the storage backend
and the flag override — every byte of the S3 configuration — and is then served
by nginx's static handler.  A PUT there is 405, a GET is a stock 404 HTML page
with no ``<Code>`` in it.  Nothing diagnoses this at config time, and nothing
can: the flag slot has no view of which handler the location ended up with.

This is standard nginx handler semantics — ``proxy_pass`` behaves the same way —
so it is a trap rather than a divergence, and the cure is one line (repeat
``brix_s3 on;`` inside the nested location, §B).  What makes it worth pinning is
that the failure is silent, the surviving configuration looks complete, and the
directive an operator was reaching for is the only reason they nested at all.

WHAT THIS FILE ASSERTS
----------------------
§A  verify_chunk_signatures: the pair, the default, the bytes that land on the
    OFF arm, and the security-negative that says the flag narrows the per-chunk
    check and not authentication.
§B  DEFECT CANDIDATE #71: the nested pair — the same override with and without
    the handler.
§C  allow_unsigned_session_token: both refusals and the control that shows the
    gate only acts when a session token is actually present.
§D  brix_s3_token: bearer accepted/refused, SigV4 unaffected, the token-only
    consequence, and a tampered bearer.
§E  list_cache: stale vs fresh, what the staleness is keyed on, and that the
    stale answer is the previous answer rather than a broken one.
§F  zip_access: the member, the whole archive, the missing member, and a
    traversing member name.
§G  the parse tier for all five: values, arity, duplicates, placement.
§H  brix_backend_passthrough_persist — the last of the seven both-arms-unwritten
    directives, closed at parse level only (it has no reader; DEFECT #35).
§I  the source: the handler install and the five merge defaults are where this
    file says they are.

Ledger: lc-audit16f-s3flags (one http listener, sixteen locations, /metrics).
"""

import datetime as dt
import hashlib
import hmac
import io
import os
import re
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from urllib.parse import quote

import pytest
import requests

from config_parse import nginx_t
from fleet_lifecycle_ports import (
    PARSE_PLACEHOLDER_PORT,
    SHARED_PARSE_PLACEHOLDER_PORT,
)
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN, url_host
from utils.make_token import TokenIssuer

def _expression_1(forge_seed, seed):
    return (
        "0" * 64 if forge_seed else seed
    )

def _expression_2(tamper, index):
    return (
        tamper is not None and index == tamper
    )

def _expression_3(amz_date, decoded_len, scope, signed, forge_seed, seed):
    return (
        {
                "x-amz-date": amz_date,
                "x-amz-content-sha256": STREAMING,
                "x-amz-decoded-content-length": str(decoded_len),
                "Content-Encoding": "aws-chunked",
                "Authorization": (
                    f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, "
                    f"SignedHeaders={signed}, "
                    f"Signature={'0' * 64 if forge_seed else seed}")}
    )


def _guard_sign_1(session_token, sign_session_token, headers):
    if session_token and sign_session_token:
        headers.append(("x-amz-security-token", session_token))

def _guard_sign_2(session_token, out):
    if session_token:
        out["x-amz-security-token"] = session_token

def _guard_s3flags_3():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


pytestmark = [pytest.mark.timeout(600),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16f-s3flags")]

NAME = "lc-audit16f-s3flags"
ROOT = Path(__file__).resolve().parents[1]
MODULE_C = ROOT / "src/protocols/s3/module.c"
MERGE_C = ROOT / "src/protocols/s3/module_merge.c"

ACCESS_KEY = "AKIAAUDIT16F"
SECRET_KEY = "audit16f-secret-key"
REGION = "us-east-1"
ISSUER = "https://audit16f.example.com"
AUDIENCE = "audit16f-s3"

SEED = "seed.txt"
PAYLOAD = b"audit16f-s3-location-flags\n"
ARCHIVE = "arch.zip"
MEMBER = "inner.txt"
MEMBER_BODY = b"INNER MEMBER\n"
SUBKEYS = ("sub/a.txt", "sub/b.txt")

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
STREAMING = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"

# The three arms of each flag, by the bucket that carries them.  The bucket IS
# the location prefix: s3_parse_uri() reads the bucket out of the first URI
# segment, so an arm cannot be anything smaller than its own export.
ON, OFF, DEFAULT = 0, 1, 2
VERIFY = ("vcon", "vcoff", "vcdef")
SESSION = ("uston", "ustoff", "ustdef")
BEARER = ("tokon", "tokoff", "tokdef")
LISTING = ("lcon", "lcoff", "lcdef")
ZIP = ("zipon", "zipoff", "zipdef")
BUCKETS = VERIFY + SESSION + BEARER + LISTING + ZIP

# The nested pair under /vcon/, both addressing the vcon bucket.
NESTED_BARE = "vcon/sub"     # the override alone — no handler
NESTED_WHOLE = "vcon/deep"   # the override plus `brix_s3 on`

# The five, as (directive, merge-field, merging function) — §G and §I read this.
FLAGS = (
    ("brix_s3_verify_chunk_signatures", "verify_chunk_signatures"),
    ("brix_s3_allow_unsigned_session_token", "allow_unsigned_session_token"),
    ("brix_s3_token", "token_enable"),
    ("brix_s3_list_cache", "list_cache"),
    # brix_s3_zip_access became bare brix_zip_access on the COMMON module
    # (phase-101 W4): BRIX_HTTP_ALL_CONF scope, shared merge, stream twin —
    # none of this file's location-only/flag-slot/merges-to-off anchors hold
    # for it any more.  Its config surface is pinned by test_zip_unification
    # and test_audit16o_webdav_scoped_flag_arms; §F below still probes the
    # S3-plane BEHAVIOUR through the bare name.
)
FLAG_NAMES = [name for name, _ in FLAGS]

_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK), reason=f"nginx not executable: {NGINX_BIN}")


# --------------------------------------------------------------------------- #
# Client-side SigV4, byte-identical to the server's canonicalization           #
# (auth_sigv4_verify_crypto.c; build_canonical_qs sorts the parameters and      #
# percent-encodes name and value, which is why the query form exists here at    #
# all — an empty canonical-query line fails every `?list-type=2` request).      #
# --------------------------------------------------------------------------- #

def _signing_key(secret, date):
    key = hmac.new(f"AWS4{secret}".encode(), date.encode(), hashlib.sha256).digest()
    for part in (REGION.encode(), b"s3", b"aws4_request"):
        key = hmac.new(key, part, hashlib.sha256).digest()
    return key


def _canonical_query(query):
    if not query:
        return ""
    pairs = sorted((quote(k, safe="-_.~"), quote(v, safe="-_.~"))
                   for k, v in query.items())
    return "&".join(f"{k}={v}" for k, v in pairs)


def _host_header(port):
    """Exactly what requests will put in the Host header, so the signature is
    over the bytes the server sees rather than over a second spelling of them."""
    return f"{url_host(HOST)}:{port}"


def _sign(port, method, path, *, query=None, session_token=None,
          sign_session_token=True, secret=SECRET_KEY):
    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")

    headers = [("host", _host_header(port)), ("x-amz-date", amz_date)]
    _guard_sign_1(session_token, sign_session_token, headers)
    headers.sort()
    signed = ";".join(name for name, _ in headers)
    canonical_headers = "".join(f"{name}:{value}\n" for name, value in headers)

    canonical = (f"{method}\n{quote(path, safe='/-_.~')}\n"
                 f"{_canonical_query(query)}\n"
                 f"{canonical_headers}\n{signed}\nUNSIGNED-PAYLOAD")
    sts = (f"AWS4-HMAC-SHA256\n{amz_date}\n{date}/{REGION}/s3/aws4_request\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    signature = hmac.new(_signing_key(secret, date), sts.encode(),
                         hashlib.sha256).hexdigest()

    out = {"x-amz-date": amz_date,
           "Authorization": (
               "AWS4-HMAC-SHA256 "
               f"Credential={ACCESS_KEY}/{date}/{REGION}/s3/aws4_request, "
               f"SignedHeaders={signed}, Signature={signature}")}
    _guard_sign_2(session_token, out)
    return out


def _streaming_put(port, bucket, key, chunks, *, tamper=None, forge_seed=False):
    """A signed aws-chunked PUT.

    ``tamper`` corrupts one chunk's signature (the per-chunk chain, which is
    what brix_s3_verify_chunk_signatures decides to check).  ``forge_seed``
    corrupts the REQUEST's own signature instead — a different gate entirely,
    and the control that keeps §A from reading as "the flag disables auth".
    """
    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    scope = f"{date}/{REGION}/s3/aws4_request"
    key_material = _signing_key(SECRET_KEY, date)

    decoded_len = sum(len(chunk) for chunk in chunks)
    uri = f"/{bucket}/{key}"
    signed = ("content-encoding;host;x-amz-content-sha256;x-amz-date;"
              "x-amz-decoded-content-length")
    canonical_headers = (
        f"content-encoding:aws-chunked\n"
        f"host:{_host_header(port)}\n"
        f"x-amz-content-sha256:{STREAMING}\n"
        f"x-amz-date:{amz_date}\n"
        f"x-amz-decoded-content-length:{decoded_len}\n")
    canonical = (f"PUT\n{uri}\n\n{canonical_headers}\n{signed}\n"
                 "UNSIGNED-PAYLOAD")
    sts = (f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    seed = hmac.new(key_material, sts.encode(), hashlib.sha256).hexdigest()

    # Each chunk signs its own payload over the PREVIOUS signature, so the seed
    # is the first link of the chain even when the request carries a forged one.
    body = b""
    previous = _expression_1(forge_seed, seed)
    for index, payload in enumerate(list(chunks) + [b""]):
        chunk_sts = (f"AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n"
                     f"{previous}\n{EMPTY_SHA256}\n"
                     f"{hashlib.sha256(payload).hexdigest()}")
        signature = hmac.new(key_material, chunk_sts.encode(),
                             hashlib.sha256).hexdigest()
        previous = signature
        if _expression_2(tamper, index):
            signature = "0" * 64
        body += b"%x;chunk-signature=%s\r\n%s\r\n" % (
            len(payload), signature.encode(), payload)

    headers = _expression_3(amz_date, decoded_len, scope, signed, forge_seed, seed)
    return requests.put(f"http://{_host_header(port)}{uri}", headers=headers,
                        data=body, timeout=30)


# --------------------------------------------------------------------------- #
# Requests and responses                                                       #
# --------------------------------------------------------------------------- #

def _url(port, path):
    return f"http://{_host_header(port)}{path}"


def _get(port, path, *, query=None, headers=None, **kwargs):
    return requests.get(_url(port, path), params=query, headers=headers,
                        timeout=30, **kwargs)


def _signed_get(port, path, *, query=None, **sign_kwargs):
    return _get(port, path, query=query,
                headers=_sign(port, "GET", path, query=query, **sign_kwargs))


def _signed_put(port, path, body):
    return requests.put(_url(port, path), headers=_sign(port, "PUT", path),
                        data=body, timeout=30)


def _bearer_get(port, path, token):
    return _get(port, path, headers={"Authorization": f"Bearer {token}"})


def _code(response):
    """The S3 ``<Code>`` of an error response, or None when the body is not an
    S3 error at all — which is itself the observation §B makes."""
    match = re.search(r"<Code>([^<]+)</Code>", response.text)
    return match.group(1) if match else None


def _message(response):
    match = re.search(r"<Message>([^<]*)</Message>", response.text)
    return match.group(1) if match else ""


def _keys(response):
    """The Key elements of a ListObjectsV2 response, in the order returned."""
    assert response.status_code == 200, response.text[:300]
    return [el.text for el in ET.fromstring(response.text).findall(".//{*}Key")]


def _listing(port, bucket):
    return _keys(_signed_get(port, f"/{bucket}/", query={"list-type": "2"}))


def _metrics(port):
    response = _get(port, "/metrics")
    assert response.status_code == 200, response.text[:200]
    return response.text


def _metric(text, needle):
    """The value of one exposition line, 0.0 when the family never named it."""
    for line in text.splitlines():
        if line.startswith(needle + " "):
            return float(line.split()[-1])
    return 0.0


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

class _Planes:
    """The started instance and the issuer every bearer here is minted from."""

    def __init__(self, endpoint, issuer, data):
        self.endpoint = endpoint
        self.issuer = issuer
        self.data = data
        self.port = endpoint.port

    def token(self, **kwargs):
        return self.issuer.generate(scope="storage.read:/", **kwargs)

    def root(self, bucket):
        return self.data / bucket


@pytest.fixture
def s3flags(lifecycle, tmp_path):
    """Fifteen buckets, one listener, one key.

    Every arm is seeded identically, so a verdict that differs between two of
    them cannot be explained by their contents.  The listing arms get a subtree
    as well: the whole question §E asks is what a second listing says after
    something changed underneath.
    """
    _guard_s3flags_3()

    data = tmp_path / "data"
    for bucket in BUCKETS:
        (data / bucket).mkdir(parents=True)
        (data / bucket / SEED).write_bytes(PAYLOAD)
    for bucket in LISTING:
        (data / bucket / "sub").mkdir()
        for key in SUBKEYS:
            (data / bucket / key).write_bytes(PAYLOAD)

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(MEMBER, MEMBER_BODY.decode())
    blob = archive.getvalue()
    for bucket in ZIP:
        (data / bucket / ARCHIVE).write_bytes(blob)

    issuer = TokenIssuer(str(tmp_path / "tokens"), issuer=ISSUER,
                         audience=AUDIENCE)
    issuer.init_keys()

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16f_s3flags.conf",
        protocol="s3",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST,
                         "ACCESS_KEY": ACCESS_KEY,
                         "SECRET_KEY": SECRET_KEY,
                         "REGION": REGION,
                         "JWKS": issuer.jwks_path,
                         "ISSUER": ISSUER,
                         "AUDIENCE": AUDIENCE},
        reason="audit-16f the five S3 location flags at value granularity"))

    planes = _Planes(endpoint, issuer, data)
    planes.archive = blob
    return planes


# --------------------------------------------------------------------------- #
# §A — brix_s3_verify_chunk_signatures                                         #
# --------------------------------------------------------------------------- #

