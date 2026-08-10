"""
matrix_layer.py — the (protocol × auth × tls × backend) node factory.

THE GAP this closes: every cell of the coverage matrix was a hand-written
module with its own hand-written config template. 299 `NginxInstanceSpec(...)`
literals across 212 modules, zero `pytest_generate_tests`, zero `indirect=True`
— so adding a backend or an auth mechanism meant writing N new modules by hand,
and the matrix re-sparsified with every addition.
docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md §7 item 19.

WHAT IT GIVES YOU

    @pytest.mark.matrix(protocols=["root", "webdav"], auths=["none", "token"],
                        tls=[False, True], backends=["posix", "xroot"])
    def test_something(matrix_node):
        assert matrix_node.read("obj.bin") == matrix_node.seed("obj.bin", b"...")

`conftest.pytest_generate_tests` expands the mark into one parametrized case per
cell, `matrix_node` stands the cell up through the registry lifecycle harness,
and `Node` hides the per-protocol client so the test body is written once.

UNREACHABLE CELLS ARE PARAMETRIZED, NOT DROPPED. `supported()` is the single
place that says why a combination cannot exist (S3 authenticates with SigV4, not
a bearer — INVARIANT 6; XrdCl refuses to put a token on a cleartext wire; WebDAV
GSI means a client certificate, which means TLS). An unreachable cell still
appears in the report as a skip WITH ITS REASON, because "this cell is empty"
and "this cell is impossible" are the two things the audit found the suite could
not tell apart.

TWO TEMPLATES, NOT N. `configs/nginx_matrix_stream.conf` and
`configs/nginx_matrix_http.conf` carry `{AUTH}` / `{TLS}` / `{STORAGE}`
placeholders that this module fills; nothing here writes config text to disk.

PORTS: the cell instances reuse two ledger names, `lc-matrix-node` and
`lc-matrix-origin`, because only one cell is up at a time — every matrix module
must therefore carry `@pytest.mark.xdist_group("lc-matrix")`.
"""
import datetime as dt
import hashlib
import hmac
import os
import ssl
import subprocess
import urllib.parse
import urllib.request

import pytest

from server_registry import NginxInstanceSpec
from settings import (BIND_HOST, CA_CERT, CA_DIR, HOST, PKI_DIR, PROXY_STD,
                      TEST_ROOT)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
TOKEN_DIR = os.path.join(TEST_ROOT, "tokens")
CLIENT_CERT = os.path.join(PKI_DIR, "user", "usercert.pem")
CLIENT_KEY = os.path.join(PKI_DIR, "user", "userkey.pem")

NODE_NAME = "lc-matrix-node"
ORIGIN_NAME = "lc-matrix-origin"

BUCKET = "matrixbucket"
S3_ACCESS_KEY = "matrix-access"
S3_SECRET_KEY = "matrix-secret-key"
S3_REGION = "us-east-1"

PROTOCOLS = ("root", "webdav", "s3")
AUTHS = ("none", "gsi", "token", "sigv4")
BACKENDS = ("posix", "xroot", "http")

_STREAM_PROTOCOLS = ("root",)


class Cell:
    """One (protocol, auth, tls, backend) coordinate. Hashable and printable —
    its `id` is what shows up in the pytest report."""

    __slots__ = ("protocol", "auth", "tls", "backend")

    def __init__(self, protocol, auth, tls, backend):
        self.protocol, self.auth, self.tls, self.backend = (
            protocol, auth, tls, backend)

    @property
    def id(self):
        return (f"{self.protocol}-{self.auth}-"
                f"{'tls' if self.tls else 'clear'}-{self.backend}")

    def __repr__(self):
        return f"Cell({self.id})"


def supported(cell):
    """Why this cell cannot exist, or None if it can.

    Every entry is a product constraint, not a harness limitation — read it
    before adding a cell to a matrix mark and finding it skipped.
    """
    for check in _SUPPORT_CHECKS:
        reason = check(cell)
        if reason:
            return reason
    return None


def _known_axis(cell):
    axes = (("protocol", PROTOCOLS), ("auth", AUTHS), ("backend", BACKENDS))
    for name, values in axes:
        value = getattr(cell, name)
        if value not in values:
            return f"unknown {name} {value!r}"
    return None


def _s3_auth(cell):
    if cell.protocol == "s3" and cell.auth not in ("none", "sigv4"):
        return "S3 authenticates with SigV4, never a bearer or a proxy (INVARIANT 6)"
    if cell.protocol != "s3" and cell.auth == "sigv4":
        return "SigV4 is the S3 request-signing scheme; no other plane offers it"
    return None


def _secure_transport(cell):
    return _root_token_transport(cell) or _webdav_gsi_transport(cell)


def _root_token_transport(cell):
    if cell.protocol == "root" and cell.auth == "token" and not cell.tls:
        return ("XrdCl refuses to send a bearer over a cleartext wire, so a "
                "root:// token plane is only drivable with brix_tls on")
    return None


def _webdav_gsi_transport(cell):
    if cell.protocol == "webdav" and cell.auth == "gsi" and not cell.tls:
        return "WebDAV GSI is a client certificate, which requires TLS"
    return None


def _s3_http_origin(cell):
    if cell.backend == "http" and cell.protocol == "s3":
        return ("the S3 front over an http:// origin needs a co-hosted origin "
                "and worker_processes 2 — see test_s3_nested_gateway.py")
    return None


_SUPPORT_CHECKS = (_known_axis, _s3_auth, _secure_transport, _s3_http_origin)


def expand(protocols=PROTOCOLS, auths=("none",), tls=(False,),
           backends=("posix",)):
    """Cross the axes into (cells, ids) for `metafunc.parametrize`."""
    cells = [Cell(p, a, t, b)
             for p in protocols for a in auths for t in tls for b in backends]
    return cells, [c.id for c in cells]


# --------------------------------------------------------------------------- #
# Config rendering — the placeholders the two templates expose.                #
# --------------------------------------------------------------------------- #
def _indent(lines, pad="        "):
    return "".join(f"{pad}{ln}\n" for ln in lines if ln)


def _stream_auth(cell):
    if cell.auth == "gsi":
        return _indent(["brix_auth gsi;",
                        f"brix_certificate     {_cert()};",
                        f"brix_certificate_key {_key()};",
                        f"brix_trusted_ca      {CA_CERT};"])
    if cell.auth == "token":
        return _indent(["brix_auth token;",
                        f"brix_token_jwks     {TOKEN_DIR}/jwks.json;",
                        'brix_token_issuer   "https://test.example.com";',
                        'brix_token_audience "nginx-xrootd";'])
    return _indent(["brix_auth none;"])


def _cert():
    return os.path.join(PKI_DIR, "server", "hostcert.pem")


def _key():
    return os.path.join(PKI_DIR, "server", "hostkey.pem")


def _stream_tls(cell):
    if not cell.tls:
        return ""
    if cell.auth == "gsi":
        # The GSI block already names the service certificate; naming it twice
        # is `[emerg] "brix_certificate" directive is duplicate`.
        return _indent(["brix_tls on;"])
    return _indent(["brix_tls on;",
                    f"brix_certificate     {_cert()};",
                    f"brix_certificate_key {_key()};"])


def _storage(cell, origin_port, data_root, http_plane):
    """The one line that says where the bytes live."""
    if cell.backend == "xroot":
        return _indent([f"brix_storage_backend root://{BIND_HOST}:{origin_port};"])
    if cell.backend == "http":
        return _indent([f"brix_storage_backend http://{BIND_HOST}:{origin_port};"])
    if http_plane:
        return _indent([f"brix_storage_backend posix:{data_root};"])
    return _indent([f"brix_export {data_root};"])


def _http_location(cell, origin_port, data_root):
    body = [f"brix_{'s3' if cell.protocol == 's3' else 'webdav'} on;"]
    body.append("brix_allow_write on;")
    if cell.protocol == "s3":
        body += [f"brix_s3_bucket   {BUCKET};", "brix_s3_max_keys 1000;"]
        if cell.backend != "posix":
            # A remote-backed S3 front still resolves its keys against a local
            # export root; without one the bucket path is answered NoSuchKey
            # before the backend is ever dialled.  Its own (empty) tree also
            # makes "the bytes are upstream" a filesystem fact.
            body.append(f"brix_export {data_root};")
        if cell.auth == "sigv4":
            body += [f"brix_s3_access_key {S3_ACCESS_KEY};",
                     f"brix_s3_secret_key {S3_SECRET_KEY};",
                     f"brix_s3_region     {S3_REGION};"]
    elif cell.auth == "token":
        body += ["brix_webdav_auth required;",
                 f"brix_webdav_token_jwks     {TOKEN_DIR}/jwks.json;",
                 'brix_webdav_token_issuer   "https://test.example.com";',
                 'brix_webdav_token_audience "nginx-xrootd";']
    elif cell.auth == "gsi":
        body += ["brix_webdav_auth required;", f"brix_trusted_ca_dir {CA_DIR};"]
    else:
        body += ["brix_webdav_auth none;"]
    return (_storage(cell, origin_port, data_root, http_plane=True)
            + _indent(body, pad="            "))


def _http_server_extra(cell):
    if not cell.tls:
        return ""
    lines = [f"ssl_certificate     {_cert()};",
             f"ssl_certificate_key {_key()};"]
    if cell.auth == "gsi":
        lines += ["ssl_verify_client optional_no_ca;", "ssl_verify_depth 10;",
                  "brix_webdav_proxy_certs on;"]
    return _indent(lines)


# --------------------------------------------------------------------------- #
# The node.                                                                    #
# --------------------------------------------------------------------------- #
class Node:
    """A running cell: the instance, where its bytes really live, and one
    read/seed pair that hides the per-protocol client."""

    def __init__(self, cell, endpoint, store, lifecycle, token=None):
        self.cell = cell
        self.endpoint = endpoint
        self.port = endpoint.port
        self.store = store            # the dir a seeded object must land in
        self.token = token
        self._lc = lifecycle

    # -- seeding ---------------------------------------------------------- #
    def seed(self, name, body):
        """Write `body` where the cell's storage will find it, and return it."""
        path = os.path.join(self.store, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)
        os.chmod(path, 0o644)
        return body

    # -- reading ---------------------------------------------------------- #
    def read(self, name, *, authenticated=True, tmp=None):
        """Fetch `name` through the cell's own protocol and credential.

        Returns bytes, or raises `Refused` when the server declined — the two
        outcomes every matrix test distinguishes.
        """
        if self.cell.protocol == "root":
            return self._read_root(name, authenticated, tmp)
        return self._read_http(name, authenticated)

    # -- per-protocol clients --------------------------------------------- #
    def _read_root(self, name, authenticated, tmp):
        dst_dir = str(tmp or self.store)
        dst = os.path.join(dst_dir, f".matrix-out-{os.getpid()}")
        env = self._root_environment(authenticated)
        scheme = "roots" if self.cell.tls else "root"
        url = f"{scheme}://{HOST}:{self.port}/{name}"
        try:
            return _run_root_client(url, dst, env)
        finally:
            _remove_output(dst)

    def _root_environment(self, authenticated):
        env = dict(os.environ)
        env.pop("LD_LIBRARY_PATH", None)
        env.pop("BEARER_TOKEN", None)
        env.pop("X509_USER_PROXY", None)
        env["X509_CERT_DIR"] = CA_DIR
        if not authenticated:
            return env
        credential = {
            "gsi": ("X509_USER_PROXY", PROXY_STD),
            "token": ("BEARER_TOKEN", self.token),
        }.get(self.cell.auth)
        if credential:
            env[credential[0]] = credential[1]
        return env

    def _read_http(self, name, authenticated):
        key = f"{BUCKET}/{name}" if self.cell.protocol == "s3" else name
        scheme = "https" if self.cell.tls else "http"
        url = f"{scheme}://{HOST}:{self.port}/{key}"
        headers = self._http_headers(key, authenticated)
        status, body = _http_get(url, headers, self.cell)
        if status != 200:
            raise Refused(status, body[:300].decode("utf-8", "replace"))
        return body

    def _http_headers(self, key, authenticated):
        headers = {}
        if not authenticated:
            return headers
        if self.cell.auth == "token":
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.cell.auth == "sigv4":
            headers.update(sigv4_headers("GET", HOST, self.port, f"/{key}"))
        return headers


class Refused(Exception):
    """The server declined the read. `.code` is the client return code
    (root://) or the HTTP status; `.detail` is the tail of what it said."""

    def __init__(self, code, detail=""):
        super().__init__(f"refused: code={code} {detail}")
        self.code = code
        self.detail = detail


def _run_root_client(url, dst, env):
    proc = subprocess.run(
        [XRDCP, "-f", url, dst], env=env, capture_output=True, timeout=120
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace")[-300:]
        raise Refused(proc.returncode, detail)
    with open(dst, "rb") as handle:
        return handle.read()


def _remove_output(path):
    if os.path.exists(path):
        os.unlink(path)


def _http_get(url, headers, cell):
    ctx = None
    if url.startswith("https"):
        ctx = ssl.create_default_context(cafile=CA_CERT)
        ctx.check_hostname = False
        if cell.auth == "gsi":
            ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:                     # TLS refusal, reset
        raise Refused(-1, str(e.reason)) from None


def sigv4_headers(method, host, port, path):
    """SigV4 header-auth for the matrix S3 planes (host;x-amz-date,
    UNSIGNED-PAYLOAD — the same canonicalization the server performs)."""
    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    canonical = (f"{method}\n{urllib.parse.quote(path, safe='/-_.~')}\n\n"
                 f"host:{host}:{port}\nx-amz-date:{amz_date}\n\n"
                 "host;x-amz-date\nUNSIGNED-PAYLOAD")
    sts = ("AWS4-HMAC-SHA256\n" f"{amz_date}\n"
           f"{date}/{S3_REGION}/s3/aws4_request\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    k = hmac.new(f"AWS4{S3_SECRET_KEY}".encode(), date.encode(),
                 hashlib.sha256).digest()
    for part in (S3_REGION, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    return {
        "x-amz-date": amz_date,
        "Authorization": (
            f"AWS4-HMAC-SHA256 "
            f"Credential={S3_ACCESS_KEY}/{date}/{S3_REGION}/s3/aws4_request, "
            f"SignedHeaders=host;x-amz-date, Signature={sig}"),
    }


# --------------------------------------------------------------------------- #
# The factory.                                                                 #
# --------------------------------------------------------------------------- #
def make_node(cell, *, tmp, lifecycle, token=None):
    """Stand the cell up (plus its origin, when the backend is remote)."""
    reason = supported(cell)
    if reason:
        pytest.skip(f"{cell.id}: {reason}")

    base = str(tmp)
    data_root = os.path.join(base, "data")
    os.makedirs(data_root, exist_ok=True)

    origin_port, store = None, data_root
    if cell.backend in ("xroot", "http"):
        origin_root = os.path.join(base, "origin")
        os.makedirs(origin_root, exist_ok=True)
        origin_cell = Cell("root" if cell.backend == "xroot" else "webdav",
                           "none", False, "posix")
        origin_ep = lifecycle.start(_spec(origin_cell, ORIGIN_NAME, origin_root,
                                          None, "matrix origin"))
        origin_port, store = origin_ep.port, origin_root

    endpoint = lifecycle.start(_spec(cell, NODE_NAME, data_root, origin_port,
                                     f"matrix cell {cell.id}"))
    return Node(cell, endpoint, store, lifecycle, token=token)


def _spec(cell, name, data_root, origin_port, reason):
    if cell.protocol in _STREAM_PROTOCOLS:
        return NginxInstanceSpec(
            name=name, template="nginx_matrix_stream.conf", protocol="root",
            readiness="tcp", data_root=data_root, reason=reason,
            template_values={
                "STORAGE": _storage(cell, origin_port, data_root,
                                    http_plane=cell.backend != "posix"),
                "AUTH": _stream_auth(cell),
                "TLS": _stream_tls(cell),
            })
    return NginxInstanceSpec(
        name=name, template="nginx_matrix_http.conf", protocol="http",
        readiness="tcp", data_root=data_root, reason=reason,
        template_values={
            "LISTEN_OPTS": " ssl" if cell.tls else "",
            "SERVER_EXTRA": _http_server_extra(cell),
            "LOCATION_BODY": _http_location(cell, origin_port, data_root),
        })
