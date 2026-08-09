"""Phase-36 §7.2.3 — WebDAV / XrdHttp over IPv6 (HTTP client).

Exercises the WebDAV method surface (GET/HEAD/PUT + Range + Want-Digest, DELETE,
MKCOL, MOVE/COPY, PROPFIND depth 0/1, LOCK/UNLOCK, OPTIONS) against the dedicated
"ipv6-webdav" nginx instance bound to the IPv6 loopback ``[::1]`` and pre-started
by ``manage_test_servers.sh start-all``
(``start_dedicated_nginx "ipv6-webdav" "nginx_ipv6_webdav.conf" "${IPV6_WEBDAV_PORT}"``),
serving ``IPV6_WEBDAV_DATA_ROOT`` as an anonymous, writable WebDAV root
(``tests/configs/nginx_ipv6_webdav.conf``: ``listen [::1]:{PORT};`` +
``brix_webdav on; brix_webdav_auth none; brix_allow_write on;``).

The Python ``requests`` / ``http.client`` stack handles the ``[::1]`` bracket
form correctly (unlike the PyXRootD root:// client, which mishandles
``root://[::1]`` literals), so every request simply targets
``http://[::1]:IPV6_WEBDAV_PORT``.

GATING vs REGRESSION (phase-36 §7.3):
  * The PROPFIND / MOVE / COPY ``Destination``-header cases are tagged GATING:
    they assert the server never emits a bare (unbracketed) IPv6 literal into a
    href / re-emitted ``Destination`` (``webdav/propfind.c``; the bracket-on-emit
    contract).  A bare ``::1`` in a ``host:port`` authority is ambiguous, so the
    correct behaviour is *relative* hrefs (no host literal at all) — that is what
    these tests pin.
  * Everything else is REGRESSION / SMOKE: it proves WebDAV/XrdHttp functions
    identically over IPv6 as over IPv4, exercising the already-clean socket /
    resolution layer over ``[::1]``.

Skip discipline (never fail on instance-absent):
  * every test depends on the session fixture ``requires_ipv6_loopback`` (auto,
    via the module-scoped autouse ``_ipv6_webdav`` fixture);
  * ``reachable6(IPV6_WEBDAV_PORT)`` probes the dedicated instance and skips
    cleanly if it is down.

Run with ``TEST_SKIP_SERVER_SETUP=1`` against an already-running start-all.
"""

import os
import socket
import uuid
import zlib
import xml.etree.ElementTree as ET

import pytest

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False

from settings import HOST6, IPV6_WEBDAV_DATA_ROOT, IPV6_WEBDAV_PORT, url_host

DAV_NS = "DAV:"

# IPv6 literal must be bracketed in a URL authority; requests/http.client handle
# this correctly.  This is the whole point of the IPv6 WebDAV suite.
BASE_URL = f"http://{url_host(HOST6)}:{IPV6_WEBDAV_PORT}"

# Seed file content (24 bytes, matches the harness-seeded test.txt convention).
SEED_NAME = "ipv6_seed.txt"
SEED_CONTENT = b"hello from nginx-xrootd\n"


# ---------------------------------------------------------------------------
# Reachability probe (AF_INET6 loopback) — mirrors tests/test_ipv6_s3.py so a
# same-port IPv4 listener can never mask a down IPv6 instance.
# ---------------------------------------------------------------------------
def reachable6(port: int, timeout: float = 3.0) -> bool:
    """True if [::1]:port accepts an IPv6 TCP connection."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((HOST6, port, 0, 0))
            return True
    except OSError:
        return False


@pytest.fixture(scope="module", autouse=True)
def _ipv6_webdav(requires_ipv6_loopback):
    """Gate the whole module on IPv6 loopback + a live ipv6-webdav instance, and
    seed a readable file into the (shared-filesystem) data root.

    Depending on the session-scoped ``requires_ipv6_loopback`` makes every test a
    clean no-op on hosts without usable ``::1``.  We then probe the dedicated
    instance and skip if it is down — instance-absent never reddens the suite.
    """
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    # The dedicated instance shares this local filesystem (DATA_DIR ==
    # IPV6_WEBDAV_DATA_ROOT == ${TEST_ROOT}/data-ipv6-webdav).  start-all creates
    # and seeds it, but a TEST_SKIP_SERVER_SETUP run may target a freshly wiped
    # tree, so seed a known-readable file defensively.
    os.makedirs(IPV6_WEBDAV_DATA_ROOT, exist_ok=True)
    seed_path = os.path.join(IPV6_WEBDAV_DATA_ROOT, SEED_NAME)
    with open(seed_path, "wb") as f:
        f.write(SEED_CONTENT)

    if not reachable6(IPV6_WEBDAV_PORT):
        pytest.skip(
            f"dedicated ipv6-webdav nginx not reachable on [{HOST6}]:{IPV6_WEBDAV_PORT} — "
            f"run tests/manage_test_servers.sh start-all"
        )


# ---------------------------------------------------------------------------
# URL + method helpers (mirror tests/test_http_webdav.py /
# test_http_webdav_status_codes.py, retargeted at http://[::1]:PORT).
# ---------------------------------------------------------------------------
def _url(path):
    return f"{BASE_URL}{path}"


def _uid():
    return uuid.uuid4().hex[:12]


def _put(path, data=b"", **kw):
    return requests.put(_url(path), data=data, timeout=10, **kw)


def _get(path, **kw):
    return requests.get(_url(path), timeout=10, **kw)


def _head(path, **kw):
    return requests.head(_url(path), timeout=10, **kw)


def _delete(path, **kw):
    return requests.delete(_url(path), timeout=10, **kw)


def _mkcol(path, **kw):
    return requests.request("MKCOL", _url(path), timeout=10, **kw)


def _propfind(path, depth="1", body=None, **kw):
    if body is None:
        body = (
            '<?xml version="1.0"?>'
            '<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
        )
    headers = {"Depth": depth, "Content-Type": "application/xml"}
    headers.update(kw.pop("headers", {}))
    return requests.request(
        "PROPFIND", _url(path), data=body, headers=headers, timeout=10, **kw
    )


def _move(src, dst, overwrite="T", **kw):
    headers = {"Destination": f"{BASE_URL}{dst}", "Overwrite": overwrite}
    headers.update(kw.pop("headers", {}))
    return requests.request("MOVE", _url(src), headers=headers, timeout=10, **kw)


def _copy(src, dst, overwrite="T", depth=None, **kw):
    headers = {"Destination": f"{BASE_URL}{dst}", "Overwrite": overwrite}
    if depth is not None:
        headers["Depth"] = depth
    headers.update(kw.pop("headers", {}))
    return requests.request("COPY", _url(src), headers=headers, timeout=10, **kw)


def _lock(path, timeout=None, **kw):
    headers = {}
    if timeout:
        headers["Timeout"] = f"Second-{timeout}"
    headers.update(kw.pop("headers", {}))
    body = kw.pop(
        "data",
        '<?xml version="1.0" encoding="utf-8" ?>'
        '<D:lockinfo xmlns:D="DAV:">'
        "<D:lockscope><D:exclusive/></D:lockscope>"
        "<D:locktype><D:write/></D:locktype>"
        "</D:lockinfo>",
    )
    return requests.request(
        "LOCK", _url(path), data=body, headers=headers, timeout=10, **kw
    )


def _unlock(path, token, **kw):
    if not token.startswith("<"):
        token = f"<{token}>"
    headers = {"Lock-Token": token}
    headers.update(kw.pop("headers", {}))
    return requests.request(
        "UNLOCK", _url(path), headers=headers, timeout=10, **kw
    )


def _hrefs(xml_text):
    """Return every <D:href> text from a 207 Multi-Status body.

    NOTE: this descends into *all* hrefs, including those nested inside live
    properties such as ``<D:owner><D:href>...</D:href></D:owner>`` (the DAV:owner
    principal href, e.g. ``anonymous``).  It is the right helper for the
    host-literal scan (a bare ``::1`` must not appear in *any* href) but it
    over-counts for "one response per resource" assertions — use
    ``_response_hrefs`` for those.
    """
    root = ET.fromstring(xml_text)
    return [el.text or "" for el in root.iter(f"{{{DAV_NS}}}href")]


def _response_hrefs(xml_text):
    """Return one resource href per ``<D:response>`` — the direct-child
    ``<D:response><D:href>`` only, ignoring hrefs nested inside live properties
    (e.g. the ``<D:owner>`` principal href).  This is the per-resource count the
    PROPFIND multistatus actually models."""
    root = ET.fromstring(xml_text)
    out = []
    for resp in root.iter(f"{{{DAV_NS}}}response"):
        href = resp.find(f"{{{DAV_NS}}}href")
        if href is not None:
            out.append(href.text or "")
    return out


# ---------------------------------------------------------------------------
# OPTIONS  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------

def _assert_href_has_no_host_literal(href: str):
    """A WebDAV href must not embed the IPv6 host literal.  A bare ``::1`` would
    be the §3 bracket bug; an absolute ``http://[::1]:PORT/...`` (bracketed or
    not) is also wrong here because nginx emits server-relative hrefs."""
    for bad in ("::1", "[::1]", "[::"):  # net-literal-allow: malformed IPv6 host payloads under test
        assert bad not in href, f"href carries IPv6 host literal {bad!r}: {href!r}"


# ---------------------------------------------------------------------------
# PROPFIND allprop properties  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
