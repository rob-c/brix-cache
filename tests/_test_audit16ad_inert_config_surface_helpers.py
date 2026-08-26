"""tests/test_audit16ad_inert_config_surface.py — audit tranche 16, file 30.

WHY THIS FILE EXISTS
    The combinatorial audit hunts flag directives whose second arm no config in
    this tree has ever written.  Two were left in that state that the earlier
    sweeps had passed over:

        brix_webdav_open_file_cache_errors   — `on` written once, `off` never
        brix_webdav_open_file_cache_events   — `off` written once, `on` never

    The single place either had ever appeared is one parse-only cell in
    test_audit15_zero_directive_parse.py:99-103, which asks whether the lines
    load and nothing else.  Writing the missing arms is what this file was
    opened to do.  What the missing arms turned out to be worth is the finding.

    A third directive rides along, for a different reason.
    `brix_backend_passthrough_persist` is NOT an unwritten arm: tranche 16's
    file 6 (test_audit16f_s3_location_flags.py §H) already writes both of its
    arms in all three HTTP scopes, and its inertness is already DEFECT
    CANDIDATE #35, pinned by test_audit15j_zero_coverage_stragglers.py.  What
    #35 has never had is a running server: every cell that pins it asks
    `nginx -t`, and a grep for the reader is not a measurement.  §C below is
    the behavioural half — three live locations differing by that directive and
    by nothing else — and §D adds the parse negatives (arity, bad value, three
    illegal scopes) that file 6, which only ever writes well-formed arms, has
    no cells for.

THE FINDING — DEFECT CANDIDATE #110
    Neither flag can have a second arm that means anything, because the whole
    family they belong to is never read.

    `brix_webdav_open_file_cache` is not a stub.  Its setter
    (module_directives.c:262-311) parses `max=`/`inactive=`/`off`, refuses a
    missing `max`, refuses a duplicate, and on success calls
    ngx_open_file_cache_init() — a real ngx_open_file_cache_t is allocated out of
    the config pool and stored on the location conf.  Four more directives
    (`_valid`, `_min_uses`, `_errors`, `_events`) fill in the four fields beside
    it (webdav_loc_conf.h:200-204), and config_merge.c:147-156 merges all five
    with defaults chosen to match stock nginx's.

    Then nothing happens.  No translation unit under src/, shared/ or client/
    calls ngx_open_cached_file(), and within webdav/ the five fields appear only
    in the command table, config.c's NGX_CONF_UNSET init, and that merge.  The
    allocation is the last event in the life of the cache.

    #110 is that family and only that family.  The same shape, one directive
    wide, is already on the books as DEFECT CANDIDATE #35 —
    brix_backend_passthrough_persist: command table (http_common.c:239), init
    (shared_conf.h:100), merge (:428-429), adopt macro (:441), and no reader.
    The five directives here earn a number of their own because they are a
    different subject and because they go one step further than #35 does: #35's
    flag is a field nothing consults, while this family reaches
    ngx_open_file_cache_init() and takes a real allocation out of the config
    pool before being forgotten.

WHY IT IS WORTH A NUMBER RATHER THAN A SHRUG
    An inert directive is not merely useless; it answers.  `nginx -t` accepts
    it, so an operator who writes

        brix_webdav_open_file_cache max=100000 inactive=60s;
        brix_webdav_open_file_cache_errors on;

    is told the file is good, and has every reason to believe the export now
    caches open file descriptors and negative lookups.  It does not.  The
    directive that in stock nginx is the standard answer to "my export stats the
    same file thousands of times a second" here does nothing at all, silently,
    and the operator's next move is to raise `max`.

    `_errors on` is the sharper half.  In stock nginx it caches ENOENT and
    EACCES for `valid` seconds — a real change in what a client is told about a
    file that has just been created, deleted, or had its permissions revoked.
    Configuring it here changes nothing, which is safe; but the same lines under
    a future implementation would change a security-relevant answer, and no test
    would have noticed either way.  §E below is written against that day.

WHAT THIS FILE DOES NOT CLAIM
    Not that the family SHOULD be wired.  A VFS-seam export does not open files
    the way a static-file location does (invariant 12: raw data syscalls live in
    src/fs/backend/), so an fd cache keyed on a filesystem path may be the wrong
    shape for this server entirely — in which case the cure is deletion, not
    implementation.  The claim here is only that the directives are accepted and
    inert, that no configuration of them is distinguishable from their absence,
    and that the accepting is what makes it a defect.

    Nor that the passthrough flag is a new finding.  It is #35, already pinned
    at the parse tier; what is new is that #35 has now been read off a running
    server instead of off `nginx -t` and a grep.  Nor is it dead code in the
    sense of unreachable: it is reachable, merged, and readable from any brix
    HTTP location conf.  It has no reader today.

HOW THE MEASUREMENT WORKS
    Every cell is a comparison against a control.  A test that only said "the
    cached location returns the right bytes" would pass just as happily with a
    working cache, so each probe is built to be one a working cache would FAIL:
    a file replaced by rename (new inode), a file truncated in place (same
    inode), a file deleted, a 404 followed by a create, a permission revoked
    after a successful read.  With `valid 1h` and `min_uses 1` configured, a
    live cache would still be holding every one of those when the next request
    arrives.  It never is.
"""

import http.client
import os
import stat
from pathlib import Path

import pytest
import requests

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

NAME = "lc-audit16ad-inert"
PORT = LIFECYCLE_SHARED_PORTS[NAME]["port"]

# The four cache planes.  CACHE_NONE is the control: not one directive of the
# family.  The two flag arms are the two the audit was opened for.
CACHE_ARMS = ("cache-on", "cache-eoff", "cache-voff", "cache-none")
# The three passthrough planes: `on`, `off`, and the merge default (0) written
# by omitting the line.
PP_ARMS = ("pp-on", "pp-off", "pp-abs")
# The read-only plane carrying the full cache configuration.
RO = "cache-ro"

TIMEOUT = 10

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

class _Planes:
    """One listener, eight locations, one export — addressed by URI prefix.

    The WebDAV resolver maps the full request URI under the export root, so
    `/cache-on/f.txt` is `<root>/cache-on/f.txt`: the planes are already
    disjoint on disk without eight roots, and a cell that writes into one can
    never be read by another.
    """

    def __init__(self, instance, root):
        self.instance = instance
        self.root = Path(root)

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        log = Path(self.instance.prefix) / "logs" / "error.log"
        return log.read_text(errors="replace") if log.exists() else ""

    def disk(self, arm, name):
        """The on-disk path a URI resolves to — the cells reach behind nginx's
        back through this, which is the whole method of §A."""
        return self.root / arm / name


@pytest.fixture(scope="module")
def planes(tmp_path_factory):
    """MODULE-scoped with its own harness, for the reason files 27-29 give: the
    port is fixed by the ledger, so a per-test start/stop races the OS releasing
    it.  Each cell owns its own file name, so the writes never collide.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("audit16ad") / "export"
    root.mkdir()
    for arm in CACHE_ARMS + PP_ARMS + (RO,):
        (root / arm).mkdir()

    harness = LifecycleHarness()
    try:
        instance = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16ad_inert_config_surface.conf",
            data_root=str(root),
            template_values={"BIND_HOST": BIND_HOST},
            reason="audit-16ad the never-read configuration surface: the five "
                   "brix_webdav_open_file_cache* directives and "
                   "brix_backend_passthrough_persist, both arms of each flag."))
        yield _Planes(instance, root)
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# HTTP helpers                                                                 #
# --------------------------------------------------------------------------- #

def _url(arm, name):
    return f"http://{HOST}:{PORT}/{arm}/{name}"


def _get(arm, name, **kw):
    return requests.get(_url(arm, name), timeout=TIMEOUT, **kw)


def _head(arm, name, **kw):
    return requests.head(_url(arm, name), timeout=TIMEOUT, **kw)


def _put(arm, name, data, **kw):
    return requests.put(_url(arm, name), data=data, timeout=TIMEOUT, **kw)


def _delete(arm, name, **kw):
    return requests.delete(_url(arm, name), timeout=TIMEOUT, **kw)


def _propfind(arm, name, depth="0", **kw):
    body = ('<?xml version="1.0"?>'
            '<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>')
    headers = {"Depth": depth, "Content-Type": "application/xml"}
    headers.update(kw.pop("headers", {}))
    return requests.request("PROPFIND", _url(arm, name), data=body,
                            headers=headers, timeout=TIMEOUT, **kw)


def _mkcol(arm, name, **kw):
    return requests.request("MKCOL", _url(arm, name), timeout=TIMEOUT, **kw)


def _options(arm, name, **kw):
    return requests.request("OPTIONS", _url(arm, name), timeout=TIMEOUT, **kw)


def _raw_get(path):
    """GET a request-target byte-for-byte as written.

    `requests` resolves dot segments in the URL before the request leaves the
    process, so a traversal handed to it never reaches nginx — the escape cells
    in §E would be asking urllib3 about its URL parser instead of asking the
    server about its path resolver.  http.client sends the string.
    """
    conn = http.client.HTTPConnection(HOST, PORT, timeout=TIMEOUT)
    try:
        conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", f"{HOST}:{PORT}")
        conn.putheader("Connection", "close")
        conn.endheaders()
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def _seed(planes, arm, name, payload):
    """Create a file behind nginx's back and read it once, so any cache that
    exists has been given the chance to fill.  `min_uses 1` is configured, so
    one read is enough to promote an entry in a live nginx open-file cache."""
    path = planes.disk(arm, name)
    path.write_bytes(payload)
    r = _get(arm, name)
    assert r.status_code == 200, r.text
    assert r.content == payload
    return path


def _uid(request):
    """A file name unique to the calling test, so the module needs no cleanup
    and a rerun cannot read the previous run's bytes."""
    return request.node.name.replace("[", "_").replace("]", "").replace("/", "_")


# --------------------------------------------------------------------------- #
# A. The cache is allocated and then never consulted                           #
# --------------------------------------------------------------------------- #

