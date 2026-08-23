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

@pytest.mark.parametrize("arm", CACHE_ARMS)
class TestTheCacheIsAllocatedAndNeverConsulted:
    """Five probes a live open-file cache would fail, run on every cache arm
    and on the control.

    Each location is configured `max=1024 inactive=1h`, `valid 1h`,
    `min_uses 1` — parameters chosen so that a working cache could not possibly
    have expired between the two requests of any cell below.  `_seed` performs
    the first read, which is the fill; the assertion is about the second.
    """

    def test_two_reads_of_an_unchanged_file_agree(self, planes, request, arm):
        """The baseline.  Without it a later cell's `200` could be read as the
        location being broken rather than as the cache being absent."""
        name = _uid(request) + ".bin"
        _seed(planes, arm, name, b"16ad baseline\n")
        r = _get(arm, name)
        assert r.status_code == 200, r.text
        assert r.content == b"16ad baseline\n"

    def test_a_replaced_inode_is_visible_on_the_next_request(self, planes,
                                                             request, arm):
        """Rename-over: the path now names a DIFFERENT inode.

        This is the cell a cached file descriptor cannot survive.  nginx's
        open-file cache holds the fd itself, so a location that had really
        cached this file would keep serving the old inode's bytes for `valid`
        seconds — an hour, here — no matter what the directory entry points at.
        """
        name = _uid(request) + ".bin"
        path = _seed(planes, arm, name, b"first inode\n")
        replacement = path.with_suffix(".new")
        replacement.write_bytes(b"second inode, longer payload\n")
        replacement.replace(path)

        r = _get(arm, name)
        assert r.status_code == 200, r.text
        assert r.content == b"second inode, longer payload\n"

    def test_a_truncation_in_place_is_visible_on_the_next_request(
            self, planes, request, arm):
        """Same inode, new size — the cached *stat* rather than the cached fd.

        A live cache stores st_size with the entry, so Content-Length is the
        field that would go stale here even where the fd stayed valid.
        """
        name = _uid(request) + ".bin"
        path = _seed(planes, arm, name, b"a much longer original payload\n")
        with open(path, "r+b") as fh:
            fh.truncate(0)
            fh.write(b"short\n")

        r = _get(arm, name)
        assert r.status_code == 200, r.text
        assert r.content == b"short\n"
        assert r.headers["Content-Length"] == "6"

    def test_a_deleted_file_is_a_404_on_the_next_request(self, planes, request,
                                                         arm):
        """Existence is not cached either.  With `_events on` configured, stock
        nginx would evict on the inotify delete; with `_events off` it would
        serve the stale entry until `valid`.  Both arms answer 404 at once,
        which is what says neither arm was consulted."""
        name = _uid(request) + ".bin"
        path = _seed(planes, arm, name, b"about to vanish\n")
        path.unlink()

        r = _get(arm, name)
        assert r.status_code == 404, f"{r.status_code}: {r.text}"

    def test_a_404_then_a_create_is_a_200_on_the_next_request(self, planes,
                                                              request, arm):
        """The `_errors` cell, and the reason that flag has two arms at all.

        In stock nginx `open_file_cache_errors on` caches the ENOENT for
        `valid` seconds: this sequence would answer 404 twice.  `errors off`
        would answer 404 then 200.  The two arms are configured on adjacent
        locations here and both answer 404 then 200 — the flag has no arm that
        changes the answer because the lookup it would change never runs.
        """
        name = _uid(request) + ".bin"
        assert _get(arm, name).status_code == 404

        planes.disk(arm, name).write_bytes(b"created after the miss\n")
        r = _get(arm, name)
        assert r.status_code == 200, f"{r.status_code}: {r.text}"
        assert r.content == b"created after the miss\n"


# --------------------------------------------------------------------------- #
# B. Arm against arm, and every arm against the control                        #
# --------------------------------------------------------------------------- #

# A fixed mtime stamped on every seeded file before it is read.  nginx builds a
# weak ETag out of mtime and size, so pinning the mtime is what lets two arms be
# compared on the ETag itself rather than on "both had one" — the comparison is
# then byte-for-byte and a difference of any kind would show.
FIXED_MTIME = 1600000000

# Response headers that must differ between two arms even when nothing else
# does: the clock, and the connection bookkeeping.
_VOLATILE = {"date", "connection", "keep-alive", "server"}


def _headers(response):
    return tuple(sorted((k.lower(), v) for k, v in response.headers.items()
                        if k.lower() not in _VOLATILE))


def _stamp(path):
    os.utime(path, (FIXED_MTIME, FIXED_MTIME))


def _fingerprint(planes, arm, tag):
    """Run one scripted request sequence against `arm` and return everything it
    answered, in order.

    The sequence deliberately covers a read, a metadata read, a property read,
    a capability probe, a write, a re-read and a delete — the whole surface a
    location has.  Two arms whose fingerprints are equal are the same location
    written twice, which is the claim §B and §C are each making.
    """
    out = []
    miss = f"{tag}-missing.bin"
    out.append(("get-missing", _get(arm, miss).status_code))

    name = f"{tag}-read.bin"
    path = planes.disk(arm, name)
    path.write_bytes(b"16ad fingerprint payload\n")
    _stamp(path)

    r = _get(arm, name)
    out.append(("get", r.status_code, r.content, _headers(r)))
    r = _head(arm, name)
    out.append(("head", r.status_code, _headers(r)))
    r = _propfind(arm, name)
    out.append(("propfind", r.status_code, f"/{arm}/{name}" in r.text))
    r = _options(arm, name)
    out.append(("options", r.status_code,
                tuple(sorted(r.headers.get("Allow", "").replace(" ", "").split(","))),
                r.headers.get("DAV", "")))

    written = f"{tag}-write.bin"
    out.append(("put", _put(arm, written, b"written by the fingerprint\n").status_code))
    r = _get(arm, written)
    out.append(("get-written", r.status_code, r.content))
    out.append(("delete", _delete(arm, written).status_code))
    out.append(("get-deleted", _get(arm, written).status_code))
    return tuple(out)


class TestTheArmsAreTheSameLocationWrittenFourTimes:
    """The four cache planes answer identically to everything.

    §A showed that no probe distinguishes a configured cache from an absent
    one.  This section is the other direction: nothing at all distinguishes
    them, including the headers, so the difference between `_errors on` and
    `_errors off` is not merely invisible to the probes §A chose — it is
    invisible.
    """

    def test_every_cache_arm_answers_exactly_as_the_control_does(self, planes):
        control = _fingerprint(planes, "cache-none", "fp")
        for arm in CACHE_ARMS:
            if arm == "cache-none":
                continue
            assert _fingerprint(planes, arm, "fp") == control, (
                f"{arm} differs from the cache-none control")

    def test_the_two_flag_arms_differ_from_each_other_in_nothing(self, planes):
        """`_errors on` + `_events on` against `_errors off` + `_events on`,
        and against `_errors on` + `_events off`.  These three locations are the
        arms this file was opened to write; the assertion is that writing them
        was the whole of what could be done with them."""
        both_on = _fingerprint(planes, "cache-on", "fp2")
        assert _fingerprint(planes, "cache-eoff", "fp2") == both_on
        assert _fingerprint(planes, "cache-voff", "fp2") == both_on


# --------------------------------------------------------------------------- #
# C. brix_backend_passthrough_persist — DEFECT CANDIDATE #35, measured live    #
# --------------------------------------------------------------------------- #

class TestThePassthroughPersistArms:
    """`on`, `off`, and absent.

    The merge default is 0 (shared_conf.h:428-429), so `off` and absent are the
    same location by construction and the third plane is what turns that into a
    measurement.  All three agree because the flag has no reader — DEFECT
    CANDIDATE #35, pinned at the parse tier by
    test_audit15j_zero_coverage_stragglers.py and written in all three HTTP
    scopes by tranche-16 file 6.  Neither of those starts a server; these cells
    are the first that do, which is the difference between "no reader was
    found" and "no reader answered".
    """

    def test_on_off_and_absent_answer_identically(self, planes):
        prints = {arm: _fingerprint(planes, arm, "pp") for arm in PP_ARMS}
        assert prints["pp-off"] == prints["pp-abs"], (
            "off and absent must be the merge default twice")
        assert prints["pp-on"] == prints["pp-abs"], (
            "the on arm has no reader, so it cannot differ")

    def test_the_flag_does_not_change_a_posix_backend_into_a_passthrough(
            self, planes):
        """The name says persistence across a passthrough; the export here is
        posix and there is no upstream to pass through to.  If the flag were
        read anywhere on this path, the most likely shape of the bug would be a
        location that stopped resolving locally — so the cell that matters is
        that the bytes still come off the disk they were written to."""
        payload = b"16ad passthrough locality\n"
        for arm in PP_ARMS:
            name = "locality.bin"
            planes.disk(arm, name).write_bytes(payload)
            r = _get(arm, name)
            assert r.status_code == 200, f"{arm}: {r.status_code} {r.text}"
            assert r.content == payload, arm

    def test_a_write_through_each_arm_lands_in_that_arms_subtree(self, planes):
        """Three arms, one export root: the URI prefix is what separates them.
        A flag that redirected a write elsewhere would show up here as a file in
        the wrong directory rather than as a bad status code."""
        for arm in PP_ARMS:
            name = "landing.bin"
            assert _put(arm, name, arm.encode()).status_code in (201, 204)
            assert planes.disk(arm, name).read_bytes() == arm.encode()
        for arm in PP_ARMS:
            assert planes.disk(arm, "landing.bin").read_bytes() == arm.encode()


# --------------------------------------------------------------------------- #
# D. The parse tier                                                            #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, **slots):
    """`nginx -t` on the 16j scaffold with the named slots filled.

    The scaffold (`configs/nginx_audit16jparse.conf`) is reused rather than
    copied, for the reason file 29 gives and this file needs more sharply: it
    writes no directive of either family, so the duplicate cases below can be
    sure the duplicate they are shown is the one they wrote.  A scaffold that
    already carried a `brix_webdav_open_file_cache` line would answer every
    such negative with "is duplicate" before the negative reached its subject.
    """
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "PORT2": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "BACKEND": f"posix:{data}",
              "KNOBS": "", "STREAM_KNOBS": "", "HTTP_KNOBS": "",
              "LOC_KNOBS": "", "OUTER": "", "EXTRA": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16jparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _diagnostics(out):
    """Only the lines nginx itself flagged: a tmp_path name can contain the
    token under test, so a substring search over the whole output would match
    the temp directory rather than a diagnostic."""
    return [ln for ln in out.splitlines()
            if any(tag in ln for tag in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


FLAGS = ("brix_webdav_open_file_cache_errors",
         "brix_webdav_open_file_cache_events",
         "brix_backend_passthrough_persist")


class TestTheFlagArmsParse:
    """Both arms of all three flags, in both legal HTTP scopes, and refused in
    every scope that is not one.

    The well-formed passthrough cells overlap tranche-16 file 6 deliberately —
    a third flag costs nothing once the scaffold is rendered, and having all
    three answer the same question in the same place is what makes the "no
    configuration of any of them is distinguishable" claim readable.  The
    negatives are the part file 6 has no cells for.
    """

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_a_location(self, tmp_path, flag, arm):
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_a_server(self, tmp_path, flag, arm):
        """All three are declared MAIN|SRV|LOC, so a server block is legal and
        the location below inherits.  That inheritance is real — it is the
        merge at config_merge.c:153-156 and shared_conf.h:428 — which is what
        makes an inert flag more than a typo: it is inherited, documented
        behaviour that does not exist."""
        rc, out = _parse(tmp_path, HTTP_KNOBS=f"        {flag} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("token", ("ON", "Off", "oFF"))
    def test_the_arms_are_case_insensitive(self, tmp_path, flag, token):
        """`ngx_conf_set_flag_slot` compares with ngx_strcasecmp, which is what
        makes the audit's grep for `<flag> off` sound only because no config in
        the corpus spells it any other way."""
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {token};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("value", ("yes", "1", "true", "disabled"))
    def test_a_value_outside_the_two_arms_is_refused(self, tmp_path, flag,
                                                     value):
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {value};\n")
        assert rc != 0, out
        assert any(f'invalid value "{value}" in "{flag}"' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("args", ("", "on off"))
    def test_the_wrong_arity_is_refused(self, tmp_path, flag, args):
        line = f"            {flag} {args};\n" if args else f"            {flag};\n"
        rc, out = _parse(tmp_path, LOC_KNOBS=line)
        assert rc != 0, out
        assert any(f'invalid number of arguments in "{flag}"' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("slot,indent", (("KNOBS", "        "),
                                             ("STREAM_KNOBS", "    "),
                                             ("OUTER", "")))
    def test_every_scope_outside_http_is_refused(self, tmp_path, flag, slot,
                                                 indent):
        """The stream server, the stream main context and the main context.

        The message is "not allowed here" rather than "unknown directive" in all
        three, which is worth measuring: the name is known process-wide because
        an HTTP module declared it, so an operator who writes one of these into
        a stream server is told the scope is wrong and not that the directive
        does not exist — the friendlier of the two errors, and the one that
        makes the inertness harder to notice.
        """
        rc, out = _parse(tmp_path, **{slot: f"{indent}{flag} on;\n"})
        assert rc != 0, out
        assert any(f'"{flag}" directive is not allowed here' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)


class TestTheCacheDirectiveParses:
    """`brix_webdav_open_file_cache` is the one member of the family with a
    custom setter, so it is the one with something to get wrong."""

    def test_a_well_formed_cache_is_accepted(self, tmp_path):
        rc, out = _parse(tmp_path, LOC_KNOBS=(
            "            brix_webdav_open_file_cache max=1024 inactive=1h;\n"))
        assert rc == 0, out

    def test_no_parameters_at_all_is_refused_for_the_missing_max(self, tmp_path):
        """Declared NGX_CONF_ANY, so the parser accepts zero arguments and the
        setter is the only thing that can refuse them."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS="            brix_webdav_open_file_cache;\n")
        assert rc != 0, out
        assert any('"brix_webdav_open_file_cache" must have the "max" parameter'
                   in ln for ln in _diagnostics(out)), _diagnostics(out)

    def test_inactive_without_max_is_refused_for_the_missing_max(self, tmp_path):
        """`inactive` alone is a plausible thing to write and says nothing about
        `max`; the refusal must still name `max`."""
        rc, out = _parse(tmp_path, LOC_KNOBS=(
            "            brix_webdav_open_file_cache inactive=30s;\n"))
        assert rc != 0, out
        assert any('must have the "max" parameter' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("token", ("max=0", "max=-1", "max=abc", "bogus",
                                       "inactive=zz", "MAX=8", "off=1"))
    def test_a_bad_parameter_is_refused_and_named(self, tmp_path, token):
        """`webdav_open_file_cache_arg` returns NGX_ERROR for an unknown token
        and for an out-of-range `max`, and the caller quotes the offending token
        back.  `MAX=8` is in the list because the token match is ngx_strncmp and
        therefore case-SENSITIVE, unlike the flag arms two classes up — the two
        halves of one family disagree about case."""
        rc, out = _parse(tmp_path, LOC_KNOBS=(
            f"            brix_webdav_open_file_cache {token};\n"))
        assert rc != 0, out
        assert any(f'invalid "brix_webdav_open_file_cache" parameter "{token}"'
                   in ln for ln in _diagnostics(out)), _diagnostics(out)

    @pytest.mark.parametrize("line", ("off", "off max=8", "max=8 off"))
    def test_off_disables_the_cache_in_any_position(self, tmp_path, line):
        """`off` is checked AFTER the whole argument loop, so it wins wherever
        it appears — the opposite of the order dependence file 29 found in
        `brix_manager_mode` against the CMS auto-derivation, and worth stating
        next to it: the same codebase does both."""
        rc, out = _parse(tmp_path, LOC_KNOBS=(
            f"            brix_webdav_open_file_cache {line};\n"))
        assert rc == 0, out

    def test_a_second_cache_directive_in_one_location_is_refused(self, tmp_path):
        """The sentinel guard at module_directives.c:272 — the conf slot starts
        NGX_CONF_UNSET_PTR, so a second call sees a value and returns
        "is duplicate" rather than leaking the first allocation."""
        rc, out = _parse(tmp_path, LOC_KNOBS=(
            "            brix_webdav_open_file_cache max=8;\n"
            "            brix_webdav_open_file_cache max=9;\n"))
        assert rc != 0, out
        assert any('"brix_webdav_open_file_cache" directive is duplicate' in ln
                   for ln in _diagnostics(out)), _diagnostics(out)

    def test_a_server_cache_and_a_location_cache_are_not_a_duplicate(self,
                                                                     tmp_path):
        """Different conf structs, so the sentinel guard is per-scope and the
        location simply overrides.  A test that only wrote the duplicate case
        could not tell the guard from a global."""
        rc, out = _parse(tmp_path,
                         HTTP_KNOBS="        brix_webdav_open_file_cache max=8;\n",
                         LOC_KNOBS="            brix_webdav_open_file_cache max=9;\n")
        assert rc == 0, out

    @pytest.mark.parametrize("line,message", (
        ("brix_webdav_open_file_cache_valid zz;",
         '"brix_webdav_open_file_cache_valid" directive invalid value'),
        ("brix_webdav_open_file_cache_min_uses xx;",
         '"brix_webdav_open_file_cache_min_uses" directive invalid number'),
    ))
    def test_the_numeric_members_refuse_a_non_number(self, tmp_path, line,
                                                     message):
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {line}\n")
        assert rc != 0, out
        assert any(message in ln for ln in _diagnostics(out)), _diagnostics(out)

    def test_the_four_knobs_are_accepted_with_no_cache_to_tune(self, tmp_path):
        """The family validates nothing about itself.  `_valid`, `_min_uses`,
        `_errors` and `_events` all load in a location that never asked for a
        cache — there is no cross-check saying they are meaningless without one,
        which is the config-time shape of the same defect the runtime shows: the
        fields are set and nobody is watching."""
        rc, out = _parse(tmp_path, LOC_KNOBS=(
            "            brix_webdav_open_file_cache_valid    1h;\n"
            "            brix_webdav_open_file_cache_min_uses 3;\n"
            "            brix_webdav_open_file_cache_errors   on;\n"
            "            brix_webdav_open_file_cache_events   on;\n"))
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)

    def test_a_cache_off_beside_the_four_knobs_is_still_accepted(self, tmp_path):
        """And the explicit contradiction — a cache turned off with all four of
        its knobs tuned — draws nothing either."""
        rc, out = _parse(tmp_path, LOC_KNOBS=(
            "            brix_webdav_open_file_cache          off;\n"
            "            brix_webdav_open_file_cache_valid    1h;\n"
            "            brix_webdav_open_file_cache_min_uses 3;\n"
            "            brix_webdav_open_file_cache_errors   on;\n"
            "            brix_webdav_open_file_cache_events   on;\n"))
        assert rc == 0, out
        assert _diagnostics(out) == [], _diagnostics(out)


# --------------------------------------------------------------------------- #
# E. Security negatives — what an inert cache is not allowed to soften         #
# --------------------------------------------------------------------------- #

class TestTheGatesAreReachedOnEveryRequest:
    """The cells written against the day the family is wired.

    A live open-file cache is the classic way for a server to keep answering
    about a resource whose access has already been withdrawn: the fd and the
    stat are held for `valid` seconds regardless of what happened to the file
    or its permissions afterwards.  With `valid 1h` configured on four
    locations here, every one of these cells would fail if the cache existed
    and were consulted — which is exactly why they belong in this file and not
    in a general WebDAV suite.  They are the ones that must not start failing.
    """

    @pytest.mark.parametrize("method,expected", (("PUT", 403),
                                                 ("DELETE", 403),
                                                 ("MKCOL", 403)))
    def test_the_write_gate_refuses_on_the_cached_read_only_plane(
            self, planes, method, expected):
        """CACHE_RO carries the full cache configuration beside
        `brix_allow_write off`.  The gate is `allow_write` (invariant 3: it is
        checked before token scope), and no amount of caching configured on the
        same location moves it."""
        name = "ro-write-target.bin"
        planes.disk(RO, name).write_bytes(b"read only\n")
        r = requests.request(method, _url(RO, name), data=b"x", timeout=TIMEOUT)
        assert r.status_code == expected, f"{method}: {r.status_code} {r.text}"
        assert planes.disk(RO, name).read_bytes() == b"read only\n"

    def test_the_read_only_plane_still_reads(self, planes):
        """The refusals above have to be the write gate and not the location
        being broken."""
        name = "ro-readable.bin"
        planes.disk(RO, name).write_bytes(b"readable\n")
        r = _get(RO, name)
        assert r.status_code == 200, r.text
        assert r.content == b"readable\n"
        assert _propfind(RO, name).status_code == 207

    def test_options_reports_the_write_gate_and_not_the_cache(self, planes):
        """OPTIONS is the one response whose shape the arms could legitimately
        differ on, so it is the sharpest equality claim available: all four
        cache planes advertise the same methods, and the read-only plane
        advertises strictly fewer."""
        allows = {}
        for arm in CACHE_ARMS + (RO,):
            r = _options(arm, "")
            assert r.status_code in (200, 204), f"{arm}: {r.status_code}"
            allows[arm] = {m.strip() for m in
                           r.headers.get("Allow", "").split(",") if m.strip()}
        writable = allows["cache-none"]
        for arm in CACHE_ARMS:
            assert allows[arm] == writable, f"{arm} advertises a different Allow"
        def _assert_test_options_reports_the_write_gate_and_not_the_cache_1():
            assert allows[RO] < writable, allows[RO]
            assert "PUT" not in allows[RO] and "GET" in allows[RO]

        _assert_test_options_reports_the_write_gate_and_not_the_cache_1()

    @pytest.mark.parametrize("arm", CACHE_ARMS + (RO,))
    def test_a_revoked_permission_is_seen_on_the_very_next_request(
            self, planes, request, arm):
        """Read the file, then take the read away.

        A live cache with `min_uses 1` has an entry after the first request and
        `valid 1h` says it may reuse it without re-stat'ing for an hour.  The
        second request is refused, so it did not.
        """
        if os.geteuid() == 0:
            pytest.skip("root bypasses the mode bits this cell revokes")
        name = _uid(request) + ".bin"
        path = _seed(planes, arm, name, b"about to be revoked\n")
        try:
            path.chmod(0)
            r = _get(arm, name)
            assert r.status_code == 403, f"{r.status_code}: {r.text}"
        finally:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    @pytest.mark.parametrize("arm", CACHE_ARMS + (RO,))
    def test_a_file_removed_behind_the_server_is_not_served_again(
            self, planes, request, arm):
        """The same statement about existence rather than permission, and the
        one that includes the read-only plane — where the removal cannot come
        through the server at all, so it is unambiguously behind its back."""
        name = _uid(request) + ".bin"
        path = _seed(planes, arm, name, b"about to be removed\n")
        path.unlink()
        r = _get(arm, name)
        assert r.status_code == 404, f"{r.status_code}: {r.text}"

    @pytest.mark.parametrize("arm", CACHE_ARMS + (RO,))
    @pytest.mark.parametrize("escape", (
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//etc/passwd",
    ))
    def test_an_escape_above_the_export_is_refused_on_every_arm(
            self, planes, arm, escape):
        """Invariant 4 (`resolve_path()` before every open) is upstream of
        anything the cache family could touch, and the refusal must not depend
        on which arm is configured."""
        status, body = _raw_get(f"/{arm}/{escape}")
        assert status in (400, 403, 404), f"{status}: {body[:200]!r}"
        assert b"root:x:" not in body

    def test_a_normalised_path_is_judged_by_the_location_it_lands_in(self,
                                                                     planes):
        """`/cache-on/../cache-ro/x` normalises to `/cache-ro/x` BEFORE location
        matching, so it is the read-only location's rules that apply — not the
        writable one the client typed.  A cache keyed on the pre-normalisation
        URI would be a way to launder that; there is no cache, and the write is
        refused."""
        name = "normalised-target.bin"
        planes.disk(RO, name).write_bytes(b"still read only\n")
        url = f"http://{HOST}:{PORT}/cache-on/../{RO}/{name}"
        assert requests.get(url, timeout=TIMEOUT).status_code == 200
        r = requests.put(url, data=b"overwritten", timeout=TIMEOUT)
        assert r.status_code == 403, f"{r.status_code}: {r.text}"
        assert planes.disk(RO, name).read_bytes() == b"still read only\n"


# --------------------------------------------------------------------------- #
# F. The instance said nothing about any of it                                 #
# --------------------------------------------------------------------------- #

class TestNothingIsLoggedAboutTheInertDirectives:
    """The last thing that could rescue an inert directive is a diagnostic.

    An operator who configured a cache and got a NOTICE saying the export does
    not use one would find out at startup.  Eight locations, five of them
    carrying the family and three carrying the passthrough flag, produce no
    mention of either — which is what makes DEFECT CANDIDATE #110, and #35
    beside it, a silent failure rather than a documented no-op.
    """

    def test_the_startup_log_never_names_the_cache_family(self, planes):
        log = planes.errlog()
        assert log, "the instance produced no error log at all"
        offenders = [ln for ln in log.splitlines()
                     if "open_file_cache" in ln]
        assert offenders == [], offenders

    def test_the_startup_log_never_names_the_passthrough_flag(self, planes):
        offenders = [ln for ln in planes.errlog().splitlines()
                     if "passthrough_persist" in ln]
        assert offenders == [], offenders

    def test_the_instance_started_clean(self, planes):
        """No [emerg]/[alert]/[error] from the config load: the eight locations
        above are a configuration a real deployment could hold, and the claim
        that the directives are accepted means accepted without complaint.

        Request-scoped lines are excluded by their `client:` field rather than
        by a whitelist of texts — §E deliberately asks for paths that do not
        resolve, and an [error] per refused traversal is the server working.
        """
        bad = [ln for ln in planes.errlog().splitlines()
               if any(tag in ln for tag in ("[emerg]", "[alert]", "[error]"))
               and "client:" not in ln]
        assert bad == [], bad
