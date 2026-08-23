# tests/test_rpm_mirror_native.py — the RPM/dnf pull-through mirror as a C
# server surface (phase-104 D15.9). Ports: mock origin 14170, brix nginx
# fronts 14171 (canonical) and 14172 (1 s metadata TTL, so the freshness leg
# does not sleep out the canonical 60).
#
# D11 shipped this mirror as an nginx recipe: proxy_pass + proxy_cache, with
# the repository's own layout expressed in regex locations. This lane is the
# same mirror as a HANDLER — one directive, the shared cache tier underneath,
# and the two things a recipe could never do:
#   * verify every digest-named metadata file against the checksum createrepo
#     put in its own name, at the edge, before it is ever served, and
#   * refuse and REPORT a write, so a scanner probing for a repository to
#     plant a package in shows up in the guard audit log.
#
# Three legs, per the standing rule:
#   success  — cold fill then warm hit (one upstream GET per object), ranged
#              and conditional serving, immutable-vs-mutable TTL split, and
#              dnf itself installing through the C mirror;
#   error    — a broken or absent origin fails promptly and does not poison
#              the cache, while already-cached objects keep serving;
#   security — tampered metadata is quarantined and never served, a write
#              method is refused and audited, a traversal never reaches the
#              origin, and a mirror configured with the wrong verification
#              mode does not start at all.
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "rpm"))

from mirror_lane import (                                      # noqa: E402
    PREFIX, Mirror, build_repo, cache_files, error_log, fault, get, hits,
    missing_tools, package_uris, repodata_names, reset,
    spawn_mock, start_mirror, stop_mocks,
)

sys.path.insert(0, os.path.join(HERE, "cvmfs"))

from config_templates import render_config_to_path              # noqa: E402
from conformance_common import NGINX_BIN                        # noqa: E402
from settings import HOST                                       # noqa: E402

MOCK_PORT = 14170
NGINX_PORT = 14171
NGINX_PORT_FAST = 14172
NGINX_PORT_PREFETCH = 14176

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-rpm-mirror-native"),
    pytest.mark.timeout(600),
]


@pytest.fixture(scope="module")
def origin(tmp_path_factory):
    """A real repository (brixrpm createrepo over the D12 fixtures), served by
    the control-plane mock so the lane can see what left the box."""
    blocked = missing_tools()
    if blocked:
        pytest.skip(blocked)
    docroot = tmp_path_factory.mktemp("rpm-origin")
    repo = build_repo(docroot)
    proc, base = spawn_mock(MOCK_PORT, docroot)
    try:
        yield base, repo
    finally:
        stop_mocks(proc)


@pytest.fixture
def mirror(lifecycle, origin, tmp_path):
    base, _repo = origin
    reset(base)
    return start_mirror(lifecycle, "lc-rpm-native", NGINX_PORT, MOCK_PORT,
                        tmp_path / "cache")


def _one_metadata(repo):
    """One digest-named metadata URI — the self-addressing route."""
    named, _repomd = repodata_names(repo)
    assert named, "createrepo wrote no digest-named metadata"
    return named[0]


# ---------------------------------------------------------------- success ---

def test_cold_fill_then_warm_hit_costs_one_upstream_get(mirror: Mirror, origin):
    """The whole point of a mirror: N clients, one upstream GET per object.

    The second request must be answered from the local store — and the origin's
    own journal is the only place that distinction is visible, since a hit and
    a refill look identical to the client.
    """
    base, repo = origin
    uri = _one_metadata(repo)

    cold_status, _, cold_body = get(mirror.base + uri)
    assert cold_status == 200
    assert cold_body == (repo / uri[len(PREFIX):]).read_bytes()
    assert len(hits(base, method="GET", path_suffix=uri.rsplit("/", 1)[-1])) == 1

    for _ in range(3):
        warm_status, _, warm_body = get(mirror.base + uri)
        assert warm_status == 200
        assert warm_body == cold_body
    assert len(hits(base, method="GET", path_suffix=uri.rsplit("/", 1)[-1])) == 1
    assert uri.lstrip("/") in cache_files(mirror.cache)


def test_package_serves_ranged_and_conditional(mirror: Mirror, origin):
    """Packages are the bulk bytes: dnf resumes them, and a proxy that cannot
    answer a Range turns every interrupted download into a whole refetch."""
    _base, repo = origin
    uri = package_uris(repo)[0]

    status, headers, body = get(mirror.base + uri)
    assert status == 200
    assert body == (repo / uri[len(PREFIX):]).read_bytes()
    assert headers.get("Accept-Ranges") == "bytes"
    etag = headers.get("ETag")
    assert etag, "no validator: every client refetches the whole package"

    part_status, part_headers, part = get(mirror.base + uri,
                                          {"Range": "bytes=0-31"})
    assert part_status == 206
    assert part == body[:32]
    assert part_headers["Content-Range"] == "bytes 0-31/%d" % len(body)

    again, _, _ = get(mirror.base + uri, {"If-None-Match": etag})
    assert again == 304


def test_repomd_refetched_after_ttl_but_metadata_never_is(
        lifecycle, origin, tmp_path):
    """The one distinction the file NAMES encode: repomd.xml is the mutable
    freshness root and everything beside it is immutable because its name IS
    its checksum. A mirror that re-validated the digest-named files would pay
    an upstream round trip per `dnf makecache` for bytes that cannot change;
    one that cached repomd.xml forever would pin the site to a stale index."""
    base, repo = origin
    reset(base)
    fast = start_mirror(lifecycle, "lc-rpm-native-fast", NGINX_PORT_FAST,
                        MOCK_PORT, tmp_path / "cache-fast", metadata_ttl="1s")
    _named, repomd = repodata_names(repo)
    metadata = _one_metadata(repo)

    for uri in (repomd, metadata):
        assert get(fast.base + uri)[0] == 200
    time.sleep(2.0)
    for uri in (repomd, metadata):
        assert get(fast.base + uri)[0] == 200

    assert len(hits(base, method="GET", path_suffix="repomd.xml")) == 2
    assert len(hits(base, method="GET",
                    path_suffix=metadata.rsplit("/", 1)[-1])) == 1


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("dnf") is None or shutil.which("unshare")
                    is None, reason="dnf/unshare not installed")
def test_dnf_installs_through_the_native_mirror(mirror: Mirror, origin,
                                                tmp_path):
    """The oracle. Everything above asserts our own beliefs about the layout;
    this asserts a real package manager's, depsolving and installing three
    packages through the handler."""
    _base, _repo = origin
    root = tmp_path / "installroot"
    cache = tmp_path / "dnfcache"
    done = subprocess.run(
        ["unshare", "-r", "--", "dnf", "--disablerepo=*",
         "--installroot=%s" % root, "--releasever=9",
         "--setopt=cachedir=%s" % cache,
         "--repofrompath=brixmirror,%s" % (mirror.base + PREFIX),
         "--enablerepo=brixmirror", "--setopt=gpgcheck=0",
         "-y", "install", "brixtest-app"],
        capture_output=True, text=True, timeout=300)

    assert done.returncode == 0, (done.stdout + done.stderr)[-2000:]
    for want in ("brixtest-app-0.9-4", "brixtest-lib-2:2.0-1",
                 "brixtest-tools-1.2-3"):
        assert want in done.stdout, done.stdout


# ------------------------------------------------------------------ error ---

# A 503 and a 404 are different KINDS of failure, and the fill plane answers
# them differently on purpose: a 404 is the origin's definitive statement that
# the object is not there (404 straight through), while a 503 is transient, so
# the never-drop fill retries it to its deadline and then hands the client the
# keep-alive 504 + Retry-After that says "ask again" rather than a 502 that
# says "this is broken". Both must leave the store empty.
@pytest.mark.parametrize("kind,expect", [("error", 504), ("notfound", 404)])
def test_broken_origin_fails_promptly_and_caches_nothing(
        mirror: Mirror, origin, kind, expect):
    """An origin that is 503ing or has lost a file must not become a cached
    404/50x: the next request has to try again, because the failure is the
    origin's transient state and not a property of the object."""
    base, repo = origin
    uri = _one_metadata(repo)
    fault(base, kind, path_re=uri.rsplit("/", 1)[-1])

    started = time.time()
    status, _, _ = get(mirror.base + uri)
    assert status == expect
    assert time.time() - started < 30, "a broken origin hung the request"
    assert uri.lstrip("/") not in cache_files(mirror.cache)

    fault(base, "none")
    assert get(mirror.base + uri)[0] == 200


def test_cached_objects_survive_the_origin_going_away(mirror: Mirror, origin):
    """The reason a site runs a mirror at all: when the upstream is down, the
    packages already pulled keep installing."""
    base, repo = origin
    uri = _one_metadata(repo)
    assert get(mirror.base + uri)[0] == 200

    fault(base, "error")
    status, _, body = get(mirror.base + uri)
    assert status == 200
    assert body == (repo / uri[len(PREFIX):]).read_bytes()
    # …and an object never pulled is honestly unavailable, not a silent empty:
    # 504 + Retry-After, the never-drop plane's "the origin is down, ask again".
    unavailable, headers, _ = get(mirror.base + package_uris(repo)[0])
    assert unavailable == 504
    assert headers.get("Retry-After")


# --------------------------------------------------------------- security ---

def test_tampered_metadata_is_refused_never_cached_and_audited(
        mirror: Mirror, origin):
    """Repository metadata is the index every `dnf install` on the site
    trusts. createrepo names each file after its checksum, so bytes that do
    not hash to their own name are the wrong bytes — an upstream compromise,
    a poisoned CDN edge, or a MITM — and must never reach a client or the
    store. The guard line is what makes it an alert rather than a log entry."""
    base, repo = origin
    uri = _one_metadata(repo)
    fault(base, "tamper", path_re=uri.rsplit("/", 1)[-1])

    status, _, _ = get(mirror.base + uri)
    assert status == 502
    assert uri.lstrip("/") not in cache_files(mirror.cache)

    audit = error_log(mirror.endpoint)
    assert "signal=rpm_tamper" in audit
    assert 'path="%s"' % uri in audit

    # The refusal is about the bytes, not the object: a healthy origin serves.
    fault(base, "none")
    assert get(mirror.base + uri)[0] == 200


@pytest.mark.parametrize("method", ["PUT", "POST", "PATCH", "DELETE"])
def test_write_methods_are_refused_and_audited(mirror: Mirror, origin, method):
    """A pull-through mirror is read-only by construction and dnf never
    writes. A write is a scanner looking for a repository to plant a package
    in — a supply-chain compromise with a very short path to root everywhere
    — so it is refused, told what IS allowed, and reported."""
    base, _repo = origin
    target = PREFIX + "Packages/evil.rpm"

    status, headers, _ = get(mirror.base + target, method=method)
    assert status == 405
    assert set(headers.get("Allow", "").replace(" ", "").split(",")) == \
        {"GET", "HEAD"}
    assert hits(base, path_suffix="evil.rpm") == [], "a write reached upstream"

    audit = error_log(mirror.endpoint)
    assert "signal=rpmwrite" in audit
    assert 'path="%s"' % target in audit


@pytest.mark.parametrize("path", [
    PREFIX + "../../etc/passwd",
    PREFIX + "Packages/../../../etc/shadow",
    PREFIX + "repodata/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
])
def test_traversal_never_reaches_the_origin(mirror: Mirror, origin, path):
    """The cache key is the request URI verbatim, which makes the key space
    the URI space: a path that escapes the repository must be refused by the
    grammar, before anything is asked of the origin or written to the store."""
    base, _repo = origin
    status, _, _ = get(mirror.base + path)

    assert status in (400, 404)
    assert [r for r in hits(base) if "passwd" in r["path"]
            or "shadow" in r["path"]] == []
    assert not [f for f in cache_files(mirror.cache) if "etc" in f]


@pytest.mark.parametrize("verify", ["cvmfs-cas", "oci-digest", "off"])
def test_wrong_verification_mode_refuses_to_start(tmp_path, verify):
    """The verification is not an option on this surface — it is the surface.
    A mirror that fills metadata without checking it against the name the
    repository index gave it is a cache of whatever the network said, so the
    only safe answer to a misconfiguration is a server that does not come up.
    """
    conf = render_config_to_path(
        "rpm_mirror.conf", tmp_path / "rpm.conf", strict=True,
        LOG_DIR=str(tmp_path), BIND_HOST=HOST, PORT=NGINX_PORT_FAST + 1,
        MOCK_HOST=HOST, MOCK_PORT=MOCK_PORT, PREFIX=PREFIX,
        CACHE_DIR=str(tmp_path / "cache"), METADATA_TTL="60s",
        VERIFY_MODE=verify, EXTRA_LINES="")
    proc = subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path),
                           "-c", str(conf), "-e", str(tmp_path / "start.log")],
                          capture_output=True, text=True, timeout=60)

    assert proc.returncode != 0, "a mirror without rpm-repodata verify started"
    assert "rpm-repodata" in proc.stderr, proc.stderr


def test_cleartext_upstream_refuses_to_start_without_the_opt_in(tmp_path):
    """A cleartext origin lets anyone on the path substitute a package before
    this mirror ever hashes it (packages carry no digest in their name — only
    metadata does). It is allowed only where someone wrote down that they meant
    it, which is what the test fixture template itself does."""
    text = (Path(HERE) / "configs" / "rpm_mirror.conf").read_text()
    conf = tmp_path / "rpm-cleartext.conf"
    conf.write_text(text
                    .replace("brix_rpm_mirror_insecure on;", "")
                    .replace("{LOG_DIR}", str(tmp_path))
                    .replace("{BIND_HOST}", HOST)
                    .replace("{PORT}", str(NGINX_PORT_FAST + 2))
                    .replace("{MOCK_HOST}", HOST)
                    .replace("{MOCK_PORT}", str(MOCK_PORT))
                    .replace("{PREFIX}", PREFIX)
                    .replace("{CACHE_DIR}", str(tmp_path / "cache"))
                    .replace("{METADATA_TTL}", "60s")
                    .replace("{VERIFY_MODE}", "rpm-repodata")
                    .replace("{EXTRA_LINES}", ""))
    proc = subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path),
                           "-c", str(conf), "-e", str(tmp_path / "start.log")],
                          capture_output=True, text=True, timeout=60)

    assert proc.returncode != 0
    assert "brix_rpm_mirror_insecure" in proc.stderr, proc.stderr


def test_shipped_brix_recipe_parses(tmp_path):
    """deploy/rpm-mirror/brix.conf.example is documentation an operator PASTES,
    so it is held to the same standard as a template this suite renders: every
    directive spelled correctly, legal in the context it is written in, and the
    whole file accepted by the binary it is written for. A parse is not a
    deployment — but a recipe that does not parse has never been run."""
    (tmp_path / "store").mkdir()
    text = (Path(HERE).parent / "deploy" / "rpm-mirror"
            / "brix.conf.example").read_text()
    text = (text
            .replace("@PORT@", str(NGINX_PORT_FAST + 3))
            .replace("@CACHEDIR@", str(tmp_path))
            .replace("@ORIGIN@", "https://mirror.example.org/el9"))
    assert "@" not in "".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    ), "the shipped recipe still has an unsubstituted placeholder"

    conf = tmp_path / "brix.conf"
    conf.write_text(text)
    proc = subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path),
                           "-c", str(conf), "-e", str(tmp_path / "start.log")],
                          capture_output=True, text=True, timeout=60)

    assert proc.returncode == 0, proc.stderr


# ------------------------------------------- warm repodata prefetch (D15.10) ---

# Appendix X finding X-3: a stock EL9 dnf fetches repomd.xml and then primary
# AND filelists, unconditionally, every time its metadata window expires. Those
# two fetches are a cold client's entire wait and they are named by the index
# the mirror is already holding — so `brix_rpm_prefetch on` warms them the
# moment a new repomd.xml lands. The rows below are the three claims that make
# that safe: it does nothing unless asked, it fetches exactly the two files the
# index names, and it fetches NOTHING the request grammar would have refused
# from a client.


def _warm_names(repo):
    """The digest-named primary and filelists files, as bare basenames."""
    named, _repomd = repodata_names(repo)
    out = [n.rsplit("/", 1)[-1] for n in named
           if "-primary" in n or "-filelists" in n]
    assert len(out) == 2, named
    return out


def _wait_for_hit(base, suffix, method="GET", timeout=15.0):
    """The origin's journal is the only place the warm fetch is visible: the
    client's response has already been written by the time it happens. A
    failing fetch may never reach its GET — the fill stats the object first —
    so a leg that asserts an ATTEMPT passes method=None."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = hits(base, method=method, path_suffix=suffix)
        if rows:
            return rows
        time.sleep(0.05)
    return hits(base, method=method, path_suffix=suffix)


def _wait_for_cached(mirror: Mirror, rel, timeout=15.0):
    """The store is written by the warm fill's own thread, so a file that is
    on its way is a `.xrd-tmp` part and not the object yet."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if rel in cache_files(mirror.cache):
            return True
        time.sleep(0.05)
    return rel in cache_files(mirror.cache)


def test_prefetch_is_off_until_it_is_asked_for(mirror: Mirror, origin):
    """Speculation spends someone else's bandwidth, so the default is that a
    mirror fetches exactly what was asked of it and nothing else."""
    base, repo = origin
    _named, repomd = repodata_names(repo)

    assert get(mirror.base + repomd)[0] == 200
    time.sleep(1.0)

    assert [r for r in hits(base, method="GET")
            if r["path"].endswith("repomd.xml")], "the index itself was fetched"
    for name in _warm_names(repo):
        assert hits(base, method="GET", path_suffix=name) == [], \
            "%s was fetched without a client asking" % name


def test_prefetch_warms_primary_and_filelists_before_the_client_asks(
        lifecycle, origin, tmp_path):
    """The success leg: one client GET of repomd.xml, and the two files dnf
    asks for next are already local — so the client's next two requests cost
    no upstream round trip at all."""
    base, repo = origin
    reset(base)
    warm = start_mirror(lifecycle, "lc-rpm-native-warm", NGINX_PORT_PREFETCH,
                        MOCK_PORT, tmp_path / "cache-warm",
                        extra_lines="brix_rpm_prefetch on;")
    _named, repomd = repodata_names(repo)
    names = _warm_names(repo)

    assert get(warm.base + repomd)[0] == 200
    for name in names:
        assert len(_wait_for_hit(base, name)) == 1, \
            "%s was not warmed by the index that named it" % name

    for name in names:
        rel = PREFIX.lstrip("/") + "repodata/" + name
        assert _wait_for_cached(warm, rel), "%s never landed in the store" % name

    # The client's own request now costs nothing upstream — which is the whole
    # point, and the only way to tell a warmed object from a lucky one.
    for name in names:
        uri = PREFIX + "repodata/" + name
        def _assert_test_prefetch_warms_primary_and_filelists_before_the_client_asks_4():
            assert get(warm.base + uri)[0] == 200
            assert len(hits(base, method="GET", path_suffix=name)) == 1

        _assert_test_prefetch_warms_primary_and_filelists_before_the_client_asks_4()


def test_prefetch_failure_is_invisible_to_the_client(lifecycle, origin,
                                                     tmp_path):
    """The error leg. A warm fill that fails must cost the client nothing: the
    index it asked for is served, no half-object is admitted to the store, and
    the file is fetched normally the moment a client actually wants it."""
    base, repo = origin
    reset(base)
    warm = start_mirror(lifecycle, "lc-rpm-native-warmfail",
                        NGINX_PORT_PREFETCH, MOCK_PORT,
                        tmp_path / "cache-warmfail",
                        extra_lines="brix_rpm_prefetch on;")
    _named, repomd = repodata_names(repo)
    primary = [n for n in _warm_names(repo) if "-primary" in n][0]
    fault(base, "notfound", path_re=primary)

    def _assert_test_prefetch_failure_is_invisible_to_the_client_2():
        assert get(warm.base + repomd)[0] == 200
        assert _wait_for_hit(base, primary, method=None), "the warm fill never ran"

    _assert_test_prefetch_failure_is_invisible_to_the_client_2()
    assert PREFIX.lstrip("/") + "repodata/" + primary not in \
        cache_files(warm.cache)

    fault(base, "none")
    uri = PREFIX + "repodata/" + primary
    def _assert_test_prefetch_failure_is_invisible_to_the_client_3():
        assert get(warm.base + uri)[0] == 200
        assert PREFIX.lstrip("/") + "repodata/" + primary in cache_files(warm.cache)

    _assert_test_prefetch_failure_is_invisible_to_the_client_3()


def test_prefetch_fetches_nothing_the_grammar_would_refuse(lifecycle, origin,
                                                           tmp_path):
    """The security leg. A repomd.xml is UPSTREAM data: it is the mutable root,
    so it is not self-verifying, and a compromised origin can put anything in a
    <location href>. Every href is therefore re-checked by the same grammar the
    gate applies to a client request, and only a digest-named metadata file —
    which the fill then verifies against the checksum in its own name — is ever
    fetched. Everything else is dropped, unfetched and unlogged as a request."""
    base, repo = origin
    reset(base)
    docroot = repo.parent
    evil = docroot / PREFIX.strip("/") / "poisoned" / "repodata"
    evil.mkdir(parents=True, exist_ok=True)
    (evil / "repomd.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<repomd xmlns="http://linux.duke.edu/metadata/repo">\n'
        '  <data type="primary">\n'
        '    <location href="../../../etc/passwd"/>\n'
        '  </data>\n'
        '  <data type="filelists">\n'
        '    <location href="http://evil.example/filelists.xml.gz"/>\n'
        '  </data>\n'
        '  <data type="primary">\n'
        '    <location href="/etc/shadow"/>\n'
        '  </data>\n'
        '  <data type="filelists">\n'
        '    <location href="repodata/filelists.xml.gz"/>\n'
        '  </data>\n'
        '</repomd>\n')
    warm = start_mirror(lifecycle, "lc-rpm-native-warmevil",
                        NGINX_PORT_PREFETCH, MOCK_PORT,
                        tmp_path / "cache-warmevil",
                        extra_lines="brix_rpm_prefetch on;")

    assert get(warm.base + PREFIX + "poisoned/repodata/repomd.xml")[0] == 200
    time.sleep(1.0)

    for probe in ("passwd", "shadow", "evil.example", "filelists.xml.gz"):
        assert [r for r in hits(base) if probe in r["path"]] == [], \
            "the mirror followed a location it should have dropped: %s" % probe
    def _assert_test_prefetch_fetches_nothing_the_grammar_would_refuse_1():
        assert [f for f in cache_files(warm.cache)
                if "etc" in f or f.endswith("filelists.xml.gz")] == []
    
        # The one href that is a legal path but NOT a digest-named metadata file is
        # the interesting drop: it is refused for what it is, and said so.
        assert "not a digest-named metadata file" in error_log(warm.endpoint)

    _assert_test_prefetch_fetches_nothing_the_grammar_would_refuse_1()
