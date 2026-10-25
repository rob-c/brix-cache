"""Phase-108 C13/A.4 — the ``brix_n2n_*`` name-translation directives are
validated at ``nginx -t``, not at runtime.

The generic name→PFN stage (``brix_path_lfn_to_pfn`` / ``brix_path_pfn_to_lfn``)
carries a per-export ``brix_n2n_cfg_t`` that the config layer fills. Every
switch that could misroute an object — an unknown scheme, RAL with no pool, a
pool or prefix that would silently truncate into the fixed-width cfg field, or
RAL on the RADOS backend (whose pool is bound at the ioctx, so a ``<pool>:``
prefix would be the WRONG object name) — is a *config* error surfaced as an
``[emerg]`` diagnostic, so a mistranslation can never reach a live request.

Config-parse checks render a template, run ``nginx -t``, and assert on the
return code and the diagnostic. No server boots, so no port binds and no
storage driver initializes — a ``ceph:`` / ``http://`` backend PARSES on any
build (the driver only binds at worker start, which ``-t`` never reaches),
which is exactly what lets these validations be tested without a live cluster.
Runtime regressions additionally exercise translated pblock opens/metadata and
an offloaded HTTP-origin cache fill, without requiring an external service.
"""

import os
from pathlib import Path
import subprocess

import pytest
import requests
from config_templates import render_config_to_path

from _test_phase25_ratelimit_helpers import _parse_fail, _http_values
from cmdscripts.live_common import LiveRun
from ephemeral_port import free_ports
from settings import BIND_HOST, NGINX_BIN, XRDCP_BIN

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason="nginx binary not built")


def _loc(backend, *knobs):
    """A second ``location /t`` carrying a storage backend + n2n directives, for
    the ``EXTRA_LOCATIONS`` slot of ``nginx_rl_http.conf`` (whose default
    ``location /`` is an unrelated posix export)."""
    lines = ["        location /t {",
             "            brix_webdav on;",
             f"            brix_storage_backend {backend};"]
    lines += [f"            {k};" for k in knobs]
    lines += ["            brix_webdav_auth none;",
              "        }", ""]
    return "\n".join(lines)


def _t(tmp_path, backend, *knobs):
    return _parse_fail(tmp_path, "nginx_rl_http.conf",
                       _http_values("", "", _loc(backend, *knobs)))


# --------------------------------------------------------------------------
# Accept: a valid (or absent) translation parses cleanly.
# --------------------------------------------------------------------------

def test_no_n2n_directive_keeps_the_backend_derived_default(tmp_path):
    # A ceph export with no brix_n2n_* keeps the parser-derived CEPHFS_PATH
    # default; the stage is inert-by-omission, never a parse error.
    rc, out = _t(tmp_path, "ceph:xrdtest")
    assert rc == 0, out


def test_identity_scheme_parses(tmp_path):
    rc, out = _t(tmp_path, "ceph:xrdtest", "brix_n2n_scheme identity")
    assert rc == 0, out


def test_cephfs_path_with_prefix_override_parses(tmp_path):
    rc, out = _t(tmp_path, "ceph:xrdtest",
                 "brix_n2n_scheme cephfs_path", "brix_n2n_prefix /store/")
    assert rc == 0, out


def test_ral_on_a_non_ceph_backend_parses(tmp_path):
    # RAL is valid off the RADOS backend (the pool prefix is meaningful there);
    # http is the smallest non-ceph backend that registers an entry at parse.
    rc, out = _t(tmp_path, "http://o.example/",
                 "brix_n2n_scheme ral", "brix_n2n_pool poolA")
    assert rc == 0, out


# --------------------------------------------------------------------------
# Reject: every mistranslation is caught at parse, with its own diagnostic.
# --------------------------------------------------------------------------

def test_unknown_scheme_is_rejected(tmp_path):
    rc, out = _t(tmp_path, "ceph:xrdtest", "brix_n2n_scheme bogus")
    assert rc != 0, out
    assert "brix_n2n_scheme: unknown scheme" in out, out
    assert "bogus" in out, out


def test_ral_on_the_ceph_backend_is_rejected(tmp_path):
    # The footgun guard: RAL names "<pool>:<prefix><lfn>", but RADOS binds the
    # pool at the ioctx and keys objects by "<prefix><lfn>". RAL would be the
    # wrong object name, so it is refused rather than silently mismapped.
    rc, out = _t(tmp_path, "ceph:xrdtest",
                 "brix_n2n_scheme ral", "brix_n2n_pool p")
    assert rc != 0, out
    assert "brix_n2n_scheme ral is invalid" in out, out
    assert "ceph" in out, out


def test_ral_without_a_pool_is_rejected(tmp_path):
    rc, out = _t(tmp_path, "http://o.example/", "brix_n2n_scheme ral")
    assert rc != 0, out
    assert "brix_n2n_scheme ral requires brix_n2n_pool" in out, out


def test_a_pool_that_would_truncate_is_rejected_not_truncated(tmp_path):
    # 128 bytes into a 128-byte field (max 127 + NUL) is a config error, never a
    # runtime truncation that would silently address the wrong pool.
    rc, out = _t(tmp_path, "http://o.example/",
                 "brix_n2n_scheme ral", "brix_n2n_pool " + "p" * 128)
    assert rc != 0, out
    assert "brix_n2n_pool is too long" in out, out


def test_a_prefix_that_would_truncate_is_rejected_not_truncated(tmp_path):
    rc, out = _t(tmp_path, "ceph:xrdtest",
                 "brix_n2n_scheme cephfs_path", "brix_n2n_prefix /" + "a" * 255)
    assert rc != 0, out
    assert "brix_n2n_prefix is too long" in out, out


def _mapped_endpoints(root, ports, prefix):
    """Render both protocols against one translated driver namespace."""
    common = f"brix_export {root}; brix_storage_backend pblock; "
    if prefix:
        common += f"brix_n2n_scheme cephfs_path; brix_n2n_prefix {prefix};"
    stream = f"""server {{ listen {BIND_HOST}:{ports[0]};
        brix_root on; brix_auth none; brix_upload_resume off;
        brix_allow_write on; {common} }}
    server {{ listen {BIND_HOST}:{ports[2]};
        brix_root on; brix_auth none; brix_upload_resume off;
        brix_allow_write off; {common} }}"""
    http = f"""server {{ listen {BIND_HOST}:{ports[1]}; location / {{
        brix_webdav on; brix_webdav_auth none; brix_allow_write on;
        {common} }} }}"""
    return stream, http


def _mapped_configuration(run, root, ports, prefix):
    """Keep the identity seed and mapped server's configuration identical."""
    stream, http = _mapped_endpoints(root, ports, prefix)
    return render_config_to_path('nginx_n2n_mapped.conf', run.root / 'nginx.conf',
                                 strict=True, PREFIX=run.root,
                                 STREAM_ENDPOINTS=stream, HTTP_ENDPOINTS=http)


@pytest.fixture(scope="module")
def mapped_namespace():
    """Seed the physical parent before exposing it as the logical export root."""
    with LiveRun("n2n-cross-plane", Path(NGINX_BIN)) as run:
        ports = free_ports(3)
        root = run.mkdir("export")
        config = _mapped_configuration(run, root, ports, "")
        run.start_nginx(run.root, config, ports[0])
        response = requests.request("MKCOL", f"http://{BIND_HOST}:{ports[1]}/mapped",
                                    timeout=15)
        assert response.status_code == 201, response.text[:200]
        run.stop_nginx(run.root)
        config = _mapped_configuration(run, root, ports, "/mapped")
        run.start_nginx(run.root, config, ports[0])
        run.call([run.nginx, "-p", run.root, "-c", config, "-t"])
        yield run, ports


def _mapped_copy(run, source, destination, *, succeeds=True):
    """Use the selected native client, retaining a bounded failure diagnostic."""
    result = subprocess.run([XRDCP_BIN, "-f", str(source), str(destination)],
                            capture_output=True, text=True, timeout=20)
    assert (result.returncode == 0) == succeeds, result.stderr[-2000:]
    return result


@pytest.mark.timeout(90)
@pytest.mark.parametrize("size", [0, 1, 1500000])
def test_translated_root_write_is_visible_to_http(mapped_namespace, size):
    """Root writes must use exactly the physical key used by HTTP reads."""
    run, ports = mapped_namespace
    source = run.root / f"root-{size}.bin"
    payload = bytes(range(251)) * (size // 251) + bytes(range(size % 251))
    source.write_bytes(payload)
    name = source.name
    _mapped_copy(run, source, f"root://{BIND_HOST}:{ports[0]}//{name}")
    response = requests.get(f"http://{BIND_HOST}:{ports[1]}/{name}", timeout=15)
    assert response.status_code == 200, response.text[:200]
    assert response.content == payload, "translated root/HTTP bytes differ"


@pytest.mark.timeout(90)
def test_translated_http_write_is_visible_to_root(mapped_namespace):
    """The read existence probe and the actual open must translate identically."""
    run, ports = mapped_namespace
    payload = b"HTTP-to-root physical namespace\x00" * 10000
    response = requests.put(f"http://{BIND_HOST}:{ports[1]}/http.bin",
                            data=payload, timeout=15)
    assert response.status_code in (200, 201, 204), response.text[:200]
    destination = run.root / "download.bin"
    _mapped_copy(run, f"root://{BIND_HOST}:{ports[0]}//http.bin", destination)
    assert destination.read_bytes() == payload, "translated HTTP/root bytes differ"


@pytest.mark.timeout(90)
def test_translated_missing_key_is_not_created_by_a_read(mapped_namespace):
    """An absent mapped object fails on both planes without publishing bytes."""
    run, ports = mapped_namespace
    destination = run.root / "missing.bin"
    _mapped_copy(run, f"root://{BIND_HOST}:{ports[0]}//missing.bin",
                 destination, succeeds=False)
    response = requests.get(f"http://{BIND_HOST}:{ports[1]}/missing.bin", timeout=15)
    assert response.status_code == 404, response.text[:200]


@pytest.mark.timeout(90)
def test_translation_does_not_bypass_readonly_mutation_policy(mapped_namespace):
    """A physical-name translation must never widen the endpoint's authority."""
    run, ports = mapped_namespace
    source = run.root / "denied-source.bin"
    source.write_bytes(b"must-not-be-published")
    _mapped_copy(run, source, f"root://{BIND_HOST}:{ports[2]}//denied.bin",
                 succeeds=False)
    response = requests.get(f"http://{BIND_HOST}:{ports[1]}/denied.bin", timeout=15)
    assert response.status_code == 404, "read-only root upload published an object"


@pytest.mark.timeout(90)
def test_translated_metadata_and_delete_use_the_data_namespace(mapped_namespace):
    """HEAD and DELETE must not lose the mapping in a hand-built metadata ctx."""
    run, ports = mapped_namespace
    url = f"http://{BIND_HOST}:{ports[1]}/metadata.bin"
    response = requests.put(url, data=b"metadata-and-data-agree", timeout=15)
    assert response.status_code in (200, 201, 204), response.text[:200]
    response = requests.head(url, timeout=15)
    assert response.status_code == 200, "HEAD missed a mapped object"
    assert int(response.headers["Content-Length"]) == 23, "HEAD size differs"
    response = requests.delete(url, timeout=15)
    assert response.status_code == 204, response.text[:200]
    assert requests.get(url, timeout=15).status_code == 404, "DELETE left data behind"
    _mapped_copy(run, f"root://{BIND_HOST}:{ports[0]}//metadata.bin",
                 run.root / "deleted.bin", succeeds=False)


@pytest.fixture(scope="module")
def mapped_cache_namespace():
    """Warm one mapped cache, with separate service and deny-mode endpoints."""
    with LiveRun("n2n-cache-fill", Path(NGINX_BIN)) as run:
        root_port, http_port, origin_port, deny_root, deny_http = free_ports(5)
        export, store = run.mkdir("export"), run.mkdir("store")
        credentials = run.mkdir("empty-credentials")
        origin = run.mkdir("origin")
        mapped = run.mkdir("origin", "mapped")
        payload = b"mapped-cache-payload\x00" * 10000
        (mapped / "cache.bin").write_bytes(payload)
        (origin / "cache.bin").write_bytes(b"wrong-unprefixed-alias")
        _mapped_cache_origin(run, origin, origin_port)
        common = f"""brix_export {export};
            brix_storage_backend http://{BIND_HOST}:{origin_port}/;
            brix_n2n_scheme cephfs_path; brix_n2n_prefix /mapped;
            brix_cache_store posix:{store};"""
        config = render_config_to_path('nginx_n2n_cache.conf', run.root / 'nginx.conf',
            strict=True, PREFIX=run.root, BIND_HOST=BIND_HOST, ROOT_PORT=root_port,
            DENY_ROOT=deny_root, HTTP_PORT=http_port, DENY_HTTP=deny_http,
            CREDENTIALS=credentials, COMMON=common)
        run.start_nginx(run.root, config, root_port)
        destination = run.root / "cold.bin"
        url = f"root://{BIND_HOST}:{root_port}//cache.bin"
        _mapped_copy(run, url, destination)
        assert destination.read_bytes() == payload, "cold fill used the wrong physical key"
        yield run, (root_port, http_port, origin_port, deny_root, deny_http), payload


@pytest.mark.timeout(90)
def test_translated_async_cache_fill_and_hit_share_one_physical_key(mapped_cache_namespace):
    """A cold fill must not cache an unprefixed alias or miss its own warm key."""
    run, ports, payload = mapped_cache_namespace
    cached = run.root / "store" / "mapped" / "cache.bin"
    assert cached.read_bytes() == payload, "fill did not publish the mapped cache key"
    assert not (run.root / "store" / "cache.bin").exists(), "fill published an unprefixed alias"
    _mapped_copy(run, f"root://{BIND_HOST}:{ports[0]}//cache.bin", run.root / "warm.bin")
    assert (run.root / "warm.bin").read_bytes() == payload, "warm key missed its fill"
    response = requests.get(f"http://{BIND_HOST}:{ports[1]}/cache.bin", timeout=15)
    assert response.status_code == 200, response.text[:200]
    assert response.content == payload, "HTTP did not share the root cache key"
    _mapped_copy(run, f"root://{BIND_HOST}:{ports[0]}//absent.bin",
                 run.root / "absent.bin", succeeds=False)


@pytest.mark.timeout(90)
@pytest.mark.parametrize("origin_state", ["missing", "shorter", "longer"])
def test_cached_metadata_matches_bytes_when_origin_changes(mapped_cache_namespace, origin_state):
    """Cached bytes retain their own size even when origin metadata disagrees."""
    run, ports, payload = mapped_cache_namespace
    origin = run.root / "origin" / "mapped" / "cache.bin"
    _change_cached_origin(origin, origin_state)
    try:
        response = requests.head(f"http://{BIND_HOST}:{ports[1]}/cache.bin", timeout=15)
        assert response.status_code == 200, "HEAD lost a complete cached object"
        assert int(response.headers["Content-Length"]) == len(payload), "HEAD used origin size"
        destination = run.root / f"metadata-{origin_state}.bin"
        _mapped_copy(run, f"root://{BIND_HOST}:{ports[0]}//cache.bin", destination)
        assert destination.read_bytes() == payload, "preflight and served bytes disagree"
    finally:
        origin.write_bytes(payload)


def _change_cached_origin(origin, state):
    """Perturb only the fixture's origin, never the cached object or cinfo."""
    if state == "missing":
        origin.unlink()
        return
    replacements = {"shorter": b"new-short-origin", "longer": b"new-long-origin" * 30000}
    origin.write_bytes(replacements[state])


@pytest.mark.timeout(90)
def test_warm_cache_still_requires_backend_credentials(mapped_cache_namespace):
    """Deny-mode gates run before cached metadata and bytes, on both protocols."""
    run, ports, payload = mapped_cache_namespace
    access = run.root / "origin-server" / "access.log"
    before = access.read_text()
    url = f"http://{BIND_HOST}:{ports[4]}/cache.bin"
    assert requests.head(url, timeout=15).status_code == 403, "cached HEAD bypassed deny"
    assert requests.get(url, timeout=15).status_code == 403, "cached GET bypassed deny"
    _mapped_copy(run, f"root://{BIND_HOST}:{ports[3]}//cache.bin",
                 run.root / "forbidden.bin", succeeds=False)
    assert access.read_text() == before, "credential refusal contacted the origin"
    response = requests.get(f"http://{BIND_HOST}:{ports[1]}/cache.bin", timeout=15)
    assert response.content == payload, "refusal damaged the shared cached object"


def _mapped_cache_origin(run, origin, port):
    """Use an independent origin, matching the ordinary remote-cache topology."""
    prefix = run.mkdir("origin-server")
    config = render_config_to_path('nginx_n2n_origin.conf', prefix / 'nginx.conf',
        strict=True, PREFIX=prefix, BIND_HOST=BIND_HOST, PORT=port, ORIGIN=origin)
    run.start_nginx(prefix, config, port)
