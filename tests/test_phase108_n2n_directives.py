"""Phase-108 C13/A.4 — the ``brix_n2n_*`` name-translation directives are
validated at ``nginx -t``, not at runtime.

The generic name→PFN stage (``brix_path_lfn_to_pfn`` / ``brix_path_pfn_to_lfn``)
carries a per-export ``brix_n2n_cfg_t`` that the config layer fills. Every
switch that could misroute an object — an unknown scheme, RAL with no pool, a
pool or prefix that would silently truncate into the fixed-width cfg field, or
RAL on the RADOS backend (whose pool is bound at the ioctx, so a ``<pool>:``
prefix would be the WRONG object name) — is a *config* error surfaced as an
``[emerg]`` diagnostic, so a mistranslation can never reach a live request.

Pure config-parse property: render a template, run ``nginx -t``, assert on the
return code and the diagnostic. No server boots, so no port binds and no
storage driver initializes — a ``ceph:`` / ``http://`` backend PARSES on any
build (the driver only binds at worker start, which ``-t`` never reaches),
which is exactly what lets these validations be tested without a live cluster.
"""

import os

import pytest

from _test_phase25_ratelimit_helpers import _parse_fail, _http_values
from settings import NGINX_BIN

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
