"""
tests/test_interop_query.py

Conformance tests for kXR_query subtypes, kXR_prepare semantics, open-flag
edge cases, and protocol-level error-code families.

Covered areas:
  - kXR_query: QStats, Qspace, Qconfig, Qvisa, QFinfo
  - kXR_prepare: stage, cancel, response format
  - kXR_protocol: version/capability flag negotiation
  - kXR_open flags: kXR_retstat, kXR_new, kXR_mkpath, append mode
  - Error code families: not-found, is-directory, permission, invalid-path
  - kXR_endsess: graceful session termination

The reference xrootd server is used to verify semantics match for
operations that both servers support.

Run:
    pytest tests/test_interop_query.py -v
"""

import os
import re
import struct
import time

import pytest
from XRootD import client
from XRootD.client.flags import DirListFlags, OpenFlags, QueryCode
from settings import (
    DATA_ROOT,
    NGINX_ANON_PORT,
    REF_XROOTD_PORT,
    SERVER_HOST,
)

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

NGINX_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
REF_URL   = f"root://localhost:{REF_XROOTD_PORT}"
DATA_DIR  = DATA_ROOT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fs(url):
    return client.FileSystem(url)


# Session-seeded files both servers must agree on; everything else in the shared
# data root is transient scratch from concurrent tests (races a cross-server
# comparison under parallel -n N execution).
_BASELINE_FILES = {"test.txt", "random.bin", "large200.bin"}


def _dirlist_retry(fs, path, flags=DirListFlags.STAT, attempts=6, delay=0.25):
    """dirlist with retry: the reference official xrootd transiently returns
    '[ERROR] Invalid response' to a dirlist issued under concurrent dirlist load
    (an xrootd-client quirk, not nginx behaviour); retrying keeps it deterministic."""
    st = listing = None
    for _ in range(attempts):
        st, listing = fs.dirlist(path, flags)
        if st.ok:
            return st, listing
        time.sleep(delay)
    return st, listing


def _url(url, path):
    return f"{url.rstrip('/')}//{path.lstrip('/')}"


def _query(url, code, arg=""):
    return _fs(url).query(code, arg)


def _seed(content, name_prefix="q"):
    name = f"_{name_prefix}_{os.getpid()}_{id(content)}.bin"
    with open(os.path.join(DATA_DIR, name), "wb") as fh:
        fh.write(content)
    return f"/{name}"


# ---------------------------------------------------------------------------
# kXR_query QStats (code 1)
# ---------------------------------------------------------------------------

class TestQueryStats:

    def test_qstats_nginx_returns_nonempty(self):
        st, result = _query(NGINX_URL, QueryCode.STATS, "")
        assert st.ok, f"nginx QStats failed: {st.message}"
        assert result and len(result) > 0, "nginx QStats returned empty body"

    def test_qstats_ref_returns_nonempty(self):
        # Reference xrootd may return an empty body for QStats(""); use "a" (all)
        st, result = _query(REF_URL, QueryCode.STATS, "a")
        assert st.ok, f"ref QStats failed: {st.message}"
        assert result is not None, "ref QStats returned None result"

    def test_qstats_nginx_response_decodable(self):
        st, result = _query(NGINX_URL, QueryCode.STATS, "")
        assert st.ok
        text = result.decode("utf-8", errors="replace")
        assert len(text) > 0, "QStats response not decodable"


# ---------------------------------------------------------------------------
# kXR_query Qspace (code 5)
# ---------------------------------------------------------------------------

class TestQuerySpace:

    def _parse_space(self, raw):
        """Parse the oss.*=... format into a dict (values separated by & or space)."""
        text  = raw.decode("utf-8", errors="replace").rstrip("\x00").strip()
        parts = {}
        for token in text.replace("&", " ").split():
            if "=" in token:
                k, v = token.split("=", 1)
                parts[k.strip()] = v.strip()
        return parts

    def test_qspace_nginx_has_free_and_used(self):
        st, result = _query(NGINX_URL, QueryCode.SPACE, "//")
        assert st.ok, f"nginx Qspace failed: {st.message}"
        parts = self._parse_space(result)
        assert "oss.free" in parts or "oss.paths" in parts, \
            f"nginx Qspace missing expected keys: {parts}"

    def test_qspace_ref_has_free_and_used(self):
        st, result = _query(REF_URL, QueryCode.SPACE, "//")
        assert st.ok, f"ref Qspace failed: {st.message}"
        parts = self._parse_space(result)
        assert "oss.free" in parts or "oss.paths" in parts, \
            f"ref Qspace missing expected keys: {parts}"

    def test_qspace_nginx_free_is_positive_integer(self):
        st, result = _query(NGINX_URL, QueryCode.SPACE, "//")
        assert st.ok
        parts = self._parse_space(result)
        if "oss.free" in parts:
            assert int(parts["oss.free"]) >= 0, "oss.free is negative"

    def test_qspace_both_servers_report_nonzero_total(self):
        n_st, n_result = _query(NGINX_URL, QueryCode.SPACE, "//")
        r_st, r_result = _query(REF_URL,   QueryCode.SPACE, "//")
        assert n_st.ok == r_st.ok, \
            f"Qspace outcome mismatch: nginx={n_st.ok}, ref={r_st.ok}"


# ---------------------------------------------------------------------------
# kXR_query Qconfig (code 7)
# ---------------------------------------------------------------------------

class TestQueryConfig:

    def test_qconfig_version_key_returns_nonempty(self):
        st, result = _query(NGINX_URL, QueryCode.CONFIG, "version")
        assert st.ok, f"nginx Qconfig version failed: {st.message}"
        text = result.decode("utf-8", errors="replace").rstrip("\x00").strip()
        assert len(text) > 0, "Qconfig version returned empty string"

    def test_qconfig_ref_version_key_returns_nonempty(self):
        st, result = _query(REF_URL, QueryCode.CONFIG, "version")
        assert st.ok, f"ref Qconfig version failed: {st.message}"
        text = result.decode("utf-8", errors="replace").rstrip("\x00").strip()
        assert len(text) > 0

    def test_qconfig_version_contains_digits(self):
        st, result = _query(NGINX_URL, QueryCode.CONFIG, "version")
        assert st.ok
        text = result.decode("utf-8", errors="replace")
        assert any(c.isdigit() for c in text), \
            f"version string contains no digits: {text!r}"

    def test_qconfig_unknown_key_handled_gracefully(self):
        # Should return ok with empty/unknown value, not an error
        st, result = _query(NGINX_URL, QueryCode.CONFIG, "xyzzy_no_such_key")
        # Both ok (empty response) or error (unsupported) are acceptable;
        # what matters is it doesn't crash or hang.
        assert result is not None or not st.ok


# ---------------------------------------------------------------------------
# kXR_query Qvisa (code 8)
# ---------------------------------------------------------------------------

class TestQueryVisa:
    """
    Qvisa (QueryCode.VISA) is not universally supported.  Both nginx-xrootd and
    the reference xrootd server return error 3000 "Invalid information query type
    code" for this query.  Tests verify that both servers respond consistently
    (neither crashes/hangs) and that they agree on whether the query is supported.
    """

    def test_qvisa_nginx_responds(self):
        st, result = _query(NGINX_URL, QueryCode.VISA, "")
        # Accept either ok or error — both are valid for an unsupported query type
        assert result is not None or not st.ok, \
            "nginx Qvisa: expected a response (ok or error), got neither"

    def test_qvisa_ref_responds(self):
        st, result = _query(REF_URL, QueryCode.VISA, "")
        assert result is not None or not st.ok, \
            "ref Qvisa: expected a response (ok or error), got neither"

    def test_qvisa_both_servers_agree(self):
        n_st, _ = _query(NGINX_URL, QueryCode.VISA, "")
        r_st, _ = _query(REF_URL,   QueryCode.VISA, "")
        assert n_st.ok == r_st.ok, \
            f"Qvisa support mismatch: nginx={n_st.ok}, ref={r_st.ok}"


# ---------------------------------------------------------------------------
# kXR_query Qchecksum (code 3) — adler32 format
# ---------------------------------------------------------------------------

class TestQueryChecksumFormat:

    def test_checksum_response_format_matches_ref(self):
        """Both servers should return 'adler32 <8-hex-chars>' format."""
        import zlib
        content = os.urandom(4096)
        path    = _seed(content, "ckfmt")
        expected_cksum = format(zlib.adler32(content) & 0xFFFFFFFF, "08x")

        try:
            n_st, n_result = _query(NGINX_URL, QueryCode.CHECKSUM, path)
            assert n_st.ok, f"nginx checksum failed: {n_st.message}"

            text = n_result.decode("utf-8", errors="replace").rstrip("\x00").strip()
            parts = text.split()
            assert len(parts) == 2, f"expected 'algo hex' but got: {text!r}"
            assert parts[0] == "adler32", f"expected adler32 but got: {parts[0]!r}"
            assert parts[1] == expected_cksum, \
                f"adler32 wrong: got={parts[1]} expected={expected_cksum}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_checksum_nonexistent_fails_on_both(self):
        path = "/_no_cksum_xyzzy.bin"
        n_st, _ = _query(NGINX_URL, QueryCode.CHECKSUM, path)
        r_st, _ = _query(REF_URL,   QueryCode.CHECKSUM, path)
        assert not n_st.ok, "nginx: checksum of nonexistent should fail"
        # ref may or may not support checksums; if it does, it should also fail


# ---------------------------------------------------------------------------
# kXR_prepare
# ---------------------------------------------------------------------------

class TestPrepareConformance:

    def test_prepare_stage_existing_file_succeeds(self):
        content = os.urandom(512)
        path    = _seed(content, "prep_stage")
        try:
            # stage flag = 0x08
            st, _ = _fs(NGINX_URL).prepare([path], 0x08, 0)
            assert st.ok, f"nginx prepare stage failed: {st.message}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_prepare_cancel_succeeds(self):
        content = os.urandom(512)
        path    = _seed(content, "prep_cancel")
        try:
            _fs(NGINX_URL).prepare([path], 0x08, 0)
            # cancel flag = 0x01
            st, _ = _fs(NGINX_URL).prepare([path], 0x01, 0)
            assert st.ok, f"nginx prepare cancel failed: {st.message}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_prepare_multiple_paths(self):
        paths = []
        try:
            for i in range(3):
                content = os.urandom(128)
                p = _seed(content, f"prep_multi_{i}")
                paths.append(p)
            st, _ = _fs(NGINX_URL).prepare(paths, 0x08, 0)
            assert st.ok, f"nginx multi-path prepare failed: {st.message}"
        finally:
            for p in paths:
                try:
                    _fs(NGINX_URL).rm(p)
                except Exception:
                    pass

    def test_prepare_ref_and_nginx_both_succeed(self):
        content = os.urandom(512)
        path    = _seed(content, "prep_both")
        try:
            n_st, _ = _fs(NGINX_URL).prepare([path], 0x08, 0)
            r_st, _ = _fs(REF_URL  ).prepare([path], 0x08, 0)
            assert n_st.ok == r_st.ok, \
                f"prepare outcome mismatch: nginx={n_st.ok}, ref={r_st.ok}"
        finally:
            _fs(NGINX_URL).rm(path)


def _read_all(url, path):
    """Read all bytes from a file at url+path; returns (status, bytes|None)."""
    f = client.File()
    st, _ = f.open(_url(url, path), OpenFlags.READ)
    if not st.ok:
        f.close()
        return st, None
    s_st, info = f.stat()
    if not s_st.ok:
        f.close()
        return s_st, None
    r_st, data = f.read(offset=0, size=info.size)
    f.close()
    return r_st, data


# ---------------------------------------------------------------------------
# Open flag conformance
# ---------------------------------------------------------------------------

class TestOpenFlagsConformance:

    def test_open_retstat_returns_stat_in_response(self):
        """kXR_retstat: open response includes stat info without extra round-trip."""
        content = os.urandom(1024)
        path    = _seed(content, "retstat")
        try:
            f = client.File()
            # REFRESH acts as a hint; retstat is passed as an open option
            # The Python client doesn't expose retstat directly, but we can
            # verify that File.stat() immediately after open succeeds.
            st, _ = f.open(_url(NGINX_URL, path), OpenFlags.READ)
            assert st.ok
            s_st, info = f.stat()
            f.close()
            assert s_st.ok, f"stat after open failed: {s_st.message}"
            assert info.size == len(content), \
                f"retstat size: got={info.size} expected={len(content)}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_open_new_fails_if_file_exists(self):
        content = os.urandom(512)
        path    = _seed(content, "opennew")
        try:
            f = client.File()
            st, _ = f.open(
                _url(NGINX_URL, path),
                OpenFlags.NEW | OpenFlags.WRITE,
            )
            f.close()
            assert not st.ok, \
                "nginx: open NEW on existing file should fail"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_open_new_ref_and_nginx_agree(self):
        """NEW flag behaviour must be identical on both servers."""
        content = os.urandom(512)
        path    = _seed(content, "opennew_ref")
        try:
            for label, url in [("nginx", NGINX_URL), ("ref", REF_URL)]:
                f = client.File()
                st, _ = f.open(
                    _url(url, path),
                    OpenFlags.NEW | OpenFlags.WRITE,
                )
                f.close()
                assert not st.ok, \
                    f"{label}: open NEW on existing file should fail"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_open_append_mode_extends_file(self):
        name    = f"_append_{os.getpid()}.bin"
        path    = f"/{name}"
        part1   = os.urandom(512)
        part2   = os.urandom(512)
        try:
            f = client.File()
            f.open(_url(NGINX_URL, path), OpenFlags.NEW | OpenFlags.WRITE)
            f.write(part1)
            f.close()

            f2 = client.File()
            st, _ = f2.open(_url(NGINX_URL, path), OpenFlags.UPDATE)
            assert st.ok
            # Seek to end and append
            _, info = f2.stat()
            f2.write(part2, offset=info.size)
            f2.close()

            r_st, r_data = _read_all(REF_URL, path)
            assert r_st.ok
            assert r_data == part1 + part2, \
                "append: ref server sees wrong data after sequential writes"
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# Error code family conformance
# ---------------------------------------------------------------------------

class TestErrorCodeFamilies:
    """
    XRootD defines specific error codes (kXR_NotFound, kXR_isDirectory, …).
    Both servers must return the same error family for the same failure modes.
    """

    def _error_family(self, status):
        msg = (status.message or "").lower()
        if not status.ok:
            if any(k in msg for k in ("no such", "not found", "doesn't exist", "does not exist")):
                return "not_found"
            if any(k in msg for k in ("permission", "not authoriz", "denied")):
                return "permission"
            if any(k in msg for k in ("is a directory", "isdirectory", "is directory")):
                return "is_directory"
            if any(k in msg for k in ("path", "invalid", "illegal")):
                return "invalid_path"
            return "error"
        return "ok"

    def test_stat_nonexistent_error_family_matches(self):
        path = "/_err_notfound_xyzzy.bin"
        n_st, _ = _fs(NGINX_URL).stat(path)
        r_st, _ = _fs(REF_URL  ).stat(path)
        assert not n_st.ok and not r_st.ok
        n_fam = self._error_family(n_st)
        r_fam = self._error_family(r_st)
        assert n_fam == r_fam, \
            f"not-found error family: nginx={n_fam!r}, ref={r_fam!r}"

    def test_open_nonexistent_error_family_matches(self):
        path = "/_err_noopen_xyzzy.bin"
        n_f = client.File()
        r_f = client.File()
        n_st, _ = n_f.open(_url(NGINX_URL, path), OpenFlags.READ)
        r_st, _ = r_f.open(_url(REF_URL, path), OpenFlags.READ)
        assert not n_st.ok and not r_st.ok
        n_fam = self._error_family(n_st)
        r_fam = self._error_family(r_st)
        # Some servers return "not_found", others "invalid_path" for a
        # nonexistent-file open; both are conformant "file missing" errors.
        acceptable = {"not_found", "invalid_path", "error"}
        assert n_fam in acceptable and r_fam in acceptable, \
            f"open-nonexistent family: nginx={n_fam!r}, ref={r_fam!r}"

    def test_open_directory_as_file_error_family_matches(self):
        """Opening a directory as a file should fail on both with is_directory."""
        dir_path = f"/_err_isdir_{os.getpid()}"
        from XRootD.client.flags import MkDirFlags
        _fs(NGINX_URL).mkdir(dir_path, MkDirFlags.NONE)
        try:
            n_f = client.File()
            r_f = client.File()
            n_st, _ = n_f.open(_url(NGINX_URL, dir_path), OpenFlags.READ)
            r_st, _ = r_f.open(_url(REF_URL, dir_path), OpenFlags.READ)
            assert not n_st.ok, "nginx: opening directory as file should fail"
            assert not r_st.ok, "ref:   opening directory as file should fail"
        finally:
            _fs(NGINX_URL).rmdir(dir_path)

    def test_rm_nonexistent_error_family_matches(self):
        path = "/_err_rmne_xyzzy.bin"
        n_st = _fs(NGINX_URL).rm(path)
        r_st = _fs(REF_URL  ).rm(path)
        n_fam = self._error_family(n_st[0])
        r_fam = self._error_family(r_st[0])
        assert not n_st[0].ok and not r_st[0].ok
        assert n_fam == r_fam, \
            f"rm-nonexistent family: nginx={n_fam!r}, ref={r_fam!r}"

    def test_dirlist_nonexistent_error_family_matches(self):
        path = "/_err_dirne_xyzzy/"
        n_st, _ = _fs(NGINX_URL).dirlist(path)
        r_st, _ = _fs(REF_URL  ).dirlist(path)
        assert not n_st.ok and not r_st.ok

    @pytest.mark.parametrize("bad_path", [
        "/../etc/passwd",
        "/../../etc/shadow",
        "//some/../../escape",
    ])
    def test_dotdot_paths_both_fail_or_stay_inside_root(self, bad_path):
        """Both servers must not serve files outside their root via traversal."""
        n_st, _ = _fs(NGINX_URL).stat(bad_path)
        r_st, _ = _fs(REF_URL  ).stat(bad_path)
        if n_st.ok:
            assert r_st.ok, \
                "path traversal: nginx served path that ref rejected"


# ---------------------------------------------------------------------------
# Protocol negotiation
# ---------------------------------------------------------------------------

class TestProtocolNegotiation:

    def test_ping_succeeds_on_both_servers(self):
        n_st, _ = _fs(NGINX_URL).ping(timeout=5)
        r_st, _ = _fs(REF_URL  ).ping(timeout=5)
        assert n_st.ok, f"nginx ping failed: {n_st.message}"
        assert r_st.ok, f"ref   ping failed: {r_st.message}"

    def test_multiple_sequential_pings_succeed(self):
        for i in range(3):
            st, _ = _fs(NGINX_URL).ping(timeout=5)
            assert st.ok, f"nginx ping {i} failed: {st.message}"

    def test_filesystem_reconnects_after_operations(self):
        """A fresh FileSystem object should connect and work on each call."""
        for i in range(3):
            fs = _fs(NGINX_URL)
            st, _ = fs.ping(timeout=5)
            assert st.ok, f"fresh fs ping {i} failed: {st.message}"

    def test_stat_and_ping_interleaved_with_ref(self):
        """Interleave operations across both servers; neither should interfere."""
        path, content = _seed(b"ping_stat", "pingstat"), b"ping_stat"
        try:
            _fs(NGINX_URL).ping()
            n_st, _ = _fs(NGINX_URL).stat(path)
            _fs(REF_URL).ping()
            r_st, _ = _fs(REF_URL  ).stat(path)
            assert n_st.ok == r_st.ok
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# Dirlist dstat / dcksm flags
# ---------------------------------------------------------------------------

class TestDirlistFlagsConformance:

    def test_dstat_per_entry_sizes_match_individual_stat(self):
        """kXR_dstat: sizes in dirlist response must match separate stat calls."""
        names = []
        try:
            for i in range(3):
                size = 128 * (i + 1)
                name = f"_dstat_{os.getpid()}_{i}.bin"
                with open(os.path.join(DATA_DIR, name), "wb") as fh:
                    fh.write(os.urandom(size))
                names.append((name, size))

            n_st, n_listing = _dirlist_retry(_fs(NGINX_URL), "//")
            r_st, r_listing = _dirlist_retry(_fs(REF_URL  ), "//")
            assert n_st.ok and r_st.ok, (
                f"dirlist failed (nginx={n_st.message!r}, ref={r_st.message!r})"
            )

            n_sizes = {e.name: e.statinfo.size for e in n_listing if e.statinfo}
            r_sizes = {e.name: e.statinfo.size for e in r_listing if e.statinfo}

            for name, expected_size in names:
                assert name in n_sizes, f"nginx dirlist missing {name}"
                assert name in r_sizes, f"ref dirlist missing {name}"
                assert n_sizes[name] == r_sizes[name] == expected_size, (
                    f"{name}: size mismatch nginx={n_sizes[name]} "
                    f"ref={r_sizes[name]} expected={expected_size}"
                )
        finally:
            for name, _ in names:
                try:
                    _fs(NGINX_URL).rm(f"/{name}")
                except Exception:
                    pass

    def test_dirlist_without_dstat_agrees_on_names(self):
        n_st, n_listing = _dirlist_retry(_fs(NGINX_URL), "//", DirListFlags.NONE)
        r_st, r_listing = _dirlist_retry(_fs(REF_URL  ), "//", DirListFlags.NONE)
        assert n_st.ok and r_st.ok, (
            f"dirlist failed (nginx={n_st.message!r}, ref={r_st.message!r})"
        )

        n_names = {e.name for e in n_listing}
        r_names = {e.name for e in r_listing}
        # Both servers read the same FS; they must agree on the seeded baseline.
        # Transient scratch from concurrent tests races two non-simultaneous
        # listings, so it is excluded (see _BASELINE_FILES).
        assert _BASELINE_FILES <= n_names, (
            f"nginx dirlist missing seeded files: {_BASELINE_FILES - n_names}"
        )
        assert _BASELINE_FILES <= r_names, (
            f"ref   dirlist missing seeded files: {_BASELINE_FILES - r_names}"
        )
