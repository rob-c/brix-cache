"""
test_audit15i_plane_pins.py — the audit's DISMISSED pairs, turned into guards
(§D of docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md).

§D lists eight feature pairs the audit checked and did not file as gaps, each
dismissed because the pair is impossible *by construction* — a TAKE1 directive,
a directive that exists on only one nginx plane, a protocol that refuses write
grammar outright.  Every one of those dismissals is a claim about the config
surface that nothing in the suite was checking.  A dismissal is only durable
while the construction holds: the day someone gives `brix_io_uring` an http
twin, or relaxes `brix_auth` to TAKE12, §D quietly becomes wrong and the pair
it dismissed becomes an untested cross.  This file makes that day noisy.

Everything here is parse-tier: render a config into `tmp_path` and run
`nginx -t`.  No server boots, no port is bound, no registry spec is created —
`nginx -t` never binds, so the listen port is a placeholder.  Guard-negative
configs are synthesized into `tmp_path`; no tracked config is ever touched.

  * `brix_auth` is TAKE1 (directives_auth.h:12) — two schemes in one directive
    and two directives in one server are both refused, so "auth x auth on one
    server" has no config to express it.
  * plane exclusivity, both directions — `brix_io_uring` and
    `brix_data_substreams` are stream-only; `brix_webdav_checksum_on_write` and
    `brix_srr` are http-only.  Each is refused with "directive is not allowed
    here" on the far plane and parses on its own, which is what makes
    "checksum_on_write x io_uring", "root x checksum_on_write",
    "webdav x substreams" and "root x srr" plane-vacuous rather than untested.
  * cvmfs refuses write grammar — §D dismisses "cvmfs x auth/write features"
    citing the read_only force-clear, but the real guard is stronger and fires
    first: `brix_allow_write on` in a cvmfs location is an EMERG at nginx -t
    (cvmfs_module_build.c:97).

DEFECT CANDIDATE #32 (low severity, fail-safe direction) — the two cvmfs
guards are ordered so the softer one disarms the louder one.
ngx_http_brix_cvmfs_merge_loc_conf() runs cvmfs_merge_preamble() (which calls
ngx_http_brix_shared_merge -> brix_shared_apply_read_only, zeroing allow_write)
BEFORE cvmfs_merge_cache() -> brix_cvmfs_reject_unsupported(), which then reads
allow_write == 0 and stays quiet.  So `brix_allow_write on` alone is a hard
config error, while `brix_allow_write on; brix_read_only on;` parses clean —
the explicit write grant becomes exactly the "silent no-op" the guard's own
comment (cvmfs_module_build.c:94-96) says it exists to prevent.  Writes are
refused either way, so nothing is exploitable; what is lost is the operator's
error message.  test_read_only_disarms_the_cvmfs_write_rejection pins the
current behaviour and says how to flip it.
"""

import os
import re
import subprocess

import pytest

from _test_phase25_ratelimit_helpers import (
    _parse_fail,
    _http_values,
    _stream_values,
)
from settings import BIND_HOST, NGINX_BIN

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason="nginx binary not built")

DEFECT32 = ("DEFECT CANDIDATE #32 has been FIXED: `brix_allow_write on` inside "
            "a cvmfs location is now rejected even when `brix_read_only on` is "
            "present. Flip this expectation to expect rc != 0 and the "
            "'cvmfs is a read-only protocol' diagnostic.")

# The one-line diagnostic nginx emits for a directive used on a plane whose
# module never declared it — the exact string every plane-exclusivity claim in
# §D reduces to.
WRONG_PLANE = "directive is not allowed here"

# Stream-plane directives that must NOT exist on the http plane, with the
# smallest value each accepts.  brix_io_uring is the one §B2.11 named.
STREAM_ONLY = [
    ("brix_io_uring", "auto"),
    ("brix_data_substreams", "on"),
]

# ...and the mirror: http-plane directives with no stream twin.  §D calls the
# absence of a stream checksum_on_write a parity DECISION (stream checksums are
# on-demand, via kXR_chksum), not an oversight — so the reject is the pin.
HTTP_ONLY = [
    ("brix_webdav_checksum_on_write", "adler32"),
    ("brix_srr", "on"),
]

_CVMFS_CONF = "nginx_audit15i_cvmfs_write.conf"


def _prefix(path):
    """`_parse_fail` renders into an EXISTING directory; tests that parse more
    than one config need a fresh prefix per parse (one error.log, one
    conf/nginx.conf), so make the sub-prefix before handing it over."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def _stream_t(tmp_path, knobs):
    return _parse_fail(_prefix(tmp_path), "nginx_rl_stream.conf",
                       _stream_values(knobs, ""))


def _http_t(tmp_path, knobs, extra_locations=""):
    return _parse_fail(_prefix(tmp_path), "nginx_rl_http.conf",
                       _http_values(knobs, "", extra_locations))


def _cvmfs_t(tmp_path, knobs):
    """Parse a lone cvmfs location carrying `knobs`, and hand back the
    parse-time NOTICE lines alongside the usual (rc, output).

    Parse-time log calls go through `cf->log`, which is still the DEFAULT log
    while the config is being read — nginx only switches to the configured
    error_log once ngx_init_cycle has finished parsing.  So the merge NOTICE
    lands in <prefix>/logs/error.log, not in the {LOG_DIR}/error.log the
    template names, and that directory has to exist first or nginx aborts with
    "could not open error log file".
    """
    root = tmp_path / "cvmfs"
    (root / "logs").mkdir(parents=True)
    rc, out = _parse_fail(root, _CVMFS_CONF,
                          {"BIND_HOST": BIND_HOST, "CVMFS_KNOBS": knobs})
    log = root / "logs" / "error.log"
    notices = [ln for ln in log.read_text(encoding="utf-8").splitlines()
               if "read_only on" in ln] if log.exists() else []
    return rc, out, notices


def _links_liburing():
    """True when the binary under test was linked against liburing.

    The §B2.13 blocker in a function: a bare `./configure` produces a binary
    with no ring, and the whole io_uring row skips.  `BRIX_ENABLE_IO_URING=1
    ./configure --add-module=$REPO ... && make` produces one with it.
    """
    try:
        out = subprocess.run(["ldd", str(NGINX_BIN)], capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("ldd unavailable; cannot classify the binary's ring support")
    return "liburing" in (out.stdout or "")


# --------------------------------------------------------------------------- #
# "auth x auth on one server" — unsupported by construction                    #
# --------------------------------------------------------------------------- #


def test_brix_auth_takes_exactly_one_scheme(tmp_path):
    """Two schemes in one directive is a parse error, not a scheme list."""
    rc, out = _stream_t(tmp_path, "        brix_auth gsi sss;\n")
    assert rc != 0, out
    assert "invalid number of arguments" in out, out
    assert "brix_auth" in out, out


def test_brix_auth_cannot_be_repeated_in_one_server(tmp_path):
    """...and stacking two brix_auth lines is refused as a duplicate, so a
    single stream server can never carry two schemes at once.  Mixed-auth is a
    CLUSTER property (the chaos mixed-auth helpers), never a server property."""
    # The template already sets `brix_auth none;`, so one more line collides.
    rc, out = _stream_t(tmp_path, "        brix_auth gsi;\n")
    assert rc != 0, out
    assert "duplicate" in out, out
    assert "brix_auth" in out, out


# --------------------------------------------------------------------------- #
# Plane exclusivity — both directions                                          #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("directive,value", STREAM_ONLY)
def test_stream_only_directives_are_refused_on_the_http_plane(
        tmp_path, directive, value):
    rc, out = _http_t(tmp_path, f"            {directive} {value};\n")
    assert rc != 0, out
    assert WRONG_PLANE in out, out
    assert directive in out, out


@pytest.mark.parametrize("directive,value", HTTP_ONLY)
def test_http_only_directives_are_refused_on_the_stream_plane(
        tmp_path, directive, value):
    rc, out = _stream_t(tmp_path, f"        {directive} {value};\n")
    assert rc != 0, out
    assert WRONG_PLANE in out, out
    assert directive in out, out


def test_every_dismissed_directive_parses_on_its_own_plane(tmp_path):
    """The control that makes the four rejects above mean "wrong plane" rather
    than "bad value": each directive, same value, on the plane that declares
    it."""
    for i, (directive, value) in enumerate(STREAM_ONLY):
        rc, out = _stream_t(tmp_path / f"s{i}", f"        {directive} {value};\n")
        assert rc == 0, f"{directive} rejected on the stream plane: {out}"
    for i, (directive, value) in enumerate(HTTP_ONLY):
        # brix_srr is a location directive with no home in the WebDAV location
        # (one brix protocol per location), so it gets its own.
        if directive == "brix_srr":
            rc, out = _http_t(
                tmp_path / f"h{i}", "",
                extra_locations=("        location /srr/ {\n"
                                 f"            {directive} {value};\n"
                                 "            brix_srr_name audit15i;\n"
                                 "        }\n"))
        else:
            rc, out = _http_t(tmp_path / f"h{i}",
                              f"            {directive} {value};\n")
        assert rc == 0, f"{directive} rejected on the http plane: {out}"


def test_io_uring_on_never_silently_degrades_to_the_thread_pool(tmp_path):
    """`brix_io_uring on` is a demand, not a preference: on a binary without
    liburing it must be an EMERG naming the rebuild, never a quiet fallback.

    This is the §B2.13 blocker as an assertion.  The io_uring row sat "written
    but never executed" for three tranches because the default test binary has
    no ring; the failure mode that would have hidden it forever is a config
    that says `on`, gets the thread pool, and reports success.
    """
    rc, out = _stream_t(tmp_path, "        brix_io_uring on;\n")
    if _links_liburing():
        assert rc == 0, out
        return
    assert rc != 0, out
    assert "requires a build with liburing" in out, out
    assert "BRIX_ENABLE_IO_URING=1" in out, out


def test_io_uring_auto_parses_on_any_build(tmp_path):
    """The documented escape hatch the EMERG above points at: `auto` is the
    value that IS allowed to fall back, and it must parse everywhere."""
    rc, out = _stream_t(tmp_path, "        brix_io_uring auto;\n")
    assert rc == 0, out


# --------------------------------------------------------------------------- #
# "cvmfs x auth/write features" — refused, not merely defaulted off            #
# --------------------------------------------------------------------------- #


def test_cvmfs_refuses_explicit_write_permission(tmp_path):
    """The guard §D should have cited: a cvmfs location that asks for writes
    dies at nginx -t, before read_only enters the picture at all."""
    rc, out, notices = _cvmfs_t(tmp_path, "            brix_allow_write on;\n")
    assert rc != 0, out
    assert "cvmfs is a read-only protocol" in out, out
    assert "brix_allow_write" in out, out
    assert notices == [], f"read_only was never set, yet it logged: {notices}"


def test_read_only_disarms_the_cvmfs_write_rejection(tmp_path):
    """DEFECT CANDIDATE #32 — adding `brix_read_only on` to the config the
    previous test proves is fatal makes it parse clean.

    The force-clear runs in the preamble merge and zeroes allow_write; the
    cvmfs write rejection runs afterwards and sees nothing to reject.  The
    operator gets a NOTICE about read_only instead of an error about the
    directive they actually got wrong.
    """
    rc, out, notices = _cvmfs_t(tmp_path,
                                "            brix_allow_write on;\n"
                                "            brix_read_only on;\n")
    assert rc == 0, f"{DEFECT32}\n{out}"
    assert "cvmfs is a read-only protocol" not in out, DEFECT32
    # The force-clear did happen — it is the reason the rejection stayed quiet.
    assert notices, ("read_only was set but brix_shared_apply_read_only logged "
                     "nothing; the force-clear is the mechanism this test "
                     f"depends on. Output: {out}")
    assert "overrides allow_write" in notices[0], notices


def test_a_cvmfs_location_without_read_only_logs_no_override(tmp_path):
    """Control: the NOTICE the test above leans on is read_only-driven, not
    something every cvmfs merge emits."""
    rc, out, notices = _cvmfs_t(tmp_path, "")
    assert rc == 0, out
    assert notices == [], notices


def test_cvmfs_refuses_the_rest_of_the_write_grammar(tmp_path):
    """Security-negative: the write-side tier grammar is refused too, so
    "cvmfs x write features" cannot be reached through the staging door either.
    Unlike allow_write, this guard reads a field read_only does not touch, so
    read_only cannot disarm it.
    """
    rc, out, _ = _cvmfs_t(tmp_path,
                          "            brix_stage on;\n"
                          "            brix_read_only on;\n")
    assert rc != 0, out
    assert "cvmfs is a read-only protocol" in out, out
    assert "staging is not supported" in out, out


def test_the_wrong_plane_diagnostic_is_a_stable_string(tmp_path):
    """Everything above pattern-matches nginx's own wording. If a version bump
    reworded it, four tests would go green for the wrong reason — so pin the
    string against a directive whose plane confinement is not in question."""
    rc, out = _http_t(tmp_path, "            brix_root on;\n")
    assert rc != 0, out
    assert re.search(r'"brix_root" directive is not allowed here', out), out
