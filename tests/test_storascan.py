"""
xrdstorascan — the backend-aware storage admin tool (phase 1: verify + bench).

Two layers:
  * test_storascan_core_unit — compiles + runs the standalone pure-core suite
    (client/apps/storascan_unittest.c): percentile / throughput / verdict math.
    Needs only a C compiler, no server.
  * the fleet tests — drive the built `xrdstorascan` binary against the live
    anon endpoint over root://, exercising `verify` (A1, end-to-end checksum)
    and `bench` (B1, throughput/latency sweep), plus the error/arg-negative
    paths. They SKIP (never fail) when the fleet or built client is absent.

See docs/superpowers/specs/2026-06-29-client-backend-sysadmin-tooling-design.md.
"""
import json
import os
import shutil
import subprocess
import zlib

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APPS = os.path.join(REPO, "client", "apps")
CORE = os.path.join(APPS, "storascan_core.c")
UT = os.path.join(APPS, "storascan_unittest.c")
BIN = os.path.join(REPO, "client", "bin", "xrdstorascan")


# --------------------------------------------------------------------------- #
# Pure-core unit suite (no server).                                           #
# --------------------------------------------------------------------------- #
def test_storascan_core_unit(tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not (os.path.exists(CORE) and os.path.exists(UT)):
        pytest.skip("storascan core sources missing")
    out = str(tmp_path / "ut")
    comp = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror", "-o", out, UT, CORE, "-lm"],
        capture_output=True, text=True)
    assert comp.returncode == 0, \
        "storascan_core unit suite failed to COMPILE:\n%s" % comp.stderr
    run = subprocess.run([out], capture_output=True, text=True, timeout=60)
    print(run.stdout)
    assert run.returncode == 0, \
        "storascan_core unit suite reported failures:\n%s\n%s" % (run.stdout, run.stderr)
    assert "all checks passed" in run.stdout


# --------------------------------------------------------------------------- #
# Fleet integration — verify (A1) + bench (B1) over root:// (anon endpoint).  #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def anon(clientconf_env):  # noqa: F811  (fixture imported below)
    from clientconf import endpoints as E
    if "anon" not in clientconf_env["healthy"]:
        pytest.skip("anon endpoint not reachable")
    if not os.path.exists(BIN):
        pytest.skip("xrdstorascan not built")
    return E.ANON


# Pull the shared fixture into this module's namespace for the fixture above.
from clientconf.fixtures import clientconf_env  # noqa: E402,F401


def _biggest_corpus_file():
    """The largest seeded corpus entry (remote path, local path, size)."""
    from clientconf import corpus
    from settings import DATA_ROOT
    entry = max(corpus.FILES, key=lambda e: e.size)
    local = os.path.join(DATA_ROOT, corpus.PREFIX, entry.rel)
    return entry.remote, local, entry.size


def _run(anon, *args, timeout=120):
    return subprocess.run([BIN, *args], capture_output=True, text=True,
                          env=anon.auth_env(), timeout=timeout)


def test_verify_matches_recorded_checksum(anon):
    remote, local, size = _biggest_corpus_file()
    if size == 0 or not os.path.exists(local):
        pytest.skip("no usable corpus file")
    r = _run(anon, "verify", anon.url(remote), "--algo", "adler32")
    # rc 0 = match, rc 2 = server stored no checksum. A mismatch (1) or error
    # (3) is a real failure — the bytes we pulled must agree with the server.
    assert r.returncode in (0, 2), \
        "verify rc=%d\nstdout=%s\nstderr=%s" % (r.returncode, r.stdout, r.stderr)
    if r.returncode == 0:
        want = "%08x" % (zlib.adler32(open(local, "rb").read()) & 0xffffffff)
        assert want in r.stdout, \
            "verify OK but digest %s not in output: %s" % (want, r.stdout)


def test_verify_missing_file_errors(anon):
    r = _run(anon, "verify", anon.url("/clientconf/does-not-exist.bin"))
    assert r.returncode != 0, "verify of a missing file must fail"


def test_verify_bad_algo_is_usage_error(anon):
    remote, _, _ = _biggest_corpus_file()
    r = _run(anon, "verify", anon.url(remote), "--algo", "not-a-real-algo")
    assert r.returncode == 64, "bad --algo should be a usage error (64)"


def test_bench_read_sweep_json(anon):
    remote, _, size = _biggest_corpus_file()
    if size == 0:
        pytest.skip("no usable corpus file")
    r = _run(anon, "bench", anon.url(remote),
             "--op", "read", "--block", "16K,64K", "--parallel", "1,2",
             "--count", "8", "--json")
    assert r.returncode == 0, \
        "bench rc=%d\nstdout=%s\nstderr=%s" % (r.returncode, r.stdout, r.stderr)
    recs = [json.loads(ln) for ln in r.stdout.splitlines() if ln.strip()]
    assert len(recs) == 4, "expected 2x2 sweep cells, got %d" % len(recs)
    for rec in recs:
        assert rec["t"] == "bench"
        assert rec["ops"] > 0, "a cell did zero ops: %s" % rec
        assert rec["throughput_mibps"] >= 0.0
        assert rec["p50_ms"] >= 0.0


def test_bench_bad_pattern_is_usage_error(anon):
    remote, _, _ = _biggest_corpus_file()
    r = _run(anon, "bench", anon.url(remote), "--pattern", "diagonal")
    assert r.returncode == 64, "bad --pattern should be a usage error (64)"
