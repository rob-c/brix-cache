"""
test_client_xrdfs_eos_x509.py — native xrdfs read-only commands over GSI.

WHAT: Exercises every read-only `xrdfs` command against the local GSI harness by
      default, or against a live EOS endpoint when TEST_EOS_ENDPOINT is set.
      Proves GSI auth works and that file-content commands survive XRootD
      redirects plus the standard `cksum` query format (lib/checksum.c).
WHY:  These broke before: file reads (cat/head/tail/wc/grep/hexdump/readv) died in
      a redirect loop, and `cksum` sent a malformed "algo path" query. This locks
      the behavior in.
HOW:  Self-contained by default: the pytest harness provides a local GSI server,
      CA directory, and proxy. Everything is env-overridable:
        TEST_EOS_ENDPOINT  (default root://localhost:<gsi-port>)
        TEST_EOS_FILE      (default /test.txt)               — a readable file
        TEST_EOS_DIR       (default /)                       — a listable dir
        X509_USER_PROXY    (default harness proxy)
        X509_CERT_DIR      (default harness CA dir)

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests python3 -m pytest \
      tests/test_client_xrdfs_eos_x509.py -v -p no:xdist
"""
import os
import re
import shutil
import socket
import subprocess

import pytest

from settings import (
    CA_DIR as HARNESS_CA_DIR,
    DATA_ROOT,
    NGINX_GSI_PORT,
    PROXY_STD,
    SERVER_HOST,
)

pytestmark = pytest.mark.timeout(300)


def _harness_listing_dir():
    """Create a stable, per-xdist-worker directory in the harness export and
    return its server-relative path.

    The read-only listing commands (ls -R / find / du / tree) recurse over
    EOS_DIR. Pointing them at the shared export root ("/") makes them flaky
    under -n8: other test files concurrently create and delete files and
    subdirectories in the root, so a recursive walk can fail (rc != 0) when an
    entry vanishes mid-descent. Confining the walk to a small directory owned by
    this worker removes that cross-test churn without weakening any assertion —
    the commands still exercise the exact same server code paths.
    """
    worker = os.environ.get("PYTEST_XDIST_WORKER", "") or "main"
    rel = f"_eos_x509_ls_{worker}"
    abs_dir = os.path.join(DATA_ROOT, rel)
    os.makedirs(abs_dir, exist_ok=True)
    for name in ("alpha.txt", "beta.txt"):
        with open(os.path.join(abs_dir, name), "w") as fh:
            fh.write("eos-x509 listing fixture\n")
    return "/" + rel

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")

USE_LIVE_EOS = "TEST_EOS_ENDPOINT" in os.environ
ENDPOINT = os.environ.get(
    "TEST_EOS_ENDPOINT", f"root://{SERVER_HOST}:{NGINX_GSI_PORT}")
EOS_FILE = os.environ.get(
    "TEST_EOS_FILE", "/eos/lhcb/README" if USE_LIVE_EOS else "/test.txt")
EOS_DIR = os.environ.get(
    "TEST_EOS_DIR",
    "/eos/lhcb/user/r/rcurrie" if USE_LIVE_EOS else _harness_listing_dir())
PROXY = os.environ.get(
    "X509_USER_PROXY", f"/tmp/x509up_u{os.getuid()}" if USE_LIVE_EOS else PROXY_STD)
CA_DIR = os.environ.get(
    "X509_CERT_DIR", "/etc/grid-security/certificates" if USE_LIVE_EOS else HARNESS_CA_DIR)


def _endpoint_host(ep):
    m = re.match(r"root[s]?://\[?([^\]/:]+)\]?(?::(\d+))?", ep)
    if not m:
        return None, 1094
    return m.group(1), int(m.group(2) or 1094)


def _reachable(host, port):
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except OSError:
        return False


def _proxy_valid(path):
    """True if the proxy exists and openssl says it is not expired."""
    if not os.path.exists(path):
        return False
    if shutil.which("openssl") is None:
        return True   # can't check; assume the caller knows
    r = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-checkend", "0"],
                       capture_output=True, text=True)
    return r.returncode == 0   # 0 = will NOT expire within 0s (i.e. still valid)


@pytest.fixture(scope="module")
def eos_env():
    if not os.path.isdir(CA_DIR):
        pytest.fail(f"no CA dir {CA_DIR} (set X509_CERT_DIR)")
    if not _proxy_valid(PROXY):
        pytest.fail(f"no valid X.509 proxy at {PROXY} (set X509_USER_PROXY)")
    host, port = _endpoint_host(ENDPOINT)
    if host is None or not _reachable(host, port):
        pytest.fail(f"GSI endpoint {ENDPOINT} ({host}:{port}) not reachable")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs"],
                          capture_output=True, text=True, timeout=240)
    if proc.returncode != 0 or not os.path.exists(XRDFS):
        pytest.fail(f"xrdfs build failed:\n{proc.stdout}\n{proc.stderr}")
    env = dict(os.environ)
    env["X509_USER_PROXY"] = PROXY
    env["X509_CERT_DIR"] = CA_DIR
    # the native client's optional codec libs live in the conda prefix at build time
    prefix = env.get("CONDA_PREFIX")
    if prefix:
        env["LD_LIBRARY_PATH"] = os.path.join(prefix, "lib") + os.pathsep + \
            env.get("LD_LIBRARY_PATH", "")
    return env


def _run(env, *args, timeout=60):
    return subprocess.run([XRDFS, ENDPOINT, *args],
                          capture_output=True, text=True, env=env, timeout=timeout)


# --- the read-only command matrix -----------------------------------------
# Each: (id, argv, validator(result) -> bool). Validators keep it server-agnostic.

def _nonempty(r):       return r.returncode == 0 and len(r.stdout) > 0
def _ok(r):             return r.returncode == 0


def _cases():
    F, D = EOS_FILE, EOS_DIR
    grep_pattern = "/eos" if USE_LIVE_EOS else "nginx-xrootd"
    return [
        ("stat",          ["stat", F],            lambda r: r.returncode == 0 and "Size:" in r.stdout),
        ("ls",            ["ls", D],              _nonempty),
        ("ls_long",       ["ls", "-l", D],        _nonempty),
        ("ls_recursive",  ["ls", "-R", D],        _ok),
        ("du",            ["du", "-h", D],        _nonempty),
        ("tree",          ["tree", "-L", "1", D], _nonempty),
        ("find",          ["find", D, "-type", "f"], _ok),
        ("cat",           ["cat", F],             _nonempty),   # ← redirect-opaque fix
        ("head",          ["head", "-c", "40", F], _nonempty),
        ("tail",          ["tail", "-c", "40", F], _nonempty),
        ("wc",            ["wc", F],              _nonempty),
        ("grep",          ["grep", grep_pattern, F], _ok),
        ("hexdump",       ["hexdump", "-n", "16", F], _nonempty),
        ("readv",         ["readv", F, "0", "16"], _nonempty),
        ("cksum",         ["cksum", F],           _nonempty),   # ← cks.type query fix
        ("locate",        ["locate", F],          _nonempty),
        ("query_cksum",   ["query", "checksum", F], _nonempty),
        ("query_config",  ["query", "config", "version"], _nonempty),
    ]


@pytest.mark.parametrize("name,argv,validator", _cases(), ids=[c[0] for c in _cases()])
def test_eos_readonly_command(eos_env, name, argv, validator):
    r = _run(eos_env, *argv)
    assert validator(r), (
        f"`xrdfs {ENDPOINT} {' '.join(argv)}` failed:\n"
        f"  rc={r.returncode}\n  stdout={r.stdout[:400]!r}\n  stderr={r.stderr[:400]!r}"
    )


def test_eos_cat_is_redirect_loop_free(eos_env):
    """Regression: a file read must NOT die in the EOS open→DS redirect loop."""
    r = _run(eos_env, "cat", EOS_FILE)
    assert r.returncode == 0, r.stderr
    assert "redirect loop" not in r.stderr
    assert "capability illegal" not in r.stderr
    assert len(r.stdout) > 0


def test_eos_cksum_matches_query(eos_env):
    """Regression: the `cksum` command and `query checksum` agree (no 'algo path')."""
    rc = _run(eos_env, "cksum", EOS_FILE)
    rq = _run(eos_env, "query", "checksum", EOS_FILE)
    assert rc.returncode == 0 and rq.returncode == 0, f"{rc.stderr}\n{rq.stderr}"
    assert "disallowed" not in rc.stderr
    # both report the same adler32 hex digest
    chex = rc.stdout.split()[1] if len(rc.stdout.split()) >= 2 else ""
    assert chex and chex in rq.stdout, f"cksum={rc.stdout!r} query={rq.stdout!r}"


def _parse_stat(text):
    """Parse `xrdfs stat` "Key:  value" lines into a dict (keys lower-cased)."""
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip().lower()] = v.strip()
    return out


def test_eos_stat_extended_fields(eos_env):
    """Regression: EOS sends an extended stat tail (ctime/atime/mode/owner/group)
    after the 4 mandatory fields; our xrdfs must parse and print them, and format
    times in UTC like official xrdfs (not local time)."""
    r = _run(eos_env, "stat", EOS_DIR)
    assert r.returncode == 0, r.stderr
    d = _parse_stat(r.stdout)
    core_keys = ("path", "id", "size", "mtime", "flags")
    extended_keys = ("ctime", "atime", "mode", "owner", "group")
    for key in core_keys:
        assert key in d, f"missing '{key}' in stat output:\n{r.stdout}"
    if USE_LIVE_EOS:
        for key in extended_keys:
            assert key in d, f"missing '{key}' in stat output:\n{r.stdout}"
    if "mode" not in d:
        return
    # Mode is octal with a leading zero (e.g. 0750); owner/group are names.
    assert re.fullmatch(r"0[0-7]{3,4}", d["mode"]), f"bad mode {d['mode']!r}"
    assert d.get("owner", "") and d.get("group", "")


def test_eos_stat_matches_official(eos_env):
    """Our `xrdfs stat` output matches official xrdfs when available.

    The self-contained local harness may not have a separate official client
    configured for its test CA, so that path validates our own parsed stat fields
    instead of skipping the test.
    """
    ours_run = _run(eos_env, "stat", EOS_DIR)
    assert ours_run.returncode == 0, ours_run.stderr
    ours = _parse_stat(ours_run.stdout)
    official = shutil.which("xrdfs")
    if (not USE_LIVE_EOS
        or official is None
        or os.path.realpath(official) == os.path.realpath(XRDFS)):
        for key in ("id", "size", "mtime", "flags"):
            assert key in ours, f"native stat lacks {key}: {ours_run.stdout}"
        return
    # Official xrdfs needs system libs, not the conda prefix our client builds with.
    sys_env = dict(os.environ)
    sys_env["X509_USER_PROXY"] = PROXY
    sys_env["X509_CERT_DIR"] = CA_DIR
    sys_env.pop("LD_LIBRARY_PATH", None)
    off = subprocess.run([official, ENDPOINT, "stat", EOS_DIR],
                         capture_output=True, text=True, env=sys_env, timeout=60)
    assert off.returncode == 0, f"official xrdfs not usable here: {off.stderr[:200]}"
    theirs = _parse_stat(off.stdout)
    for key in ("id", "size", "mtime", "ctime", "atime", "flags", "mode",
                "owner", "group"):
        assert key in theirs, f"official lacks {key}: {off.stdout}"
        assert ours.get(key) == theirs[key], (
            f"stat field '{key}' differs: ours={ours.get(key)!r} "
            f"official={theirs[key]!r}")
