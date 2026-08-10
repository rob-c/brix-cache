"""xrdfs locate flags + stat -q flag queries (parity audit §7.12).

locate used to hardcode wire options=0 and take no flags; stat had no -q.
Now:
  * ``locate [-n] [-r] [-d] [-m|-h] [-i] [-p] <path>`` — the stock flag
    surface. -r sets kXR_refresh (BriX flushes + bypasses the loc/redirect
    caches, §2.7), -n sets kXR_nowait, -m/-h set kXR_prefname; -i/-p are
    accepted for stock CLI compatibility (this client never resolves names in
    replies and never sends tried= on a first attempt, so both hold by
    default). -d deep-locates: every file under a directory is located and
    printed as "<path>: <reply>".
  * ``stat -q <query>`` — the stock flag-query contract, pinned LIVE against
    stock xrdfs 5.6.9: '&' requires every named flag, '|' is satisfied by
    any (linear left-to-right fold); exit 0 when the query holds, 55 when it
    does not, 50 for an unknown flag name.

Server: the shared fleet's writable anon root:// server (NGINX_ANON_PORT),
same doctrine as test_xrootdfs.py.

Run (against a started fleet):
    PYTHONPATH=tests pytest tests/test_xrdfs_locate_statq.py -v
"""

import os
import shutil
import subprocess
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

pytestmark = [pytest.mark.timeout(120)]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
URL = None  # set in _built (needs the fleet port)


@pytest.fixture(scope="module")
def built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs"],
                   capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDFS):
        pytest.skip("xrdfs build failed")


@pytest.fixture()
def tree(built):
    """A small tree in the anon export: base/f1.txt base/f2.txt base/sub/f3.txt."""
    base = f"_locq_{os.getpid()}_{int(time.time() * 1000)}"
    root = os.path.join(DATA_ROOT, base)
    os.makedirs(os.path.join(root, "sub"))
    for rel in ("f1.txt", "f2.txt", os.path.join("sub", "f3.txt")):
        with open(os.path.join(root, rel), "wb") as fh:
            fh.write(b"payload:" + rel.encode())
    yield base
    shutil.rmtree(root, ignore_errors=True)


def _run(*args):
    url = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
    return subprocess.run([XRDFS, url, *args], capture_output=True, text=True,
                          timeout=30)


# --------------------------------------------------------------------------- #
# locate flags
# --------------------------------------------------------------------------- #

def test_locate_plain_and_flagged(tree):
    """(success) locate works bare and with every wire-bit flag; -r (refresh,
    honoured server-side per §2.7), -n, -m, -i, -p all still resolve the
    path."""
    for flags in ([], ["-r"], ["-n"], ["-m"], ["-h"], ["-i"], ["-p"],
                  ["-r", "-n", "-m"]):
        p = _run("locate", *flags, f"/{tree}/f1.txt")
        assert p.returncode == 0, f"locate {flags}: {p.stderr}"
        assert p.stdout.strip(), f"locate {flags}: empty reply"


def test_locate_deep_lists_every_file(tree):
    """(success) locate -d on a directory prints a '<path>: <reply>' line for
    every FILE in the tree, including nested ones."""
    p = _run("locate", "-d", f"/{tree}")
    assert p.returncode == 0, p.stderr
    out = p.stdout
    for rel in (f"/{tree}/f1.txt", f"/{tree}/f2.txt", f"/{tree}/sub/f3.txt"):
        assert f"{rel}: " in out, f"deep locate missed {rel}:\n{out}"
    assert f"/{tree}/sub: " not in out, "directories must not be located"


def test_locate_missing_path_fails(tree):
    """(error) locate of a nonexistent path exits nonzero, flagged or not."""
    for flags in ([], ["-r"], ["-d"]):
        p = _run("locate", *flags, "/does-not-exist-xyz")
        assert p.returncode != 0, f"locate {flags} of missing path succeeded"


def test_locate_unknown_flag_refused(tree):
    """(security-neg) an unknown dash-flag is refused with the usage error —
    never silently treated as a path or ignored."""
    p = _run("locate", "-z", f"/{tree}/f1.txt")
    assert p.returncode == 50, f"unknown flag not refused: {p.returncode}"
    assert "usage" in p.stderr.lower(), p.stderr


def test_locate_deep_on_file_locates_just_it(tree):
    """(security-neg) -d on a plain file degrades to the single-path locate —
    no directory walk, no fabricated entries."""
    p = _run("locate", "-d", f"/{tree}/f1.txt")
    assert p.returncode == 0, p.stderr
    assert len(p.stdout.strip().splitlines()) == 1, p.stdout


# --------------------------------------------------------------------------- #
# stat -q
# --------------------------------------------------------------------------- #

def test_statq_holds(tree):
    """(success) queries that hold exit 0 — dir IsDir, file IsReadable,
    OR with one absent flag, AND with both present (stock semantics)."""
    for path, query in ((f"/{tree}", "IsDir"),
                        (f"/{tree}/f1.txt", "IsReadable"),
                        (f"/{tree}", "Offline|IsDir"),
                        (f"/{tree}", "IsReadable&IsDir")):
        p = _run("stat", "-q", query, path)
        assert p.returncode == 0, \
            f"stat -q {query} {path}: rc={p.returncode} {p.stderr}"


def test_statq_fails_with_55(tree):
    """(error) queries that do not hold exit 55 (the stock code): file IsDir,
    AND with one absent flag."""
    for path, query in ((f"/{tree}/f1.txt", "IsDir"),
                        (f"/{tree}", "IsReadable&Offline")):
        p = _run("stat", "-q", query, path)
        assert p.returncode == 55, \
            f"stat -q {query} {path}: rc={p.returncode} (want 55)"


def test_statq_unknown_flag_refused(tree):
    """(security-neg) an unknown flag name is refused with usage code 50
    (stock behaviour) and names the accepted vocabulary — it must never
    silently evaluate to false/true."""
    p = _run("stat", "-q", "BogusFlag", f"/{tree}")
    assert p.returncode == 50, f"rc={p.returncode} (want 50)"
    assert "IsDir" in p.stderr, p.stderr


# --------------------------------------------------------------------------- #
# ls -u / -C / -Z / -D (stock flag surface, parity audit §7.12)
# --------------------------------------------------------------------------- #

def test_ls_u_prints_urls(tree):
    """(success) ls -u prefixes every entry with root://host:port; -D is
    accepted (identity: single-server listings are never merged, so there are
    no duplicates to re-show)."""
    p = _run("ls", "-u", "-D", f"/{tree}")
    assert p.returncode == 0, p.stderr
    lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
    assert lines, "empty ls -u listing"
    for line in lines:
        assert line.startswith(f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/"), \
            f"entry not URL-formed: {line!r}"
    assert any(line.endswith("/f1.txt") for line in lines), p.stdout


def test_ls_C_appends_matching_checksum(tree):
    """(success) ls -C appends adler32:<hex> per file, matching a local
    adler32 of the same bytes; directories carry no checksum column."""
    import zlib
    payload = b"payload:f1.txt"
    want = "%08x" % (zlib.adler32(payload) & 0xFFFFFFFF)
    p = _run("ls", "-C", f"/{tree}")
    assert p.returncode == 0, p.stderr
    f1 = [ln for ln in p.stdout.splitlines() if ln.endswith(f"adler32:{want}")
          and "f1.txt" in ln]
    assert f1, f"f1.txt checksum column missing/wrong:\n{p.stdout}"
    subs = [ln for ln in p.stdout.splitlines()
            if ln.rstrip("/").endswith("/sub")]
    assert subs and "adler32" not in subs[0], \
        f"directory entry grew a checksum column: {subs}"


def test_ls_Z_lists_zip_members(tree):
    """(success) ls -Z lists a remote ZIP archive's members with their
    uncompressed sizes (store and deflate both)."""
    import zipfile
    zpath = os.path.join(DATA_ROOT, tree, "arch.zip")
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("stored.txt", "S" * 100,
                    compress_type=zipfile.ZIP_STORED)
        zf.writestr("deflated.txt", "D" * 5000,
                    compress_type=zipfile.ZIP_DEFLATED)
    p = _run("ls", "-Z", f"/{tree}/arch.zip")
    assert p.returncode == 0, p.stderr
    assert "stored.txt" in p.stdout and "deflated.txt" in p.stdout, p.stdout
    assert "100" in p.stdout and "5000" in p.stdout, p.stdout


def test_ls_Z_non_zip_refused(tree):
    """(error) ls -Z on a plain file fails cleanly, naming the problem."""
    p = _run("ls", "-Z", f"/{tree}/f1.txt")
    assert p.returncode != 0, "plain file accepted as a ZIP archive"
    assert "zip" in p.stderr.lower(), p.stderr


def test_ls_Z_malformed_zip_bounds_checked(tree):
    """(security-neg) a crafted EOCD claiming an absurd central directory is
    refused by the shared parser's bounds checks — clean error, no crash."""
    bad = os.path.join(DATA_ROOT, tree, "bomb.zip")
    # EOCD: signature, disk fields, entry count 0xFFFF, cd size/offset far
    # beyond the file, empty comment.
    import struct as _s
    with open(bad, "wb") as fh:
        fh.write(b"junkdata" * 8)
        fh.write(_s.pack("<IHHHHIIH", 0x06054b50, 0, 0, 0xFFFF, 0xFFFF,
                         0x7FFFFFFF, 0x7FFFFFFF, 0))
    p = _run("ls", "-Z", f"/{tree}/bomb.zip")
    assert p.returncode != 0, "malformed ZIP accepted"
    assert "zip" in p.stderr.lower(), p.stderr
