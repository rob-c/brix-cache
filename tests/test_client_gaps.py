"""
Native-client gap closures (phase-37 §16): capabilities the clients previously
lacked, now implemented.

  * kXR_readv  — xrdfs readv <path> <off len>...        (scatter-gather read)
  * kXR_writev — xrdfs writev <path> <off hexdata>...   (scatter-gather write)
  * recursive  — xrdcp -r <dir> <dir>                   (directory-tree copy)
  * SRR        — xrddiag srr <http-url>                 (WLCG Storage Resource Reporting)

Each test self-hosts its own nginx (root stream server for readv/writev/recursive;
an http SRR location for srr) on free loopback ports, so it never needs the fleet.

Run:
    PYTHONPATH=tests pytest tests/test_client_gaps.py -v -p no:xdist
"""

import hashlib
import os
import pathlib
import shutil
import subprocess

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

# Each self-hosted server here stands up through the phase-81 registry
# (LifecycleHarness) rather than launching nginx directly; the marker keeps this
# suite out of the registry-lint direct-launch scope.
pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")


def _build(*targets):
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    r = subprocess.run(["make", "-C", CLIENT_DIR, *targets],
                       capture_output=True, text=True, timeout=240)
    for t in targets:
        if not os.path.exists(os.path.join(CLIENT_DIR, "bin", t)):
            pytest.skip(f"{t} build failed:\n{r.stdout}\n{r.stderr}")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


@pytest.fixture(scope="module")
def rw_root():
    """A writable root:// (stream) server, owned by the registry harness."""
    _build("xrdfs", "xrdcp")
    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="cgaps-rw-root",
        template="nginx_stream_posix_anon.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST, "WORKER_CONNECTIONS": 64},
    ))
    data = endpoint.data_root
    yield {"port": endpoint.port, "data": pathlib.Path(data)}
    harness.close()


def test_readv_scatter_gather(rw_root):
    (rw_root["data"] / "f.txt").write_bytes(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    url = f"root://{HOST}:{rw_root['port']}"
    p = subprocess.run([XRDFS, url, "readv", "/f.txt", "0", "5", "10", "6"],
                       capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr
    # segments [0,5)=ABCDE and [10,16)=KLMNOP, concatenated
    assert p.stdout == b"ABCDEKLMNOP", p.stdout


def test_readv_past_eof_clean_error(rw_root):
    """A segment that runs past EOF must fail cleanly (nonzero, no partial/garbage
    bytes on stdout) — the server rejects it; the client must surface the error
    without emitting uninitialized segment buffers."""
    (rw_root["data"] / "f.txt").write_bytes(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    url = f"root://{HOST}:{rw_root['port']}"
    # [0,5)=ABCDE and [30,20) which runs 14 bytes past the 36-byte EOF
    p = subprocess.run([XRDFS, url, "readv", "/f.txt", "0", "5", "30", "20"],
                       capture_output=True, timeout=30)
    assert p.returncode != 0
    assert p.stdout == b"", p.stdout   # nothing written on the error path


def test_readv_bad_args_rejected(rw_root):
    """Non-numeric offset/length is rejected cleanly (no crash, nonzero exit)."""
    url = f"root://{HOST}:{rw_root['port']}"
    p = subprocess.run([XRDFS, url, "readv", "/f.txt", "0", "notanumber"],
                       capture_output=True, timeout=30)
    assert p.returncode != 0
    assert b"bad offset/length" in p.stderr, p.stderr


def test_writev_scatter_gather(rw_root):
    url = f"root://{HOST}:{rw_root['port']}"
    # write 'aa' (6161) at 0 and 'ZZ' (5a5a) at 4 → "aa\0\0ZZ"
    w = subprocess.run([XRDFS, url, "writev", "/wv.txt", "0", "6161", "4", "5a5a"],
                       capture_output=True, timeout=30)
    assert w.returncode == 0, w.stderr
    got = (rw_root["data"] / "wv.txt").read_bytes()
    assert got == b"aa\x00\x00ZZ", got


def test_recursive_copy_roundtrip(rw_root, tmp_path):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_bytes(b"top-level\n")
    (src / "sub" / "b.txt").write_bytes(b"nested\n")
    (src / "sub" / "c.bin").write_bytes(os.urandom(4096))
    url = f"root://{HOST}:{rw_root['port']}"

    # `xrdcp -r` nests the copied tree under the source's last path component
    # (stock parity: the reference client preserves the source dir name rather
    # than flattening it). So `xrdcp -r src //tree` lands src's contents under
    # //tree/src, and the reverse `xrdcp -r //tree back` lands //tree's contents
    # under back/tree. A round trip therefore re-nests at each leg.
    up = subprocess.run([XRDCP, "-r", str(src), f"{url}//tree"],
                        capture_output=True, text=True, timeout=60)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"
    back = tmp_path / "back"
    dn = subprocess.run([XRDCP, "-r", f"{url}//tree", str(back)],
                        capture_output=True, text=True, timeout=60)
    assert dn.returncode == 0, f"{dn.stdout}\n{dn.stderr}"

    # every source file must round-trip byte-exact under the nested dest root
    # (back/tree/src/<rel>); the recursive download must create the missing
    # parent directories itself (mkdir -p), not just the leaf.
    landed = back / "tree" / "src"
    for rel in ("a.txt", "sub/b.txt", "sub/c.bin"):
        orig = (src / rel).read_bytes()
        rt = (landed / rel).read_bytes()
        assert hashlib.md5(orig).hexdigest() == hashlib.md5(rt).hexdigest(), rel


@pytest.fixture(scope="module")
def srr_server():
    _build("xrddiag")
    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="cgaps-srr",
        template="nginx_srr_self.conf",
        protocol="http",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST},
    ))
    yield {"port": endpoint.port}
    harness.close()


def test_srr_consumer(srr_server):
    p = subprocess.run([XRDDIAG, "srr", f"http://{HOST}:{srr_server['port']}",
                        "--probe-timeout", "6000"],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "implementation=BriX-Cache" in p.stdout, p.stdout
    assert "shares:" in p.stdout and "capacity:" in p.stdout, p.stdout


def test_srr_json(srr_server):
    p = subprocess.run([XRDDIAG, "srr", f"http://{HOST}:{srr_server['port']}",
                        "--json", "--probe-timeout", "6000"],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    import json
    doc = json.loads(p.stdout)
    assert "storageservice" in doc, p.stdout
