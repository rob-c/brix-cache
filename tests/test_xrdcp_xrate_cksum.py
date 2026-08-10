"""xrdcp --xrate/--xrate-threshold pacing + sha-family checksums (§7.13).

--xrate caps the serial pump's rate (stock RATE[k|m|g] spellings);
--xrate-threshold fails a transfer whose average rate sinks below a floor
(3 s grace).  The sha family (sha1/sha256/sha512) joins --cksum for the
LOCAL modes only — the server checksum plane has no sha support, so
``sha*:source`` is a loud usage error instead of a silent UNVERIFIED pass.
--rm-bad-cksum is accepted as a stock-compat alias: BriX's fail-closed
default already drops mismatched destinations unconditionally.

  * success   — a paced download takes at least the rate-implied time and is
                byte-exact; sha256 literal verification passes
  * error     — a self-tripped threshold fails with the floor named; bad rate
                strings are usage errors
  * security  — sha256:source refuses loudly; a wrong sha digest (with and
                without --rm-bad-cksum) leaves no destination

Run:
    PYTHONPATH=tests pytest tests/test_xrdcp_xrate_cksum.py -v
"""

import hashlib
import os
import subprocess
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(120),
    pytest.mark.skipif(not os.path.exists(XRDCP),
                       reason="brix-xrdcp not built (client/bin/xrdcp)"),
]

CONTENT = bytes((i * 17 + 3) % 251 for i in range(1536 * 1024))   # 1.5 MiB
NAME = "xrate-src.bin"


@pytest.fixture(scope="module", autouse=True)
def staged():
    os.makedirs(DATA_ROOT, exist_ok=True)
    with open(os.path.join(DATA_ROOT, NAME), "wb") as f:
        f.write(CONTENT)
    yield
    try:
        os.remove(os.path.join(DATA_ROOT, NAME))
    except FileNotFoundError:
        pass


def _url():
    return f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//{NAME}"


def _run(args, timeout=90):
    return subprocess.run([XRDCP] + args, capture_output=True, text=True,
                          timeout=timeout)


class TestXrate:

    def test_paced_download_respects_cap(self, tmp_path):
        """(success) 1.5 MiB at --xrate 512k must take >= ~3 s (assert a 2 s
        floor for load tolerance) and land byte-exact."""
        dst = tmp_path / "out.bin"
        t0 = time.monotonic()
        res = _run(["--xrate", "512k", _url(), str(dst)])
        elapsed = time.monotonic() - t0
        assert res.returncode == 0, res.stderr
        assert dst.read_bytes() == CONTENT
        assert elapsed >= 2.0, (
            f"paced download finished in {elapsed:.2f}s — --xrate ignored")

    def test_threshold_floor_trips(self, tmp_path):
        """(error) --xrate 64k with a 10m floor self-trips after the grace:
        the copy fails naming the floor and leaves no destination."""
        dst = tmp_path / "out.bin"
        res = _run(["--xrate", "64k", "--xrate-threshold", "10m",
                    _url(), str(dst)])
        assert res.returncode != 0
        assert "xrate-threshold" in res.stderr, res.stderr
        assert not dst.exists()

    @pytest.mark.parametrize("bad", ["0", "-5", "bogus", "10x",
                                     "99999999999999999999g"])
    def test_bad_rate_is_usage_error(self, bad, tmp_path):
        """(security-neg) hostile rate strings are usage errors — never a
        wrapped/tiny rate."""
        res = _run(["--xrate", bad, _url(), str(tmp_path / "o")], timeout=30)
        assert res.returncode == 50, (bad, res.returncode, res.stderr)


class TestShaCksum:

    def test_sha256_literal_verifies(self, tmp_path):
        """(success) --cksum sha256:<correct> passes and the file lands."""
        dst = tmp_path / "out.bin"
        digest = hashlib.sha256(CONTENT).hexdigest()
        res = _run(["--cksum", f"sha256:{digest}", _url(), str(dst)])
        assert res.returncode == 0, res.stderr
        assert dst.read_bytes() == CONTENT

    def test_sha512_print_mode(self, tmp_path):
        """(success) sha512:print emits the local digest."""
        dst = tmp_path / "out.bin"
        res = _run(["--cksum", "sha512:print", _url(), str(dst)])
        assert res.returncode == 0, res.stderr
        assert hashlib.sha512(CONTENT).hexdigest() in (res.stdout + res.stderr)

    def test_sha_source_refused_loudly(self, tmp_path):
        """(security-neg) sha256:source must be a LOUD failure naming the
        limitation — never a silent unverified pass."""
        dst = tmp_path / "out.bin"
        res = _run(["--cksum", "sha256:source", _url(), str(dst)])
        assert res.returncode != 0
        assert "sha" in res.stderr and "literal" in res.stderr, res.stderr

    @pytest.mark.parametrize("extra", [[], ["--rm-bad-cksum"]])
    def test_wrong_sha_drops_destination(self, extra, tmp_path):
        """(security-neg) a wrong sha256 digest fails closed with no
        destination file — identically with and without --rm-bad-cksum (the
        stock flag is an alias of BriX's stricter default)."""
        dst = tmp_path / "out.bin"
        res = _run(["-s", *extra, "--cksum", "sha256:" + "0" * 64,
                    _url(), str(dst)])
        assert res.returncode != 0
        assert not dst.exists()
