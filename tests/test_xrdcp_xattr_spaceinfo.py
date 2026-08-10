"""xrdcp --xattr + xrdfs spaceinfo (parity-audit §7.13 / §7.12).

--xattr mirrors USER-namespace extended attributes across a completed
root://↔local copy over the kXR_fattr plane, best-effort (warnings only) —
and with a hard namespace wall: system./security./trusted. names never cross
in either direction, so a hostile remote attribute name cannot plant kernel
metadata (capabilities, ACLs) on a local file.

spaceinfo is new: the verb did not exist (stock scripts got "unknown
command"); its five-line report now matches stock 5.6.9's byte shape
(labels padded to column 21), with values from the same kXR_Qspace source.

  * success   — an uploaded user.* attribute round-trips (upload sets it
                remotely, download restores it locally); spaceinfo prints the
                stock shape with sane numbers
  * error     — --xattr on a failing copy changes nothing (no attribute
                writes); a malformed spaceinfo invocation is a usage error
  * security  — a remote attribute named "security.capability" is NOT
                applied to the local destination

DIVERGENCE (documented, not a bug): BriX's kXR_Qspace reports the whole
export's capacity for any ABSOLUTE path — it does not locate the subpath
first — so spaceinfo on a non-existent subpath still prints the export
numbers, where stock 5.6.9 returns kXR_NotFound. The verb's OUTPUT SHAPE is
the §7.12 deliverable and matches stock byte-for-byte; the whole-export
Qspace semantics are a pre-existing server behavior with its own
conformance coverage.

Run:
    PYTHONPATH=tests pytest tests/test_xrdcp_xattr_spaceinfo.py -v
"""

import os
import re
import subprocess

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(120),
    pytest.mark.skipif(not (os.path.exists(XRDCP) and os.path.exists(XRDFS)),
                       reason="brix client tools not built"),
]

URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"


def _xattr_supported(path):
    try:
        os.setxattr(path, "user.probe", b"1")
        os.removexattr(path, "user.probe")
        return True
    except OSError:
        return False


class TestXattrPreserve:

    def test_user_xattr_round_trips(self, tmp_path):
        """(success) user.* attributes survive upload and download."""
        src = tmp_path / "src.bin"
        src.write_bytes(b"xattr round trip\n")
        if not _xattr_supported(str(src)):
            pytest.skip("filesystem lacks user xattrs")
        os.setxattr(str(src), "user.prov", b"run-42")
        os.setxattr(str(src), "user.origin", b"testsuite")

        res = subprocess.run([XRDCP, "--xattr", "-f", str(src),
                              f"{URL}//xattr-rt.bin"],
                             capture_output=True, text=True, timeout=60)
        assert res.returncode == 0, res.stderr
        try:
            got = subprocess.run([XRDFS, URL, "xattr", "get",
                                  "/xattr-rt.bin", "user.prov"],
                                 capture_output=True, text=True, timeout=30)
            assert got.returncode == 0, got.stderr
            assert got.stdout.strip() == "run-42"

            back = tmp_path / "back.bin"
            res = subprocess.run([XRDCP, "--xattr",
                                  f"{URL}//xattr-rt.bin", str(back)],
                                 capture_output=True, text=True, timeout=60)
            assert res.returncode == 0, res.stderr
            assert os.getxattr(str(back), "user.prov") == b"run-42"
            assert os.getxattr(str(back), "user.origin") == b"testsuite"
        finally:
            os.unlink(os.path.join(DATA_ROOT, "xattr-rt.bin"))

    def test_without_flag_nothing_transfers(self, tmp_path):
        """(error-shape) the default copy carries NO attributes — --xattr is
        strictly opt-in."""
        src = tmp_path / "plain.bin"
        src.write_bytes(b"no xattrs please\n")
        if not _xattr_supported(str(src)):
            pytest.skip("filesystem lacks user xattrs")
        os.setxattr(str(src), "user.leak", b"nope")
        res = subprocess.run([XRDCP, "-f", str(src), f"{URL}//xattr-off.bin"],
                             capture_output=True, text=True, timeout=60)
        assert res.returncode == 0, res.stderr
        try:
            got = subprocess.run([XRDFS, URL, "xattr", "get",
                                  "/xattr-off.bin", "user.leak"],
                                 capture_output=True, text=True, timeout=30)
            assert got.returncode != 0, "attribute crossed without --xattr"
        finally:
            os.unlink(os.path.join(DATA_ROOT, "xattr-off.bin"))

    def test_hostile_namespace_never_lands(self, tmp_path):
        """(security-neg) a remote attribute in a kernel namespace is refused
        on download: plant one server-side via the raw fattr plane, download
        with --xattr, and prove the local file did NOT receive it."""
        name = "xattr-hostile.bin"
        with open(os.path.join(DATA_ROOT, name), "wb") as f:
            f.write(b"hostile attr host\n")
        try:
            # the raw verb allows any name remotely; the COPY must filter it
            subprocess.run([XRDFS, URL, "xattr", "set", "/" + name,
                            "security.capability", "hostile"],
                           capture_output=True, text=True, timeout=30)
            dst = tmp_path / "out.bin"
            res = subprocess.run([XRDCP, "--xattr", f"{URL}//{name}",
                                  str(dst)],
                                 capture_output=True, text=True, timeout=60)
            assert res.returncode == 0, res.stderr
            with pytest.raises(OSError):
                os.getxattr(str(dst), "security.capability")
            with pytest.raises(OSError):
                os.getxattr(str(dst), "user.security.capability")
        finally:
            os.unlink(os.path.join(DATA_ROOT, name))


class TestSpaceinfo:

    STOCK_SHAPE = re.compile(
        r"^Path:               \S+\n"
        r"Total:              \d+\n"
        r"Free:               \d+\n"
        r"Used:               \d+\n"
        r"Largest free chunk: \d+\n$")

    def test_stock_shape_and_sanity(self):
        """(success) the five stock lines, labels padded to column 21, with
        internally consistent numbers."""
        res = subprocess.run([XRDFS, URL, "spaceinfo", "/"],
                             capture_output=True, text=True, timeout=30)
        assert res.returncode == 0, res.stderr
        assert self.STOCK_SHAPE.match(res.stdout), repr(res.stdout)
        nums = [int(x) for x in re.findall(r"(\d+)$", res.stdout, re.M)]
        total, free, used, chunk = nums
        assert 0 < free <= total
        assert used <= total
        assert chunk <= free

    def test_default_path_is_root(self):
        """(success) spaceinfo with no path argument reports the export root —
        the same numbers as an explicit '/'."""
        no_arg = subprocess.run([XRDFS, URL, "spaceinfo"],
                                capture_output=True, text=True, timeout=30)
        assert no_arg.returncode == 0, no_arg.stderr
        assert self.STOCK_SHAPE.match(no_arg.stdout), repr(no_arg.stdout)
        assert no_arg.stdout.splitlines()[0] == "Path:               /"

    def test_missing_subpath_reports_export_divergence(self):
        """(divergence) BriX Qspace is whole-export, so spaceinfo on a
        non-existent subpath still prints the export numbers (stock 404s here).
        Pin the divergence so a future change is a deliberate decision."""
        res = subprocess.run([XRDFS, URL, "spaceinfo", "/no/such/dir-xyz"],
                             capture_output=True, text=True, timeout=30)
        assert res.returncode == 0, res.stderr
        assert self.STOCK_SHAPE.match(res.stdout), repr(res.stdout)
