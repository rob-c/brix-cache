"""xrdfs query — the full stock code list (parity-audit §7.12).

BriX's ``query`` verb spoke 4 of stock's 9 code spellings; the missing five
(checksumcancel, xattr, prepare, opaque, opaquefile) now map onto their wire
infotypes (kXR_Qckscan-cancel / kXR_Qxattr / kXR_QPrep / kXR_Qopaque /
kXR_Qopaquf) with the same path-resolution rules the existing codes use.

  * success   — xattr returns oss.* metadata; checksum returns a digest;
                config version answers
  * error     — prepare with an unknown request id is a clean server error;
                an unknown subtype is a usage error (50)
  * security  — checksumcancel on a traversal path is refused by the server,
                never resolved outside the export

Run:
    PYTHONPATH=tests pytest tests/test_xrdfs_query_codes.py -v
"""

import os
import subprocess

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(60),
    pytest.mark.skipif(not os.path.exists(XRDFS),
                       reason="brix-xrdfs not built (client/bin/xrdfs)"),
]

NAME = "qcodes.bin"


@pytest.fixture(scope="module", autouse=True)
def staged():
    os.makedirs(DATA_ROOT, exist_ok=True)
    with open(os.path.join(DATA_ROOT, NAME), "wb") as f:
        f.write(b"query-codes probe\n")
    yield
    try:
        os.remove(os.path.join(DATA_ROOT, NAME))
    except FileNotFoundError:
        pass


def _q(*args, timeout=30):
    return subprocess.run(
        [XRDFS, f"root://{SERVER_HOST}:{NGINX_ANON_PORT}", "query", *args],
        capture_output=True, text=True, timeout=timeout)


class TestQueryCodes:

    def test_xattr_returns_oss_metadata(self):
        """(success) query xattr <path> answers the oss.* legacy metadata."""
        res = _q("xattr", "/" + NAME)
        assert res.returncode == 0, res.stderr
        assert "oss." in res.stdout, res.stdout

    def test_checksum_and_config_still_work(self):
        """(success) the pre-existing codes are unchanged by the widening."""
        res = _q("checksum", "/" + NAME)
        assert res.returncode == 0, res.stderr
        assert "adler32" in res.stdout
        res = _q("config", "version")
        assert res.returncode == 0, res.stderr
        assert res.stdout.strip() != ""

    def test_prepare_unknown_reqid_clean_error(self):
        """(error) query prepare <bogus-id> is a clean server-side error, not
        a client crash or a usage error."""
        res = _q("prepare", "no-such-reqid-123")
        assert res.returncode not in (0, 50), (res.returncode, res.stderr)
        assert res.stderr.strip() != ""

    def test_unknown_subtype_usage_error(self):
        """(error) an unknown code stays exit 50 with the widened usage."""
        res = _q("bogus-code", "x")
        assert res.returncode == 50
        assert "unknown query subtype" in res.stderr

    def test_checksumcancel_traversal_refused(self):
        """(security-neg) checksumcancel with a dotdot path is refused by the
        server's path hygiene — the new code cannot become an escape hatch."""
        res = _q("checksumcancel", "../../etc/passwd")
        assert res.returncode != 0
        assert "passwd" not in res.stdout, res.stdout
