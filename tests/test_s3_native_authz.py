"""test_s3_native_authz.py — phase-101 W5.2c: native brix_authdb READ ACL on S3.

W5 unified brix_authdb onto the shared preamble but enforced it only on webdav,
leaving it accepted-but-inert on S3.  W5.2c closes that: the S3 access phase now
enforces the native u/g/p/h rules (from common.authdb_rules, deep-copied and
finalized against this export's own root) on the confined object path.

A rule-covered path is served; a path with no covering rule is default-denied
(403), and a host rule (`p <ip>`) matches on the peer — exactly like webdav and
root://.  Self-contained: spawns a single anonymous S3 server as a subprocess.

Run:  PYTHONPATH=. python3 -m pytest test_s3_native_authz.py -p no:xdist -q
"""

import os
import urllib.request
import urllib.error

import pytest

from settings import BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [
    pytest.mark.skipif(
        not os.path.exists(NGINX_BIN),
        reason="nginx binary (set NGINX_BIN) not available"),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-s3-native-authz"),
]

_SERVER = "lc-s3-native-authz"


def _http_code(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


@pytest.fixture()
def s3_authdb_server(lifecycle, tmp_path):
    data = tmp_path / "data"
    for sub in ("grant", "private", "host"):
        (data / sub).mkdir(parents=True)
        (data / sub / "f.txt").write_text(sub + "\n")
    authdb = tmp_path / "authdb"
    # u * grants /grant to anyone; a peer rule grants /host to loopback; /private
    # is covered by NO rule -> default-deny.
    authdb.write_text("u * /grant rl\np 127.0.0.1 /host r\np ::1 /host r\n")  # net-literal-allow: loopback literal is the subject under test

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=_SERVER,
        template="nginx_lc_s3_native_authz.conf",
        data_root=str(data),
        protocol="s3",
        template_values={"BIND_HOST": BIND_HOST, "AUTHDB": str(authdb)},
        reason="native authdb ACL enforcement on the S3 plane"))
    yield f"http://{BIND_HOST}:{endpoint.port}/b"


def test_authdb_grants_rule_covered_path(s3_authdb_server):
    """`u * /grant rl` -> a GET under /grant is served."""
    assert _http_code(f"{s3_authdb_server}/grant/f.txt") == 200


def test_authdb_grants_host_rule_path(s3_authdb_server):
    """`p 127.0.0.1 /host r` -> the loopback peer is served under /host."""
    assert _http_code(f"{s3_authdb_server}/host/f.txt") == 200


def test_authdb_denies_uncovered_path(s3_authdb_server):
    """No rule covers /private -> default-deny (403), not a silent 200.

    This is the W5.2c guarantee: bare brix_authdb on S3 is ENFORCED, not an
    accepted-but-inert no-op."""
    assert _http_code(f"{s3_authdb_server}/private/f.txt") == 403
