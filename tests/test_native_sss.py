"""
Native SSS (Simple Shared Secret) auth — phase-37 §6 + §14.3.

End-to-end gate for the clean-room client's SSS support: xrdsssadmin mints a
keytab, an nginx stream server is configured with `brix_auth sss` against that
same keytab, and the native xrdfs authenticates with `--auth sss` — proving the
client builds a byte-exact SSS credential (16-byte header + BF32(40-byte data
header + NAME TLV + IEEE-CRC32)) that the server decrypts and accepts.

Self-contained: spins up its own nginx (NGINX_BIN) on a free port with a temp
keytab and data dir, so it never touches the shared fleet. Builds the client.

Run (serial):
    PYTHONPATH=tests pytest tests/test_native_sss.py -v -p no:xdist
"""

import hashlib
import os
import shutil
import subprocess

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-native-sss")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDSSSADMIN = os.path.join(CLIENT_DIR, "bin", "xrdsssadmin-brix")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")


def _clean_env(extra=None):
    env = {k: v for k, v in os.environ.items()}
    for k in ("X509_USER_PROXY", "X509_CERT_DIR", "BEARER_TOKEN",
              "BEARER_TOKEN_FILE", "XrdSecSSSKT", "XrdSecsssKT"):
        env.pop(k, None)
    if extra:
        env.update(extra)
    return env


@pytest.fixture(scope="module")
def _client_built():
    # Build the client tools we need.
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp", "xrdsssadmin-brix"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDSSSADMIN):
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")


@pytest.fixture()
def sss_server(lifecycle, _client_built, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    payload = os.urandom(40000)
    (data / "probe.txt").write_bytes(b"sss-ok\n")
    (data / "blob.bin").write_bytes(payload)

    # Server keytab: anybody/anygroup so the client's local login name is accepted.
    kt_srv = str(tmp_path / "server.keytab")
    r = subprocess.run([XRDSSSADMIN, "-k", kt_srv, "add", "--id", "1",
                        "--user", "anybody", "--group", "anygroup", "--name", "testhost"],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"xrdsssadmin add failed: {r.stdout}{r.stderr}"

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-native-sss",
        template="nginx_lc_native_sss.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "KEYTAB": kt_srv},
        reason="stream SSS keytab auth"))

    return {"port": ep.port, "kt_srv": kt_srv, "data": data, "payload": payload,
            "root": tmp_path}


def _xrdfs(server, *args, keytab=None, timeout=30):
    env = _clean_env({"XrdSecSSSKT": keytab} if keytab else None)
    url = f"root://{HOST}:{server['port']}"
    return subprocess.run([XRDFS, "--auth", "sss", url, *args],
                          capture_output=True, text=True, env=env, timeout=timeout)


# --------------------------------------------------------------------------
# the gate: SSS auth succeeds
# --------------------------------------------------------------------------

def test_sss_stat_authenticates(sss_server):
    p = _xrdfs(sss_server, "stat", "/probe.txt", keytab=sss_server["kt_srv"])
    assert p.returncode == 0, f"sss stat failed:\n{p.stdout}\n{p.stderr}"
    assert "Size:" in p.stdout, p.stdout


def test_sss_ls(sss_server):
    p = _xrdfs(sss_server, "ls", "/", keytab=sss_server["kt_srv"])
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "blob.bin" in p.stdout and "probe.txt" in p.stdout, p.stdout


def test_sss_explain_reports_sss(sss_server):
    p = _xrdfs(sss_server, "explain", keytab=sss_server["kt_srv"])
    assert p.returncode == 0, p.stderr
    assert "authenticated with: sss" in p.stdout, p.stdout


def test_sss_download_md5_exact(sss_server, tmp_path):
    out = tmp_path / "blob.out"
    env = _clean_env({"XrdSecSSSKT": sss_server["kt_srv"]})
    url = f"root://{HOST}:{sss_server['port']}//blob.bin"
    p = subprocess.run([XRDCP, "--auth", "sss", url, str(out)],
                       capture_output=True, text=True, env=env, timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    got = out.read_bytes()
    assert hashlib.md5(got).hexdigest() == hashlib.md5(sss_server["payload"]).hexdigest()


# --------------------------------------------------------------------------
# negatives
# --------------------------------------------------------------------------

def test_sss_no_keytab_fails(sss_server, tmp_path):
    missing = str(tmp_path / "nope.keytab")
    p = _xrdfs(sss_server, "stat", "/probe.txt", keytab=missing)
    assert p.returncode != 0, p.stdout


def test_sss_wrong_key_rejected(sss_server, tmp_path):
    # Same wire id (1) but a different random key → server CRC mismatch → reject.
    kt_bad = str(tmp_path / "bad.keytab")
    r = subprocess.run([XRDSSSADMIN, "-k", kt_bad, "add", "--id", "1",
                        "--user", "anybody", "--group", "anygroup"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    p = _xrdfs(sss_server, "stat", "/probe.txt", keytab=kt_bad)
    assert p.returncode != 0, f"wrong key was accepted!\n{p.stdout}"


# --------------------------------------------------------------------------
# Regression: SSS verify-chain deny must be terminal (auth_request.c sss_deny).
#
# A deny used to funnel through brix_sss_auth_failed(), which returns NGX_OK
# after queueing the kXR_error. Callers gate on `rc != NGX_OK`, so an NGX_OK
# deny fell through to sss_map_identity()/sss_reply():
#   * unknown key id  -> cred.key == NULL -> key->user NULL deref -> worker crash
#     (remote, pre-auth DoS: one unauthenticated packet kills the worker)
#   * wrong key (CRC) -> non-NULL key      -> spurious kXR_ok + registered session
# The fix routes every deny through sss_deny() (returns NGX_DONE, stashing the
# wire result in replied_rc), so a deny never reaches identity mapping.
# --------------------------------------------------------------------------

def _mint_keytab(tmp_path, name, key_id):
    kt = str(tmp_path / name)
    r = subprocess.run([XRDSSSADMIN, "-k", kt, "add", "--id", str(key_id),
                        "--user", "anybody", "--group", "anygroup"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return kt


def test_sss_unknown_key_id_rejected(sss_server, tmp_path):
    # Client presents wire id 2; the server keytab only holds id 1, so
    # brix_sss_find_key() returns NULL. Must be a clean deny, not acceptance.
    kt_unknown = _mint_keytab(tmp_path, "unknown.keytab", 2)
    p = _xrdfs(sss_server, "stat", "/probe.txt", keytab=kt_unknown)
    assert p.returncode != 0, f"unknown key id was accepted!\n{p.stdout}"


def test_sss_server_survives_unknown_key(sss_server, tmp_path):
    # SECURITY-NEGATIVE / DoS regression: the unknown-key-id credential is the
    # exact input that crashed the worker via the NULL-key dereference. Fire it,
    # then prove the server is still alive by authenticating a legitimate
    # request on a fresh connection. Pre-fix, the worker was dead here.
    kt_unknown = _mint_keytab(tmp_path, "unknown2.keytab", 2)
    for _ in range(3):
        bad = _xrdfs(sss_server, "stat", "/probe.txt", keytab=kt_unknown)
        assert bad.returncode != 0, f"unknown key id was accepted!\n{bad.stdout}"

    good = _xrdfs(sss_server, "stat", "/probe.txt", keytab=sss_server["kt_srv"])
    assert good.returncode == 0, (
        "server did not survive an unknown-key SSS credential — "
        f"legitimate auth afterwards failed:\n{good.stdout}\n{good.stderr}")
    assert "Size:" in good.stdout, good.stdout


def test_sss_wrong_key_no_auth_leak(sss_server, tmp_path):
    # A wrong-key (non-NULL key, CRC-mismatch) deny must NOT authenticate a
    # session. Observable proxy: the wrong-key stat is rejected, and the server
    # keeps behaving correctly for a subsequent legitimate request (a leaked or
    # crashed session would break the follow-up).
    kt_bad = _mint_keytab(tmp_path, "bad2.keytab", 1)  # right id, wrong secret
    bad = _xrdfs(sss_server, "stat", "/probe.txt", keytab=kt_bad)
    assert bad.returncode != 0, f"wrong key was accepted!\n{bad.stdout}"

    good = _xrdfs(sss_server, "ls", "/", keytab=sss_server["kt_srv"])
    assert good.returncode == 0, f"{good.stdout}\n{good.stderr}"
    assert "probe.txt" in good.stdout, good.stdout
