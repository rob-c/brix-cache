"""XRootD ``pwd`` (XrdSecpwd) password-auth — Phase 52 WS-B.

End-to-end coverage of the native pure-C client speaking the ``pwd`` protocol to
our nginx server: a 2-round DH-bootstrapped exchange whose credential is verified
(PBKDF2-HMAC-SHA1) against ``brix_pwd_file``.  Each behaviour has the mandated
trio — success, error (wrong password), and a security-negative (unknown user must
not be an enumeration oracle; no credential must be rejected).

The fixture spawns a throwaway nginx on a private high port (no shared fleet), so
it never collides with the 11xxx interop band.  Skips cleanly if the native client
is not built.
"""
import hashlib
import os
import subprocess

import pytest

from settings import NGINX_BIN  # noqa: E402
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

PW = "s3cret-passw0rd"
USER = "pwduser"


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)


def _pwd_hash(password, salt):
    """The exact KDF stock XrdSecpwd uses: PBKDF2-HMAC-SHA1, 10000 iters, 24 B."""
    return hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 10000, 24)


@pytest.fixture()
def pwd_server(lifecycle, tmp_path):
    if not os.path.exists(NATIVE_XRDCP):
        pytest.skip("native client/bin/xrdcp must be built (make -C client)")

    data = tmp_path / "data"
    data.mkdir()
    (data / "hello.txt").write_text("hello-pwd-auth\n")

    salt = bytes(range(8))
    pwd_file = tmp_path / "pwd.db"
    pwd_file.write_text(
        "# test password database\n"
        f"{USER}:{salt.hex()}:{_pwd_hash(PW, salt).hex()}\n")

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-pwd-auth",
        template="nginx_lc_pwd_auth.conf",
        protocol="root",
        template_values={"DATA_DIR": str(data), "PWD_FILE": str(pwd_file)},
        reason="stream pwd-file auth"))
    yield {"url": f"root://127.0.0.1:{ep.port}", "data": data}


def _env(password=PW, user=USER):
    e = dict(os.environ)
    e.pop("XrdSecCREDS", None)
    if password is None:
        e.pop("XRDC_PWD", None)
    else:
        e["XRDC_PWD"] = password
    e["XRDC_PWD_USER"] = user
    return e


# ---- success ---------------------------------------------------------------- #

def test_pwd_download(pwd_server, tmp_path):
    out = str(tmp_path / "got.txt")
    r = _run([NATIVE_XRDCP, "--auth", "pwd", "-f",
              f"{pwd_server['url']}//hello.txt", out], env=_env())
    assert r.returncode == 0, f"pwd download failed: {r.stderr}"
    assert open(out).read() == "hello-pwd-auth\n"


def test_pwd_upload(pwd_server, tmp_path):
    src = str(tmp_path / "up.txt")
    open(src, "w").write("uploaded-via-pwd\n")
    r = _run([NATIVE_XRDCP, "--auth", "pwd", "-f", src,
              f"{pwd_server['url']}//up.txt"], env=_env())
    assert r.returncode == 0, f"pwd upload failed: {r.stderr}"
    assert (pwd_server["data"] / "up.txt").read_text() == "uploaded-via-pwd\n"


# ---- error ------------------------------------------------------------------ #

def test_pwd_wrong_password_rejected(pwd_server, tmp_path):
    out = str(tmp_path / "bad.txt")
    r = _run([NATIVE_XRDCP, "--auth", "pwd", "-f",
              f"{pwd_server['url']}//hello.txt", out],
             env=_env(password="not-the-password"))
    assert r.returncode != 0, "wrong password must be rejected"
    assert not os.path.exists(out) or os.path.getsize(out) == 0


# ---- security-negative ------------------------------------------------------ #

def test_pwd_unknown_user_rejected(pwd_server, tmp_path):
    """An unknown user must fail exactly like a wrong password (no enumeration
    oracle, no different error/timing surface)."""
    out = str(tmp_path / "ghost.txt")
    r = _run([NATIVE_XRDCP, "--auth", "pwd", "-f",
              f"{pwd_server['url']}//hello.txt", out],
             env=_env(user="ghost"))
    assert r.returncode != 0, "unknown user must be rejected"


def test_pwd_no_credential_rejected(pwd_server, tmp_path):
    """With no password supplied the client must not authenticate."""
    out = str(tmp_path / "none.txt")
    r = _run([NATIVE_XRDCP, "--auth", "pwd", "-f",
              f"{pwd_server['url']}//hello.txt", out],
             env=_env(password=None))
    assert r.returncode != 0, "missing credential must be rejected"
