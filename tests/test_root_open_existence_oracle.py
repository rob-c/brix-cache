"""No-root verification of the root:// read-open existence-oracle fix (open_request.c).

The direct read-open path now runs the authorization gate BEFORE probing existence, so a denied
principal receives an IDENTICAL kXR_NotAuthorized whether or not the path exists — closing the
namespace-existence oracle (a denied user could previously distinguish kXR_NotFound (absent)
from kXR_NotAuthorized (present-but-denied)). Authorized principals still see the real answer
(NotFound for a genuinely absent path).

Non-cache GSI+authdb node (impersonation off — the gate is a worker-level wire decision), VO
ACL `g cms /` as the discriminator.

Run: PYTHONPATH=tests pytest tests/test_root_open_existence_oracle.py -v   (no root needed)
"""
import os
import socket
import subprocess
import time
from types import SimpleNamespace

import pytest

from mu_authz_lib import creds, fleet, ports, principals
from mu_authz_lib.adapters import measure_root

_PORT = ports.MU.DIRECT_AUTHZ
_URL = f"root://{ports.MU.HOST}:{_PORT}"
_EXISTS = "/prot/exists.dat"
_GHOST = "/prot/ghost-never-created.dat"


def _port_open(p):
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect((ports.MU.HOST, p))
        return True
    except OSError:
        return False
    finally:
        s.close()


@pytest.fixture(scope="module")
def direct_authz_env():
    principals.build_cast()
    d = os.path.join(ports.MU.DATA_ROOT, "prot")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "exists.dat"), "wb") as f:
        f.write(b"S" * 4096)
    # ensure the ghost path really is absent
    ghost = os.path.join(ports.MU.DATA_ROOT, _GHOST.lstrip("/"))
    if os.path.exists(ghost):
        os.remove(ghost)
    os.makedirs(ports.MU.MU_ROOT, exist_ok=True)
    with open(ports.MU.AUTHDB, "w") as f:
        f.write("g cms / rl\n")            # only VO cms may read
    for dd in (ports.MU.CONFIG_DIR, ports.MU.LOG_DIR):
        os.makedirs(dd, exist_ok=True)

    subst = fleet._base_subst()
    subst["{AUTHDB}"] = ports.MU.AUTHDB
    src = os.path.join(fleet._CFG_SRC, "root_direct_authz_noimp.conf")
    text = open(src).read()
    for k, v in subst.items():
        text = text.replace(k, v)
    dst = os.path.join(ports.MU.CONFIG_DIR, "root_direct_authz_noimp.conf")
    with open(dst, "w") as f:
        f.write(text)

    pidf = os.path.join(ports.MU.MU_ROOT, "direct_authz.pid")
    subprocess.run([fleet.NGINX, "-c", dst, "-g", f"pid {pidf};"],
                   check=True, capture_output=True)
    deadline = time.time() + 15
    while time.time() < deadline and not _port_open(_PORT):
        time.sleep(0.2)
    if not _port_open(_PORT):
        raise TimeoutError(f"direct authz server never listened on {_PORT}")
    try:
        yield _URL
    finally:
        try:
            os.kill(int(open(pidf).read().strip()), 15)
        except (ProcessLookupError, ValueError, FileNotFoundError):
            pass


def _voms(name, vo):
    cert = os.path.join(ports.MU.PKI_DIR, "user", f"{name}_usercert.pem")
    key = os.path.join(ports.MU.PKI_DIR, "user", f"{name}_userkey.pem")
    proxy = creds.gen_voms_proxy(cert, key, f"oracle_{name}", vo)
    return SimpleNamespace(name=name, proxy=proxy, token="", s3_key="", s3_secret="")


def test_denied_principal_gets_identical_verdict_regardless_of_existence(direct_authz_env):
    """The oracle: a denied principal (VO atlas) must get the SAME denial for an existing path
    and a non-existent one — never NotFound for one and NotAuthorized for the other."""
    url = direct_authz_env
    bob = _voms("bob", "atlas")

    v_exists = measure_root(url, _EXISTS, "read", principal=bob)
    v_ghost = measure_root(url, _GHOST, "read", principal=bob)
    assert v_exists.decision == "DENY", f"denied bob must be refused the existing path: {v_exists}"
    assert v_ghost.decision == "DENY", f"denied bob must be refused the absent path: {v_ghost}"
    assert v_exists == v_ghost, (
        f"EXISTENCE ORACLE: denied bob distinguishes existing vs absent — "
        f"exists={v_exists} ghost={v_ghost} (must be identical)")
    assert v_exists.tier != "none", (
        f"denied bob's verdict must be an authz denial, not NotFound: {v_exists}")


def test_authorized_principal_sees_real_answer(direct_authz_env):
    """No regression: an authorized principal (VO cms) reads an existing file and gets NotFound
    for a genuinely absent one — the real answer, not masked."""
    url = direct_authz_env
    alice = _voms("alice", "cms")

    assert measure_root(url, _EXISTS, "read", principal=alice).decision == "ALLOW", \
        "authorized alice must read the existing file"
    v_ghost = measure_root(url, _GHOST, "read", principal=alice)
    assert v_ghost.decision == "DENY" and v_ghost.tier == "none", (
        f"authorized alice must get NotFound (tier none) for an absent path: {v_ghost}")
