"""authdb authorization granularity behind the four non-GSI auth mechanisms.

Audit gap P1-4 (docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md):
``pwd``, ``sss``, ``host`` and ``krb5`` each had tests that prove *identity* and
stop there.  Nothing anywhere drove ``brix_authdb`` behind them, so the second
gate — does the authenticated name actually restrict which paths and which
privileges the session gets? — was unproven for every mechanism except GSI
(``test_authdb.py``).

Each mechanism gets one server whose authdb carries the same rule shapes:

    u <identity>   /u-own        rl     path scope granted to this identity
    u not-this-user /u-other     rl     same path shape, a different identity
    g <vo>         /g-own        rl     VO/group scope granted to this identity
    g not-this-vo  /g-other      rl     VO/ACL denial
    u <identity>   /lookup-only  l      privilege scope: stat yes, read no
    u <identity>   /rw           rwl    write scope
                   /unlisted     -      no rule at all -> default-deny

which pins the three axes the mechanisms differ on: what lands in ``login.dn``
(pwd user / sss keytab user / reverse-DNS peer name / krb5 local name), what
lands in the VO list (pwd 4th field, sss keytab group, nothing for host/krb5),
and — for ``host`` only — the ``p`` peer-address rule type.

Unprivileged; each server is a throwaway registry-lifecycle instance.  Skips
cleanly when the native client is not built or the KDC tooling is absent.

Run (serial):
    PYTHONPATH=. python3 -m pytest test_authdb_mechanism_scope.py -p no:xdist
"""

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import kdc_helpers
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import (
    BIND_HOST,
    HOST,
    KRB5_CCACHE,
    KRB5_CONF,
    KRB5_KEYTAB,
    KRB5_SERVICE_PRINCIPAL,
    NGINX_BIN,
    TEST_ROOT,
    url_host,
)

pytestmark = [pytest.mark.serial, pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-authdb-mech")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")
XRDSSSADMIN = os.path.join(CLIENT_DIR, "bin", "xrdsssadmin-brix")

# Rule-bearing directories, plus the one deliberately absent from the authdb.
RULE_DIRS = ("u-own", "g-own", "u-other", "g-other", "lookup-only", "rw",
             "p-own", "p-other", "unlisted")
SEED = b"authdb mechanism scope\n"

PWD_USER, PWD_PW, PWD_VO = "pwduser", "s3cret-passw0rd", "pwdvo"
SSS_USER, SSS_VO = "sssuser", "sssvo"
KRB5_LOCALNAME = "alice"          # krb5_aname_to_localname(alice@REALM)


def _rules(user, vo=None, peer=None):
    """The rule battery above, bound to one mechanism's identity."""
    lines = [
        f"u {user} /u-own rl",
        "u not-this-user /u-other rl",
        f"u {user} /lookup-only l",
        f"u {user} /rw rwl",
        "g not-this-vo /g-other rl",
    ]
    if vo:
        lines.append(f"g {vo} /g-own rl")
    if peer:
        lines.append(f"p {peer} /p-own rl")
        lines.append("p 192.0.2.0/24 /p-other rl")  # net-literal-allow: TEST-NET-1 peer rule that must NOT match
    return "".join(line + "\n" for line in lines)


def _seed(root):
    for name in RULE_DIRS:
        d = root / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "seed.txt").write_bytes(SEED)


def _clean_env(extra=None):
    env = {k: v for k, v in os.environ.items()}
    for k in ("X509_USER_PROXY", "X509_CERT_DIR", "BEARER_TOKEN",
              "BEARER_TOKEN_FILE", "XrdSecSSSKT", "XRDC_PWD", "XRDC_PWD_USER",
              "KRB5CCNAME"):
        env.pop(k, None)
    if extra:
        env.update(extra)
    return env


class Mech:
    """One authenticated client bound to one mechanism's server."""

    def __init__(self, auth, url, env, has_vo=True):
        self.auth, self.url, self.env, self.has_vo = auth, url, env, has_vo

    def stat(self, path):
        return subprocess.run([XRDFS, "--auth", self.auth, self.url, "stat", path],
                              capture_output=True, text=True, env=self.env,
                              timeout=60)

    def read(self, path, out):
        return subprocess.run([XRDCP, "--auth", self.auth, "-f",
                               f"{self.url}/{path}", str(out)],
                              capture_output=True, text=True, env=self.env,
                              timeout=60)

    def write(self, src, path):
        return subprocess.run([XRDCP, "--auth", self.auth, "-f", str(src),
                               f"{self.url}/{path}"],
                              capture_output=True, text=True, env=self.env,
                              timeout=60)


@pytest.fixture(scope="module")
def harness():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    h = LifecycleHarness()
    try:
        yield h
    finally:
        h.close()


@pytest.fixture(scope="module")
def client_built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler to build the native client")
    proc = subprocess.run(
        ["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp", "xrdsssadmin-brix"],
        capture_output=True, text=True, timeout=300)
    if proc.returncode != 0 or not os.path.exists(XRDCP):
        pytest.skip(f"native build failed:\n{proc.stdout}\n{proc.stderr}")


def _start(harness, name, template, values, tmp_path, rules):
    data = tmp_path / f"{name}-data"
    data.mkdir(parents=True, exist_ok=True)
    _seed(data)
    authdb = tmp_path / f"{name}.authdb"
    authdb.write_text(rules)
    return harness.start(NginxInstanceSpec(
        name=name, template=template, protocol="root",
        template_values={"BIND_HOST": url_host(BIND_HOST), "DATA_DIR": str(data),
                         "AUTHDB": str(authdb), **values},
        reason="authdb authorization granularity per auth mechanism"))


# --------------------------------------------------------------------------
# one server per mechanism
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mech_pwd(harness, client_built, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("authdb-pwd")
    salt = bytes(range(8))
    digest = hashlib.pbkdf2_hmac("sha1", PWD_PW.encode(), salt, 10000, 24)
    pwd_file = tmp / "pwd.db"
    pwd_file.write_text(f"{PWD_USER}:{salt.hex()}:{digest.hex()}:{PWD_VO}\n")

    ep = _start(harness, "lc-authdb-pwd", "nginx_authdb_pwd.conf",
                {"PWD_FILE": str(pwd_file)}, tmp, _rules(PWD_USER, PWD_VO))
    return Mech("pwd", f"root://{url_host(HOST)}:{ep.port}",
                _clean_env({"XRDC_PWD": PWD_PW, "XRDC_PWD_USER": PWD_USER}))


@pytest.fixture(scope="module")
def mech_sss(harness, client_built, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("authdb-sss")
    keytab = str(tmp / "server.keytab")
    r = subprocess.run([XRDSSSADMIN, "-k", keytab, "add", "--id", "1",
                        "--user", SSS_USER, "--group", SSS_VO,
                        "--name", "testhost"], capture_output=True, text=True)
    assert r.returncode == 0, f"xrdsssadmin add failed: {r.stdout}{r.stderr}"

    ep = _start(harness, "lc-authdb-sss", "nginx_authdb_sss.conf",
                {"KEYTAB": keytab}, tmp, _rules(SSS_USER, SSS_VO))
    return Mech("sss", f"root://{url_host(HOST)}:{ep.port}",
                _clean_env({"XrdSecSSSKT": keytab}))


@pytest.fixture(scope="module")
def mech_host(harness, client_built, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("authdb-host")
    r = subprocess.run(["getent", "hosts", "127.0.0.1"],  # net-literal-allow: loopback reverse-DNS is the host-auth identity
                       capture_output=True, text=True, timeout=30)
    peer_name = r.stdout.split()[1] if len(r.stdout.split()) > 1 else ""
    if not peer_name:
        pytest.skip("127.0.0.1 has no reverse-DNS name on this host")  # net-literal-allow: loopback reverse-DNS skip condition

    ep = _start(harness, "lc-authdb-host", "nginx_authdb_host.conf",
                {"ALLOWLIST": f"{peer_name} localhost localhost.localdomain"},  # net-literal-allow: host-auth allowlist names under test
                tmp,
                _rules(peer_name, peer=peer_name and "127.0.0.1/32"))  # net-literal-allow: authdb p-rule for the loopback peer under test
    # host auth identifies the peer by reverse-DNS, so the client must dial the
    # loopback address the allowlist was built from.
    return Mech("host", f"root://127.0.0.1:{ep.port}",  # net-literal-allow: loopback dial required for host-auth peer match
                _clean_env(), has_vo=False)


@pytest.fixture(scope="module")
def mech_krb5(harness, client_built, tmp_path_factory):
    if not kdc_helpers.krb5_tools_available():
        pytest.skip("MIT KDC tooling not installed (install krb5-server)")
    if "libkrb5" not in subprocess.run(["ldd", XRDCP], capture_output=True,
                                       text=True).stdout:
        pytest.skip("client built without -DBRIX_HAVE_KRB5")
    if not kdc_helpers.up():
        pytest.skip("krb5 realm could not be provisioned")

    tmp = tmp_path_factory.mktemp("authdb-krb5")
    # The acceptor needs the realm profile at nginx -t time; the launcher
    # inherits this process's environment.
    os.environ["KRB5_CONFIG"] = KRB5_CONF
    try:
        ep = _start(harness, "lc-authdb-krb5", "nginx_authdb_krb5.conf",
                    {"PRINCIPAL": KRB5_SERVICE_PRINCIPAL, "KEYTAB": KRB5_KEYTAB},
                    tmp, _rules(KRB5_LOCALNAME))
        yield Mech("krb5", f"root://{url_host(HOST)}:{ep.port}",
                   _clean_env({"KRB5_CONFIG": KRB5_CONF,
                               "KRB5CCNAME": KRB5_CCACHE}),
                   has_vo=False)
    finally:
        kdc_helpers.down()


MECHS = ("pwd", "sss", "host", "krb5")


@pytest.fixture
def mech(request):
    return request.getfixturevalue(f"mech_{request.node.callspec.params['name']}")


# --------------------------------------------------------------------------
# success: the identity's own scopes are granted
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", MECHS)
def test_user_rule_grants_read(mech, tmp_path, name):
    """u <identity> /u-own rl: the authenticated name is what the rule matches."""
    out = tmp_path / "own.txt"
    r = mech.read("/u-own/seed.txt", out)
    assert r.returncode == 0, f"{name}: own-scope read denied: {r.stderr}"
    assert out.read_bytes() == SEED


@pytest.mark.parametrize("name", MECHS)
def test_group_rule_grants_read(mech, tmp_path, name):
    """g <vo> /g-own rl: the mechanism's VO list feeds the group matcher."""
    if not mech.has_vo:
        pytest.skip(f"{name} carries no VO list (login.vo_list is empty)")
    out = tmp_path / "grp.txt"
    r = mech.read("/g-own/seed.txt", out)
    assert r.returncode == 0, f"{name}: VO-scope read denied: {r.stderr}"
    assert out.read_bytes() == SEED


@pytest.mark.parametrize("name", MECHS)
def test_write_allowed_on_rw_scope(mech, tmp_path, name):
    """u <identity> /rw rwl: an UPDATE-granting rule admits the upload."""
    src = tmp_path / "up.txt"
    src.write_bytes(b"uploaded\n")
    r = mech.write(src, "/rw/up.txt")
    assert r.returncode == 0, f"{name}: rw-scope write denied: {r.stderr}"


# --------------------------------------------------------------------------
# error / security-negative: every other scope is refused
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", MECHS)
def test_other_user_rule_denies_read(mech, tmp_path, name):
    """A u-rule for a different identity must not authorize this one."""
    out = tmp_path / "other.txt"
    r = mech.read("/u-other/seed.txt", out)
    assert r.returncode != 0, f"{name}: read granted by another user's rule"
    assert not out.exists() or out.read_bytes() != SEED


@pytest.mark.parametrize("name", MECHS)
def test_other_group_rule_denies_read(mech, tmp_path, name):
    """A g-rule for a VO this identity is not in must be refused."""
    out = tmp_path / "othergrp.txt"
    r = mech.read("/g-other/seed.txt", out)
    assert r.returncode != 0, f"{name}: read granted by a foreign VO rule"
    assert not out.exists() or out.read_bytes() != SEED


@pytest.mark.parametrize("name", MECHS)
def test_unlisted_path_denied(mech, tmp_path, name):
    """No rule at all is a denial, not a fallthrough: authdb is default-deny."""
    out = tmp_path / "unlisted.txt"
    r = mech.read("/unlisted/seed.txt", out)
    assert r.returncode != 0, f"{name}: unlisted path was readable"
    assert not out.exists() or out.read_bytes() != SEED


@pytest.mark.parametrize("name", MECHS)
def test_lookup_only_rule_denies_read(mech, tmp_path, name):
    """Privilege granularity, not just path granularity: an 'l' rule authorizes
    stat (BRIX_AUTH_LOOKUP) but must refuse an open-for-read (BRIX_AUTH_READ)."""
    st = mech.stat("/lookup-only/seed.txt")
    assert st.returncode == 0, f"{name}: 'l' rule did not authorize stat: {st.stderr}"

    out = tmp_path / "lookuponly.txt"
    r = mech.read("/lookup-only/seed.txt", out)
    assert r.returncode != 0, f"{name}: 'l' rule leaked read access"
    assert not out.exists() or out.read_bytes() != SEED


@pytest.mark.parametrize("name", MECHS)
def test_write_denied_on_read_only_scope(mech, tmp_path, name):
    """The identity's own read scope must not carry UPDATE, even with
    brix_allow_write on at the server level."""
    src = tmp_path / "up2.txt"
    src.write_bytes(b"must not land\n")
    r = mech.write(src, "/u-own/up2.txt")
    assert r.returncode != 0, f"{name}: write granted by an 'rl' rule"


# --------------------------------------------------------------------------
# host mechanism only: the p (peer-address) rule type
# --------------------------------------------------------------------------

def test_host_peer_rule_grants_read(mech_host, tmp_path):
    """p <peer>/32 authorizes the host-authenticated peer by address."""
    out = tmp_path / "peer.txt"
    r = mech_host.read("/p-own/seed.txt", out)
    assert r.returncode == 0, f"peer-scope read denied: {r.stderr}"
    assert out.read_bytes() == SEED


def test_host_nonmatching_peer_rule_denied(mech_host, tmp_path):
    """A p-rule for an unrelated network must not authorize this peer."""
    out = tmp_path / "peerdeny.txt"
    r = mech_host.read("/p-other/seed.txt", out)
    assert r.returncode != 0, "read granted by a nonmatching peer rule"
    assert not out.exists() or out.read_bytes() != SEED


def test_authdb_denial_is_logged(mech_pwd, tmp_path):
    """The denial path must leave the auditable warn line (path + privs + dn),
    not fail silently — this is the only record an operator gets."""
    mech_pwd.read("/unlisted/seed.txt", tmp_path / "x.txt")
    log = Path(TEST_ROOT, "registry", "lc-authdb-pwd", "logs", "error.log")
    if not log.exists():
        pytest.skip("instance log not at the registry path")
    body = log.read_text(errors="replace")
    assert "authdb denied" in body, "no authdb denial line was logged"
    assert f'dn="{PWD_USER}"' in body, "denial line does not name the identity"
