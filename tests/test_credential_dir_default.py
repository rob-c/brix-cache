"""brix_storage_credential_dir defaults to a tmpfs store and is self-ensuring.

Regression for the shared_conf change: when the directive is absent the store
defaults to /dev/shm/brix-creds (RAM-backed — delegated private keys never
touch real disk), the directory is created 0700 at config time, and every
unusable state is shouted at the admin via startup [warn] lines instead of
silently breaking delegation (or killing nginx).

Covers the mandated triplet:
  success           — no directive at all: nginx creates /dev/shm/brix-creds
                      mode 0700 and a real two-step delegation lands there;
  error             — an uncreatable explicit path warns "cannot create
                      credential store" but nginx -t still succeeds;
  security-negative — a pre-existing group/other-accessible store warns that
                      delegated private keys may be exposed;
plus the opt-out: an explicit "" keeps the feature off with no warning.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
      pytest tests/test_credential_dir_default.py -v -p no:xdist
"""

import os
import pathlib
import shutil
import stat

import pytest

from cmdscripts.delegation_twostep import (
    curl,
    delegation_id,
    ensure_pki,
    key_for_dn,
    mint_certs,
    sign_csr,
)
from settings import CA_CERT, NGINX_BIN, SERVER_CERT, SERVER_KEY
from server_registry import NginxInstanceSpec

DEFAULT_STORE = "/dev/shm/brix-creds"

pytestmark = pytest.mark.uses_lifecycle_harness


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    base = tmp_path_factory.mktemp("creddefpki")
    ok, message = ensure_pki(base)
    if not ok:
        pytest.skip(message)
    ok, message, dns = mint_certs(base)
    if not ok:
        pytest.skip(message)
    certs = base / "certs"
    return {
        "a_cert": certs / "a_eec_cert.pem",
        "a_key": certs / "a_eec_key.pem",
        "a_dn": dns["A_DN"],
    }


def _spec(name, cred_dir_directive, readiness="none"):
    return NginxInstanceSpec(
        name=name,
        template="nginx_lc_cred_dir_default.conf",
        protocol="webdav",
        readiness=readiness,
        template_values={
            "HOST_CERT": SERVER_CERT,
            "HOST_KEY": SERVER_KEY,
            "CA_CERT": CA_CERT,
            "CRED_DIR_DIRECTIVE": cred_dir_directive,
        },
    )


def _nginx_t(lifecycle, name, cred_dir_directive):
    """Render + nginx -t via the harness; return (exit code, combined output)."""
    reg = lifecycle.register(_spec(name, cred_dir_directive))
    lifecycle.launcher.render_nginx(reg)
    res = lifecycle.launcher.nginx_test(reg)
    return res.returncode, res.stdout + res.stderr


def test_default_store_created_and_receives_delegation(lifecycle, pki):
    """Success: no directive -> /dev/shm/brix-creds exists 0700, T4 lands in it."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if os.path.exists(DEFAULT_STORE) and not os.access(DEFAULT_STORE, os.W_OK):
        pytest.skip(f"{DEFAULT_STORE} exists and is not ours (shared host)")
    preexisting = os.path.isdir(DEFAULT_STORE)

    # no brix_storage_credential_dir line -> exercises the /dev/shm default
    ep = lifecycle.start(_spec("lc-cred-dir-default", "", readiness="webdav"))
    port, work = ep.port, pathlib.Path(ep.data_root)
    stored = None
    try:
        assert os.path.isdir(DEFAULT_STORE), \
            "default credential store was not created at config time"
        mode = stat.S_IMODE(os.stat(DEFAULT_STORE).st_mode)
        assert mode == 0o700, f"default store mode is {oct(mode)}, wanted 0700"
        # The store is handed to the RUNTIME worker identity: under a root
        # harness the always-on de-escalation drops workers to `nobody`
        # (brix_worker_user default), so the chown must target that account —
        # a root-owned 0700 store would EACCES every delegation PUT.
        if os.geteuid() == 0:
            import pwd
            expect_uid = pwd.getpwnam("nobody").pw_uid
        else:
            expect_uid = os.geteuid()
        assert os.stat(DEFAULT_STORE).st_uid == expect_uid

        # full two-step delegation with NO configured dir: the credential
        # must land in the default store — the "deployed for free" contract.
        url = f"https://127.0.0.1:{port}/.well-known/brix-delegation"
        hdrs, csr = work / "hdrs.txt", work / "csr.pem"
        code, _ = curl(url + "/request", pki["a_cert"], pki["a_key"],
                       output=csr, headers=hdrs)
        assert code == "200", f"getProxyReq rejected (code={code})"
        did = delegation_id(hdrs)
        assert did, "no X-Brix-Delegation-Id header"
        signed = work / "signed.pem"
        assert sign_csr(csr, pki["a_cert"], pki["a_key"], signed)
        body = work / "body.pem"
        body.write_bytes(signed.read_bytes() + pki["a_cert"].read_bytes())
        code, _ = curl(f"{url}/{did}", pki["a_cert"], pki["a_key"],
                       output=work / "resp.txt", upload=body)
        assert code in ("200", "201"), f"putProxy rejected (code={code})"

        stored = os.path.join(DEFAULT_STORE, key_for_dn(pki["a_dn"]) + ".pem")
        assert os.path.isfile(stored), \
            f"delegated credential not in the default store: {stored}"
        assert stat.S_IMODE(os.stat(stored).st_mode) == 0o600
    finally:
        if stored and os.path.exists(stored):
            os.unlink(stored)
        if not preexisting and os.path.isdir(DEFAULT_STORE):
            shutil.rmtree(DEFAULT_STORE, ignore_errors=True)


def test_uncreatable_dir_warns_but_is_not_fatal(lifecycle):
    """Error: mkdir cannot succeed (missing parent) -> [warn], nginx -t OK."""
    bogus = f"/dev/shm/brix-missing-{os.getpid()}/creds"
    code, out = _nginx_t(lifecycle, "lc-cred-dir-uncreatable",
                         f"brix_storage_credential_dir {bogus};")
    assert code == 0, f"a broken credential dir must not kill startup:\n{out}"
    assert "cannot create credential store" in out, \
        f"missing admin shout about uncreatable store:\n{out}"
    assert "brix_storage_credential_dir is fixed" in out


def test_lax_permissions_shouted_at_admin(lifecycle, tmp_path):
    """Security-negative: 0755 store -> exposure warning naming private keys."""
    lax = tmp_path / "lax-creds"
    lax.mkdir(mode=0o755)
    os.chmod(lax, 0o755)   # explicit: mkdir mode is umask-filtered
    code, out = _nginx_t(lifecycle, "lc-cred-dir-lax",
                         f"brix_storage_credential_dir {lax};")
    assert code == 0
    assert "group/other-accessible" in out, \
        f"missing exposure warning for lax store perms:\n{out}"
    assert "private keys may be exposed" in out


def test_explicit_empty_string_opts_out_silently(lifecycle):
    """Opt-out: `brix_storage_credential_dir "";` -> feature off, no warning."""
    code, out = _nginx_t(lifecycle, "lc-cred-dir-optout",
                         'brix_storage_credential_dir "";')
    assert code == 0, out
    assert "credential store" not in out, \
        f"opt-out must not warn about the credential store:\n{out}"
