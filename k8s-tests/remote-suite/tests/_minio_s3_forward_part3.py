# --------------------------------------------------------------------------
# P80.3 — per-user backend credentials for WRITES + metadata (sd_remote).
# staged_open_cred/stat_cred/unlink_cred registration means an authenticated
# principal's <user>.s3 file signs the staged upload (and its noreplace HEAD),
# never the shared static credential. pwd auth supplies a cheap local
# authenticated principal (identity DN = username → cred key = username).
# --------------------------------------------------------------------------

REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

PWD_ALICE = "alice"
PWD_BOB = "bob"
PWD_PASSWORD = "s3cret-pw"


def _pwd_db_line(user, password):
    salt = os.urandom(8)
    h = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 10000, 24)
    return f"{user}:{salt.hex()}:{h.hex()}"


def _pwd_ucred_conf(pwd_file, cred_dir):
    """Conf factory: pwd-authenticated root:// front whose STATIC credential
    is deliberately wrong — only the per-user cred dir can sign correctly."""
    def conf(port, minio_port, root, logs, secret_key):
        return f"""
daemon on;
error_log {logs}/error.log info;
pid {logs}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    brix_credential minio {{
        s3_access_key {MINIO_AK};
        s3_secret_key {secret_key};
        s3_region {REGION};
    }}
    server {{
        listen 127.0.0.1:{port};
        brix_root on;
        brix_auth pwd;
        brix_pwd_file {pwd_file};
        brix_allow_write on;
        brix_upload_resume off;
        brix_export {root};
        brix_storage_backend s3://127.0.0.1:{minio_port}/{BUCKET};
        brix_storage_credential minio;
        brix_storage_credential_dir {cred_dir};
        brix_storage_credential_fallback deny;
    }}
}}
"""
    return conf


def _xrdcp_pwd(user, src, dst, timeout=60):
    env = {**os.environ,
           "XRDC_PWD": PWD_PASSWORD,
           "XRDC_PWD_USER": user,
           "XRD_CONNECTIONRETRY": "1",
           "XRD_REQUESTTIMEOUT": "30",
           "XRD_STREAMTIMEOUT": "30"}
    env.pop("XrdSecCREDS", None)
    return subprocess.run([NATIVE_XRDCP, "--auth", "pwd", "-f", src, dst],
                          capture_output=True, text=True,
                          timeout=timeout, env=env)


def _prepare_user_credentials():
    aux = tempfile.mkdtemp(prefix="minio_fwd_ucred_aux.")
    pwd_file = os.path.join(aux, "pwd.db")
    with open(pwd_file, "w") as f:
        f.write(_pwd_db_line(PWD_ALICE, PWD_PASSWORD) + "\n")
        f.write(_pwd_db_line(PWD_BOB, PWD_PASSWORD) + "\n")
    cred_dir = os.path.join(aux, "creds")
    os.makedirs(cred_dir, exist_ok=True)
    alice_cred = os.path.join(cred_dir, f"{PWD_ALICE}.s3")
    with open(alice_cred, "w") as f:
        f.write(f"{MINIO_AK}\n{MINIO_SK}\n{REGION}\n")
    os.chmod(alice_cred, 0o600)
    return aux, pwd_file, cred_dir


def _require_user_credential_lane():
    if REMOTE_MODE:
        pytest.skip("per-user cred lane is launched locally only")
    if not os.access(NATIVE_XRDCP, os.X_OK):
        pytest.skip("native xrdcp (client/bin/xrdcp) not available")


def _start_user_credential_node(minio, aux, pwd_file, cred_dir):
    (port,) = free_ports(1)
    base, result = _start_nginx(
        port, minio["port"], WRONG_SECRET, "ucred",
        conf_fn=_pwd_ucred_conf(pwd_file, cred_dir),
    )
    if result.returncode != 0:
        _stop_nginx(base)
        shutil.rmtree(aux, ignore_errors=True)
        pytest.fail(f"[brix-machinery] nginx rejected the per-user-cred "
                    f"config: {result.stderr[-500:]}")
    if not _wait_port("127.0.0.1", port):
        error = _tail(os.path.join(base, "logs", "error.log"))
        _stop_nginx(base)
        shutil.rmtree(aux, ignore_errors=True)
        pytest.fail(f"[brix-machinery] per-user-cred node never listened: "
                    f"{error}")
    return base, port


@pytest.fixture(scope="module")
def brix_ucred(minio):
    """pwd-auth root:// front: wrong static secret, per-user cred dir with
    alice.s3 = the real MinIO keys, no bob.s3, fallback deny."""
    _require_user_credential_lane()
    aux, pwd_file, cred_dir = _prepare_user_credentials()
    base, port = _start_user_credential_node(minio, aux, pwd_file, cred_dir)
    yield {"host": "127.0.0.1", "port": port, "base": base}
    _stop_nginx(base)
    shutil.rmtree(aux, ignore_errors=True)


class TestPerUserWriteCredential:

    def test_alice_upload_signed_with_her_credential(self, minio, brix_ucred,
                                                     tmp_path):
        """Success: the static credential is WRONG, so the upload can only
        land if alice's per-user .s3 triple signed the staged write (and its
        noreplace probe). Byte-exact in MinIO proves staged_open_cred ran."""
        body = os.urandom(150_000)
        src = tmp_path / "alice_up.bin"
        src.write_bytes(body)
        p = _xrdcp_pwd(PWD_ALICE, str(src),
                       _root_url(brix_ucred, "alice_up.bin"))
        if p.returncode != 0:
            err = _tail(os.path.join(brix_ucred["base"], "logs", "error.log"))
            attribute_failure(f"alice per-user-cred PUT failed: "
                              f"{(p.stderr or p.stdout)[-300:]} / log: {err}")
        r = minio_request("GET", f"/{BUCKET}/alice_up.bin")
        if r.status_code != 200:
            attribute_failure(f"alice's upload absent from MinIO (direct GET "
                              f"{r.status_code}) — per-user credential did "
                              f"not sign the staged write")
        assert _sha256(r.content) == _sha256(body), \
            "[brix-machinery] alice's per-user-cred upload corrupted in MinIO"

    def test_bob_without_credential_is_refused(self, minio, brix_ucred,
                                               tmp_path):
        """Error: bob authenticates fine but has no bob.s3 and fallback is
        deny — the write must fail and nothing may reach MinIO (the wrong
        static credential must NOT be used as a fallback)."""
        src = tmp_path / "bob_up.bin"
        src.write_bytes(os.urandom(4096))
        p = _xrdcp_pwd(PWD_BOB, str(src), _root_url(brix_ucred, "bob_up.bin"))
        assert p.returncode != 0, \
            "SECURITY: bob's upload succeeded without a per-user credential " \
            "under fallback=deny"
        r = minio_request("GET", f"/{BUCKET}/bob_up.bin")
        assert r.status_code == 404, \
            f"SECURITY: bob's refused upload reached MinIO anyway " \
            f"(GET {r.status_code})"

    def test_deny_is_logged_and_secret_never_leaks(self, brix_ucred):
        """Security-negative: the refusal is an auditable deny (needle from
        vfs_cred.c) and alice's per-user secret never appears in any log."""
        log = _tail(os.path.join(brix_ucred["base"], "logs", "error.log"),
                    n=200_000)
        assert "(fallback=deny) - refusing" in log, \
            "[brix-machinery] per-user deny left no auditable log line"
        assert PWD_BOB in log, \
            "[brix-machinery] deny log does not name the refused principal"
        assert MINIO_SK not in log, \
            "SECURITY: per-user secret key leaked into error.log"
