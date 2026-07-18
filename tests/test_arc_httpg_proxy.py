"""
httpg reverse proxy with TRUE per-user credential delegation, in front of a
real NorduGrid ARC-CE 7 (arc-ce-image).

"httpg" here is the modern WLCG sense: HTTPS whose TLS client authentication
is an RFC 3820 proxy-certificate chain (voms-proxy-init / arcproxy output).
Stock nginx cannot terminate it — OpenSSL rejects proxy chains unless
X509_V_FLAG_ALLOW_PROXY_CERTS is set, so every proxy-authenticated request
dies with 400 "proxy certificates not allowed" even under
`ssl_verify_client optional_no_ca`.  This module's `brix_webdav_proxy_certs on`
sets that flag on the listener's SSL_CTX.

Unlike a static-credential lab, NO user credential appears in the nginx
config.  Each user first DELEGATES a short-lived proxy to the gateway through
the brix delegation endpoint (`brix_delegation_endpoint on`, proxy-upload
form: an EEC-authenticated PUT whose body is the user's own proxy; the chain
is PKIX-verified against the grid CA and DN-matched before being stored in
`brix_storage_credential_dir` as x5h-<sha256(DN)[:32]>.pem).  The back leg
then resolves the delegated credential of the *verified front-leg identity*
via `proxy_ssl_certificate $brix_delegated_cred` (the variable re-derives
the storage key from the chain's end-entity DN at request time — no map
block, no per-user config) — so the ARC-CE authenticates every forwarded
request as the real submitting user.  All trust (front-leg client verify,
delegation-chain verify, back-leg server verify) comes from ONE hashed CA
directory via brix_client_certificate_folder / brix_ssl_client_capath /
brix_webdav_cadir / brix_proxy_ssl_capath — no bundle file anywhere.
The front leg FAILS CLOSED (`ssl_verify_client on`): a client presenting no
certificate, or one that does not chain to the grid CA, is refused by nginx
itself and never proxied; an authenticated identity that never delegated
reaches ARC with no credential and fails there, with ARC's answer relayed
back to the client.

The suite drives two grid users (alice, bob) end-to-end through nginx:

    delegate  (PUT /.well-known/brix-delegation, per user)
    arcsub    (-C https://localhost:<front>/arex -T arcrest -Q NONE)
    arcstat   (asserts Owner: = each user's own DN; -v output shown with -s)
    arcget    (retrieve session dir, assert job stdout)

plus per-user isolation at the ARC-CE (bob cannot read alice's session),
fail-closed anonymous rejection at nginx (400, never proxied), a guard
bounce (junk path -> 444 + audit line, even when authenticated), and
front-leg security negatives (untrusted CA cert -> 400; proxy-authenticated
delegation upload -> 403 strict-DN refusal).

Requirements (each missing one skips the module):
  * docker with the image nordugrid/arc-ce-image:rocky9-arc7-atlas pulled
  * nordugrid-arc7-client on the host (arcproxy/arcsub/arcstat/arcget)
  * the brix nginx build (NGINX_BIN, default /tmp/nginx-1.28.3/objs/nginx)

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_arc_httpg_proxy.py -v -s -p no:xdist
"""

import glob
import hashlib
import os
import re
import shutil
import ssl
import subprocess
import tarfile
import time
import http.client

import pytest

from guard_http_lib import NGINX_BIN, AuditLog, free_port
from config_templates import render_config

pytestmark = [pytest.mark.slow, pytest.mark.serial,
              pytest.mark.timeout(600)]

ARC_IMAGE = "nordugrid/arc-ce-image:rocky9-arc7-atlas"
ARC_USERS = ("alice", "bob")
JOB_XRSL = """\
&(executable="/bin/sh")
 (arguments="-c" "echo hello-from-arc; id -un")
 (stdout="stdout.txt")
 (stderr="stderr.txt")
 (jobname="brix-deleg-test")
 (queue="fork")
"""


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _require_tools():
    for tool in ("docker", "arcproxy", "arcsub", "arcstat", "arcget"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} not found on PATH")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if _run(["docker", "image", "inspect", ARC_IMAGE]).returncode != 0:
        pytest.skip(f"ARC image missing: docker pull {ARC_IMAGE}")


def _cred_key(dn):
    """brix_sd_ucred_key hash form for a GSI DN (ucred.c)."""
    return "x5h-" + hashlib.sha256(dn.encode()).hexdigest()[:32]


def _https(port, cert=None, key=None):
    ctx = ssl._create_unverified_context()
    if cert is not None:
        ctx.load_cert_chain(str(cert), str(key) if key else None)
    return http.client.HTTPSConnection("127.0.0.1", port, timeout=15,
                                       context=ctx)


def _wait_tls(port, tries=100):
    for _ in range(tries):
        try:
            conn = _https(port)
            conn.request("GET", "/arex/rest/1.0/info")
            conn.getresponse().read()
            conn.close()
            return
        except Exception:
            time.sleep(0.5)
    pytest.fail(f"TLS endpoint on 127.0.0.1:{port} never became ready")


@pytest.fixture(scope="module")
def arc_ce(tmp_path_factory):
    """Real ARC-CE 7 in a container: fresh test CA, one usercert per test
    user, A-REX + WS(REST) interface up on 127.0.0.1:<port>; host cert and
    user tarballs copied out."""
    _require_tools()
    root = tmp_path_factory.mktemp("arc_httpg")
    name = f"brix-arc-httpg-{os.getpid()}"
    port = free_port()

    _run(["docker", "rm", "-f", name])
    rc = _run(["docker", "run", "-d", "--name", name, "--hostname",
               "localhost", "-p", f"127.0.0.1:{port}:443",
               ARC_IMAGE, "sleep", "infinity"])
    if rc.returncode != 0:
        pytest.skip(f"docker run failed: {rc.stderr.strip()}")
    try:
        # The baked-in test-CA certs are expired; regenerate, then start
        # A-REX and its WS (REST) interface the way the image's systemd
        # units would.
        usercerts = " && ".join(
            f"arcctl test-ca usercert -t -n {u} -f" for u in ARC_USERS)
        rc = _run(["docker", "exec", name, "bash", "-c",
                   f"arcctl test-ca init -f && arcctl test-ca hostcert -f"
                   f" && {usercerts}"])
        assert rc.returncode == 0, f"test-ca setup failed: {rc.stderr}"
        rc = _run(["docker", "exec", name, "bash", "-c",
                   "/usr/share/arc/arc-arex-start && sleep 2 && "
                   "/usr/share/arc/arc-arex-ws-start"])
        assert rc.returncode == 0, f"arex startup failed: {rc.stderr}"

        outs = [(":/etc/grid-security/testCA-hostcert.pem", "hostcert.pem"),
                (":/etc/grid-security/testCA-hostkey.pem", "hostkey.pem")]
        outs += [(f":/usercert-{u}.tar.gz", f"{u}.tar.gz") for u in ARC_USERS]
        for src, dst in outs:
            rc = _run(["docker", "cp", name + src, str(root / dst)])
            assert rc.returncode == 0, f"docker cp {src} failed: {rc.stderr}"

        _wait_tls(port)
        yield {"root": root, "port": port, "name": name}
    finally:
        _run(["docker", "rm", "-f", name])


@pytest.fixture(scope="module")
def grid_users(arc_ce):
    """Per-user test-CA credentials and a live RFC 3820 proxy for each."""
    root = arc_ce["root"]
    users = {}
    for u in ARC_USERS:
        udir = root / u
        udir.mkdir()
        with tarfile.open(root / f"{u}.tar.gz") as tar:
            tar.extractall(udir)
        cred = udir / "arc-testca-usercert"
        env = dict(os.environ,
                   X509_USER_CERT=str(cred / "usercert.pem"),
                   X509_USER_KEY=str(cred / "userkey.pem"),
                   X509_USER_PROXY=str(cred / "userproxy.pem"),
                   X509_CERT_DIR=str(cred / "certificates"))
        rc = _run(["arcproxy"], env=env)
        assert rc.returncode == 0, f"arcproxy({u}): {rc.stdout}{rc.stderr}"
        dn = f"/DC=org/DC=nordugrid/DC=ARC/O=TestCA/CN={u}"
        users[u] = {"env": env, "dn": dn, "key": _cred_key(dn),
                    "eec_cert": cred / "usercert.pem",
                    "eec_key": cred / "userkey.pem",
                    "proxy": cred / "userproxy.pem",
                    "ca_dir": cred / "certificates"}
    ca_dir = users[ARC_USERS[0]]["ca_dir"]
    ca_pem = glob.glob(str(ca_dir / "ARC-TestCA-*.pem"))
    assert ca_pem, "test-CA certificate missing from user tarball"
    return {"users": users, "ca": ca_pem[0], "ca_dir": ca_dir}


@pytest.fixture(scope="module")
def front(arc_ce, grid_users, tmp_path_factory):
    """brix nginx terminating httpg: delegation endpoint + guard + per-user
    delegated-credential selection on the ARC back leg."""
    base = tmp_path_factory.mktemp("arc_front")
    for sub in ("tmp", "export", "creds"):
        (base / sub).mkdir()
    port = free_port()
    audit = base / "guard-audit.log"
    conf = base / "nginx.conf"
    conf.write_text(render_config("nginx_arc_httpg_proxy.conf",
                                  BASE_DIR=base,
                                  FRONT_PORT=port,
                                  BACKEND_PORT=arc_ce["port"],
                                  HOST_CERT=arc_ce["root"] / "hostcert.pem",
                                  HOST_KEY=arc_ce["root"] / "hostkey.pem",
                                  CA_DIR=grid_users["ca_dir"],
                                  CRED_DIR=base / "creds",
                                  AUDIT_LOG=audit))
    rc = _run([NGINX_BIN, "-t", "-c", str(conf)])
    assert rc.returncode == 0, f"nginx -t failed: {rc.stderr}"
    rc = _run([NGINX_BIN, "-c", str(conf)])
    assert rc.returncode == 0, f"nginx start failed: {rc.stderr}"
    try:
        _wait_tls(port)
        yield {"port": port, "audit": AuditLog(str(audit)),
               "creds": base / "creds"}
    finally:
        _run([NGINX_BIN, "-c", str(conf), "-s", "stop"])


def _delegate(front, user, cert, key):
    conn = _https(front["port"], cert, key)
    conn.request("PUT", "/.well-known/brix-delegation",
                 body=user["proxy"].read_bytes())
    resp = conn.getresponse()
    body = resp.read().decode(errors="replace")
    conn.close()
    return resp.status, body


@pytest.fixture(scope="module")
def delegated(front, grid_users):
    """Each user deposits their proxy at the gateway (EEC-authenticated)."""
    for name, u in grid_users["users"].items():
        status, body = _delegate(front, u, u["eec_cert"], u["eec_key"])
        assert status == 201, f"delegation({name}) -> {status}: {body}"
        stored = front["creds"] / (u["key"] + ".pem")
        assert stored.is_file(), f"no stored credential for {name}"
        assert "PRIVATE KEY" in stored.read_text(), \
            f"stored credential for {name} is unusable (no private key)"
    return grid_users["users"]


# Shared across the ordered tests below: jobids from the submission test.
_state = {}


def test_delegated_submit_stat_get_per_user(front, delegated, tmp_path):
    """Both users submit through the front; ARC sees each job owned by the
    submitting user's own DN (the delegated credential, not a shared one).
    alice's job is run to completion and retrieved with arcget."""
    xrsl = tmp_path / "hello.xrsl"
    xrsl.write_text(JOB_XRSL)
    ce = f"https://localhost:{front['port']}/arex"

    for name, u in delegated.items():
        jobs = tmp_path / f"{name}-jobs.dat"
        rc = _run(["arcsub", "-j", str(jobs), "-C", ce, "-T", "arcrest",
                   "-Q", "NONE", str(xrsl)], env=u["env"], timeout=120)
        assert rc.returncode == 0, f"arcsub({name}): {rc.stdout}{rc.stderr}"
        m = re.search(r"jobid:\s*(\S+)", rc.stdout)
        assert m, f"no jobid in arcsub output: {rc.stdout}"
        jobid = m.group(1)
        assert f":{front['port']}/arex/rest" in jobid, \
            f"job ID does not route through the nginx front: {jobid}"
        _state[name] = {"jobid": jobid, "jobs": jobs}

    for name, u in delegated.items():
        stat_out = ""
        deadline = time.time() + 180
        while time.time() < deadline:
            rc = _run(["arcstat", "-j", str(_state[name]["jobs"]), "-a"],
                      env=u["env"], timeout=60)
            stat_out = rc.stdout
            if "Finished" in stat_out:
                break
            time.sleep(5)
        assert "State: Finished" in stat_out, \
            f"{name}'s job never finished: {stat_out}"
        assert "Exit Code: 0" in stat_out

        rc_l = _run(["arcstat", "-j", str(_state[name]["jobs"]), "-a", "-l"],
                    env=u["env"], timeout=60)
        print(f"\n=== arcstat ({name}) ===\n{stat_out}"
              f"\n=== arcstat -l ({name}) ===\n{rc_l.stdout}")
        # THE point of the delegation lab: the job's Owner at the ARC-CE is
        # the submitting user's own identity.
        assert f"Owner: {u['dn']}" in rc_l.stdout, \
            f"{name}'s job not owned by {name}: {rc_l.stdout}"
        assert f":{front['port']}/arex" in rc_l.stdout

    u = delegated["alice"]
    fetched = tmp_path / "fetched"
    rc = _run(["arcget", "-j", str(_state["alice"]["jobs"]), "-a",
               "-D", str(fetched), "-k"], env=u["env"], timeout=120)
    assert rc.returncode == 0, f"arcget failed: {rc.stdout}{rc.stderr}"
    outs = glob.glob(str(fetched / "*" / "stdout.txt"))
    assert outs, f"no stdout.txt retrieved: {rc.stdout}"
    stdout_txt = open(outs[0]).read()
    assert "hello-from-arc" in stdout_txt, stdout_txt


def test_cross_user_isolation_at_arc(front, delegated):
    """bob's delegated identity cannot read alice's session directory: the
    ARC-CE — not nginx — enforces per-user ownership, which is only possible
    because each request reaches it under the real user's credential."""
    if "alice" not in _state:
        pytest.skip("no alice job from the submission test")
    path = (_state["alice"]["jobid"].split(str(front["port"]), 1)[1]
            + "/session/stdout.txt")

    statuses = {}
    for name in ("alice", "bob"):
        u = delegated[name]
        conn = _https(front["port"], u["proxy"])
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        statuses[name] = resp.status
        conn.close()
    assert statuses["alice"] == 200, statuses
    assert statuses["bob"] == 404, \
        f"bob can reach alice's session: {statuses}"


def test_anonymous_rejected_at_nginx(front, delegated):
    """Fail-closed: with `ssl_verify_client on` a client that presents no
    certificate is rejected by nginx itself (400) — the request is never
    proxied, so no identity can leak to the ARC-CE."""
    conn = _https(front["port"])
    conn.request("GET", "/arex/rest/1.0/jobs")
    resp = conn.getresponse()
    body = resp.read().decode(errors="replace")
    conn.close()
    assert resp.status == 400, \
        f"anonymous request not refused at nginx: {resp.status} {body[:200]}"
    assert "nginx" in body, "rejection did not come from the front proxy"


def test_proxy_authenticated_delegation_rejected(front, grid_users):
    """Security negative: the delegation endpoint's strict DN match refuses
    an upload authenticated with the proxy itself (leaf DN has the extra
    /CN=<n> level) — delegation requires possession of the EEC."""
    u = grid_users["users"]["alice"]
    status, _ = _delegate(front, u, u["proxy"], None)
    assert status == 403, f"proxy-authenticated upload -> {status}"


def test_junk_path_bounced_before_backend(front, grid_users):
    """Guard drops scanner junk with 444 (connection close, no HTTP
    response) and writes a signature audit line.  The probe authenticates
    as a valid grid user: under fail-closed TLS an anonymous probe would
    already have died at the 400 certificate check, so this proves the
    guard bounces junk even from an authenticated identity."""
    u = grid_users["users"]["alice"]
    conn = _https(front["port"], u["proxy"], u["proxy"])
    with pytest.raises((http.client.BadStatusLine, ConnectionError, OSError)):
        conn.request("GET", "/wp-login.php")
        conn.getresponse()
    conn.close()

    hits = []
    for _ in range(50):   # LOG-phase write races the closed connection
        hits = [ln for ln in front["audit"].lines()
                if '/wp-login.php' in ln]
        if hits:
            break
        time.sleep(0.1)
    assert hits, "no audit line for the bounced junk path"
    assert "signal=signature" in hits[-1] and "status=444" in hits[-1]


def test_untrusted_client_cert_rejected(front, tmp_path):
    """Security negative: a client certificate that does not chain to the
    grid CA fails front-leg verification — nginx answers 400 itself and the
    request is never proxied to the ARC-CE."""
    cert = tmp_path / "bogus-cert.pem"
    key = tmp_path / "bogus-key.pem"
    rc = _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
               "-keyout", str(key), "-out", str(cert), "-days", "1",
               "-subj", "/DC=org/DC=evil/CN=mallory"])
    assert rc.returncode == 0, rc.stderr

    conn = _https(front["port"], cert, key)
    conn.request("GET", "/arex/rest/1.0/jobs")
    resp = conn.getresponse()
    body = resp.read().decode(errors="replace")
    conn.close()

    assert resp.status == 400, f"expected 400, got {resp.status}: {body}"
    assert "nginx" in body    # nginx's own error page, not an ARC response
