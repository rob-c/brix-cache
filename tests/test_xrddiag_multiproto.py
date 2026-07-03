"""
xrddiag remote-doctor (phase-37 §15.10): multi-protocol transfer deep-dive.

`xrddiag remote-doctor <url> …` routes each URL by scheme to a per-protocol battery
that checks every stage of a transfer for that protocol:

    root[s]://  connect / handshake / TLS / login / auth / open / read / checksum / locate
    http://     connect / status / byte-ranges / Digest checksum / Content-Length
    https://    + TLS handshake + certificate
    davs://     + WebDAV class (OPTIONS DAV) + PROPFIND collection listing + TPC capability
    s3://       connect / TLS / anon-auth posture (403/404/200) / SigV4 signature acceptance
    cms://      manager connect / locate (which DS holds a path) / redirect→data-server

The HTTP-family batteries use a clean-room TLS-capable HTTP/1.1 client (lib/http.c +
lib/tls.c); S3 uses a clean-room SigV4 signer (libxrdproto HMAC-SHA256). No libcurl,
no libXrd*. PII-free: only statuses / header names / sizes / cipher — never a token,
key, signature, or response body.

Self-contained: one nginx serves the same data over root (stream), WebDAV (http +
https), and S3 (http) on free loopback ports, with a self-signed cert for TLS. cms is
exercised against the shared fleet's cluster redirector (skipped when it is down).

Run:
    PYTHONPATH=tests pytest tests/test_xrddiag_multiproto.py -v -p no:xdist
"""

import json
import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST

pytestmark = pytest.mark.timeout(120)

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")

_CLEAN_ENV = {k: v for k, v in os.environ.items()}
for _k in ("X509_USER_PROXY", "X509_CERT_DIR", "BEARER_TOKEN", "BEARER_TOKEN_FILE",
           "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
    _CLEAN_ENV.pop(_k, None)


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def servers(tmp_path_factory):
    """One nginx serving the same data over root / http / https / davs / s3."""
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    if subprocess.run(["make", "-C", CLIENT_DIR, "xrddiag"],
                      capture_output=True, text=True, timeout=180).returncode != 0 \
            or not os.path.exists(XRDDIAG):
        pytest.skip("xrddiag build failed")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if shutil.which("openssl") is None:
        pytest.skip("openssl needed to mint a self-signed cert")

    root = tmp_path_factory.mktemp("mproto")
    data = root / "data"
    data.mkdir()
    (data / "probe.txt").write_bytes(b"hello-multiproto\n")
    cert = str(root / "cert.pem")
    key = str(root / "key.pem")
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", cert, "-days", "2",
                        "-subj", "/CN=localhost"], capture_output=True)
    if r.returncode != 0:
        pytest.skip("openssl cert generation failed")

    pr, ph, ps, p3 = _free_port(), _free_port(), _free_port(), _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 256; }}
stream {{
    server {{ listen {BIND_HOST}:{pr}; xrootd on; brix_storage_backend posix:{data}; brix_auth none; }}
}}
http {{
    access_log off;
    client_body_temp_path {root}/cbt;
    proxy_temp_path {root}/pt;
    fastcgi_temp_path {root}/ft;
    uwsgi_temp_path {root}/ut;
    scgi_temp_path {root}/sct;
    server {{ listen {BIND_HOST}:{ph};
             location / {{ brix_webdav on; brix_webdav_storage_backend posix:{data}; brix_webdav_auth none; }} }}
    server {{ listen {BIND_HOST}:{ps} ssl;
             ssl_certificate {cert}; ssl_certificate_key {key};
             location / {{ brix_webdav on; brix_webdav_storage_backend posix:{data}; brix_webdav_auth none; }} }}
    server {{ listen {BIND_HOST}:{p3};
             location / {{ brix_s3 on; brix_s3_storage_backend posix:{data}; }} }}
}}
""")
    t = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)], capture_output=True, text=True)
    if t.returncode != 0:
        pytest.skip("nginx -t failed:\n" + t.stderr)
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        if _port_up(HOST, pr) and _port_up(HOST, ph) and _port_up(HOST, ps) \
                and _port_up(HOST, p3):
            break
        time.sleep(0.1)
    yield {"root": pr, "http": ph, "https": ps, "s3": p3}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def _run(*args, env=None, timeout=60):
    return subprocess.run([XRDDIAG, *args], capture_output=True, text=True,
                          env=env or _CLEAN_ENV, timeout=timeout)


def _dx(blob):
    doc = json.loads(blob)["remote_doctor"]
    ep = doc["endpoints"][0]
    return ep, {d["probe"]: d for d in ep["diagnosis"]}


# --------------------------------------------------------------------------
# root:// (regression — the libbrix battery still runs through the router)
# --------------------------------------------------------------------------

def test_root_via_router(servers):
    p = _run("remote-doctor", f"root://{HOST}:{servers['root']}//probe.txt",
             "--json", "--metrics-port", "0", "--probe-timeout", "6000")
    ep, dx = _dx(p.stdout)
    assert ep["protocol"] == "root", ep
    assert dx["read"]["verdict"] == "ok", dx


# --------------------------------------------------------------------------
# http:// + https:// (WebDAV GET stages)
# --------------------------------------------------------------------------

def test_http_stages(servers):
    p = _run("remote-doctor", f"http://{HOST}:{servers['http']}/probe.txt",
             "--json", "--probe-timeout", "6000")
    ep, dx = _dx(p.stdout)
    assert ep["protocol"] == "http", ep
    assert dx["http"]["verdict"] == "ok", dx
    assert "ranges" in dx and "checksum" in dx, dx


def test_https_tls_and_stages(servers):
    p = _run("remote-doctor", f"https://{HOST}:{servers['https']}/probe.txt",
             "--json", "--no-verify-tls", "--probe-timeout", "6000")
    ep, dx = _dx(p.stdout)
    assert ep["protocol"] == "https", ep
    assert dx["tls"]["verdict"] == "ok", dx
    assert dx["http"]["verdict"] == "ok", dx
    assert ep["facts"]["tls"].startswith("TLS"), ep["facts"]


def test_https_cert_verify_fails_self_signed(servers):
    """Without --no-verify-tls the self-signed cert must be REJECTED (a real fault
    a deployment would hit) → the tls stage is RED."""
    p = _run("remote-doctor", f"https://{HOST}:{servers['https']}/probe.txt",
             "--json", "--probe-timeout", "6000")
    ep, dx = _dx(p.stdout)
    assert ep["status"] == "RED", ep
    assert dx["tls"]["verdict"] == "fail", dx
    assert "verif" in dx["tls"]["cause"].lower(), dx["tls"]


# --------------------------------------------------------------------------
# davs:// (WebDAV class 2 + PROPFIND)
# --------------------------------------------------------------------------

def test_davs_webdav_stages(servers):
    p = _run("remote-doctor", f"davs://{HOST}:{servers['https']}/probe.txt",
             "--json", "--no-verify-tls", "--probe-timeout", "6000")
    ep, dx = _dx(p.stdout)
    assert ep["protocol"] == "davs", ep
    assert dx["tls"]["verdict"] == "ok", dx
    assert dx.get("davs-class", {}).get("verdict") == "ok", dx
    assert "davs-listing" in dx, dx


# --------------------------------------------------------------------------
# s3:// (anon posture + SigV4 signature acceptance)
# --------------------------------------------------------------------------

def test_s3_posture(servers):
    p = _run("remote-doctor", f"s3://{HOST}:{servers['s3']}/probe.txt",
             "--json", "--probe-timeout", "6000")
    ep, dx = _dx(p.stdout)
    assert ep["protocol"] == "s3", ep
    assert ep["connected"] is True, ep
    # without creds the SigV4 check is posture-only (skipped, labelled)
    assert "s3-sigv4" in dx, dx


def test_s3_sigv4_accepted(servers):
    """A clean-room SigV4-signed request must be accepted by the server (proves the
    signer's canonicalization/signing-key chain is correct)."""
    env = dict(_CLEAN_ENV)
    env["AWS_ACCESS_KEY_ID"] = "test"
    env["AWS_SECRET_ACCESS_KEY"] = "secret"
    p = _run("remote-doctor", f"s3://{HOST}:{servers['s3']}/probe.txt",
             "--json", "--probe-timeout", "6000", env=env)
    ep, dx = _dx(p.stdout)
    assert dx["s3-sigv4"]["verdict"] in ("ok", "fail"), dx   # ran (not skipped)
    assert dx["s3-sigv4"]["verdict"] == "ok", dx             # signer is correct


# --------------------------------------------------------------------------
# cms:// (cluster manager — fleet-gated)
# --------------------------------------------------------------------------

def test_cms_manager_trace():
    from settings import SERVER_HOST, CLUSTER_REDIR_PORT
    if not _port_up(SERVER_HOST, CLUSTER_REDIR_PORT):
        pytest.skip("cluster redirector not running")
    p = _run("remote-doctor", f"cms://{SERVER_HOST}:{CLUSTER_REDIR_PORT}//",
             "--json", "--metrics-port", "0", "--probe-timeout", "5000", timeout=40)
    ep, dx = _dx(p.stdout)
    assert ep["protocol"] == "cms", ep
    assert dx["cms-connect"]["verdict"] == "ok", dx
    assert "cms-locate" in dx and "cms-redirect" in dx, dx


# --------------------------------------------------------------------------
# routing, dead-hop, and PII
# --------------------------------------------------------------------------

def test_multi_protocol_one_run(servers):
    """All protocols of one host in a single invocation — each routed to its battery."""
    p = _run("remote-doctor",
             f"root://{HOST}:{servers['root']}//probe.txt",
             f"http://{HOST}:{servers['http']}/probe.txt",
             f"https://{HOST}:{servers['https']}/probe.txt",
             f"davs://{HOST}:{servers['https']}/probe.txt",
             f"s3://{HOST}:{servers['s3']}/probe.txt",
             "--json", "--no-verify-tls", "--metrics-port", "0",
             "--probe-timeout", "6000")
    doc = json.loads(p.stdout)["remote_doctor"]
    protos = [e["protocol"] for e in doc["endpoints"]]
    assert protos == ["root", "http", "https", "davs", "s3"], protos


def test_http_dead_hop(servers):
    p = _run("remote-doctor", "https://127.0.0.1:1/x",
             "--json", "--probe-timeout", "2000")
    ep, dx = _dx(p.stdout)
    assert ep["status"] == "RED", ep
    assert p.returncode != 0


def test_multiproto_pii_free(servers):
    """No token/key/signature/body leak across any protocol's diagnosis."""
    env = dict(_CLEAN_ENV)
    env["AWS_ACCESS_KEY_ID"] = "AKIAEXAMPLEKEYID"
    env["AWS_SECRET_ACCESS_KEY"] = "supersecretkeymaterial"
    for url in (f"https://{HOST}:{servers['https']}/probe.txt",
                f"s3://{HOST}:{servers['s3']}/probe.txt"):
        p = _run("remote-doctor", url, "--json", "--no-verify-tls",
                 "--probe-timeout", "6000", env=env)
        blob = p.stdout
        for leak in ("AKIAEXAMPLEKEYID", "supersecretkeymaterial", "Signature=",
                     "hello-multiproto"):
            assert leak not in blob, f"leak {leak} in {url}: {blob}"
