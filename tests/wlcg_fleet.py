"""WlcgInstance — a self-contained nginx serving davs:// with a custom CA dir.

Used by the WLCG x509 conformance e2e tests.  Each instance renders its own
nginx.conf, points brix_webdav_cadir at a scenario's hashed CA directory, and
sets brix_webdav_signing_policy / brix_webdav_crl_mode as the test requires.

The davs:// surface is what these tests drive: nginx requests the TLS client
certificate (ssl_verify_client optional_no_ca) and brix's own auth_cert.c
verifies the chain against the CA dir via brix_gsi_verify_chain — the exact code
path where signing_policy and CRL enforcement live.  The client uses `curl -k`
so the throwaway server certificate never matters; only the CLIENT credential
(and the server's verdict on it) is under test.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import settings

_SERVER_CERT: Path | None = None
_SERVER_KEY: Path | None = None


def _ensure_server_cert(base: Path) -> tuple[Path, Path]:
    """A throwaway self-signed server cert, shared across instances (curl -k)."""
    global _SERVER_CERT, _SERVER_KEY
    if _SERVER_CERT and _SERVER_CERT.exists():
        return _SERVER_CERT, _SERVER_KEY
    d = base / "_wlcg_server"
    d.mkdir(parents=True, exist_ok=True)
    cert, key = d / "server.pem", d / "server.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "3650",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)
    _SERVER_CERT, _SERVER_KEY = cert, key
    return cert, key


class WlcgInstance:
    def __init__(self, prefix, ca_dir, *, signing_policy="on", crl="",
                 crl_mode="try"):
        self.prefix = Path(prefix)
        self.ca_dir = Path(ca_dir)
        self.signing_policy = signing_policy
        self.crl = crl
        self.crl_mode = crl_mode

        self.logs = self.prefix / "logs"
        self.data = self.prefix / "data"
        self.tmp = self.prefix / "tmp"
        for d in (self.prefix, self.logs, self.data, self.tmp):
            d.mkdir(parents=True, exist_ok=True)
        self.conf = self.prefix / "nginx.conf"
        self.error_log = self.logs / "error.log"
        (self.davs_port,) = settings.free_ports(1)
        self._server_cert, self._server_key = _ensure_server_cert(
            Path(settings.TEST_ROOT))

    # -- config ------------------------------------------------------------- #
    def render(self):
        crl_line = (f"            brix_webdav_crl {self.crl};\n"
                    if self.crl else "")
        return f"""\
worker_processes 1;
daemon on;
master_process on;
error_log {self.error_log} notice;
pid {self.prefix}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {self.tmp}/client;
    proxy_temp_path {self.tmp}/proxy;
    fastcgi_temp_path {self.tmp}/fastcgi;
    uwsgi_temp_path {self.tmp}/uwsgi;
    scgi_temp_path {self.tmp}/scgi;
    server {{
        listen {self.davs_port} ssl;
        server_name localhost;
        ssl_certificate     {self._server_cert};
        ssl_certificate_key {self._server_key};
        ssl_verify_client   optional_no_ca;
        ssl_verify_depth    10;
        brix_webdav_proxy_certs on;
        location / {{
            brix_webdav          on;
            brix_storage_backend posix:{self.data};
            brix_webdav_cadir    {self.ca_dir};
            brix_webdav_signing_policy {self.signing_policy};
            brix_webdav_crl_mode {self.crl_mode};
{crl_line}            brix_webdav_auth     required;
        }}
    }}
}}
"""

    def write(self):
        self.conf.write_text(self.render())

    # -- lifecycle ---------------------------------------------------------- #
    def _nginx(self, *args, check=True):
        return subprocess.run(
            [settings.NGINX_BIN, "-p", str(self.prefix), "-c", str(self.conf),
             *args],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            check=check)

    def configtest(self):
        self.write()
        return self._nginx("-t", check=False)

    def start(self):
        self.write()
        self._nginx()               # daemonizes
        self._wait_listening()
        return self

    def reload(self):
        self.write()
        self._nginx("-s", "reload")
        time.sleep(0.5)             # let workers pick up the new store

    def stop(self):
        pidfile = self.prefix / "nginx.pid"
        try:
            pid = int(pidfile.read_text().strip())
            os.kill(pid, signal.SIGQUIT)
        except (FileNotFoundError, ValueError, ProcessLookupError):
            self._nginx("-s", "quit", check=False)
        for _ in range(50):
            if not pidfile.exists():
                break
            time.sleep(0.1)

    def _wait_listening(self, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = subprocess.run(
                ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "2", f"https://127.0.0.1:{self.davs_port}/"],
                capture_output=True, text=True)
            if r.stdout.strip():
                return
            time.sleep(0.2)
        raise RuntimeError(f"davs port {self.davs_port} never came up")

    # -- client ------------------------------------------------------------- #
    def attempt_davs(self, cred_pem):
        """PROPFIND with a client cert.  Returns (accepted, http_status).

        accepted is True when the server admitted the credential (any non-auth
        status), False when it rejected the certificate (401/403 auth failure).
        """
        r = subprocess.run(
            ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "10",
             "--cert", str(cred_pem), "--key", str(cred_pem),
             "-X", "PROPFIND", "-H", "Depth: 0",
             f"https://127.0.0.1:{self.davs_port}/"],
            capture_output=True, text=True)
        code = r.stdout.strip() or "000"
        accepted = code not in ("401", "403", "000", "495", "496")
        return accepted, code
