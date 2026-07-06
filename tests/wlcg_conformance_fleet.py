"""ConformanceFleet — the fixed server set for the 500-case x509 suite.

Instead of a server per test, we stand up one long-lived nginx per distinct
config-group in the manifest.  Every config-group server points at the SAME big
`shared/ca` directory (a realistic multi-hundred-CA grid trust store); the
credential's `group` selects which config (signing_policy / crl_mode / dir-form)
evaluates it.  Running all 500 `curl --cert` probes against ~7 pre-stood servers
takes a couple of minutes, not hours.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import settings
from wlcg_fleet import _ensure_server_cert
from x509forge import GROUPS


class _Server:
    def __init__(self, prefix: Path, ca_dir: Path, *, cafile=None,
                 signing_policy="on", crl_mode="off", crl=""):
        self.prefix = Path(prefix)
        self.ca_dir = ca_dir
        self.cafile = cafile
        self.signing_policy = signing_policy
        self.crl_mode = crl_mode
        self.crl = crl
        self.logs = self.prefix / "logs"
        self.data = self.prefix / "data"
        self.tmp = self.prefix / "tmp"
        for d in (self.prefix, self.logs, self.data, self.tmp):
            d.mkdir(parents=True, exist_ok=True)
        self.conf = self.prefix / "nginx.conf"
        (self.port,) = settings.free_ports(1)
        self._cert, self._key = _ensure_server_cert(Path(settings.TEST_ROOT))

    def render(self):
        if self.cafile is not None:
            ca_line = f"            brix_webdav_cafile   {self.cafile};\n"
        else:
            ca_line = f"            brix_webdav_cadir    {self.ca_dir};\n"
        crl_line = (f"            brix_webdav_crl {self.crl};\n"
                    if self.crl else "")
        return f"""\
worker_processes 1;
daemon on;
master_process on;
error_log {self.logs}/error.log crit;
pid {self.prefix}/nginx.pid;
events {{ worker_connections 128; }}
http {{
    access_log off;
    client_body_temp_path {self.tmp}/client;
    proxy_temp_path {self.tmp}/proxy;
    fastcgi_temp_path {self.tmp}/fastcgi;
    uwsgi_temp_path {self.tmp}/uwsgi;
    scgi_temp_path {self.tmp}/scgi;
    server {{
        listen {self.port} ssl;
        server_name localhost;
        ssl_certificate     {self._cert};
        ssl_certificate_key {self._key};
        ssl_verify_client   optional_no_ca;
        ssl_verify_depth    12;
        brix_webdav_proxy_certs on;
        location / {{
            brix_webdav          on;
            brix_storage_backend posix:{self.data};
{ca_line}            brix_webdav_signing_policy {self.signing_policy};
            brix_webdav_crl_mode {self.crl_mode};
{crl_line}            brix_webdav_auth     required;
        }}
    }}
}}
"""

    def start(self):
        self.conf.write_text(self.render())
        subprocess.run([settings.NGINX_BIN, "-p", str(self.prefix),
                        "-c", str(self.conf)],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, check=True)
        self._wait()

    def _wait(self, timeout=12.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = subprocess.run(
                ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "2", f"https://127.0.0.1:{self.port}/"],
                capture_output=True, text=True)
            if r.stdout.strip() not in ("", "000"):
                return
            time.sleep(0.2)
        raise RuntimeError(f"conformance server on {self.port} never came up")

    def stop(self):
        pidfile = self.prefix / "nginx.pid"
        try:
            os.kill(int(pidfile.read_text().strip()), signal.SIGQUIT)
        except (FileNotFoundError, ValueError, ProcessLookupError):
            pass


class ConformanceFleet:
    def __init__(self, forge_root: Path):
        self.root = Path(forge_root)
        self.shared_ca = self.root / "shared" / "ca"
        self.bundle = self.root / "shared" / "bundle.pem"
        self.servers: dict[str, _Server] = {}

    def _groups_in_manifest(self):
        manifest = json.loads((self.root / "manifest.json").read_text())
        return {r["group"] for r in manifest if r["surface"] == "davs"}

    def start(self):
        base = self.root / "servers"
        for grp in sorted(self._groups_in_manifest()):
            cfg = GROUPS[grp]
            cafile = None
            ca_dir = self.shared_ca
            if "cafile" in cfg:
                cafile = self.bundle
                ca_dir = None
            crl = str(self.shared_ca) if cfg.get("crl") == "ca" else ""
            srv = _Server(base / grp, ca_dir, cafile=cafile,
                          signing_policy=cfg["signing_policy"],
                          crl_mode=cfg["crl_mode"], crl=crl)
            srv.start()
            self.servers[grp] = srv

    def verdict(self, cred_name: str, group: str):
        """Present the credential to the group's server. Returns (accepted, code).
        2xx (207 PROPFIND multistatus) = admitted; any 4xx/5xx = rejected."""
        srv = self.servers[group]
        cred = self.root / "creds" / cred_name
        r = subprocess.run(
            ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "10", "--cert", str(cred), "--key", str(cred),
             "-X", "PROPFIND", "-H", "Depth: 0",
             f"https://127.0.0.1:{srv.port}/"],
            capture_output=True, text=True)
        code = r.stdout.strip() or "000"
        return code.startswith("2"), code

    def stop(self):
        for srv in self.servers.values():
            srv.stop()
