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

import subprocess
import time
from pathlib import Path

import settings
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

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
    """A davs:// x509-conformance server, driven through the registry harness.

    Each instance renders the committed ``nginx_wlcg_conformance.conf`` template
    (shared with :class:`wlcg_conformance_fleet.ConformanceFleet`) via its own
    ``LifecycleHarness`` — no nginx config is hand-rolled and no nginx process is
    launched directly.  The port is registry-allocated and exposed as
    ``davs_port`` for :meth:`attempt_davs`; ``reload()`` re-signals the same
    instance so a hot change to the on-disk CA/CRL material takes effect without
    a config-text change, exactly as the old ``-s reload`` path did.
    """

    _SEQ = 0

    def __init__(self, prefix, ca_dir=None, *, cafile=None, signing_policy="on",
                 crl="", crl_mode="try"):
        self.prefix = Path(prefix)
        self.data = self.prefix / "data"
        self.data.mkdir(parents=True, exist_ok=True)
        cert, key = _ensure_server_cert(Path(settings.TEST_ROOT))

        # Whole-line trust/CRL injections, matching the template's {CA_LINE} /
        # {CRL_LINE} seams (12-space indent + trailing newline baked in).
        if cafile is not None:
            ca_line = f"            brix_webdav_cafile   {Path(cafile)};\n"
        else:
            ca_line = f"            brix_webdav_cadir    {Path(ca_dir)};\n"
        crl_line = f"            brix_webdav_crl {crl};\n" if crl else ""

        WlcgInstance._SEQ += 1
        self._name = f"lc-wlcginst-{WlcgInstance._SEQ}"
        self._spec = NginxInstanceSpec(
            name=self._name,
            template="nginx_wlcg_conformance.conf",
            protocol="https",
            readiness="tcp",
            data_root=str(self.data),
            template_values={
                "CERT": str(cert),
                "KEY": str(key),
                "CA_LINE": ca_line,
                "CRL_LINE": crl_line,
                "SIGNING_POLICY": signing_policy,
                "CRL_MODE": crl_mode,
            },
        )
        # Register up front so the port is reserved (for davs_port / attempt_davs)
        # and configtest() can render + `nginx -t` without ever starting.
        self._harness = LifecycleHarness()
        self._registered = self._harness.register(self._spec)
        self.davs_port = self._harness.endpoint(self._name).port

    # -- lifecycle ---------------------------------------------------------- #
    def configtest(self):
        """Render the config and run ``nginx -t`` WITHOUT starting.

        Returns a CompletedProcess whose ``stdout`` carries the combined
        stdout+stderr (nginx writes its ``[emerg]`` diagnostic to stderr; the
        old merged-stream ``_nginx`` put it on stdout, and callers assert on
        ``.stdout``)."""
        self._harness.launcher.render_nginx(self._registered)
        result = self._harness.nginx_test(self._name, check=False)
        return subprocess.CompletedProcess(
            result.args, result.returncode,
            stdout=(result.stdout or "") + (result.stderr or ""),
            stderr=result.stderr)

    def start(self):
        self._harness.start_registered(self._name)   # render + nginx -t + launch
        self._wait_listening()
        return self

    def reload(self):
        self._harness.reload(self._name)

    def stop(self):
        self._harness.close()                        # stop + unregister; idempotent

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
        # PROPFIND on the (existing) export root yields 2xx (207 Multi-Status)
        # exactly when the credential was admitted; any 4xx/5xx — 400 (chain
        # build failed), 401/403 (auth/policy reject), 495/496 (TLS cert
        # errors) — means the certificate was not accepted.
        accepted = code.startswith("2")
        return accepted, code
