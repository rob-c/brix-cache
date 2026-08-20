"""ConformanceFleet — the fixed server set for the 500-case x509 suite.

Instead of a server per test, we stand up one long-lived nginx per distinct
config-group in the manifest.  Every config-group server points at the SAME big
`shared/ca` directory (a realistic multi-hundred-CA grid trust store); the
credential's `group` selects which config (signing_policy / crl_mode / dir-form)
evaluates it.  Running all 500 `curl --cert` probes against ~7 pre-stood servers
takes a couple of minutes, not hours.

Lifecycle is owned by a registry ``LifecycleHarness``: each group's davs server
is a dynamically-ported ``NginxInstanceSpec`` rendered from the committed
``nginx_wlcg_conformance.conf`` template, so no nginx config is hand-rolled and
no nginx process is launched directly.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import settings
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from wlcg_fleet import _ensure_server_cert
from x509forge import GROUPS
from settings import HOST


class ConformanceFleet:
    def __init__(self, forge_root: Path):
        self.root = Path(forge_root)
        self.shared_ca = self.root / "shared" / "ca"
        self.bundle = self.root / "shared" / "bundle.pem"
        self.ports: dict[str, int] = {}
        self._harness: LifecycleHarness | None = None

    def _groups_in_manifest(self):
        manifest = json.loads((self.root / "manifest.json").read_text())
        return {r["group"] for r in manifest if r["surface"] == "davs"}

    def start(self):
        cert, key = _ensure_server_cert(Path(settings.TEST_ROOT))
        self._harness = LifecycleHarness()
        base = self.root / "servers"
        for grp in sorted(self._groups_in_manifest()):
            cfg = GROUPS[grp]
            if "cafile" in cfg:
                ca_line = f"            brix_webdav_cafile   {self.bundle};\n"
            else:
                ca_line = f"            brix_webdav_cadir    {self.shared_ca};\n"
            crl = str(self.shared_ca) if cfg.get("crl") == "ca" else ""
            crl_line = f"            brix_webdav_crl {crl};\n" if crl else ""
            endpoint = self._harness.start(NginxInstanceSpec(
                name=f"lc-wlcgconf-{grp}",
                template="nginx_wlcg_conformance.conf",
                protocol="https",
                readiness="tcp",
                data_root=str(base / grp / "data"),
                template_values={
                    "CERT": str(cert),
                    "KEY": str(key),
                    "CA_LINE": ca_line,
                    "CRL_LINE": crl_line,
                    "SIGNING_POLICY": cfg["signing_policy"],
                    "CRL_MODE": cfg["crl_mode"],
                },
            ))
            self.ports[grp] = endpoint.port

    def verdict(self, cred_name: str, group: str):
        """Present the credential to the group's server. Returns (accepted, code).
        2xx (207 PROPFIND multistatus) = admitted; any 4xx/5xx = rejected."""
        port = self.ports[group]
        cred = self.root / "creds" / cred_name
        r = subprocess.run(
            ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "10", "--cert", str(cred), "--key", str(cred),
             "-X", "PROPFIND", "-H", "Depth: 0",
             f"https://{HOST}:{port}/"],
            capture_output=True, text=True)
        code = r.stdout.strip() or "000"
        return code.startswith("2"), code

    def stop(self):
        if self._harness is not None:
            self._harness.close()
            self._harness = None
        self.ports.clear()
