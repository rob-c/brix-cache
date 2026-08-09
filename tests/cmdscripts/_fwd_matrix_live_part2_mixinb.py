"""Direct Python ports for the credential-forwarding matrix live shell scenarios.

Ports ``run_fwd_brix_brix.sh`` (pairing C), ``run_fwd_brix_xrootd.sh``
(pairing A), ``run_fwd_xrootd_brix.sh`` (pairing B),
``fwd_b_token_forward_probe.sh`` (the pairing-B token evidence probe), and
``run_transparent_relay.sh``.  The :class:`ForwardHarness` below is the Python
port of the shared shell library ``tests/lib/fwd_matrix.sh`` — node spawners,
PKI/token minting, per-cell scoped teardown, and the backend-identity
assertions.  Each public scenario contains its shell script's own acceptance
sequence and PASS/FAIL/GAP/UNSUPPORTED/SKIP cell verdicts.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Iterator, NamedTuple

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from lib_py.util import wait_tcp
from settings import BIND_HOST, CA_CERT, CA_DIR, CA_KEY, HOST, SERVER_CERT, SERVER_KEY
from ephemeral_port import free_ports

BRIX_XRDCP = REPO_ROOT / "client/bin/xrdcp"
BRIX_XRDFS = REPO_ROOT / "client/bin/xrdfs"
XROOTD_BIN = Path(os.environ.get("XROOTD_BIN", os.environ.get("BRIX_BIN", "/usr/bin/xrootd")))
SYS_XRDCP = shutil.which("xrdcp")

A_CN, B_CN, SVC_CN = "Fwd User A", "Fwd User B", "Fwd Service"
A_SUB, B_SUB = "fwd-user-a", "fwd-user-b"
TOK_AUD = "nginx-xrootd"


class _ForwardHarnessMixinB:
    """Python port of tests/lib/fwd_matrix.sh: topology + assertion library."""

    def spawn_xrootd_node(self, role: str, mode: str, port: int,
                          backend: str = "", cred: str = "gsi") -> Path | None:
        d = self.run.mkdir(role)
        for sub in ("data", "admin", "run", "scitok_cache"):
            (d / sub).mkdir(exist_ok=True)
        cfg, log = d / "x.cfg", d / "x.log"
        log.write_text("")
        sec_block = self._xrootd_sec_block(d, cred)
        if mode == "origin":
            cfg.write_text(f"""xrd.port {port}
xrd.network nodnr
xrd.allow host *
oss.localroot {d}/data
all.export /
all.adminpath {d}/admin
all.pidpath   {d}/run
xrd.trace off
{sec_block}
""")
        elif mode == "xrdhttp":
            # Stock XrdHttp origin over TLS with GSI client-cert auth; userA's
            # EEC DN is gridmapped to fwd-user-a (the pinned identity marker).
            a_dn = self.eec_dn(self.proxy_a) or ""
            (d / "gridmap").write_text(f'"{a_dn}" fwd-user-a\n')
            (d / "authdb").write_text("u fwd-user-a / a\n")
            (d / "data").chmod(0o777)
            cfg.write_text(f"""xrd.port {port}
xrd.protocol http:{port} libXrdHttp.so
xrd.network nodnr
xrd.allow host *
xrd.tls   {SERVER_CERT} {SERVER_KEY}
xrd.tlsca certdir {CA_DIR}
http.cadir {CA_DIR}
http.cert  {SERVER_CERT}
http.key   {SERVER_KEY}
http.secxtractor libXrdHttpVOMS.so
http.gridmap {d}/gridmap
oss.localroot {d}/data
all.export /
all.adminpath {d}/admin
all.pidpath   {d}/run
acc.authdb {d}/authdb
ofs.authorize 1
sec.protbind * none
xrd.trace off
""")
        elif mode == "pss":
            cfg.write_text(f"""all.role server
all.export /
oss.localroot {d}/data
all.adminpath {d}/admin
all.pidpath   {d}/run
xrd.port {port}
xrd.network nodnr
xrd.allow host *
xrd.trace off
ofs.osslib libXrdPss.so
pss.origin {backend}
pss.setopt DebugLevel 0
{sec_block}
""")
        else:
            raise LiveFailure(f"spawn_xrootd_node: unknown mode {mode}")

        if cred == "token":
            return log if self.spawn_bwrap_xrootd(d, cfg, log, port) else None

        # Stock xrootd refuses to run as superuser, so under the root harness drop
        # it to `nobody` and open the node tree (traverse in + write data/admin/run/
        # log). Without this the origin never binds and the brix front's backend
        # connect is refused (kXR 3012) — every gsi two-hop cell fails put_ok=0.
        xrd_runas: list[str] = []
        if os.geteuid() == 0:
            xrd_runas = ["-R", "nobody"]
            subprocess.run(["chmod", "a+rx", str(self.run.root)], check=False)
            subprocess.run(["chmod", "-R", "a+rwX", str(d)], check=False)
        _call([XROOTD_BIN, *xrd_runas, "-c", cfg, "-l", log, "-b"])
        for _ in range(20):
            pids = sorted((d / "run").glob("*.pid"))
            if pids:
                self.node_pidfiles.append(pids[0])
                break
            time.sleep(0.2)
        self.last_log = log
        time.sleep(0.8)
        return log

    # -- assertions ---------------------------------------------------------
    @staticmethod
    def assert_backend_identity(kind: str, log: Path | None, expect: str) -> bool:
        if log is None or not log.is_file():
            return False
        text = log.read_text(errors="replace")
        # brix_sanitize_log_string writes spaces as literal \x20.
        alt = f"({re.escape(expect)}|{re.escape(expect.replace(' ', chr(92) + 'x20'))})"
        if kind == "stock":
            for line in text.splitlines():
                if "login as " in line and re.search(f"CN={alt}", line):
                    return True
            return re.search(rf"login as {alt}( |$)", text, re.M) is not None
        if kind == "brix":
            if re.search(rf"GSI auth OK ([^ ]* )?dn=.*{alt}", text):
                return True
            return re.search(rf'valid token sub="?{re.escape(expect)}"?', text) is not None
        return False

    @staticmethod
    def assert_denied(proto: str, result: FrontResult) -> bool:
        if proto == "https":
            return result.deny_obs in ("403", "404")
        if proto == "root":
            return not result.put_ok
        return False

    # -- front-leg client drivers -------------------------------------------
    def gsi_env(self, proxy: Path) -> dict[str, str]:
        return {"X509_USER_PROXY": str(proxy), "X509_CERT_DIR": CA_DIR,
                "XrdSecGSICADIR": CA_DIR, "XrdSecGSICRLCHECK": "0"}

    def token_env(self, jwt: Path) -> dict[str, str]:
        return {"BEARER_TOKEN": jwt.read_text().strip(),
                "X509_USER_PROXY": "/dev/null", "XrdSecPROTOCOL": "ztn"}

    def front_put_get(self, hop1: str, cred: str, port: int, obj: str, who: str) -> FrontResult:
        payload = self.prefix / f"payload_{who}.bin"
        back = self.prefix / f"back_{who}.bin"
        payload.write_bytes(os.urandom(65536))
        back.unlink(missing_ok=True)
        put_ok, deny_obs = False, ""
        if hop1 == "root":
            url = f"root://{HOST}:{port}/{obj}"
            if cred == "gsi":
                env = self.gsi_env(self.proxy_a if who == "A" else self.proxy_b)
            else:
                env = self.token_env(self.token_a if who == "A" else self.token_b)
            put = _call([BRIX_XRDCP, "-f", payload, url], env_add=env, timeout=60)
            put_ok = put.returncode == 0
            if not put_ok:
                deny_obs = "1"
            _call([BRIX_XRDCP, "-f", url, back], env_add=env, timeout=60)
        else:
            url = f"https://{HOST}:{port}/{obj}"
            if cred == "gsi":
                px = self.proxy_a if who == "A" else self.proxy_b
                auth = ["--cert", str(px), "--key", str(px)]
            else:
                jwt = self.token_a if who == "A" else self.token_b
                auth = ["-H", f"Authorization: Bearer {jwt.read_text().strip()}"]
            code = _curl_code(*auth, "-T", str(payload), url)
            if code in ("200", "201", "204"):
                put_ok = True
            else:
                deny_obs = code
            _call(["curl", "-sk", *auth, "-o", back, url], timeout=60)
        get_ok = put_ok and back.is_file() and back.read_bytes() == payload.read_bytes()
        return FrontResult(put_ok, get_ok, deny_obs)

    def install_gsi_cred(self, cred_dir: Path, front_log: Path, hop1: str, port: int) -> None:
        """Learn the front's derived credential stem via a probe, install A's proxy."""
        if hop1 == "root":
            _call([BRIX_XRDCP, "-f", "/dev/null", f"root://{HOST}:{port}//_probe_key.bin"],
                  env_add=self.gsi_env(self.proxy_a), timeout=30)
        else:
            _call(["curl", "-sk", "--cert", str(self.proxy_a), "--key", str(self.proxy_a),
                   "-o", os.devnull, "-T", str(self.proxy_a),
                   f"https://{HOST}:{port}/_probe_key.bin"], timeout=30)
        time.sleep(0.3)
        stem = ""
        if front_log.is_file():
            match = re.search(r"key=(x5h-[0-9a-f]+|[A-Za-z0-9@._-]+)",
                              front_log.read_text(errors="replace"))
            if match:
                stem = match.group(1)
        if not stem:
            proc = _call(["openssl", "x509", "-in", self.proxy_a, "-noout", "-subject"])
            dn = proc.stdout.strip().removeprefix("subject=").strip()
            stem = "x5h-" + hashlib.sha256(dn.encode()).hexdigest()[:32]
        target = cred_dir / f"{stem}.pem"
        shutil.copy(self.proxy_a, target)
        target.chmod(0o644)

    # -- wire/feasibility decoding -------------------------------------------
    @staticmethod
    def hop1(wire: str) -> str:
        return "root" if wire in ("RR", "RH") else "https"

    @staticmethod
    def hop2(wire: str) -> str:
        return "root" if wire in ("RR", "HR") else "https"

    def feasibility_probe(self, pairing: str, hop2: str, cred: str) -> tuple[str, str]:
        have_xrootd = os.access(XROOTD_BIN, os.X_OK)
        have_xrdhttp = Path("/usr/lib64/libXrdHttp-5.so").is_file() or Path("/usr/lib/libXrdHttp-5.so").is_file()
        if pairing == "B":
            if hop2 == "https":
                return "SKIP", "stock xrootd proxy has no https backend leg"
            if not have_xrootd:
                return "SKIP", "stock xrootd absent"
            return "SUPPORTED", ""
        if pairing == "A":
            if not have_xrootd:
                return "SKIP", "stock xrootd absent"
            if cred == "token":
                if hop2 == "https":
                    return "SKIP", "pairing A https backend leg is GSI-only (stock XrdHttp ztn-over-http not provisioned)"
                if shutil.which("bwrap") is None:
                    return "SKIP", "token origin needs bwrap for rootless OIDC CA-bundle trust; bwrap absent"
                return "SUPPORTED", ""
            if hop2 == "https" and not have_xrdhttp:
                return "SKIP", "stock XrdHttp plugin (libXrdHttp) not present — no https backend node"
            return "SUPPORTED", ""
        if pairing == "C":
            return "SUPPORTED", ""
        return "SKIP", f"unknown pairing {pairing}"

    def backend_leg_config(self, pairing: str, hop2: str, cred: str,
                           backend_url: str, cred_dir: Path | None) -> str:
        frag = f"brix_storage_backend {backend_url};"
        if cred == "gsi":
            frag += (f"\n            brix_storage_credential origin;"
                     f"\n            brix_storage_credential_dir {cred_dir};"
                     "\n            brix_storage_credential_fallback deny;")
        else:
            frag += "\n            brix_storage_credential origin_ca;"
        if pairing == "C" or (pairing == "A" and cred == "token"):
            frag += "\n            brix_backend_delegation passthrough;"
        return frag
