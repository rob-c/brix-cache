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
from cmdscripts.fwd_matrix_live import _call, _curl_code  # noqa: E402 (split-drop fix)

BRIX_XRDCP = REPO_ROOT / "client/bin/xrdcp"
BRIX_XRDFS = REPO_ROOT / "client/bin/xrdfs"
XROOTD_BIN = Path(os.environ.get("XROOTD_BIN", os.environ.get("BRIX_BIN", "/usr/bin/xrootd")))
SYS_XRDCP = shutil.which("xrdcp")

A_CN, B_CN, SVC_CN = "Fwd User A", "Fwd User B", "Fwd Service"
A_SUB, B_SUB = "fwd-user-a", "fwd-user-b"
TOK_AUD = "nginx-xrootd"


class FrontResult(NamedTuple):
    """Outcome of one forwarding-matrix PUT/GET cell."""
    put_ok: bool
    get_ok: bool
    deny_obs: str


def _call(*args, **kwargs):
    """Resolve the parent module's command runner lazily to avoid import cycles."""
    from cmdscripts.fwd_matrix_live import _call as parent_call
    return parent_call(*args, **kwargs)


def _curl_code(*args, **kwargs):
    """Resolve the parent module's curl helper lazily after continuation load."""
    from cmdscripts.fwd_matrix_live import _curl_code as parent_curl_code
    return parent_curl_code(*args, **kwargs)


class _ForwardHarnessMixinB:
    """Python port of tests/lib/fwd_matrix.sh: topology + assertion library."""

    def _node_directory(self, role):
        directory = self.run.mkdir(role)
        for subdirectory in ("data", "admin", "run", "scitok_cache"):
            (directory / subdirectory).mkdir(exist_ok=True)
        return directory

    def _origin_config(self, directory, port, security):
        return f"""xrd.port {port}
xrd.network nodnr
xrd.allow host *
oss.localroot {directory}/data
all.export /
all.adminpath {directory}/admin
all.pidpath   {directory}/run
xrd.trace off
{security}
"""

    def _xrdhttp_config(self, directory, port):
        subject = self.eec_dn(self.proxy_a) or ""
        (directory / "gridmap").write_text(f'"{subject}" fwd-user-a\n')
        (directory / "authdb").write_text("u fwd-user-a / a\n")
        (directory / "data").chmod(0o777)
        return f"""xrd.port {port}
xrd.protocol http:{port} libXrdHttp.so
xrd.network nodnr
xrd.allow host *
xrd.tls   {SERVER_CERT} {SERVER_KEY}
xrd.tlsca certdir {CA_DIR}
http.cadir {CA_DIR}
http.cert  {SERVER_CERT}
http.key   {SERVER_KEY}
http.secxtractor libXrdHttpVOMS.so
http.gridmap {directory}/gridmap
oss.localroot {directory}/data
all.export /
all.adminpath {directory}/admin
all.pidpath   {directory}/run
acc.authdb {directory}/authdb
ofs.authorize 1
sec.protbind * none
xrd.trace off
"""

    @staticmethod
    def _pss_config(directory, port, backend, security):
        return f"""all.role server
all.export /
oss.localroot {directory}/data
all.adminpath {directory}/admin
all.pidpath   {directory}/run
xrd.port {port}
xrd.network nodnr
xrd.allow host *
xrd.trace off
ofs.osslib libXrdPss.so
pss.origin {backend}
pss.setopt DebugLevel 0
{security}
"""

    def _node_config(self, mode, directory, port, backend, security):
        builders = {
            "origin": lambda: self._origin_config(directory, port, security),
            "xrdhttp": lambda: self._xrdhttp_config(directory, port),
            "pss": lambda: self._pss_config(directory, port, backend, security),
        }
        if mode not in builders:
            raise LiveFailure(f"spawn_xrootd_node: unknown mode {mode}")
        return builders[mode]()

    def _remember_node_pid(self, directory):
        for _attempt in range(20):
            pids = sorted((directory / "run").glob("*.pid"))
            if pids:
                self.node_pidfiles.append(pids[0])
                return
            time.sleep(0.2)

    def _launch_stock_node(self, directory, config, log):
        run_as = []
        if os.geteuid() == 0:
            run_as = ["-R", "nobody"]
            subprocess.run(["chmod", "a+rx", str(self.run.root)], check=False)
            subprocess.run(["chmod", "-R", "a+rwX", str(directory)], check=False)
        _call([XROOTD_BIN, *run_as, "-c", config, "-l", log, "-b"])
        self._remember_node_pid(directory)

    def spawn_xrootd_node(self, role: str, mode: str, port: int,
                          backend: str = "", cred: str = "gsi") -> Path | None:
        directory = self._node_directory(role)
        cfg, log = directory / "x.cfg", directory / "x.log"
        log.write_text("")
        security = self._xrootd_sec_block(directory, cred)
        cfg.write_text(self._node_config(mode, directory, port, backend, security))

        if cred == "token":
            return log if self.spawn_bwrap_xrootd(directory, cfg, log, port) else None
        self._launch_stock_node(directory, cfg, log)
        self.last_log = log
        time.sleep(0.8)
        return log

    # -- assertions ---------------------------------------------------------
    @staticmethod
    def _stock_identity(text, pattern):
        for line in text.splitlines():
            if "login as " in line and re.search(f"CN={pattern}", line):
                return True
        return re.search(rf"login as {pattern}( |$)", text, re.M) is not None

    @staticmethod
    def _brix_identity(text, expect, pattern):
        if re.search(rf"GSI auth OK ([^ ]* )?dn=.*{pattern}", text):
            return True
        return re.search(rf'valid token sub="?{re.escape(expect)}"?', text) is not None

    @staticmethod
    def assert_backend_identity(kind: str, log: Path | None, expect: str) -> bool:
        if log is None or not log.is_file():
            return False
        text = log.read_text(errors="replace")
        # brix_sanitize_log_string writes spaces as literal \x20.
        alt = f"({re.escape(expect)}|{re.escape(expect.replace(' ', chr(92) + 'x20'))})"
        if kind == "stock":
            return _ForwardHarnessMixinB._stock_identity(text, alt)
        if kind == "brix":
            return _ForwardHarnessMixinB._brix_identity(text, expect, alt)
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
        # XrdCl's ztn handler requires TLS.  Select it explicitly for this
        # roots:// leg; the client otherwise prefers an ambient GSI proxy.
        # Keep the literal as well as the file convention because these live
        # tokens are generated with ordinary temporary-file permissions.
        return {"BEARER_TOKEN": jwt.read_text().strip(),
                "BEARER_TOKEN_FILE": str(jwt), "X509_CERT_DIR": CA_DIR,
                "XrdSecPROTOCOL": "ztn", "X509_USER_PROXY": str(self.proxy_a)}

    def _root_front_environment(self, cred, who):
        if cred == "gsi":
            credential = self.proxy_a if who == "A" else self.proxy_b
            return self.gsi_env(credential)
        credential = self.token_a if who == "A" else self.token_b
        return self.token_env(credential)

    @staticmethod
    def _root_front_protocol(cred):
        if cred == "token":
            return "roots", ["--auth", "ztn"]
        return "root", []

    def _root_front_put_get(self, cred, port, obj, who, payload, back):
        scheme, auth_args = self._root_front_protocol(cred)
        url = f"{scheme}://{HOST}:{port}/{obj}"
        env = self._root_front_environment(cred, who)
        put = _call(
            [BRIX_XRDCP, *auth_args, "-f", payload, url],
            env_add=env,
            env_drop=("X509_USER_CERT", "X509_USER_KEY"),
            timeout=60,
        )
        _call(
            [BRIX_XRDCP, *auth_args, "-f", url, back],
            env_add=env,
            env_drop=("X509_USER_CERT", "X509_USER_KEY"),
            timeout=60,
        )
        if put.returncode == 0:
            return True, ""
        client_error = (put.stderr or put.stdout).strip().replace("\n", " ")
        return False, client_error[-400:] or f"rc={put.returncode}"

    def _https_auth(self, cred, who):
        if cred == "gsi":
            proxy = self.proxy_a if who == "A" else self.proxy_b
            return ["--cert", str(proxy), "--key", str(proxy)]
        token = self.token_a if who == "A" else self.token_b
        return ["-H", f"Authorization: Bearer {token.read_text().strip()}"]

    def _https_front_put_get(self, cred, port, obj, who, payload, back):
        url = f"https://{HOST}:{port}/{obj}"
        auth = self._https_auth(cred, who)
        code = _curl_code(*auth, "-T", str(payload), url)
        _call(["curl", "-sk", *auth, "-o", back, url], timeout=60)
        if code in ("200", "201", "204"):
            return True, ""
        return False, code

    def front_put_get(self, hop1: str, cred: str, port: int, obj: str, who: str) -> FrontResult:
        payload = self.prefix / f"payload_{who}.bin"
        back = self.prefix / f"back_{who}.bin"
        payload.write_bytes(os.urandom(65536))
        back.unlink(missing_ok=True)
        if hop1 == "root":
            put_ok, deny_obs = self._root_front_put_get(
                cred, port, obj, who, payload, back
            )
        else:
            put_ok, deny_obs = self._https_front_put_get(
                cred, port, obj, who, payload, back
            )
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

    @staticmethod
    def _pairing_b_feasibility(hop2, have_xrootd):
        if hop2 == "https":
            return "SKIP", "stock xrootd proxy has no https backend leg"
        if not have_xrootd:
            return "SKIP", "stock xrootd absent"
        return "SUPPORTED", ""

    @staticmethod
    def _pairing_a_token_feasibility(hop2):
        if hop2 == "https":
            return "SKIP", "pairing A https backend leg is GSI-only (stock XrdHttp ztn-over-http not provisioned)"
        if shutil.which("bwrap") is None:
            return "SKIP", "token origin needs bwrap for rootless OIDC CA-bundle trust; bwrap absent"
        return "SUPPORTED", ""

    @classmethod
    def _pairing_a_feasibility(cls, hop2, cred, have_xrootd, have_xrdhttp):
        if not have_xrootd:
            return "SKIP", "stock xrootd absent"
        if cred == "token":
            return cls._pairing_a_token_feasibility(hop2)
        if hop2 == "https" and not have_xrdhttp:
            return "SKIP", "stock XrdHttp plugin (libXrdHttp) not present — no https backend node"
        return "SUPPORTED", ""

    def feasibility_probe(self, pairing: str, hop2: str, cred: str) -> tuple[str, str]:
        have_xrootd = os.access(XROOTD_BIN, os.X_OK)
        have_xrdhttp = Path("/usr/lib64/libXrdHttp-5.so").is_file() or Path("/usr/lib/libXrdHttp-5.so").is_file()
        if pairing == "B":
            return self._pairing_b_feasibility(hop2, have_xrootd)
        if pairing == "A":
            return self._pairing_a_feasibility(
                hop2, cred, have_xrootd, have_xrdhttp
            )
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
