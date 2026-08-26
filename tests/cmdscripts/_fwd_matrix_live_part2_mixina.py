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

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT, inject_nginx_load_modules
# _call is defined in the fwd_matrix_live parent (loaded before this mixin);
# import it so the mixin methods can spawn subprocesses (split-drop fix).
from cmdscripts.fwd_matrix_live import _call, _curl_code  # noqa: E402
from lib_py.util import wait_tcp
from settings import BIND_HOST, CA_CERT, CA_DIR, CA_KEY, HOST, SERVER_CERT, SERVER_KEY
from ephemeral_port import free_ports

def _expression_1(backend):
    return (
        f"brix_storage_backend {backend};" if backend else ""
    )

def _expression_2(proto):
    return (
        f"brix_certificate {SERVER_CERT}; brix_certificate_key {SERVER_KEY};" if proto == "roots" else ""
    )


def _phase_kill_pidfiles_1(pids, pidfile):
    try:
        pids.append(int(pidfile.read_text().strip()))
    except (OSError, ValueError):
        pass

def _phase_kill_pidfiles_2(pid):
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass

def _phase_kill_pidfiles_3(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _guard_kill_pidfiles_1(pids):
    if pids:
        time.sleep(0.4)


BRIX_XRDCP = REPO_ROOT / "client/bin/xrdcp"
BRIX_XRDFS = REPO_ROOT / "client/bin/xrdfs"
XROOTD_BIN = Path(os.environ.get("XROOTD_BIN", os.environ.get("BRIX_BIN", "/usr/bin/xrootd")))
SYS_XRDCP = shutil.which("xrdcp")

A_CN, B_CN, SVC_CN = "Fwd User A", "Fwd User B", "Fwd Service"
A_SUB, B_SUB = "fwd-user-a", "fwd-user-b"
TOK_AUD = "nginx-xrootd"


def _call(*args, **kwargs):
    """Resolve the parent module's process helper after continuation loading."""
    from cmdscripts.fwd_matrix_live import _call as parent_call

    return parent_call(*args, **kwargs)


def _curl_code(*args, **kwargs):
    """Resolve the parent module's curl helper after continuation loading."""
    from cmdscripts.fwd_matrix_live import _curl_code as parent_curl_code

    return parent_curl_code(*args, **kwargs)


class _ForwardHarnessMixinA:
    """Python port of tests/lib/fwd_matrix.sh: topology + assertion library."""

    def __init__(self, label: str, nginx: Path | None = None) -> None:
        self.run = LiveRun(f"fwd_{label}", nginx)
        self.prefix = self.run.root
        self.node_pidfiles: list[Path] = []
        self.results: list[tuple[str, str, str]] = []
        self.any_fail = 0
        self.last_log: Path | None = None
        self.oidc_port = free_ports(1)[0]
        self.tok_issuer = f"https://localhost:{self.oidc_port}"  # net-literal-allow: cert-CN-bound issuer host
        self.tok_jwks: Path | None = None
        self.token_a: Path | None = None
        self.token_b: Path | None = None
        self.proxy_a = self.prefix / "proxy_a.pem"
        self.proxy_b = self.prefix / "proxy_b.pem"
        self.svc_proxy = self.prefix / "proxy_svc.pem"
        self._ca_bundle: Path | None = None

    def __enter__(self) -> "ForwardHarness":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._kill_pidfiles(self.node_pidfiles)
        self.node_pidfiles.clear()
        self.run.close()

    # -- preflight / bookkeeping ------------------------------------------
    def preflight(self, *, need_xrootd: bool = False) -> str | None:
        for binary in (self.run.nginx, BRIX_XRDCP, BRIX_XRDFS):
            if not os.access(binary, os.X_OK):
                return f"missing {binary}"
        if need_xrootd and not os.access(XROOTD_BIN, os.X_OK):
            return f"stock xrootd ({XROOTD_BIN}) not present — pairing requires it"
        return None

    def record(self, key: str, outcome: str, detail: str = "") -> None:
        self.results.append((key, outcome, detail))
        if outcome == "FAIL":
            self.any_fail = 1
        print(f"  {outcome:<22} {key:<30} {detail}")

    def summary(self, label: str) -> None:
        print(f"\n---- {label} summary ----")
        for key, outcome, detail in self.results:
            print(f"  {key:<30} {outcome:<14} {detail}")

    @staticmethod
    def _kill_pidfiles(pidfiles: list[Path]) -> None:
        pids = []
        for pidfile in pidfiles:
            _phase_kill_pidfiles_1(pids, pidfile)
        for pid in pids:
            _phase_kill_pidfiles_2(pid)
        _guard_kill_pidfiles_1(pids)
        for pid in pids:
            _phase_kill_pidfiles_3(pid)

    @contextmanager
    def cell(self) -> Iterator[None]:
        """Per-cell teardown: stop only the nodes started inside the cell."""
        mark = len(self.node_pidfiles)
        try:
            yield
        finally:
            self._kill_pidfiles(self.node_pidfiles[mark:])
            del self.node_pidfiles[mark:]

    # -- PKI + token authority --------------------------------------------
    def mint_pki(self) -> bool:
        if not (Path(CA_CERT).is_file() and Path(CA_KEY).is_file()):
            proc = _call(
                [sys.executable, "-c", "import pki_helpers; pki_helpers.blitz_test_pki()"],
                env_add={"PYTHONPATH": str(REPO_ROOT / "tests")},
            )
            if proc.returncode:
                print(f"SKIP: PKI provisioning failed: {proc.stderr[-2000:]}")
                return False
        if not Path(CA_KEY).is_file():
            print(f"SKIP: CA key not found ({CA_KEY})")
            return False
        minter = REPO_ROOT / "tests/lib/fwd_mint_proxy.py"
        for cn, out in ((A_CN, self.proxy_a), (B_CN, self.proxy_b), (SVC_CN, self.svc_proxy)):
            proc = _call([sys.executable, minter, CA_CERT, CA_KEY, cn, out])
            if proc.returncode:
                print(f"SKIP: proxy mint failed for {cn}: {proc.stderr[-1000:]}")
                return False
        return True

    def mint_token(self) -> bool:
        tok_dir = self.prefix / "tok"
        proc = _call([sys.executable, REPO_ROOT / "utils/make_token.py", "init", tok_dir])
        if proc.returncode:
            print("SKIP: make_token.py init failed (cryptography missing?)")
            return False
        self.tok_jwks = tok_dir / "jwks.json"
        self.token_a = self.prefix / "token_a.jwt"
        self.token_b = self.prefix / "token_b.jwt"
        if not self._start_oidc_server():
            return False
        proc = _call([sys.executable, REPO_ROOT / "utils/make_token.py", "gen",
                      "--sub", A_SUB, "--scope", "storage.read:/ storage.modify:/",
                      "--issuer", self.tok_issuer, "-o", self.token_a, tok_dir])
        if proc.returncode:
            print("SKIP: token A gen failed")
            return False
        # userB gets a WRONG-ISSUER token so the backend genuinely rejects it.
        proc = _call([sys.executable, REPO_ROOT / "utils/make_token.py", "gen",
                      "--sub", B_SUB, "--scope", "storage.read:/ storage.modify:/",
                      "--kind", "wrong-issuer", "-o", self.token_b, tok_dir])
        if proc.returncode:
            print("SKIP: token B gen failed")
            return False
        return True

    def _start_oidc_server(self) -> bool:
        oidc_dir = self.run.mkdir("oidc", ".well-known").parent
        (oidc_dir / ".well-known/openid-configuration").write_text(
            f'{{"issuer":"{self.tok_issuer}","jwks_uri":"{self.tok_issuer}/jwks.json"}}\n')
        shutil.copy(self.tok_jwks, oidc_dir / "jwks.json")
        self.run.spawn([sys.executable, REPO_ROOT / "tests/lib/fwd_oidc_server.py",
                        oidc_dir, str(self.oidc_port), SERVER_CERT, SERVER_KEY])
        for _ in range(20):
            code = _curl_code("--cacert", CA_CERT,
                              f"{self.tok_issuer}/.well-known/openid-configuration")
            if code == "200":
                return True
            time.sleep(0.2)
        print(f"SKIP: local HTTPS OIDC discovery server did not come up on {self.oidc_port}")
        return False

    def trusted_ca_bundle(self) -> Path:
        """Test CA prepended to a copy of the OS default bundle (bwrap bind)."""
        if self._ca_bundle is None:
            self._ca_bundle = self.prefix / "ca-bundle-trust.crt"
            sysb = Path("/etc/pki/tls/certs/ca-bundle.crt")
            if not sysb.is_file():
                sysb = Path("/etc/ssl/certs/ca-certificates.crt")
            try:
                self._ca_bundle.write_bytes(Path(CA_CERT).read_bytes() + sysb.read_bytes())
            except OSError:
                shutil.copy(CA_CERT, self._ca_bundle)
        return self._ca_bundle

    def eec_dn(self, pem: Path) -> str | None:
        """End-entity DN of a proxy chain in the XRootD /-slash form."""
        blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                            pem.read_text(errors="replace"), re.S)
        for block in blocks:
            proc = _call(["openssl", "x509", "-noout", "-subject"], input=block + "\n")
            subj = proc.stdout.strip().removeprefix("subject=").strip()
            if not subj or re.search(r",\s*CN\s*=\s*[0-9]+$", subj):
                continue  # a proxy delegation leaf
            return "/" + re.sub(r", ", "/", re.sub(r" = ", "=", subj))
        return None

    # -- node spawners ------------------------------------------------------
    def _start_nginx(self, d: Path, conf: Path, label: str) -> bool:
        inject_nginx_load_modules(conf)
        cmd: list[str | Path] = [self.run.nginx, "-p", d, "-c", conf]
        # Root harness: the always-on de-escalation drops workers to `nobody`,
        # which cannot traverse the 0700 mkdtemp LiveRun tree — so the
        # confined-ops open of the export root fails EACCES ("cannot open
        # export root for kernel-confined path operations"), the node never
        # serves, and a TPC pull to it just times out (rc=51). Open the whole
        # LiveRun tree (per-node dirs, minted proxies and credential stores are
        # spread across it) for that worker.
        from cmdscripts import open_tree_for_worker  # noqa: PLC0415
        open_tree_for_worker(self.run.root, conf)
        proc = _call(cmd, env_drop=("NGINX",))
        if proc.returncode:
            print(f"  (start failed for {label}: {proc.stderr.strip()})", file=sys.stderr)
            return False
        self.node_pidfiles.append(d / "nginx.pid")
        time.sleep(0.6)
        return True

    def spawn_brix_node(self, role: str, proto: str, port: int,
                        backend: str = "", extra: str = "") -> Path | None:
        d = self.run.mkdir(role)
        for sub in ("export", "logs", "cache"):
            (d / sub).mkdir(exist_ok=True)
        log = d / "logs/e.log"
        backend_line = _expression_1(backend)
        if proto in ("root", "roots"):
            tls = _expression_2(proto)
            conf = self.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export {d}/export;
        brix_allow_write on;
        brix_upload_resume off;
        {tls}
        {backend_line}
        {extra}
    }}
}}
""")
        elif proto in ("davs", "http"):
            if proto == "davs":
                ssl = f"""listen {BIND_HOST}:{port} ssl;
        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;"""
            else:
                ssl = f"listen {BIND_HOST}:{port};"
            conf = self.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {d}/logs/access.log;
    client_body_temp_path {d}/export;
    server {{
        {ssl}
        location / {{
            brix_webdav on;
            brix_allow_write on;
            brix_export {d}/export;
            brix_trusted_ca {CA_CERT};
            {backend_line}
            {extra}
        }}
    }}
}}
""")
        else:
            raise LiveFailure(f"spawn_brix_node: unknown proto {proto}")
        if not self._start_nginx(d, conf, f"brix {role}/{proto}"):
            return None
        self.last_log = log
        return log

    def _xrootd_sec_block(self, d: Path, cred: str) -> str:
        sec_lib = Path("/usr/lib64/libXrdSec-5.so")
        if not sec_lib.is_file():
            sec_lib = Path("/usr/lib/libXrdSec-5.so")
        if cred == "gsi":
            return (f"xrootd.seclib {sec_lib}\n"
                    f"sec.protocol gsi -certdir:{CA_DIR} -cert:{SERVER_CERT} -key:{SERVER_KEY}"
                    " -gridmap:none -gmapopt:10 -crl:0\n"
                    "sec.protbind * gsi")
        if cred == "token":
            (d / "scitokens.cfg").write_text(f"""[Global]
audience = {TOK_AUD}
[Issuer test]
issuer = {self.tok_issuer}
base_path = /
default_user = fwduser
""")
            return (f"xrd.tls   {SERVER_CERT} {SERVER_KEY}\n"
                    f"xrd.tlsca certdir {CA_DIR}\n"
                    f"xrootd.seclib {sec_lib}\n"
                    "sec.protocol ztn\n"
                    "sec.protbind * ztn\n"
                    "ofs.authorize 1\n"
                    f"ofs.authlib libXrdAccSciTokens-5.so config={d}/scitokens.cfg")
        return ""

    def spawn_bwrap_xrootd(self, d: Path, cfg: Path, log: Path, port: int) -> bool:
        """Launch xrootd under bwrap with a test-CA-augmented default bundle."""
        if shutil.which("bwrap") is None:
            print("  (token origin needs bwrap for rootless CA-bundle trust; absent)", file=sys.stderr)
            log.touch()
            self.last_log = log
            return False
        bundle = self.trusted_ca_bundle()
        real_bundle = os.path.realpath("/etc/pki/tls/certs/ca-bundle.crt")
        cache = d / "scitok_cache"
        shutil.rmtree(cache, ignore_errors=True)
        cache.mkdir()
        # Stock xrootd refuses to run as superuser ("Security reasons prohibit
        # running as superuser"), so under the root harness it never binds and the
        # brix front's backend connect is refused (kXR 3012 / "exhausted all
        # endpoints"). Drop it to `nobody` and open the node tree so that account
        # can traverse in, read the config, and write its data/admin/run/log/cache.
        xrd_runas: list[str] = []
        if os.geteuid() == 0:
            xrd_runas = ["-R", "nobody"]
            subprocess.run(["chmod", "a+rx", str(self.run.root)], check=False)
            subprocess.run(["chmod", "-R", "a+rwX", str(d)], check=False)
        proc = self.run.spawn(["bwrap", "--dev-bind", "/", "/",
                               "--bind", bundle, real_bundle,
                               "--setenv", "XDG_CACHE_HOME", cache,
                               XROOTD_BIN, *xrd_runas, "-c", cfg, "-l", log])
        pidfile = d / "bwrap.pid"
        pidfile.write_text(str(proc.pid))
        self.node_pidfiles.append(pidfile)
        self.last_log = log
        wait_tcp(HOST, port, 6)
        time.sleep(0.4)
        return True
