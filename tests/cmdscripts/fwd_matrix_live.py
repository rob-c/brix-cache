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


def _call(argv: list[str | Path], *, env_add: dict[str, str] | None = None,
          env_drop: tuple[str, ...] = (), input: str | None = None,
          stdout_to: Path | None = None, timeout: float | None = None) -> subprocess.CompletedProcess:
    """Run a command with additions to AND removals from the environment.

    ``env_drop`` matters twice over: ``NGINX`` is a reserved nginx env var
    (inherited socket fds) that must never reach a spawned nginx, and
    ``XRDC_GSI_DELEGATE`` must be truly UNSET (not empty) for the userB
    no-delegation negative control.
    """
    env = {k: v for k, v in os.environ.items() if k not in env_drop}
    env.update(env_add or {})
    out = stdout_to.open("wb") if stdout_to else subprocess.PIPE
    try:
        proc = subprocess.Popen(
            [str(a) for a in argv], env=env,
            stdin=subprocess.PIPE if input is not None else None,
            stdout=out, stderr=subprocess.PIPE,
            text=stdout_to is None,
        )
        try:
            stdout, stderr = proc.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
    finally:
        if stdout_to:
            out.close()
    if not isinstance(stderr, str):
        stderr = (stderr or b"").decode(errors="replace")
    if not isinstance(stdout, str):
        stdout = ""
    return subprocess.CompletedProcess([str(a) for a in argv], proc.returncode, stdout, stderr)


def _curl_code(*args: str | Path) -> str:
    proc = _call(["curl", "-sk", "-o", os.devnull, "-w", "%{http_code}", *args], timeout=60)
    return proc.stdout.strip() or "000"


class FrontResult(NamedTuple):
    put_ok: bool
    get_ok: bool
    deny_obs: str


class ForwardHarness:
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
            try:
                pids.append(int(pidfile.read_text().strip()))
            except (OSError, ValueError):
                pass
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        if pids:
            time.sleep(0.4)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

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
        backend_line = f"brix_storage_backend {backend};" if backend else ""
        if proto in ("root", "roots"):
            tls = f"brix_certificate {SERVER_CERT}; brix_certificate_key {SERVER_KEY};" if proto == "roots" else ""
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
            brix_webdav_cafile {CA_CERT};
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


def _outcome(harness: ForwardHarness, label: str) -> int:
    harness.summary(label)
    if harness.any_fail:
        print(f"{label}: FAIL cells present")
    else:
        print(f"{label}: no FAIL cells")
    return harness.any_fail


# ===========================================================================
# Pairing C — run_fwd_brix_brix.sh (brix-front -> brix-back)
# ===========================================================================

def _c_backend_extra(h: ForwardHarness, proto: str, cred: str) -> str:
    if proto == "root":
        if cred == "gsi":
            return (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                    f"        brix_certificate_key {SERVER_KEY};\n"
                    f"        brix_trusted_ca      {CA_CERT};")
        return (f"brix_auth token;\n        brix_token_jwks     {h.tok_jwks};\n"
                f"        brix_token_issuer   {h.tok_issuer};\n"
                f"        brix_token_audience {TOK_AUD};")
    if cred == "gsi":
        return "brix_webdav_auth required;"
    return (f"brix_webdav_auth required;\n            brix_webdav_token_jwks     {h.tok_jwks};\n"
            f"            brix_webdav_token_issuer   {h.tok_issuer};\n"
            f"            brix_webdav_token_audience {TOK_AUD};")


def _spawn_c_front(h: ForwardHarness, role: str, fproto: str, cred: str, fport: int,
                   burl: str, cred_dir: Path) -> Path | None:
    d = h.run.mkdir(role)
    for sub in ("export", "logs"):
        (d / sub).mkdir(exist_ok=True)
    log = d / "logs/e.log"
    leg = h.backend_leg_config("C", "root" if burl.startswith("root") else "https", cred, burl, cred_dir)
    if fproto == "root":
        if cred == "gsi":
            auth = (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                    f"        brix_certificate_key {SERVER_KEY};\n"
                    f"        brix_trusted_ca      {CA_CERT};")
        else:
            auth = (f"brix_auth token;\n        brix_token_jwks     {h.tok_jwks};\n"
                    f"        brix_token_issuer   {h.tok_issuer};\n"
                    f"        brix_token_audience {TOK_AUD};")
        conf = h.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    brix_credential origin {{ x509_proxy {h.svc_proxy}; ca_dir {CA_DIR}; }}
    brix_credential origin_ca {{ ca_dir {CA_DIR}; }}
    server {{
        listen {BIND_HOST}:{fport};
        brix_root on;
        brix_export {d}/export;
        brix_allow_write on;
        brix_upload_resume off;
        {auth}
        {leg}
    }}
}}
""")
    else:
        auth = f"brix_webdav_cafile {CA_CERT}; brix_webdav_auth required;"
        if cred != "gsi":
            auth += (f"\n            brix_webdav_token_jwks     {h.tok_jwks};\n"
                     f"            brix_webdav_token_issuer   {h.tok_issuer};\n"
                     f"            brix_webdav_token_audience {TOK_AUD};")
        conf = h.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {d}/logs/access.log;
    client_body_temp_path {d}/export;
    brix_credential origin {{ x509_proxy {h.svc_proxy}; ca_dir {CA_DIR}; }}
    brix_credential origin_ca {{ ca_dir {CA_DIR}; }}
    server {{
        listen {BIND_HOST}:{fport} ssl;
        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        location / {{
            brix_webdav on;
            brix_allow_write on;
            brix_export {d}/export;
            {auth}
            {leg}
        }}
    }}
}}
""")
    if not h._start_nginx(d, conf, f"C front {role}"):
        return None
    h.last_log = log
    return log


_C_TOK_GAP = r"backend has NO credential|serve offload: materialise failed|getxattr lock on .* failed"
_C_WOB_GAP = r"root:// write to a whole-object storage backend is not supported"
_C_UNSUP = (r"cannot scope a session to a user credential|not.?implemented|unsupported|"
            r"no per-user|cannot present|passthrough.*unavailable|" + _C_WOB_GAP + "|" + _C_TOK_GAP)


def _run_cell_c(h: ForwardHarness, wire: str, cred: str) -> None:
    hop1, hop2 = h.hop1(wire), h.hop2(wire)
    key = f"C {wire} {cred}"
    verdict, why = h.feasibility_probe("C", hop2, cred)
    if verdict != "SUPPORTED":
        h.record(key, verdict, why)
        return
    if cred == "token" and h.tok_jwks is None:
        h.record(key, "SKIP", "token authority unavailable")
        return
    bport, fport = free_ports(2)
    if hop2 == "root":
        bproto, burl = "root", f"root://{HOST}:{bport}"
    else:
        bproto, burl = "davs", f"https://{HOST}:{bport}"
    fproto = "root" if hop1 == "root" else "davs"

    blog = h.spawn_brix_node(f"cbk_{wire}_{cred}", bproto, bport, "", _c_backend_extra(h, bproto, cred))
    if blog is None:
        h.record(key, "FAIL", "brix backend start failed")
        return
    bexport = h.prefix / f"cbk_{wire}_{cred}/export"
    cred_dir = h.run.mkdir(f"creds_c_{wire}_{cred}")
    cred_dir.chmod(0o777)
    flog = _spawn_c_front(h, f"cfr_{wire}_{cred}", fproto, cred, fport, burl, cred_dir)
    if flog is None:
        h.record(key, "FAIL", "brix front start failed")
        return
    if cred == "gsi":
        h.install_gsi_cred(cred_dir, flog, hop1, fport)

    # ---- positive: userA two-hop PUT+GET + backend sees A ----
    blog.write_text("")
    pos = h.front_put_get(hop1, cred, fport, f"posC_{wire}.bin", "A")
    if not pos.get_ok:
        ftext = flog.read_text(errors="replace") if flog.is_file() else ""
        if re.search(_C_UNSUP, ftext, re.I):
            why = "front cannot forward credential on this path"
            if "cannot scope a session to a user credential" in ftext:
                why = ('backend "http" driver cannot scope a session to a per-user credential '
                       "(Phase-70 https-backend-leg gap)")
            if re.search(_C_WOB_GAP, ftext):
                why = ("root:// front -> whole-object https backend WRITE unsupported — the "
                       "block-write path (kXR_write/pgwrite) needs a staged-commit adapter to PUT "
                       "the object; sd_http has no random-write open (Phase-70 root->http-backend write gap)")
            if re.search(_C_TOK_GAP, ftext):
                why = ("backend leg did not receive the passed-through bearer — sd_xroot/serve-offload "
                       "needs a static brix_storage_credential (Phase-70 token passthrough gap)")
            h.record(key, "UNSUPPORTED", f"{why} (put_ok={int(pos.put_ok)})")
        else:
            h.record(key, "FAIL", f"userA two-hop PUT/GET not byte-exact (put_ok={int(pos.put_ok)})")
        return
    time.sleep(0.4)
    if not (h.assert_backend_identity("brix", blog, A_CN) or h.assert_backend_identity("brix", blog, A_SUB)):
        h.record(key, "FAIL", f"backend log did not show userA (DN={A_CN} / sub={A_SUB})")
        return
    # ---- negative: userB denied on backend leg, no bytes ----
    neg = h.front_put_get(hop1, cred, fport, f"negC_{wire}.bin", "B")
    if not h.assert_denied("root" if hop1 == "root" else "https", neg):
        h.record(key, "FAIL", f"userB not denied on backend leg (deny_obs={neg.deny_obs})")
        return
    if (bexport / f"negC_{wire}.bin").is_file():
        h.record(key, "FAIL", "userB bytes reached the backend store")
        return
    h.record(key, "PASS", "userA at backend, userB denied, no leak (passthrough)")


def fwd_brix_brix(nginx: Path | None = None) -> int:
    """Port of run_fwd_brix_brix.sh — pairing C, brix-front -> brix-back."""
    with ForwardHarness("c", nginx) as h:
        reason = h.preflight()
        if reason:
            print(f"run_fwd_brix_brix: environment SKIP ({reason})")
            return 0
        if not h.mint_pki():
            return 0
        if not h.mint_token():
            print("  (token authority unavailable — token cells will SKIP)")
            h.tok_jwks = None
        print("== credential-forwarding matrix — PAIRING C (brix-front -> brix-back) ==")
        for wire in ("RR", "HH", "HR", "RH"):
            for cred in ("gsi", "token"):
                with h.cell():
                    _run_cell_c(h, wire, cred)
        unsupported = sum(1 for _, outcome, _ in h.results if outcome == "UNSUPPORTED")
        rc = _outcome(h, "run_fwd_brix_brix")
        if unsupported:
            print(f"  !! pairing C has {unsupported} UNSUPPORTED cell(s) — REAL Phase-70 gap(s) to flag (spec §9.4)")
        return rc


# ===========================================================================
# Pairing A — run_fwd_brix_xrootd.sh (brix-front -> stock-xrootd-back)
# ===========================================================================

def _spawn_a_front_root(h: ForwardHarness, role: str, port: int, svc_block: str, server_extra: str) -> Path | None:
    d = h.run.mkdir(role)
    for sub in ("export", "logs"):
        (d / sub).mkdir(exist_ok=True)
    log = d / "logs/e.log"
    conf = h.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    {svc_block}
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export {d}/export;
        brix_allow_write on;
        brix_upload_resume off;
        {server_extra}
    }}
}}
""")
    if not h._start_nginx(d, conf, f"A front {role}"):
        return None
    h.last_log = log
    return log


def _spawn_a_front_davs(h: ForwardHarness, role: str, port: int, leg: str) -> Path | None:
    d = h.run.mkdir(role)
    for sub in ("export", "logs"):
        (d / sub).mkdir(exist_ok=True)
    log = d / "logs/e.log"
    conf = h.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {d}/logs/access.log;
    client_body_temp_path {d}/export;
    brix_credential origin {{ x509_proxy {h.svc_proxy}; ca_dir {CA_DIR}; }}
    server {{
        listen {BIND_HOST}:{port} ssl;
        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        location / {{
            brix_webdav on;
            brix_allow_write on;
            brix_export {d}/export;
            brix_webdav_cafile {CA_CERT};
            brix_webdav_auth required;
            {leg}
        }}
    }}
}}
""")
    if not h._start_nginx(d, conf, f"A davs front {role}"):
        return None
    h.last_log = log
    return log


def _run_cell_a(h: ForwardHarness, wire: str, cred: str) -> None:
    hop1, hop2 = h.hop1(wire), h.hop2(wire)
    key = f"A {wire} {cred}"
    verdict, why = h.feasibility_probe("A", hop2, cred)
    if verdict != "SUPPORTED":
        h.record(key, verdict, why)
        return
    if cred == "token" and h.tok_jwks is None:
        h.record(key, "SKIP", "token authority unavailable")
        return
    oport, fport = free_ports(2)

    if cred == "token":
        blog = h.spawn_xrootd_node(f"obk_{wire}_{cred}", "origin", oport, "", "token")
        if blog is None:
            h.record(key, "FAIL", "stock token origin start failed")
            return
        burl = f"roots://{HOST}:{oport}"
    elif hop2 == "https":
        blog = h.spawn_xrootd_node(f"obk_{wire}_{cred}", "xrdhttp", oport, "", "gsi")
        if blog is None:
            h.record(key, "FAIL", "stock XrdHttp origin start failed")
            return
        burl = f"https://{HOST}:{oport}"
    else:
        blog = h.spawn_xrootd_node(f"obk_{wire}_{cred}", "origin", oport, "", "gsi")
        burl = f"root://{HOST}:{oport}"

    cred_dir = h.run.mkdir(f"creds_{wire}_{cred}")
    cred_dir.chmod(0o777)
    # TOKEN cells keep the root-front bearer-passthrough path (a stock ztn
    # backend is roots://-only), so their front proto is pinned to root.
    fhop1 = "root" if cred == "token" else hop1
    leg = h.backend_leg_config("A", hop2, cred, burl, cred_dir)
    if fhop1 == "root":
        if cred == "token":
            svc_block = f"brix_credential origin_ca {{ ca_dir {CA_DIR}; }}"
            auth_block = (f"brix_auth token;\n        brix_certificate     {SERVER_CERT};\n"
                          f"        brix_certificate_key {SERVER_KEY};\n"
                          f"        brix_token_jwks     {h.tok_jwks};\n"
                          f"        brix_token_issuer   {h.tok_issuer};\n"
                          f"        brix_token_audience {TOK_AUD};")
        else:
            svc_block = f"brix_credential origin {{ x509_proxy {h.svc_proxy}; ca_dir {CA_DIR}; }}"
            auth_block = (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                          f"        brix_certificate_key {SERVER_KEY};\n"
                          f"        brix_trusted_ca      {CA_CERT};")
        flog = _spawn_a_front_root(h, f"afront_{wire}_{cred}", fport, svc_block, f"{auth_block}\n        {leg}")
    else:
        flog = _spawn_a_front_davs(h, f"afront_{wire}_{cred}", fport, leg)
    if flog is None:
        h.record(key, "FAIL", "brix front start failed")
        return

    if cred == "gsi":
        h.install_gsi_cred(cred_dir, flog, fhop1, fport)
    time.sleep(0.5)

    # ---- positive: userA PUT+GET, backend sees A (retry once past the
    # probe-connection cred-miss race) ----
    if blog is not None:
        blog.write_text("")
    pos = h.front_put_get(fhop1, cred, fport, f"posA_{wire}.bin", "A")
    if not pos.get_ok:
        time.sleep(0.4)
        pos = h.front_put_get(fhop1, cred, fport, f"posA2_{wire}.bin", "A")
    if not pos.get_ok:
        detail = f"userA two-hop PUT/GET not byte-exact (put_ok={int(pos.put_ok)})"
        ftext = flog.read_text(errors="replace") if flog.is_file() else ""
        if cred == "token":
            evidence = [line for line in ftext.splitlines()
                        if re.search(r"kXR 3028|origin TLS handshake failed|ztn", line, re.I)]
            if evidence:
                detail = f"front->stock-origin ztn/TLS leg failed (put_ok={int(pos.put_ok)}): {evidence[-1]}"
        h.record(key, "FAIL", detail)
        return
    time.sleep(0.4)
    expect_id = A_SUB if cred == "token" else ("fwd-user-a" if hop2 == "https" else A_CN)
    if not h.assert_backend_identity("stock", blog, expect_id):
        h.record(key, "FAIL", f"backend log did not show userA ({expect_id})")
        return
    # ---- negative: userB denied on the backend leg, no bytes ----
    obdir = h.prefix / f"obk_{wire}_{cred}/data"
    neg = h.front_put_get(fhop1, cred, fport, f"negB_{wire}.bin", "B")
    if not h.assert_denied("root" if fhop1 == "root" else "https", neg):
        h.record(key, "FAIL", f"userB was NOT denied on backend leg (deny_obs={neg.deny_obs})")
        return
    if (obdir / f"negB_{wire}.bin").is_file():
        h.record(key, "FAIL", "userB bytes reached the backend store")
        return
    h.record(key, "PASS", "userA DN at backend, userB denied, no leak")


def fwd_brix_xrootd(nginx: Path | None = None) -> int:
    """Port of run_fwd_brix_xrootd.sh — pairing A, brix-front -> xrootd-back."""
    with ForwardHarness("a", nginx) as h:
        reason = h.preflight(need_xrootd=True)
        if reason:
            print(f"run_fwd_brix_xrootd: pairing A SKIPPED wholesale ({reason})")
            return 0
        if not h.mint_pki():
            return 0
        if not h.mint_token():
            print("  (token authority unavailable — token cells will SKIP)")
            h.tok_jwks = None
        print("== credential-forwarding matrix — PAIRING A (brix-front -> xrootd-back) ==")
        for wire in ("RR", "HH", "HR", "RH"):
            for cred in ("gsi", "token"):
                with h.cell():
                    _run_cell_a(h, wire, cred)
        return _outcome(h, "run_fwd_brix_xrootd")


# ===========================================================================
# Pairing B — run_fwd_xrootd_brix.sh (stock-pss-front -> brix-back)
# ===========================================================================

_B_TOKEN_GAP = ("stock xrootd v5.9.6 does not forward the client WLCG token to the origin "
                "(pss/pfc/persona all proven not to carry the bearer — see "
                "fwd_b_token_forward_probe.sh); brix-back would authenticate the service, "
                "not fwd-user-a")


def _run_cell_b(h: ForwardHarness, wire: str, cred: str) -> None:
    key = f"B {wire} {cred}"
    verdict, why = h.feasibility_probe("B", h.hop2(wire), cred)
    if verdict != "SUPPORTED":
        h.record(key, verdict, why)
        return
    # Token forwarding through a stock xrootd front is a PROVEN stock blocker
    # (XrdPssConfig: "We don't support credential forwarding, yet").
    if cred == "token":
        h.record(key, "GAP", _B_TOKEN_GAP)
        return
    if SYS_XRDCP is None:
        h.record(key, "SKIP", "system xrdcp absent — cannot drive the stock pss front")
        return

    bport, fport = free_ports(2)
    if cred == "gsi":
        bextra = (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                  f"        brix_certificate_key {SERVER_KEY};\n"
                  f"        brix_trusted_ca      {CA_CERT};")
    else:
        bextra = (f"brix_auth token;\n        brix_token_jwks     {h.tok_jwks};\n"
                  f"        brix_token_issuer   {h.tok_issuer};\n"
                  f"        brix_token_audience {TOK_AUD};")
    blog = h.spawn_brix_node(f"bbk_{wire}_{cred}", "root", bport, "", bextra)
    if blog is None:
        h.record(key, "FAIL", "brix backend start failed")
        return
    bexport = h.prefix / f"bbk_{wire}_{cred}/export"
    h.spawn_xrootd_node(f"bfront_{wire}_{cred}", "pss", fport, f"{HOST}:{bport}", cred)

    blog.write_text("")
    payload = h.prefix / "payloadB_A.bin"
    payload.write_bytes(os.urandom(65536))
    if cred == "gsi":
        env = h.gsi_env(h.proxy_a)
    else:
        env = {"BEARER_TOKEN": h.token_a.read_text().strip()}
    _call([SYS_XRDCP, "-f", payload, f"root://{HOST}:{fport}//posB_{wire}.bin"],
          env_add=env, timeout=60)
    time.sleep(0.5)

    blog_text = blog.read_text(errors="replace") if blog.is_file() else ""
    if h.assert_backend_identity("brix", blog, A_CN) or h.assert_backend_identity("brix", blog, A_SUB):
        if (bexport / f"posB_{wire}.bin").is_file():
            h.record(key, "PASS", "stock pss forwarded userA identity to brix-back")
        else:
            h.record(key, "GAP", "userA authenticated at brix-back but no bytes (pss delegated auth only)")
        return
    if re.search(r"GSI auth OK dn=|valid token sub=", blog_text):
        h.record(key, "GAP", "stock pss forwarded its own service identity, not userA (documented stock limitation)")
    elif not blog_text.strip() or not re.search(r"auth|login|token", blog_text):
        h.record(key, "GAP", "stock pss forwarded no client credential to brix-back (anonymous forward)")
    else:
        h.record(key, "GAP", "brix-back saw a non-userA identity from the stock pss front")


def fwd_xrootd_brix(nginx: Path | None = None) -> int:
    """Port of run_fwd_xrootd_brix.sh — pairing B, xrootd-front -> brix-back."""
    with ForwardHarness("b", nginx) as h:
        reason = h.preflight(need_xrootd=True)
        if reason:
            print(f"run_fwd_xrootd_brix: pairing B SKIPPED wholesale ({reason})")
            return 0
        if not h.mint_pki():
            return 0
        if not h.mint_token():
            print("  (token authority unavailable — token cells will SKIP)")
            h.tok_jwks = None
        print("== credential-forwarding matrix — PAIRING B (xrootd-front -> brix-back) ==")
        for wire in ("RR", "HR", "HH", "RH"):
            for cred in ("gsi", "token"):
                with h.cell():
                    _run_cell_b(h, wire, cred)
        return _outcome(h, "run_fwd_xrootd_brix")


# ===========================================================================
# fwd_b_token_forward_probe.sh — empirical pairing-B token-forwarding probe
# ===========================================================================

def _probe_front_sec_block(h: ForwardHarness, d: Path) -> str:
    (d / "scitokens.cfg").write_text(f"""[Global]
audience = {TOK_AUD}
[Issuer test]
issuer = {h.tok_issuer}
base_path = /
default_user = fwduser
""")
    sec_lib = Path("/usr/lib64/libXrdSec-5.so")
    if not sec_lib.is_file():
        sec_lib = Path("/usr/lib/libXrdSec-5.so")
    return (f"xrd.tls   {SERVER_CERT} {SERVER_KEY}\n"
            f"xrd.tlsca certdir {CA_DIR}\n"
            f"xrootd.seclib {sec_lib}\n"
            "sec.protocol ztn\n"
            "sec.protbind * ztn\n"
            "ofs.authorize 1\n"
            f"ofs.authlib libXrdAccSciTokens-5.so config={d}/scitokens.cfg")


_PROBE_CFG = {
    "fwd": "ofs.osslib libXrdPss.so\npss.origin {origin}\npss.setopt DebugLevel 0",
    "pfc": ("ofs.osslib libXrdPfc.so\npfc.osslib libXrdPss.so\npss.origin {origin}\n"
            "pss.setopt DebugLevel 0\npfc.blocksize 1M"),
    "persona": ("ofs.osslib libXrdPss.so\npss.origin {origin}\npss.persona client\n"
                "pss.setopt DebugLevel 0"),
}


def _probe_spawn_front(h: ForwardHarness, role: str, variant: str, port: int, backhost: str) -> Path:
    d = h.run.mkdir(role)
    for sub in ("data", "admin", "run", "pfc", "scitok_cache"):
        (d / sub).mkdir(exist_ok=True)
    cfg, log = d / "x.cfg", d / "x.log"
    log.write_text("")
    localroot = d / ("pfc" if variant == "pfc" else "data")
    origin = f"roots://{backhost}/"     # ztn requires TLS to the origin
    cfg.write_text(f"""all.role server
all.export /
oss.localroot {localroot}
all.adminpath {d}/admin
all.pidpath   {d}/run
xrd.port {port}
xrd.network nodnr
xrd.allow host *
xrd.trace off
{_PROBE_CFG[variant].format(origin=origin)}
{_probe_front_sec_block(h, d)}
""")
    h.spawn_bwrap_xrootd(d, cfg, log, port)
    return log


def _grep_tail(log: Path, pattern: str, count: int) -> list[str]:
    if not log.is_file():
        return []
    lines = [line for line in log.read_text(errors="replace").splitlines()
             if re.search(pattern, line, re.I)]
    return lines[-count:]


def _probe_variant(h: ForwardHarness, variant: str, probe_results: list[tuple[str, str, str]]) -> None:
    def rec(status: str, detail: str) -> None:
        probe_results.append((variant, status, detail))
        print(f"  [{status}] {variant:<26} {detail}")

    bport, fport = free_ports(2)
    bextra = (f"brix_auth token;\n        brix_token_jwks     {h.tok_jwks};\n"
              f"        brix_token_issuer   {h.tok_issuer};\n"
              f"        brix_token_audience {TOK_AUD};")
    blog = h.spawn_brix_node("bbk_tok_" + variant, "roots", bport, "", bextra)
    if blog is None:
        rec("SKIP", "brix token backend failed to start")
        return
    bexport = h.prefix / f"bbk_tok_{variant}/export"
    front_log = _probe_spawn_front(h, f"sf_{variant}", variant, fport, f"{HOST}:{bport}")

    if not wait_tcp(HOST, fport, 2):
        why = ";".join(_grep_tail(front_log, r"Config|error|persona|unsupported|unable", 3))
        rec("BLOCKED", f"front did not listen: {why or f'see {front_log}'}")
        return

    blog.write_text("")
    payload = h.prefix / f"pl_{variant}.bin"
    payload.write_bytes(os.urandom(65536))
    env = {"BEARER_TOKEN": h.token_a.read_text().strip(), "XrdSecPROTOCOL": "ztn",
           "X509_CERT_DIR": CA_DIR, "X509_CERT_FILE": CA_CERT, "XrdSecGSICADIR": CA_DIR,
           "XRD_CONNECTIONWINDOW": "8", "XRD_CONNECTIONRETRY": "1",
           "XRD_REQUESTTIMEOUT": "12", "XRD_STREAMTIMEOUT": "12",
           "XRD_TIMEOUTRESOLUTION": "1"}
    _call([SYS_XRDCP, "-f", payload, f"roots://{HOST}:{fport}//probe_{variant}.bin"],
          env_add=env, timeout=40)
    time.sleep(0.8)

    blog_text = blog.read_text(errors="replace") if blog.is_file() else ""
    if re.search(r'valid token sub="?fwd-user-a"?', blog_text):
        if (bexport / f"probe_{variant}.bin").is_file():
            rec("PASS", "brix-back authenticated END USER (sub=fwd-user-a) AND bytes landed")
        else:
            rec("PARTIAL", "brix-back authenticated sub=fwd-user-a but no bytes")
    elif re.search(r"valid token sub=", blog_text):
        sub = re.findall(r'valid token sub="?[^" ]+', blog_text)[-1]
        rec("WRONG_ID", f"brix-back authenticated a NON-userA token: {sub}")
    elif re.search(r"token|auth|login|Auth", blog_text):
        rec("NO_FWD", "brix-back saw auth activity but NOT userA's token (see below)")
    else:
        rec("NO_FWD", "brix-back authenticated NOBODY — token NOT forwarded (anonymous)")

    print(f"    --- brix-back auth-relevant log ({variant}) ---")
    for line in _grep_tail(blog, r"token|auth|login|ztn|handshake|anonymous|entity|sub=", 8):
        print(f"      {line}")
    print(f"    --- stock front auth/config log ({variant}) ---")
    for line in _grep_tail(front_log, r"ztn|token|persona|forward|Config|login|auth|error", 8):
        print(f"      {line}")


def token_forward_probe(nginx: Path | None = None) -> int:
    """Port of fwd_b_token_forward_probe.sh — evidence probe, never a FAIL gate."""
    with ForwardHarness("bprobe", nginx) as h:
        reason = h.preflight(need_xrootd=True)
        if reason:
            print(f"fwd_b_token_forward_probe: probe SKIPPED ({reason})")
            return 0
        if SYS_XRDCP is None:
            print("fwd_b_token_forward_probe: probe SKIPPED (system xrdcp absent)")
            return 0
        if not h.mint_pki():
            return 0
        if not h.mint_token():
            print("fwd_b_token_forward_probe: probe SKIPPED (token authority)")
            return 0
        print("== PAIRING B token-forwarding EMPIRICAL PROBE (stock front -> brix-back roots://) ==")
        probe_results: list[tuple[str, str, str]] = []
        for variant in ("fwd", "pfc", "persona"):
            with h.cell():
                _probe_variant(h, variant, probe_results)
        print("\n---- probe summary ----")
        for variant, status, detail in probe_results:
            print(f"  {variant:<10} {status:<10} {detail}")
        return 0


# ===========================================================================
# run_transparent_relay.sh — root:// tap/relay passthrough + opcode logging
# ===========================================================================

def transparent_relay(nginx: Path | None = None) -> int:
    """Port of run_transparent_relay.sh."""
    if not os.access(BRIX_XRDFS, os.X_OK):
        print(f"run_transparent_relay: SKIP (missing {BRIX_XRDFS})")
        return 0
    with LiveRun("relay", nginx) as run:
        origin_port, relay_port = free_ports(2)
        origin, relay = run.mkdir("o"), run.mkdir("n")
        (origin / "root").mkdir()
        (origin / "logs").mkdir()
        (relay / "logs").mkdir()
        origin_conf = run.write(origin / "nginx.conf", f"""daemon on; error_log {origin}/logs/e.log info; pid {origin}/pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{origin_port}; brix_root on; brix_export {origin}/root; brix_auth none; }} }}
""")
        relay_conf = run.write(relay / "nginx.conf", f"""daemon on; error_log {relay}/logs/e.log info; pid {relay}/pid;
events {{ worker_connections 64; }}
stream {{ server {{
    listen {BIND_HOST}:{relay_port}; brix_root on;
    brix_transparent_proxy {HOST}:{origin_port};
}} }}
""")
        # Root harness: these configs pin no `user`, so the always-on
        # de-escalation drops workers to `nobody`, which cannot traverse the
        # 0700 mkdtemp tree — the export's confined-ops open EACCESes and the
        # node never serves. Open the tree for that worker (this direct launch
        # bypasses ForwardHarness._start_nginx, so the opening is repeated here).
        from cmdscripts import open_tree_for_worker  # noqa: PLC0415
        for prefix, conf, port in ((origin, origin_conf, origin_port), (relay, relay_conf, relay_port)):
            open_tree_for_worker(run.root, conf)
            result = _call([run.nginx, "-p", prefix, "-c", conf],
                           env_drop=("NGINX",))
            if result.returncode:
                print(f"start failed: {result.stderr.strip()}")
                return 2
            run.pidfiles.append(prefix / "pid")
        time.sleep(1)
        payload = origin / "root/f.bin"
        payload.write_bytes(os.urandom(300000))

        got = run.root / "relay_a.got"
        _call([BRIX_XRDFS, f"root://{HOST}:{relay_port}", "cat", "/f.bin"],
              stdout_to=got, timeout=60)
        stat = _call([BRIX_XRDFS, f"root://{HOST}:{relay_port}", "stat", "/f.bin"], timeout=60)
        time.sleep(0.5)
        relay_log = (relay / "logs/e.log").read_text(errors="replace")
        checks = [
            (got.is_file() and got.read_bytes() == payload.read_bytes(), "relay passthrough byte-exact"),
            (stat.returncode == 0, "stat via relay"),
            ('"op":"open"' in relay_log, "tap logged open"),
            ('"op":"stat"' in relay_log, "tap logged stat"),
        ]
        for passed, message in checks:
            print(f"  {'ok  ' if passed else 'FAIL'} {message}")
        return 0 if all(passed for passed, _ in checks) else 1


SCENARIOS = {
    "fwd-brix-brix": fwd_brix_brix,
    "fwd-brix-xrootd": fwd_brix_xrootd,
    "fwd-xrootd-brix": fwd_xrootd_brix,
    "token-forward-probe": token_forward_probe,
    "transparent-relay": transparent_relay,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"fwd matrix scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
