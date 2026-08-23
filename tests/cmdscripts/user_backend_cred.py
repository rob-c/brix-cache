"""Direct Python ports of the per-user backend-credential live shell suites.

Ports ``run_user_backend_cred.sh`` (base), ``run_user_backend_cred_root.sh``
(root), ``run_user_backend_cred_ns.sh`` (ns), ``run_user_backend_cred_p2.sh``
(p2), and ``run_multiuser_authz.sh`` (multiuser-authz).  Every externally
visible assertion of the shell scripts is reproduced as a Python check; ports
come from the fixed ``cmdscripts`` band (``fleet_ports.CMDSCRIPTS_PORTS`` via
the module ``_PORTS`` slice) and all scratch state lives under a ``LiveRun``
root that the context manager reaps.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, CA_CERT, CA_DIR, CA_KEY, HOST, PROXY_STD, SERVER_CERT, SERVER_KEY

_PORTS = cmdscript_ports("user_backend_cred")

SKIP = 77  # distinct scenario outcome: prerequisites unavailable

XRDCP = REPO_ROOT / "client/bin/xrdcp"
XRDFS = REPO_ROOT / "client/bin/xrdfs"

_KEY_RE = re.compile(r"key=(x5h-[0-9a-f]+|[A-Za-z0-9@._-]+)")
_DN_A_RE = r"Test.User|Test\\x20User"
_DN_SVC_RE = r"SVC.Proxy"
_DENY_LOG_RE = r"fallback=deny.*refusing|per-user backend credential.*fallback=deny"


class Suite:
    """ok/bad ledger matching the shell scripts' output convention."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.failed = False

    def ok(self, message: str) -> None:
        print(f"  ok   {message}")

    def bad(self, message: str) -> None:
        print(f"  FAIL {message}")
        self.failed = True

    def note(self, message: str) -> None:
        print(f"  NOTE {message}")

    def check(self, passed: bool, ok_msg: str, bad_msg: str | None = None) -> bool:
        if passed:
            self.ok(ok_msg)
        else:
            self.bad(bad_msg or ok_msg)
        return passed

    def finish(self) -> int:
        print("")
        print(f"{self.name}: {'FAILURES' if self.failed else 'ALL PASS'}")
        return 1 if self.failed else 0


def _skip(message: str) -> int:
    print(f"SKIP: {message}")
    return SKIP


def _read(path: Path | str) -> str:
    path = Path(path)
    return path.read_text(errors="replace") if path.exists() else ""


def _grep(path: Path | str, pattern: str) -> bool:
    return re.search(pattern, _read(path)) is not None


def _count(path: Path | str, pattern: str) -> int:
    return sum(1 for line in _read(path).splitlines() if re.search(pattern, line))


def _last_line(path: Path | str, pattern: str) -> str:
    matches = [line for line in _read(path).splitlines() if re.search(pattern, line)]
    return matches[-1] if matches else ""


def _truncate(path: Path | str) -> None:
    Path(path).write_text("")


def _quiet(argv: list[str | Path], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(a) for a in argv],
        env={**os.environ, **(env or {})},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _curl_code(url: str, *extra: str | Path, cert: Path | None = None, key: Path | None = None, output: Path | None = None) -> str:
    args: list[str] = ["curl", "-sk", "--max-time", "25", "-o", str(output or os.devnull), "-w", "%{http_code}"]
    if cert is not None:
        args += ["--cert", str(cert), "--key", str(key or cert)]
    result = _quiet([*args, *[str(item) for item in extra], url])
    return result.stdout.strip()


def _wait_ready(url: str, tries: int = 20) -> bool:
    for _ in range(tries):
        probe = _quiet(["curl", "-sk", "-o", os.devnull, "--max-time", "1", f"{url}/"])
        if probe.returncode == 0:
            return True
        time.sleep(0.2)
    return False


def _ensure_pki(run: LiveRun) -> str | None:
    """Provision the shared test PKI if absent/expired.  Returns a skip reason or None."""
    # Refresh only the proxy when the CA/hostcert exist — a full blitz would
    # regenerate the CA and desync the standing fleet, breaking every concurrent
    # GSI/TLS test. See live_common.refresh_shared_pki.
    from cmdscripts.live_common import refresh_shared_pki  # noqa: PLC0415
    ok, msg = refresh_shared_pki(run.root, want_proxy=True)
    if not ok:
        return msg
    if not Path(CA_KEY).is_file():
        return f"CA key not found ({CA_KEY})"
    return None


def _mint_ee(run: LiveRun, out_dir: Path, subject: str) -> tuple[Path, Path] | None:
    """Mint a plain end-entity cert off the shared test CA.  Returns (cert, key)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    key, req, cert = out_dir / "key.pem", out_dir / "req.pem", out_dir / "cert.pem"
    run.call(
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-subj", subject, "-out", req],
        check=False,
    )
    signed = run.call(
        ["openssl", "x509", "-req", "-in", req, "-CA", CA_CERT, "-CAkey", CA_KEY,
         "-set_serial", "0x" + os.urandom(8).hex(), "-days", "2", "-out", cert],
        check=False,
    )
    if signed.returncode != 0 or not cert.exists():
        return None
    return cert, key


def _combine(cert: Path, key: Path, out: Path) -> Path:
    out.write_text(cert.read_text() + key.read_text())
    out.chmod(0o600)
    return out


def _key_from_dn(run: LiveRun, proxy: Path | str) -> str:
    """Same derivation as ucred.c: x5h-<sha256hex32> over the oneline subject."""
    subject = run.call(["openssl", "x509", "-in", proxy, "-noout", "-subject", "-nameopt", "oneline"], check=False).stdout
    dn = re.sub(r"^subject= *", "", subject.strip())
    return "x5h-" + hashlib.sha256(dn.encode()).hexdigest()[:32]


def _learn_key(run: LiveRun, log: Path, proxy: Path | str, *, last: bool = False) -> str:
    matches = _KEY_RE.findall(_read(log))
    if matches:
        return matches[-1] if last else matches[0]
    return _key_from_dn(run, proxy)


def _install_cred(source: Path | str, dest: Path) -> None:
    shutil.copyfile(source, dest)
    dest.chmod(0o644)


def _start_prefixed(run: LiveRun, prefix: Path, conf: Path) -> tuple[bool, str]:
    # These per-scenario configs carry no `user` directive, so under the root
    # harness the master starts as root and the always-on de-escalation drops
    # workers to `nobody` — which cannot traverse the 0700 mkdtemp tree, write
    # the export/stage trees, or read the root-owned credential files.
    # run.call() bypasses cmdscripts.run(), so mirror its tree-opening here
    # (whole LiveRun root: creds/ and the minted user proxies are siblings of
    # the nginx prefix).
    from cmdscripts import open_tree_for_worker
    open_tree_for_worker(run.root, conf)
    result = run.call([str(run.nginx), "-p", str(prefix), "-c", str(conf)], check=False)
    if result.returncode == 0:
        pidfile = prefix / "nginx.pid"
        if pidfile not in run.pidfiles:
            run.pidfiles.append(pidfile)
        return True, ""
    return False, result.stderr or result.stdout


def _stop_prefixed(prefix: Path, wait: float = 0.7) -> None:
    pidfile = prefix / "nginx.pid"
    try:
        os.kill(int(pidfile.read_text().strip()), signal.SIGTERM)
    except (OSError, ValueError):
        return
    time.sleep(wait)


def _process_holds_path(entry, prefix):
    try:
        if "nginx" not in os.readlink(entry / "exe"):
            return False
        for fd in (entry / "fd").iterdir():
            if os.readlink(fd).startswith(prefix):
                return True
    except OSError:
        return False
    return False


def _kill_orphans(subtree: Path) -> None:
    """Kill orphaned nginx workers holding files open under subtree (post kill -9)."""
    prefix = str(subtree)
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        if _process_holds_path(entry, prefix):
            os.kill(int(entry.name), signal.SIGTERM)


def _origin_conf(prefix: Path, port: int) -> Path:
    conf = prefix / "nginx.conf"
    conf.write_text(f"""daemon on;
error_log {prefix}/logs/e.log info;
pid {prefix}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{
    listen {BIND_HOST}:{port};
    brix_root on;
    brix_export {prefix}/root;
    brix_allow_write on;
    brix_auth gsi;
    brix_certificate     {SERVER_CERT};
    brix_certificate_key {SERVER_KEY};
    brix_trusted_ca      {CA_CERT};
}} }}
""")
    return conf


def _write_expired_cert(path: Path) -> bool:
    """Write a verifiably-expired self-signed cert (2020-01-01..2020-01-02)."""
    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired-test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2020, 1, 2))
            .sign(key, hashes.SHA256())
        )
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return True
    except Exception:
        return False


# ===========================================================================
# Scenario: base (run_user_backend_cred.sh) — davs frontend, 7 assertions.
# ===========================================================================

def _base_front_conf(prefix: Path, port: int, origin_port: int, creds: Path, fallback: str, flush: str, service_proxy: Path | str) -> Path:
    conf = prefix / "nginx.conf"
    conf.write_text(f"""daemon on;
error_log {prefix}/logs/e.log info;
pid {prefix}/nginx.pid;
env BRIX_STAGE_JOURNAL_DIR={prefix}/journal;
env BRIX_XFER_AUDIT_LOG={prefix}/logs/xfer_audit.log;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {prefix}/logs/access.log;
    client_body_temp_path {prefix}/export;
    brix_credential origin {{ x509_proxy {service_proxy}; ca_dir {CA_DIR}; }}
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
            brix_export {prefix}/export;
            brix_webdav_cafile {CA_CERT};
            brix_webdav_auth required;
            brix_storage_backend root://{HOST}:{origin_port};
            brix_storage_credential origin;
            brix_storage_credential_dir {creds};
            brix_storage_credential_fallback {fallback};
            brix_stage on;
            brix_stage_store posix:{prefix}/stage;
            brix_stage_flush {flush};
        }}
    }}
}}
""")
    return conf

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "user_backend_cred_part2.py",
                    "user_backend_cred_part3.py", "user_backend_cred_part4.py",
                    "user_backend_cred_part5.py")
