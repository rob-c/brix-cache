"""Direct Python ports of the brixMount/brixcvmfs FUSE and scvmfs live shell scenarios.

Ported shell scripts (kept in place; these are their Python replacements):
  tests/run_mount_cvmfs_live.sh      -> mount-cvmfs-live
  tests/run_brixmount_live.sh        -> brixmount-live
  tests/run_brixcvmfs_live.sh        -> brixcvmfs-live
  tests/run_brixcvmfs_atlas_live.sh  -> atlas-live
  tests/run_brixcvmfs_clever_live.sh -> clever-live
  tests/run_brixcvmfs_overlay.sh     -> overlay
  tests/run_scvmfs.sh                -> scvmfs

Every scenario mounts FUSE (or drives a live TLS listener) and therefore must
be opt-in gated by the collector; each unmounts in a finally block so an
aborted run never leaves an orphaned mount that wedges the fleet.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, SERVER_HOST

_PORTS = cmdscript_ports("brixcvmfs_live")


def scvmfs(nginx: Path | None = None) -> int:
    """Experimental scvmfs:// secure protocol: TLS parity, transport-neg,
    bearer authz negatives, and config-time layering enforcement."""
    with LiveRun("scvmfs", nginx) as run:
        if not run.nginx.exists():
            raise LiveSkip(f"nginx binary not found: {run.nginx}")
        if shutil.which("openssl") is None:
            raise LiveSkip("openssl not installed")
        run.mkdir("cache")
        run.mkdir("logs")
        mock_port, tls_port = _PORTS[1], _PORTS[2]  # was free_port(), free_port()

        # throwaway TLS identity for the listener
        run.call([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-keyout", run.root / "key.pem", "-out", run.root / "crt.pem",  # net-literal-allow: throwaway TLS cert subject CN
        ])
        # minimal issuer registry for the bearer negatives: one REAL RSA key
        # that simply never signed our test tokens.
        run.call(["openssl", "genrsa", "-out", run.root / "reg.pem", "2048"])
        modulus_out = run.call(["openssl", "rsa", "-in", run.root / "reg.pem", "-noout", "-modulus"]).stdout
        modulus_hex = modulus_out.strip().split("=", 1)[1]
        n_b64 = base64.urlsafe_b64encode(bytes.fromhex(modulus_hex)).rstrip(b"=").decode()
        run.write(
            run.root / "jwks.json",
            json.dumps({"keys": [{"kty": "RSA", "kid": "t1", "alg": "RS256", "use": "sig", "n": n_b64, "e": "AQAB"}]}),
        )
        run.write(
            run.root / "scitokens.cfg",
            "[Global]\naudience = https://wlcg.cern.ch/jwt/v1/any\n\n"
            f"[Issuer test]\nissuer = https://tokens.example\nbase_path = /cvmfs\njwks_file = {run.root}/jwks.json\n",
        )

        run.spawn([sys.executable, REPO_ROOT / "tests/cvmfs/mock_stratum1.py", "--port", str(mock_port), "--objects", "4", "--seed", "55"])
        from lib_py.util import wait_tcp

        if not wait_tcp(BIND_HOST, mock_port, 10):
            raise LiveFailure(f"mock Stratum-1 did not listen on {mock_port}")
        objects = json.loads(run.call(["curl", "-sS", f"http://{HOST}:{mock_port}/ctl/objects"]).stdout)
        obj = objects[0]

        def mkconf(authz: str, extra: str) -> Path:
            return run.write(
                run.root / "nginx.conf",
                f"""daemon on; error_log {run.root}/logs/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen {BIND_HOST}:{tls_port} ssl;
    ssl_certificate     {run.root}/crt.pem;
    ssl_certificate_key {run.root}/key.pem;
    location /cvmfs/ {{
        brix_storage_backend http://{HOST}:{mock_port};
        brix_cache_store posix:{run.root}/cache;
        brix_cvmfs on;
        brix_scvmfs on;
        brix_scvmfs_authz {authz};
{extra}
    }}
}} }}
""",
            )

        # 1: TLS parity (authz none)
        config = mkconf("none", "")
        run.start_nginx(run.root, config, tls_port)
        tls_body = run.curl_bytes(f"https://{HOST}:{tls_port}{obj}", "-k")
        ref_body = run.curl_bytes(f"http://{HOST}:{mock_port}{obj}")
        # 2: plain HTTP to the TLS port is refused, not served
        plain_status = run.curl_status(f"http://{HOST}:{tls_port}{obj}")
        # 3: bearer authz-negs
        run.stop_nginx(run.root)
        config = mkconf("bearer", f"        brix_scvmfs_token_issuers {run.root}/scitokens.cfg;")
        run.start_nginx(run.root, config, tls_port)
        missing_status = run.curl_status(f"https://{HOST}:{tls_port}{obj}", "-k")
        garbage_status = run.curl_status(f"https://{HOST}:{tls_port}{obj}", "-k", "-H", "Authorization: Bearer not.a.token")
        # positive bearer acceptance is exercised by the fleet token fixtures,
        # not by this port (parity with the shell script's scope).
        # 4: layering enforced at config time
        bad = run.write(
            run.root / "bad.conf",
            f"""events {{ worker_connections 32; }}
http {{ server {{ listen {BIND_HOST}:{tls_port} ssl;
    ssl_certificate {run.root}/crt.pem; ssl_certificate_key {run.root}/key.pem;
    location / {{ brix_scvmfs on; }} }} }}
""",
        )
        layering = run.call([run.nginx, "-t", "-c", bad, "-p", run.root], check=False)
        return _checks([
            (tls_body == ref_body, "scvmfs TLS parity byte-exact"),
            (plain_status == 400, f"plain HTTP on scvmfs listener refused (got {plain_status})"),
            (missing_status == 401 and garbage_status == 401, f"bearer: missing/garbage token -> 401 ({missing_status}/{garbage_status})"),
            (layering.returncode != 0, "scvmfs without cvmfs rejected by nginx -t"),
        ])


SCENARIOS = {
    "mount-cvmfs-live": mount_cvmfs_live,
    "brixmount-live": brixmount_live,
    "brixcvmfs-live": brixcvmfs_live,
    "negfilter-live": negfilter_live,
    "atlas-live": atlas_live,
    "clever-live": clever_live,
    "overlay": overlay,
    "scvmfs": scvmfs,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveSkip as exc:
        print(f"SKIP: {exc}")
        return 0
    except LiveFailure as exc:
        print(f"brixcvmfs live scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
