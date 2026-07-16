"""Direct Python port of run_cred_metrics.sh — Prometheus counters for credential outcomes.

Verifies that ``brix_cred_select_user_total``, ``brix_cred_select_fallback_total``,
and ``brix_cred_select_deny_total`` are exported on /metrics and move when the
corresponding credential outcomes fire at the VFS credential gate.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import time

from cmdscripts.live_common import LiveFailure, LiveRun
from cmdscripts.user_backend_cred import (
    SKIP,
    Suite,
    _curl_code,
    _ensure_pki,
    _grep,
    _install_cred,
    _learn_key,
    _mint_ee,
    _origin_conf,
    _quiet,
    _skip,
    _start_prefixed,
    _stop_prefixed,
    _wait_ready,
)
from settings import CA_CERT, CA_DIR, PROXY_STD, SERVER_CERT, SERVER_KEY, free_ports


def _metric_sum(family: str, text: str) -> int:
    total = 0.0
    for line in text.splitlines():
        if line.startswith(family):
            try:
                total += float(line.split()[-1])
            except (IndexError, ValueError):
                pass
    return int(total)


def _front_conf(prefix: Path, port: int, metrics_port: int, origin_port: int, creds: Path, fallback: str) -> Path:
    conf = prefix / "nginx.conf"
    conf.write_text(f"""daemon on;
error_log {prefix}/logs/e.log info;
pid {prefix}/nginx.pid;
env BRIX_STAGE_JOURNAL_DIR={prefix}/journal;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {prefix}/logs/access.log;
    client_body_temp_path {prefix}/export;
    brix_credential origin {{ x509_proxy {PROXY_STD}; ca_dir {CA_DIR}; }}
    server {{
        listen 127.0.0.1:{port} ssl;
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
            brix_storage_backend root://127.0.0.1:{origin_port};
            brix_storage_credential origin;
            brix_storage_credential_dir {creds};
            brix_storage_credential_fallback {fallback};
            brix_stage on;
            brix_stage_store posix:{prefix}/stage;
            brix_stage_flush sync;
        }}
    }}
    server {{
        listen 127.0.0.1:{metrics_port};
        location /metrics {{ brix_metrics on; }}
    }}
}}
""")
    return conf


def counters(nginx: Path | None = None) -> int:
    suite = Suite("run_cred_metrics")
    with LiveRun("ucredm", nginx) as run:
        skip = _ensure_pki(run)
        if skip:
            return _skip(skip)
        origin, front = run.mkdir("o"), run.mkdir("f")
        for name in ("logs", "root"):
            (origin / name).mkdir(exist_ok=True)
        for name in ("logs", "export", "stage", "journal"):
            (front / name).mkdir(exist_ok=True)
        creds = run.mkdir("creds")
        creds.chmod(0o777)

        minted = _mint_ee(run, run.mkdir("b"), "/DC=test/DC=xrootd/CN=Cred Metrics User B/CN=99998")
        if minted is None:
            return _skip("user-B cert mint failed")
        b_cert, b_key = minted

        payload = run.root / "ucredm_payload.bin"
        payload.write_bytes(os.urandom(4096))

        cmop, cmfp, cmmp = free_ports(3)
        started, detail = _start_prefixed(run, origin, _origin_conf(origin, cmop))
        if not started:
            return _skip(f"origin start failed: {detail}")
        time.sleep(0.5)
        flog = front / "logs/e.log"
        urlf = f"https://127.0.0.1:{cmfp}"

        def front_start(fallback: str) -> bool:
            conf = _front_conf(front, cmfp, cmmp, cmop, creds, fallback)
            started, detail = _start_prefixed(run, front, conf)
            if not started:
                print(f"SKIP: frontend start failed ({fallback}): {detail}")
                return False
            time.sleep(0.5)
            _wait_ready(urlf)
            return True

        def scrape() -> str:
            return _quiet(["curl", "-s", "--max-time", "5", f"http://127.0.0.1:{cmmp}/metrics"]).stdout

        # ---- step 0: learn the derived key for user A ---------------------------
        print("--- step 0: learning derived key for user A ---")
        if not front_start("deny"):
            return SKIP
        _curl_code(f"{urlf}/probe_key.bin", "-T", payload, cert=Path(PROXY_STD))
        time.sleep(0.3)
        a_key = _learn_key(run, flog, PROXY_STD)
        if not a_key:
            suite.bad("could not derive key for user A")
            return suite.finish()
        print(f"  user-A credential stem: {a_key}")
        _install_cred(PROXY_STD, creds / f"{a_key}.pem")
        _stop_prefixed(front)

        # ---- assertion 1: user A with cred → cred_select_user_total++ ------------
        print("--- assertion 1: user A with cred → cred_select_user_total increments ---")
        if not front_start("deny"):
            return SKIP
        before = scrape()
        if not re.search(r"^brix_cred_select_user_total", before, re.MULTILINE):
            suite.bad("1: brix_cred_select_user_total family absent from /metrics (expected before implementation)")
            suite.bad("2: brix_cred_select_fallback_total family absent")
            suite.bad("3: brix_cred_select_deny_total family absent")
            print("")
            print("run_cred_metrics: FAIL (expected — families not yet implemented)")
            return 1
        user_before = _metric_sum("brix_cred_select_user_total", before)
        code = _curl_code(f"{urlf}/cm1.bin", "-T", payload, cert=Path(PROXY_STD))
        suite.check(code in ("201", "204"), f"1a: A PUT accepted (code={code})",
                    f"1a: A PUT → {code} (want 201/204)")
        time.sleep(0.3)
        after = scrape()
        user_after = _metric_sum("brix_cred_select_user_total", after)
        suite.check(user_after > user_before,
                    f"1b: cred_select_user_total incremented ({user_before} → {user_after})",
                    f"1b: cred_select_user_total did not increment ({user_before} → {user_after})")
        _stop_prefixed(front)

        # ---- assertion 2: user B, no cred, allow → cred_select_fallback_total++ --
        print("--- assertion 2: user B (no cred), allow → cred_select_fallback_total increments ---")
        if not front_start("allow"):
            return SKIP
        before = scrape()
        fallback_before = _metric_sum("brix_cred_select_fallback_total", before)
        code = _curl_code(f"{urlf}/cm2.bin", "-T", payload, cert=b_cert, key=b_key)
        suite.check(code in ("201", "204"),
                    f"2a: B PUT allowed via fallback (code={code})",
                    f"2a: B PUT fallback → {code} (want 201/204)")
        time.sleep(0.3)
        after = scrape()
        fallback_after = _metric_sum("brix_cred_select_fallback_total", after)
        suite.check(fallback_after > fallback_before,
                    f"2b: cred_select_fallback_total incremented ({fallback_before} → {fallback_after})",
                    f"2b: cred_select_fallback_total did not increment ({fallback_before} → {fallback_after})")
        _stop_prefixed(front)

        # ---- assertion 3: user B, no cred, deny → cred_select_deny_total++ -------
        print("--- assertion 3: user B (no cred), deny → cred_select_deny_total increments ---")
        if not front_start("deny"):
            return SKIP
        before = scrape()
        deny_before = _metric_sum("brix_cred_select_deny_total", before)
        code = _curl_code(f"{urlf}/cm3.bin", "-T", payload, cert=b_cert, key=b_key)
        suite.check(code == "403", "3a: B PUT denied (403)", f"3a: B PUT → {code} (want 403)")
        time.sleep(0.3)
        after = scrape()
        deny_after = _metric_sum("brix_cred_select_deny_total", after)
        suite.check(deny_after > deny_before,
                    f"3b: cred_select_deny_total incremented ({deny_before} → {deny_after})",
                    f"3b: cred_select_deny_total did not increment ({deny_before} → {deny_after})")

        print("")
        print("--- sample /metrics output ---")
        sample = [line for line in after.splitlines() if line.startswith("brix_cred_select_")]
        for line in sample or ["  (no cred_select_ lines)"]:
            print(line)
        _stop_prefixed(front)

        return suite.finish()


SCENARIOS = {"counters": counters}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"cred metrics scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
