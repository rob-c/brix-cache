"""Direct Python port of tests/demo_dashboard_live.sh.

Live web-monitoring-portal demo (sustained load): ensures the nginx-xrootd
gateway (root:// stream + web dashboard) is up, does one 100 MB IN (PUT) + OUT
(GET) round-trip over root:// and verifies it byte-exact, seeds a bounded
read-source object, then detaches NSTREAMS throttled xrdcp workers so the
dashboard shows a constant churn of live transfer rows.

Every transfer is pipe-throttled: xrdcp reads/writes stdin/stdout through an
in-process rate limiter (the shell used a helper python script piped around
xrdcp; here the pacing loop feeds/reads the xrdcp pipe directly), so the wire
rate is smooth and the portal never shows a full-speed burst.

Stop the live traffic:  kill -- -$(cat /tmp/xrd-dash-demo.pid)
Stop the gateway:       tests/manage_test_servers.sh stop
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

from cmdscripts.live_common import LiveRun

TESTS_DIR = Path(__file__).resolve().parents[1]

ROOT_PORT = int(os.environ.get("DEMO_ROOT_PORT", "11094"))     # anonymous root:// (read + write)
DASH_PORT = int(os.environ.get("DEMO_DASH_PORT", "8445"))      # dedicated dashboard portal
DASH_GATE_PORT = int(os.environ.get("DEMO_DASH_GATE_PORT", "8443"))
ROOT_URL = f"root://localhost:{ROOT_PORT}"
DASH_HOST_PORT = f"localhost:{DASH_PORT}"
DASH_URL = f"https://{DASH_HOST_PORT}/brix/"
DASH_PASS = "testpassword"                                     # from the test config
DEMO_OBJ = "dashboard_demo_100mb.bin"
SIZE_BYTES = int(os.environ.get("DEMO_SIZE_BYTES", str(100 * 1024 * 1024)))  # 100 MiB
GEN_PIDFILE = Path("/tmp/xrd-dash-demo.pid")
SRC = Path("/tmp/xrd-dash-demo-src-100mb.bin")   # persistent: the detached
                                                 # generator keeps reading it
NGINX_BIN = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
TEST_CONF = Path("/tmp/xrd-test/conf/nginx.conf")
TEST_PKI_CERT = Path("/tmp/xrd-test/pki/server/hostcert.pem")

_CHUNK = 8192


def _say(text: str) -> None:
    print(f"\n{text}", flush=True)


def _listening(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# Pipe-throttled xrdcp transfers (replaces the shell's thr_put / thr_get).
# Backpressure on the pipe paces the wire to a smooth rate.
# --------------------------------------------------------------------------- #
def _pace(sent: int, rate_bps: int, t0: float) -> None:
    lag = sent / rate_bps - (time.time() - t0)
    if lag > 0:
        time.sleep(lag)


def throttled_put(rate_bps: int, source, obj: str, *, limit: int | None = None,
                  root_url: str = ROOT_URL) -> int:
    """`throttle < SRC | xrdcp -f - root://...//obj`, paced to rate_bps.

    `source` is a Path; `limit` caps the bytes fed (the shell's `head -c`).
    """
    xrdcp = shutil.which("xrdcp") or "xrdcp"
    proc = subprocess.Popen([xrdcp, "-f", "-", f"{root_url}//{obj}"],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0, sent = time.time(), 0
    try:
        with Path(source).open("rb") as stream:
            remaining = limit
            while True:
                want = _CHUNK if remaining is None else min(_CHUNK, remaining)
                if want == 0:
                    break
                block = stream.read(want)
                if not block:
                    break
                proc.stdin.write(block)
                proc.stdin.flush()
                sent += len(block)
                if remaining is not None:
                    remaining -= len(block)
                _pace(sent, rate_bps, t0)
    except BrokenPipeError:
        pass
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
    return proc.wait()


def throttled_get(rate_bps: int, obj: str, dest: Path | None, *,
                  root_url: str = ROOT_URL) -> int:
    """`xrdcp -f root://...//obj - | throttle > DST`, paced to rate_bps.

    `dest=None` discards the bytes (the sustained OUT streams).
    """
    xrdcp = shutil.which("xrdcp") or "xrdcp"
    proc = subprocess.Popen([xrdcp, "-f", f"{root_url}//{obj}", "-"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    t0, got = time.time(), 0
    sink = Path(dest).open("wb") if dest is not None else None
    try:
        while True:
            block = proc.stdout.read(_CHUNK)
            if not block:
                break
            if sink is not None:
                sink.write(block)
            got += len(block)
            _pace(got, rate_bps, t0)
    finally:
        if sink is not None:
            sink.close()
    return proc.wait()


# --------------------------------------------------------------------------- #
# Gateway + dashboard plumbing
# --------------------------------------------------------------------------- #
def _ensure_gateway(run: LiveRun) -> None:
    """Start the prepared test gateway when :ROOT_PORT is not listening yet."""
    if _listening(ROOT_PORT):
        return
    if NGINX_BIN.exists() and os.access(NGINX_BIN, os.X_OK) and TEST_CONF.is_file() and TEST_PKI_CERT.is_file():
        _say(f"Starting nginx-xrootd (root:// + dashboard) from {TEST_CONF} ...")
        run.call([NGINX_BIN, "-p", "/tmp/xrd-test", "-c", TEST_CONF], check=False)
    else:
        _say("Preparing test environment + servers (first run)...")
        try:
            from cmdscripts import manage_test_servers
            manage_test_servers.main(["start"])   # full-fleet extras; may fail —
        except Exception as exc:                  # noqa: BLE001 — gate on ports below
            print(f"fleet start failed (continuing to port gate): {exc}", file=sys.stderr)
    time.sleep(1)


def _dashboard_login_cookie(run: LiveRun) -> str:
    proc = run.call([
        "curl", "-sk", "-i", "-X", "POST", "-d", f"password={DASH_PASS}",
        f"https://{DASH_HOST_PORT}/brix/login",
    ], check=False)
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if parts and parts[0].lower() == "set-cookie:" and len(parts) > 1:
            return parts[1].rstrip(";").strip()
    return ""


def _stop_previous_generator() -> None:
    if not GEN_PIDFILE.exists():
        return
    try:
        old = int(GEN_PIDFILE.read_text().strip())
    except ValueError:
        return
    for target in (-old, old):
        try:
            os.kill(target, signal.SIGTERM)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Sustained multi-stream generator (detached; the shell's setsid block)
# --------------------------------------------------------------------------- #
def generate(minutes: float, streams: int, rate_bps: int, xfer_bytes: int,
             src: str, root_url: str) -> int:
    """Worker loops: odd streams READ the shared source, even streams WRITE a
    per-stream object; each bounded transfer is immediately replaced (churn)."""
    import threading

    end = time.time() + minutes * 60

    def worker(n: int) -> None:
        while time.time() < end:
            if n % 2 == 1:      # OUT: read XB from the shared source
                throttled_get(rate_bps, "dash_read_src.bin", None, root_url=root_url)
            else:               # IN: write XB to a per-stream object
                throttled_put(rate_bps, src, f"dash_stream_{n}.bin",
                              limit=xfer_bytes, root_url=root_url)

    threads = [threading.Thread(target=worker, args=(n,), daemon=False)
               for n in range(1, streams + 1)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    GEN_PIDFILE.unlink(missing_ok=True)
    return 0


def _spawn_generator(minutes: float, streams: int, rate_bps: int, xfer_bytes: int) -> int:
    """Detach the generator in its own session so it outlives this process."""
    _stop_previous_generator()
    proc = subprocess.Popen(
        [sys.executable, "-m", "cmdscripts.dashboard_demo_live", "generate",
         "--minutes", str(minutes), "--streams", str(streams),
         "--rate-bps", str(rate_bps), "--xfer-bytes", str(xfer_bytes),
         "--src", str(SRC), "--root-url", ROOT_URL],
        cwd=str(TESTS_DIR),
        env={**os.environ, "PYTHONPATH": str(TESTS_DIR)},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    GEN_PIDFILE.write_text(f"{proc.pid}\n")
    return proc.pid


# --------------------------------------------------------------------------- #
# Full demo flow
# --------------------------------------------------------------------------- #
def demo(live_minutes: float | None = None) -> int:
    live_minutes = float(os.environ.get("LIVE_MINUTES", "20")) if live_minutes is None else live_minutes
    streams = int(os.environ.get("NSTREAMS", "5"))
    rate_bps = int(os.environ.get("RATE_BPS", "100000"))
    seed_rate_bps = int(os.environ.get("SEED_RATE_BPS", "5000000"))
    xfer_bytes = int(os.environ.get("XFER_BYTES", str(8 * 1024 * 1024)))

    if shutil.which("xrdcp") is None:
        print("SKIP: xrdcp not found (install xrootd-client)")
        return 0

    checks: list[tuple[bool, str]] = []

    def check(ok: bool, label: str) -> bool:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
        checks.append((bool(ok), label))
        return bool(ok)

    with LiveRun("dash-demo") as run:
        # 1) Gateway (root:// + dashboard) up.
        _ensure_gateway(run)
        if not check(_listening(ROOT_PORT), f"root:// (:{ROOT_PORT}) listening"):
            return 1
        if not check(_listening(DASH_GATE_PORT), f"dashboard (:{DASH_GATE_PORT}) listening"):
            return 1

        # 2) Dashboard portal + login sanity.
        code = run.curl_status(DASH_URL, "-k")
        check(code != 0, f"dashboard reachable at {DASH_URL} (portal http={code})")
        cookie = _dashboard_login_cookie(run)
        snap = run.curl_status(f"https://{DASH_HOST_PORT}/brix/api/v1/snapshot",
                               "-k", "--cookie", cookie)
        _say(f"Dashboard OK  (portal http={code}, api/v1/snapshot http={snap})")

        # 3) 100 MB source file (persistent — the detached generator reads it).
        if not SRC.exists() or SRC.stat().st_size == 0:
            _say("Generating 100 MB test file...")
            with SRC.open("wb") as stream:
                remaining = SIZE_BYTES
                while remaining > 0:
                    block = os.urandom(min(1 << 20, remaining))
                    stream.write(block)
                    remaining -= len(block)

        # 4+5) Throttled IN (PUT) + OUT (GET) round-trip over root://.
        out = run.root / "out.bin"
        seed_mbs = seed_rate_bps // 1000000
        _say(f"IN   ->  throttled PUT 100 MB (~{seed_mbs} MB/s)  {SRC}  ->  {ROOT_URL}//{DEMO_OBJ}")
        t0 = time.time()
        if not check(throttled_put(seed_rate_bps, SRC, DEMO_OBJ) == 0, "throttled PUT succeeded"):
            return 1
        _say(f"OUT  <-  throttled GET 100 MB (~{seed_mbs} MB/s)  {ROOT_URL}//{DEMO_OBJ}  ->  {out}")
        if not check(throttled_get(seed_rate_bps, DEMO_OBJ, out) == 0, "throttled GET succeeded"):
            return 1
        t1 = time.time()

        # 6) Round-trip must be byte-exact.
        same = out.exists() and out.stat().st_size == SRC.stat().st_size and out.read_bytes() == SRC.read_bytes()
        if not check(same, f"round-trip byte-exact (100 MB in + out in {int((t1 - t0) * 1000)} ms)"):
            return 1

        # 7) Seed the bounded read-source object all OUT streams pull from.
        xfer_mb = xfer_bytes // 1024 // 1024
        _say(f"Seeding read-source object ({xfer_mb} MiB, pipe-throttled, ~{seed_mbs} MB/s)...")
        seeded = throttled_put(seed_rate_bps, SRC, "dash_read_src.bin", limit=xfer_bytes) == 0
        if not check(seeded, "read-source object seeded"):
            return 1

        # 8) Detached sustained multi-stream traffic.
        gen_pid = _spawn_generator(live_minutes, streams, rate_bps, xfer_bytes)
        check(gen_pid > 0, f"stream generator detached (pid {gen_pid})")

        # 9) Point the user at the LIVE portal.
        print(f"""
============================================================================
  THE WEB MONITORING PORTAL IS LIVE — open it in your browser now:

         {DASH_URL}

  Login password:  {DASH_PASS}
  Self-signed TLS cert — accept the browser's security warning.

  Every transfer is pipe-throttled for a smooth wire rate (no bursts):
    * the opening round-trip + seeding ran at ~{seed_mbs} MB/s,
    * {streams} parallel xrdcp workers (alternating in/out) now run at
      {rate_bps // 1000} kB/s each, every transfer moving {xfer_mb} MiB
      (~{xfer_bytes // rate_bps}s) for {live_minutes} min.
  Stream-group leader pid: {gen_pid}

  Stop the live traffic:   kill -- -{gen_pid}    (or: kill -- -$(cat {GEN_PIDFILE}))
  Stop the gateway:        tests/manage_test_servers.sh stop
============================================================================
""")
    return 0 if all(ok for ok, _ in checks) else 1


SCENARIOS = {"demo": demo}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    demo_parser = sub.add_parser("demo", help="full live-dashboard demo flow")
    demo_parser.add_argument("live_minutes", nargs="?", type=float, default=None)
    gen = sub.add_parser("generate", help="internal: detached traffic generator")
    gen.add_argument("--minutes", type=float, required=True)
    gen.add_argument("--streams", type=int, required=True)
    gen.add_argument("--rate-bps", type=int, required=True)
    gen.add_argument("--xfer-bytes", type=int, required=True)
    gen.add_argument("--src", required=True)
    gen.add_argument("--root-url", required=True)
    ns = parser.parse_args(argv)
    if ns.command == "generate":
        return generate(ns.minutes, ns.streams, ns.rate_bps, ns.xfer_bytes, ns.src, ns.root_url)
    return demo(getattr(ns, "live_minutes", None))


if __name__ == "__main__":
    raise SystemExit(main())
