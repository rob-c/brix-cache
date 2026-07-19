"""Direct Python ports for the tap-proxy / env-proxy live shell scenarios.

Ports ``run_tap_proxy.sh``, ``run_tap_proxy_gsi.sh``,
``run_tap_proxy_gsi_hybrid.sh``, and ``run_proxy_env_live.sh``.  Each public
scenario keeps the shell test's own acceptance sequence and assertions; the
shared code below only removes repeated PKI/nginx/process plumbing.
"""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import shutil
import socket as socket_module
import struct
import subprocess
import sys
import time

from cmdscripts.gsi_trust_live import ensure_shared_pki
from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from lib_py.util import wait_tcp
from settings import CA_CERT, CA_DIR, SERVER_CERT, SERVER_KEY, TEST_ROOT, free_ports

XRDFS = REPO_ROOT / "client" / "bin" / "xrdfs"
OUR_XRDCP = Path(os.environ.get("OUR_XRDCP", REPO_ROOT / "client" / "bin" / "xrdcp"))
STOCK_XRDCP = Path("/usr/bin/xrdcp")
PROXY_STD = Path(TEST_ROOT) / "pki" / "user" / "proxy_std.pem"
USERCERT = Path(TEST_ROOT) / "pki" / "user" / "usercert.pem"


def _result(checks: list[tuple[bool, str]]) -> int:
    for passed, message in checks:
        print(f"  {'ok  ' if passed else 'FAIL'} {message}")
    return 0 if all(passed for passed, _ in checks) else 1


def _skip(reason: str) -> int:
    print(f"SKIP: {reason}")
    return 0


def _grep(path: Path, needle: str) -> bool:
    return path.exists() and needle in path.read_text(errors="replace")


def _same_bytes(left: Path, right: Path) -> bool:
    return left.exists() and right.exists() and left.read_bytes() == right.read_bytes()


def _origin_stream_conf(run: LiveRun, prefix: Path, port: int, *, gsi: bool) -> Path:
    auth = (
        f"""brix_auth gsi;
    brix_certificate     {SERVER_CERT};
    brix_certificate_key {SERVER_KEY};
    brix_trusted_ca      {CA_CERT};"""
        if gsi
        else "brix_auth none;\n    brix_allow_write on; brix_upload_resume off;"
    )
    return run.write(
        prefix / "nginx.conf",
        f"""daemon on; error_log {prefix}/logs/e.log info; pid {prefix}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{port}; brix_root on; brix_export {prefix}/root;
    {auth}
}} }}
""",
    )


def _tap_proxy_conf(run: LiveRun, prefix: Path, port: int, upstream_port: int, *, gsi: bool) -> Path:
    if gsi:
        body = f"""    brix_auth gsi;
    brix_gsi_signed_dh require;
    brix_tpc_delegate on;
    brix_certificate     {SERVER_CERT};
    brix_certificate_key {SERVER_KEY};
    brix_trusted_ca      {CA_CERT};
    brix_tap_proxy on;
    brix_tap_proxy_upstream 127.0.0.1:{upstream_port};
    brix_tap_proxy_auth gsi;"""
        threads = "thread_pool default threads=4;\n"
    else:
        body = f"""    brix_auth none;
    brix_allow_write on;
    brix_tap_proxy on;
    brix_tap_proxy_upstream 127.0.0.1:{upstream_port};
    brix_tap_proxy_auth anonymous;"""
        threads = ""
    return run.write(
        prefix / "nginx.conf",
        f"""daemon on; error_log {prefix}/logs/e.log info; pid {prefix}/nginx.pid;
{threads}events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{port}; brix_root on;
{body}
}} }}
""",
    )


# ---------------------------------------------------------------------------
# run_tap_proxy.sh — terminating anon tap proxy, passthrough + ckpXeq framing.
# ---------------------------------------------------------------------------
def _recvall(sock: socket_module.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        assert chunk, "connection closed"
        buf += chunk
    return buf


def _resp(sock: socket_module.socket) -> tuple[int, bytes]:
    header = _recvall(sock, 8)
    status = struct.unpack(">H", header[2:4])[0]
    dlen = struct.unpack(">I", header[4:8])[0]
    return status, (_recvall(sock, dlen) if dlen else b"")


def _ckpxeq_via_proxy(port: int, origin_file: Path) -> bool:
    """ckpXeq stock framing through the proxy: the trailing sub-body must be
    forwarded verbatim AND the file handle translated in BOTH the outer
    chkpoint body and the embedded sub-header (forward_request.c)."""
    sock = socket_module.socket()
    sock.settimeout(10)
    sock.connect(("127.0.0.1", port))
    try:
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        _recvall(sock, 16)
        sock.sendall(b"\x00\x01" + struct.pack(">H", 3006) + b"\x00" * 16 + struct.pack(">I", 0))
        assert _resp(sock)[0] == 0
        sock.sendall(b"\x00\x01" + struct.pack(">H", 3007) + b"\x00" * 16 + struct.pack(">I", 10) + b"anonymous\x00")
        assert _resp(sock)[0] == 0, "login via proxy failed"

        path = b"/ckp.bin\x00"
        req = (
            b"\x00\x02"
            + struct.pack(">HHH", 3010, 0o644, 0x0020 | 0x0008 | 0x0002)
            + b"\x00" * 12
            + struct.pack(">I", len(path))
        )
        sock.sendall(req + path)
        status, body = _resp(sock)
        assert status == 0, f"open via proxy failed: {status} {body!r}"
        fh = body[:4]

        def chkpoint(sid: bytes, opcode: int, dlen: int = 0) -> bytes:
            return sid + struct.pack(">H", 3012) + fh + b"\x00" * 11 + bytes([opcode]) + struct.pack(">I", dlen)

        sock.sendall(chkpoint(b"\x00\x03", 0))  # ckpBegin
        assert _resp(sock)[0] == 0, "ckpBegin via proxy failed"

        data = b"PROXIED-CKPXEQ"
        sub = b"\x00\x04" + struct.pack(">H", 3019) + fh + struct.pack(">q", 0) + b"\x00" * 4 + struct.pack(">I", len(data))
        sock.sendall(chkpoint(b"\x00\x04", 4, 24) + sub)  # ckpXeq, dlen=24
        sock.sendall(data)  # streamed sub-body
        status, _ = _resp(sock)
        assert status == 0, f"ckpXeq write via proxy failed: {status}"

        sock.sendall(chkpoint(b"\x00\x05", 1))  # ckpCommit
        assert _resp(sock)[0] == 0, "ckpCommit via proxy failed"

        # alignment: ping then close must still work on the same connection
        sock.sendall(b"\x00\x06" + struct.pack(">H", 3011) + b"\x00" * 16 + struct.pack(">I", 0))
        assert _resp(sock)[0] == 0, "connection desynced after ckpXeq via proxy"
        sock.sendall(b"\x00\x07" + struct.pack(">H", 3003) + fh + b"\x00" * 12 + struct.pack(">I", 0))
        assert _resp(sock)[0] == 0

        assert origin_file.read_bytes() == data, "ckpXeq bytes did not land at the origin"
        return True
    finally:
        sock.close()


def tap_proxy(nginx: Path | None = None) -> int:
    if not os.access(XRDFS, os.X_OK):
        return _skip(f"native xrdfs not built ({XRDFS})")
    with LiveRun("tapproxy", nginx) as run:
        op, pp = free_ports(2)
        origin, proxy = run.mkdir("o"), run.mkdir("n")
        for prefix, names in ((origin, ("root", "logs")), (proxy, ("logs",))):
            for name in names:
                (prefix / name).mkdir(exist_ok=True)
        run.start_nginx(origin, _origin_stream_conf(run, origin, op, gsi=False), op)
        run.start_nginx(proxy, _tap_proxy_conf(run, proxy, pp, op, gsi=False), pp)
        source = origin / "root" / "f.bin"
        source.write_bytes(os.urandom(400000))

        checks: list[tuple[bool, str]] = []
        got = run.root / "a.got"
        with got.open("wb") as out:
            subprocess.run(
                [str(XRDFS), f"root://127.0.0.1:{pp}", "cat", "/f.bin"],
                stdout=out,
                stderr=subprocess.DEVNULL,
            )
        checks.append((_same_bytes(source, got), "terminating proxy passthrough byte-exact"))
        stat_rc = run.call([XRDFS, f"root://127.0.0.1:{pp}", "stat", "/f.bin"], check=False).returncode
        checks.append((stat_rc == 0, "stat via tap proxy"))

        try:
            ckp_ok = _ckpxeq_via_proxy(pp, origin / "root" / "ckp.bin")
        except (OSError, AssertionError) as exc:
            print(f"  ckpXeq probe error: {exc}")
            ckp_ok = False
        checks.append((ckp_ok, "ckpXeq stock framing via tap proxy (embedded fh + streamed sub-body)"))

        time.sleep(0.5)
        proxy_log = proxy / "logs" / "e.log"
        checks.append((_grep(proxy_log, '"op":"open"'), "tap logged open"))
        checks.append((_grep(proxy_log, '"dir":"u2c"'), "tap logged a response"))
        return _result(checks)


# ---------------------------------------------------------------------------
# run_tap_proxy_gsi.sh — delegating GSI client -> tap proxy -> GSI nginx origin.
# ---------------------------------------------------------------------------
def _client_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env.update({"X509_USER_PROXY": str(PROXY_STD), "X509_CERT_DIR": CA_DIR, "XrdSecGSICADIR": CA_DIR})
    env.update(extra or {})
    return env


def _xrdcp_read(binary: Path, url: str, dest: Path, log: Path, extra_env: dict[str, str]) -> int:
    with log.open("w") as sink:
        return subprocess.run(
            [str(binary), "-f", url, str(dest)],
            env=_client_env(extra_env),
            stdout=sink,
            stderr=subprocess.STDOUT,
        ).returncode


def _delegation_checks(run: LiveRun, pp: int, source: Path, proxy_log: Path, url_path: str,
                       positive_checks) -> list[tuple[bool, str]]:
    """Shared positive (repo client) + negative (stock client) delegation flow."""
    checks: list[tuple[bool, str]] = []
    if os.access(OUR_XRDCP, os.X_OK):
        got = run.root / "deleg_a.got"
        rc = _xrdcp_read(OUR_XRDCP, f"root://localhost:{pp}/{url_path}", got, run.root / "xrdcp.log",
                         {"XRDC_GSI_DELEGATE": "1"})
        checks.extend(positive_checks(rc == 0 and _same_bytes(source, got)))
        checks.append((_grep(proxy_log, '"op":"open"'), "tap logged open"))
    else:
        print("  SKIP repo-client delegation (build client first: make -C client xrdcp)")

    # negative: stock plain read cannot delegate -> clean decline, NO crash
    _xrdcp_read(STOCK_XRDCP, f"root://localhost:{pp}/{url_path}", run.root / "deleg_b.got",
                run.root / "xrdcp_stock.log", {"XrdSecGSIDELEGPROXY": "2"})
    checks.append((_grep(proxy_log, "declined to delegate"), "stock plain-read client declines delegation cleanly"))
    checks.append((not _grep(proxy_log, "signal 11"), "proxy survived the stock non-delegating client (no crash)"))
    return checks


def tap_proxy_gsi(nginx: Path | None = None) -> int:
    if not os.access(STOCK_XRDCP, os.X_OK):
        return _skip("stock xrdcp not installed")
    with LiveRun("tapgsi", nginx) as run:
        message = ensure_shared_pki(run.root, want_proxy=True)
        if message:
            return _skip(message)
        op, pp = free_ports(2)
        origin, proxy = run.mkdir("o"), run.mkdir("n")
        for prefix, names in ((origin, ("root", "logs")), (proxy, ("logs",))):
            for name in names:
                (prefix / name).mkdir(exist_ok=True)
        run.start_nginx(origin, _origin_stream_conf(run, origin, op, gsi=True), op)
        run.start_nginx(proxy, _tap_proxy_conf(run, proxy, pp, op, gsi=True), pp)
        source = origin / "root" / "f.bin"
        source.write_bytes(os.urandom(400000))
        origin_log = origin / "logs" / "e.log"
        proxy_log = proxy / "logs" / "e.log"

        def positive(byte_exact: bool) -> list[tuple[bool, str]]:
            return [
                (byte_exact, "GSI delegation: repo client -> tap proxy -> GSI upstream byte-exact"),
                (
                    _grep(origin_log, 'GSI auth OK dn="/DC=test/DC=xrootd/CN=Test'),
                    "upstream authenticated the forward as the delegated user",
                ),
            ]

        checks = _delegation_checks(run, pp, source, proxy_log, "/f.bin", positive)
        code = _result(checks)
        if code:
            print("--- proxy error.log (tail) ---")
            print("\n".join(proxy_log.read_text(errors="replace").splitlines()[-25:]) if proxy_log.exists() else "")
        return code


# ---------------------------------------------------------------------------
# run_tap_proxy_gsi_hybrid.sh — repo client -> tap proxy -> OFFICIAL xrootd.
# ---------------------------------------------------------------------------
def tap_proxy_gsi_hybrid(nginx: Path | None = None) -> int:
    if shutil.which("xrootd") is None:
        return _skip("official xrootd not installed")
    if not os.access(STOCK_XRDCP, os.X_OK):
        return _skip("stock xrdcp not installed")
    with LiveRun("taphybrid", nginx) as run:
        if not run.nginx.exists():
            return _skip("nginx not built")
        message = ensure_shared_pki(run.root, want_proxy=True)
        if message:
            return _skip(message)
        xo, pp = free_ports(2)
        data = run.mkdir("data")
        proxy_prefix = run.mkdir("n")
        (proxy_prefix / "logs").mkdir(exist_ok=True)
        source = data / "f.bin"
        source.write_bytes(os.urandom(400000))
        hostkey = run.root / "hostkey.pem"
        hostkey.write_bytes(Path(SERVER_KEY).read_bytes())
        hostkey.chmod(0o600)

        # gridmap the user's END-ENTITY DN (xrootd strips proxy CNs down to it)
        me = getpass.getuser()
        subject = run.call(
            ["openssl", "x509", "-in", USERCERT, "-noout", "-subject", "-nameopt", "compat"],
            check=False,
        ).stdout.strip()
        eec_dn = subject.split("=", 1)[1].lstrip() if "=" in subject else ""
        if not eec_dn:
            return _skip("could not read the user EEC DN")
        (run.root / "gridmap").write_text(f'"{eec_dn}" {me}\n')

        # OFFICIAL xrootd GSI-only upstream
        cfg = run.write(
            run.root / "brix.cfg",
            f"""xrd.port {xo}
all.export /data
oss.localroot {run.root}
xrootd.seclib libXrdSec.so
sec.protocol /usr/lib64 gsi -certdir:{CA_DIR} -cert:{SERVER_CERT} -key:{hostkey} -gridmap:{run.root}/gridmap -d:1 -crl:0 -gmapopt:2
sec.protbind * only gsi
""",
        )
        run.spawn(["xrootd", "-c", cfg, "-l", run.root / "brix.log", "-n", "up"])
        if not wait_tcp("127.0.0.1", xo, 5):
            return _skip("official xrootd upstream did not start")

        try:
            run.start_nginx(proxy_prefix, _tap_proxy_conf(run, proxy_prefix, pp, xo, gsi=True), pp)
        except LiveFailure as exc:
            print(f"proxy-fail: {exc}")
            return 2

        # xrootd -n up writes its log under the instance subdir (…/up/brix.log)
        uplog = run.root / "up" / "brix.log"
        proxy_log = proxy_prefix / "logs" / "e.log"

        def positive(byte_exact: bool) -> list[tuple[bool, str]]:
            return [
                (byte_exact, "repo client -> nginx tap proxy -> OFFICIAL xrootd byte-exact"),
                (
                    _grep(uplog, f"login as {me}"),
                    "official xrootd mapped the delegated proxy + logged the pull in as the user",
                ),
            ]

        if uplog.exists():
            uplog.write_text("")
        checks = _delegation_checks(run, pp, source, proxy_log, "/data/f.bin", positive)
        return _result(checks)


# ---------------------------------------------------------------------------
# run_proxy_env_live.sh — env-proxy pickup: CONNECT tunnel, brixcvmfs, no_proxy.
# ---------------------------------------------------------------------------
CVMFS_CORE = [
    "shared/cvmfs/client/client.c",
    "shared/cvmfs/fetch/fetch.c",
    "shared/cvmfs/object/object.c",
    "shared/cvmfs/failover/failover.c",
    "shared/cvmfs/catalog/catalog.c",
    "shared/cvmfs/grammar/hash.c",
    "shared/cvmfs/grammar/classify.c",
    "shared/cvmfs/signature/manifest.c",
    "shared/cvmfs/signature/whitelist.c",
    "shared/cvmfs/signature/verify.c",
    "shared/cvmfs/config/repo.c",
    "shared/cvmfs/config/cvmfs_conf.c",
    "shared/cvmfs/walk/walk.c",
    "shared/cache/cas_store.c",
    "shared/net/proxy_env.c",
]

BRIX_CONN_LDLIBS = [
    "-lssl", "-lcrypto", "-lz", "-lkrb5", "-lk5crypto", "-lcom_err", "-lzstd", "-llzma",
    "-lbrotlienc", "-lbrotlidec", "-lbz2", "-l:liblz4.so.1", "-luring", "-lpthread",
]


def _fusermount(mnt: Path) -> None:
    for tool in ("fusermount3", "fusermount"):
        if shutil.which(tool) and subprocess.run(
            [tool, "-u", str(mnt)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0:
            return


def _spawn_logged(run: LiveRun, argv: list[str], env: dict[str, str], stderr_path: Path) -> subprocess.Popen:
    proc = subprocess.Popen(
        [str(item) for item in argv],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=stderr_path.open("wb"),
    )
    run.processes.append(proc)
    return proc


def _await_mount(path: Path, expect: str, timeout: float = 30.0) -> str:
    """Poll a FUSE-backed file until it reads the expected content (or times out).

    The mount is spawned asynchronously and populates lazily over the network, so
    the file is not readable the instant the process starts.  Polling to a
    deadline replaces a fixed sleep that raced the mount coming up under
    concurrent load; on a healthy system this returns within a second, so it adds
    no wall-clock cost to the passing path.  Returns the last content or error
    read, so a timed-out check still reports a meaningful diagnostic.
    """
    deadline = time.monotonic() + timeout
    got = ""
    while True:
        try:
            got = path.read_text().rstrip("\n")
            if got == expect:
                return got
        except OSError as exc:
            got = f"<error: {exc}>"
        if time.monotonic() >= deadline:
            return got
        time.sleep(0.25)


def proxy_env_live(nginx: Path | None = None) -> int:  # noqa: ARG001 — no nginx in this scenario
    for tool in ("gcc", "pkg-config"):
        if shutil.which(tool) is None:
            return _skip(f"{tool} not installed")
    fuse_cflags = subprocess.run(["pkg-config", "--cflags", "fuse3"], capture_output=True, text=True)
    fuse_libs = subprocess.run(["pkg-config", "--libs", "fuse3"], capture_output=True, text=True)
    if fuse_cflags.returncode or fuse_libs.returncode:
        return _skip("fuse3 development package not installed")
    if shutil.which("fusermount3") is None and shutil.which("fusermount") is None:
        return _skip("fusermount not installed")
    if not Path("/dev/fuse").exists():
        return _skip("/dev/fuse not available")
    # brixcvmfs now links the prebuilt client static libs; without them the
    # standalone build can't resolve the connection stack — skip, don't hard-fail.
    for lib in ("client/libbrix.a", "shared/xrdproto/libxrdproto.a"):
        if not (REPO_ROOT / lib).exists():
            return _skip(f"{lib} not built (run make -C client lib && make -C shared/xrdproto)")

    repo = "test.cern.ch"
    expect = "Hello from a LIVE CVMFS-brix mount!"
    with LiveRun("proxyenv", nginx) as run:
        hport, pport = free_ports(2)
        web, mnt, cache, tmp = run.mkdir("web"), run.mkdir("mnt"), run.mkdir("cache"), run.mkdir("tmp")
        pub = run.root / "pub.pem"
        plog = run.root / "proxy.log"
        plog.touch()
        mkrepo, harness, brixcvmfs = run.root / "brix_mkrepo", run.root / "proxy_harness", run.root / "brixcvmfs"

        checks: list[tuple[bool, str]] = []
        print("== build ==")
        builds = [
            (mkrepo, ["gcc", "-Wall", "-I", "shared", "-o", str(mkrepo), "tests/cvmfs/brix_mkrepo.c",
                      "shared/cvmfs/grammar/hash.c", "shared/cvmfs/object/object.c",
                      "shared/cvmfs/catalog/catalog.c", "-lsqlite3", "-lcrypto", "-lz"]),
            (harness, ["gcc", "-Wall", "-Wextra", "-Werror", "-I", "shared", "-o", str(harness),
                       "tests/cvmfs/proxy_tunnel_harness.c", "shared/net/proxy_connect.c"]),
            # brixcvmfs.c now pulls in the client/lib connection stack
            # (net/cpool.h -> client/lib/brix.h -> src wire structs; uses
            # brix_cpool_*), so the standalone build needs the same include roots
            # and static libs the canonical client/Makefile brixMount recipe uses:
            # -Iclient/lib -Isrc -DXRDPROTO_NO_NGX + libbrix.a + libxrdproto.a.
            (brixcvmfs, ["gcc", "-Wall", "-Wextra", "-Werror",
                         "-I", "shared", "-I", "client/lib", "-I", "src",
                         "-DXRDPROTO_NO_NGX", *fuse_cflags.stdout.split(),
                         "-o", str(brixcvmfs), "client/apps/fs/brixcvmfs.c", *CVMFS_CORE,
                         "client/libbrix.a", "shared/xrdproto/libxrdproto.a",
                         *fuse_libs.stdout.split(), "-lcurl", "-lsqlite3", "-lcrypto", "-lz",
                         *BRIX_CONN_LDLIBS]),
        ]
        for target, argv in builds:
            result = run.call(argv, cwd=REPO_ROOT, check=False)
            if result.returncode:
                print(f"  FAIL build {target.name}: {(result.stderr or result.stdout)[-500:]}")
                return 1

        run.call([mkrepo, repo, web, pub])
        run.spawn(["python3", "-m", "http.server", str(hport)], cwd=web)
        run.spawn(["python3", REPO_ROOT / "tests" / "cvmfs" / "tiny_proxy.py", str(pport), plog])
        time.sleep(1.5)

        try:
            print("== (A) CONNECT tunnel handshake ==")
            tunnel = run.call(
                [harness, "127.0.0.1", str(pport), "localhost", str(hport), f"/cvmfs/{repo}/.cvmfspublished"],
                check=False,
            )
            checks.append(
                (
                    tunnel.returncode == 0 and _grep(plog, f"CONNECT localhost:{hport}"),
                    "CONNECT tunnel used + 200 ok",
                )
            )

            print("== (A2) real brix_tcp_connect: direct path unchanged + proxy path tunnels ==")
            libbrix = REPO_ROOT / "client" / "libbrix.a"
            if libbrix.exists():
                brix_conn = run.root / "brix_conn"
                link = run.call(
                    ["gcc", "-Wall", "-Iclient/lib", "-Isrc", "-Ishared", "-DXRDPROTO_NO_NGX",
                     "-o", str(brix_conn), "tests/cvmfs/brix_connect_harness.c",
                     str(libbrix), "shared/xrdproto/libxrdproto.a", *BRIX_CONN_LDLIBS],
                    cwd=REPO_ROOT,
                    check=False,
                )
                if link.returncode:
                    print(f"  SKIP: libbrix harness link failed ({(link.stderr or '').splitlines()[-1:]})")
                else:
                    direct_env = {k: v for k, v in os.environ.items()
                                  if k not in ("http_proxy", "https_proxy", "all_proxy")}
                    plog.write_text("")
                    direct = subprocess.run([str(brix_conn), "localhost", str(hport)], env=direct_env,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    checks.append(
                        (
                            direct.returncode == 0 and plog.stat().st_size == 0,
                            "direct connect ok (no proxy, path unchanged)",
                        )
                    )
                    plog.write_text("")
                    proxied = subprocess.run(
                        [str(brix_conn), "localhost", str(hport)],
                        env={**direct_env, "http_proxy": f"http://127.0.0.1:{pport}"},
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    checks.append(
                        (
                            proxied.returncode == 0 and _grep(plog, f"CONNECT localhost:{hport}"),
                            "proxied connect tunnels ok",
                        )
                    )
            else:
                print("  SKIP: client/libbrix.a not built (run make -C client lib)")

            mount_env = {k: v for k, v in os.environ.items() if k not in ("no_proxy", "NO_PROXY")}
            mount_env.update(
                {
                    "BRIXCVMFS_SERVER": f"http://localhost:{hport}/cvmfs/{repo}",
                    "BRIXCVMFS_PUBKEY": str(pub),
                    "BRIXCVMFS_TMP": str(tmp),
                }
            )

            print("== (B) brixcvmfs via http_proxy (report + mount) ==")
            plog.write_text("")
            err = run.root / "mount_b.err"
            _spawn_logged(
                run,
                [brixcvmfs, repo, mnt, "-o", "fresh,auto_unmount", "-f"],
                {**mount_env, "http_proxy": f"http://127.0.0.1:{pport}", "BRIXCVMFS_CACHE": str(cache)},
                err,
            )
            got = _await_mount(mnt / "hello", expect)
            checks.append((got == expect, f"content via proxy [{got}]"))
            checks.append((_grep(err, f"using HTTP proxy 127.0.0.1:{pport}"), "reported proxy use ok"))
            checks.append((_grep(plog, f"GET-forward localhost:{hport}"), "proxy actually forwarded ok"))
            _fusermount(mnt)
            time.sleep(1)

            print("== (C) no_proxy forces direct ==")
            plog.write_text("")
            cache2 = run.mkdir("cache2")
            err2 = run.root / "mount_c.err"
            _spawn_logged(
                run,
                [brixcvmfs, repo, mnt, "-o", "auto_unmount", "-f"],
                {
                    **mount_env,
                    "http_proxy": f"http://127.0.0.1:{pport}",
                    "no_proxy": "localhost,127.0.0.1",
                    "BRIXCVMFS_CACHE": str(cache2),
                },
                err2,
            )
            got = _await_mount(mnt / "hello", expect)
            checks.append((got == expect, f"direct mount content [{got}]"))
            checks.append((plog.stat().st_size == 0, "no_proxy honored (direct) ok"))
            _fusermount(mnt)
            time.sleep(1)
        finally:
            _fusermount(mnt)
        return _result(checks)


SCENARIOS = {
    "proxy-env-live": proxy_env_live,
    "tap-proxy": tap_proxy,
    "tap-proxy-gsi": tap_proxy_gsi,
    "tap-proxy-gsi-hybrid": tap_proxy_gsi_hybrid,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"tap-proxy scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
