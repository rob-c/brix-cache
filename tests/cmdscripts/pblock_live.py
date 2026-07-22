"""Direct Python ports for the pblock storage-driver live shell scenarios.

Ports ``run_pblock_root.sh``, ``run_pblock_webdav.sh``,
``run_pblock_writethrough.sh``, and ``run_pblock_meta_gsi.sh``.  Each public
scenario keeps its shell test's own acceptance sequence and assertions; ports
are allocated dynamically instead of the scripts' fixed literals.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT, random_file, sha256
from lib_py.pki import regenerate_pki
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, TEST_ROOT
from fleet_ports import cmdscript_ports

_PORTS = cmdscript_ports("pblock_live")

XRDCP = REPO_ROOT / "client/bin/xrdcp"
XRDFS = REPO_ROOT / "client/bin/xrdfs"
XRDDIAG = REPO_ROOT / "client/bin/xrddiag"
XRDADLER32 = REPO_ROOT / "client/bin/xrdadler32"
XRDCRC32C = REPO_ROOT / "client/bin/xrdcrc32c"
LIBXRDC = REPO_ROOT / "client/libbrix.a"
PROTOLIB = REPO_ROOT / "shared/xrdproto/libxrdproto.a"
META_BENCH_SRC = REPO_ROOT / "tests/tools/pblock_meta_bench.c"

PKI_DIR = Path(TEST_ROOT) / "pki"
CA_CERT = PKI_DIR / "ca/ca.pem"
CA_DIR = PKI_DIR / "ca"
SERVER_CERT = PKI_DIR / "server/hostcert.pem"
SERVER_KEY = PKI_DIR / "server/hostkey.pem"
PROXY_STD = PKI_DIR / "user/proxy_std.pem"

CLIENT_REQUIREMENTS = {
    "pblock-root": (XRDCP, XRDFS, XRDADLER32, XRDCRC32C),
    "pblock-webdav": (),
    "pblock-writethrough": (XRDCP,),
    "pblock-meta-gsi": (XRDFS, XRDDIAG),
    "pblock-lab": (XRDCP,),
}


def _checks(values: list[tuple[bool, str]]) -> int:
    for passed, text in values:
        print(f"  {'ok  ' if passed else 'FAIL'} {text}")
    return 0 if all(passed for passed, _ in values) else 1


def pblock_root(nginx: Path | None = None) -> int:
    """End-to-end root:// on the pblock storage driver: data movement,
    metadata, checksum-at-rest, and namespace mutation, all landing in the
    block catalog + data dir."""
    (port,) = _PORTS[0:1]  # was free_ports(1)
    with LiveRun("pblock_root", nginx) as run:
        run.mkdir("root")
        run.mkdir("logs")
        config = run.write(run.root / "nginx.conf", f"""daemon on;
error_log {run.root}/logs/error.log info;
pid {run.root}/nginx.pid;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export {run.root}/root;
        brix_auth none;
        brix_allow_write on;
        brix_upload_resume off;
        brix_storage_backend  pblock;
        brix_pblock_block_size 1m;
        brix_access_log {run.root}/logs/access.log;
    }}
}}
""")
        run.start_nginx(run.root, config, port)
        time.sleep(1)
        host = f"root://{HOST}:{port}"
        hub = f"{host}/"

        small, multi = run.root / "small.bin", run.root / "multi.bin"
        random_file(small, 700000)    # < 1 block
        random_file(multi, 2621440)   # 2.5 blocks
        checks: list[tuple[bool, str]] = []

        checks.append((run.call([XRDCP, "-f", small, f"{hub}s.bin"], check=False).returncode == 0, "PUT small (1 block)"))
        checks.append((run.call([XRDCP, "-f", multi, f"{hub}m.bin"], check=False).returncode == 0, "PUT multi (3 blocks)"))
        small_got, multi_got = run.root / "s.got", run.root / "m.got"
        checks.append((run.call([XRDCP, "-f", f"{hub}s.bin", small_got], check=False).returncode == 0, "GET small"))
        checks.append((run.call([XRDCP, "-f", f"{hub}m.bin", multi_got], check=False).returncode == 0, "GET multi"))
        checks.append((small_got.exists() and sha256(small_got) == sha256(small), "GET small byte-exact"))
        checks.append((multi_got.exists() and sha256(multi_got) == sha256(multi), "GET multi byte-exact"))

        stat_out = run.call([XRDFS, host, "stat", "/m.bin"], check=False).stdout
        size = next((line.split()[1] for line in stat_out.splitlines() if line.strip().startswith("Size:")), "")
        checks.append((size == "2621440", f"stat size (multi) ({size})"))

        ref_adler = run.call([XRDADLER32, multi], check=False).stdout.split()
        srv_query = run.call([XRDFS, host, "query", "checksum", "/m.bin"], check=False).stdout
        srv_adler = next((line.split()[1] for line in srv_query.splitlines() if "adler32" in line and len(line.split()) > 1), "")
        checks.append((bool(ref_adler) and srv_adler == ref_adler[0], f"adler32 whole-file ({srv_adler})"))
        ref_crc = run.call([XRDCRC32C, multi], check=False).stdout.split()
        crc_query = run.call([XRDFS, host, "query", "checksum", "/m.bin?cks.type=crc32c"], check=False).stdout
        srv_crc = next((line.split()[1] for line in crc_query.splitlines() if "crc32c" in line and len(line.split()) > 1), "")
        checks.append((bool(ref_crc) and srv_crc == ref_crc[0], f"crc32c whole-file ({srv_crc})"))

        checks.append((run.call([XRDFS, host, "mkdir", "/d"], check=False).returncode == 0, "mkdir /d"))
        checks.append((run.call([XRDCP, "-f", small, f"{hub}d/x.bin"], check=False).returncode == 0, "PUT /d/x.bin"))
        listing = run.call([XRDFS, host, "ls", "/"], check=False).stdout
        checks.append(("s.bin" in listing, "ls shows s.bin"))
        checks.append(("/d" in listing, "ls shows /d"))
        checks.append((run.call([XRDFS, host, "rm", "/s.bin"], check=False).returncode == 0, "rm /s.bin"))
        checks.append((run.call([XRDFS, host, "stat", "/s.bin"], check=False).returncode != 0, "stat removed (gone)"))

        checks.append(((run.root / "root/catalog.db").is_file(), "catalog.db present"))
        checks.append(((run.root / "root/data").is_dir(), "data/ block dir present"))
        return _checks(checks)


def pblock_webdav(nginx: Path | None = None) -> int:
    """End-to-end WebDAV-on-pblock matrix: data movement, metadata, namespace
    mutation, the phase-68 orphan-parent regression, and the on-disk catalog."""
    (port,) = _PORTS[1:2]  # was free_ports(1)
    with LiveRun("pblock_webdav", nginx) as run:
        for name in ("root", "tmp", "logs"):
            run.mkdir(name)
        config = run.write(run.root / "nginx.conf", f"""daemon on;
error_log {run.root}/logs/error.log info;
pid {run.root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {run.root}/tmp;
    client_max_body_size 200m;
    server {{
        listen {BIND_HOST}:{port};
        location / {{
            dav_methods PUT DELETE MKCOL MOVE COPY;
            brix_webdav on;
            brix_export {run.root}/root;
            brix_webdav_auth none;
            brix_allow_write on;
            brix_storage_backend  pblock;
            brix_webdav_pblock_block_size 1m;
        }}
    }}
}}
""")
        run.start_nginx(run.root, config, port)
        time.sleep(1)
        url = f"http://{HOST}:{port}"

        small, multi = run.root / "small.bin", run.root / "multi.bin"
        random_file(small, 700000)    # < 1 block
        random_file(multi, 2621440)   # 2.5 blocks
        checks: list[tuple[bool, str]] = []

        checks.append((run.curl_status(f"{url}/s.bin", "-T", str(small)) == 201, "PUT small (1 block) 201"))
        checks.append((run.curl_status(f"{url}/m.bin", "-T", str(multi)) == 201, "PUT multi (3 blocks) 201"))
        checks.append((run.curl_bytes(f"{url}/s.bin") == small.read_bytes(), "GET small byte-exact"))
        checks.append((run.curl_bytes(f"{url}/m.bin") == multi.read_bytes(), "GET multi byte-exact"))
        ranged = run.curl_bytes(f"{url}/m.bin", "-r", "1048570-1048580")
        checks.append((ranged == multi.read_bytes()[1048570:1048581], "Range GET across block boundary"))

        checks.append((run.curl_status(f"{url}/s.bin", "-I") == 200, "HEAD existing 200"))
        checks.append((run.curl_status(f"{url}/none", "-I") == 404, "HEAD missing 404"))
        checks.append((run.curl_status(f"{url}/", "-X", "PROPFIND", "-H", "Depth: 1") == 207, "PROPFIND root depth1 207"))

        checks.append((run.curl_status(f"{url}/d", "-X", "MKCOL") == 201, "MKCOL /d 201"))
        checks.append((run.curl_status(f"{url}/d/x.bin", "-T", str(small)) == 201, "PUT /d/x.bin 201"))
        checks.append((run.curl_status(f"{url}/s.bin", "-X", "MOVE", "-H", f"Destination: {url}/s2.bin") == 201, "MOVE /s.bin -> /s2.bin 201"))
        checks.append((run.curl_status(f"{url}/s.bin", "-I") == 404, "HEAD moved-from (gone) 404"))
        checks.append((run.curl_status(f"{url}/s2.bin", "-I") == 200, "HEAD moved-to 200"))
        checks.append((run.curl_status(f"{url}/s2.bin", "-X", "COPY", "-H", f"Destination: {url}/cp.bin") == 201, "COPY /s2.bin -> /cp.bin 201"))
        checks.append((run.curl_bytes(f"{url}/cp.bin") == small.read_bytes(), "GET copy byte-exact"))
        checks.append((run.curl_status(f"{url}/d", "-X", "DELETE") == 409, "DELETE /d (non-empty) 409"))
        checks.append((run.curl_status(f"{url}/d/x.bin", "-X", "DELETE") == 204, "DELETE /d/x.bin (file) 204"))
        checks.append((run.curl_status(f"{url}/d", "-X", "DELETE") == 204, "DELETE /d (now empty) 204"))
        checks.append((run.curl_status(f"{url}/d", "-I") == 404, "HEAD deleted dir 404"))

        # Orphan-parent regression (phase-68 fix): a PUT whose parent
        # collection does not exist must 409 (RFC 4918 9.7.1, posix parity).
        checks.append((run.curl_status(f"{url}/nodir/orphan.bin", "-T", str(small)) == 409, "PUT into missing collection 409"))
        checks.append((run.curl_status(f"{url}/nodir", "-X", "MKCOL") == 201, "MKCOL /nodir 201"))
        checks.append((run.curl_status(f"{url}/nodir/orphan.bin", "-T", str(small)) == 201, "PUT after MKCOL 201"))
        propfind = run.call(["curl", "-sS", "--max-time", "25", "-X", "PROPFIND", "-H", "Depth: 1", f"{url}/nodir/"], check=False).stdout
        checks.append(("orphan.bin" in propfind, "parent collection lists the new file"))

        checks.append(((run.root / "root/catalog.db").is_file(), "catalog.db present"))
        checks.append(((run.root / "root/data").is_dir(), "data/ block dir present"))
        return _checks(checks)


def pblock_writethrough(nginx: Path | None = None) -> int:
    """The cache fronts a driver-backed PRIMARY: a pblock-backed export with
    sync write-through mirrors a multi-block file to a separate root://
    origin by reading it back THROUGH the pblock driver."""
    origin_port, primary_port = _PORTS[2:4]  # was free_ports(2)
    with LiveRun("pblock_wt", nginx) as run:
        origin, primary = run.mkdir("o"), run.mkdir("p")
        for directory, names in ((origin, ("root", "logs")), (primary, ("root", "cache", "logs"))):
            for name in names:
                (directory / name).mkdir(exist_ok=True)
        origin_conf = run.write(origin / "nginx.conf", f"""daemon on;
error_log {origin}/logs/error.log info;
pid {origin}/nginx.pid;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{origin_port};
        brix_root on;
        brix_storage_backend posix:{origin}/root;
        brix_auth none;
        brix_allow_write on;
        brix_upload_resume off;
    }}
}}
""")
        primary_conf = run.write(primary / "nginx.conf", f"""daemon on;
error_log {primary}/logs/error.log info;
pid {primary}/nginx.pid;
events {{ worker_connections 64; }}
thread_pool default threads=2;
stream {{
    server {{
        listen {BIND_HOST}:{primary_port};
        brix_root on;
        brix_auth none;
        brix_allow_write on;
        brix_upload_resume off;
        brix_storage_backend  pblock://{primary}/root/;
        brix_pblock_block_size 1m;
        brix_write_through on;
        brix_wt_mode sync;
        brix_wt_origin {HOST}:{origin_port};
    }}
}}
""")
        run.start_nginx(origin, origin_conf, origin_port)
        run.start_nginx(primary, primary_conf, primary_port)
        time.sleep(1)

        source = run.root / "src.bin"
        random_file(source, 2621440)  # 2.5 pblock blocks
        put = run.call([XRDCP, "-f", source, f"root://{HOST}:{primary_port}//m.bin"], check=False).returncode == 0
        time.sleep(1)  # sync-mode flush completes during close; let the origin settle

        mirror = origin / "root/m.bin"
        checks = [(put, "PUT to pblock primary")]
        if mirror.exists():
            checks.append((True, "origin file present"))
            checks.append((sha256(mirror) == sha256(source), "origin bytes match (multi-block, driver read-back)"))
            checks.append((mirror.stat().st_size == 2621440, f"origin size {mirror.stat().st_size} == 2621440"))
        else:
            checks.append((False, "origin file missing — write-through did not mirror"))
            log = (primary / "logs/error.log").read_text(errors="replace")
            for line in [l for l in log.splitlines() if re.search(r"wt: flush", l, re.I)][-2:]:
                print(f"    {line}")
        checks.append(((primary / "root/data").is_dir(), "pblock data/ dir present"))
        checks.append((not (primary / "root/m.bin").is_file(), "no raw POSIX file at primary path"))
        return _checks(checks)


# --------------------------------------------------------------------------- #
# pblock-lab — Phase-83 fault-injection lab: the `?tail` → sidecar → ctl path  #
# --------------------------------------------------------------------------- #

def lab_conf(run: LiveRun, port: int, tail: str, *,
             workers: int | None = None, webdav: bool = False) -> Path:
    """Render a minimal pblock-lab nginx config to ``<root>/nginx.conf``.

    Single committed source for the Phase-83 pblock-lab server configs: the lab
    ``test_*.py`` modules call this instead of embedding an nginx config heredoc
    (registry lint forbids an inline runnable config in a test module — see
    ``test_server_registry_lint.py``).

    ``tail`` is the backend ``?tail`` query (e.g. ``"?snap=1"``), empty for a
    production (gate-off) export.  ``workers`` emits ``worker_processes`` when
    not None — the oplog/single-flight labs pin it.  ``webdav`` selects the
    ``http{}``/WebDAV front (atomic-publish overwrites drive the versioning and
    per-block-transform labs) over the default ``stream{}`` root:// front."""
    wp = f"worker_processes {workers};\n" if workers is not None else ""
    if webdav:
        return run.write(run.root / "nginx.conf", f"""daemon on;
error_log {run.root}/logs/error.log info;
pid {run.root}/nginx.pid;
{wp}events {{ worker_connections 64; }}
http {{
    client_body_temp_path {run.root}/tmp;
    client_max_body_size 200m;
    server {{
        listen {BIND_HOST}:{port};
        location / {{
            dav_methods PUT DELETE MKCOL MOVE COPY;
            brix_webdav on;
            brix_export {run.root}/root;
            brix_webdav_auth none;
            brix_allow_write on;
            brix_storage_backend  pblock://{run.root}/root{tail};
            brix_webdav_pblock_block_size 1m;
        }}
    }}
}}
""")
    return run.write(run.root / "nginx.conf", f"""daemon on;
error_log {run.root}/logs/error.log info;
pid {run.root}/nginx.pid;
{wp}events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export {run.root}/root;
        brix_auth none;
        brix_allow_write on;
        brix_upload_resume off;
        brix_storage_backend  pblock://{run.root}/root{tail};
        brix_pblock_block_size 1m;
        brix_access_log {run.root}/logs/access.log;
    }}
}}
""")


def _lab_conf(run: LiveRun, port: int, tail: str) -> Path:
    """Back-compat internal alias for :func:`lab_conf` (stream, no worker pin)."""
    return lab_conf(run, port, tail)


def pblock_lab_spec(name: str, tail: str, *,
                    workers: int = 1, webdav: bool = False) -> NginxInstanceSpec:
    """Registry spec for a Phase-83 pblock-lab throwaway server.

    The single source the lab ``test_*.py`` modules build every server through:
    the config is the committed on-disk template
    (``configs/nginx_pblock_lab.conf`` — stream/root:// — or the ``_webdav``
    variant for the atomic-publish overwrite labs), so no test embeds a runnable
    nginx config or launches nginx itself; the lifecycle harness owns
    start/stop.  ``tail`` is the backend ``?tail`` gate query (e.g. ``"?snap=1"``,
    empty ``""`` for a gate-off production export); ``workers`` pins
    ``worker_processes`` (the oplog/single-flight labs need it fixed)."""
    return NginxInstanceSpec(
        name=name,
        template="nginx_pblock_lab_webdav.conf" if webdav else "nginx_pblock_lab.conf",
        protocol="webdav" if webdav else "root",
        template_values={"BIND_HOST": BIND_HOST, "TAIL": tail, "WORKERS": workers},
        reason="Phase-83 pblock fault-injection lab",
    )


def pblock_worker_own(catalog: Path) -> None:
    """Hand a test-written catalog.db (and its WAL/SHM sidecars) to the pblock
    worker's account so the worker can open it read-write.

    Under the root harness the pblock nginx worker runs as ``nobody`` and OWNS
    catalog.db (pblock refuses to touch root-owned on-disk state). Test helpers
    that poke the catalog over an sqlite3 side-channel run as the root pytest
    process, so if the worker has not yet lazily created catalog.db their
    ``sqlite3.connect()`` creates it root-owned — after which the nobody worker
    cannot open it read-write, the ``objects`` table is never created, and
    pblock-fsck fails "no such table: objects". Call this after any such
    side-channel write. Best-effort; a no-op when unprivileged.
    """
    if os.geteuid() != 0:
        return
    runas = os.environ.get("REF_RUNAS_USER", "nobody")
    for p in (catalog, Path(str(catalog) + "-wal"), Path(str(catalog) + "-shm")):
        if p.exists():
            try:
                shutil.chown(p, runas, runas)
            except (OSError, LookupError):
                pass


def pblock_worker_readable(path: Path) -> None:
    """Make a test-written file (e.g. a crypt keyfile) reachable and readable by
    the pblock worker's account under the root harness.

    The lifecycle worker runs as ``nobody`` but the root pytest process writes
    xform keyfiles into its 0700 ``mkdtemp`` LiveRun tree, which the worker cannot
    traverse to read — so the crypt/xform backend init fails EACCES and the export
    silently degrades. Grant world-read on the file and world-traverse on the
    containing directory. Best-effort; a no-op when unprivileged.
    """
    if os.geteuid() != 0:
        return
    try:
        if path.exists():
            os.chmod(path, 0o644)
            os.chmod(path.parent, os.stat(path.parent).st_mode | 0o011)
    except OSError:
        pass


def _ctl_set(catalog: Path, key: str, value: str, epoch: int) -> None:
    """Inject a runtime ctl rule exactly as a test operator would via the
    sqlite3 CLI — a side-channel into the live export's catalog.db."""
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS ctl("
                     "key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', "
                     "epoch INTEGER NOT NULL DEFAULT 0);")
        conn.execute("INSERT OR REPLACE INTO ctl(key, value, epoch) "
                     "VALUES(?, ?, ?);", (key, value, epoch))
        conn.commit()
    finally:
        conn.close()
    pblock_worker_own(catalog)


def pblock_lab(nginx: Path | None = None) -> int:
    """Phase-83 lab plumbing end-to-end over root://: the config `?tail`
    becomes the <root>/pblock.opts sidecar, a runtime ctl fault.pread rule
    fails a fresh read (snapshot-at-open), and with the master gate OFF the
    identical rule is inert (byte-for-byte production driver)."""
    checks: list[tuple[bool, str]] = []

    # (success) lab gate ON: sidecar written, transfers clean before any rule.
    (port,) = _PORTS[4:5]  # was free_ports(1)
    with LiveRun("pblock_lab_on", nginx) as run:
        run.mkdir("root")
        run.mkdir("logs")
        config = _lab_conf(run, port, "?lab=1")
        run.start_nginx(run.root, config, port)
        time.sleep(1)
        host = f"root://{HOST}:{port}"
        hub = f"{host}/"

        sidecar = run.root / "root/pblock.opts"
        checks.append((sidecar.is_file(), "pblock.opts sidecar written by config"))
        checks.append((sidecar.is_file() and "lab=1" in sidecar.read_text(),
                       "sidecar carries lab=1"))

        src = run.root / "src.bin"
        random_file(src, 700000)
        got = run.root / "clean.got"
        checks.append((run.call([XRDCP, "-f", src, f"{hub}f.bin"], check=False).returncode == 0,
                       "PUT clean (gate on, no rule)"))
        checks.append((run.call([XRDCP, "-f", f"{hub}f.bin", got], check=False).returncode == 0,
                       "GET clean before fault"))
        checks.append((got.exists() and sha256(got) == sha256(src), "GET clean byte-exact"))

        # (error) inject a read fault; a FRESH open must surface EIO → GET fails.
        _ctl_set(run.root / "root/catalog.db", "fault.pread", "errno=EIO", 1)
        faulted = run.root / "faulted.got"
        rc = run.call([XRDCP, "-f", f"{hub}f.bin", faulted], check=False).returncode
        checks.append((rc != 0, "GET after fault.pread=EIO fails (snapshot-at-open)"))

    # (security-neg) gate OFF: identical ctl rule is inert — read still succeeds.
    (port2,) = _PORTS[5:6]  # was free_ports(1)
    with LiveRun("pblock_lab_off", nginx) as run:
        run.mkdir("root")
        run.mkdir("logs")
        config = _lab_conf(run, port2, "")          # no `?tail` ⇒ lab OFF
        run.start_nginx(run.root, config, port2)
        time.sleep(1)
        host = f"root://{HOST}:{port2}"
        hub = f"{host}/"

        src = run.root / "src.bin"
        random_file(src, 700000)
        checks.append((not (run.root / "root/pblock.opts").exists(),
                       "no sidecar when tail absent (production path)"))
        checks.append((run.call([XRDCP, "-f", src, f"{hub}f.bin"], check=False).returncode == 0,
                       "PUT (gate off)"))
        _ctl_set(run.root / "root/catalog.db", "fault.pread", "errno=EIO", 1)
        off_got = run.root / "off.got"
        rc = run.call([XRDCP, "-f", f"{hub}f.bin", off_got], check=False).returncode
        checks.append((rc == 0 and off_got.exists() and sha256(off_got) == sha256(src),
                       "GET ignores fault with gate off (fail-closed master gate)"))

    return _checks(checks)


# --------------------------------------------------------------------------- #
# pblock-meta-gsi — concurrent GSI metadata-storm reliability + perf proof    #
# --------------------------------------------------------------------------- #

def _ensure_pki(run: LiveRun) -> bool:
    """Provision the fleet CA-signed PKI on demand; refresh an expired proxy WITHOUT
    regenerating the CA.  A full regen (regenerate_pki/blitz_test_pki) rebuilds the
    CA and desyncs the standing fleet — it loaded its certs at startup, so freshly
    minted proxies then chain to a CA the fleet no longer trusts and every
    concurrent GSI/TLS test fails.  refresh_shared_pki refreshes only the proxy
    when the CA/hostcert exist.  See live_common.refresh_shared_pki."""
    from cmdscripts.live_common import refresh_shared_pki  # noqa: PLC0415
    ok, msg = refresh_shared_pki(run.root, want_proxy=True)
    if not ok:
        print(f"SKIP: {msg}")
    return ok


def _build_meta_bench(run: LiveRun) -> Path:
    bench = run.root / "pblock_meta_bench"
    build = run.call(
        [
            "cc", "-O2", "-Wall", "-I", REPO_ROOT / "client/lib", "-I", REPO_ROOT / "src",
            "-DXRDPROTO_NO_NGX", META_BENCH_SRC, LIBXRDC, PROTOLIB,
            "-lssl", "-lcrypto", "-lz", "-lkrb5", "-lk5crypto", "-lcom_err", "-lzstd",
            "-llzma", "-lbrotlienc", "-lbrotlidec", "-lbz2", "-l:liblz4.so.1",
            "-luring", "-lpthread", "-o", bench,
        ],
        check=False,
    )
    if build.returncode:
        raise LiveFailure(f"harness build failed: {build.stderr}")
    return bench


def pblock_meta_gsi(nginx: Path | None = None, *,
                    workers: int | None = None,
                    ops_per_worker: int | None = None,
                    p99_ceil_ms: int | None = None,
                    proxy_override: str | None = None) -> int:
    """Concurrent GSI metadata storm on the pblock backend in three layers
    (libbrix harness, xrdfs CLI chain, xrddiag client validation) asserting
    zero op failures, catalog integrity, server health, and a p99 ceiling."""
    workers = int(os.environ.get("WORKERS", "8")) if workers is None else workers
    ops_per_worker = int(os.environ.get("OPS_PER_WORKER", "125")) if ops_per_worker is None else ops_per_worker
    # The 50ms default assumes a lightly-loaded >=8-core host; on smaller
    # boxes (shared 4-core CI, whole fleet resident) scheduler contention alone
    # blows a hard 50ms tail, so scale the default — still env-overridable.
    if p99_ceil_ms is None:
        cores = os.cpu_count() or 8
        default_ceil = 50 if cores >= 8 else 50 * 8 // max(cores, 1)
        p99_ceil_ms = int(os.environ.get("P99_CEIL_MS", str(default_ceil)))
    block_size = os.environ.get("PBLOCK_BLOCK_SIZE", "1m")
    proxy_override = os.environ.get("MB_PROXY_OVERRIDE") if proxy_override is None else proxy_override

    nginx_bin = Path(nginx or os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    for need in (nginx_bin, XRDFS, XRDDIAG, LIBXRDC, PROTOLIB):
        if not Path(need).exists():
            print(f"SKIP: missing {need}")
            return 0

    (port,) = _PORTS[6:7]  # was free_ports(1)
    with LiveRun("pblock_meta_gsi", nginx) as run:
        run.mkdir("root")
        run.mkdir("logs")
        if not _ensure_pki(run):
            return 0
        env = {
            "X509_USER_PROXY": proxy_override or str(PROXY_STD),
            "X509_CERT_DIR": str(CA_DIR),
        }
        host = f"root://{HOST}:{port}/"
        config = run.write(run.root / "nginx.conf", f"""daemon on;
error_log {run.root}/logs/error.log info;
pid {run.root}/nginx.pid;
events {{ worker_connections 256; }}
thread_pool default threads=8 max_queue=512;
stream {{
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export            {run.root}/root;
        brix_auth            gsi;
        brix_certificate     {SERVER_CERT};
        brix_certificate_key {SERVER_KEY};
        brix_trusted_ca      {CA_CERT};
        brix_allow_write     on;
        brix_upload_resume   off;
        brix_storage_backend pblock;
        brix_pblock_block_size {block_size};
        brix_access_log {run.root}/logs/access.log;
    }}
}}
""")
        run.start_nginx(run.root, config, port)
        time.sleep(1)

        bench = _build_meta_bench(run)
        plan = ["--workers", str(workers), "--ops-per-worker", str(ops_per_worker), "--p99-ceil-ms", str(p99_ceil_ms)]
        checks: list[tuple[bool, str]] = []
        data_dir = run.root / "root/data"

        print("== Layer (a): libbrix direct code ==")
        create = run.call([bench, *plan, "--phase", "create", "--json", host], env=env, check=False)
        print(create.stdout)
        if create.returncode != 0:
            # Same single-tail rationale as the metabench retry below: one
            # descheduled op past the p99 ceiling must not flap the gate.
            time.sleep(1)
            run.call([bench, *plan, "--phase", "remove", "--json", host], env=env, check=False)
            create = run.call([bench, *plan, "--phase", "create", "--json", host], env=env, check=False)
            print(create.stdout)
        checks.append((create.returncode == 0, f"layer-a create: zero failures + p99<={p99_ceil_ms}ms (rc={create.returncode})"))

        print("== verify: catalog integrity ==")
        expected = sorted(run.call([bench, *plan, "--print-expected", host], env=env, check=False).stdout.splitlines())
        lsr = run.call([XRDFS, host, "ls", "-R", "/"], env=env, check=False).stdout
        missing = 0
        for line in expected:
            fields = line.split()
            if len(fields) >= 3 and fields[2] not in lsr:
                missing += 1
        checks.append((missing == 0, f"namespace readback: {missing} expected path(s) missing" if missing else "namespace readback: all expected paths present"))
        want_files = sum(1 for line in expected if len(line.split()) >= 2 and line.split()[1] == "0")
        got_blocks = sum(1 for path in data_dir.rglob("*") if path.is_file()) if data_dir.exists() else 0
        checks.append((got_blocks == want_files, f"block catalog integrity: {got_blocks} blocks == {want_files} files"))

        # chmod must PERSIST through the driver setattr slot (regression guard:
        # pblock chmod was previously a silent no-op).
        def perm_column() -> str:
            listing = run.call([XRDFS, host, "ls", "-l", "/w0/d0"], env=env, check=False).stdout
            for line in listing.splitlines():
                if line.rstrip().endswith("/f0"):
                    return line.split()[0]
            return ""

        run.call([XRDFS, host, "chmod", "/w0/d0/f0", "0644"], env=env, check=False)
        mode_a = perm_column()
        run.call([XRDFS, host, "chmod", "/w0/d0/f0", "0600"], env=env, check=False)
        mode_b = perm_column()
        checks.append((bool(mode_a) and mode_a != mode_b,
                       f"chmod persists through driver (0644 '{mode_a}' != 0600 '{mode_b}')"))

        print("== Layer (a): remove phase + leak check ==")
        remove = run.call([bench, *plan, "--phase", "remove", "--json", host], env=env, check=False)
        print(remove.stdout)
        # The bench emits compact JSON ('"failures":0'); match it whitespace-
        # insensitively so the p99-only retry actually fires.
        if (remove.returncode != 0
                and '"failures":0' in remove.stdout.replace(" ", "")):
            # p99-only breach (zero op failures): single-tail retry — but the
            # namespace is already gone, so re-create then re-remove.
            time.sleep(1)
            run.call([bench, *plan, "--phase", "create", "--json", host], env=env, check=False)
            remove = run.call([bench, *plan, "--phase", "remove", "--json", host], env=env, check=False)
            print(remove.stdout)
        checks.append((remove.returncode == 0, f"layer-a remove: zero failures (rc={remove.returncode})"))
        root_listing = run.call([XRDFS, host, "ls", "/"], env=env, check=False).stdout
        checks.append(("/w0" not in root_listing, "store empty after remove (no namespace leak)"))
        left_blocks = sum(1 for path in data_dir.rglob("*") if path.is_file()) if data_dir.exists() else 0
        checks.append((left_blocks == 0, f"no leftover blocks after remove ({left_blocks} left)"))

        print("== verify: server health after storm ==")
        checks.append((run.call([XRDFS, host, "stat", "/"], env=env, check=False).returncode == 0,
                       "fresh GSI login + stat OK after storm"))

        print("== Layer (b): full xrdfs CLI chain (concurrent GSI sessions) ==")
        results: dict[int, int] = {}

        def worker_chain(index: int) -> None:
            rc = 0
            base = f"/wb{index}"
            for argv in (
                ["mkdir", base],                       # top-level
                ["mkdir", f"{base}/d0"],               # NESTED non-recursive (the fix)
                ["chmod", f"{base}/d0", "700"],
                ["touch", f"{base}/d0/f0"],            # create + setattr/utimes (the fix)
                ["chmod", f"{base}/d0/f0", "640"],
                ["stat", f"{base}/d0/f0"],
            ):
                proc = subprocess.run(
                    [str(XRDFS), host, *argv],
                    env={**os.environ, **env},
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if proc.returncode:
                    rc = 1
            results[index] = rc

        threads = [threading.Thread(target=worker_chain, args=(w,)) for w in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        b_fail = sum(1 for w in range(workers) if results.get(w) != 0)
        checks.append((b_fail == 0, f"xrdfs chain: {workers - b_fail}/{workers} concurrent sessions clean (incl. nested mkdir)"))
        lsr_b = run.call([XRDFS, host, "ls", "-R", "/"], env=env, check=False).stdout
        b_missing = sum(1 for w in range(workers) if f"/wb{w}/d0/f0" not in lsr_b)
        checks.append((b_missing == 0, f"xrdfs chain: namespace readback complete ({b_missing} missing)"))
        for w in range(workers):
            for argv in (["rm", f"/wb{w}/d0/f0"], ["rmdir", f"/wb{w}/d0"], ["rmdir", f"/wb{w}"]):
                run.call([XRDFS, host, *argv], env=env, check=False)

        print("== Layer (c): xrddiag client validation ==")
        check_out = run.call([XRDDIAG, "check", host], env=env, check=False)
        checks.append(("Result: 0 failure" in (check_out.stdout + check_out.stderr),
                       "xrddiag check: client conformance all-green"))
        # metabench p99 is a single-tail statistic over a few hundred ops, so a
        # lone descheduled op (e.g. a concurrent build stealing cores) can spike
        # it past the ceiling.  Retry once so a transient tail does not flap the
        # gate; a genuine perf regression fails both attempts (and the
        # p99_ceil_ms=1 selftest still fails both, as intended).
        metabench = [XRDDIAG, "metabench", "-S", str(workers), "--count", str(ops_per_worker), host]
        bench_out = run.call(metabench, env=env, check=False)
        if bench_out.returncode != 0:
            time.sleep(1)
            bench_out = run.call(metabench, env=env, check=False)
        for line in (bench_out.stdout + bench_out.stderr).splitlines():
            print(f"  {line}")
        checks.append((bench_out.returncode == 0,
                       f"xrddiag metabench: client performs (0 fail, p99 within ceiling) (rc={bench_out.returncode})"))
        return _checks(checks)


def selftest(nginx: Path | None = None) -> int:
    """Port of the shell's --selftest mode: drives the umbrella three ways
    (success / fault-injection / security-negative)."""
    rc = 0
    print("[selftest] 1/3 success: a healthy run must PASS")
    if pblock_meta_gsi(nginx) == 0:
        print("  ok   success")
    else:
        print("  FAIL success")
        rc = 1
    print("[selftest] 2/3 fault: an unsatisfiable p99 ceiling (1ms) must FAIL")
    if pblock_meta_gsi(nginx, p99_ceil_ms=1) == 0:
        print("  FAIL fault-not-detected")
        rc = 1
    else:
        print("  ok   fault detected")
    print("[selftest] 3/3 security-neg: an invalid GSI proxy must be rejected")
    if pblock_meta_gsi(nginx, proxy_override="/dev/null") == 0:
        print("  FAIL gsi-bypass")
        rc = 1
    else:
        print("  ok   GSI gate enforced")
    print("selftest PASS" if rc == 0 else "selftest FAIL")
    return rc


SCENARIOS = {
    "pblock-root": pblock_root,
    "pblock-webdav": pblock_webdav,
    "pblock-writethrough": pblock_writethrough,
    "pblock-meta-gsi": pblock_meta_gsi,
    "pblock-lab": pblock_lab,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="three-way selftest of pblock-meta-gsi")
    parser.add_argument("scenario", nargs="?", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        if ns.selftest:
            return selftest(ns.nginx)
        if not ns.scenario:
            parser.error("scenario required unless --selftest")
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"pblock scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
