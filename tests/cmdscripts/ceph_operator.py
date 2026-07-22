"""Python ports for tests/ceph/*.sh operator/live harnesses."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import os
import shutil
import subprocess
import tarfile
import tempfile

from cmdscripts.compile_run import REPO_ROOT, result, run


CEPH = REPO_ROOT / "tests" / "ceph"


def _tail(proc: subprocess.CompletedProcess, limit: int = 3000) -> str:
    return (proc.stderr or proc.stdout or "")[-limit:]


def _docker(argv: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.Popen(
        ["docker", *argv],
        cwd=str(REPO_ROOT),
        text=False,
        stdin=subprocess.PIPE if input_bytes is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate(input_bytes)
    return subprocess.CompletedProcess(["docker", *argv], proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace"))


def _docker_text(argv: list[str]) -> subprocess.CompletedProcess:
    return run(["docker", *argv], cwd=REPO_ROOT)


def _need_docker() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "SKIP: docker not found"
    return True, ""


def _container_running(name: str) -> bool:
    proc = _docker_text(["ps", "--format", "{{.Names}}"])
    return proc.returncode == 0 and name in proc.stdout.splitlines()


def _cp_many(work: str, files: Iterable[str]) -> subprocess.CompletedProcess | None:
    for rel in files:
        proc = _docker_text(["cp", str(REPO_ROOT / rel), f"{work}:/work/repo/{rel}"])
        if proc.returncode != 0:
            return proc
    return None


def build_in_container(base: Path) -> tuple[bool, str]:
    ok, msg = _need_docker()
    if not ok:
        return result(True, msg)
    image = os.environ.get("IMAGE", "xrd-ceph-build")
    work = os.environ.get("WORK", "xrd-ceph-work")
    ceph_dir = Path(os.environ.get("CEPH_DIR", "/tmp/ceph-harness"))
    inspected = _docker_text(["image", "inspect", image])
    if inspected.returncode != 0:
        return result(True, f"SKIP: build Docker image first: docker build -f tests/ceph/Dockerfile.build -t {image} tests/ceph")
    if not (ceph_dir / "ceph.conf").exists():
        return result(True, "SKIP: start Ceph harness first")
    _docker_text(["rm", "-f", work])
    started = _docker_text(["run", "-d", "--name", work, "--network", "host", image, "-c", "sleep infinity"])
    if started.returncode != 0:
        return result(False, f"docker run failed: {_tail(started)}")
    _docker_text(["exec", work, "mkdir", "-p", "/work/repo"])
    # Pack ONLY the source tree into the module build context. The in-container
    # build runs its own configure+make in /opt/nginx-src with
    # --add-module=/work/repo, so it needs the repo's sources and root ./config --
    # never build output, vendored deps, virtualenvs, or agent caches. Prune those
    # whole subtrees from the walk (os.walk so we never descend into them): the old
    # rglob("*") stat-walked + gzip-tar'd all 5G+/100k+ files one at a time --
    # .rpmbuild alone is a 3G rpm BUILD tree -- stalling the session fixture for
    # tens of minutes before the build could even start.
    prune_dirs = {
        ".git", ".tmp", ".rpmbuild", "node_modules", "__pycache__",
        ".venv", ".venv311", ".opencode", ".claude", ".superpowers",
        ".cache", "objs", "site",
    }
    skip_ext = (".o", ".pic.o", ".pyc")
    tar_path = base / "xrd-src.tgz"
    with tarfile.open(tar_path, "w:gz") as tar:
        for root, dirs, filenames in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in prune_dirs]
            for name in filenames:
                if name.endswith(skip_ext):
                    continue
                path = Path(root) / name
                tar.add(path, arcname=str(path.relative_to(REPO_ROOT)), recursive=False)
    with tar_path.open("rb") as fh:
        copied = _docker(["exec", "-i", work, "tar", "xzf", "-", "-C", "/work/repo"], input_bytes=fh.read())
    if copied.returncode != 0:
        return result(False, f"source tar copy failed: {_tail(copied)}")
    for src, dst in ((ceph_dir / "ceph.conf", "/etc/ceph/ceph.conf"), (ceph_dir / "ceph.client.admin.keyring", "/etc/ceph/ceph.client.admin.keyring")):
        proc = _docker_text(["cp", str(src), f"{work}:{dst}"])
        if proc.returncode != 0:
            return result(False, f"docker cp {src} failed: {_tail(proc)}")
    built = _docker_text([
        "exec",
        work,
        "bash",
        "-lc",
        "cd /opt/nginx-src && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=/work/repo && make -j$(nproc) && ls -l objs/nginx",
    ])
    return result(built.returncode == 0, f"build_in_container exited {built.returncode}: {_tail(built)}")


def sd_ceph_live(base: Path) -> tuple[bool, str]:
    ok, msg = _need_docker()
    if not ok:
        return result(True, msg)
    work = os.environ.get("WORK", "xrd-ceph-work")
    if not _container_running(work):
        return result(True, f"SKIP: work container {work} not running")
    files = [
        "src/fs/backend/rados/sd_ceph.c",
        "src/fs/backend/rados/sd_ceph_io.c",
        "src/fs/backend/rados/sd_ceph_object.c",
        "src/fs/backend/rados/sd_ceph_cred.c",
        "src/fs/backend/rados/sd_ceph_dir.c",
        "src/fs/backend/rados/sd_ceph_internal.h",
        "src/fs/backend/rados/sd_ceph.h",
        "src/fs/backend/rados/sd_ceph_striper.h",
        "src/fs/backend/rados/sd_ceph_object_rename.c",
        "src/fs/backend/rados/sd_ceph_compat.c",
        "tests/ceph/sd_ceph_live_test.c",
        "client/apps/ceph/ngx_shim.h",
    ]
    _docker_text(["exec", work, "mkdir", "-p", "/work/repo/tests/ceph", "/work/repo/src/fs/backend/rados", "/work/repo/client/apps/ceph"])
    failed = _cp_many(work, files)
    if failed:
        return result(False, f"docker cp failed: {_tail(failed)}")
    cmd = (
        "cd /work/repo && gcc -Wall -Wextra -Werror -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH "
        "-I src -I src/fs/backend -I src/fs/backend/rados -include client/apps/ceph/ngx_shim.h "
        "tests/ceph/sd_ceph_live_test.c src/fs/backend/rados/sd_ceph.c "
        "src/fs/backend/rados/sd_ceph_object_rename.c "
        "src/fs/backend/rados/sd_ceph_io.c src/fs/backend/rados/sd_ceph_object.c "
        "src/fs/backend/rados/sd_ceph_cred.c src/fs/backend/rados/sd_ceph_dir.c "
        "src/fs/backend/rados/sd_ceph_compat.c "
        "-lrados -o /tmp/sd_ceph_live && /tmp/sd_ceph_live"
    )
    proc = _docker_text(["exec", "-e", f"CEPH_POOL={os.environ.get('CEPH_POOL', 'xrdtest')}", "-e", "CEPH_CONF=/etc/ceph/ceph.conf", work, "bash", "-lc", cmd])
    return result(proc.returncode == 0, f"sd_ceph_live exited {proc.returncode}: {_tail(proc)}")


def sd_ceph_cred_live(base: Path) -> tuple[bool, str]:
    ok, msg = _need_docker()
    if not ok:
        return result(True, msg)
    work = os.environ.get("WORK", "xrd-ceph-work")
    demo = os.environ.get("DEMO", "xrd-ceph-demo")
    pool = os.environ.get("CEPH_POOL", "xrdtest")
    if not _container_running(work) or not _container_running(demo):
        return result(True, "SKIP: Ceph work/demo containers not running")
    provision = (
        f"ceph auth get-or-create client.bob mon 'allow r' osd 'allow rwx pool={pool}' -o /tmp/ceph.client.bob.keyring && "
        f"ceph auth get-or-create client.readonly mon 'allow r' osd 'allow r pool={pool}' -o /tmp/ceph.client.readonly.keyring && "
        "for i in $(seq 0 9); do ceph auth get-or-create client.u$i mon 'allow r' osd 'allow r pool="
        f"{pool}' -o /tmp/ceph.client.u$i.keyring; done"
    )
    prov = _docker_text(["exec", demo, "bash", "-lc", provision])
    if prov.returncode != 0:
        return result(False, f"CephX provisioning failed: {_tail(prov)}")
    for name in ["bob", "readonly", *[f"u{i}" for i in range(10)]]:
        cat = _docker(["exec", demo, "cat", f"/tmp/ceph.client.{name}.keyring"])
        if cat.returncode == 0:
            _docker(["exec", "-i", work, "tee", f"/etc/ceph/ceph.client.{name}.keyring"], input_bytes=cat.stdout.encode())
    files = [
        "src/fs/backend/rados/sd_ceph.c", "src/fs/backend/rados/sd_ceph_io.c",
        "src/fs/backend/rados/sd_ceph_object.c", "src/fs/backend/rados/sd_ceph_cred.c",
        "src/fs/backend/rados/sd_ceph_dir.c",
        "src/fs/backend/rados/sd_ceph_internal.h", "src/fs/backend/rados/sd_ceph.h",
        "src/fs/backend/rados/sd_ceph_object_rename.c",
        "src/fs/backend/rados/sd_ceph_compat.c", "src/fs/backend/rados/sd_ceph_compat.h",
        "src/fs/backend/rados/sd_ceph_striper.h", "src/fs/backend/ucred.h",
        "tests/ceph/sd_ceph_cred_live_test.c", "client/apps/ceph/ngx_shim.h",
    ]
    _docker_text(["exec", work, "mkdir", "-p", "/work/repo/tests/ceph", "/work/repo/src/fs/backend/rados", "/work/repo/client/apps/ceph"])
    failed = _cp_many(work, files)
    if failed:
        return result(False, f"docker cp failed: {_tail(failed)}")
    cmd = (
        "cd /work/repo && gcc -Wall -Wextra -Werror -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH "
        "-I src -I src/fs/backend -I src/fs/backend/rados -include client/apps/ceph/ngx_shim.h "
        "tests/ceph/sd_ceph_cred_live_test.c src/fs/backend/rados/sd_ceph.c "
        "src/fs/backend/rados/sd_ceph_object_rename.c "
        "src/fs/backend/rados/sd_ceph_io.c src/fs/backend/rados/sd_ceph_object.c "
        "src/fs/backend/rados/sd_ceph_cred.c src/fs/backend/rados/sd_ceph_dir.c "
        "src/fs/backend/rados/sd_ceph_compat.c "
        "-lrados -o /tmp/sd_ceph_cred_live && /tmp/sd_ceph_cred_live"
    )
    proc = _docker_text(["exec", "-e", f"CEPH_POOL={pool}", "-e", "CEPH_CONF=/etc/ceph/ceph.conf", "-e", "CEPH_BOB_KEYRING=/etc/ceph/ceph.client.bob.keyring", "-e", "CEPH_READONLY_KEYRING=/etc/ceph/ceph.client.readonly.keyring", "-e", "CEPH_UN_KEYRING_DIR=/etc/ceph", work, "bash", "-lc", cmd])
    return result(proc.returncode == 0, f"sd_ceph_cred_live exited {proc.returncode}: {_tail(proc)}")


def cephfs_ro_live(base: Path) -> tuple[bool, str]:
    ok, msg = _need_docker()
    if not ok:
        return result(True, msg)
    work = os.environ.get("WORK", "xrd-ceph-work")
    if not _container_running(work):
        return result(True, f"SKIP: work container {work} not running")
    files = [
        "src/fs/backend/sd.h", "src/fs/backend/rados/sd_ceph.c", "src/fs/backend/rados/sd_ceph.h",
        "src/fs/backend/rados/sd_ceph_internal.h", "src/fs/backend/rados/sd_ceph_io.c",
        "src/fs/backend/rados/sd_ceph_object.c", "src/fs/backend/rados/sd_ceph_cred.c",
        "src/fs/backend/rados/sd_ceph_dir.c",
        "src/fs/backend/rados/sd_ceph_striper.h", "src/fs/backend/rados/sd_ceph_compat.h",
        "src/fs/backend/rados/sd_ceph_compat.c", "src/fs/backend/rados/cephfs_denc.c",
        "src/fs/backend/rados/cephfs_denc.h", "src/fs/backend/rados/cephfs_layout.c",
        "src/fs/backend/rados/cephfs_layout.h", "src/fs/backend/rados/sd_cephfs_ro.c",
        "src/fs/backend/rados/sd_cephfs_ro_internal.h", "src/fs/backend/rados/sd_cephfs_ro_resolve.c",
        "src/fs/backend/rados/sd_cephfs_ro_dir.c", "client/apps/ceph/ngx_shim.h",
        "src/fs/backend/rados/sd_ceph_object_rename.c",
        "tests/ceph/sd_cephfs_ro_live_test.c",
    ]
    _docker_text(["exec", work, "mkdir", "-p", "/work/repo/src/fs/backend/rados", "/work/repo/tests/ceph", "/work/repo/client/apps/ceph"])
    failed = _cp_many(work, files)
    if failed:
        return result(False, f"docker cp failed: {_tail(failed)}")
    cmd = (
        "cd /work/repo && gcc -Wall -Wextra -Werror -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH "
        "-I src -I src/fs/backend -I src/fs/backend/rados -include client/apps/ceph/ngx_shim.h "
        "tests/ceph/sd_cephfs_ro_live_test.c src/fs/backend/rados/sd_cephfs_ro.c "
        "src/fs/backend/rados/sd_cephfs_ro_resolve.c src/fs/backend/rados/sd_cephfs_ro_dir.c "
        "src/fs/backend/rados/sd_ceph.c src/fs/backend/rados/sd_ceph_io.c "
        "src/fs/backend/rados/sd_ceph_object.c src/fs/backend/rados/sd_ceph_object_rename.c "
        "src/fs/backend/rados/sd_ceph_cred.c "
        "src/fs/backend/rados/sd_ceph_dir.c "
        "src/fs/backend/rados/sd_ceph_compat.c src/fs/backend/rados/cephfs_layout.c "
        "src/fs/backend/rados/cephfs_denc.c -lrados -o /tmp/cephfsro_live && /tmp/cephfsro_live"
    )
    proc = _docker_text(["exec", "-e", "CEPH_CONF=/etc/ceph/ceph.conf", work, "bash", "-lc", cmd])
    return result(proc.returncode == 0, f"cephfs_ro_live exited {proc.returncode}: {_tail(proc)}")


def ceph_export_smoke(base: Path) -> tuple[bool, str]:
    ok, msg = _need_docker()
    if not ok:
        return result(True, msg)
    work = os.environ.get("WORK", "xrd-ceph-work")
    if not _container_running(work):
        return result(True, f"SKIP: work container {work} not running")
    cmd = r"""
# net-literal-allow: container-internal loopback (script runs inside ceph container)
set -u
NGINX=/opt/nginx-src/objs/nginx
RUN=/work/run
RPORT=1094
HPORT=8080
POOL="${CEPH_POOL:-xrdtest}"
XRDCP="$(command -v xrdcp)"
XRDFS="$(command -v xrdfs)"
[ -n "$XRDCP" ] && [ -n "$XRDFS" ] || exit 2
pkill -9 nginx 2>/dev/null; sleep 1
# -p "$RUN" below relocates nginx's prefix so its default temp/log dirs resolve
# under $RUN; without it the module build's default prefix (/usr/local/nginx) is
# never created (no `make install`) and `nginx -t` dies on mkdir(proxy_temp).
rm -rf "$RUN"; mkdir -p "$RUN/tmp" "$RUN/logs" /export
# Workers de-escalate unconditionally (always-on brix worker drop): a root
# master's workers land on a confined account, which must still be able to
# read the Ceph conf/keyring and write the export + temp dirs. Provision a
# dedicated non-root account rather than serving as "nobody".
id -u xrdsmoke >/dev/null 2>&1 || useradd -r -M -s /sbin/nologin xrdsmoke
chmod a+r /etc/ceph/ceph.conf /etc/ceph/*.keyring 2>/dev/null
chown -R xrdsmoke "$RUN" /export
cat > "$RUN/nginx.conf" <<EOF
daemon on;
user xrdsmoke;
worker_processes 1;
error_log $RUN/error.log info;
pid $RUN/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${RPORT}; brix_root on; brix_export /export; brix_auth none; brix_allow_write on; brix_upload_resume off; brix_storage_backend ceph:${POOL}; brix_access_log $RUN/xrd_access.log; } }
http { access_log off; client_max_body_size 0; client_body_temp_path $RUN/tmp; server { listen 127.0.0.1:${HPORT}; location / { brix_webdav on; brix_export /export; brix_webdav_auth none; brix_allow_write on; } } }
EOF
"$NGINX" -p "$RUN" -t -c "$RUN/nginx.conf" || exit 2
"$NGINX" -p "$RUN" -c "$RUN/nginx.conf" || exit 2
trap '[ -f "$RUN/nginx.pid" ] && kill "$(cat "$RUN/nginx.pid")" 2>/dev/null' EXIT
sleep 1
head -c 1500000 /dev/urandom > /tmp/in.bin
"$XRDCP" -f /tmp/in.bin root://127.0.0.1:${RPORT}//c1.bin
"$XRDCP" -f root://127.0.0.1:${RPORT}//c1.bin /tmp/out1.bin
cmp -s /tmp/in.bin /tmp/out1.bin || exit 1
curl -sf -T /tmp/in.bin http://127.0.0.1:${HPORT}/w1.bin
curl -sf http://127.0.0.1:${HPORT}/w1.bin -o /tmp/out2.bin
cmp -s /tmp/in.bin /tmp/out2.bin || exit 1
rados -c /etc/ceph/ceph.conf -p "$POOL" ls | grep -q 'c1.bin'
echo "ceph_export_smoke: ALL PASS"
"""
    proc = _docker_text(["exec", "-e", f"CEPH_POOL={os.environ.get('CEPH_POOL', 'xrdtest')}", work, "bash", "-lc", cmd])
    return result(proc.returncode == 0, f"ceph_export_smoke exited {proc.returncode}: {_tail(proc)}")


def cephfs_ro_smoke(base: Path) -> tuple[bool, str]:
    ok, msg = _need_docker()
    if not ok:
        return result(True, msg)
    work = os.environ.get("WORK", "xrd-ceph-work")
    if not _container_running(work):
        return result(True, f"SKIP: work container {work} not running")
    cmd = r"""
# net-literal-allow: container-internal loopback (script runs inside ceph container)
set -u
NGINX=/opt/nginx-src/objs/nginx
RUN=/work/run-ro
RPORT=1095
HPORT=8081
META="${CEPHFS_META:-cephfs_metadata}"
DATA="${CEPHFS_DATA:-cephfs_data}"
ASSERT="${CEPHFS_ASSERT:-assume_quiesced=1}"
XRDCP="$(command -v xrdcp)"
XRDFS="$(command -v xrdfs)"
[ -n "$XRDCP" ] && [ -n "$XRDFS" ] || exit 2
pkill -9 nginx 2>/dev/null; sleep 1
# -p "$RUN" relocates the nginx prefix so default temp/log dirs resolve under
# $RUN (the module build's default /usr/local/nginx prefix is never created).
rm -rf "$RUN"; mkdir -p "$RUN/tmp" "$RUN/logs" /export
cat > "$RUN/nginx.conf" <<EOF
daemon on;
user root;
worker_processes 1;
error_log $RUN/error.log info;
pid $RUN/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${RPORT}; brix_root on; brix_export /export; brix_auth none; brix_storage_backend cephfsro:${META}+${DATA}?${ASSERT}; brix_access_log $RUN/xrd_access.log; } }
http { access_log off; client_body_temp_path $RUN/tmp; server { listen 127.0.0.1:${HPORT}; location / { brix_webdav on; brix_export /export; brix_webdav_auth none; } } }
EOF
"$NGINX" -p "$RUN" -t -c "$RUN/nginx.conf" || exit 2
"$NGINX" -p "$RUN" -c "$RUN/nginx.conf" || exit 2
trap '[ -f "$RUN/nginx.pid" ] && kill "$(cat "$RUN/nginx.pid")" 2>/dev/null' EXIT
sleep 1
"$XRDFS" root://127.0.0.1:${RPORT} stat /dir1/sub/big.bin | grep -q 'Size: 5242880'
"$XRDCP" -f root://127.0.0.1:${RPORT}//dir1/hello.txt /tmp/hello.out
grep -q 'HELLO CEPHFS via libcephfs' /tmp/hello.out
curl -sf http://127.0.0.1:${HPORT}/dir1/hello.txt -o /tmp/hello.web
grep -q 'HELLO CEPHFS via libcephfs' /tmp/hello.web
echo "cephfs_ro_smoke: ALL PASS"
"""
    proc = _docker_text(["exec", "-e", f"CEPHFS_META={os.environ.get('CEPHFS_META', 'cephfs_metadata')}", "-e", f"CEPHFS_DATA={os.environ.get('CEPHFS_DATA', 'cephfs_data')}", work, "bash", "-lc", cmd])
    return result(proc.returncode == 0, f"cephfs_ro_smoke exited {proc.returncode}: {_tail(proc)}")


def striper_migrate(base: Path) -> tuple[bool, str]:
    ok, msg = _need_docker()
    if not ok:
        return result(True, msg)
    work = os.environ.get("WORK", "xrd-ceph-work")
    if not _container_running(work):
        return result(True, f"SKIP: work container {work} not running")
    _docker_text(["exec", work, "mkdir", "-p", "/work/repo/tests/ceph", "/work/repo/client/apps/ceph"])
    failed = _cp_many(work, ["tests/ceph/striper_seed.c", "client/apps/ceph/xrdceph_striper_migrate.cpp", "client/apps/ceph/xrdceph_migrate_config.h"])
    if failed:
        return result(False, f"docker cp failed: {_tail(failed)}")
    cmd = "cd /work/repo && gcc -Wall -D_FILE_OFFSET_BITS=64 tests/ceph/striper_seed.c -lradosstriper -lrados -o /tmp/striper_seed && g++ -std=c++17 -Wall -D_FILE_OFFSET_BITS=64 client/apps/ceph/xrdceph_striper_migrate.cpp -lrados -lcephfs -lpthread -o /tmp/migtool && /tmp/migtool --help >/dev/null"
    proc = _docker_text(["exec", "-e", "CEPH_CONF=/etc/ceph/ceph.conf", work, "bash", "-lc", cmd])
    return result(proc.returncode == 0, f"striper migrate build smoke exited {proc.returncode}: {_tail(proc)}")


def rescue_tools(base: Path) -> tuple[bool, str]:
    ok, msg = _need_docker()
    if not ok:
        return result(True, msg)
    work = os.environ.get("WORK", "xrd-ceph-work")
    if not _container_running(work):
        return result(True, f"SKIP: work container {work} not running")
    # Keep in step with client/Makefile's CEPH_CORE_SRCS / CEPHFS_RO_SRCS — that is the
    # build's source of truth (the RPM drives it too); this list only has to carry the
    # same TUs, plus the headers they include, into the container.
    files = [
        "src/fs/backend/sd.h", "src/fs/backend/rados/sd_ceph.c", "src/fs/backend/rados/sd_ceph.h",
        "src/fs/backend/rados/sd_ceph_internal.h", "src/fs/backend/rados/sd_ceph_io.c",
        "src/fs/backend/rados/sd_ceph_cred.c", "src/fs/backend/rados/sd_ceph_object.c",
        "src/fs/backend/rados/sd_ceph_object_rename.c",
        "src/fs/backend/rados/sd_ceph_dir.c",
        "src/fs/backend/rados/sd_ceph_striper.h", "src/fs/backend/rados/sd_ceph_compat.c",
        "src/fs/backend/rados/sd_ceph_compat.h", "src/fs/backend/rados/cephfs_denc.c",
        "src/fs/backend/rados/cephfs_denc.h", "src/fs/backend/rados/cephfs_layout.c",
        "src/fs/backend/rados/cephfs_layout.h", "src/fs/backend/rados/sd_cephfs_ro.c",
        "src/fs/backend/rados/sd_cephfs_ro_internal.h", "src/fs/backend/rados/sd_cephfs_ro_dir.c",
        "src/fs/backend/rados/sd_cephfs_ro_resolve.c",
        "client/apps/ceph/ngx_shim.h", "client/apps/ceph/xrdcephfs_rescue.c",
        "client/apps/ceph/xrdrados_rescue.c", "client/apps/ceph/xrdceph_migrate.c",
    ]
    _docker_text(["exec", work, "mkdir", "-p", "/work/repo/src/fs/backend/rados", "/work/repo/client/apps/ceph"])
    failed = _cp_many(work, files)
    if failed:
        return result(False, f"docker cp failed: {_tail(failed)}")
    # Mirrors client/Makefile CEPH_CORE_SRCS / CEPHFS_RO_SRCS.  The tools compile the
    # driver TUs directly, so these lists are a symbol closure: when a TU is split,
    # omitting the new sibling here fails at LINK ("undefined reference to sd_ceph_*"),
    # not at compile.  sd_ceph_striper.c is deliberately absent — unreferenced here,
    # and it would drag in libradosstriper.
    cmd = (
        "cd /work/repo && FLAT_SRCS='src/fs/backend/rados/sd_ceph.c src/fs/backend/rados/sd_ceph_compat.c "
        "src/fs/backend/rados/sd_ceph_io.c src/fs/backend/rados/sd_ceph_cred.c "
        "src/fs/backend/rados/sd_ceph_object.c src/fs/backend/rados/sd_ceph_object_rename.c "
        "src/fs/backend/rados/sd_ceph_dir.c' && "
        "CEPHFS_SRCS=\"src/fs/backend/rados/sd_cephfs_ro.c src/fs/backend/rados/sd_cephfs_ro_dir.c "
        "src/fs/backend/rados/sd_cephfs_ro_resolve.c src/fs/backend/rados/cephfs_layout.c "
        "src/fs/backend/rados/cephfs_denc.c $FLAT_SRCS\" && "
        "CC='gcc -Wall -Wextra -Werror -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH -I src -I src/fs/backend -I src/fs/backend/rados -include client/apps/ceph/ngx_shim.h' && "
        "$CC client/apps/ceph/xrdcephfs_rescue.c $CEPHFS_SRCS -lrados -o /tmp/xrdcephfs_rescue && "
        "$CC client/apps/ceph/xrdrados_rescue.c $FLAT_SRCS -lrados -o /tmp/xrdrados_rescue && "
        "$CC client/apps/ceph/xrdceph_migrate.c $FLAT_SRCS -lrados -o /tmp/xrdceph_migrate"
    )
    proc = _docker_text(["exec", "-e", "CEPH_CONF=/etc/ceph/ceph.conf", work, "bash", "-lc", cmd])
    return result(proc.returncode == 0, f"rescue tools build exited {proc.returncode}: {_tail(proc)}")


def py_migrate(base: Path) -> tuple[bool, str]:
    ok, msg = _need_docker()
    if not ok:
        return result(True, msg)
    work = os.environ.get("WORK", "xrd-ceph-work")
    if not _container_running(work):
        return result(True, f"SKIP: work container {work} not running")
    _docker_text(["exec", work, "mkdir", "-p", "/work/pymig"])
    for rel in ["client/apps/ceph/pymigrate", "client/apps/ceph/xrdceph_striper_migrate.py", "client/apps/ceph/xrdceph_cephfs_to_striper.py", "tests/ceph/striper_seed.c"]:
        dest = f"{work}:/work/pymig/{Path(rel).name if rel.endswith('.py') or rel.endswith('.c') else 'pymigrate'}"
        proc = _docker_text(["cp", str(REPO_ROOT / rel), dest])
        if proc.returncode != 0:
            return result(False, f"docker cp {rel} failed: {_tail(proc)}")
    cmd = "cd /work/pymig && python3 xrdceph_striper_migrate.py --help >/dev/null && python3 xrdceph_cephfs_to_striper.py --help >/dev/null"
    proc = _docker_text(["exec", "-e", "CEPH_CONF=/etc/ceph/ceph.conf", work, "bash", "-lc", cmd])
    return result(proc.returncode == 0, f"py migrate help smoke exited {proc.returncode}: {_tail(proc)}")


RUNNERS = {
    "build_in_container": build_in_container,
    "striper_migrate": striper_migrate,
    "rescue_tools": rescue_tools,
    "cephfs_ro_live": cephfs_ro_live,
    "ceph_export_smoke": ceph_export_smoke,
    "py_migrate": py_migrate,
    "sd_ceph_cred_live": sd_ceph_cred_live,
    "cephfs_ro_smoke": cephfs_ro_smoke,
    "sd_ceph_live": sd_ceph_live,
}


def run_checks(base: Path, names: Iterable[str] | None = None) -> list[tuple[bool, str]]:
    selected = list(names or [])
    if not selected:
        return [result(True, "Ceph operator ports are importable; execution is opt-in")]
    results = []
    for name in selected:
        runner = RUNNERS.get(name)
        if runner is None:
            results.append(result(False, f"unknown Ceph runner: {name}"))
            continue
        if os.environ.get("PHASE81_RUN_CEPH_PORTS") != "1":
            results.append(result(True, f"SKIP {name}: set PHASE81_RUN_CEPH_PORTS=1 to execute"))
            continue
        work = base / name
        work.mkdir(parents=True, exist_ok=True)
        results.append(runner(work))
    return results


def entry(argv: list[str]) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ceph_operator.") as tmp:
        results = run_checks(Path(tmp), argv)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
