# tests/test_cvmfs_ingest_oracle.py — phase-104 D10: the composition oracle.
# mock OCI registry → `brixcvmfs ingest image` → nginx Stratum-0 → verifiers
# that are NOT our own read stack: the OFFICIAL cvmfs2 client (in the
# registry.cern.ch/cvmfs/service container, phase-96 S9 pattern) walks the
# mounted tree, and PODMAN is the flatten oracle — its own export of the same
# image (whiteout applied by podman's overlay code) must diff-walk clean
# against what cvmfs serves. The headline leg then round-trips a freshly
# imported image through podman push → ingest → host FUSE mount →
# `podman run --rootfs` off /cvmfs.
#
# Error leg: Stratum-0 down → the official client fails the mount inside its
# container (no host FUSE mount, so the orphaned-mount fleet trap cannot
# trigger). Security leg: one flipped byte in a live CAS payload object → the
# official client refuses the object's bytes. The serve side here is a plain
# stratum-0 file serve — the signal=cvmfs_tamper guard line belongs to the
# cache-fronted composition (D14), not this lane.
#
# Rootless pre-flights pinned from the App-Z manual run (both fail as a bare
# ENOENT otherwise): the host mount uses -o allow_other (needs
# user_allow_other in /etc/fuse.conf) and `podman system migrate` runs after
# mounting so the pause process's namespace sees the fresh mount.
# Ports: srv_ingest_oracle block (canonical 13660; session-tiled).
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

import pytest

def _check_podman_truth_1(r):
    assert r.returncode == 0, r.stderr.decode()

def _check_podman_truth_2(cid):
    assert cid, "podman create produced no container id"

def _check_podman_truth_3(exp):
    assert exp.returncode == 0, exp.stderr.decode()

def _guard_podman_truth_1(m, truth, name, tf):
    if m.isdir():
        truth[name.rstrip("/")] = ("dir", "")
    elif m.issym():
        truth[name] = ("link", m.linkname)
    elif m.isfile():
        truth[name] = ("file", hashlib.sha1(
            tf.extractfile(m).read()).hexdigest())

def _check_test_mounted_tree_diffwalks_clean_against_podman_4(truth):
    assert "share/extra" in truth and "share/data" not in truth, \
        f"fixture drift: podman truth {sorted(truth)}"

def _check_test_mounted_tree_diffwalks_clean_against_podman_5(walk):
    assert walk.returncode == 0 and "===OK===" in walk.stdout, \
        (walk.stdout + walk.stderr)[-800:]

def _check_test_mounted_tree_diffwalks_clean_against_podman_6(seen, truth):
    assert seen == truth, (
        f"only-cvmfs: {sorted(set(seen) - set(truth))[:10]}\n"
        f"only-podman: {sorted(set(truth) - set(seen))[:10]}\n"
        f"mismatch: {[p for p in set(seen) & set(truth) if seen[p] != truth[p]][:10]}")


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from cmdscripts.cvmfs_publish_txn import cas_path, lookup, open_catalog, parse_manifest
from cmdscripts.live_common import LiveRun
from conformance_common import BRIXMOUNT, NGINX_BIN, PortBlock, fuse_mount
from config_templates import render_config
from settings import BIND_HOST, HOST

REPO_ROOT = Path(__file__).resolve().parent.parent
BRIX = REPO_ROOT / "client" / "bin" / "brixcvmfs"
MOCK = Path(__file__).resolve().parent / "oci" / "mock_registry.py"

_BLOCK = PortBlock("srv_ingest_oracle")
MOCK_PORT = _BLOCK.mock()
NGINX_PORT = _BLOCK.nginx()
DOWN_PORT = _BLOCK.nginx()          # reserved, never bound: the error leg
FQRN = "oracle-img.brix.io"
IMAGE = os.environ.get("BRIX_CVMFS_SERVICE_IMAGE",
                       "registry.cern.ch/cvmfs/service:latest")
APP_ROOT = f"/images/{HOST}/lab/app:v2"     # tag symlink inside the repo

pytestmark = [
    pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                       reason=f"nginx binary not found: {NGINX_BIN}"),
    pytest.mark.skipif(not BRIX.exists(),
                       reason="client/bin/brixcvmfs not built (make -C client)"),
    pytest.mark.timeout(900),
    pytest.mark.slow,
]


def _preflight():
    # podman specifically: the oracle legs need --tls-verify=false against a
    # plain-http registry and `run --rootfs`, neither of which docker has.
    rt = shutil.which("podman")
    if rt is None:
        pytest.skip("no podman (the D10 oracle legs are podman-specific)")
    rt = "podman"
    if not os.path.exists("/dev/fuse"):
        pytest.skip("no /dev/fuse on this host")
    if subprocess.run([rt, "image", "inspect", IMAGE],
                      capture_output=True).returncode != 0:
        pull = subprocess.run([rt, "pull", IMAGE], capture_output=True,
                              text=True, timeout=600)
        if pull.returncode != 0:
            pytest.skip(f"cannot pull {IMAGE}: {pull.stderr.strip()[-200:]}")
    return rt


def _pod(rt, *args, timeout=300, stdin=None):
    return subprocess.run([rt, *map(str, args)], capture_output=True,
                          input=stdin, timeout=timeout)


def _brix(*args, env=None, timeout=180):
    full = dict(os.environ)
    if env:
        full.update(env)
    return subprocess.run([str(BRIX), *map(str, args)], capture_output=True,
                          text=True, timeout=timeout, env=full)


def _client_run(rt, pubdir, script):
    """Run a mount script inside the official-client container (S9 pattern)."""
    return subprocess.run(
        [rt, "run", "--rm", "--network=host", "--device", "/dev/fuse",
         "--cap-add", "SYS_ADMIN", "-v", f"{pubdir}:/brix:ro",
         "--entrypoint", "/bin/sh", IMAGE, "-c", script],
        capture_output=True, text=True, timeout=300)


def _mount_sh(pubdir_unused=None):
    return ("set -e\n"
            "mkdir -p /mnt/repo /tmp/cache\n"
            "cvmfs2 -o config=/brix/client.conf " + FQRN + " /mnt/repo"
            " >/tmp/mount.out 2>&1"
            " || { echo MOUNT_FAIL; cat /tmp/mount.out /tmp/cvmfs.log"
            " 2>/dev/null; exit 7; }\n")


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    """mock registry → ingest lab/app:v2 → nginx Stratum-0, once."""
    rt = _preflight()
    base = tmp_path_factory.mktemp("oracle")
    mock = subprocess.Popen(
        [sys.executable, str(MOCK), "--port", str(MOCK_PORT), "--push"])
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(
                    f"http://{HOST}:{MOCK_PORT}/ctl/log", timeout=0.2)
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("mock registry never came up")

        with LiveRun("cvmfs_ingest_oracle", NGINX_BIN) as run:
            run.mkdir("logs")
            web = run.mkdir("web")
            repo = run.mkdir("web", "cvmfs") / FQRN
            r = _brix("repo", "mkfs", FQRN, repo)
            assert r.returncode == 0, r.stderr
            r = _brix("ingest", "image", f"{HOST}:{MOCK_PORT}/lab/app:v2",
                      "--repo", repo, "--insecure")
            assert r.returncode == 0, r.stderr

            conf = run.write(
                run.root / f"nginx.{NGINX_PORT}.conf",
                render_config(
                    "nginx_cvmfs_stratum0_lab.conf",
                    USER_LINE="user root;\n" if os.geteuid() == 0 else "",
                    LOG_FILE=f"{run.root}/logs/e.{NGINX_PORT}.log",
                    PID_FILE=f"{run.root}/nginx.{NGINX_PORT}.pid",
                    BIND_HOST=BIND_HOST, PORT=NGINX_PORT,
                    LISTEN_SSL="", SSL_LINES="",
                    LOCATION_LINES=f"""
        brix_cvmfs on;
        brix_cvmfs_stratum0_root {web};"""))
            run.start_nginx(run.root, conf, NGINX_PORT)

            pubdir = base / "pub"
            pubdir.mkdir()
            (pubdir / f"{FQRN}.pub").write_bytes(
                (repo / "keys" / f"{FQRN}.pub").read_bytes())
            (pubdir / "client.conf").write_text(
                f"CVMFS_SERVER_URL=http://{HOST}:{NGINX_PORT}/cvmfs/{FQRN}\n"
                "CVMFS_HTTP_PROXY=DIRECT\n"
                f"CVMFS_PUBLIC_KEY=/brix/{FQRN}.pub\n"
                "CVMFS_CACHE_BASE=/tmp/cache\n"
                "CVMFS_RELOAD_SOCKETS=/tmp/cache\n"
                "CVMFS_USYSLOG=/tmp/cvmfs.log\n")
            yield rt, repo, pubdir, base
    finally:
        mock.terminate()
        mock.wait()


# ---- success 1: podman is the flatten oracle -----------------------------

def _podman_truth(rt):
    """{relpath: (kind, payload)} from podman's own flatten of lab/app:v2."""
    ref = f"{HOST}:{MOCK_PORT}/lab/app:v2"
    r = _pod(rt, "pull", "--tls-verify=false", ref)
    _check_podman_truth_1(r)
    cid = _pod(rt, "create", ref).stdout.decode().strip()
    _check_podman_truth_2(cid)
    try:
        exp = _pod(rt, "export", cid)
        _check_podman_truth_3(exp)
        # runtime files podman materializes in an exported container that are
        # not image content (exact names — image payload under etc/ must stay)
        synthetic = {"dev", "proc", "sys", "run", ".dockerenv",
                     "etc/hosts", "etc/hostname", "etc/resolv.conf",
                     "etc/mtab"}
        truth = {}
        with tarfile.open(fileobj=io.BytesIO(exp.stdout)) as tf:
            for m in tf:
                name = m.name
                if name.startswith("./"):
                    name = name[2:]
                if not name or name.rstrip("/") in synthetic:
                    continue
                _guard_podman_truth_1(m, truth, name, tf)
        return truth
    finally:
        _pod(rt, "rm", cid)


def test_mounted_tree_diffwalks_clean_against_podman(lab):
    rt, _repo, pubdir, _base = lab
    truth = _podman_truth(rt)
    _check_test_mounted_tree_diffwalks_clean_against_podman_4(truth)

    walk = _client_run(rt, pubdir, _mount_sh() + (
        f'cd "/mnt/repo{APP_ROOT}/"\n'
        "echo ===WALK===\n"
        "find . -mindepth 1 | sort | while read p; do\n"
        "  if [ -L \"$p\" ]; then echo \"L|$p|$(readlink \"$p\")\";\n"
        "  elif [ -d \"$p\" ]; then echo \"D|$p|\";\n"
        "  else echo \"F|$p|$(sha1sum \"$p\" | cut -d' ' -f1)\"; fi\n"
        "done\n"
        "echo ===OK===\n"))
    _check_test_mounted_tree_diffwalks_clean_against_podman_5(walk)

    seen = {}
    kinds = {"D": "dir", "F": "file", "L": "link"}
    for line in walk.stdout.split("===WALK===\n", 1)[1].split("===OK===")[0].splitlines():
        k, name, payload = line.split("|", 2)
        if name.startswith("./"):
            name = name[2:]
        if name in (".manifest.json", ".config.json"):
            continue                    # our sidecars, not image content
        seen[name] = (kinds[k], payload)
    _check_test_mounted_tree_diffwalks_clean_against_podman_6(seen, truth)


# ---- success 2: podman runs a container off the cvmfs mount ---------------

def test_podman_runs_rootfs_from_cvmfs_mount(lab, tmp_path):
    rt, repo, _pubdir, _base = lab
    src = tmp_path / "ok.c"
    src.write_text("int main(void) { return 0; }\n")
    binary = tmp_path / "ok"
    if subprocess.run(["cc", "-static", "-o", binary, src],
                      capture_output=True).returncode != 0:
        pytest.skip("no static libc on this host for the rootfs payload")

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("bin/ok")
        info.size = binary.stat().st_size
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(binary.read_bytes()))
    # podman's local image store is spelled "localhost/": an OCI reference,
    # not a network host — the push below sends it to the real mock registry.
    r = _pod(rt, "import", "-", "localhost/brixoracle:1",  # net-literal-allow: local image-store reference
             stdin=buf.getvalue())
    assert r.returncode == 0, r.stderr.decode()
    r = _pod(rt, "push", "--tls-verify=false", "localhost/brixoracle:1",  # net-literal-allow: the same local-store reference
             f"{HOST}:{MOCK_PORT}/lab/tiny:1")
    assert r.returncode == 0, r.stderr.decode()
    r = _brix("ingest", "image", f"{HOST}:{MOCK_PORT}/lab/tiny:1",
              "--repo", repo, "--insecure")
    assert r.returncode == 0, r.stderr

    with fuse_mount(FQRN, f"http://{HOST}:{NGINX_PORT}/cvmfs/{FQRN}",
                    repo / "keys" / f"{FQRN}.pub",
                    opts="auto_unmount,allow_other") as (mnt, _proc):
        assert os.path.ismount(mnt), "host FUSE mount did not come up"
        rootfs = Path(mnt) / "images" / HOST / "lab" / "tiny:1"
        assert (rootfs / "bin" / "ok").exists()
        _pod(rt, "system", "migrate")   # Z-4: refresh the pause-process ns
        run = _pod(rt, "run", "--rm", "--rootfs", f"{rootfs}:O", "/bin/ok")
        assert run.returncode == 0, run.stderr.decode()[-500:]


# ---- error: stratum-0 down fails the mount, cleanly -----------------------

def test_stratum0_down_mount_fails_clean(lab, tmp_path):
    rt, repo, _pubdir, _base = lab
    dead = tmp_path / "pub"
    dead.mkdir()
    (dead / f"{FQRN}.pub").write_bytes(
        (repo / "keys" / f"{FQRN}.pub").read_bytes())
    (dead / "client.conf").write_text(
        f"CVMFS_SERVER_URL=http://{HOST}:{DOWN_PORT}/cvmfs/{FQRN}\n"
        "CVMFS_HTTP_PROXY=DIRECT\n"
        f"CVMFS_PUBLIC_KEY=/brix/{FQRN}.pub\n"
        "CVMFS_CACHE_BASE=/tmp/cache\n"
        "CVMFS_RELOAD_SOCKETS=/tmp/cache\n"
        "CVMFS_USYSLOG=/tmp/cvmfs.log\n")
    probe = _client_run(rt, dead, _mount_sh() + "echo MOUNT_OK\n")
    assert probe.returncode != 0 and "MOUNT_FAIL" in probe.stdout, \
        (probe.stdout + probe.stderr)[-400:]
    assert "MOUNT_OK" not in probe.stdout


# ---- security: a tampered CAS payload object is refused -------------------

def test_tampered_cas_object_refused(lab, tmp_path):
    rt, repo, pubdir, _base = lab
    # the catalog stores the tag as a symlink — resolve the digest root via
    # the ingest memo, exactly as a retag would
    digest = (repo / ".brix-ingest" / "memo" / "images" / HOST / "lab"
              / "app:v2").read_text().split()[1]
    root = f"/images/.images/sha256/{digest[7:]}"
    cat = open_catalog(repo, parse_manifest(repo)["C"], tmp_path)
    row = lookup(cat, f"{root}/share/extra")
    cat.close()
    assert row is not None
    victim = cas_path(repo, row[3].hex())
    clean = victim.read_bytes()
    flipped = bytearray(clean)
    flipped[len(flipped) // 2] ^= 0xFF
    try:
        victim.write_bytes(bytes(flipped))
        probe = _client_run(rt, pubdir, _mount_sh() + (
            f'if cat "/mnt/repo{APP_ROOT}/share/extra" > /tmp/out 2>&1; then\n'
            "  echo TAMPER_SERVED; else echo TAMPER_REFUSED; fi\n"))
        assert "TAMPER_REFUSED" in probe.stdout, \
            (probe.stdout + probe.stderr)[-400:]
    finally:
        victim.write_bytes(clean)
    good = _client_run(rt, pubdir, _mount_sh() + (
        f'cat "/mnt/repo{APP_ROOT}/share/extra" > /dev/null && echo READ_OK\n'))
    assert "READ_OK" in good.stdout, (good.stdout + good.stderr)[-400:]
