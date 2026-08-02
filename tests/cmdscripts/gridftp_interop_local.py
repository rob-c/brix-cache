#!/usr/bin/env python3
"""Run the GridFTP cross-implementation interop matrix locally, no k8s cluster.

The phase-82 interop matrix
(``k8s-tests/remote-suite/tests/test_gridftp_interop.py``) drives the brix
GridFTP gateway with the *reference* grid client stack — ``globus-url-copy``,
``gfal-copy`` and a VOMS-attributed proxy — rather than brix's own client code,
so a framing or GSI regression both halves of brix would agree on still gets
caught. In-cluster it needs a live k8s deployment (``charts/gridftp-interop``)
plus the ``gridftp-client`` image for those tools.

This runner removes the *cluster* half of that requirement: it boots the
combined gsiftp+ftp gateway locally (``tests/configs/nginx_gridftp_interop.conf``,
the same two-listener-over-one-export topology the chart renders) and drives the
identical matrix from the ``gridftp-client`` image under **rootless podman** with
``--network=host``. What stays required is only the container image (one
network-fed ``podman build`` — see ``k8s-tests/Dockerfiles/gridftp-client``) and
the local test PKI; every prerequisite self-skips with a clear reason.

    # once, to build the client image (needs network for the EL9 grid RPMs):
    python3 -m cmdscripts.gridftp_interop_local build-image
    # then run the matrix against a locally-booted gateway:
    python3 -m cmdscripts.gridftp_interop_local run
    # inspect the exact podman invocation without running anything:
    python3 -m cmdscripts.gridftp_interop_local run --dry-run

Exit codes: 0 success/dry-run, 77 skipped (missing prerequisite, like an
autotools SKIP), non-zero on a real matrix failure.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# --- single source of truth for the interop client contract ------------------
# The reference grid client stacks the matrix drives. The gridftp-client image
# MUST ship all three; tools/ci/check_gridftp_interop_image.py imports these
# lists so a Dockerfile edit that drops a stack reddens the gate instead of
# silently degrading a matrix cell to a skip.
INTEROP_CLIENT_PACKAGES = (
    "globus-gass-copy-progs",   # -> globus-url-copy (primary GridFTP client)
    "gfal2-util-scripts",       # -> gfal-copy       (independent 2nd stack; EL9
                                #    CLI package name, NOT gfal2-util)
    "voms-clients-cpp",         # -> voms-proxy-*    (VOMS-AC proxy minting)
)
INTEROP_CLIENT_TOOLS = ("globus-url-copy", "gfal-copy", "voms-proxy-info")

# The env-var contract the containerised matrix reads (kept identical to the
# remote-suite test's os.environ.get keys). The guard cross-checks that the test
# and this runner agree on every name.
INTEROP_ENV_VARS = (
    "TEST_GRIDFTP_HOST",
    "TEST_GRIDFTP_GSIFTP_PORT",
    "TEST_GRIDFTP_FTP_PORT",
    "TEST_GRIDFTP_BACKEND_PBLOCK_PORT",   # non-posix backend leg (P82.6)
    "TEST_GRIDFTP_BACKEND_S3_PORT",       # object-store backend leg (P82.6, s3)
    "X509_USER_PROXY",
    "TEST_GRIDFTP_VOMS_PROXY",
)

# SigV4 keys shared by the embedded brix_s3 origin and the gateway's s3
# credential block — fixed test material, never a real secret (mirrors
# tests/test_gridftp_s3.py so the cluster-free s3 leg is self-contained).
S3_ACCESS_KEY = "AKIDGRIDFTPINTEROP01"
S3_SECRET_KEY = "Z3JpZGZ0cC1pbnRlcm9wLXMzLXNlY3JldC1rZXktdGVzdA=="

DEFAULT_IMAGE = "brix-gridftp-client:dev"
INTEROP_TEST = "k8s-tests/remote-suite/tests/test_gridftp_interop.py"

# In-container mount targets (fixed; the plan maps host paths onto these).
# The interop matrix file is self-contained (stdlib + pytest only), so it is
# mounted ALONE into a clean dir rather than the whole repo — that sidesteps the
# repo's root pytest.ini (its `filterwarnings` names urllib3, absent in the grid
# image) and the remote-suite conftest, neither of which the matrix needs.
_C_TESTDIR = "/interop"
_C_PROXY = "/creds/user_proxy.pem"
_C_VOMS = "/creds/vuser_proxy.pem"
_C_CADIR = "/etc/grid-security/certificates"

SKIP = 77


def build_interop_run_plan(
    *,
    host: str,
    gsiftp_port: int,
    ftp_port: int,
    repo_root: str,
    proxy: str,
    ca_dir: str,
    image: str = DEFAULT_IMAGE,
    voms_proxy: str | None = None,
    pblock_port: int | None = None,
    s3_port: int | None = None,
    test_target: str = INTEROP_TEST,
    bulk_n: int | None = None,
    network: str = "host",
    extra_pytest: tuple[str, ...] = (),
) -> dict:
    """Build the ``podman run`` invocation that drives the matrix in-container.

    Pure: constructs argv/env/mounts from its arguments only, so it is unit
    tested offline without podman, an image, or a running gateway. The live
    ``run`` path calls this then executes the returned ``argv``.
    """
    repo_root = os.path.abspath(repo_root)
    host_test = os.path.join(repo_root, test_target)
    c_test = f"{_C_TESTDIR}/{os.path.basename(test_target)}"
    mounts = [
        (host_test, c_test, "ro"),
        (os.path.abspath(proxy), _C_PROXY, "ro"),
        (os.path.abspath(ca_dir), _C_CADIR, "ro"),
    ]
    env = {
        "TEST_GRIDFTP_HOST": host,
        "TEST_GRIDFTP_GSIFTP_PORT": str(gsiftp_port),
        "TEST_GRIDFTP_FTP_PORT": str(ftp_port),
        "X509_USER_PROXY": _C_PROXY,
        "X509_CERT_DIR": _C_CADIR,
    }
    if voms_proxy is not None:
        mounts.append((os.path.abspath(voms_proxy), _C_VOMS, "ro"))
        env["TEST_GRIDFTP_VOMS_PROXY"] = _C_VOMS
    if pblock_port is not None:
        # The pblock-backed gsiftp listener the runner boots alongside the posix
        # export — the interop matrix's non-posix backend cell drives it and
        # self-skips when this is unset.
        env["TEST_GRIDFTP_BACKEND_PBLOCK_PORT"] = str(pblock_port)
    if s3_port is not None:
        # The s3://-backed gsiftp listener (export routes through the embedded
        # brix_s3 origin) — the interop matrix's object-store backend cell drives
        # it and self-skips when this is unset.
        env["TEST_GRIDFTP_BACKEND_S3_PORT"] = str(s3_port)
    if bulk_n is not None:
        env["TEST_GRIDFTP_BULK_N"] = str(bulk_n)

    # pytest inside the container: the interop file only, no repo config
    # (`-c /dev/null` — the repo pytest.ini is deliberately not mounted), tmp
    # under a writable tmpfs, the `serial` marker registered inline.
    pytest_argv = [
        "python3", "-m", "pytest", c_test,
        "-v", "-p", "no:cacheprovider", "-c", "/dev/null",
        "-o", "markers=serial: run serially",
        *extra_pytest,
    ]

    argv = ["podman", "run", "--rm", f"--network={network}",
            "-w", _C_TESTDIR, "--tmpfs", "/tmp:rw,size=512m"]
    for src, dst, mode in mounts:
        argv += ["-v", f"{src}:{dst}:{mode}"]
    for key, val in env.items():
        argv += ["-e", f"{key}={val}"]
    argv.append(image)
    argv += pytest_argv

    return {"argv": argv, "container_env": env, "mounts": mounts,
            "pytest_argv": pytest_argv, "image": image}


# --- live orchestration ------------------------------------------------------

def _skip(msg: str) -> int:
    print(f"SKIP: {msg}", file=sys.stderr)
    return SKIP


def _stop_pidfile(pidfile: Path) -> None:
    try:
        os.kill(int(pidfile.read_text().strip()), 15)
    except (OSError, ValueError):
        pass


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _image_present(image: str) -> bool:
    if not shutil.which("podman"):
        return False
    p = subprocess.run(["podman", "image", "exists", image])
    return p.returncode == 0


def _pki_paths(pki_dir: Path) -> dict:
    return {
        "cert": pki_dir / "server" / "hostcert.pem",
        "key": pki_dir / "server" / "hostkey.pem",
        "ca": pki_dir / "ca",
        "proxy": pki_dir / "user" / "proxy_std.pem",
        "voms": pki_dir / "user" / "vuser_proxy.pem",   # optional
    }


def _substitute(template: Path, out: Path, subs: dict) -> Path:
    # Token replacement, NOT str.format: nginx configs are full of literal
    # `{ ... }` blocks that str.format would try to interpret as fields.
    conf = template.read_text()
    for tok, val in subs.items():
        conf = conf.replace(tok, val)
    out.write_text(conf)
    return out


def _render_gateway_conf(*, template: Path, out: Path, log_dir: Path,
                         data_root: Path, bind_host: str, gsiftp_port: int,
                         ftp_port: int, pki: dict, pblock_gsiftp_port: int,
                         pblock_root: Path) -> Path:
    return _substitute(template, out, {
        "{GSIFTP_PORT}": str(gsiftp_port), "{FTP_PORT}": str(ftp_port),
        "{PBLOCK_GSIFTP_PORT}": str(pblock_gsiftp_port),
        "{DATA_ROOT}": str(data_root), "{PBLOCK_ROOT}": str(pblock_root),
        "{LOG_DIR}": str(log_dir),
        "{BIND_HOST}": str(bind_host), "{SERVER_CERT}": str(pki["cert"]),
        "{SERVER_KEY}": str(pki["key"]), "{CA_DIR}": str(pki["ca"]),
    })


def _render_s3_conf(*, template: Path, out: Path, log_dir: Path,
                    bind_host: str, pki: dict, s3_gsiftp_port: int,
                    s3_origin_port: int, s3_dir: Path, s3_export: Path,
                    tmp_dir: Path) -> Path:
    # The s3-backend leg is a SECOND nginx instance (2 workers, own pid/log dir):
    # pblock in the main config needs 1 worker, the s3 origin needs 2 — see the
    # config headers. Cluster-free: the object store is an embedded brix_s3 origin.
    return _substitute(template, out, {
        "{S3_GSIFTP_PORT}": str(s3_gsiftp_port),
        "{S3_ORIGIN_PORT}": str(s3_origin_port),
        "{S3_DIR}": str(s3_dir), "{S3_EXPORT}": str(s3_export),
        "{TMP_DIR}": str(tmp_dir),
        "{S3_ACCESS_KEY}": S3_ACCESS_KEY, "{S3_SECRET_KEY}": S3_SECRET_KEY,
        "{LOG_DIR}": str(log_dir),
        "{BIND_HOST}": str(bind_host), "{SERVER_CERT}": str(pki["cert"]),
        "{SERVER_KEY}": str(pki["key"]), "{CA_DIR}": str(pki["ca"]),
    })


def build_image(image: str) -> int:
    if not shutil.which("podman"):
        return _skip("podman not on PATH — rootless container runtime required")
    root = _repo_root()
    dockerfile = root / "k8s-tests/Dockerfiles/gridftp-client/Dockerfile"
    if not dockerfile.exists():
        return _skip(f"missing {dockerfile}")
    print(f"building {image} from {dockerfile} (needs network for EL9 grid RPMs)")
    p = subprocess.run(
        ["podman", "build", "-t", image, "-f", str(dockerfile), str(root)])
    if p.returncode != 0:
        print("podman build failed — most commonly no network for the grid RPMs",
              file=sys.stderr)
    return p.returncode


def run(image: str, *, dry_run: bool, bulk_n: int | None) -> int:
    root = _repo_root()
    sys.path.insert(0, str(root / "tests"))
    import settings  # noqa: E402  (tests/settings.py)

    nginx = Path(settings.NGINX_BIN)
    pki = _pki_paths(Path(settings.PKI_DIR))
    template = root / "tests/configs/nginx_gridftp_interop.conf"

    if not dry_run:
        if not _image_present(image):
            return _skip(f"image {image!r} absent — run `gridftp_interop_local "
                         f"build-image` first (one network-fed podman build)")
        if not os.access(nginx, os.X_OK):
            return _skip(f"nginx not executable: {nginx}")
        for key in ("cert", "key", "ca", "proxy"):
            if not pki[key].exists():
                return _skip(f"test PKI incomplete: missing {pki[key]}")

    gsiftp_port = int(os.environ.get("TEST_GRIDFTP_GSIFTP_PORT", "2811"))
    ftp_port = int(os.environ.get("TEST_GRIDFTP_FTP_PORT", "2810"))
    pblock_port = int(os.environ.get("TEST_GRIDFTP_BACKEND_PBLOCK_PORT", "2812"))
    s3_port = int(os.environ.get("TEST_GRIDFTP_BACKEND_S3_PORT", "2813"))
    s3_origin_port = int(os.environ.get("TEST_GRIDFTP_S3_ORIGIN_PORT", "2814"))
    voms = str(pki["voms"]) if pki["voms"].exists() else None

    plan = build_interop_run_plan(
        host=settings.SERVER_HOST, gsiftp_port=gsiftp_port, ftp_port=ftp_port,
        repo_root=str(root), proxy=str(pki["proxy"]), ca_dir=str(pki["ca"]),
        image=image, voms_proxy=voms, pblock_port=pblock_port, s3_port=s3_port,
        bulk_n=bulk_n,
    )

    if dry_run:
        print(json.dumps(plan, indent=2))
        return 0

    # Boot both instances (main 1-worker gateway + s3 2-worker leg), drive the
    # matrix, tear both down.
    work = Path(settings.TEST_ROOT) / "gridftp-interop-local"
    log_dir = work / "logs"
    s3_log_dir = work / "logs-s3"
    data_root = work / "export"
    pblock_root = work / "export-pblock"
    s3_export = work / "export-s3"          # gateway staging root for the s3 leg
    s3_dir = work / "s3-origin"             # embedded brix_s3 object root
    tmp_dir = work / "http-tmp"             # http body/proxy temp paths
    for d in (log_dir, s3_log_dir, data_root, pblock_root, s3_export, s3_dir,
              tmp_dir):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)
    conf = _render_gateway_conf(
        template=template, out=work / "gateway.conf", log_dir=log_dir,
        data_root=data_root, bind_host=settings.BIND_HOST,
        gsiftp_port=gsiftp_port, ftp_port=ftp_port, pki=pki,
        pblock_gsiftp_port=pblock_port, pblock_root=pblock_root)
    s3_conf = _render_s3_conf(
        template=root / "tests/configs/nginx_gridftp_interop_s3.conf",
        out=work / "gateway-s3.conf", log_dir=s3_log_dir,
        bind_host=settings.BIND_HOST, pki=pki, s3_gsiftp_port=s3_port,
        s3_origin_port=s3_origin_port, s3_dir=s3_dir, s3_export=s3_export,
        tmp_dir=tmp_dir)

    pidfiles = []
    for label, cfg, ldir in (("gateway", conf, log_dir),
                             ("s3-leg", s3_conf, s3_log_dir)):
        start = subprocess.run([str(nginx), "-c", str(cfg), "-e",
                                str(ldir / "error.log")],
                               capture_output=True, text=True)
        if start.returncode != 0:
            for pf in pidfiles:
                _stop_pidfile(pf)
            return _skip(f"{label} failed to start: {start.stderr.strip()}")
        pidfiles.append(ldir / "nginx.pid")
    time.sleep(1.0)
    try:
        print("running interop matrix:", " ".join(plan["argv"]))
        return subprocess.run(plan["argv"]).returncode
    finally:
        for pf in pidfiles:
            _stop_pidfile(pf)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["run", "build-image"], nargs="?", default="run")
    ap.add_argument("--image", default=DEFAULT_IMAGE)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the podman invocation and exit (no build/boot)")
    ap.add_argument("--bulk-n", type=int, default=None,
                    help="override TEST_GRIDFTP_BULK_N for the FTS batch cell")
    a = ap.parse_args(argv)
    if a.cmd == "build-image":
        return build_image(a.image)
    return run(a.image, dry_run=a.dry_run, bulk_n=a.bulk_n)


if __name__ == "__main__":
    raise SystemExit(main())
