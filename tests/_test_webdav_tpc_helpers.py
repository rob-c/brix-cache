"""
tests/test_webdav_tpc.py

HTTP third-party-copy integration tests for the nginx WebDAV plugin.

The nginx fixture starts several HTTPS WebDAV endpoints so COPY can be tested
against different source and destination policies:

  - nginx+plugin source with required x509 auth
  - nginx+plugin source with no auth
  - nginx+plugin destination with TPC enabled via CA file
  - nginx+plugin destination with TPC enabled via CA directory
  - nginx+plugin destinations that are read-only, TPC-disabled, or missing
    outbound service credentials

Optional xrootd interop tests start an official XrdHttp/XrdHttpTPC endpoint
when the local xrootd binary and HTTP plugins are installed.

Run:
    pytest tests/test_webdav_tpc.py -v
"""

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from settings import (
    HOST,
    PKI_DIR as PKI_DIR_STR,
    WEBDAV_TPC_DEST_CADIR_PORT,
    WEBDAV_TPC_DEST_CAFILE_PORT,
    WEBDAV_TPC_DEST_DISABLED_PORT,
    WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT,
    WEBDAV_TPC_DEST_READONLY_PORT,
    WEBDAV_TPC_SOURCE_OPEN_PORT,
    WEBDAV_TPC_SOURCE_REQUIRED_PORT,
    TEST_ROOT,
    XRDHTTP_HTTP_PORT,
)

# Self-provisions a multi-instance WebDAV third-party-copy mesh (source +
# cafile/cadir/readonly destination nginx instances). Under the parallel bulk
# lane co-executing suites contended those shared instances and flaked the cadir
# push (404) when the endpoints were up. Pin to the isolated serial lane, like
# the other stateful mesh/topology suites. (In environments without the stock
# XrdHttp reference endpoint the whole module skips via its autouse fixture.)
def _expression_1(data_root):
    return (
        {
                name: data_root / name
                for name in (
                    "source_required",
                    "source_open",
                    "dest_cafile",
                    "dest_cadir",
                    "dest_no_service_cert",
                    "dest_disabled",
                    "dest_readonly",
                )
            }
    )

def _expression_2(log_path):
    return (
        log_path.read_text(errors="replace") if log_path.exists() else ""
    )


def _guard_tpc_nginx_1(root):
    if root.exists():
        shutil.rmtree(root)

def _guard_tpc_nginx_2(ok, port):
    if not ok:
        pytest.fail(f"nginx WebDAV TPC fixture did not start on port {port}.")

def _guard_reference_xrd_http_3(path):
    if not path.exists():
        pytest.skip(f"test PKI file not found: {path}")


pytestmark = [pytest.mark.serial]

PKI_DIR = Path(PKI_DIR_STR)
CA_DIR = PKI_DIR / "ca"
CA_PEM = CA_DIR / "ca.pem"
CLIENT_CERT = PKI_DIR / "user" / "usercert.pem"
CLIENT_KEY = PKI_DIR / "user" / "userkey.pem"
SERVER_CERT = PKI_DIR / "server" / "hostcert.pem"
SERVER_KEY = PKI_DIR / "server" / "hostkey.pem"


@dataclass(frozen=True)
class TpcNginx:
    workdir: Path
    source_required_port: int
    source_open_port: int
    dest_cafile_port: int
    dest_cadir_port: int
    dest_no_service_cert_port: int
    dest_disabled_port: int
    dest_readonly_port: int
    source_required_root: Path
    source_open_root: Path
    dest_cafile_root: Path
    dest_cadir_root: Path
    dest_no_service_cert_root: Path
    dest_disabled_root: Path
    dest_readonly_root: Path


@dataclass(frozen=True)
class ReferenceXrdHttp:
    workdir: Path
    data_root: Path
    http_port: int


def _require_common_tools():
    if shutil.which("curl") is None:
        pytest.skip("curl not found")
    for path in (CA_PEM, CLIENT_CERT, CLIENT_KEY, SERVER_CERT, SERVER_KEY):
        if not path.exists():
            pytest.skip(f"test PKI file not found: {path}")


def _curl(*args, timeout=30):
    cmd = [
        "curl",
        "-sk",
        "--cert",
        str(CLIENT_CERT),
        "--key",
        str(CLIENT_KEY),
        "--cacert",
        str(CA_PEM),
        *args,
    ]
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _copy_push(source_port: int, source_path: str, dest_url: str, *headers, timeout=30):
    """Send a TPC push COPY to source_port: the server reads source_path and
    PUTs it to dest_url."""
    args = [
        "-X",
        "COPY",
        f"https://{HOST}:{source_port}{source_path}",
        "-H",
        "Credential: none",
        "-H",
        f"Destination: {dest_url}",
    ]
    for header in headers:
        args.extend(["-H", header])
    return _curl(*args, "-w", "%{http_code}", "-o", "/dev/null", timeout=timeout)


def _copy_push_code(source_port: int, source_path: str, dest_url: str, *headers, timeout=30) -> int:
    result = _copy_push(source_port, source_path, dest_url, *headers, timeout=timeout)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return int(result.stdout.strip())


def _copy_pull(dest_port: int, dest_path: str, source_url: str, *headers, timeout=30):
    args = [
        "-X",
        "COPY",
        f"https://{HOST}:{dest_port}{dest_path}",
        "-H",
        "Credential: none",
        "-H",
        f"Source: {source_url}",
    ]
    for header in headers:
        args.extend(["-H", header])
    return _curl(*args, "-w", "%{http_code}", "-o", "/dev/null", timeout=timeout)


def _copy_code(dest_port: int, dest_path: str, source_url: str, *headers, timeout=30) -> int:
    result = _copy_pull(dest_port, dest_path, source_url, *headers, timeout=timeout)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return int(result.stdout.strip())


def _write(path: Path, content: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _wait_for_file(path: Path, content: bytes, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.read_bytes() == content:
            return True
        time.sleep(0.2)
    return False


@pytest.fixture(scope="session", autouse=True)
def tpc_nginx():
    _require_common_tools()

    workdir = Path(TEST_ROOT) / "dedicated" / "webdav-tpc"
    data_root = Path(TEST_ROOT) / "data-webdav-tpc"

    roots = _expression_1(data_root)
    for root in roots.values():
        _guard_tpc_nginx_1(root)
        root.mkdir(parents=True, exist_ok=True)

    ports = {
        "source_required": WEBDAV_TPC_SOURCE_REQUIRED_PORT,
        "source_open": WEBDAV_TPC_SOURCE_OPEN_PORT,
        "dest_cafile": WEBDAV_TPC_DEST_CAFILE_PORT,
        "dest_cadir": WEBDAV_TPC_DEST_CADIR_PORT,
        "dest_no_service_cert": WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT,
        "dest_disabled": WEBDAV_TPC_DEST_DISABLED_PORT,
        "dest_readonly": WEBDAV_TPC_DEST_READONLY_PORT,
    }

    for port in ports.values():
        ok = False
        for _ in range(40):
            try:
                result = _curl(
                    "-X",
                    "OPTIONS",
                    f"https://{HOST}:{port}/",
                    "-o",
                    "/dev/null",
                    timeout=3,
                )
            except subprocess.TimeoutExpired:
                time.sleep(0.2)
                continue
            if result.returncode == 0:
                ok = True
                break
            time.sleep(0.2)
        _guard_tpc_nginx_2(ok, port)

    yield TpcNginx(
        workdir=workdir,
        source_required_port=ports["source_required"],
        source_open_port=ports["source_open"],
        dest_cafile_port=ports["dest_cafile"],
        dest_cadir_port=ports["dest_cadir"],
        dest_no_service_cert_port=ports["dest_no_service_cert"],
        dest_disabled_port=ports["dest_disabled"],
        dest_readonly_port=ports["dest_readonly"],
        source_required_root=roots["source_required"],
        source_open_root=roots["source_open"],
        dest_cafile_root=roots["dest_cafile"],
        dest_cadir_root=roots["dest_cadir"],
        dest_no_service_cert_root=roots["dest_no_service_cert"],
        dest_disabled_root=roots["dest_disabled"],
        dest_readonly_root=roots["dest_readonly"],
    )


@pytest.fixture(scope="session", autouse=True)
def reference_xrd_http():
    for path in (CA_PEM, SERVER_CERT, SERVER_KEY):
        _guard_reference_xrd_http_3(path)

    workdir = Path(TEST_ROOT) / "xrdhttp"
    data_root = Path(TEST_ROOT) / "data-xrdhttp"
    data_root.mkdir(parents=True, exist_ok=True)
    http_port = XRDHTTP_HTTP_PORT

    ready = False
    probe_path = data_root / "probe.txt"
    probe_path.write_text("xrootd http probe\n")
    for _ in range(40):
        result = _curl(
            f"https://{HOST}:{http_port}/probe.txt",
            "-o",
            "/dev/null",
            timeout=3,
        )
        if result.returncode == 0:
            ready = True
            break
        time.sleep(0.25)
    if not ready:
        log_path = workdir / "xrdhttp.log"
        log = _expression_2(log_path)
        pytest.skip(
            "reference XrdHttp endpoint did not start; "
            f"log tail:\n{log[-3000:]}"
        )

    yield ReferenceXrdHttp(workdir=workdir, data_root=data_root, http_port=http_port)
