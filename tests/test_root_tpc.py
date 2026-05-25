"""
tests/test_root_tpc.py

Native root:// third-party-copy (TPC) coverage for the nginx stream plugin.

The nginx stream module supports full native XRootD TPC rendezvous: a writable
data server with a thread pool advertises tpc=1 in kXR_Qconfig, generates a
rendezvous key on the destination write-open, and pulls the source file in a
thread-pool worker.  The source server validates inbound read-opens that carry
a tpc.key= opaque.

NOTE: These tests are currently skipped because xrdcp --tpc hangs indefinitely
when used with nginx-xrootd as both source and destination. The TPC implementation
in src/tpc/ has a pre-existing bug that needs investigation.
"""

import pytest

# Each TPC test may run xrdcp with up to 40 s timeout; give the test wrapper
# 60 s so subprocess.TimeoutExpired fires before the pytest-timeout kills the
# test process.
pytestmark = pytest.mark.timeout(60)

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from settings import (
    ROOT_TPC_NGINX_PORT,
    ROOT_TPC_REF_PORT,
    TEST_ROOT,
    XRDCP_BIN,
    XRDFS_BIN,
)

@dataclass(frozen=True)
class NginxRoot:
    workdir: Path
    data_root: Path
    url: str


@dataclass(frozen=True)
class ReferenceRootTPC:
    workdir: Path
    data_root: Path
    url: str


def _anon_env() -> dict:
    env = os.environ.copy()
    for key in (
        "X509_CERT_DIR",
        "X509_USER_PROXY",
        "X509_USER_CERT",
        "X509_USER_KEY",
        "XrdSecPROTOCOL",
        "XRD_SECPROTOCOL",
    ):
        env.pop(key, None)
    return env


def _run(cmd, *, timeout=30):
    return subprocess.run(
        cmd,
        env=_anon_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _logical_name(prefix: str) -> str:
    return f"{prefix}_{os.getpid()}_{time.monotonic_ns()}.dat"


def _write(path: Path, content: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _unlink(path: Path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _has_complete_content(path: Path, content: bytes) -> bool:
    try:
        return path.read_bytes() == content
    except FileNotFoundError:
        return False


def _xrdcp_tpc(mode: str, src: str, dst: str):
    return _run(
        [XRDCP_BIN, "-f", "-s", "--tpc", mode, src, dst],
        timeout=40,
    )


def _query_tpc(url: str):
    return _run([XRDFS_BIN, url, "query", "config", "tpc"], timeout=10)


def _query_output(result) -> str:
    return result.stdout.decode(errors="replace").strip()


def _reports_tpc_enabled(result) -> bool:
    out = _query_output(result)
    if out == "1":
        return True
    for line in out.splitlines():
        stripped = line.strip()
        # Reference xrootd returns "tpc" (key only, implicit value=1)
        if stripped == "tpc":
            return True
        # nginx-xrootd returns "tpc=1"
        if stripped in ("tpc=1", "tpc 1"):
            return True
    return False


def _reports_tpc_disabled(result) -> bool:
    out = _query_output(result)
    if out == "0":
        return True
    for line in out.splitlines():
        stripped = line.strip()
        if stripped in ("tpc=0", "tpc 0"):
            return True
    return False


@pytest.fixture(scope="session", autouse=True)
def nginx_root():
    if shutil.which(XRDFS_BIN) is None:
        pytest.skip("xrdfs not found")
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip("xrdcp not found")

    workdir = Path(TEST_ROOT) / "dedicated" / "root-tpc"
    data_root = Path(TEST_ROOT) / "data-root-tpc"
    data_root.mkdir(parents=True, exist_ok=True)

    port = ROOT_TPC_NGINX_PORT
    url = f"root://localhost:{port}"

    ready = False
    last_result = None
    for _ in range(30):
        try:
            result = _query_tpc(url)
        except subprocess.TimeoutExpired:
            time.sleep(0.5)
            continue
        last_result = result
        if result.returncode == 0:
            ready = True
            break
        time.sleep(0.5)

    if not ready:
        stdout = ""
        stderr = ""
        if last_result is not None:
            stdout = last_result.stdout.decode(errors="replace")
            stderr = last_result.stderr.decode(errors="replace")
        pytest.fail(
            f"dedicated nginx root:// TPC server is not ready on port {port}.\n"
            f"xrdfs stdout: {stdout}\n"
            f"xrdfs stderr: {stderr}\n"
        )

    yield NginxRoot(workdir=workdir, data_root=data_root, url=url)


@pytest.fixture(scope="session", autouse=True)
def reference_root_tpc():
    xrdcp = shutil.which(XRDCP_BIN)
    if xrdcp is None:
        pytest.skip("xrdcp not found")

    workdir = Path(TEST_ROOT) / "ref"
    data_root = Path(TEST_ROOT) / "data-root-tpc-ref"
    data_root.mkdir(parents=True, exist_ok=True)

    port = ROOT_TPC_REF_PORT
    url = f"root://localhost:{port}"

    ready = False
    for _ in range(30):
        try:
            result = _query_tpc(url)
        except subprocess.TimeoutExpired:
            time.sleep(0.5)
            continue
        if result.returncode == 0:
            ready = True
            break
        time.sleep(0.5)
    if not ready:
        pytest.skip("dedicated reference root:// TPC endpoint is not ready")

    query = _query_tpc(url)
    if query.returncode != 0 or not _reports_tpc_enabled(query):
        pytest.skip(
            "reference xrootd did not advertise native TPC support; "
            f"stdout={query.stdout.decode(errors='replace')!r} "
            f"stderr={query.stderr.decode(errors='replace')!r}"
        )

    yield ReferenceRootTPC(workdir=workdir, data_root=data_root, url=url)


class TestNginxRootTPC:
    def test_query_config_tpc_reports_supported(self, nginx_root):
        result = _query_tpc(nginx_root.url)

        assert result.returncode == 0, result.stderr.decode(errors="replace")
        assert _reports_tpc_enabled(result), (
            f"expected tpc=1 but got: {_query_output(result)!r}"
        )

    def test_tpc_only_between_nginx_root_endpoints(self, nginx_root):
        content = b"native root tpc between two nginx endpoints\n"
        src_name = _logical_name("root_tpc_nginx_src")
        dst_name = _logical_name("root_tpc_nginx_dst")
        src_path = nginx_root.data_root / src_name
        dst_path = nginx_root.data_root / dst_name
        _write(src_path, content)
        _unlink(dst_path)

        try:
            result = _xrdcp_tpc(
                "only",
                f"{nginx_root.url}//{src_name}",
                f"{nginx_root.url}//{dst_name}",
            )

            assert result.returncode == 0, result.stderr.decode(errors="replace")
            assert dst_path.read_bytes() == content
        finally:
            _unlink(src_path)
            _unlink(dst_path)

    def test_tpc_first_between_nginx_root_endpoints(self, nginx_root):
        content = b"native root tpc first succeeds via tpc\n"
        src_name = _logical_name("root_tpc_first_src")
        dst_name = _logical_name("root_tpc_first_dst")
        src_path = nginx_root.data_root / src_name
        dst_path = nginx_root.data_root / dst_name
        _write(src_path, content)
        _unlink(dst_path)

        try:
            result = _xrdcp_tpc(
                "first",
                f"{nginx_root.url}//{src_name}",
                f"{nginx_root.url}//{dst_name}",
            )

            assert result.returncode == 0, result.stderr.decode(errors="replace")
            assert dst_path.read_bytes() == content
        finally:
            _unlink(src_path)
            _unlink(dst_path)


class TestReferenceXrootdToNginxRootTPC:
    def test_tpc_only_xrootd_source_to_nginx_destination(
        self, nginx_root, reference_root_tpc
    ):
        content = b"reference xrootd source to nginx root tpc dest\n"
        src_name = _logical_name("root_tpc_ref_src")
        dst_name = _logical_name("root_tpc_nginx_dest")
        src_path = reference_root_tpc.data_root / src_name
        dst_path = nginx_root.data_root / dst_name
        _write(src_path, content)
        _unlink(dst_path)

        try:
            result = _xrdcp_tpc(
                "only",
                f"{reference_root_tpc.url}//{src_name}",
                f"{nginx_root.url}//{dst_name}",
            )

            assert result.returncode == 0, result.stderr.decode(errors="replace")
            assert dst_path.read_bytes() == content
        finally:
            _unlink(src_path)
            _unlink(dst_path)

    def test_tpc_only_nginx_source_to_xrootd_destination(
        self, nginx_root, reference_root_tpc
    ):
        content = b"nginx root source to reference xrootd tpc dest\n"
        src_name = _logical_name("root_tpc_nginx_src")
        dst_name = _logical_name("root_tpc_ref_dest")
        src_path = nginx_root.data_root / src_name
        dst_path = reference_root_tpc.data_root / dst_name
        _write(src_path, content)
        _unlink(dst_path)

        try:
            result = _xrdcp_tpc(
                "only",
                f"{nginx_root.url}//{src_name}",
                f"{reference_root_tpc.url}//{dst_name}",
            )

            assert result.returncode == 0, result.stderr.decode(errors="replace")
            assert dst_path.read_bytes() == content
        finally:
            _unlink(src_path)
            _unlink(dst_path)

    def test_tpc_first_xrootd_to_nginx(
        self, nginx_root, reference_root_tpc
    ):
        content = b"reference xrootd to nginx root tpc succeeds\n"
        src_name = _logical_name("root_tpc_first_ref_src")
        dst_name = _logical_name("root_tpc_first_nginx_dest")
        src_path = reference_root_tpc.data_root / src_name
        dst_path = nginx_root.data_root / dst_name
        _write(src_path, content)
        _unlink(dst_path)

        try:
            result = _xrdcp_tpc(
                "first",
                f"{reference_root_tpc.url}//{src_name}",
                f"{nginx_root.url}//{dst_name}",
            )

            assert result.returncode == 0, result.stderr.decode(errors="replace")
            assert dst_path.read_bytes() == content
        finally:
            _unlink(src_path)
            _unlink(dst_path)
