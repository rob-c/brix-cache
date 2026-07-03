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

    roots = {
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
    for root in roots.values():
        if root.exists():
            shutil.rmtree(root)
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
        if not ok:
            pytest.fail(f"nginx WebDAV TPC fixture did not start on port {port}.")

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
        if not path.exists():
            pytest.skip(f"test PKI file not found: {path}")

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
        log = log_path.read_text(errors="replace") if log_path.exists() else ""
        pytest.skip(
            "reference XrdHttp endpoint did not start; "
            f"log tail:\n{log[-3000:]}"
        )

    yield ReferenceXrdHttp(workdir=workdir, data_root=data_root, http_port=http_port)


class TestNginxPluginToPluginTPC:
    def test_required_source_to_required_destination(self, tpc_nginx):
        content = b"nginx plugin source requiring x509 auth\n"
        _write(tpc_nginx.source_required_root / "required-source.txt", content)

        source = (
            f"https://{HOST}:{tpc_nginx.source_required_port}"
            "/required-source.txt"
        )
        code = _copy_code(
            tpc_nginx.dest_cafile_port,
            "/copied-from-required.txt",
            source,
            "TransferHeaderX-Test-Tpc: plugin-required",
        )

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "copied-from-required.txt").read_bytes() == content

    def test_open_source_to_cadir_destination(self, tpc_nginx):
        content = b"nginx plugin open source, destination trusts a CA directory\n"
        _write(tpc_nginx.source_open_root / "open-source.txt", content)

        source = f"https://{HOST}:{tpc_nginx.source_open_port}/open-source.txt"
        code = _copy_code(tpc_nginx.dest_cadir_port, "/copied-via-cadir.txt", source)

        assert code == 201
        assert (tpc_nginx.dest_cadir_root / "copied-via-cadir.txt").read_bytes() == content

    def test_overwrite_false_preserves_existing_destination(self, tpc_nginx):
        _write(tpc_nginx.source_open_root / "overwrite-source.txt", b"new content\n")
        existing = tpc_nginx.dest_cafile_root / "overwrite-target.txt"
        _write(existing, b"existing content\n")

        source = f"https://{HOST}:{tpc_nginx.source_open_port}/overwrite-source.txt"
        code = _copy_code(
            tpc_nginx.dest_cafile_port,
            "/overwrite-target.txt",
            source,
            "Overwrite: F",
        )

        assert code == 412
        assert existing.read_bytes() == b"existing content\n"

    def test_tpc_disabled_destination_rejects_copy(self, tpc_nginx):
        _write(tpc_nginx.source_open_root / "disabled-source.txt", b"disabled dest\n")

        source = f"https://{HOST}:{tpc_nginx.source_open_port}/disabled-source.txt"
        code = _copy_code(tpc_nginx.dest_disabled_port, "/should-not-copy.txt", source)

        assert code == 405
        assert not (tpc_nginx.dest_disabled_root / "should-not-copy.txt").exists()

    def test_readonly_destination_rejects_copy_before_pull(self, tpc_nginx):
        _write(tpc_nginx.source_open_root / "readonly-source.txt", b"readonly dest\n")

        source = f"https://{HOST}:{tpc_nginx.source_open_port}/readonly-source.txt"
        code = _copy_code(tpc_nginx.dest_readonly_port, "/should-not-copy.txt", source)

        assert code == 403
        assert not (tpc_nginx.dest_readonly_root / "should-not-copy.txt").exists()

    def test_missing_service_credential_cannot_pull_required_source(self, tpc_nginx):
        content = b"requires outbound client cert\n"
        _write(tpc_nginx.source_required_root / "needs-cert.txt", content)

        source = f"https://{HOST}:{tpc_nginx.source_required_port}/needs-cert.txt"
        code = _copy_code(
            tpc_nginx.dest_no_service_cert_port,
            "/missing-service-cert.txt",
            source,
        )

        assert code == 502
        assert not (tpc_nginx.dest_no_service_cert_root / "missing-service-cert.txt").exists()


class TestXrootdHttpInteropTPC:
    def test_brix_http_source_to_nginx_plugin_destination(self, tpc_nginx, reference_xrd_http):
        content = b"xrootd http source pulled into nginx plugin destination\n"
        _write(reference_xrd_http.data_root / "xrd-source.txt", content)

        source = f"https://{HOST}:{reference_xrd_http.http_port}/xrd-source.txt"
        code = _copy_code(tpc_nginx.dest_cafile_port, "/from-xrootd-http.txt", source)

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "from-xrootd-http.txt").read_bytes() == content

    def test_nginx_plugin_source_to_brix_http_destination(self, tpc_nginx, reference_xrd_http):
        content = b"nginx plugin source pulled into xrootd http destination\n"
        _write(tpc_nginx.source_open_root / "nginx-source-for-xrd.txt", content)

        source = f"https://{HOST}:{tpc_nginx.source_open_port}/nginx-source-for-xrd.txt"
        result = _curl(
            "-X",
            "COPY",
            f"https://{HOST}:{reference_xrd_http.http_port}/from-nginx-plugin.txt",
            "-H",
            "Credential: none",
            "-H",
            f"Source: {source}",
            "-w",
            "%{http_code}",
            "-o",
            "/dev/null",
            timeout=30,
        )

        assert result.returncode == 0, result.stderr.decode(errors="replace")
        assert int(result.stdout.strip()) in (200, 201, 202)
        assert _wait_for_file(
            reference_xrd_http.data_root / "from-nginx-plugin.txt",
            content,
        )


class TestHTTPTPCPush:
    """HTTP-TPC push-mode tests: the source server reads a local file and PUTs
    it to a remote HTTPS destination (curl --upload-file)."""

    def test_push_basic_creates_file_at_destination(self, tpc_nginx):
        content = b"pushed via HTTP-TPC push mode\n"
        _write(tpc_nginx.source_open_root / "push-source.txt", content)

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-basic-dest.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_open_port, "/push-source.txt", dest_url
        )

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "push-basic-dest.txt").read_bytes() == content

    def test_push_required_source_with_auth(self, tpc_nginx):
        content = b"push from auth-required source\n"
        _write(tpc_nginx.source_required_root / "push-required-source.txt", content)

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-from-required.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_required_port,
            "/push-required-source.txt",
            dest_url,
        )

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "push-from-required.txt").read_bytes() == content

    def test_push_to_cadir_destination(self, tpc_nginx):
        content = b"push to cadir destination\n"
        _write(tpc_nginx.source_open_root / "push-cadir-source.txt", content)

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cadir_port}/push-via-cadir.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_open_port, "/push-cadir-source.txt", dest_url
        )

        assert code == 201
        assert (tpc_nginx.dest_cadir_root / "push-via-cadir.txt").read_bytes() == content

    def test_push_nonexistent_source_returns_404(self, tpc_nginx):
        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-should-not-exist.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_open_port, "/no-such-file.txt", dest_url
        )

        assert code == 404
        assert not (tpc_nginx.dest_cafile_root / "push-should-not-exist.txt").exists()

    def test_push_directory_source_returns_409(self, tpc_nginx):
        (tpc_nginx.source_open_root / "push-dir").mkdir(exist_ok=True)

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-dir-dest.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_open_port, "/push-dir", dest_url
        )

        assert code == 409

    def test_push_tpc_disabled_on_source_returns_405(self, tpc_nginx):
        """dest_disabled_port has brix_webdav_tpc off — COPY must be rejected."""
        _write(tpc_nginx.dest_disabled_root / "push-disabled-src.txt", b"x\n")

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-disabled.txt"
        )
        code = _copy_push_code(
            tpc_nginx.dest_disabled_port, "/push-disabled-src.txt", dest_url
        )

        assert code == 405

    def test_push_missing_service_cert_destination_fails_502(self, tpc_nginx):
        """Source has no outbound cert — destination (auth required) rejects curl PUT."""
        _write(tpc_nginx.dest_no_service_cert_root / "push-no-cert-src.txt", b"data\n")

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-no-cert-dest.txt"
        )
        code = _copy_push_code(
            tpc_nginx.dest_no_service_cert_port,
            "/push-no-cert-src.txt",
            dest_url,
        )

        assert code == 502
        assert not (tpc_nginx.dest_cafile_root / "push-no-cert-dest.txt").exists()

    def test_push_non_https_destination_rejected_400(self, tpc_nginx):
        _write(tpc_nginx.source_open_root / "push-http-dest-src.txt", b"data\n")

        code = _copy_push_code(
            tpc_nginx.source_open_port,
            "/push-http-dest-src.txt",
            f"http://{HOST}:9999/should-be-rejected",
        )

        assert code == 400

    def test_push_with_transfer_header_forwarded(self, tpc_nginx):
        content = b"push with transfer header\n"
        _write(tpc_nginx.source_open_root / "push-xfer-hdr-src.txt", content)

        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-xfer-hdr-dest.txt"
        )
        code = _copy_push_code(
            tpc_nginx.source_open_port,
            "/push-xfer-hdr-src.txt",
            dest_url,
            "TransferHeaderX-Custom-Test: tpc-push-test",
        )

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "push-xfer-hdr-dest.txt").read_bytes() == content

    def test_push_overwrite_false_forwarded(self, tpc_nginx):
        """Pushing with Overwrite: F should be forwarded to the destination.
        If the destination exists, it should return 412."""
        _write(tpc_nginx.source_open_root / "push-ovr-src.txt", b"new\n")
        dest_file = tpc_nginx.dest_cafile_root / "push-ovr-dest.txt"
        _write(dest_file, b"old\n")

        dest_url = f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-ovr-dest.txt"
        
        # When Overwrite: F is forwarded, the destination returns 412.
        # Since we use curl --fail, it exits with an error and we return 502.
        code = _copy_push_code(
            tpc_nginx.source_open_port,
            "/push-ovr-src.txt",
            dest_url,
            "Overwrite: F",
        )

        assert code == 502
        assert dest_file.read_bytes() == b"old\n"

    def test_both_source_and_destination_headers_rejected_400(self, tpc_nginx):
        """Supplying both Source: and Destination: is ambiguous — must return 400."""
        _write(tpc_nginx.source_open_root / "push-both-hdrs.txt", b"data\n")

        source_url = (
            f"https://{HOST}:{tpc_nginx.source_open_port}/push-both-hdrs.txt"
        )
        dest_url = (
            f"https://{HOST}:{tpc_nginx.dest_cafile_port}/push-both-hdrs-dest.txt"
        )
        result = _curl(
            "-X",
            "COPY",
            f"https://{HOST}:{tpc_nginx.source_open_port}/push-both-hdrs.txt",
            "-H",
            "Credential: none",
            "-H",
            f"Source: {source_url}",
            "-H",
            f"Destination: {dest_url}",
            "-w",
            "%{http_code}",
            "-o",
            "/dev/null",
        )
        assert result.returncode == 0
        assert int(result.stdout.strip()) == 400
