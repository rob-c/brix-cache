"""Authorized VOMS identity carry through the outbound gsiftp backend."""

from __future__ import annotations

import http.client
import os
from pathlib import Path
import subprocess
import sys

import pytest

from pki_helpers import blitz_test_pki
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import (
    BIND_HOST, CA_DIR, NGINX_BIN, PKI_DIR, PROXY_STD, SERVER_CERT,
    SERVER_HOST, SERVER_KEY, USER_CERT, USER_KEY, VOMSDIR,
)


pytestmark = [
    pytest.mark.serial,
    pytest.mark.slow,
    pytest.mark.timeout(300),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-gsiftp-voms-backend"),
]

_VOMS_PROXY = Path(__file__).resolve().parents[1] / "utils" / "voms_proxy_fake.py"


def _run(*argv: str) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(argv)} failed:\n{result.stderr}")
    return result.stdout


def _certificate_dn(path: Path, field: str) -> str:
    output = _run(
        "openssl", "x509", "-in", str(path), "-noout", f"-{field}",
        "-nameopt", "compat",
    )
    return output.strip().split("=", 1)[1].strip()


def _make_voms_signer(cert: Path, key: Path) -> None:
    csr = cert.with_suffix(".csr")
    ext = cert.with_name("voms_ext.conf")
    _run("openssl", "genrsa", "-out", str(key), "2048")
    _run(
        "openssl", "req", "-new", "-key", str(key), "-out", str(csr),
        "-subj", "/DC=test/DC=xrootd/CN=voms.test.local",
    )
    ext.write_text(
        "[voms_ext]\nsubjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid:always\nbasicConstraints = CA:FALSE\n",
        encoding="utf-8",
    )
    _run(
        "openssl", "x509", "-req", "-in", str(csr),
        "-CA", str(Path(CA_DIR) / "ca.pem"),
        "-CAkey", str(Path(CA_DIR) / "ca.key"), "-CAcreateserial",
        "-out", str(cert), "-days", "2", "-extensions", "voms_ext",
        "-extfile", str(ext),
    )


def _make_vomsdir(cert: Path) -> None:
    lsc = f"{_certificate_dn(cert, 'subject')}\n{_certificate_dn(cert, 'issuer')}\n"
    for vo in ("atlas", "cms"):
        directory = Path(VOMSDIR) / vo
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "voms.test.local.lsc").write_text(lsc, encoding="utf-8")


def _make_proxy(vo: str, destination: Path, cert: Path, key: Path) -> None:
    _run(
        sys.executable, str(_VOMS_PROXY), "-cert", USER_CERT, "-key", USER_KEY,
        "-certdir", CA_DIR, "-hostcert", str(cert), "-hostkey", str(key),
        "-voms", vo, "-fqan", f"/{vo}/Role=NULL/Capability=NULL",
        "-uri", "voms.test.local:15000", "-out", str(destination),
        "-hours", "1",
    )


def _prepare_credentials() -> tuple[Path, Path]:
    if not _VOMS_PROXY.is_file():
        pytest.skip("utils/voms_proxy_fake.py is unavailable")
    blitz_test_pki()
    voms_root = Path(PKI_DIR) / "voms"
    cert, key = voms_root / "voms_cert.pem", voms_root / "voms_key.pem"
    _make_voms_signer(cert, key)
    _make_vomsdir(cert)
    atlas = Path(PKI_DIR) / "user" / "proxy_vo_atlas.pem"
    cms = Path(PKI_DIR) / "user" / "proxy_vo_cms.pem"
    _make_proxy("atlas", atlas, cert, key)
    _make_proxy("cms", cms, cert, key)
    return atlas, cms


class _VomsLab:
    def __init__(self, tmp: Path, atlas: Path, cms: Path):
        origin = tmp / "origin"
        (origin / "vodata").mkdir(parents=True)
        (origin / "open").mkdir()
        (origin / "vodata" / "secret.txt").write_bytes(b"atlas-only")
        (origin / "open" / "public.txt").write_bytes(b"public")
        exports = [tmp / name for name in ("atlas", "plain", "cms")]
        for export in exports:
            export.mkdir()
        harness = LifecycleHarness()
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-gsiftp-voms-backend",
            template="nginx_lc_gsiftp_voms_backend.conf",
            protocol="http",
            readiness="tcp",
            data_root=str(origin),
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_ROOT": str(origin),
                "ATLAS_EXPORT": str(exports[0]),
                "PLAIN_EXPORT": str(exports[1]),
                "CMS_EXPORT": str(exports[2]),
                "ATLAS_PROXY": str(atlas),
                "PLAIN_PROXY": PROXY_STD,
                "CMS_PROXY": str(cms),
                "CA_DIR": CA_DIR,
                "VOMSDIR": VOMSDIR,
                "SERVER_CERT": SERVER_CERT,
                "SERVER_KEY": SERVER_KEY,
            },
            reason="VOMS identity carry through an outbound gsiftp backend",
        ))
        self.harness = harness
        self.port = endpoint.port
        self.plain_port = endpoint.extra_ports["PLAIN_PORT"]
        self.cms_port = endpoint.extra_ports["CMS_PORT"]

    def close(self) -> None:
        self.harness.close()


@pytest.fixture(scope="module")
def voms_backend(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    atlas, cms = _prepare_credentials()
    lab = _VomsLab(tmp_path_factory.mktemp("gsiftp-voms"), atlas, cms)
    yield lab
    lab.close()


def _get(port: int, path: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(SERVER_HOST, port, timeout=30)
    connection.request("GET", path)
    response = connection.getresponse()
    result = response.status, response.read()
    connection.close()
    return result


def test_authorized_voms_proxy_reaches_vo_gated_origin(voms_backend):
    assert _get(voms_backend.port, "/vodata/secret.txt") == (200, b"atlas-only")


def test_plain_proxy_is_denied_by_vo_gated_origin(voms_backend):
    # The GridFTP origin deliberately maps both absent and unauthorized paths
    # to 550.  The outbound backend preserves that non-disclosure boundary as
    # HTTP 404 instead of guessing whether the remote object exists.
    assert _get(voms_backend.plain_port, "/vodata/secret.txt")[0] == 404
    assert _get(voms_backend.plain_port, "/open/public.txt") == (200, b"public")


def test_wrong_vo_proxy_cannot_cross_atlas_gate(voms_backend):
    assert _get(voms_backend.cms_port, "/vodata/secret.txt")[0] == 404
