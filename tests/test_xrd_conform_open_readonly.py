"""Real BriX token/read-only ordering coverage for Phase-118 OPN-012."""
import json
import os
from pathlib import Path
import subprocess

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import (BIND_HOST, CA_DIR, HOST, SERVER_CERT, SERVER_KEY,
                      TOKENS_DIR, url_host)
from test_xrd_conform_cache import EvictOrigin
from test_xrd_conform_http_semantics import XRD, _clean_environment
from utils.make_token import TokenIssuer


pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-phase118-open-readonly")]


def _write_token(path, token):
    path.write_text(token, encoding="utf-8")
    path.chmod(0o600)
    return str(path)


@pytest.fixture(scope="module")
def readonly_topology(tmp_path_factory):
    issuer = TokenIssuer(TOKENS_DIR)
    if not (os.path.exists(issuer.key_path)
            and os.path.exists(issuer.jwks_path)):
        issuer.init_keys()
    credentials = tmp_path_factory.mktemp("phase118_open_credentials")
    token_file = _write_token(
        credentials / "full.jwt",
        issuer.generate(
            sub="phase118-open",
            scope="storage.read:/ storage.create:/ storage.modify:/"),
    )
    readonly_root = tmp_path_factory.mktemp("phase118_open_readonly")
    writable_root = tmp_path_factory.mktemp("phase118_open_writable")
    harness = LifecycleHarness()
    try:
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-phase118-open-readonly",
            template="nginx_lc_phase118_open_readonly.conf",
            protocol="root",
            readiness="tcp",
            host=BIND_HOST,
            template_values={
                "BIND_HOST": BIND_HOST,
                "READONLY_ROOT": str(readonly_root),
                "WRITABLE_ROOT": str(writable_root),
                "JWKS": issuer.jwks_path,
                "TOKEN_ISSUER": issuer.issuer,
                "TOKEN_AUDIENCE": issuer.audience,
                "CERT_FILE": SERVER_CERT,
                "KEY_FILE": SERVER_KEY,
                "CA_DIR": CA_DIR,
            },
            reason="Phase-118 read-only policy before token scope"))
        host = url_host(HOST)
        yield {
            "readonly": f"roots://{host}:{endpoint.port}//fixture",
            "writable":
                f"roots://{host}:{endpoint.extra_ports['PORT_WRITABLE']}"
                "//fixture",
            "token_file": token_file,
            "roots": (readonly_root, writable_root),
        }
    finally:
        harness.close()


def _run(tmp_path, fixture_url, token_file, verify=False):
    with EvictOrigin() as primary:
        primary.objects["/primary"] = b"control"
        primary_url = f"root://{HOST}:{primary.port}//primary"
        output = tmp_path / str(primary.port)
        environment = _clean_environment()
        environment["X509_CERT_DIR"] = CA_DIR
        if token_file is not None:
            environment["BEARER_TOKEN_FILE"] = token_file
        command = [str(XRD), "conform", "accept", primary_url,
             "--profile", "data", "--only", "OPN-012",
             "--open-fixture", f"readonly={fixture_url}",
             "--allow-mutate", "--scratch", "/phase118-open",
             "--fail-on", "divergent", "--wall-seconds", "30",
             "--request-limit", "128", "--byte-limit", "1048576",
             "--out", str(output)]
        if verify:
            command.extend(["--verify-negative", "OPN-012"])
        result = subprocess.run(
            command,
            env=environment, text=True, capture_output=True,
            timeout=45, check=False,
        )
        report = json.loads((output / "report.json").read_text(
            encoding="utf-8"))
        row = next(row for row in report["results"]
                   if row["id"] == "OPN-012")
        return result, row


def test_readonly_refusal_precedes_anonymous_and_token_identity(
        tmp_path, readonly_topology):
    result, row = _run(tmp_path, readonly_topology["readonly"],
                       readonly_topology["token_file"])
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant"
    assert row["reason"] == \
        "readonly-refusal-preceded-credential-evaluation"


def test_writable_control_cannot_masquerade_as_readonly(
        tmp_path, readonly_topology):
    result, row = _run(tmp_path, readonly_topology["writable"],
                       readonly_topology["token_file"], verify=True)
    assert result.returncode == 1, result.stderr + result.stdout
    assert row["verdict"] == "divergent"
    assert row["reason"] == "readonly-refusal-depended-on-credential"
    assert not (Path(readonly_topology["roots"][1])
                / "phase118-open" / "brix-conform-open-readonly-order").exists()


def test_missing_token_never_becomes_readonly_evidence(
        tmp_path, readonly_topology):
    result, row = _run(tmp_path, readonly_topology["readonly"], None)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "inconclusive"
    assert row["reason"] == "readonly-identity-pair-unavailable"
