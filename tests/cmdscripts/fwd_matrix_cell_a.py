"""Pairing-A cell orchestration for the forwarding matrix."""

from __future__ import annotations

import re
import time


def _supported(harness, key, hop2, credential):
    verdict, reason = harness.feasibility_probe("A", hop2, credential)
    if verdict != "SUPPORTED":
        harness.record(key, verdict, reason)
        return False
    if credential == "token" and harness.tok_jwks is None:
        harness.record(key, "SKIP", "token authority unavailable")
        return False
    return True


def _spawn_backend(harness, wire, credential, hop2, port, namespace):
    role = f"obk_{wire}_{credential}"
    if credential == "token":
        log = harness.spawn_xrootd_node(role, "origin", port, "", "token")
        return log, f"roots://{namespace['HOST']}:{port}", "token"
    if hop2 == "https":
        log = harness.spawn_xrootd_node(role, "xrdhttp", port, "", "gsi")
        return log, f"https://{namespace['HOST']}:{port}", "xrdhttp"
    log = harness.spawn_xrootd_node(role, "origin", port, "", "gsi")
    return log, f"root://{namespace['HOST']}:{port}", "origin"


def _backend_ready(harness, key, backend):
    log, _url, kind = backend
    if log is not None:
        return True
    if kind == "token":
        harness.record(key, "FAIL", "stock token origin start failed")
        return False
    if kind == "xrdhttp":
        harness.record(key, "FAIL", "stock XrdHttp origin start failed")
        return False
    return True


def _root_front_blocks(harness, credential, namespace):
    ca_dir = namespace["CA_DIR"]
    if credential == "token":
        service = f"brix_credential origin_ca {{ ca_dir {ca_dir}; }}"
        auth = (
            f"brix_auth token;\n        brix_tls on;\n"
            f"        brix_certificate     {namespace['SERVER_CERT']};\n"
            f"        brix_certificate_key {namespace['SERVER_KEY']};\n"
            f"        brix_token_jwks     {harness.tok_jwks};\n"
            f"        brix_token_issuer   {harness.tok_issuer};\n"
            f"        brix_token_audience {namespace['TOK_AUD']};"
        )
        return service, auth
    service = (
        f"brix_credential origin {{ x509_proxy {harness.svc_proxy}; "
        f"ca_dir {ca_dir}; }}"
    )
    auth = (
        f"brix_auth gsi;\n        brix_certificate     {namespace['SERVER_CERT']};\n"
        f"        brix_certificate_key {namespace['SERVER_KEY']};\n"
        f"        brix_trusted_ca      {namespace['CA_CERT']};"
    )
    return service, auth


def _spawn_front(
    harness, wire, credential, hop1, hop2, port, backend_url, credential_dir,
    namespace,
):
    front_hop = "root" if credential == "token" else hop1
    leg = harness.backend_leg_config(
        "A", hop2, credential, backend_url, credential_dir
    )
    role = f"afront_{wire}_{credential}"
    if front_hop == "root":
        service, auth = _root_front_blocks(harness, credential, namespace)
        log = namespace["_spawn_a_front_root"](
            harness, role, port, service, f"{auth}\n        {leg}"
        )
    else:
        log = namespace["_spawn_a_front_davs"](harness, role, port, leg)
    return front_hop, log


def _prepare_cell(harness, key, wire, credential, hop1, hop2, namespace):
    origin_port, front_port = namespace["free_ports"](2)
    backend = _spawn_backend(
        harness, wire, credential, hop2, origin_port, namespace
    )
    if not _backend_ready(harness, key, backend):
        return None
    backend_log, backend_url, _kind = backend
    credential_dir = harness.run.mkdir(f"creds_{wire}_{credential}")
    credential_dir.chmod(0o777)
    front_hop, front_log = _spawn_front(
        harness, wire, credential, hop1, hop2, front_port, backend_url,
        credential_dir, namespace,
    )
    if front_log is None:
        harness.record(key, "FAIL", "brix front start failed")
        return None
    if credential == "gsi":
        harness.install_gsi_cred(credential_dir, front_log, front_hop, front_port)
    time.sleep(0.5)
    return backend_log, front_log, front_hop, front_port


def _positive_result(harness, wire, credential, front_hop, front_port):
    result = harness.front_put_get(
        front_hop, credential, front_port, f"posA_{wire}.bin", "A"
    )
    if result.get_ok:
        return result
    time.sleep(0.4)
    return harness.front_put_get(
        front_hop, credential, front_port, f"posA2_{wire}.bin", "A"
    )


def _token_failure_evidence(front_log):
    text = front_log.read_text(errors="replace") if front_log.is_file() else ""
    return [
        line for line in text.splitlines()
        if re.search(r"kXR 3028|origin TLS handshake failed|ztn", line, re.I)
    ]


def _positive_failure_detail(result, credential, front_log):
    detail = f"userA two-hop PUT/GET not byte-exact (put_ok={int(result.put_ok)})"
    if credential != "token":
        return detail
    if result.deny_obs:
        detail += f" client={result.deny_obs}"
    evidence = _token_failure_evidence(front_log)
    if evidence:
        return (f"front->stock-origin ztn/TLS leg failed "
                f"(put_ok={int(result.put_ok)}): {evidence[-1]}")
    return detail


def _expected_identity(credential, hop2, namespace):
    if credential == "token":
        return namespace["A_SUB"]
    if hop2 == "https":
        return "fwd-user-a"
    return namespace["A_CN"]


def _positive(
    harness, key, wire, credential, hop2, backend_log, front_log,
    front_hop, front_port, namespace,
):
    if backend_log is not None:
        backend_log.write_text("")
    result = _positive_result(harness, wire, credential, front_hop, front_port)
    if not result.get_ok:
        detail = _positive_failure_detail(result, credential, front_log)
        harness.record(key, "FAIL", detail)
        return False
    time.sleep(0.4)
    identity = _expected_identity(credential, hop2, namespace)
    if not harness.assert_backend_identity("stock", backend_log, identity):
        harness.record(key, "FAIL", f"backend log did not show userA ({identity})")
        return False
    return True


def _negative(harness, key, wire, credential, front_hop, front_port):
    backend_dir = harness.prefix / f"obk_{wire}_{credential}/data"
    result = harness.front_put_get(
        front_hop, credential, front_port, f"negB_{wire}.bin", "B"
    )
    protocol = "root" if front_hop == "root" else "https"
    if not harness.assert_denied(protocol, result):
        harness.record(
            key, "FAIL",
            f"userB was NOT denied on backend leg (deny_obs={result.deny_obs})",
        )
        return
    if (backend_dir / f"negB_{wire}.bin").is_file():
        harness.record(key, "FAIL", "userB bytes reached the backend store")
        return
    harness.record(key, "PASS", "userA DN at backend, userB denied, no leak")


def run_cell_a(harness, wire, credential, namespace):
    hop1, hop2 = harness.hop1(wire), harness.hop2(wire)
    key = f"A {wire} {credential}"
    if not _supported(harness, key, hop2, credential):
        return
    prepared = _prepare_cell(
        harness, key, wire, credential, hop1, hop2, namespace
    )
    if prepared is None:
        return
    backend_log, front_log, front_hop, front_port = prepared
    if not _positive(
        harness, key, wire, credential, hop2, backend_log, front_log,
        front_hop, front_port, namespace,
    ):
        return
    _negative(harness, key, wire, credential, front_hop, front_port)
