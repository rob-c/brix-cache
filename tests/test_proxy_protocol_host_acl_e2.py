"""E-2 — host ACL layered over a proxy_protocol listener is refused at load.

Host-based auth (``brix_host_allow``) trusts the connection's peer address. On
a ``listen ... proxy_protocol`` socket that address is whatever the immediate
client asserts in the PROXY header, so a spoofed header would satisfy the
allowlist. The only safe way to combine the two is a trusted-proxy allowlist
(``set_real_ip_from``, from the realip module) constraining who may send a
PROXY header — and this build ships without realip, so that allowlist cannot
be expressed at all.

The contract (docs/07-security/hyper-hardening-plan.md, E-2) is therefore a
hard, unconditional config rejection:

  * success           — ``brix_host_allow`` on a plain listener passes
    ``nginx -t`` (host ACL is fine when the peer address is genuine);
  * error             — a ``proxy_protocol`` listener with no host ACL passes
    ``nginx -t`` (proxy_protocol alone is fine);
  * security-negative — ``proxy_protocol`` + ``brix_host_allow`` on the same
    server is REFUSED: ``nginx -t`` fails with an ``[emerg]`` naming the
    spoofable-peer coupling.

Modules are statically linked into NGINX_BIN, so each case is a minimal
stream{} config run through ``nginx -t`` — no fleet, no lifecycle harness.

Run: PYTHONPATH=tests pytest tests/test_proxy_protocol_host_acl_e2.py -v
"""

import os
import subprocess

import pytest

from settings import NGINX_BIN


@pytest.fixture(scope="module")
def data_root(tmp_path_factory):
    return str(tmp_path_factory.mktemp("e2_export"))


@pytest.fixture(scope="module", autouse=True)
def _require_binary():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


def _run_nginx_t(tmp_path, listen: str, extra: str, data_root: str):
    """Render a minimal stream{} brix_root server and run `nginx -t`.
    `listen` is the listen argument tail (e.g. "proxy_protocol"), `extra`
    holds server-scope directives. Returns (returncode, stdout+stderr)."""
    prefix = tmp_path
    (prefix / "conf").mkdir(exist_ok=True)
    (prefix / "logs").mkdir(exist_ok=True)
    conf = prefix / "conf" / "nginx.conf"
    conf.write_text(
        "daemon off;\n"
        "events { worker_connections 64; }\n"
        "stream {\n"
        "  server {\n"
        f"    listen 127.0.0.1:18391 {listen};\n"
        "    brix_root on;\n"
        f"    brix_storage_backend posix:{data_root};\n"
        f"{extra}"
        "  }\n"
        "}\n"
    )
    res = subprocess.run(
        [NGINX_BIN, "-t", "-p", str(prefix), "-c", "conf/nginx.conf"],
        capture_output=True, text=True, timeout=30,
    )
    return res.returncode, res.stdout + res.stderr


HOST_ACL = "    brix_auth host;\n    brix_host_allow 127.0.0.0/8;\n"
REFUSE_MARK = "refusing insecure configuration"


# -- success: a host ACL on a genuine (non-proxy) listener is accepted ------- #
def test_host_acl_without_proxy_protocol_loads(tmp_path, data_root):
    rc, out = _run_nginx_t(tmp_path, "", HOST_ACL, data_root)
    assert rc == 0, f"host ACL on a plain listener must pass nginx -t\n{out}"
    assert REFUSE_MARK not in out, out


# -- error: proxy_protocol with no host ACL is a valid, accepted config ------ #
def test_proxy_protocol_without_host_acl_loads(tmp_path, data_root):
    rc, out = _run_nginx_t(tmp_path, "proxy_protocol", "", data_root)
    assert rc == 0, f"proxy_protocol alone must pass nginx -t\n{out}"
    assert REFUSE_MARK not in out, out


# -- security-negative: the two together are refused at config time ---------- #
def test_proxy_protocol_with_host_acl_is_refused(tmp_path, data_root):
    rc, out = _run_nginx_t(tmp_path, "proxy_protocol", HOST_ACL, data_root)
    assert rc != 0, (
        "brix_host_allow over a proxy_protocol listener MUST fail nginx -t "
        f"(spoofable peer address)\n{out}")
    assert REFUSE_MARK in out and "[emerg]" in out, (
        f"refusal must be an emerg insecure-config line\n{out}")
    assert "proxy_protocol" in out and "set_real_ip_from" in out, (
        f"refusal must name the coupling and the (absent) remedy\n{out}")
