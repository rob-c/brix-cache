"""E-1 — valid-but-dangerous configs are loud at load and refused under strict.

Several configurations parse cleanly yet leave the export wide open:

  * S3 with neither a SigV4 access key nor WLCG token auth  → every request
    is served unauthenticated;
  * a writable WebDAV export whose auth is not *required*    → an anonymous
    client may create / overwrite / delete objects;
  * an anonymous dashboard                                   → client
    identities, paths and IPs are readable without a login.

Each is a legitimate choice for a closed lab and a foot-gun in production, so
the contract (docs/07-security/hyper-hardening-plan.md, E-1) is:

  * success           — a *secured* variant of each surface passes `nginx -t`
    with no insecure-config diagnostic;
  * error             — the insecure variant still passes `nginx -t` but emits
    an ``[warn] brix: insecure configuration`` line naming the setting;
  * security-negative — the SAME insecure variant with ``brix_strict_security
    on`` is REFUSED: `nginx -t` fails with an ``[emerg]`` insecure-config line.

The modules are statically linked into NGINX_BIN, so each case is driven by
writing a minimal config and running ``nginx -t`` directly — no fleet, no
lifecycle harness.

Run: PYTHONPATH=tests pytest tests/test_strict_security_e1.py -v   (no root needed)
"""

import os
import subprocess

import pytest

from settings import BIND_HOST, NGINX_BIN

pytestmark = pytest.mark.usefixtures()  # self-contained; no fleet attach


@pytest.fixture(scope="module")
def export_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("e1_export")
    return str(d)


def _run_nginx_t(tmp_path, body: str):
    """Render a minimal http{} config carrying `body` inside a location and run
    `nginx -t`. Returns (returncode, combined stdout+stderr)."""
    prefix = tmp_path
    (prefix / "conf").mkdir(exist_ok=True)
    (prefix / "logs").mkdir(exist_ok=True)
    conf = prefix / "conf" / "nginx.conf"
    conf.write_text(
        "daemon off;\n"
        "events { worker_connections 64; }\n"
        "http {\n"
        "  server {\n"
        f"    listen {BIND_HOST}:18390;\n"
        "    location / {\n"
        f"{body}\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    res = subprocess.run(
        [NGINX_BIN, "-t", "-p", str(prefix), "-c", "conf/nginx.conf"],
        capture_output=True, text=True, timeout=30,
    )
    return res.returncode, res.stdout + res.stderr


# Each surface: (label, insecure body, secured body). {STRICT} is substituted
# with the brix_strict_security directive (or "") and {EXPORT} with the export.
SURFACES = {
    "s3": {
        "insecure": (
            "{STRICT}"
            "      brix_s3 on;\n"
            "      brix_export {EXPORT};"
        ),
        "secure": (
            "      brix_s3 on;\n"
            "      brix_s3_access_key AKIDEXAMPLE;\n"
            "      brix_s3_secret_key secretsecretsecret;\n"
            "      brix_export {EXPORT};"
        ),
    },
    "webdav": {
        "insecure": (
            "{STRICT}"
            "      brix_webdav on;\n"
            "      brix_webdav_auth none;\n"
            "      brix_allow_write on;\n"
            "      brix_export {EXPORT};"
        ),
        "secure": (
            "      brix_webdav on;\n"
            "      brix_webdav_auth none;\n"
            "      brix_export {EXPORT};"    # read-only: no unauth-write exposure
        ),
    },
    "dashboard": {
        "insecure": (
            "{STRICT}"
            "      brix_dashboard on;\n"
            "      brix_dashboard_anonymous on;"
        ),
        "secure": (
            "      brix_dashboard on;\n"
            "      brix_dashboard_anonymous off;"
        ),
    },
}

INSECURE_MARK = "brix: insecure configuration"


def _body(surface, kind, strict, export):
    strict_line = "      brix_strict_security on;\n" if strict else ""
    return SURFACES[surface][kind].format(STRICT=strict_line, EXPORT=export)


@pytest.fixture(scope="module", autouse=True)
def _require_binary():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


# -- success: the secured variant of each surface is clean ------------------- #
@pytest.mark.parametrize("surface", list(SURFACES))
def test_secured_config_has_no_insecure_diagnostic(tmp_path, export_dir, surface):
    rc, out = _run_nginx_t(tmp_path, _body(surface, "secure", False, export_dir))
    assert rc == 0, f"{surface}: secured config must pass nginx -t\n{out}"
    assert INSECURE_MARK not in out, (
        f"{surface}: secured config must not emit an insecure-config line\n{out}")


# -- error: the insecure variant warns but is still accepted (warn-only) ----- #
@pytest.mark.parametrize("surface", list(SURFACES))
def test_insecure_config_warns_and_loads(tmp_path, export_dir, surface):
    rc, out = _run_nginx_t(tmp_path, _body(surface, "insecure", False, export_dir))
    assert rc == 0, f"{surface}: warn-only insecure config must still load\n{out}"
    assert INSECURE_MARK in out, f"{surface}: no insecure-config warning\n{out}"
    assert "[warn]" in out, f"{surface}: insecure line must be a warn\n{out}"


# -- security-negative: the same insecure config is REFUSED under strict ----- #
@pytest.mark.parametrize("surface", list(SURFACES))
def test_strict_security_refuses_insecure_config(tmp_path, export_dir, surface):
    rc, out = _run_nginx_t(tmp_path, _body(surface, "insecure", True, export_dir))
    assert rc != 0, (
        f"{surface}: brix_strict_security on MUST fail nginx -t on this "
        f"insecure config\n{out}")
    assert INSECURE_MARK in out and "[emerg]" in out, (
        f"{surface}: strict refusal must be an emerg insecure-config line\n{out}")
    assert "refused: brix_strict_security on" in out, (
        f"{surface}: refusal must name the strict directive\n{out}")


# -- coverage: strict mode is a no-op on an ALREADY-secure config ------------ #
@pytest.mark.parametrize("surface", list(SURFACES))
def test_strict_security_accepts_secure_config(tmp_path, export_dir, surface):
    body = "      brix_strict_security on;\n" + _body(surface, "secure", False,
                                                       export_dir)
    rc, out = _run_nginx_t(tmp_path, body)
    assert rc == 0, (
        f"{surface}: strict mode must accept an already-secure config\n{out}")
    assert INSECURE_MARK not in out
