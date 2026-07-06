"""Config-time HARD guard: a cache/state/stage tree nested inside an export is rejected.

Sidecars (.cinfo/.meta) and upload temps must never sit in a client-visible namespace. Beyond
the runtime name filter (test_mu_sidecar_hidden.py), the STRUCTURAL guarantee is that the
service trees are not in the export at all — enforced at config time: a nesting is a
deploy-blocking `nginx -t` error, not a warning. This test asserts each protocol rejects a
nested cache/stage tree and accepts one placed outside the export.

Run: PYTHONPATH=tests pytest tests/test_mu_sidecar_config_guard.py -v   (no root needed)
"""
import os
import subprocess

import pytest

from mu_authz_lib import fleet, ports, principals

_ROOT = os.path.join(ports.MU.MU_ROOT, "guard")
_EXPORT = os.path.join(_ROOT, "export")
_OUTSIDE = os.path.join(_ROOT, "outside")
_NESTED = os.path.join(_EXPORT, "svc")          # inside the export → must be rejected
_CA = os.path.join(ports.MU.CA_DIR, "ca.pem")
_TMP = os.path.join(_ROOT, "tmp")


def _prep_dirs():
    principals.build_cast()   # ensures the test CA exists (webdav auth precheck)
    for d in (_EXPORT, _OUTSIDE, _NESTED, _TMP, os.path.join(_ROOT, "logs")):
        os.makedirs(d, exist_ok=True)


def _nginx_t(text, name):
    _prep_dirs()
    cfg = os.path.join(_ROOT, f"{name}.conf")
    with open(cfg, "w") as f:
        f.write(text)
    r = subprocess.run([fleet.NGINX, "-t", "-c", cfg, "-g", f"pid {_ROOT}/{name}.pid;"],
                       capture_output=True, text=True, timeout=30)
    return r.returncode, r.stderr


def _stream(stage=None, state=None):
    lines = [f"        brix_stage_dir {stage};" ] if stage else []
    if state:
        lines.append(f"        brix_cache_state_root {state};")
    body = "\n".join(lines)
    return f"""worker_processes 1;
error_log {_ROOT}/logs/e.log crit;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen 127.0.0.1:19990;
        brix_root on;
        brix_export {_EXPORT};
        brix_storage_backend posix:{_EXPORT};
        brix_auth none;
        brix_allow_write on;
{body}
    }}
}}
"""


def _webdav(cache_root=None, stage=None):
    lines = []
    if cache_root:
        lines.append(f"            brix_webdav_cache_root {cache_root};")
    if stage:
        lines.append(f"            brix_webdav_stage_dir {stage};")
    body = "\n".join(lines)
    tmp = "\n    ".join(f"{p} {_TMP};" for p in
                        ("client_body_temp_path", "proxy_temp_path", "fastcgi_temp_path",
                         "uwsgi_temp_path", "scgi_temp_path"))
    return f"""worker_processes 1;
error_log {_ROOT}/logs/e.log crit;
events {{ worker_connections 64; }}
http {{
    access_log off;
    {tmp}
    server {{
        listen 127.0.0.1:19991;
        location / {{
            brix_webdav on;
            brix_export {_EXPORT};
            brix_storage_backend posix:{_EXPORT};
            brix_webdav_auth required;
            brix_webdav_cafile {_CA};
            brix_allow_write on;
{body}
        }}
    }}
}}
"""


def _s3(cache_root):
    tmp = "\n    ".join(f"{p} {_TMP};" for p in
                        ("client_body_temp_path", "proxy_temp_path", "fastcgi_temp_path",
                         "uwsgi_temp_path", "scgi_temp_path"))
    return f"""worker_processes 1;
error_log {_ROOT}/logs/e.log crit;
events {{ worker_connections 64; }}
http {{
    access_log off;
    {tmp}
    server {{
        listen 127.0.0.1:19992;
        location / {{
            brix_s3 on;
            brix_export {_EXPORT};
            brix_storage_backend posix:{_EXPORT};
            brix_s3_cache_root {cache_root};
        }}
    }}
}}
"""


# (label, config text, nested?) — nested must be rejected, outside must be accepted.
CASES = [
    ("stream-stage-nested", _stream(stage=_NESTED), True),
    ("stream-stage-outside", _stream(stage=_OUTSIDE), False),
    ("stream-state-nested", _stream(state=_NESTED), True),
    ("stream-state-outside", _stream(state=_OUTSIDE), False),
    ("webdav-cacheroot-nested", _webdav(cache_root=_NESTED), True),
    ("webdav-cacheroot-outside", _webdav(cache_root=_OUTSIDE), False),
    ("webdav-stage-nested", _webdav(cache_root=_OUTSIDE, stage=_NESTED), True),
    ("s3-cacheroot-nested", _s3(_NESTED), True),
    ("s3-cacheroot-outside", _s3(_OUTSIDE), False),
]


@pytest.mark.parametrize("label,text,nested", CASES, ids=[c[0] for c in CASES])
def test_config_guard_rejects_nested_service_tree(label, text, nested):
    rc, stderr = _nginx_t(text, label)
    if nested:
        assert rc != 0, f"{label}: a service tree inside the export MUST be rejected\n{stderr}"
        assert "at or beneath export root" in stderr, (
            f"{label}: rejected for the wrong reason (not the export-guard)\n{stderr}")
    else:
        assert rc == 0, f"{label}: a service tree outside the export must be accepted\n{stderr}"
