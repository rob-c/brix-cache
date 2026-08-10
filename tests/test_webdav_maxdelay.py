"""brix_webdav_maxdelay — the http.maxdelay analog (parity audit §6.11).

The WebDAV GET path answers a nearline (tape) recall with a 202 "staging"
response plus a `Retry-After` telling the client how long to wait before polling
again — a hardcoded 10 s. `brix_webdav_maxdelay <time>` caps that poll wait, so a
deployment can TIGHTEN (never lengthen) the recall poll cadence; 0 (default)
keeps the 10 s.

The 202 emission fires only under a live nearline recall (EAGAIN from the VFS
open), which needs a tape/nearline backend to reproduce; the clamp itself is a
minimal `min()` on that existing, separately-covered emission point
(`webdav/get.c`). What warrants a dedicated guard here is the config grammar — a
mistyped time must fail `nginx -t`, a valid one must wire — so these are
self-contained nginx -t accept/reject cases (no server bind, no fleet).

Run:
    PYTHONPATH=tests pytest tests/test_webdav_maxdelay.py -v
"""

import subprocess

import pytest

from cmdscripts.live_common import inject_nginx_load_modules
from settings import BIND_HOST, NGINX_BIN


def _nginx_t(root, directive):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    for d in ("cbt", "pt", "ft", "ut", "st"):
        (root / d).mkdir(exist_ok=True)
    conf = root / "md.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {root}/cbt; proxy_temp_path {root}/pt;
    fastcgi_temp_path {root}/ft; uwsgi_temp_path {root}/ut; scgi_temp_path {root}/st;
    access_log off;
    server {{ listen {BIND_HOST}:13897;
        location / {{
            brix_webdav on;
            brix_storage_backend posix:{root}/data;
            brix_webdav_auth none;
            {directive}
        }}
    }}
}}
""")
    inject_nginx_load_modules(conf)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


ACCEPT = [
    "brix_webdav_maxdelay 0;",
    "brix_webdav_maxdelay 5s;",
    "brix_webdav_maxdelay 30;",
    "brix_webdav_maxdelay 1m;",
]

REJECT = [
    ("brix_webdav_maxdelay notatime;", "invalid value"),
    ("brix_webdav_maxdelay 5s 9s;", "invalid number of arguments"),
    ("brix_webdav_maxdelay 1m; brix_webdav_maxdelay 2m;", "duplicate"),
]


@pytest.mark.parametrize("directive", ACCEPT)
def test_accepted(tmp_path, directive):
    rc, out = _nginx_t(tmp_path, directive)
    assert rc == 0, f"expected accept for {directive!r}:\n{out}"
    assert "successful" in out


@pytest.mark.parametrize("directive,needle", REJECT)
def test_rejected(tmp_path, directive, needle):
    rc, out = _nginx_t(tmp_path, directive)
    assert rc != 0, f"expected reject for {directive!r}:\n{out}"
    assert needle in out, f"expected {needle!r} for {directive!r}, got:\n{out}"
