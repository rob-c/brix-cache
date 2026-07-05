"""
Integration test for the cache stale-dirty reaper's per-reason Prometheus
counter — brix_cache_dirty_reaped_total{reason="abandoned|incomplete|completed"}.

It stands up its own stream-only xrootd (cache state root + a 1-second
brix_cache_dirty_max_age, which arms the per-worker reaper) plus an HTTP
/metrics endpoint, plants one cached file in each reap class via the REAL
.cinfo write-back API (linked against the built cinfo.o), waits for the reaper's
5s first tick, and asserts:

  * each data file (+ its .cinfo sidecar) was reaped;
  * a clean file with NO .cinfo record is left untouched;
  * /metrics reports exactly one reap per reason.

The three classes are constructed from the cinfo write-back state the reaper
classifies on (see brix_cache_reap_reason_t):

  abandoned  — mark_dirty only            → DIRTY, flush_gen==0 (never flushed)
  incomplete — dirty → clean → dirty      → DIRTY, flush_gen>0  (re-dirtied)
  completed  — dirty → clean              → CLEAN, flush_gen>0  (finished WB)

Self-skips when the nginx binary or the compiled cinfo.o are absent (e.g. a
checkout without a build).
"""
import os
import re
import socket
import struct
import subprocess
import time

import pytest

try:
    from settings import NGINX_BIN
except Exception:  # noqa: BLE001 — settings import optional outside the harness
    NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

_OBJS = os.path.dirname(NGINX_BIN)
_CINFO_O = os.path.join(_OBJS, "addon", "cache", "cinfo.o")
# cinfo.c calls into the unified metadata (xmeta) engine, so the planter must
# link those objects too or the standalone link fails on brix_xmeta_* refs.
_CINFO_DEPS = [
    os.path.join(_OBJS, "addon", "meta", "xmeta.o"),
    os.path.join(_OBJS, "addon", "meta", "xmeta_path.o"),
    os.path.join(_OBJS, "addon", "meta", "xmeta_carrier.o"),
    os.path.join(_OBJS, "addon", "compat", "crc32c.o"),
]
_CC = os.environ.get("CC", "cc")

pytestmark = pytest.mark.skipif(
    not (NGINX_BIN and os.path.exists(NGINX_BIN) and os.path.exists(_CINFO_O)),
    reason="nginx binary or built cinfo.o not present",
)

# A tiny C helper that drives the real cinfo write-back API against a cache path.
# Compiled once against the module's own cinfo.o so the on-disk record is exactly
# what the running server's reaper reads back.
_PLANTER_SRC = r"""
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef intptr_t ngx_int_t;
ngx_int_t brix_cache_cinfo_mark_dirty(const char *p, uint64_t size,
    uint32_t bs, uint64_t mtime, uint64_t off, uint64_t len, void *log);
ngx_int_t brix_cache_cinfo_mark_clean(const char *p, uint64_t bytes, void *log);
/* argv: <dirty|clean> <cache_path> */
int main(int argc, char **argv) {
    if (argc < 3) { return 2; }
    if (strcmp(argv[1], "dirty") == 0) {
        return brix_cache_cinfo_mark_dirty(argv[2], 4096, 1048576, 1000,
                                             0, 4096, NULL) == 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "clean") == 0) {
        return brix_cache_cinfo_mark_clean(argv[2], 4096, NULL) == 0 ? 0 : 1;
    }
    return 2;
}
"""

_CONF = """\
daemon on;
worker_processes 1;
error_log {logs}/error.log info;
pid {prefix}/nginx.pid;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen 127.0.0.1:{sport};
        xrootd on;
        brix_root {root};
        brix_auth none;
        brix_cache_state_root {state};
        brix_cache_dirty_max_age 1;
    }}
}}
http {{
    access_log off;
    client_body_temp_path {prefix}/cbt;
    proxy_temp_path {prefix}/pt;
    fastcgi_temp_path {prefix}/ft;
    uwsgi_temp_path {prefix}/ut;
    scgi_temp_path {prefix}/st;
    server {{
        listen 127.0.0.1:{mport};
        location /metrics {{ brix_metrics on; }}
    }}
}}
"""


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _brix_handshake(port):
    """Open + handshake a root:// connection so the server marks its metrics slot
    in_use (a metric row is only exported for an in_use server)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    # ClientInitHandShake: five big-endian int32 — 0,0,0,4,2012.
    s.sendall(struct.pack(">5i", 0, 0, 0, 4, 2012))
    try:
        s.recv(64)
    except OSError:
        pass
    s.close()


def _reaped_by_reason(metrics_text):
    """Sum brix_cache_dirty_reaped_total per reason across all exported rows."""
    out = {}
    pat = re.compile(
        r'brix_cache_dirty_reaped_total\{[^}]*reason="([a-z]+)"[^}]*\}\s+(\d+)')
    for reason, value in pat.findall(metrics_text):
        out[reason] = out.get(reason, 0) + int(value)
    return out


def _scrape(port):
    import urllib.request
    with urllib.request.urlopen("http://127.0.0.1:%d/metrics" % port,
                                timeout=5) as resp:
        return resp.read().decode("utf-8", "replace")


def test_cache_reap_reason_metrics(tmp_path):
    # 1. Build the cinfo planter against the module's own cinfo.o.
    src = tmp_path / "planter.c"
    src.write_text(_PLANTER_SRC)
    planter = tmp_path / "planter"
    subprocess.run([_CC, "-O", "-o", str(planter), str(src), _CINFO_O] + _CINFO_DEPS,
                   check=True)

    state = tmp_path / "state"
    root = tmp_path / "root"
    logs = tmp_path / "logs"
    for d in (state, root, logs):
        d.mkdir()

    def data_file(name):
        p = state / name
        p.write_bytes(os.urandom(4096))
        return str(p)

    def plant(op, path):
        subprocess.run([str(planter), op, path], check=True)

    # 2. Plant one file per reap reason, plus a clean (no-record) control.
    abandoned = data_file("abandoned.bin")
    incomplete = data_file("incomplete.bin")
    completed = data_file("completed.bin")
    keepme = data_file("keepme.bin")          # clean, NO .cinfo → must survive

    plant("dirty", abandoned)                  # DIRTY, flush_gen==0
    plant("dirty", incomplete)                 # DIRTY ...
    plant("clean", incomplete)                 # ... CLEAN, flush_gen=1 ...
    plant("dirty", incomplete)                 # ... DIRTY again (flush_gen>0)
    plant("dirty", completed)                  # DIRTY ...
    plant("clean", completed)                  # ... CLEAN, flush_gen=1 (finished)

    # The cinfo record is persisted via the unified xmeta carrier — xattr-
    # preferred, ".cinfo" sidecar only as a fallback where xattrs are
    # unsupported. On an xattr-capable state fs the record rides the data
    # file's user.xrd.cinfo xattr (and is removed with the file), so assert the
    # record exists via either carrier rather than assuming a sidecar file.
    def _has_cinfo_record(f):
        if os.path.exists(f + ".cinfo"):
            return True
        try:
            os.getxattr(f, "user.xrd.cinfo")
            return True
        except OSError:
            return False

    for f in (abandoned, incomplete, completed):
        assert _has_cinfo_record(f), "planted cinfo record missing for " + f

    # 3. Stand up nginx (stream cache reaper + HTTP /metrics).
    sport = _free_port()
    mport = _free_port()
    conf = tmp_path / "nginx.conf"
    conf.write_text(_CONF.format(prefix=str(tmp_path), logs=str(logs),
                                 root=str(root), state=str(state),
                                 sport=sport, mport=mport))
    subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf)],
                   check=True)
    pidfile = tmp_path / "nginx.pid"
    try:
        # Mark the stream server's metrics slot in_use so the rows export.
        time.sleep(0.3)
        _brix_handshake(sport)

        # 4. Wait for the reaper's first tick (5s) to remove the aged files
        #    (the data file AND its sidecar — the reaper unlinks them back to
        #    back, so wait for both to avoid observing the in-between state).
        deadline = time.time() + 25
        while time.time() < deadline and (os.path.exists(abandoned)
                                          or _has_cinfo_record(abandoned)):
            time.sleep(0.5)

        # 5. The three classified files (+ their cinfo records) are gone; the
        #    clean no-record control survives.
        assert not os.path.exists(abandoned), "abandoned file not reaped"
        assert not os.path.exists(incomplete), "incomplete file not reaped"
        assert not os.path.exists(completed), "completed file not reaped"
        assert not _has_cinfo_record(abandoned), "cinfo record not reaped"
        assert os.path.exists(keepme), "clean no-record file wrongly reaped"

        # 6. /metrics reports exactly one reap per reason.
        reaped = _reaped_by_reason(_scrape(mport))
        assert reaped.get("abandoned") == 1, reaped
        assert reaped.get("incomplete") == 1, reaped
        assert reaped.get("completed") == 1, reaped
    finally:
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text().strip()), 15)
            except (OSError, ValueError):
                pass
            time.sleep(0.5)
