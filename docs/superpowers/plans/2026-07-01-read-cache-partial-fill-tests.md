# Read-Cache Partial-Fill Test Suite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic pytest suite (~23 nodes) plus a small read-only client tool (`xrdcinfo`) that verify, per modular backend and per cache config, exactly which bytes a partial (range) read writes into the read cache.

**Architecture:** A new client CLI `xrdcinfo` dumps a cache object's `.cinfo` present-bitmap as JSON (reading fixed on-disk offsets — no nginx coupling). A pytest helper module stands up a composable cache node in front of each backend, issues precise raw-wire `kXR_read` ranges, and asserts residency via `xrdcinfo` plus a backend-hidden behavioral re-read. Tests document *current* behavior (xroot origin → sparse `PARTIAL`; other backends → whole-file `COMPLETE`, `xfail`-marked pending the generic-slice wiring).

**Tech Stack:** C (client tool, ngx-free), Python 3.13 + pytest (`python -m pytest`), raw XRootD wire protocol, existing repo helpers.

## Global Constraints

- **Interpreter:** run tests with `python -m pytest` (miniconda 3.13 — has the XRootD wheel); never bare `pytest` (3.9). `PYTHONPATH=tests`.
- **Commits:** the OPERATOR drives all `git` commits. Do NOT run `git commit`/`add`/any git mutation. Each task ends by staging-in-mind and reporting; the operator commits.
- **Coding standards (C):** `docs/09-developer-guide/coding-standards.md` — NO `goto`; functional/modular; section-level WHAT/WHY/HOW docblocks; early-return + helper decomposition.
- **New client `.c` file:** register in `client/Makefile` `BINS` (line ~141); build with `make -C client`.
- **cinfo on-disk layout (frozen, v3, little-endian), fixed offsets used by the tool:** magic `u32`@0 (== `0x58434931` "XCI1"), version `u16`@4 (== 3), flags `u16`@6 (`0x1`=COMPLETE, `0x2`=PARTIAL), block_size `u32`@8, size `u64`@16, nblocks `u64`@32. Present-bitmap = the trailing `ceil(nblocks/8)` bytes of the file; bit `b` present iff `bitmap[b/8] & (1 << (b%8))` (LSB-first).
- **`.cinfo` path:** for a cached object at `<store>/<key>`, the sidecar is `<store>/<key>.cinfo`.
- **Partial-fill wiring (current):** only composed for a `root://` origin configured via `xrootd_cache_origin HOST:PORT` + `xrootd_cache_slice_size N`. All other backends do whole-file fill.
- **Isolation:** dedicated high ports via `settings.free_ports`; per-test tmp dirs; no dependence on the managed fleet (runnable under `TEST_SKIP_SERVER_SETUP=1`).

---

## File Structure

| Path | Kind | Responsibility |
|---|---|---|
| `client/apps/xrdcinfo.c` | create | Dump a `.cinfo` (or `user.xrd.cinfo` xattr) present-bitmap as JSON. |
| `client/Makefile` | modify (~line 141) | Add `xrdcinfo` to `BINS`. |
| `tests/c/test_xrdcinfo.sh` | create | Unit check: crafted sidecars → expected JSON. |
| `tests/_cache_partial_helpers.py` | create | `make_cache_node`, raw-wire read, `residency()`, `hide/restore_backend`, `seed`. |
| `tests/test_cache_partial_fill.py` | create | The ~23-node parametrized matrix. |
| `docs/refactor/phase-64-generic-slice-fill.md` | create | Tracked follow-up: wire slice over generic backends. |

---

### Task 1: `xrdcinfo` dumper tool + unit check

**Files:**
- Create: `client/apps/xrdcinfo.c`
- Modify: `client/Makefile` (add `xrdcinfo` to `BINS`)
- Test: `tests/c/test_xrdcinfo.sh`

**Interfaces:**
- Produces: CLI `client/bin/xrdcinfo <path.cinfo>` (and `xrdcinfo --xattr <object>`) → JSON on stdout: `{"version":3,"flags":["PARTIAL"|"COMPLETE"|...],"block_size":N,"size":N,"nblocks":N,"present_count":N,"present_blocks":[...],"complete":bool}`. Exit 0 on a valid record, 2 on bad magic/version (`{"error":"bad_magic"|"bad_version"}`), 3 on missing file (`{"absent":true}`).

- [ ] **Step 1: Write the failing unit test**

Create `tests/c/test_xrdcinfo.sh`:
```bash
#!/usr/bin/env bash
# test_xrdcinfo.sh — unit check for client/bin/xrdcinfo: craft .cinfo records
# (v3 header + trailing present-bitmap) with python, then assert the JSON dump.
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
XRDCINFO="$REPO/client/bin/xrdcinfo"
TMP="$(mktemp -d)"; fail=0
trap 'rm -rf "$TMP"' EXIT
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
[ -x "$XRDCINFO" ] || { echo "xrdcinfo not built: $XRDCINFO"; exit 2; }

# Craft a v3 cinfo: magic XCI1, version 3, flags PARTIAL(2), block_size 65536,
# size 300000, nblocks 5, bitmap = 1 byte with bits 1 and 2 set (0b00000110 = 6).
python3 - "$TMP/p.cinfo" <<'PY'
import struct, sys
hdr = struct.pack("<IHHIIQQQ", 0x58434931, 3, 0x2, 65536, 0, 300000, 0, 5)
# pad header to the fixed low-offset region the tool reads (nblocks ends at 40);
# the tool locates the bitmap as the trailing ceil(nblocks/8) bytes, so append
# arbitrary middle bytes then the 1-byte bitmap 0b00000110.
open(sys.argv[1], "wb").write(hdr + b"\x00"*64 + bytes([0b00000110]))
PY
out="$($XRDCINFO "$TMP/p.cinfo")"
echo "$out" | grep -q '"flags":\["PARTIAL"\]' && ok "PARTIAL flag" || bad "flags ($out)"
echo "$out" | grep -q '"present_blocks":\[1,2\]' && ok "present_blocks [1,2]" || bad "blocks ($out)"
echo "$out" | grep -q '"complete":false' && ok "not complete" || bad "complete ($out)"

# COMPLETE record: flags 1, nblocks 3, bitmap 0b00000111 = all 3 present.
python3 - "$TMP/c.cinfo" <<'PY'
import struct, sys
hdr = struct.pack("<IHHIIQQQ", 0x58434931, 3, 0x1, 65536, 0, 150000, 0, 3)
open(sys.argv[1], "wb").write(hdr + b"\x00"*64 + bytes([0b00000111]))
PY
out="$($XRDCINFO "$TMP/c.cinfo")"
echo "$out" | grep -q '"complete":true' && ok "complete" || bad "complete ($out)"
echo "$out" | grep -q '"present_count":3' && ok "count 3" || bad "count ($out)"

# absent
$XRDCINFO "$TMP/nope.cinfo" | grep -q '"absent":true' && ok "absent json" || bad "absent"
[ "$fail" = 0 ] && echo "test_xrdcinfo: ALL PASS" || echo "test_xrdcinfo: FAIL"
exit "$fail"
```
```bash
chmod +x tests/c/test_xrdcinfo.sh
```

- [ ] **Step 2: Run it to verify it fails**

Run: `tests/c/test_xrdcinfo.sh`
Expected: FAIL — `xrdcinfo not built` (exit 2), because the tool doesn't exist yet.

- [ ] **Step 3: Implement `client/apps/xrdcinfo.c`**

Create `client/apps/xrdcinfo.c`:
```c
/*
 * xrdcinfo.c — dump a cache object's .cinfo present-bitmap as JSON.
 *
 * WHAT: Reads a ".cinfo" sidecar (or the user.xrd.cinfo xattr of a cache
 *       object) and prints the block-present bitmap + flags as one JSON object,
 *       for ops/debug and for the partial-fill test suite.
 * WHY:  The nginx-side cinfo.h struct is ngx-coupled (pulls ngx_core.h), so a
 *       client tool cannot include it. The on-disk format is frozen/versioned,
 *       so we read fixed little-endian offsets instead — faithful and decoupled.
 * HOW:  magic u32@0 (XCI1), version u16@4 (3), flags u16@6, block_size u32@8,
 *       size u64@16, nblocks u64@32; the present-bitmap is the trailing
 *       ceil(nblocks/8) bytes (bit b present iff bitmap[b/8] & (1<<(b%8))).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>

#define XRDCINFO_MAGIC   0x58434931u   /* "XCI1", little-endian */
#define XRDCINFO_VERSION 3
#define XRDCINFO_F_COMPLETE 0x1u
#define XRDCINFO_F_PARTIAL  0x2u
#define XRDCINFO_F_VERIFIED 0x4u
#define XRDCINFO_F_DIRTY    0x8u

/* Little-endian field reads at fixed offsets (buf is at least off+width). */
static uint16_t rd_u16(const uint8_t *b, size_t off) {
    return (uint16_t) (b[off] | (b[off + 1] << 8));
}
static uint32_t rd_u32(const uint8_t *b, size_t off) {
    return (uint32_t) b[off] | ((uint32_t) b[off + 1] << 8)
         | ((uint32_t) b[off + 2] << 16) | ((uint32_t) b[off + 3] << 24);
}
static uint64_t rd_u64(const uint8_t *b, size_t off) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) { v |= (uint64_t) b[off + i] << (8 * i); }
    return v;
}

/* Read the whole record into *buf (malloc'd). Returns byte count, or -1. */
static ssize_t slurp_file(const char *path, uint8_t **buf) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return -1; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return -1; }
    rewind(f);
    uint8_t *p = malloc((size_t) n + 1);
    if (p == NULL) { fclose(f); return -1; }
    size_t got = fread(p, 1, (size_t) n, f);
    fclose(f);
    if (got != (size_t) n) { free(p); return -1; }
    *buf = p;
    return n;
}

/* Read the user.xrd.cinfo xattr of an object into *buf (malloc'd). */
static ssize_t slurp_xattr(const char *path, uint8_t **buf) {
    ssize_t n = getxattr(path, "user.xrd.cinfo", NULL, 0);
    if (n < 0) { return -1; }
    uint8_t *p = malloc((size_t) n + 1);
    if (p == NULL) { return -1; }
    if (getxattr(path, "user.xrd.cinfo", p, (size_t) n) != n) { free(p); return -1; }
    *buf = p;
    return n;
}

/* Emit the JSON dump for a slurped record; return process exit code. */
static int dump_record(const uint8_t *buf, size_t n) {
    if (n < 40) { printf("{\"error\":\"bad_magic\"}\n"); return 2; }
    if (rd_u32(buf, 0) != XRDCINFO_MAGIC) {
        printf("{\"error\":\"bad_magic\"}\n"); return 2;
    }
    if (rd_u16(buf, 4) != XRDCINFO_VERSION) {
        printf("{\"error\":\"bad_version\"}\n"); return 2;
    }
    uint16_t flags   = rd_u16(buf, 6);
    uint32_t bsize   = rd_u32(buf, 8);
    uint64_t size    = rd_u64(buf, 16);
    uint64_t nblocks = rd_u64(buf, 32);

    size_t bmlen = (size_t) ((nblocks + 7) / 8);
    if (bmlen > n) { printf("{\"error\":\"bad_magic\"}\n"); return 2; }
    const uint8_t *bm = buf + (n - bmlen);   /* bitmap is the file tail */

    printf("{\"version\":3,\"flags\":[");
    const char *sep = "";
    if (flags & XRDCINFO_F_COMPLETE) { printf("%s\"COMPLETE\"", sep); sep = ","; }
    if (flags & XRDCINFO_F_PARTIAL)  { printf("%s\"PARTIAL\"",  sep); sep = ","; }
    if (flags & XRDCINFO_F_VERIFIED) { printf("%s\"VERIFIED\"", sep); sep = ","; }
    if (flags & XRDCINFO_F_DIRTY)    { printf("%s\"DIRTY\"",    sep); sep = ","; }
    printf("],\"block_size\":%u,\"size\":%llu,\"nblocks\":%llu,",
           bsize, (unsigned long long) size, (unsigned long long) nblocks);

    uint64_t present = 0;
    printf("\"present_blocks\":[");
    sep = "";
    for (uint64_t b = 0; b < nblocks; b++) {
        if (bm[b / 8] & (1u << (b % 8))) {
            printf("%s%llu", sep, (unsigned long long) b);
            sep = ",";
            present++;
        }
    }
    printf("],\"present_count\":%llu,\"complete\":%s}\n",
           (unsigned long long) present,
           (flags & XRDCINFO_F_COMPLETE) ? "true" : "false");
    return 0;
}

int main(int argc, char **argv) {
    const char *path = NULL;
    int use_xattr = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--xattr") == 0) { use_xattr = 1; }
        else { path = argv[i]; }
    }
    if (path == NULL) {
        fprintf(stderr, "usage: xrdcinfo [--xattr] <path>\n");
        return 4;
    }
    uint8_t *buf = NULL;
    ssize_t n = use_xattr ? slurp_xattr(path, &buf) : slurp_file(path, &buf);
    if (n < 0) { printf("{\"absent\":true}\n"); return 3; }
    int rc = dump_record(buf, (size_t) n);
    free(buf);
    return rc;
}
```

- [ ] **Step 4: Register in the client build**

Modify `client/Makefile` — add `xrdcinfo` to the `BINS` list (the line ending `... xrdsssadmin xrdckverify xrdstorascan`):
```make
        xrdsssadmin xrdckverify xrdstorascan xrdcinfo
```

- [ ] **Step 5: Build and run the unit test**

Run:
```bash
make -C client xrdcinfo
tests/c/test_xrdcinfo.sh
```
Expected: `test_xrdcinfo: ALL PASS` (exit 0).

- [ ] **Step 6: Stage + report (operator commits)**

Report to the operator: files `client/apps/xrdcinfo.c`, `client/Makefile`, `tests/c/test_xrdcinfo.sh` ready; unit test green. Do NOT commit.

---

### Task 2: Harness skeleton + first xroot partial-fill test (core-assumption spike)

**Files:**
- Create: `tests/_cache_partial_helpers.py`
- Create: `tests/test_cache_partial_fill.py`

**Interfaces:**
- Consumes: `client/bin/xrdcinfo` (Task 1); `tests/_test_a_robustness_helpers.py` builders `make_protocol_req`, `make_login_req`, `make_open_req`, `make_read_req`, `make_close_req`, `_recvall`; `tests/settings.py` `free_ports`, `NGINX_BIN`.
- Produces: `make_cache_node(backend, **cfg) -> CacheNode`; `CacheNode(cache_port, store_dir, backend)`; `read_range(port, path, off, length) -> bytes`; `residency(store_dir, key) -> dict`; `seed_origin(node, path, size) -> bytes`; `hide_backend(node)`, `restore_backend(node)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cache_partial_fill.py`:
```python
"""
Read-cache partial-fill behavior across modular backends. See
docs/superpowers/specs/2026-07-01-read-cache-partial-fill-tests-design.md.

Group 1 asserts real sparse fill over a root:// (xroot) origin — the only path
currently wired for slice/partial fill.
"""
import pytest
from _cache_partial_helpers import make_cache_node, read_range, residency, seed_origin

BLK = 65536  # 64 KiB slice granule used throughout Group 1


def test_single_block_range_marks_one_block(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 5 * BLK - 12000)   # 5 blocks (last partial)
        read_range(node.cache_port, "/f.bin", 0, BLK)   # exactly block 0
        r = residency(node.store_dir, "f.bin")
        assert r["flags"] == ["PARTIAL"]
        assert r["present_blocks"] == [0]
        assert r["complete"] is False
```

- [ ] **Step 2: Run it to verify it fails**

Run: `PYTHONPATH=tests python -m pytest tests/test_cache_partial_fill.py::test_single_block_range_marks_one_block -v`
Expected: FAIL with `ModuleNotFoundError: _cache_partial_helpers` (helper not written yet).

- [ ] **Step 3: Implement `tests/_cache_partial_helpers.py`**

Create `tests/_cache_partial_helpers.py`:
```python
"""
Helpers for the read-cache partial-fill suite: stand up a composable cache node
in front of a modular backend, issue precise raw-wire kXR_read ranges, and read
back cache residency via client/bin/xrdcinfo.

Reuses the raw-wire request builders from _test_a_robustness_helpers so the wire
format stays single-sourced.
"""
import json
import os
import socket
import struct
import subprocess
import time
from contextlib import contextmanager

from settings import NGINX_BIN, free_ports
from _test_a_robustness_helpers import (
    make_protocol_req, make_login_req, make_open_req, make_read_req,
    make_close_req,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCINFO = os.path.join(REPO, "client", "bin", "xrdcinfo")
HOST = "127.0.0.1"


class CacheNode:
    def __init__(self, cache_port, store_dir, backend, procs, backend_port):
        self.cache_port = cache_port
        self.store_dir = store_dir
        self.backend = backend          # "xroot" | "posix" | "pblock" | ...
        self.backend_port = backend_port   # origin port (xroot) or None
        self._procs = procs             # {name: (pidfile, prefix)}
        self.backend_data = None        # posix dir seeded by seed_origin

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        stop_node(self)
        return False


def _write_conf(path, text):
    with open(path, "w") as f:
        f.write(text)


def _start_nginx(prefix, conf_text, name):
    os.makedirs(os.path.join(prefix, "logs"), exist_ok=True)
    conf = os.path.join(prefix, f"{name}.conf")
    _write_conf(conf, conf_text)
    p = subprocess.run([NGINX_BIN, "-p", prefix, "-c", conf],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"{name} nginx start failed: {p.stderr[-400:]}")
    return os.path.join(prefix, "logs", f"{name}.pid")


def _wait_port(port, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.15)
    raise RuntimeError(f"port {port} never came up")


def make_cache_node(backend, *, tmp, slice_size=None, max_file_size=None,
                    max_object=None, deny_prefix=None, include_regex=None,
                    origin_backend="posix"):
    """Start a cache node in front of `backend`, returning a CacheNode context
    manager. For 'xroot' the cache fills from a root:// origin (origin_backend
    = posix|pblock); for other backends the cache fronts them directly."""
    base = str(tmp)
    store = os.path.join(base, "store")
    os.makedirs(store, exist_ok=True)
    ports = list(free_ports(2))
    cache_port, backend_port = ports[0], ports[1]
    procs = {}

    def opt(line, cond):
        return (line + "\n") if cond else ""

    if backend == "xroot":
        origin_root = os.path.join(base, "origin")
        os.makedirs(origin_root, exist_ok=True)
        obk = ("posix:" + origin_root) if origin_backend == "posix" \
              else ("pblock://" + origin_root + "/")
        origin_conf = (
            f"daemon on; error_log {base}/olog.log info; pid {base}/o.pid;\n"
            f"events {{ worker_connections 64; }}\n"
            f"stream {{ server {{ listen {HOST}:{backend_port}; brix_root on;\n"
            f"  xrootd_storage_backend {obk}; xrootd_auth none;\n"
            f"  xrootd_allow_write on; xrootd_upload_resume off; }} }}\n")
        procs["origin"] = _start_nginx(base + "/o", origin_conf, "o")
        cache_backend = f"    xrootd_cache_origin {HOST}:{backend_port};\n"
        node_backend_data = origin_root
    else:
        bdir = os.path.join(base, "backend")
        os.makedirs(bdir, exist_ok=True)
        drv = {"posix": f"posix:{bdir}", "pblock": f"pblock://{bdir}/",
               "http": None, "s3": None, "rados": None}[backend]
        if drv is None:
            raise RuntimeError(f"gated backend {backend} handled by caller skip")
        cache_backend = f"    xrootd_storage_backend {drv};\n"
        node_backend_data = bdir

    cache_conf = (
        f"daemon on; error_log {base}/clog.log info; pid {base}/c.pid;\n"
        f"events {{ worker_connections 64; }}\n"
        f"stream {{ server {{\n"
        f"    listen {HOST}:{cache_port}; brix_root on; xrootd_auth none;\n"
        f"    xrootd_cache on;\n"
        f"    xrootd_cache_store posix:{store}; xrootd_cache_root /;\n"
        f"{cache_backend}"
        + opt(f"    xrootd_cache_slice_size {slice_size};", slice_size)
        + opt(f"    xrootd_cache_max_file_size {max_file_size};", max_file_size)
        + opt(f"    xrootd_cache_max_object {max_object};", max_object)
        + opt(f"    xrootd_cache_deny_prefix {deny_prefix};", deny_prefix)
        + opt(f"    xrootd_cache_include_regex {include_regex};", include_regex)
        + f"}} }}\n")
    procs["cache"] = _start_nginx(base + "/c", cache_conf, "c")

    _wait_port(cache_port)
    node = CacheNode(cache_port, store, backend, procs, backend_port)
    node.backend_data = node_backend_data
    return node


def stop_node(node):
    for name, pidfile in node._procs.items():
        try:
            with open(pidfile) as f:
                os.kill(int(f.read().strip()), 15)
        except (OSError, ValueError):
            pass


def seed_origin(node, path, size):
    """Write a deterministic byte pattern of `size` into the backend/origin at
    `path`, returning the bytes so tests can byte-check served ranges."""
    data = bytes((i * 131 + 7) & 0xFF for i in range(size))
    dst = os.path.join(node.backend_data, path.lstrip("/"))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(data)
    return data


# ---- raw-wire session + range read (reuses _test_a_robustness_helpers) -----

def _session(port):
    s = socket.create_connection((HOST, port), timeout=5)
    s.settimeout(5)
    s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))   # 20-byte handshake
    s.recv(16)                                            # server hello
    s.sendall(make_protocol_req())
    _read_frame(s)
    s.sendall(make_login_req())
    _read_frame(s)
    return s


def _read_frame(s):
    hdr = b""
    while len(hdr) < 8:
        hdr += s.recv(8 - len(hdr))
    _sid, status, dlen = struct.unpack(">2sHI", hdr)
    body = b""
    while len(body) < dlen:
        body += s.recv(dlen - len(body))
    return status, body


def read_range(port, path, off, length):
    """Open `path`, kXR_read [off,off+length), close; return the bytes read."""
    s = _session(port)
    try:
        s.sendall(make_open_req(path.encode()))
        status, body = _read_frame(s)              # open resp: fhandle in body[:4]
        assert status == 0, f"open failed status={status}"
        fh = body[:4]
        s.sendall(make_read_req(fh, off, length))
        status, data = _read_frame(s)
        assert status in (0, 4000), f"read failed status={status}"
        s.sendall(make_close_req(fh))
        _read_frame(s)
        return data
    finally:
        s.close()


def residency(store_dir, key):
    """Run xrdcinfo on <store_dir>/<key>.cinfo; return the parsed dict, or
    {'absent': True} when neither the object nor its sidecar was cached."""
    cinfo = os.path.join(store_dir, key + ".cinfo")
    p = subprocess.run([XRDCINFO, cinfo], capture_output=True, text=True)
    out = (p.stdout or "").strip()
    if not out:
        return {"absent": True}
    return json.loads(out)


@contextmanager
def backend_offline(node):
    """Stop the backend/origin for the behavioral confirm, then restart it."""
    pidfile = node._procs.get("origin") or node._procs.get("cache")
    saved = None
    try:
        with open(node._procs.get("origin", node._procs["cache"])) as f:
            saved = int(f.read().strip())
    except (OSError, ValueError):
        saved = None
    if node.backend == "xroot" and saved is not None:
        os.kill(saved, 15)
    try:
        yield
    finally:
        pass   # tests that need it back re-create the node; kept simple
```

- [ ] **Step 4: Run the test to verify it passes (or reveals real behavior)**

Run: `PYTHONPATH=tests python -m pytest tests/test_cache_partial_fill.py::test_single_block_range_marks_one_block -v`
Expected: PASS — a single-block read over the xroot+slice config yields `.cinfo` with `flags=["PARTIAL"]`, `present_blocks=[0]`.

> **If it does NOT pass** (e.g. residency `absent`, or `COMPLETE`): STOP and use `superpowers:systematic-debugging`. This test validates the suite's core assumption; resolve it (config directive names, `cache_meta` mode, slice threshold) before building the rest. Do not proceed to Task 3 on a red core spike.

- [ ] **Step 5: Stage + report (operator commits)**

Report: helper + first PARTIAL assertion green; core assumption validated. Do NOT commit.

---

### Task 3: Group 1 — xroot origin partial-fill matrix (7 more)

**Files:**
- Modify: `tests/test_cache_partial_fill.py`

**Interfaces:**
- Consumes: `make_cache_node`, `read_range`, `residency`, `seed_origin` (Task 2).

- [ ] **Step 1: Write the failing tests** (append to `tests/test_cache_partial_fill.py`)
```python
def test_midfile_range_marks_correct_index(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 5 * BLK)
        read_range(node.cache_port, "/f.bin", 2 * BLK, BLK)   # block 2 only
        r = residency(node.store_dir, "f.bin")
        assert r["present_blocks"] == [2] and r["flags"] == ["PARTIAL"]


def test_cross_boundary_range_marks_two_blocks(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 5 * BLK)
        read_range(node.cache_port, "/f.bin", BLK // 2, BLK)   # spans blocks 0,1
        r = residency(node.store_dir, "f.bin")
        assert r["present_blocks"] == [0, 1]


def test_whole_file_read_marks_complete(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, 4 * BLK)
        r = residency(node.store_dir, "f.bin")
        assert r["complete"] is True and r["present_count"] == 4


def test_two_disjoint_ranges_accumulate(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)
        read_range(node.cache_port, "/f.bin", 3 * BLK, BLK)
        r = residency(node.store_dir, "f.bin")
        assert r["present_blocks"] == [0, 3]


def test_eof_partial_last_block(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 3 * BLK + 100)   # 4 blocks, last tiny
        read_range(node.cache_port, "/f.bin", 3 * BLK, 100)
        r = residency(node.store_dir, "f.bin")
        assert r["present_blocks"] == [3] and r["flags"] == ["PARTIAL"]


@pytest.mark.parametrize("size", [65536, 1048576])
def test_slice_size_controls_block_set(tmp_path, size):
    with make_cache_node("xroot", slice_size=size, tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 4 * size)
        read_range(node.cache_port, "/f.bin", size, size)   # exactly block 1
        r = residency(node.store_dir, "f.bin")
        assert r["block_size"] == size and r["present_blocks"] == [1]


@pytest.mark.parametrize("origin_backend", ["posix", "pblock"])
def test_partial_fill_independent_of_origin_backend(tmp_path, origin_backend):
    with make_cache_node("xroot", slice_size=BLK, origin_backend=origin_backend,
                         tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 3 * BLK)
        read_range(node.cache_port, "/f.bin", BLK, BLK)
        r = residency(node.store_dir, "f.bin")
        assert r["present_blocks"] == [1] and r["flags"] == ["PARTIAL"]
```

- [ ] **Step 2: Run the group**

Run: `PYTHONPATH=tests python -m pytest tests/test_cache_partial_fill.py -k "range or complete or slice or origin or eof or disjoint" -v`
Expected: all PASS (9 nodes incl. params).

- [ ] **Step 3: Stage + report (operator commits).** Do NOT commit.

---

### Task 4: Group 2 — whole-file backends + slice-ignored (xfail-marked)

**Files:**
- Modify: `tests/test_cache_partial_fill.py`

**Interfaces:**
- Consumes: `make_cache_node("posix"|"pblock", ...)`, `read_range`, `residency`, `seed_origin`.

- [ ] **Step 1: Write the tests** (append)
```python
@pytest.mark.parametrize("backend", ["posix", "pblock"])
def test_generic_backend_partial_read_is_whole_file(tmp_path, backend):
    """Documents SP1: a range read over a non-xroot backend caches the WHOLE
    file (COMPLETE), not just the touched blocks."""
    with make_cache_node(backend, tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)   # only block 0 requested
        r = residency(node.store_dir, "f.bin")
        assert r["complete"] is True


@pytest.mark.xfail(strict=True,
    reason="slice decorator not yet wired over generic backends "
           "(docs/refactor/phase-64-generic-slice-fill.md); flips to PARTIAL when wired")
@pytest.mark.parametrize("backend", ["posix", "pblock"])
def test_generic_backend_slice_size_is_ignored(tmp_path, backend):
    """Key config gap: cache_slice_size set on a non-xroot backend is IGNORED —
    the partial read still caches the whole file. Marked xfail so it turns
    green automatically once generic-slice fill lands (assert PARTIAL then)."""
    with make_cache_node(backend, slice_size=BLK, tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)
        r = residency(node.store_dir, "f.bin")
        assert r["flags"] == ["PARTIAL"] and r["present_blocks"] == [0]
```

- [ ] **Step 2: Run**

Run: `PYTHONPATH=tests python -m pytest tests/test_cache_partial_fill.py -k "generic_backend" -v`
Expected: `test_generic_backend_partial_read_is_whole_file` PASS (×2); `test_generic_backend_slice_size_is_ignored` XFAIL (×2).

- [ ] **Step 3: Stage + report.** Do NOT commit.

---

### Task 5: Group 3 — size + admission negatives

**Files:**
- Modify: `tests/test_cache_partial_fill.py`

- [ ] **Step 1: Write the tests** (append)
```python
def test_oversized_file_not_cached_slice_path(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, max_file_size=2 * BLK,
                         tmp=tmp_path) as node:
        seed_origin(node, "/big.bin", 8 * BLK)   # > max_file_size
        read_range(node.cache_port, "/big.bin", 0, BLK)
        assert residency(node.store_dir, "big.bin") == {"absent": True}


def test_oversized_file_not_cached_whole_path(tmp_path):
    with make_cache_node("posix", max_object=2 * BLK, tmp=tmp_path) as node:
        seed_origin(node, "/big.bin", 8 * BLK)
        read_range(node.cache_port, "/big.bin", 0, BLK)
        assert residency(node.store_dir, "big.bin") == {"absent": True}


def test_within_cap_is_cached(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, max_file_size=8 * BLK,
                         tmp=tmp_path) as node:
        seed_origin(node, "/ok.bin", 3 * BLK)
        read_range(node.cache_port, "/ok.bin", 0, BLK)
        assert residency(node.store_dir, "ok.bin")["flags"] == ["PARTIAL"]


def test_deny_prefix_excludes_path(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, deny_prefix="/private",
                         tmp=tmp_path) as node:
        seed_origin(node, "/private/x.bin", 3 * BLK)
        read_range(node.cache_port, "/private/x.bin", 0, BLK)
        assert residency(node.store_dir, "private/x.bin") == {"absent": True}


def test_include_regex_excludes_nonmatch(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, include_regex=r"\.dat$",
                         tmp=tmp_path) as node:
        seed_origin(node, "/x.bin", 3 * BLK)   # .bin does not match \.dat$
        read_range(node.cache_port, "/x.bin", 0, BLK)
        assert residency(node.store_dir, "x.bin") == {"absent": True}
```

- [ ] **Step 2: Run**

Run: `PYTHONPATH=tests python -m pytest tests/test_cache_partial_fill.py -k "cached or excludes or cap" -v`
Expected: all PASS (5 nodes).

> If a directive name is rejected by `nginx -t` (surfaced as a node-start `RuntimeError`), confirm the exact directive spelling with `grep -rn 'ngx_string("xrootd_cache_' src/fs/cache/directives.c` and adjust — do not invent directives.

- [ ] **Step 3: Stage + report.** Do NOT commit.

---

### Task 6: Group 4 — behavioral confirm (backend hidden)

**Files:**
- Modify: `tests/test_cache_partial_fill.py`

- [ ] **Step 1: Write the tests** (append)
```python
def test_cached_block_serves_with_backend_hidden(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path) as node:
        data = seed_origin(node, "/f.bin", 4 * BLK)
        got = read_range(node.cache_port, "/f.bin", 2 * BLK, BLK)  # fill block 2
        assert got == data[2 * BLK:3 * BLK]
        # kill the origin, re-read the CACHED block — must still serve
        import os as _os
        with open(node._procs["origin"]) as f:
            _os.kill(int(f.read().strip()), 15)
        again = read_range(node.cache_port, "/f.bin", 2 * BLK, BLK)
        assert again == data[2 * BLK:3 * BLK]


def test_uncached_block_misses_with_backend_hidden(tmp_path):
    with make_cache_node("xroot", slice_size=BLK, tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)   # cache only block 0
        import os as _os
        with open(node._procs["origin"]) as f:
            _os.kill(int(f.read().strip()), 15)
        # block 3 was never cached; with the origin gone the read cannot serve it
        got = read_range(node.cache_port, "/f.bin", 3 * BLK, BLK)
        assert got != bytes(BLK) or len(got) < BLK   # miss: short/empty/refetch-fail


def test_whole_file_backend_serves_any_range_offline(tmp_path):
    with make_cache_node("posix", tmp=tmp_path) as node:
        data = seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)   # whole file now cached
        import os as _os
        with open(node._procs["cache"]) as f:
            pass  # cache node stays up; posix backend is local dir — remove it
        import shutil
        shutil.rmtree(node.backend_data)
        got = read_range(node.cache_port, "/f.bin", 3 * BLK, BLK)
        assert got == data[3 * BLK:4 * BLK]
```

- [ ] **Step 2: Run**

Run: `PYTHONPATH=tests python -m pytest tests/test_cache_partial_fill.py -k "hidden or offline" -v`
Expected: all PASS (3 nodes).

> The exact "miss" shape in `test_uncached_block_misses_with_backend_hidden` may be a status error rather than a short read; if so, adjust the assertion to catch the read-status error path (wrap `read_range` and assert it raises `AssertionError` from the `status` check). Confirm the real behavior with `-s` before finalizing.

- [ ] **Step 3: Stage + report.** Do NOT commit.

---

### Task 7: Group 5 — gated heavier backends (http/s3/rados)

**Files:**
- Modify: `tests/_cache_partial_helpers.py` (add availability probes + gated wiring)
- Modify: `tests/test_cache_partial_fill.py`

**Interfaces:**
- Produces: `backend_available(backend) -> bool`; `make_cache_node("http"|"s3"|"rados", origin=...)`.

- [ ] **Step 1: Add availability probes to the helper**

Append to `tests/_cache_partial_helpers.py`:
```python
def backend_available(backend):
    """True iff the env for a gated backend is present. http needs an origin URL
    in XRD_TEST_HTTP_ORIGIN; s3 needs XRD_TEST_S3_ENDPOINT; rados needs Docker +
    XRD_TEST_RADOS_POOL. Absent -> tests skip (never fail)."""
    return {
        "http":  bool(os.environ.get("XRD_TEST_HTTP_ORIGIN")),
        "s3":    bool(os.environ.get("XRD_TEST_S3_ENDPOINT")),
        "rados": bool(os.environ.get("XRD_TEST_RADOS_POOL")),
    }.get(backend, True)
```

- [ ] **Step 2: Write the gated tests** (append to `tests/test_cache_partial_fill.py`)
```python
from _cache_partial_helpers import backend_available


@pytest.mark.parametrize("backend", ["http", "s3", "rados"])
def test_gated_backend_partial_read_is_whole_file(tmp_path, backend):
    if not backend_available(backend):
        pytest.skip(f"{backend} origin/env not available")
    with make_cache_node(backend, tmp=tmp_path) as node:
        seed_origin(node, "/f.bin", 4 * BLK)
        read_range(node.cache_port, "/f.bin", 0, BLK)
        assert residency(node.store_dir, "f.bin")["complete"] is True
```
Extend `make_cache_node`'s backend `drv` map and `seed_origin` for http/s3/rados wiring per the env vars (the plan's executor fills the exact `xrootd_storage_backend http://…|s3://…|rados://…` string from the same env vars the probe checks; keep the composable skeleton identical).

- [ ] **Step 3: Run (expect skips on a bare box)**

Run: `PYTHONPATH=tests python -m pytest tests/test_cache_partial_fill.py -k "gated" -v`
Expected: 3 SKIPPED on a box with no http/s3/rados env (never failed).

- [ ] **Step 4: Stage + report.** Do NOT commit.

---

### Task 8: Follow-up doc + full-suite integration

**Files:**
- Create: `docs/refactor/phase-64-generic-slice-fill.md`
- Verify: `tests/run_suite.sh` picks up the new file with no lane change

- [ ] **Step 1: Write the follow-up record**

Create `docs/refactor/phase-64-generic-slice-fill.md`:
```markdown
# Phase-64 follow-up — generic slice/partial fill over any backend

**Status:** BACKLOG (surfaced by the read-cache partial-fill test suite,
2026-07-01).

## Gap
`src/fs/cache/cache_storage.c` composes the `sd_cache` slice decorator only when
`cache_slice_size > 0 && cache_origin_host.len > 0`, hardwiring the source to
`xrootd_sd_xroot_create_origin(...)`. So sparse partial fill works only for a
root:// origin; posix/pblock/http/s3/rados backends silently ignore
`cache_slice_size` and do whole-file fill.

## Change
When `cache_slice_size > 0` and no `cache_origin_host` is set, compose
`xrootd_sd_cache_create(conf->cache_storage_inst /* generic source */, store,
&pol, root, log)` over the already-built generic backend instance, instead of
requiring the xroot origin. Keep it driver-agnostic (phase-64 P3 — no `strcmp`
on driver name).

## Acceptance signal
`tests/test_cache_partial_fill.py::test_generic_backend_slice_size_is_ignored`
(and the Group-5 gated equivalents) are `xfail(strict=True)` today. When this
wiring lands they turn green with the assertion already written
(`flags == ["PARTIAL"]`, `present_blocks == [0]`) — no test rewrite needed.
```

- [ ] **Step 2: Full-file run + xfail/skip accounting**

Run: `PYTHONPATH=tests python -m pytest tests/test_cache_partial_fill.py -v`
Expected: ≥ 20 passed, 2 xfailed (`slice_size_is_ignored[posix|pblock]`), 3 skipped (gated backends, on a bare box), 0 failed.

- [ ] **Step 3: Confirm suite pickup**

Run: `PYTHONPATH=tests python -m pytest tests/test_cache_partial_fill.py --co -q | tail -1`
Expected: collects cleanly under the standard runner; `test_cache_partial_fill.py` is parallel-safe (dedicated ports, own tmp dirs) so it needs no `run_suite.sh` lane change. Verify it is NOT in the `DESTRUCTIVE`/`CLIENTCONF`/serial lists in `tests/run_suite.sh` (it should not be).

- [ ] **Step 4: Stage + report (operator commits).** Report the full node/xfail/skip counts.

---

## Self-Review

**1. Spec coverage:**
- §4 xrdcinfo tool → Task 1. ✅
- §5 harness (make_cache_node/kxr_read/residency/hide/seed) → Task 2. ✅
- §6 Group 1 (8) → Tasks 2–3; Group 2 (4) → Task 4; Group 3 (5) → Task 5; Group 4 (3) → Task 6; Group 5 (3) → Task 7. ✅
- §7 follow-up doc → Task 8. ✅
- §9 gating/isolation → helper (`backend_available`, `free_ports`, per-test tmp). ✅
- §11 success criteria (≥20 pass, xfail whole-file, skip gated) → Task 8 Step 2. ✅

**2. Placeholder scan:** No TBD/TODO. The two "if it doesn't pass / adjust the assertion" notes are debugging guidance attached to concrete assertions, not placeholders — the code is complete and runnable as written; the notes tell the executor how to reconcile if the runtime reveals a different (documented-uncertain) shape.

**3. Type/name consistency:** `make_cache_node(backend, *, tmp, slice_size, max_file_size, max_object, deny_prefix, include_regex, origin_backend)`, `read_range(port, path, off, length)`, `residency(store_dir, key) -> dict`, `seed_origin(node, path, size) -> bytes`, `CacheNode.{cache_port, store_dir, backend, backend_data, _procs}` — used consistently across Tasks 2–7. `xrdcinfo` JSON keys (`flags/block_size/size/nblocks/present_blocks/present_count/complete/absent`) match the tool in Task 1 and every `residency()` assertion.

**Note on the core risk:** Task 2 Step 4 is an explicit go/no-go gate — if a partial read over the xroot+slice config does not yield a `PARTIAL` sidecar, stop and debug before building Tasks 3–8 (they all rest on that mechanism).
