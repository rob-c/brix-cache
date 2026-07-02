# Reproducing the performance benchmarks

The exact steps behind the numbers in the README table. All tests run locally on the same machine — no network — to isolate protocol and scheduling overhead from bandwidth limits. Reproduce them to validate your own build.

---

## Hardware and software

The numbers in the README were produced on:

- Linux 6.18 (WSL2-RT) on commodity x86-64 hardware
- nginx 1.28.3 built with `--with-stream --with-stream_ssl_module --with-http_ssl_module --with-threads`
- xrootd v5.9.2 from system packages
- All I/O to `/tmp` (tmpfs / page cache — disk not the bottleneck)
- `--read-sink devnull` for `root://` tests (avoids writing 128 × 1 GiB to disk)
- `--read-sink tempfile` for WebDAV tests (curl writes to a temp file by default)

---

## Prerequisites

### System packages

**RHEL 9 / AlmaLinux 9:**
```bash
sudo dnf install -y gcc make pcre2-devel zlib-devel openssl-devel \
    xrootd-client xrootd-server voms-libs curl \
    python3 python3-pip nc
```

**Ubuntu 22.04+ / Debian 12+:**
```bash
sudo apt install -y build-essential libpcre2-dev zlib1g-dev libssl-dev \
    xrootd-client xrootd-server libvomsapi1 curl \
    python3 python3-pip python3-venv netcat-openbsd
```

### Python virtual environment

```bash
cd /path/to/nginx-xrootd
python3 -m venv .venv
source .venv/bin/activate
pip install pytest xrootd pytest-timeout cryptography requests urllib3
```

---

## Step 1 — Clean build

```bash
cd /tmp
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz
cd nginx-1.28.3

# Remove any prior build artifacts
make clean 2>/dev/null || true

./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-threads \
    --add-module=/path/to/nginx-xrootd

make -j$(nproc)
```

Verify the module compiled in:

```bash
/tmp/nginx-1.28.3/objs/nginx -V 2>&1 | grep add-module
# Expected: add-module=/path/to/nginx-xrootd
```

---

## Step 2 — Test PKI and token signing authority

The benchmark uses the same PKI layout as the integration test suite. If you have already run `tests/manage_test_servers.sh start` at least once, the PKI at `/tmp/xrd-test/pki/` is ready and you can skip to Step 3.

Otherwise, follow [docs/test-pki.md](../06-authentication/test-pki-setup.md) to generate the CA, server certificate, and user proxy certificate, then:

```bash
# Token signing authority (needed for WebDAV+Bearer tests)
source .venv/bin/activate
python3 utils/make_token.py init /tmp/xrd-test/tokens
```

Minimum files required before running the load tests:

```
/tmp/xrd-test/pki/ca/ca.pem
/tmp/xrd-test/pki/server/hostcert.pem
/tmp/xrd-test/pki/server/hostkey.pem
/tmp/xrd-test/pki/user/proxy_std.pem
/tmp/xrd-test/tokens/jwks.json
/tmp/xrd-test/tokens/signing_key.pem
```

---

## Step 3 — Generate load-test data files

The `load_1g.bin` file is the default benchmark payload. Generate it once:

```bash
mkdir -p /tmp/xrd-test/data
# 1 GiB — primary benchmark file
dd if=/dev/urandom of=/tmp/xrd-test/data/load_1g.bin bs=4M count=256 status=progress

# 100 MiB — optional quick sweep
dd if=/dev/urandom of=/tmp/xrd-test/data/load_100m.bin bs=4M count=25 status=progress
```

Both files must be under `/tmp/xrd-test/data/`. The xrootd perf config symlinks this directory into its namespace, so both servers serve identical content.

---

## Step 4 — Run the benchmark

`tests/run_load_test.sh` starts servers, runs `load_test.py`, and stops servers on exit. The script accepts an optional target (`nginx`, `xrootd`, or `both`) and forwards remaining flags to `load_test.py`.

### root:// + GSI — gnuBall vs xrootd native

This is the primary comparison in the README table:

```bash
source .venv/bin/activate

bash tests/run_load_test.sh both \
    --file load_1g.bin \
    --concurrency 1,8,32,128 \
    --suite root-gsi \
    --read-sink devnull \
    --json /tmp/bench_gsi.json
```

`--read-sink devnull` discards downloaded bytes to `/dev/null` so you do not need 128 GiB of free disk space for the 128-worker run. Throughput numbers are identical to writing to a temp file because the bottleneck is protocol/CPU, not disk.

### WebDAV davs:// + x509 — gnuBall vs xrootd XrdHttp

xrootd native serves HTTPS/WebDAV via the `XrdHttp` plugin (`libXrdHttp-5.so`), configured in `tests/xrootd.perf.conf` on port 12443. Client x509 proxy certificates are authenticated by the `libXrdHttpVOMS-5.so` extractor, which maps the TLS client-cert DN through the same authdb that the `root://` protocol uses.

```bash
source .venv/bin/activate

bash tests/run_load_test.sh both \
    --file load_1g.bin \
    --concurrency 1,8,32,128 \
    --suite webdav-gsi \
    --json /tmp/bench_webdav.json
```

---

## Step 5 — Interpret the output

`load_test.py` prints a line per concurrency level:

```
n=32    ok=32/32  agg=9376 MiB/s  (9.16 GiB/s)  p50=3.1s  p95=3.4s  p99=3.4s  per-conn=342 MiB/s
```

| Field | Meaning |
|---|---|
| `n` | Number of parallel workers (simultaneous xrdcp / curl processes) |
| `ok` | Successful transfers / total |
| `agg` | Aggregate throughput: total bytes ÷ wall-clock time across all workers |
| `p50 / p95 / p99` | Transfer time percentiles across all workers |
| `per-conn` | Average per-connection throughput (total bytes ÷ workers ÷ mean elapsed) |

When `--target both` is used, a side-by-side comparison table is printed at the end and JSON results are saved to `*_nginx.json` and `*_xrootd.json`.

---

## Configuration details

### nginx perf config (`tests/nginx.perf.conf`)

Key differences from the development config that matter for throughput:

| Setting | Dev | Perf | Why |
|---|---|---|---|
| `worker_processes` | 1 | `auto` | Uses all CPU cores |
| `worker_connections` | 64 | 4096 | Handles 128+ simultaneous transfers |
| `thread_pool threads` | 4 | 32 | More async I/O threads for parallel reads |
| `reuseport` | off | on | Spreads `accept()` across worker processes |
| `error_log` level | `info` | `warn` | Eliminates log I/O as a bottleneck |
| `ssl_session_cache` | off | `shared:SSL:50m` | Amortises TLS handshakes across workers |

WebDAV syscall notes for large transfers:

- Downloads over `davs://` use `ssl_buffer_size 1m`, which reduces the number of `SSL_write()` calls nginx makes while streaming large HTTPS responses.
- Uploads that nginx has already spooled to `client_body_temp_path` now take a kernel-side fast path (`copy_file_range()` on Linux when available) from the temp file into the destination file. When that fast path is unavailable, the fallback copy buffer is 1 MiB rather than the older 64 KiB loop, which still cuts `pread()` / `write()` call volume sharply for 1 GiB uploads.

For the broader list of code-level fast paths behind these numbers, see
[optimizations.md](../09-developer-guide/optimizations.md).

### xrootd perf config (`tests/xrootd.perf.conf`)

One xrootd instance serves two protocols from the same `/tmp/xrd-test/data` tree:

| Port | Protocol | Auth |
|---|---|---|
| 12094 | `root://` native XRootD | GSI (`sec.protocol gsi`) |
| 12443 | HTTPS/WebDAV (`XrdHttp`) | x509 client cert via `libXrdHttpVOMS-5.so` |

Thread limits are set generously (`maxt 256`) to match the maximum concurrency tested. `XrdHttp` uses the same thread-per-connection model as the native protocol, so both ports are subject to the same concurrency ceiling.

---

## Extending the sweep

```bash
# Higher concurrency sweep (no disk writes)
bash tests/run_load_test.sh both \
    --file load_1g.bin \
    --concurrency 1,8,32,64,128,200,500 \
    --suite root-gsi \
    --read-sink devnull \
    --json /tmp/bench_extended.json

# Smaller file, read + write
bash tests/run_load_test.sh nginx \
    --file load_100m.bin \
    --concurrency 1,8,32,128 \
    --mode both \
    --json /tmp/bench_rw.json
```

## Notes

- All tests run on `localhost` — measured throughput reflects protocol and scheduling overhead, not physical bandwidth.
- xrootd uses one thread per connection; its aggregate throughput degrades at high concurrency as thread scheduling becomes the bottleneck. nginx uses an event-driven worker model and maintains throughput as connections scale.
- Single-connection throughput is higher for native xrootd because the `root://` binary protocol has less per-request framing overhead than HTTP/TLS (WebDAV) or the GSI handshake layered on top of XRootD.
- Re-run the sweep several times and take the median if your machine has background load; the `--json` output includes all per-run stats for post-processing.

## HTTPS throughput tuning — kernel TLS (kTLS / `SSL_sendfile`)

A WebDAV/S3 **GET** response body is served as a file-backed buffer through
nginx's output filter. On a **cleartext** connection nginx uses `sendfile(2)`
(zero-copy, page-cache → socket) — this is why cleartext S3 is the fastest path.
On a **TLS** connection the bytes must be encrypted, which historically forces
`read()` into userspace → OpenSSL encrypt → `write()`. **Kernel TLS** removes that
copy: nginx calls `SSL_sendfile()` and the kernel encrypts the file pages in place.

Enable it (Phase 32 WS1 — already set in `tests/configs/nginx_shared.conf` and
`tests/nginx.perf.conf`):

```nginx
http {
    sendfile   on;          # required for SSL_sendfile
    tcp_nopush on;
}
server {                    # each davs:// / HTTPS-S3 server block
    listen 8443 ssl;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:!aNULL;  # kTLS needs AES-GCM
    ssl_conf_command Options KTLS;   # turn on kernel TLS for this SSL context
    ssl_buffer_size  64k;            # bigger TLS records on the non-kTLS fallback
}
```

Prerequisites: Linux ≥ 4.13 with the TLS ULP (`modprobe tls`), OpenSSL ≥ 3.0
built with kTLS, and an **AES-GCM** cipher negotiated. If any is missing nginx
**falls back automatically** to `read()`+`SSL_write()` — safe to ship on.

Verify it is active:

```bash
# Per-connection kTLS socket creation: TlsTxSw (software) / TlsTxDevice (NIC offload)
# increment once per TLS connection that uses kernel TLS.
cat /proc/net/tls_stat            # before
for i in $(seq 5); do curl -sk -o /dev/null https://localhost:8443/file.bin; done
cat /proc/net/tls_stat            # TlsTxSw should be +5

# Confirm the body goes out via sendfile, not write():
strace -f -e trace=sendfile,write -p <worker-pid>   # expect sendfile on the GET
```

**Software vs hardware kTLS:** `TlsTxDevice` counts NIC-offloaded crypto; `TlsTxSw`
counts kernel software crypto. Software kTLS still eliminates the userspace data
copy (the `SSL_sendfile` win) but performs AES in the kernel, so the gain is
moderate. On a NIC with TLS offload (`ethtool -k <dev> | grep tls`), `TlsTxDevice`
engages and encryption moves off the CPU entirely — the largest HTTPS win.

## Throughput tuning bundle (Phase 32 WS5)

Applied in `tests/nginx.perf.conf` (the benchmark config) and the shared test
template `tests/configs/nginx_shared.conf`:

```nginx
http {
    sendfile        on;       # kernel zero-copy (cleartext) / SSL_sendfile (kTLS)
    tcp_nopush      on;       # coalesce response header + first data segment
    output_buffers  2 256k;   # larger file-read chunks → fewer pread/sendfile calls
    # ssl_buffer_size 64k;    # per TLS server block — fewer TLS records (non-kTLS path)
}
# top level:
thread_pool default threads=<≈ num cores> max_queue=131072;   # perf.conf uses 64
```

Sizing notes:
- **`thread_pool threads`** — every cold (page-cache-miss) `kXR_read`/`pgread`/
  `pgwrite`/cache-fill posts here. Under-sizing it (the functional test default is
  `threads=4`) serialises cold I/O under concurrency. Set to ≈ the core count; the
  benchmark config uses 64 across `worker_processes auto`.
- **`output_buffers`** — `2 256k` lets a large GET read the file in 256 KiB chunks
  instead of the 32 KiB default, cutting syscall count on bulk transfers.

### `directio` — situational, NOT a default

`directio <size>` makes nginx serve files above `<size>` with `O_DIRECT`, bypassing
the page cache — useful to stop a few huge, read-once files from evicting the
working set. **Do not enable it globally:** `O_DIRECT` defeats the Phase-32 WS4
warm-cache fast path (`preadv2(RWF_NOWAIT)`), which relies on data being resident in
the page cache, and it disables `sendfile`. Use it only on locations that serve
large files with no re-read locality (e.g. a dedicated archive/staging mount), and
measure both ways.

### Per-read fixed cost (remaining WS5 follow-ups, not yet implemented)

- **Access-log batching:** the `root://` read path writes the access log
  synchronously per read (`src/protocols/root/read/read.c`); a per-worker buffered/coalesced log
  writer would remove that fixed cost when logging is enabled. Tracked, not done.
- **WebDAV per-request cuts:** reuse the dup'd send-fd across Range requests on a
  keepalive connection, cache the resolved path per connection, short-circuit
  re-auth, and early-return CORS when there is no `Origin`. Tracked, not done.
