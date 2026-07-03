# Building from scratch

Every dependency, every compile flag, and the full test-harness setup — on one page. If you hit a build error, the troubleshooting section at the bottom has seen it before.

---

## 1. System prerequisites

**RHEL 9 / AlmaLinux 9 / Rocky 9:**

```bash
sudo dnf install -y gcc make pcre2-devel zlib-devel openssl-devel \
    xrootd-client xrootd-server \
    voms-libs curl \
    python3 python3-pip
```

**Ubuntu 22.04+ / Debian 12+:**

```bash
sudo apt install -y build-essential libpcre2-dev zlib1g-dev libssl-dev \
    xrootd-client xrootd-server \
    libvomsapi1 curl \
    python3 python3-pip python3-venv
```

Key packages and why they are needed:

| Package | Purpose |
|---|---|
| `gcc`, `make` | C compiler and build system |
| `pcre2-devel` / `libpcre2-dev` | Regular expressions (nginx core) |
| `zlib-devel` / `zlib1g-dev` | gzip compression (nginx core) |
| `openssl-devel` / `libssl-dev` | TLS and x509 certificate handling (GSI auth, WebDAV) |
| `voms-libs` / `libvomsapi1` | `libvomsapi.so.1` runtime library (VO ACL enforcement via dlopen) |
| `xrootd-client` | `xrdcp`, `xrdfs` command-line tools for testing |
| `xrootd-server` | Reference `xrootd` daemon for interoperability tests |
| `curl` | Runtime helper for optional HTTP-TPC WebDAV COPY pulls |
| Python `cryptography` | Test PKI, proxy, CRL, and JWT token generation |

VOMS support is loaded at runtime via `dlopen("libvomsapi.so.1")` — no compile-time VOMS headers or link flags are needed. If the library is present at startup, VO ACL enforcement is available; if absent, the module starts normally but `brix_require_vo` directives will fail with an error telling you to install `voms-libs` (EL9) or `libvomsapi1` (Debian/Ubuntu). See [pki.md](../06-authentication/pki-config.md) for the VOMS attribute certificate model and vomsdir/LSC file setup.

Verify `libvomsapi` is installed:

```bash
ls /usr/lib64/libvomsapi.so.1   # EL9
# or
ldconfig -p | grep libvomsapi   # any distro
```

---

## 2. Get the nginx source

Use the current stable release. The module is tested against nginx 1.28.x:

```bash
cd /tmp
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz
cd nginx-1.28.3
```

---

## 3. Clone the module

```bash
git clone https://github.com/HEP-x/nginx-xrootd.git /opt/nginx-xrootd
```

Or, if you already have it checked out:

```bash
export BRIX_MODULE=/home/you/nginx-xrootd
```

---

## 4. Configure nginx

```bash
cd /tmp/nginx-1.28.3

./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-threads \
    --add-module=/opt/nginx-xrootd
```

What each flag does:

| Flag | Required? | Purpose |
|---|---|---|
| `--with-stream` | **Yes** | Enables nginx's raw TCP stream handling — this is how the XRootD protocol is served |
| `--with-stream_ssl_module` | Recommended | TLS for the stream (XRootD) protocol |
| `--with-http_ssl_module` | Recommended | TLS for HTTP modules: WebDAV and S3-compatible HTTPS |
| `--with-threads` | **Strongly recommended** | Enables nginx thread pools for async file I/O. Without this, slow disk/network I/O paths may fall back to synchronous work on a worker process. |
| `--add-module=<path>` | **Yes** | Points to the BriX-Cache source directory |

```text
   nginx source tree          this repo
   /tmp/nginx-1.28.3          /opt/nginx-xrootd
        │                          │
        │   --add-module=──────────┤  root `config` script
        │                          │  (the ONLY source list — register new .c here)
        ▼                          ▼
   ./configure ◀─── reads `config`, generates objs/Makefile + objs/ngx_modules.c
        │            ⚠ re-run ./configure after: new .c file · new --with-* · new block
        ▼
   make -j$(nproc) ◀─── incremental rebuilds (NO configure needed for code edits)
        │               ⚠ never edit objs/Makefile (regenerated) or nginx's own src/
        ▼
   objs/nginx  ──▶  nginx -t -c …  (validate)  ──▶  run
```

The module's `config` script (at the root of this repository) runs automatically during `./configure`. It:
- Registers the **stream** modules: `ngx_stream_brix_module` for native XRootD and `ngx_stream_brix_cms_srv_module` for the CMS management listener
- Registers the **HTTP** modules: `ngx_http_brix_metrics_module` (Prometheus), `ngx_http_brix_webdav_module` (WebDAV), and `ngx_http_brix_s3_module` (S3-compatible HTTP)
- Links `-lssl -lcrypto` for OpenSSL/GSI support
- VOMS support requires no compile-time flags — `libvomsapi.so.1` is loaded at runtime via `dlopen`

### Optional performance profile (opt-in)

By default the module builds with nginx's standard optimisation flags plus the
hardening flags listed above. For throughput-sensitive deployments you can opt
into a higher optimisation profile by exporting `BRIX_OPTIMIZE` **before**
`./configure`:

```bash
BRIX_OPTIMIZE=v2 ./configure --with-stream --with-stream_ssl_module \
    --with-http_ssl_module --with-http_dav_module --with-threads \
    --add-module=/opt/nginx-xrootd
make -j"$(nproc)"
```

| `BRIX_OPTIMIZE` | Flags added | When to use |
|---|---|---|
| _(unset)_ | none (default) | Portable default; no assumptions about the CPU |
| `v2` | `-O3 -march=x86-64-v2 -fno-plt` | **Recommended.** Safe on every RHEL 9 host (SSE4.2/POPCNT are part of the x86-64-v2 baseline). Lets the compiler emit SSE4.2 everywhere, not only in the CRC-32c hot path. |
| `v3` | `-O3 -march=x86-64-v3 -fno-plt` | Fleets where **every** CPU supports AVX2/BMI2 (Haswell+/Zen+). The binary will SIGILL on older CPUs. |
| `native` | `-O3 -march=native -fno-plt` | Tuned to the build host only. **Do not** redistribute the resulting binary to other hardware. |

The profile is compile-time only and composes with the hardening flags. For
cross-module **link-time optimisation** (LTO), additionally pass
`--with-cc-opt="-flto=auto" --with-ld-opt="-flto=auto"` at the top level — LTO
must be enabled on both the compile and link steps.

> The `-O3` flag is appended after nginx's own `-O`, and the last `-O` on the
> command line wins, so there is no conflict. Re-run the full test suite after
> changing the optimisation profile, since `-O3` can expose latent
> undefined-behaviour bugs that `-O` masks.

### Verifying VOMS at runtime

After starting nginx, check the error log for the VOMS load message:

```bash
grep libvomsapi /tmp/xrd-test/logs/error.log
# Expected: xrootd: libvomsapi.so.1 loaded — VOMS VO ACL enforcement available
```

If you see `libvomsapi.so.1 not found — VOMS VO ACL enforcement disabled` instead, install `voms-libs` (EL9) or `libvomsapi1` (Debian/Ubuntu). The binary itself has no link-time dependency on VOMS — `ldd objs/nginx | grep voms` should return nothing.

---

## 5. Build

```bash
cd /tmp/nginx-1.28.3
make -j$(nproc)
```

The binary is at `/tmp/nginx-1.28.3/objs/nginx`. Verify the module compiled in:

```bash
/tmp/nginx-1.28.3/objs/nginx -V 2>&1 | grep -o 'add-module=[^ ]*'
# Expected: add-module=/opt/nginx-xrootd
```

---

## 5a. Quick build for testing (minimal)

For quick testing without the full test infrastructure setup:

```bash
# Download and extract nginx
cd /tmp
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz

# Configure with the module (adjust paths as needed)
cd /tmp/nginx-1.28.3
./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-threads \
    --add-module=/home/rcurrie/HEP-x/nginx-xrootd

# Build
make -j$(nproc)

# Binary is at: /tmp/nginx-1.28.3/objs/nginx
```

### Building with maximum features for comprehensive testing

To ensure the fix doesn't break any code paths that might be disabled by optimizations:

```bash
cd /tmp/nginx-1.28.3
./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-threads \
    --with-file-aio \
    --with-pcre \
    --with-http_realip_module \
    --with-http_addition_module \
    --with-http_flv_module \
    --with-http_mp4_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_stub_status_module \
    --with-debug \
    --add-module=/home/rcurrie/HEP-x/nginx-xrootd

make -j$(nproc)
```

Note: `--with-debug` enables expensive runtime assertions. Remove it for production builds.

The binary is at `/tmp/nginx-1.28.3/objs/nginx`.

---

## 6. Set up the test environment

The test suite expects a specific directory layout under `/tmp/xrd-test/`. This section creates it from scratch.

### 6.1 Directory structure

```bash
mkdir -p /tmp/xrd-test/{conf,data,logs,tmp}
mkdir -p /tmp/xrd-test/pki/{ca,server,user,voms,vomsdir}
mkdir -p /tmp/xrd-test/tokens
```

### 6.2 Generate the test PKI

See [docs/test-pki.md](../06-authentication/test-pki-setup.md) for a complete walkthrough of creating the CA, server cert, user cert, proxy certs, and VOMS infrastructure from scratch.

If you just want to get running quickly, the test fixtures in `tests/test_vo_acl.py` auto-generate VOMS signing certs and proxies on first run. But the CA, server cert, and user cert must exist first.

### 6.3 Create seed data

```bash
echo "hello xrootd" > /tmp/xrd-test/data/test.txt
for dir in cms atlas public; do
    mkdir -p /tmp/xrd-test/data/$dir
    echo "seed file for $dir" > /tmp/xrd-test/data/$dir/seed.txt
done
```

### 6.4 Create the token signing authority

The helper needs the Python `cryptography` package. If you are using a virtual environment, activate it before this step; otherwise install the dependencies from section 8.1 first.

```bash
cd /path/to/nginx-xrootd
python3 utils/make_token.py init /tmp/xrd-test/tokens
```

This writes `/tmp/xrd-test/tokens/signing_key.pem` and `/tmp/xrd-test/tokens/jwks.json`. See [docs/test-tokens.md](../06-authentication/test-token-generation.md) for the full walkthrough.

### 6.5 Write the test nginx.conf

Create `/tmp/xrd-test/conf/nginx.conf`:

```nginx
worker_processes 1;
error_log /tmp/xrd-test/logs/error.log info;
pid       /tmp/xrd-test/logs/nginx.pid;

thread_pool default threads=4 max_queue=65536;
events { worker_connections 64; }

stream {
    # Anonymous server (port 11094)
    server {
        listen 11094;
        xrootd on;
        brix_root /tmp/xrd-test/data;
        brix_auth none;
        brix_allow_write on;
        brix_access_log /tmp/xrd-test/logs/brix_access_anon.log;
    }

    # GSI/x509 server (port 11095)
    server {
        listen 11095;
        xrootd on;
        brix_root /tmp/xrd-test/data;
        brix_auth gsi;
        brix_allow_write on;
        brix_certificate     /tmp/xrd-test/pki/server/hostcert.pem;
        brix_certificate_key /tmp/xrd-test/pki/server/hostkey.pem;
        brix_trusted_ca      /tmp/xrd-test/pki/ca/ca.pem;
        brix_access_log /tmp/xrd-test/logs/brix_access_gsi.log;
    }

    # JWT/WLCG bearer-token server (port 11099)
    server {
        listen 11099;
        xrootd on;
        brix_root /tmp/xrd-test/data;
        brix_auth token;
        brix_allow_write on;
        brix_token_jwks     /tmp/xrd-test/tokens/jwks.json;
        brix_token_issuer   "https://test.example.com";
        brix_token_audience "nginx-xrootd";
        brix_access_log /tmp/xrd-test/logs/brix_access_token.log;
    }
}

http {
    access_log            /tmp/xrd-test/logs/http_access.log;
    client_body_temp_path /tmp/xrd-test/tmp;
    proxy_temp_path       /tmp/xrd-test/tmp;
    fastcgi_temp_path     /tmp/xrd-test/tmp;
    uwsgi_temp_path       /tmp/xrd-test/tmp;
    scgi_temp_path        /tmp/xrd-test/tmp;

    # Prometheus metrics
    server {
        listen 9100;
        location /metrics { brix_metrics on; }
    }

    # WebDAV over HTTPS (port 8443)
    server {
        listen 8443 ssl;
        server_name localhost;
        ssl_certificate     /tmp/xrd-test/pki/server/hostcert.pem;
        ssl_certificate_key /tmp/xrd-test/pki/server/hostkey.pem;
        brix_webdav_proxy_certs on;
        ssl_verify_client   optional_no_ca;
        ssl_verify_depth    10;
        client_max_body_size 1g;
        location / {
            brix_webdav         on;
            brix_webdav_root    /tmp/xrd-test/data;
            brix_webdav_cadir   /tmp/xrd-test/pki/ca;
            brix_webdav_auth    optional;
            brix_webdav_allow_write on;
            brix_webdav_token_jwks     /tmp/xrd-test/tokens/jwks.json;
            brix_webdav_token_issuer   "https://test.example.com";
            brix_webdav_token_audience "nginx-xrootd";
        }
    }
}
```

---

## 7. Start nginx

```bash
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf
```

Or use the repository helper (also manages the reference `xrootd` server on
port 11096 used by conformance tests):

```bash
cd /path/to/nginx-xrootd
tests/manage_test_servers.sh start
```

Quick smoke test:

```bash
# Anonymous access
echo "hello" > /tmp/test.txt
xrdcp /tmp/test.txt root://localhost:11094//test_upload.txt
xrdfs localhost:11094 ls /

# GSI access (requires proxy cert — see test-pki.md)
export X509_USER_PROXY=/tmp/xrd-test/pki/user/proxy_std.pem
export X509_CERT_DIR=/tmp/xrd-test/pki/ca
xrdfs root://localhost:11095 ls /

# Token access (requires token signing authority — see test-tokens.md)
export BEARER_TOKEN=$(python3 /path/to/nginx-xrootd/utils/make_token.py gen \
    --scope "storage.read:/" /tmp/xrd-test/tokens)
xrdfs root://localhost:11099 ls /
```

---

## 8. Run the test suite

For the complete testing guide — session lifecycle, how PKI/tokens/VOMS are generated, how to write new tests, and environment variables — see [testing.md](../09-developer-guide/testing-runbook.md).

### 8.1 Install Python dependencies

```bash
cd /path/to/nginx-xrootd
python3 -m venv .venv
source .venv/bin/activate
pip install pytest xrootd pytest-timeout cryptography requests urllib3
```

### 8.2 Run tests

The test suite generates the PKI, starts all test servers, and tears them down automatically. No manual server startup is needed.

```bash
# Core tests (protocol, file API, metrics)
pytest tests/test_xrootd.py tests/test_file_api.py tests/test_metrics.py -v

# Read and write handlers
pytest tests/test_write.py tests/test_readv.py -v

# GSI authentication and bridge transfers
pytest tests/test_gsi_bridge.py -v

# VO ACL enforcement (requires libvomsapi.so.1 at runtime)
pytest tests/test_vo_acl.py -v

# Token auth
pytest tests/test_token_auth.py -v

# CRL revocation checks
pytest tests/test_crl.py -v

# WebDAV / HTTPS
pytest tests/test_webdav.py -v

# WebDAV HTTP-TPC and XrdHttp interop
pytest tests/test_webdav_tpc.py -v

# Native root:// TPC behavior
pytest tests/test_root_tpc.py -v

# Everything
pytest -v
```

The VO ACL tests (`test_vo_acl.py`) start their own nginx instance on port 11103 with `brix_require_vo` directives. They auto-generate VOMS proxies if expired or missing using the Python `voms_proxy_fake.py` utility in `utils/`. Token tests use the configured port 11099. CRL tests start a dedicated nginx instance on port 11100 plus WebDAV on 8444 so they do not disturb the main listener. The HTTP-TPC tests (`test_webdav_tpc.py`) start isolated nginx WebDAV endpoints on dynamic ports and, when the local XrdHttp plugins are installed, a reference xrootd HTTPS/TPC endpoint. The native root TPC tests (`test_root_tpc.py`) start an isolated nginx root:// endpoint and a TPC-capable reference xrootd server on dynamic ports.

---

## 9. Rebuilding after code changes

After editing any `.c` or `.h` file:

```bash
cd /tmp/nginx-1.28.3
make -j$(nproc)

# Restart nginx (reload does NOT pick up a rebuilt binary)
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf -s stop
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf

# Re-run tests
cd /path/to/nginx-xrootd
pytest -v
```

---

## 10. Build options reference

### VOMS support (runtime, via dlopen)

VOMS support is always compiled in but loaded at runtime. The module calls `dlopen("libvomsapi.so.1")` during nginx startup and resolves the four API symbols it needs (`VOMS_Init`, `VOMS_Retrieve`, `VOMS_Destroy`, `VOMS_ErrorMessage`). No compile-time VOMS headers or link flags are required.

- **If `libvomsapi.so.1` is present** (e.g. from `voms-libs` on EL9): VO ACL enforcement is available. The startup log shows `xrootd: libvomsapi.so.1 loaded — VOMS VO ACL enforcement available`.
- **If `libvomsapi.so.1` is absent**: The module starts normally. `brix_vomsdir`, `brix_voms_cert_dir`, and `brix_require_vo` directives are still accepted by the config parser, but validation will fail at startup with a clear error message asking you to install the runtime library.

### Debug build

For development, use nginx's debug logging:

```bash
./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-threads \
    --with-debug \
    --add-module=/opt/nginx-xrootd

make -j$(nproc)
```

Then set `error_log ... debug;` in `nginx.conf` for protocol-level trace output.

### Production install

```bash
./configure \
    --prefix=/usr/local/nginx \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-threads \
    --add-module=/opt/nginx-xrootd

make -j$(nproc)
sudo make install
```

The binary installs to `/usr/local/nginx/sbin/nginx` and configuration goes in `/usr/local/nginx/conf/`.

---

## 11. RPM packaging (AlmaLinux 9 / RHEL 9 / Rocky 9)

The `packaging/rpm/nginx-mod-brix-cache.spec` file builds three dynamic modules as
a single RPM against the system nginx from the RHEL 9 AppStream repository.

### Prerequisites

```bash
sudo dnf install -y rpm-build nginx-mod-devel pcre2-devel zlib-devel openssl-devel
```

`nginx-mod-devel` provides the `%nginx_modconfigure` and `%nginx_modbuild` RPM
macros (in `/usr/lib/rpm/macros.d/macros.nginxmods`), which configure and build
the module against the exact nginx headers and flags used to build the installed
nginx binary. The resulting `.so` files are tied to the nginx ABI version; on
AlmaLinux 9 that is currently `nginx(abi) = 1.20.1`.

### Set up the rpmbuild tree

```bash
mkdir -p ~/rpmbuild/{SOURCES,SPECS,RPMS,SRPMS,BUILD,BUILDROOT}
```

### Create the source tarball

The spec expects a `nginx-xrootd-<version>.tar.gz` archive in `~/rpmbuild/SOURCES/`:

```bash
VERSION=0.1.0
git -C /path/to/nginx-xrootd archive \
    --format=tar.gz \
    --prefix=nginx-xrootd-${VERSION}/ \
    HEAD \
    -o ~/rpmbuild/SOURCES/nginx-xrootd-${VERSION}.tar.gz
```

Or, to build from a released tag:

```bash
VERSION=0.1.0
spectool -g -R packaging/rpm/nginx-mod-brix-cache.spec
```

(`spectool` is in the `rpm-build` package.)

### Build the RPM

```bash
cp packaging/rpm/nginx-mod-brix-cache.spec ~/rpmbuild/SPECS/

rpmbuild -bb \
    --define "version_override 0.1.0" \
    ~/rpmbuild/SPECS/nginx-mod-brix-cache.spec
```

The finished RPM lands in `~/rpmbuild/RPMS/x86_64/`:

```
~/rpmbuild/RPMS/x86_64/nginx-mod-brix-cache-0.1.0-1.el9.x86_64.rpm
```

You can also build directly from the working tree without a tarball by using
`--build-in-place` (requires rpmbuild ≥ 4.16):

```bash
rpmbuild -bb --build-in-place \
    --define "_builddir $(pwd)" \
    --define "version_override 0.1.0" \
    packaging/rpm/nginx-mod-brix-cache.spec
```

### Verify the RPM contents

```bash
rpm -qpl ~/rpmbuild/RPMS/x86_64/nginx-mod-brix-cache-*.rpm
```

Expected output:

```
/usr/lib64/nginx/modules/ngx_stream_brix_module.so
/usr/lib64/nginx/modules/ngx_stream_brix_cms_srv_module.so
/usr/lib64/nginx/modules/ngx_http_brix_metrics_module.so
/usr/lib64/nginx/modules/ngx_http_brix_webdav_module.so
/usr/lib64/nginx/modules/ngx_http_brix_s3_module.so
/usr/share/nginx/modules/mod-xrootd.conf
/usr/share/doc/nginx-mod-brix-cache/README.md
/usr/share/doc/nginx-mod-brix-cache/docs/   (all docs files)
```

Check the automatic ABI dependency:

```bash
rpm -qp --requires ~/rpmbuild/RPMS/x86_64/nginx-mod-brix-cache-*.rpm | grep nginx
# nginx(abi) = 1.20.1
# nginx-mod-stream(x86-64)
```

### Install

```bash
sudo dnf install ~/rpmbuild/RPMS/x86_64/nginx-mod-brix-cache-*.rpm
```

Or, for a local-only install without updating the dnf database:

```bash
sudo rpm -ivh ~/rpmbuild/RPMS/x86_64/nginx-mod-brix-cache-*.rpm
```

### Post-install: load the modules

The RPM writes `/usr/share/nginx/modules/mod-xrootd.conf`:

```nginx
load_module "/usr/lib64/nginx/modules/ngx_stream_brix_module.so";
load_module "/usr/lib64/nginx/modules/ngx_stream_brix_cms_srv_module.so";
load_module "/usr/lib64/nginx/modules/ngx_http_brix_metrics_module.so";
load_module "/usr/lib64/nginx/modules/ngx_http_brix_webdav_module.so";
load_module "/usr/lib64/nginx/modules/ngx_http_brix_s3_module.so";
```

On AlmaLinux 9, `/etc/nginx/nginx.conf` includes `*.conf` from
`/usr/share/nginx/modules/` in its `include` statement, so the modules are
loaded automatically after installation. Verify:

```bash
sudo nginx -t   # should say 'configuration file ... is ok'
```

If you are using a custom `nginx.conf` that does not include that directory,
add the `load_module` lines to the top level of your config (before the
`events {}` block).

### ABI compatibility note

The RPM is built against the system nginx ABI. If you update nginx (e.g. during
a `dnf update`), the module RPM must be rebuilt against the new nginx headers.
The `Requires: nginx(abi) = 1.20.1` dependency will cause `dnf` to hold back
nginx upgrades that would break the module, or refuse to install the old module
against a new nginx — whichever you prefer to resolve first.

To rebuild after a nginx update:

```bash
sudo dnf update nginx nginx-mod-devel
rpmbuild -bb --define "version_override 0.1.0" ~/rpmbuild/SPECS/nginx-mod-brix-cache.spec
sudo dnf install ~/rpmbuild/RPMS/x86_64/nginx-mod-brix-cache-*.rpm
```

---

## Sanitizer build (Phase 27 W6 — memory-safety CI)

A separate, opt-in build with AddressSanitizer + UndefinedBehaviorSanitizer +
LeakSanitizer for catching heap overflow / use-after-free / leaks reachable from
the wire. **Never the default** — it changes timing and memory layout and is
~3× slower; use it as a CI gate and for local triage.

```bash
cd /path/to/nginx-src
export REPO=/path/to/nginx-xrootd
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
    --with-http_dav_module --with-threads --add-module=$REPO \
    --with-cc-opt='-fsanitize=address,undefined -fno-omit-frame-pointer -g' \
    --with-ld-opt='-fsanitize=address,undefined'
make -j$(nproc)
```

Requires `libasan` + `libubsan` (e.g. `dnf install libasan libubsan`).

Run the suites under it; LeakSanitizer reports any leak still reachable at
process exit, ASAN catches overflow/UAF at the moment it happens:

```bash
ASAN_OPTIONS=detect_leaks=1 PYTHONPATH=tests pytest tests/ -q     # expect 0 leak reports
ASAN_OPTIONS=detect_leaks=1 PYTHONPATH=tests pytest tests/test_cms_mesh_interop.py -q
```

fd-leak / still-reachable smoke with valgrind (catches what LSan misses):

```bash
valgrind --leak-check=full --track-fds=yes objs/nginx -t -c <conf>
```

**Known benign finding:** UBSan reports `src/core/ngx_string.c:84 … null pointer
passed as argument 2` — this is nginx **core** (`ngx_memcpy(dst, NULL, 0)`), not
the module, and build governance forbids editing nginx core. Suppress it with a
`-fsanitize-ignorelist` entry or `UBSAN_OPTIONS=...` rather than patching core.

After triaging, **reconfigure without the sanitizer flags** to restore the
production binary.

## Wire-parser fuzzing (Phase 27 W7)

Standalone libFuzzer targets live in `tests/fuzz/` (built with
`clang -fsanitize=fuzzer,address`); see `tests/fuzz/README.md`. The W1
overflow-checked size helpers have a runnable target:

```bash
cd tests/fuzz
clang -O1 -g -fsanitize=fuzzer,address,undefined -I ../../src/shared \
    fuzz_safe_size.c -o fuzz_safe_size && ./fuzz_safe_size -max_total_time=120
```

### Running the test suite under the sanitizer (`SANITIZE=1`)

`tests/manage_test_servers.sh` honours `SANITIZE=1`: it exports
`ASAN_OPTIONS`/`UBSAN_OPTIONS`/`LSAN_OPTIONS` (with `tests/lsan.supp`) so every
nginx the fleet launches inherits them, writing per-pid logs to
`$TEST_ROOT/sanitize/asan.<pid>`. Workflow:

```bash
make -j$(nproc)                                  # the ASAN binary at objs/nginx
SANITIZE=1 SKIP_XRDFS_CHECK=1 tests/manage_test_servers.sh start-all
PYTHONPATH=tests pytest tests/ -q                # exercise the paths
SANITIZE=1 tests/manage_test_servers.sh stop     # each process leak-checks at exit
grep -rE 'in (brix_|ngx_.*xrootd)|/src/' "$TEST_ROOT"/sanitize/asan.* | grep -v src/core/
```

**ASAN at runtime works** — buffer-overflow / use-after-free / UBSan are caught
the moment they happen during the run (the readv/auth/S3/TPC/webdav paths were
exercised clean: no ASAN aborts).

**LeakSanitizer at-exit reporting is environment-dependent and was NOT firing
under WSL2 during development.** Root cause: nginx's daemon/worker shutdown path
does not reliably reach LSan's `atexit` hook (the module installs a best-effort
`__lsan_do_recoverable_leak_check()` in its `exit_process` hook, but
`exit_process` itself was observed not to run on SIGTERM/SIGQUIT under WSL2,
even though a standalone leaking program *is* reported correctly). On a native
Linux CI host this typically works; if it does not, drive the check another way:
run nginx with `master_process off` under `valgrind --leak-check=full
--track-fds=yes` (valgrind does not depend on the atexit path), or add a
`__lsan_do_leak_check()` call at a point the platform reaches. **Do not assume
"no asan.* files == leak-free" until you have confirmed LSan fires on this host
with a deliberately-injected leak (a known-good control).**
