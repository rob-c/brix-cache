# Build, Install, and Run: nginx-xrootd with GSI

This guide walks from a fresh host to a running `root://` server that
authenticates clients by x509 proxy certificate (GSI) and serves files from a
local POSIX directory.

**What you will have at the end:**

- An nginx process listening on port 1094 (`root://`) and port 1095 (`root://` + GSI)
- A self-signed test CA, a host certificate, a user certificate, and a proxy
  credential — enough to test end-to-end without an external grid CA
- A data directory readable and writable by authenticated clients
- Verification with `xrdcp` and `xrdfs`

If you already have real grid certificates (from your institution's grid CA)
and a real proxy from `voms-proxy-init`, skip §2 and §3 and plug the real
paths into §4.

## Pick your track

The two supported hosts install the module by different routes, and they differ
at nearly every step — package names, module directory, config layout, firewall,
SELinux. Follow **one** track through §2, then rejoin the shared sections.

| Track | How the module is installed | Sections |
|---|---|---|
| **AlmaLinux 8/9/10/11** | Prebuilt RPM from a container build | §1 → §2 |
| **Ubuntu 24.04 LTS / Debian 13** | Compiled as a dynamic module against the *distribution* nginx | **§1U** (self-contained) |

Sections §3 (test PKI) onward are shared; where a command differs by distro it
is called out inline.

---

## 0. Prerequisites

- **AlmaLinux track:** AlmaLinux 8, 9, 10, or 11 (adjust repo steps as noted),
  plus `docker` or `podman` for the container RPM build (§1)
- **Ubuntu track:** Ubuntu 24.04 LTS (or Debian 13); no container engine needed —
  see §1U
- Network access from the build host to download packages

---

## 1. Build the RPM

The RPM is built inside a container so the host needs no RPM build toolchain.
The only requirement is a working container engine.

```bash
# AlmaLinux 9 (default)
packaging/rpm/build-rpm-container.sh -v 0.1.0

# AlmaLinux 8
packaging/rpm/build-rpm-container.sh -d alma8 -v 0.1.0

# AlmaLinux 10
packaging/rpm/build-rpm-container.sh -d alma10 -v 0.1.0

# AlmaLinux 11 (once almalinux:11 is published)
packaging/rpm/build-rpm-container.sh -d alma11 -v 0.1.0
```

Built RPMs appear in `dist/`.  The `nginx-mod-xrootd-*.rpm` is the installable
module package; the `.src.rpm` is the source package.

```
dist/
  nginx-mod-xrootd-0.1.0-1.el9.x86_64.rpm   ← install this
  nginx-mod-xrootd-0.1.0-1.el9.src.rpm
```

---

## 2. Install on the target host

### 2.1 Enable required repositories

```bash
# EPEL (nginx-mod-stream, pcre2, openssl-libs)
sudo dnf install -y epel-release

# WLCG repository — provides voms-libs (required runtime dependency)
# AlmaLinux 8:
sudo dnf install -y https://linuxsoft.cern.ch/wlcg/el8/x86_64/wlcg-repo-1.0.0-1.el8.noarch.rpm
# AlmaLinux 9:
sudo dnf install -y https://linuxsoft.cern.ch/wlcg/el9/x86_64/wlcg-repo-1.0.0-1.el9.noarch.rpm
# AlmaLinux 10+ — monitor https://linuxsoft.cern.ch/wlcg/ for availability.
# Until the EL10 repo is published, use --nodeps and install voms-libs separately.
```

### 2.2 Install the RPM

```bash
sudo dnf install -y dist/nginx-mod-xrootd-0.1.0-1.el9.x86_64.rpm
```

This pulls in `nginx-mod-stream`, `openssl-libs`, `voms-libs`, and `curl`
as declared runtime dependencies, and drops a module loader snippet under
`/etc/nginx/modules-enabled/` (or the equivalent `nginx_modconfdir` for your
distribution).

Verify the modules are present:

```bash
ls /usr/lib64/nginx/modules/ngx_stream_brix_module.so
ls /usr/lib64/nginx/modules/ngx_http_brix_xrdhttp_filter_module.so
```

The dynamic build emits exactly two `.so` files. `ngx_stream_brix_module.so` is
the combined module — the `root://` stream listener plus the HTTP-side WebDAV,
S3, CVMFS, metrics and dashboard modules, which form a symbol cycle that cannot
be split across `.so` files. The other is the standalone HTTP output filter.

---

## 1U. Ubuntu / Debian: build against the distribution nginx

There is no `.deb` yet, so on Ubuntu the module is compiled as a **dynamic
module against the nginx the distribution already ships** and dropped into that
nginx's module directory. The stock `nginx` package stays in place and keeps
receiving security updates; only the `.so` is ours.

Verified end-to-end on **Ubuntu 24.04.4 LTS** against
**nginx 1.24.0-2ubuntu7.15**, gcc 13, OpenSSL 3.0.13, libcurl 8.5.0.

> **Why this works:** Ubuntu builds its nginx with `--with-compat`, the ABI
> compatibility layer that makes third-party dynamic modules loadable across
> builds with different `--with-*` option sets. Our module must be compiled with
> `--with-compat` too, from the **same nginx version** the distribution installed.

### 1U.1 Install nginx and the build toolchain

```bash
sudo apt update
sudo apt install -y build-essential dpkg-dev pkg-config \
    nginx libnginx-mod-stream
```

`libnginx-mod-stream` is mandatory, not optional: Ubuntu builds the stream core
as a dynamic module (`--with-stream=dynamic`), and the BriX stream listener
cannot register without it.

Record the exact version you are building against — the module has to match it:

```bash
dpkg -s nginx | grep ^Version      # e.g. 1.24.0-2ubuntu7.15
nginx -V 2>&1 | tr ' ' '\n' | grep compat   # must print --with-compat
```

### 1U.2 Install the module's dependencies

```bash
# Required — ./configure aborts without these
sudo apt install -y libssl-dev libpcre2-dev zlib1g-dev \
    libxml2-dev libjansson-dev libcurl4-openssl-dev

# Optional — each is auto-detected and silently skipped if absent
sudo apt install -y libkrb5-dev libsqlite3-dev libseccomp-dev \
    libzstd-dev liblzma-dev libbrotli-dev libbz2-dev liblz4-dev \
    librados-dev libradosstriper-dev libcephfs-dev liburing-dev
```

| Package | Enables |
|---|---|
| `libxml2-dev` | **Required.** WebDAV PROPFIND XML |
| `libjansson-dev` | **Required.** JSON (tokens, dashboard, config) |
| `libcurl4-openssl-dev` | **Required.** HTTP-TPC `COPY` pulls |
| `libssl-dev` | **Required.** GSI x509, TLS, checksums |
| `libkrb5-dev` | `brix_auth krb5` |
| `libsqlite3-dev` | pblock storage backend |
| `libseccomp-dev` | `brix_seccomp` syscall filter |
| `libzstd-dev` `liblzma-dev` `libbrotli-dev` `libbz2-dev` `liblz4-dev` | compression codecs |
| `librados-dev` `libradosstriper-dev` `libcephfs-dev` | Ceph / XrdCeph backends |
| `liburing-dev` | io_uring backend — additionally needs `BRIX_ENABLE_IO_URING=1` at configure time |

Runtime-only (no headers needed; loaded via `dlopen`):

```bash
sudo apt install -y libvomsapi1t64    # VO ACL enforcement
sudo apt install -y xrootd-client     # xrdcp / xrdfs, for §8
```

> **Ubuntu package-name trap:** the VOMS C library is `libvomsapi1t64` on Ubuntu
> 24.04 (the `t64` time_t transition rename). `libvomsapi1` — the name the older
> docs use — does not exist here and `apt install libvomsapi1` fails. Both ship
> the same `libvomsapi.so.1` soname the module dlopens. Confirm with
> `ldconfig -p | grep libvomsapi`.

### 1U.3 Fetch the matching nginx source

The module must be compiled against the **exact** nginx source Ubuntu built its
binary from, including the distro's patch stack. Get it from the archive rather
than from nginx.org.

Ubuntu 24.04 ships `deb-src` lines disabled, so enable them first:

```bash
sudo sed -i 's/^Types: deb$/Types: deb deb-src/' \
    /etc/apt/sources.list.d/ubuntu.sources
sudo apt update
```

<details>
<summary>On a release still using the old <code>sources.list</code> format</summary>

Uncomment the `deb-src` lines in `/etc/apt/sources.list` instead, or run
`sudo add-apt-repository --enable-source -y`.
</details>

```bash
sudo mkdir -p /usr/src/brix-nginx
cd /usr/src/brix-nginx
sudo apt-get source nginx        # unpacks nginx-1.24.0/ with Ubuntu's patches applied
```

### 1U.4 Configure

Run this from the unpacked nginx source, pointing `--add-dynamic-module` at your
checkout of this repository:

```bash
export BRIX_REPO=/path/to/brix-cache      # this repository

cd /usr/src/brix-nginx/nginx-1.24.0
sudo -E ./configure \
    --with-compat \
    --with-debug \
    --with-threads \
    --with-file-aio \
    --with-pcre-jit \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_dav_module \
    --with-http_realip_module \
    --with-http_auth_request_module \
    --with-http_slice_module \
    --with-http_stub_status_module \
    --with-stream=dynamic \
    --with-stream_ssl_module \
    --with-stream_realip_module \
    --with-stream_ssl_preread_module \
    --with-cc-opt='-g -O2 -fPIC -Wdate-time -D_FORTIFY_SOURCE=3' \
    --with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC' \
    --add-dynamic-module="$BRIX_REPO"
```

The flags that are **not** negotiable:

| Flag | Why |
|---|---|
| `--with-compat` | Without it the module signature will not match and `nginx -t` fails with *"module is not binary compatible"* |
| `--with-stream=dynamic` | Mirrors how Ubuntu built its nginx |
| `--with-threads` | The `brix_thread_pool` async-I/O path |
| `--add-dynamic-module=` | Not `--add-module=` — a static build would require replacing the distro nginx binary |

The remaining flags mirror Ubuntu's own `nginx -V` output so the build matches
the running binary. The four extra dynamic modules Ubuntu builds
(`geoip`/`image_filter`/`perl`/`xslt`) are deliberately dropped — they are not
ours to rebuild, and under `--with-compat` they have no effect on the module
signature. `-D_FORTIFY_SOURCE=3` matches Ubuntu's hardening level.

Confirm the feature detection in the output:

```
 + xrootd: _FORTIFY_SOURCE already defined (compiler default or --with-cc-opt); not overriding
 + xrootd: performance profile = v2 (-O3 -march=x86-64-v2) [default]
 + xrootd WebDAV: native MKCOL/DELETE handlers enabled
 + xrootd auth: Kerberos 5 plugin enabled (pkg-config)
 + xrootd compression: zstd / xz / brotli / bzip2 / lz4 enabled
 + xrootd storage backend: ceph/rados enabled
 + ngx_stream_brix_module was configured
```

### 1U.5 Build

```bash
cd /usr/src/brix-nginx/nginx-1.24.0
sudo make modules -j"$(nproc)"
```

`make modules` builds only the `.so` files — it does **not** build or install an
nginx binary, so the distribution's nginx is untouched. Two modules are produced:

```bash
ls -l objs/ngx_stream_brix_module.so \
      objs/ngx_http_brix_xrdhttp_filter_module.so
```

`ngx_stream_brix_module.so` is the combined module: the `root://` stream
listener *and* the HTTP-side WebDAV, S3, CVMFS, metrics and dashboard modules
all live in it (they form a symbol cycle that cannot be split across `.so`
files). The xrdhttp filter is a separate HTTP output filter.

Check every shared library resolves:

```bash
ldd objs/ngx_stream_brix_module.so | grep -c 'not found'   # must print 0
```

### 1U.6 Install the modules

```bash
sudo install -m 644 objs/ngx_stream_brix_module.so \
                    objs/ngx_http_brix_xrdhttp_filter_module.so \
                    /usr/lib/nginx/modules/
```

Note the path: **`/usr/lib/nginx/modules`** on Debian/Ubuntu, not the
`/usr/lib64/nginx/modules` used by the RPM track.

Create the loader snippet, following Debian's `modules-available` /
`modules-enabled` convention:

```bash
sudo tee /etc/nginx/modules-available/mod-brix-cache.conf > /dev/null <<'EOF'
# BriX-Cache dynamic modules.
# Must load AFTER modules/ngx_stream_module.so (50-mod-stream.conf) — the
# combined module registers stream modules and needs the stream core present.
# ngx_stream_brix_module.so must come first: it is loaded with RTLD_GLOBAL and
# its symbols back the HTTP-side modules in the filter .so.
load_module modules/ngx_stream_brix_module.so;
load_module modules/ngx_http_brix_xrdhttp_filter_module.so;
EOF

sudo ln -sf /etc/nginx/modules-available/mod-brix-cache.conf \
            /etc/nginx/modules-enabled/60-mod-brix-cache.conf
```

**The `60-` prefix is load-bearing.** `/etc/nginx/nginx.conf` includes
`modules-enabled/*.conf` in filename order, and `libnginx-mod-stream` installs
itself as `50-mod-stream.conf`. A prefix below 50 loads the BriX stream module
before the stream core exists and nginx aborts at startup.

### 1U.7 Wire up the config

Ubuntu's `nginx.conf` has **no top-level `stream {}` block and no include that
reaches one** — `conf.d/*.conf` and `sites-enabled/*` are both included from
inside `http {}`. Dropping a stream server into `conf.d/` produces
*"'server' directive is not allowed here"*. Create the stream plane explicitly.

```bash
sudo mkdir -p /etc/nginx/streams-available /etc/nginx/streams-enabled

sudo tee -a /etc/nginx/nginx.conf > /dev/null <<'EOF'

# BriX-Cache: thread pool for async file I/O (main context) + the stream plane.
thread_pool brix_pool threads=8 max_queue=4096;

stream {
	include /etc/nginx/streams-enabled/*.conf;
}
EOF
```

`thread_pool` is a **main-context** directive — it must sit at the top level of
`nginx.conf`, outside both `http {}` and `stream {}`. Without it the module
starts anyway but logs `thread pool "..." not found - async file I/O disabled`
and every disk read blocks its worker.

Now the `root://` listener:

```bash
sudo tee /etc/nginx/streams-available/brix.conf > /dev/null <<'EOF'
# BriX-Cache root:// listener — anonymous, read-only.
server {
    listen 1094;
    brix_root on;
    brix_export /srv/brix/data;
    brix_thread_pool brix_pool;
    brix_access_log /var/log/nginx/brix_stream.log;
}
EOF

sudo ln -sf /etc/nginx/streams-available/brix.conf \
            /etc/nginx/streams-enabled/brix.conf
```

And the data directory — owned by **`www-data`** on Ubuntu, not `nginx`:

```bash
sudo mkdir -p /srv/brix/data
sudo chown www-data:www-data /srv/brix/data
sudo chmod 750 /srv/brix/data
echo "hello from brix on ubuntu" | sudo tee /srv/brix/data/hello.txt > /dev/null
```

### 1U.8 Validate and start

```bash
sudo nginx -t
```

A successful load prints the module's own startup notices before the syntax-OK
line:

```
[notice] brix: libvomsapi.so.1 loaded — VOMS VO ACL enforcement available
[notice] brix: using thread pool "brix_pool" for async file I/O
[notice] brix: root:// endpoint ready — export "/srv/brix/data" (read-only), auth: none (anonymous)
[notice] brix:   NOTE: no authentication required — this endpoint is OPEN to anonymous clients
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

```bash
sudo systemctl reload nginx
ss -tlnp | grep 1094
```

### 1U.9 Smoke test

```bash
xrdcp -f root://localhost:1094//hello.txt /tmp/hello_back.txt
cat /tmp/hello_back.txt
# hello from brix on ubuntu

xrdfs root://localhost:1094 stat /hello.txt
# Path:   /hello.txt
# Size:   26
# Flags:  16 (IsReadable)

tail -3 /var/log/nginx/brix_stream.log
```

Optionally check the HTTP plane, which rides the same `.so`. This one goes in
`conf.d/` because it *is* an `http {}` server:

```bash
sudo tee /etc/nginx/conf.d/brix-http.conf > /dev/null <<'EOF'
server {
    listen 8080;
    server_name _;

    location /metrics {
        brix_metrics on;
    }

    location /webdav/ {
        brix_webdav on;
        brix_webdav_auth none;          # anonymous; see §10 for real auth
        brix_export /srv/brix/data;
    }
}
EOF

sudo nginx -t && sudo systemctl reload nginx
curl -s http://127.0.0.1:8080/metrics | head -3
curl -s -X PROPFIND -H 'Depth: 1' http://127.0.0.1:8080/webdav/ | head -c 200
```

`brix_webdav` refuses to start with `auth optional/required` unless a credential
verifier is configured — that is the intended fail-closed behaviour, not a build
problem. Set `brix_webdav_auth none` for an anonymous smoke test, or configure a
verifier (`brix_trusted_ca_dir`, `brix_token_jwks`, `brix_pwd_file`).

WebDAV maps the **whole request URI** under the export root, so
`/webdav/hello.txt` resolves to `/srv/brix/data/webdav/hello.txt`. Either place
files under a matching subdirectory or serve WebDAV from `location /`.

### 1U.10 Build the client tools and FUSE drivers

Independent of the nginx module: the CLI tools (`xrdcp`, `xrdfs`, `xrdcksum`, …),
the FUSE mounts (`xrootdfs`, `brixMount`/`brixcvmfs`), the `LD_PRELOAD` POSIX
shim and the Ceph operator tools. They link no nginx and no libXrdCl — only the
in-tree protocol core plus OpenSSL.

Two dependencies beyond §1U.2:

```bash
sudo apt install -y libfuse3-dev fuse3   # xrootdfs, brixMount, brixcvmfs
sudo apt install -y libradospp-dev       # the C++ Ceph tools (rados/librados.hpp)
```

> `librados-dev` ships only the **C** headers. The two C++ migration tools
> (`xrdceph_striper_migrate`, `xrdceph_cephfs_to_striper`) need `librados.hpp`
> from **`libradospp-dev`** — on EL that header is in `libradospp-devel`.
> Without it the build fails at `apps/ceph/xrdceph_striper_migrate.cpp`.

**Build the shared protocol core first** — `client/Makefile` has a `proto`
target but `all` does not depend on it, so a bare `make -C client` on a clean
tree dies with *"No rule to make target `../shared/xrdproto/libxrdproto.a`"*:

```bash
make -C shared/xrdproto -j"$(nproc)"
make -C client          -j"$(nproc)"
```

Everything lands in `client/bin/`. Every optional feature is auto-detected, so
with the §1U.2 packages installed you get all 29 artifacts:

```bash
ls client/bin/
# xrdcp xrdfs xrd xrdcksum xrdprep xrdgsiproxy xrddiag xrdmapc xrdstorascan …
# xrootdfs brixMount brixcvmfs        ← FUSE
# xrdceph_migrate xrdrados_rescue …   ← Ceph operator tools
# libbrixposix_preload.so             ← LD_PRELOAD POSIX shim
```

Mounting needs `/dev/fuse` and, for unprivileged use, `user_allow_other` in
`/etc/fuse.conf` if you pass `-o allow_other`.

```bash
mkdir -p /mnt/xrd
client/bin/xrootdfs root://localhost:1094/ /mnt/xrd -f &
ls /mnt/xrd
```

> Both the daemonized default and `-f` are exercised; see §1U.13 for what was
> verified and the two defects fixed along the way.

### 1U.11 Rebuilding after an nginx update

The `.so` is tied to the nginx source it was compiled against. `--with-compat`
covers differing build options, **not** a different nginx version. After
`apt upgrade` moves nginx to a new upstream version, re-run §1U.3 → §1U.6.
Patch-level Ubuntu revisions of the same upstream version (1.24.0-2ubuntu7.15 →
…7.16) do not change the ABI, but rebuilding is the cheap, safe default.

To pin nginx so an unattended upgrade cannot silently break the module:

```bash
sudo apt-mark hold nginx nginx-common libnginx-mod-stream
```

### 1U.12 Ubuntu-specific build failures

These three were real compile errors on Ubuntu 24.04 and are **fixed in the
current tree** — listed so you can recognise them on an older checkout.

| Error | Cause | Fix |
|---|---|---|
| `"_FORTIFY_SOURCE" redefined [-Werror]` on every file | Ubuntu's nginx is built with `-D_FORTIFY_SOURCE=3` in `--with-cc-opt`, and the repo's `config` also appended `-D_FORTIFY_SOURCE=2` — two conflicting `-D` flags on one command line, and nginx compiles with `-Werror`. (Ubuntu's gcc predefine of `=3` is *not* the culprit; it backs off when the command line defines the macro.) | `config` now probes for an existing definition and defers to it |
| `'CURLOPT_PROTOCOLS' is deprecated` (and the `CURLINFO_*`/`CURLOPT_XFERINFOFUNCTION` variants) | libcurl 8.5 deprecates the old spellings. The guards were `#ifdef CURLOPT_PROTOCOLS_STR` — but those names are *enumerators*, not macros, so the guard is false on every libcurl ever released and always took the deprecated branch | Every site now uses curl's own `#if CURL_AT_LEAST_VERSION(7, 85, 0)`. `tools/ci/check_curl_enum_ifdef.py` guards against the `#ifdef`-an-enum mistake coming back |
| `'__builtin___snprintf_chk' argument 6 may overlap destination object 'cvmfs_ups' [-Werror=restrict]` | gcc 13 at `-O3` with `_FORTIFY_SOURCE=3` cannot prove two members of the same struct are disjoint | `src/protocols/cvmfs/upstreams.c` formats from a separate local buffer |

If you hit a *new* `-Werror` diagnostic from a newer gcc, do not disable
`-Werror` globally — fix the site, or scope the suppression with
`--with-cc-opt="-Wno-<warning>"` and open an issue.

### 1U.13 FUSE driver status

Verified on Ubuntu 24.04 against a local server (see §1U.9) and a local CVMFS
Stratum-0 (docs/05-operations/cvmfs-stratum0.md). Both drivers work, in both
foreground (`-f`) and the daemonized default.

**`xrootdfs`** over `root://` — listing, stat, read, write, mkdir, and a 64 MiB
round-trip byte-exact. Over `http(s)://` — read-only WebDAV, 64 MiB byte-exact,
writes correctly refused.

**`brixcvmfs`** — trust-chain verify, listing, reads, symlinks, mode bits,
read-only enforcement, `--prewarm` (clean WARM sweep, exit 0), the `cvmfs-rw`
overlay with `--overlay-list` / `--overlay-reset`, and the `autofs` umbrella
with on-demand child mounts.

Two defects were found here and are now **fixed**; both were
platform-independent, not Ubuntu-specific.

| Was | Cause | Fix |
|---|---|---|
| Daemonized `xrootdfs` (no `-f`) served `ls`/`stat` but every `read()` blocked forever in `request_wait_answer` | `fuse_main()` daemonizes by forking *after* the driver built its async manager, whose `pthread` event loop does not survive `fork()` — the daemon had sockets but nothing to drive them. Metadata survived because the connection pool is synchronous on the calling thread. | The driver forks **first** (`xfs_daemon_setup` in `client/apps/fs/xrootdfs.c`), so every thread is created on the daemon side, and passes `-f` to `fuse_main` so it cannot fork again. The parent waits on a pipe until the FUSE session is live, so diagnostics and the real exit status still reach the shell, and `xrootdfs … && ls /mnt` cannot race the mount. |
| A CVMFS object larger than 8 MiB was unreadable — `EIO` after a retry storm of tiny HTTP 206 range requests | The client's transport landing buffer was a fixed `scratch[8 MiB]`, while the publisher's default chunk size is 32 MiB: the shipped publisher produced objects the shipped client could not land. Compressible content masked it; random or already-compressed payloads tripped it immediately. | The landing buffer is heap-allocated and sized per object from the plaintext size the catalog already records (`shared/cvmfs/client/client.c`), bounded by `CVMFS_OBJECT_MAX_BYTES` (`shared/cvmfs/object/object.h`). The publisher now refuses `--chunk-size` above that same constant (`CVMFS_PUBLISH_CHUNK_CEIL`), so the two can never drift apart again. |

Fixing the second one also exposed a latent off-by-one in the cache read path:
`serve_from_cache()` returned "buffer too small" when an entry's size exactly
equalled the buffer. That never fired while every buffer was a round 16 MiB,
but exact-fit is now the common case, so it is fixed too.

Regression coverage: `tests/test_xrootdfs_daemonized.py` mounts **without**
`-f` and asserts read, write, metadata, the mount being live when the launcher
returns, a non-zero exit on an unreachable endpoint, and that the daemon
detaches from the terminal and cwd. Every I/O there runs behind a deadline that
detaches the mount before reaping, because the regression mode is an
uninterruptible read that `subprocess.run(timeout=…)` cannot recover from.


### 1U.14 What Ubuntu does not have

| AlmaLinux step | Ubuntu equivalent |
|---|---|
| `dnf install epel-release` + WLCG repo | Not needed — everything is in `main`/`universe` |
| `firewall-cmd` (§6) | `sudo ufw allow 1094/tcp` (see §6) |
| SELinux labels / `nginx-mod-brix-cache-selinux` (§9) | Nothing to do by default: Ubuntu uses AppArmor, and the `nginx` package ships **no** AppArmor profile, so nginx runs unconfined. If you add your own profile, grant read on the export and the host key |
| `voms-libs` | `libvomsapi1t64` |
| user/group `nginx` | user/group `www-data` |
| `/usr/lib64/nginx/modules` | `/usr/lib/nginx/modules` |
| `dist/*.rpm` | No `.deb` yet — build from source per this section |

---

## 3. Create a test PKI (skip if you have real grid certificates)

This section creates a self-signed CA, a host certificate for nginx, a user
certificate, and a short-lived proxy credential.  Everything is self-signed and
local — no external CA is involved.

### 3.1 Set up the working directory

```bash
PKI=/etc/grid-security/test-pki

sudo mkdir -p $PKI/{ca,server,user}
```

### 3.2 Create the test CA

```bash
sudo bash -c "cd $PKI/ca && \
    openssl genrsa -out ca.key 4096 && \
    chmod 400 ca.key && \
    openssl req -new -x509 \
        -key ca.key \
        -out ca.pem \
        -days 3650 \
        -subj '/DC=test/DC=example/CN=Test Grid CA' \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'subjectKeyIdentifier=hash' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign'"

# Create hash symlinks so OpenSSL and XRootD can find the CA by subject hash
sudo bash -c "cd $PKI/ca && \
    NEW_HASH=\$(openssl x509 -in ca.pem -noout -subject_hash) && \
    OLD_HASH=\$(openssl x509 -in ca.pem -noout -subject_hash_old) && \
    ln -sf ca.pem \${NEW_HASH}.0 && \
    ln -sf ca.pem \${OLD_HASH}.0 && \
    CA_DN='/DC=test/DC=example/CN=Test Grid CA' && \
    for HASH in \$NEW_HASH \$OLD_HASH; do
        printf 'access_id_CA    X509    \"%s\"\npos_rights      globus  CA:sign\ncond_subjects   globus  \"/DC=test/DC=example/*\"\n' \
            \"\$CA_DN\" > \${HASH}.signing_policy
    done"
```

### 3.3 Create the host certificate

The Common Name must match the hostname that clients will use in `root://hostname/`.

```bash
sudo bash -c "cd $PKI/server && \
    openssl genrsa -out hostkey.pem 2048 && \
    chmod 400 hostkey.pem && \
    openssl req -new \
        -key hostkey.pem \
        -out host.csr \
        -subj '/DC=test/DC=example/CN=$(hostname -f)' && \
    openssl x509 -req \
        -in host.csr \
        -CA $PKI/ca/ca.pem \
        -CAkey $PKI/ca/ca.key \
        -CAcreateserial \
        -out hostcert.pem \
        -days 365"

# nginx workers must read the host key. The worker user is `nginx` on AlmaLinux
# and `www-data` on Ubuntu/Debian — read it out of nginx.conf rather than guess.
NGINX_USER=$(awk '$1=="user"{print $2}' /etc/nginx/nginx.conf | tr -d ';')
sudo chmod 440 $PKI/server/hostkey.pem
sudo chgrp "$NGINX_USER" $PKI/server/hostkey.pem
```

Verify:

```bash
openssl verify -CAfile $PKI/ca/ca.pem $PKI/server/hostcert.pem
# hostcert.pem: OK
```

### 3.4 Create a user certificate

```bash
sudo bash -c "cd $PKI/user && \
    openssl genrsa -out userkey.pem 2048 && \
    chmod 400 userkey.pem && \
    openssl req -new \
        -key userkey.pem \
        -out user.csr \
        -subj '/DC=test/DC=example/CN=Test User/CN=12345' && \
    openssl x509 -req \
        -in user.csr \
        -CA $PKI/ca/ca.pem \
        -CAkey $PKI/ca/ca.key \
        -CAcreateserial \
        -out usercert.pem \
        -days 365"
```

### 3.5 Create an RFC 3820 proxy certificate

XRootD's GSI layer requires a proxy certificate (a short-lived credential
derived from the user certificate, with a `proxyCertInfo` extension).  The
`make_proxy.py` helper in this repository generates a conformant proxy:

```bash
# Install the cryptography library if not already present
pip3 install cryptography

python3 utils/make_proxy.py "$PKI"
# Writes: $PKI/user/proxy_std.pem  (proxy cert + user cert + proxy key, mode 0400)
```

Verify the proxy chain:

```bash
openssl x509 -in $PKI/user/proxy_std.pem -noout -subject -dates
openssl verify -CAfile $PKI/ca/ca.pem \
    -untrusted $PKI/user/usercert.pem \
    $PKI/user/proxy_std.pem
```

---

## 4. Create the data directory

```bash
# Worker user: `nginx` on AlmaLinux, `www-data` on Ubuntu/Debian.
NGINX_USER=$(awk '$1=="user"{print $2}' /etc/nginx/nginx.conf | tr -d ';')

sudo mkdir -p /srv/xrootd/data
sudo chown "$NGINX_USER":"$NGINX_USER" /srv/xrootd/data
sudo chmod 750 /srv/xrootd/data

# Seed a test file
echo "hello from nginx-xrootd" | sudo tee /srv/xrootd/data/hello.txt > /dev/null
```

---

## 5. Write the nginx configuration

**AlmaLinux** — create `/etc/nginx/conf.d/xrootd.conf`.
**Ubuntu/Debian** — put the two `server` blocks in
`/etc/nginx/streams-available/brix.conf` and the `thread_pool` line in the main
context of `nginx.conf`; the enclosing `stream {}` comes from §1U.7. Ubuntu's
`conf.d/` is included from inside `http {}` and will reject a stream server.

```nginx
# BriX-Cache: anonymous root:// + GSI-authenticated root://
# Serves files from /srv/xrootd/data on both listeners.

stream {
    # Thread pool for async file I/O.
    # Without this, a slow disk read blocks all connections on the worker.
    # NOTE: `thread_pool` itself is a MAIN-context directive — it belongs at the
    # top level of nginx.conf, outside stream {}. Shown here for proximity only.
    thread_pool xrootd_pool threads=8 max_queue=4096;

    # ── Port 1094: anonymous access (no credentials required) ──────────────
    server {
        listen 1094;
        brix_root on;
        brix_export /srv/xrootd/data;
        brix_thread_pool xrootd_pool;
        brix_access_log /var/log/nginx/xrootd_anon.log;
    }

    # ── Port 1095: GSI / x509 proxy-certificate authentication ─────────────
    server {
        listen 1095;
        brix_root on;
        brix_auth gsi;
        brix_allow_write on;
        brix_export /srv/xrootd/data;
        brix_thread_pool xrootd_pool;

        # Server identity presented to clients during the GSI DH exchange
        brix_certificate     /etc/grid-security/test-pki/server/hostcert.pem;
        brix_certificate_key /etc/grid-security/test-pki/server/hostkey.pem;

        # CA(s) trusted to vouch for client proxy certificates.
        # Point at the directory that contains the hash symlinks (§3.2).
        brix_trusted_ca      /etc/grid-security/test-pki/ca/ca.pem;

        brix_access_log /var/log/nginx/xrootd_gsi.log;
    }
}
```

> **Using real grid certificates?**
> Replace the `brix_certificate*` and `brix_trusted_ca` paths with your
> real host certificate, key, and the IGTF CA bundle (usually
> `/etc/grid-security/certificates/`).  Point `brix_trusted_ca` at the
> directory if it contains hash-named symlinks, or at a bundle `.pem` file.

### 5.1 Check the configuration

```bash
# The stream block must be at the top level, not inside http {}.
# The stream core module must be loaded. Confirm the loader snippets:
ls /etc/nginx/modules-enabled/          # AlmaLinux: mod-xrootd.conf
                                        # Ubuntu:    50-mod-stream.conf, 60-mod-brix-cache.conf

sudo nginx -t
# nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# nginx: configuration file /etc/nginx/nginx.conf test is successful
```

If `nginx -t` reports `unknown directive "brix_root"`, the module is not loaded.
Check that `/etc/nginx/nginx.conf` includes files from `modules-enabled/` or
add `include /etc/nginx/modules-enabled/*.conf;` at the top of `nginx.conf`. On
Ubuntu also confirm the load order (§1U.6) — the BriX snippet must sort after
`50-mod-stream.conf`.

---

## 6. Open firewall ports

**AlmaLinux (firewalld):**

```bash
sudo firewall-cmd --permanent --add-port=1094/tcp
sudo firewall-cmd --permanent --add-port=1095/tcp
sudo firewall-cmd --reload
```

**Ubuntu / Debian (ufw):**

```bash
sudo ufw allow 1094/tcp
sudo ufw allow 1095/tcp
sudo ufw reload      # no-op if ufw is inactive
```

---

## 7. Start nginx

```bash
sudo systemctl enable --now nginx
# or, if nginx is already running:
sudo systemctl reload nginx
```

Check that both ports are listening:

```bash
ss -tlnp | grep -E '1094|1095'
# LISTEN  0  128  0.0.0.0:1094  ...
# LISTEN  0  128  0.0.0.0:1095  ...
```

---

## 8. Test

Install the XRootD client tools if not already present:

```bash
sudo dnf install -y xrootd-client   # AlmaLinux — provides xrdcp, xrdfs
sudo apt install -y xrootd-client   # Ubuntu/Debian (universe) — same tools
```

### 8.1 Anonymous access (port 1094)

No credentials needed.

```bash
# List root directory
xrdfs root://localhost:1094 ls /

# Download the seeded file
xrdcp root://localhost:1094//hello.txt /tmp/hello_anon.txt
cat /tmp/hello_anon.txt
# hello from nginx-xrootd

# Upload a file
echo "anonymous upload" > /tmp/anon_upload.txt
xrdcp /tmp/anon_upload.txt root://localhost:1094//anon_upload.txt
```

> Anonymous upload only succeeds if the listener has `brix_allow_write on`.
> The port-1094 server in the example config above does **not** — add it if
> you want anonymous writes.

### 8.2 GSI-authenticated access (port 1095)

```bash
# Point the client at the proxy and CA bundle
export X509_USER_PROXY=/etc/grid-security/test-pki/user/proxy_std.pem
export X509_CERT_DIR=/etc/grid-security/test-pki/ca

# List the root
xrdfs root://localhost:1095 ls /

# Upload a file (allowed because brix_allow_write on)
echo "gsi upload" > /tmp/gsi_upload.txt
xrdcp /tmp/gsi_upload.txt root://localhost:1095//gsi_upload.txt

# Download it back
xrdcp root://localhost:1095//gsi_upload.txt /tmp/gsi_upload_back.txt
diff /tmp/gsi_upload.txt /tmp/gsi_upload_back.txt
# (no output = identical)

# Confirm the authenticated DN in the access log
sudo tail -5 /var/log/nginx/xrootd_gsi.log
```

The GSI access log line looks like:

```
127.0.0.1 gsi "/DC=test/DC=example/CN=Test User/CN=12345/CN=12346" \
    [14/Apr/2026:10:23:44 +0000] "OPEN /gsi_upload.txt" OK 0 12ms
```

### 8.3 Reject without a proxy (sanity check)

```bash
unset X509_USER_PROXY
xrdfs root://localhost:1095 ls /
# [ERROR] Server responded with an error: [3010] kXR_NotAuthorized ...
```

---

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| `unknown directive "brix_root"` | Module loader snippet not included in `nginx.conf` |
| `nginx -t` passes but port not open | SELinux or firewall blocking; check `ausearch -m AVC` + `firewall-cmd --list-all` (AlmaLinux), or `ufw status` (Ubuntu) |
| GSI: `kXR_NotAuthorized` | CA hash symlinks missing (§3.2), or `brix_trusted_ca` points at wrong path |
| GSI: `server cert not trusted` | Client does not trust the server's CA; set `X509_CERT_DIR` to the CA directory |
| GSI: `proxy certificate rejected` | Proxy not RFC 3820 — regenerate with `utils/make_proxy.py` |
| `Permission denied` on data directory | The worker user (`nginx` / `www-data`) cannot read/write the export; fix ownership (§4) |
| `hostkey.pem: permission denied` | The worker group cannot read the key; fix with `chmod 440` + `chgrp` (§3.3) |
| SELinux denying nginx reading the key | Install `nginx-mod-brix-cache-selinux` (labels `/etc/grid-security` as `cert_t`) then `restorecon -Rv /etc/grid-security`; full guide: docs/05-operations/selinux-hardening.md |

**Ubuntu / Debian only:**

| Symptom | Check |
|---|---|
| `module ... is not binary compatible` | Built without `--with-compat`, or against a different nginx version than the one installed — rebuild per §1U.3–§1U.6 |
| `unknown directive "brix_root"` | Loader snippet missing or misordered; it must sort **after** `50-mod-stream.conf` (§1U.6) |
| `"server" directive is not allowed here` on a stream server | Stream block put in `conf.d/`, which Ubuntu includes from inside `http {}` — use the top-level `stream {}` from §1U.7 |
| `undefined symbol:` on startup | A dev package was missing at configure time and the feature silently disabled, or the two `.so` files are from different builds — reinstall both (§1U.6) |
| `libvomsapi.so.1 not found` notice | `sudo apt install libvomsapi1t64` (not `libvomsapi1` — see §1U.2) |
| `thread pool "..." not found` notice | `thread_pool` must be in the **main** context of `nginx.conf`, not inside `stream {}` (§1U.7) |
| `E: You must put some 'deb-src' URIs` from `apt-get source` | Source repos not enabled (§1U.3) |

### Reading nginx error logs

```bash
sudo journalctl -u nginx -f
# or
sudo tail -f /var/log/nginx/error.log
```

The module logs GSI errors at `[error]` level and diagnostic notices at
`[notice]` level in the nginx error log.

---

## 10. Next steps

| Goal | Where to look |
|---|---|
| TLS-encrypted `root://` (protect file data in transit) | [docs/03-configuration/tls-config.md](docs/03-configuration/tls-config.md) — `brix_tls on` or `roots://` |
| WebDAV (`davs://`) over HTTPS | [docs/04-protocols/](docs/04-protocols/) |
| Token (JWT/WLCG bearer) authentication | [docs/06-authentication/auth-overview.md](docs/06-authentication/auth-overview.md) §Token |
| VO / FQAN ACLs with VOMS | [docs/06-authentication/auth-overview.md](docs/06-authentication/auth-overview.md) §VOMS, `brix_require_vo` |
| S3-compatible endpoint | [docs/03-configuration/directives.md](docs/03-configuration/directives.md) `brix_s3` |
| Prometheus metrics | [docs/08-metrics-monitoring/monitoring-guide.md](docs/08-metrics-monitoring/monitoring-guide.md) |
| CRL checking | [docs/03-configuration/directives.md](docs/03-configuration/directives.md) `brix_crl` |
| Production PKI (real IGTF/grid CA) | [docs/06-authentication/](docs/06-authentication/) |
