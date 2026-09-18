# Getting Started with macOS Support

**Phase 1: Platform Detection & Build System**

This document provides quick-start instructions for building BriX-Cache on macOS after the Phase 1 implementation.

## Prerequisites

### macOS Requirements

- **Minimum Version:** macOS 12.0 (Monterey)
- **Architecture:** x86_64 (Intel) or arm64 (Apple Silicon)
- **Disk Space:** ~500MB for build dependencies

### Install Homebrew

Homebrew is the recommended package manager for macOS:

```bash
/bin/bash -c "$(curl -fsSL https://brew.sh)"
```

### Install Dependencies

The module's `config` script locates every library through `pkg-config`
(with header-and-link fallbacks for a few). Two codecs are **mandatory**
(zstd, brotli) and OpenSSL must be 3.x; everything else is optional and
compiles to a stub when absent. Verified on macOS 15 (Intel, Homebrew at
`/usr/local`) on 2026-09-15.

**Required (module + nginx core):**

```bash
brew install pkgconf openssl@3 pcre2 zstd brotli jansson krb5
```

| Library | Formula | Notes |
|---|---|---|
| pkg-config | `pkgconf` | Used by `config` for every probe |
| OpenSSL >= 3.0 | `openssl@3` | `configure` refuses OpenSSL 1.1 |
| PCRE2 | `pcre2` | nginx core requirement |
| zstd | `zstd` | Mandatory codec (`BRIX_HAVE_ZSTD=1`) |
| brotli | `brotli` | Mandatory codec (`BRIX_HAVE_BROTLI=1`) |
| jansson | `jansson` | JSON (tokens, admin API) |
| MIT Kerberos | `krb5` | **Keg-only** — see the `PKG_CONFIG_PATH` step below |

**Optional:**

```bash
brew install xz lz4              # lzma and lz4 codecs
brew install --cask macfuse      # FUSE 3 for the client mounts (xrootdfs, brixMount)
brew install xrootd              # reference xrdcp/xrdfs for the differential tests
```

**Provided by the macOS SDK — do not install from Homebrew:** zlib, bzip2,
libxml2, libcurl and sqlite3 all resolve through Homebrew's SDK `pkg-config`
shim. The formulae `zlib`, `bzip2`, `libxml2`, `curl` and `sqlite` are
keg-only, so installing them changes nothing unless you also add them to
`PKG_CONFIG_PATH`. Only do that if you need a newer version than the SDK ships.

**Linux-only — no Homebrew equivalent, nothing to install:** liburing,
libseccomp and the Ceph stack (librados, libradosstriper, libcephfs).
`config` detects their absence and disables io_uring, seccomp and the Ceph
backend automatically. See *Known Limitations* below.

### Kerberos: point pkg-config at the keg-only krb5

Homebrew's `krb5` is keg-only, so its `.pc` files are not on the default
`pkg-config` path. Without this step `config` falls back to Apple's Heimdal
`/usr/bin/krb5-config`, which emits only `-lkrb5` and none of the MIT GSSAPI
libraries the plugin links against, and the link fails on `gss_*` symbols.
Export this before running `./configure` (and before `make -C client`):

```bash
export PKG_CONFIG_PATH="$(brew --prefix krb5)/lib/pkgconfig"
```

Check that every probe resolves before configuring:

```bash
for p in openssl libpcre2-8 libzstd libbrotlienc libbrotlidec jansson \
         krb5 krb5-gssapi libxml-2.0 libcurl zlib bzip2 sqlite3 liblzma liblz4 fuse3; do
  pkg-config --exists "$p" && echo "ok      $p $(pkg-config --modversion "$p")" \
                           || echo "MISSING $p"
done
```

Expected: everything `ok` except `liblzma`/`liblz4`/`fuse3` if you skipped
the optional formulae.

With the MIT keg selected, configure prints `Kerberos 5 vendor MIT (GSS
credential import enabled)` and the forwarded-TGT capture (`brix_krb5_delegate`)
works exactly as on Linux. Against Apple's system Kerberos (Heimdal) that line
reads `non-MIT` and delegated credentials are not captured: the PAL keys
`BRIX_HAS_GSS_KRB5_IMPORT_CRED` on the vendor `configure` detected, not on the
OS. The test realm's `kinit`/`klist` must be the MIT pair too (the harness
resolves them through `kdc_helpers.krb5_tool()`; Apple's `klist` has no `-f`).

## Build Instructions

### Standard Build

The module is built into an upstream nginx source tree, exactly as on Linux
(BUILD.md §1d). There is no `./configure` at the repository root.

```bash
# 1. Fetch an nginx source tree (1.28.x is the validated series)
curl -fsSLO https://nginx.org/download/nginx-1.28.3.tar.gz
tar -xzf nginx-1.28.3.tar.gz -C /tmp
cd /tmp/nginx-1.28.3

# 2. Point pkg-config at Homebrew's keg-only krb5 (see above)
export PKG_CONFIG_PATH="$(brew --prefix krb5)/lib/pkgconfig"

# 3. Configure with the module (same option set as the Linux dev flow)
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-http_auth_request_module --with-threads \
  --add-module=/path/to/brix-cache

# 4. Build with every core
make -j"$(sysctl -n hw.ncpu)"

# 5. Test configuration
objs/nginx -t
```

Build the native client tools from the repository root with the same
`PKG_CONFIG_PATH` exported:

```bash
make -C client -j"$(sysctl -n hw.ncpu)"
```

`client/bin/xrdcp` must exist afterwards or client-dependent tests are
skipped. The FUSE binaries (`xrootdfs`, `brixMount` and its `brixcvmfs` /
`brixoci` / `brixrpm` personalities) are built only when `fuse3.pc` resolves,
i.e. when macFUSE is installed; they mount through `mount_macfuse` and the
owner unmounts with plain `umount` (there is no `fusermount3` on macOS, and
`xrd unmount` / brixautofs know that). `make -C client test` runs the C unit
suite and `make -C client install-bin DESTDIR=...` stages the same binaries
as on Linux.

### What the client build produces on macOS

| Artifact | macOS | Notes |
|---|---|---|
| `xrd`, `xrdfs`, `xrdcp`, `xrdcksum` (+ links), `xrdprep`, `xrdgsiproxy`, `xrdgsitest`, `xrdsssadmin-brix`, `xrddiag` (+ links), `xrdmapc`, `xrdstorascan`, `brix-fault-proxy` | ✅ | Built and installed exactly as on Linux. |
| `xrootdfs`, `brixMount`, `brixcvmfs`, `brixoci`, `brixrpm` | ✅ with macFUSE | `brew install --cask macfuse`; unmount with `umount`. The drivers add `-o noappledouble` themselves (macFUSE's `._name` sidecars would otherwise fail every write with ENXIO on a staging filesystem); `mknod(2)` of a regular file is root-only on XNU, and brixautofs's idle expiry (`MNT_EXPIRE`) is Linux-only and disables itself. |
| `libbrix.dylib` (+ `libbrix.a`, `libbrix.pc`) | ✅ | `make -C client lib`; versioned as `libbrix.0.1.0.dylib`. |
| `libbrixposix_preload.dylib` | ✅ | Inserted with `DYLD_INSERT_LIBRARIES` instead of `LD_PRELOAD`; SIP keeps it out of Apple-signed binaries (`/bin/cat`, `/usr/bin/python3`), so drive Homebrew tools, a venv python or your own programs. |
| `brix-fault-proxy --privileged`, `--priv-iface` levers | ⚠️ | The userland fault levers work; the root-only `netem` / `cut` levers shell out to `tc` and `nft`, which do not exist here (the MTU lever uses ioctls and works). |
| `xrdrados_rescue`, `xrdcephfs_rescue`, `xrdceph_*migrate*` | ❌ | Need librados / libcephfs headers, which Homebrew does not ship. |
| `install-automount` | ❌ | Installs a systemd unit; run `brixMount autofs` as a plain daemon (or under launchd) instead. |

### Custom Build Options

```bash
# Force-disable the Ceph probe even if librados headers are somehow present
# (io_uring and seccomp are already off: neither library exists on macOS)
BRIX_WITHOUT_CEPH=1 \
./configure --with-stream --with-threads --add-module=/path/to/brix-cache

# lz4 from a non-Homebrew prefix (Homebrew's lz4 is found via pkg-config,
# so this is only needed for e.g. a conda install)
BRIX_LZ4_CFLAGS="-I/other/prefix/include" \
BRIX_LZ4_LIBS="-L/other/prefix/lib -llz4" \
./configure --with-stream --with-threads --add-module=/path/to/brix-cache
```

### Build Output

Expected output during configure (lines printed by the module's `config`;
io_uring is silent when absent):

```
 + xrootd: macOS PAL enabled
 + xrootd: macOS frameworks: -framework Accelerate -framework CoreFoundation -framework SystemConfiguration
 + xrootd: Linux-specific hardening flags disabled on macOS
 + xrootd auth: Kerberos 5 plugin enabled (pkg-config)
 + xrootd: seccomp syscall filter disabled (install libseccomp-devel to enable)
 + xrootd compression: zstd enabled (required)
 + xrootd compression: xz/lzma enabled
 + xrootd compression: brotli enabled (required)
 + xrootd compression: bzip2 enabled (pkg-config)
 + xrootd compression: lz4 enabled (pkg-config)
 + xrootd storage backend: ceph/rados disabled (install librados-devel to enable)
 + xrootd: OpenSSL 3.6.4 (>= 3.0.0, Apache-2.0) OK
```

The Kerberos line must say `(pkg-config)`. If it says `(krb5-config)` the
Heimdal fallback was used; export `PKG_CONFIG_PATH` as described above and
re-run `./configure`.

## Verification

### Check Platform Detection

```bash
objs/nginx -V 2>&1 | grep -i "brix"
```

Expected output should include platform information.

### Run Verification Script

```bash
./verify_macos_support.sh
```

This checks that all platform files are present and correctly configured.

### Test Module Load

```bash
objs/nginx -t
```

Expected output:
```
nginx: configuration file test successful
```

## Known Limitations

### Darwin arms that used to be stubs (fixed 2026-09-15)

Older revisions carried `#if !defined(__APPLE__)` stubs that compiled but
did nothing on macOS: the WebDAV postconfiguration installed no phase
handlers (every HTTP request fell through to nginx's static 404), the
confined-open primitive was a bare `openat(2)` (no path confinement), and
the atomic renames failed with `ENOTSUP`. All three now run the real code
on Darwin; if a rebuilt module answers WebDAV requests with a plain nginx
404 page while `nginx -t` is clean, you are running a binary from before
that change. See BUILD.md §12e for the full list.

### Feature Differences from Linux

| Feature | Linux | macOS | Impact |
|---------|-------|-------|--------|
| io_uring async I/O | ✅ Full support | ❌ Thread pool fallback | ~15-20% throughput reduction on large reads |
| seccomp-bpf | ✅ Full support | ❌ Phase 4 (sandbox_exec) | Relies on macOS SIP/Gatekeeper |
| CephFS backend | ✅ Full support | ❌ Not available | Use S3 backend or Ceph NFS gateway |
| splice() zero-copy | ✅ Full support | ⚠️ Buffered copy | ~30-40% reduction for large proxy transfers |
| posix_fadvise | ✅ Full support | ⚠️ No-op (XNU lacks API) | Minimal - kernel uses adaptive readahead |
| sendfile() | ✅ Standard | ✅ With translation | Equivalent performance (wrapper handles signature differences) |
| clonefile() | ❌ Not available | ✅ APFS fast clone | Faster than copy when available |

### Performance Considerations

1. **Async I/O**: macOS uses nginx thread pool instead of io_uring
   - Impact: ~15-20% reduction in throughput for large sequential reads
   - Mitigation: Increase thread pool size in nginx.conf

2. **Zero-Copy Proxy**: macOS uses buffered copy instead of splice()
   - Impact: ~30-40% reduction for large transfers (>100MB)
   - Mitigation: Use sendfile() for file-to-socket transfers (handled by nginx core)

3. **File Access Hints**: posix_fadvise() is a no-op
   - Impact: Minimal - macOS XNU kernel uses adaptive readahead
   - No action needed

## Configuration Example

### nginx.conf for macOS

```nginx
worker_processes auto;
worker_rlimit_nofile 65536;

events {
    worker_connections 4096;
    use kqueue;  # nginx auto-detects kqueue on macOS
}

thread_pool brix_aio threads=8 max_queue=65536;

stream {
    server {
        listen 10999;
        
        # Serve local files through the native protocol
        brix_root on;
        brix_export /data;
        brix_storage_backend posix:/data/storage;
        
        # Cache configuration
        brix_cache_store posix:/data/cache;
        brix_cache_export /data;
        
        # Thread pool for async I/O (macOS uses this instead of io_uring)
        brix_thread_pool brix_aio;
    }
}
```

## Troubleshooting

### Every Stock XRootD Tool (or pyxrootd Import) Stalls for 30 Seconds

**Symptom:** `xrdfs`, `xrdcp`, `xrootd`, `cmsd` and `python -c "import
XRootD.client"` each take 30 s before doing anything; test-suite probes
report "no Python interpreter with real XRootD bindings found" or stock
`xrdfs` commands time out.

**Cause:** libXrdUtils resolves the host's identity in a static initialiser
(`XrdNetIdentity`) by reverse-resolving the primary interface address. On a
Mac whose LAN address has no PTR record, macOS's resolver waits the full 30 s,
uncached, in every process. `sample` on a stalled process shows
`XrdNetAddrInfo::Resolve` → `getnameinfo` → `mdns_hostbyaddr`.

**Solution:** XRootD's own short-circuit is the `XRDNET_IDENTITY` environment
variable. The test harness sets `XRDNET_IDENTITY=localhost` on Darwin
(`tests/lib_py/host_env.py`, from `conftest.py` and
`cmdscripts.manage_test_servers`); export it yourself for ad-hoc tool use:
```bash
export XRDNET_IDENTITY=localhost
```
A PTR record for the address (or an `/etc/hosts` entry) removes the stall
for every consumer, but needs root and tracks DHCP changes.

### Configure Does Not Print "macOS PAL enabled"

**Symptom:** the configure output lacks the `+ xrootd: macOS PAL enabled`
line, or the build later fails on Linux-only headers.

**Cause:** `config` selects the platform from `uname -s`. Anything other
than `Darwin` is treated as Linux/POSIX. This only happens under an
emulation layer or a misconfigured shell.

**Solution:**
```bash
uname -s            # must print Darwin
sw_vers -productVersion   # 12.0 or later
```

### Configure Fails with "zstd is required" or "brotli is required"

**Symptom:**
```
 + xrootd compression: zstd is required; install libzstd-dev (Debian/Ubuntu) or libzstd-devel (RHEL/Fedora)
```

**Cause:** the mandatory codec's `.pc` file is not visible to `pkg-config`.
Either the formula is missing or `pkg-config` itself is not the Homebrew
`pkgconf` (Xcode's Command Line Tools do not ship one).

**Solution:**
```bash
brew install pkgconf zstd brotli
pkg-config --modversion libzstd libbrotlienc   # both must print a version
```

### Missing Dependencies

**Symptom:**
```
ERROR: jansson library is required but was not found.
Install jansson-devel (RHEL/CentOS) or libjansson-dev (Debian/Ubuntu).
```

**Solution:**
```bash
# Install the required set (libxml2 and libcurl come from the macOS SDK)
brew install pkgconf openssl@3 pcre2 zstd brotli jansson krb5
export PKG_CONFIG_PATH="$(brew --prefix krb5)/lib/pkgconfig"
```

### Link Fails with Undefined `gss_*` Symbols

**Symptom:**
```
Undefined symbols for architecture x86_64:
  "_gss_accept_sec_context", referenced from: ...
```
or configure prints `Kerberos 5 plugin enabled (krb5-config)` instead of
`(pkg-config)`.

**Cause:** `PKG_CONFIG_PATH` was not exported, so `config` fell back to
Apple's Heimdal `/usr/bin/krb5-config`, which does not provide the MIT
GSSAPI libraries.

**Solution:**
```bash
export PKG_CONFIG_PATH="$(brew --prefix krb5)/lib/pkgconfig"
./configure ...   # re-run configure, then make
```

### Module Fails to Load

**Symptom:**
```
nginx: [emerg] dlopen("/usr/local/lib/nginx/modules/ngx_stream_brix_module.so") failed
  Library not loaded: @rpath/libssl.3.dylib
```

**Cause:** Dynamic library paths not resolved

**Solution:**
```bash
# Rebuild with explicit library paths
export LDFLAGS="-L$(brew --prefix)/lib"
export CPPFLAGS="-I$(brew --prefix)/include"

./configure --with-stream --with-threads --add-module=/path/to/brix-cache
make clean
make -j$(sysctl -n hw.ncpu)
```

### Performance Issues

**Symptom:** Lower throughput than expected on macOS

**Solutions:**

1. **Increase thread pool size:**
   ```nginx
   thread_pool brix_aio threads=16 max_queue=65536;
   ```

2. **Enable sendfile in nginx:**
   ```nginx
   http {
       sendfile on;
       tcp_nopush on;
   }
   ```

3. **Use APFS for storage:**
   - APFS supports fast clone operations
   - Better performance for copy operations

## Next Steps

### Phase 2 Implementation (Coming Soon)

- Filesystem monitoring (FSEvents integration)
- Improved async I/O handling
- Security wrapper (sandbox_exec stub)

### Testing

Run the platform checks from the repository root:

```bash
# Run integration tests
PYTHONPATH=tests python3 -m pytest tests/platform/ -v

# Performance benchmarks
./tools/benchmark/macos_perf_test.sh
```

#### The whole suite

The suite drives a ~125-member server fleet, so it wants the module binary,
the native client tools and a few host settings:

```bash
pip install -r requirements-optional.txt     # unskips ~150 tests
export PYTHONPATH=tests:brixtest/src
export TEST_NGINX_BIN=/path/to/nginx-1.28.3/objs/nginx
export TEST_BUDGET_SCALE=5      # wall-clock multiplier: this host is slower
export TEST_READY_TIMEOUT=30    # server readiness wait (default 10 s)
export BRIX_PLAT_FSYNC_FULL=0   # F_FULLFSYNC costs ~28 ms/file; cache-level
                                # fsync is enough for a test host
cd tests && python3 -m cmdscripts.operator_runtime suite --fast -n 8 -- -x
```

`TEST_BUDGET_SCALE` stretches every budget that reads it
(`lib_py.util.budget_scale`), which is what a laptop running eight workers
needs; leave it unset on a CI host.

Two host settings decide how much of the suite can run at all:

| Setting | Effect if absent |
|---|---|
| `sudo ifconfig lo0 alias 127.0.0.2 up` | ~64 tests skip. Linux routes all of 127.0.0.0/8 to `lo`; macOS assigns only 127.0.0.1, so a test needing a second client identity or a distinct origin host has nothing to bind. Not persistent across reboots. |
| `brew install --cask macfuse` | Every FUSE mount test skips (`lib_py/fuse_host.py` probes for the bundle). |

Timing budgets that only mean something on an idle machine carry
`@pytest.mark.serial`, so `--fast` skips them and `suite --pr` runs them in
its serial lane.

## References

- Full specification: `docs/refactor/macos-support-v3.0.md`
- Platform API documentation: `src/platform/README.md`
- Implementation status: `docs/platform/macos/reports/MACOS_IMPLEMENTATION_STATUS.md`
- Build configuration: `config` (lines 7-60)

## Support

For issues or questions:

1. Check `docs/09-developer-guide/agent-guide-extended.md`
2. Review `docs/platform/macos/reports/MACOS_IMPLEMENTATION_STATUS.md` for known issues
3. Run `./verify_macos_support.sh` for diagnostics
