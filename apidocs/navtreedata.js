/*
 @licstart  The following is the entire license notice for the JavaScript code in this file.

 The MIT License (MIT)

 Copyright (C) 1997-2020 by Dimitri van Heesch

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or
 substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 @licend  The above is the entire license notice for the JavaScript code in this file
*/
var NAVTREE =
[
  [ "nginx-xrootd", "index.html", [
    [ "nginx idioms for C++ reviewers", "index.html", "index" ],
    [ "src/auth/authz/acc — XrdAcc-compatible authorization engine", "md_src_2auth_2authz_2acc_2README.html", [
      [ "What it adds over <tt>native</tt>", "md_src_2auth_2authz_2acc_2README.html#autotoc_md1", null ],
      [ "Files", "md_src_2auth_2authz_2acc_2README.html#autotoc_md2", null ],
      [ "Reference", "md_src_2auth_2authz_2acc_2README.html#autotoc_md3", null ]
    ] ],
    [ "authz — path-level authorization: ACL rules, authdb, and the auth gate", "md_src_2auth_2authz_2README.html", [
      [ "Overview", "md_src_2auth_2authz_2README.html#autotoc_md5", null ],
      [ "Files", "md_src_2auth_2authz_2README.html#autotoc_md6", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2authz_2README.html#autotoc_md7", null ],
      [ "See also", "md_src_2auth_2authz_2README.html#autotoc_md8", null ]
    ] ],
    [ "crypto — shared OpenSSL X.509 / PKI core for GSI and WebDAV certificate auth", "md_src_2auth_2crypto_2README.html", [
      [ "Overview", "md_src_2auth_2crypto_2README.html#autotoc_md10", null ],
      [ "Files", "md_src_2auth_2crypto_2README.html#autotoc_md11", null ],
      [ "Key types & data structures", "md_src_2auth_2crypto_2README.html#autotoc_md12", null ],
      [ "Control & data flow", "md_src_2auth_2crypto_2README.html#autotoc_md13", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2crypto_2README.html#autotoc_md14", null ],
      [ "Entry points / extending", "md_src_2auth_2crypto_2README.html#autotoc_md15", null ],
      [ "See also", "md_src_2auth_2crypto_2README.html#autotoc_md16", null ]
    ] ],
    [ "gsi — XRootD <tt>kXR_auth</tt> dispatcher and GSI/x509 proxy-certificate authentication", "md_src_2auth_2gsi_2README.html", [
      [ "Overview", "md_src_2auth_2gsi_2README.html#autotoc_md18", null ],
      [ "Files", "md_src_2auth_2gsi_2README.html#autotoc_md19", null ],
      [ "Key types & data structures", "md_src_2auth_2gsi_2README.html#autotoc_md20", null ],
      [ "Control & data flow", "md_src_2auth_2gsi_2README.html#autotoc_md21", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2gsi_2README.html#autotoc_md22", null ],
      [ "Entry points / extending", "md_src_2auth_2gsi_2README.html#autotoc_md23", null ],
      [ "See also", "md_src_2auth_2gsi_2README.html#autotoc_md24", null ]
    ] ],
    [ "GSI GSSAPI Accept Engine", "md_src_2auth_2gssapi_2README.html", null ],
    [ "host — host-based authentication for the <tt>root://</tt> stream protocol", "md_src_2auth_2host_2README.html", [
      [ "Overview", "md_src_2auth_2host_2README.html#autotoc_md27", null ],
      [ "Files", "md_src_2auth_2host_2README.html#autotoc_md28", null ]
    ] ],
    [ "<tt>src/auth/impersonate/</tt> — per-request UNIX impersonation (phase 40)", "md_src_2auth_2impersonate_2README.html", [
      [ "Operating modes (<tt>brix_impersonation off|single|map</tt>)", "md_src_2auth_2impersonate_2README.html#autotoc_md30", null ],
      [ "Architecture", "md_src_2auth_2impersonate_2README.html#autotoc_md31", null ],
      [ "Files", "md_src_2auth_2impersonate_2README.html#autotoc_md32", null ],
      [ "How a request routes through it", "md_src_2auth_2impersonate_2README.html#autotoc_md33", null ],
      [ "Safety invariants", "md_src_2auth_2impersonate_2README.html#autotoc_md34", null ],
      [ "Tests", "md_src_2auth_2impersonate_2README.html#autotoc_md35", null ]
    ] ],
    [ "krb5 — Kerberos 5 authentication for the <tt>root://</tt> stream protocol", "md_src_2auth_2krb5_2README.html", [
      [ "Overview", "md_src_2auth_2krb5_2README.html#autotoc_md37", null ],
      [ "Files", "md_src_2auth_2krb5_2README.html#autotoc_md38", null ],
      [ "Key types & data structures", "md_src_2auth_2krb5_2README.html#autotoc_md39", null ],
      [ "Control & data flow", "md_src_2auth_2krb5_2README.html#autotoc_md40", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2krb5_2README.html#autotoc_md41", null ],
      [ "Entry points / extending", "md_src_2auth_2krb5_2README.html#autotoc_md42", null ],
      [ "See also", "md_src_2auth_2krb5_2README.html#autotoc_md43", null ]
    ] ],
    [ "pwd — password (<tt>XrdSecpwd</tt>) authentication for the <tt>root://</tt> stream protocol", "md_src_2auth_2pwd_2README.html", [
      [ "Overview", "md_src_2auth_2pwd_2README.html#autotoc_md45", null ],
      [ "The two-round exchange", "md_src_2auth_2pwd_2README.html#autotoc_md46", null ],
      [ "Files", "md_src_2auth_2pwd_2README.html#autotoc_md47", null ]
    ] ],
    [ "auth — identity and authorization", "md_src_2auth_2README.html", null ],
    [ "S3 STS Credential Exchange", "md_src_2auth_2s3_2README.html", null ],
    [ "sss — Simple Shared Secret authentication (Blowfish-CFB64 + CRC32)", "md_src_2auth_2sss_2README.html", [
      [ "Overview", "md_src_2auth_2sss_2README.html#autotoc_md51", null ],
      [ "Files", "md_src_2auth_2sss_2README.html#autotoc_md52", null ],
      [ "Key types & data structures", "md_src_2auth_2sss_2README.html#autotoc_md53", null ],
      [ "Control & data flow", "md_src_2auth_2sss_2README.html#autotoc_md54", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2sss_2README.html#autotoc_md55", null ],
      [ "Entry points / extending", "md_src_2auth_2sss_2README.html#autotoc_md56", null ],
      [ "See also", "md_src_2auth_2sss_2README.html#autotoc_md57", null ]
    ] ],
    [ "token — WLCG/SciToken JWT and macaroon bearer-token validation", "md_src_2auth_2token_2README.html", [
      [ "Overview", "md_src_2auth_2token_2README.html#autotoc_md59", null ],
      [ "Files", "md_src_2auth_2token_2README.html#autotoc_md60", null ],
      [ "Key types & data structures", "md_src_2auth_2token_2README.html#autotoc_md61", null ],
      [ "Control & data flow", "md_src_2auth_2token_2README.html#autotoc_md62", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2token_2README.html#autotoc_md63", null ],
      [ "Entry points / extending", "md_src_2auth_2token_2README.html#autotoc_md64", null ],
      [ "See also", "md_src_2auth_2token_2README.html#autotoc_md65", null ]
    ] ],
    [ "unix — XRootD <tt>unix</tt> (UNIX-name) authentication handler", "md_src_2auth_2unix_2README.html", [
      [ "Overview", "md_src_2auth_2unix_2README.html#autotoc_md67", null ],
      [ "Files", "md_src_2auth_2unix_2README.html#autotoc_md68", null ],
      [ "Key types & data structures", "md_src_2auth_2unix_2README.html#autotoc_md69", null ],
      [ "Control & data flow", "md_src_2auth_2unix_2README.html#autotoc_md70", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2unix_2README.html#autotoc_md71", null ],
      [ "Entry points / extending", "md_src_2auth_2unix_2README.html#autotoc_md72", null ],
      [ "See also", "md_src_2auth_2unix_2README.html#autotoc_md73", null ]
    ] ],
    [ "voms — Optional VOMS virtual-organisation extraction from X.509 proxies", "md_src_2auth_2voms_2README.html", [
      [ "Overview", "md_src_2auth_2voms_2README.html#autotoc_md75", null ],
      [ "Files", "md_src_2auth_2voms_2README.html#autotoc_md76", null ],
      [ "Key types & data structures", "md_src_2auth_2voms_2README.html#autotoc_md77", null ],
      [ "Control & data flow", "md_src_2auth_2voms_2README.html#autotoc_md78", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2voms_2README.html#autotoc_md79", null ],
      [ "Entry points / extending", "md_src_2auth_2voms_2README.html#autotoc_md80", null ],
      [ "See also", "md_src_2auth_2voms_2README.html#autotoc_md81", null ]
    ] ],
    [ "aio — Thread-pool async file I/O and shared response-chain builders", "md_src_2core_2aio_2README.html", [
      [ "Overview", "md_src_2core_2aio_2README.html#autotoc_md83", null ],
      [ "Optional io_uring backend (Phase 44 — <tt>uring.c</tt> / <tt>uring_submit.c</tt> / <tt>uring_admin.c</tt>)", "md_src_2core_2aio_2README.html#autotoc_md84", null ],
      [ "Thread-pool contract", "md_src_2core_2aio_2README.html#autotoc_md85", null ],
      [ "Files", "md_src_2core_2aio_2README.html#autotoc_md86", null ],
      [ "Key types & data structures", "md_src_2core_2aio_2README.html#autotoc_md87", null ],
      [ "Control & data flow", "md_src_2core_2aio_2README.html#autotoc_md88", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2aio_2README.html#autotoc_md89", null ],
      [ "Entry points / extending", "md_src_2core_2aio_2README.html#autotoc_md90", null ],
      [ "See also", "md_src_2core_2aio_2README.html#autotoc_md91", null ]
    ] ],
    [ "compat — Cross-protocol shared primitives (checksums, paths, filesystem, SSRF)", "md_src_2core_2compat_2README.html", [
      [ "Overview", "md_src_2core_2compat_2README.html#autotoc_md93", null ],
      [ "Files", "md_src_2core_2compat_2README.html#autotoc_md94", [
        [ "Checksums & hex", "md_src_2core_2compat_2README.html#autotoc_md95", null ],
        [ "HTTP-adjacent primitives", "md_src_2core_2compat_2README.html#autotoc_md96", null ],
        [ "Filesystem & namespace mutation", "md_src_2core_2compat_2README.html#autotoc_md97", null ],
        [ "Networking, async, time, logging, SHM", "md_src_2core_2compat_2README.html#autotoc_md98", null ]
      ] ],
      [ "Key types & data structures", "md_src_2core_2compat_2README.html#autotoc_md99", null ],
      [ "Control & data flow", "md_src_2core_2compat_2README.html#autotoc_md100", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2compat_2README.html#autotoc_md101", null ],
      [ "Entry points / extending", "md_src_2core_2compat_2README.html#autotoc_md102", null ],
      [ "See also", "md_src_2core_2compat_2README.html#autotoc_md103", null ]
    ] ],
    [ "config — directive lifecycle, startup validation, and per-worker resource init", "md_src_2core_2config_2README.html", [
      [ "Overview", "md_src_2core_2config_2README.html#autotoc_md105", null ],
      [ "Files", "md_src_2core_2config_2README.html#autotoc_md106", null ],
      [ "Key types & data structures", "md_src_2core_2config_2README.html#autotoc_md107", null ],
      [ "Control & data flow", "md_src_2core_2config_2README.html#autotoc_md108", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2config_2README.html#autotoc_md109", null ],
      [ "Entry points / extending", "md_src_2core_2config_2README.html#autotoc_md110", null ],
      [ "See also", "md_src_2core_2config_2README.html#autotoc_md111", null ]
    ] ],
    [ "http — Shared HTTP request/response semantics (headers, body, conditionals, ETag)", "md_src_2core_2http_2README.html", [
      [ "Overview", "md_src_2core_2http_2README.html#autotoc_md113", null ],
      [ "Files", "md_src_2core_2http_2README.html#autotoc_md114", null ],
      [ "Boundary — what stays in <tt>../compat</tt>", "md_src_2core_2http_2README.html#autotoc_md115", null ],
      [ "Control & data flow", "md_src_2core_2http_2README.html#autotoc_md116", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2http_2README.html#autotoc_md117", null ],
      [ "Entry points / extending", "md_src_2core_2http_2README.html#autotoc_md118", null ],
      [ "See also", "md_src_2core_2http_2README.html#autotoc_md119", null ]
    ] ],
    [ "Negative-Path Backoff (negcache)", "md_src_2core_2negcache_2README.html", null ],
    [ "core — platform primitives shared by every plane", "md_src_2core_2README.html", null ],
    [ "Worker seccomp-BPF Syscall Filter", "md_src_2core_2seccomp_2README.html", null ],
    [ "shm — generic cross-worker key/value store and token-bucket rate limiter in nginx shared memory", "md_src_2core_2shm_2README.html", [
      [ "Overview", "md_src_2core_2shm_2README.html#autotoc_md124", null ],
      [ "Files", "md_src_2core_2shm_2README.html#autotoc_md125", null ],
      [ "Key types & data structures", "md_src_2core_2shm_2README.html#autotoc_md126", null ],
      [ "Control & data flow", "md_src_2core_2shm_2README.html#autotoc_md127", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2shm_2README.html#autotoc_md128", null ],
      [ "Entry points / extending", "md_src_2core_2shm_2README.html#autotoc_md129", null ],
      [ "See also", "md_src_2core_2shm_2README.html#autotoc_md130", null ]
    ] ],
    [ "src/core/types — Core type definitions, tunables, and the canonical identity object", "md_src_2core_2types_2README.html", [
      [ "Overview", "md_src_2core_2types_2README.html#autotoc_md132", null ],
      [ "Files", "md_src_2core_2types_2README.html#autotoc_md133", null ],
      [ "Key types & data structures", "md_src_2core_2types_2README.html#autotoc_md134", null ],
      [ "Control & data flow", "md_src_2core_2types_2README.html#autotoc_md135", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2types_2README.html#autotoc_md136", null ],
      [ "Entry points / extending", "md_src_2core_2types_2README.html#autotoc_md137", null ],
      [ "See also", "md_src_2core_2types_2README.html#autotoc_md138", null ]
    ] ],
    [ "fs/backend — Storage Driver (SD) layer", "md_src_2fs_2backend_2README.html", [
      [ "Status — POSIX driver mediates the VFS handle data plane + lifecycle", "md_src_2fs_2backend_2README.html#autotoc_md140", null ],
      [ "Layout — one subdirectory per driver", "md_src_2fs_2backend_2README.html#autotoc_md141", null ],
      [ "Files", "md_src_2fs_2backend_2README.html#autotoc_md142", null ],
      [ "Contract", "md_src_2fs_2backend_2README.html#autotoc_md143", null ],
      [ "Adding a driver", "md_src_2fs_2backend_2README.html#autotoc_md144", null ],
      [ "See also", "md_src_2fs_2backend_2README.html#autotoc_md145", null ]
    ] ],
    [ "<tt>src/fs/cache/origin/</tt> — pluggable origin transports for the read-through cache", "md_src_2fs_2cache_2origin_2README.html", [
      [ "Overview", "md_src_2fs_2cache_2origin_2README.html#autotoc_md147", null ],
      [ "Files", "md_src_2fs_2cache_2origin_2README.html#autotoc_md148", null ],
      [ "Invariants", "md_src_2fs_2cache_2origin_2README.html#autotoc_md149", null ],
      [ "See also", "md_src_2fs_2cache_2origin_2README.html#autotoc_md150", null ]
    ] ],
    [ "<tt>src/fs/cache/</tt> — XCache-style read-through cache and write-through origin mirroring", "md_src_2fs_2cache_2README.html", [
      [ "Overview", "md_src_2fs_2cache_2README.html#autotoc_md152", null ],
      [ "Files", "md_src_2fs_2cache_2README.html#autotoc_md153", [
        [ "Read-through entry points & lifecycle", "md_src_2fs_2cache_2README.html#autotoc_md154", null ],
        [ "Slice cache (Phase 26)", "md_src_2fs_2cache_2README.html#autotoc_md155", null ],
        [ "Origin protocol client (thread-pool, blocking)", "md_src_2fs_2cache_2README.html#autotoc_md156", null ],
        [ "Integrity (checksum-on-fill)", "md_src_2fs_2cache_2README.html#autotoc_md157", null ],
        [ "Cache filesystem bookkeeping", "md_src_2fs_2cache_2README.html#autotoc_md158", null ],
        [ "Eviction", "md_src_2fs_2cache_2README.html#autotoc_md159", null ],
        [ "Unified state engine & parity", "md_src_2fs_2cache_2README.html#autotoc_md160", null ],
        [ "Write-through", "md_src_2fs_2cache_2README.html#autotoc_md161", null ],
        [ "Cache storage on a driver (exclusively-VFS)", "md_src_2fs_2cache_2README.html#autotoc_md162", null ],
        [ "Shared / config / build", "md_src_2fs_2cache_2README.html#autotoc_md163", null ]
      ] ],
      [ "Key types & data structures", "md_src_2fs_2cache_2README.html#autotoc_md164", null ],
      [ "Control & data flow", "md_src_2fs_2cache_2README.html#autotoc_md165", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2cache_2README.html#autotoc_md166", null ],
      [ "Entry points / extending", "md_src_2fs_2cache_2README.html#autotoc_md167", null ],
      [ "See also", "md_src_2fs_2cache_2README.html#autotoc_md168", null ]
    ] ],
    [ "src/fs/core — the shared <tt>vfs</tt> I/O verb layer", "md_src_2fs_2core_2README.html", null ],
    [ "meta — unified per-file metadata sidecar (xmeta)", "md_src_2fs_2meta_2README.html", [
      [ "Overview", "md_src_2fs_2meta_2README.html#autotoc_md171", null ],
      [ "Files", "md_src_2fs_2meta_2README.html#autotoc_md172", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2meta_2README.html#autotoc_md173", null ],
      [ "See also", "md_src_2fs_2meta_2README.html#autotoc_md174", null ]
    ] ],
    [ "path — untrusted-path confinement, resolution, ACL/auth gating, and access logging", "md_src_2fs_2path_2README.html", [
      [ "Overview", "md_src_2fs_2path_2README.html#autotoc_md176", null ],
      [ "Files", "md_src_2fs_2path_2README.html#autotoc_md177", null ],
      [ "Key types & data structures", "md_src_2fs_2path_2README.html#autotoc_md178", null ],
      [ "Control & data flow", "md_src_2fs_2path_2README.html#autotoc_md179", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2path_2README.html#autotoc_md180", null ],
      [ "Entry points / extending", "md_src_2fs_2path_2README.html#autotoc_md181", null ],
      [ "See also", "md_src_2fs_2path_2README.html#autotoc_md182", null ]
    ] ],
    [ "fs — Unified VFS: the single POSIX-filesystem data plane", "md_src_2fs_2README.html", [
      [ "Overview", "md_src_2fs_2README.html#autotoc_md184", null ],
      [ "Shared with the userland clients: <tt>module→vfs_server→vfs→backend</tt>", "md_src_2fs_2README.html#autotoc_md185", null ],
      [ "Files", "md_src_2fs_2README.html#autotoc_md186", null ],
      [ "Key types & data structures", "md_src_2fs_2README.html#autotoc_md187", null ],
      [ "Control & data flow", "md_src_2fs_2README.html#autotoc_md188", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2README.html#autotoc_md189", null ],
      [ "The CI seam guard (three tiers)", "md_src_2fs_2README.html#autotoc_md190", null ],
      [ "Entry points / extending", "md_src_2fs_2README.html#autotoc_md191", null ],
      [ "See also", "md_src_2fs_2README.html#autotoc_md192", null ]
    ] ],
    [ "<tt>src/fs/scan/</tt> — bulk storage scan / verify / inventory engine", "md_src_2fs_2scan_2README.html", [
      [ "Layering", "md_src_2fs_2scan_2README.html#autotoc_md194", null ],
      [ "Files", "md_src_2fs_2scan_2README.html#autotoc_md195", null ],
      [ "Endpoint", "md_src_2fs_2scan_2README.html#autotoc_md196", null ],
      [ "Status", "md_src_2fs_2scan_2README.html#autotoc_md197", null ]
    ] ],
    [ "tier — composable storage tiers (cache/stage decorators over backends)", "md_src_2fs_2tier_2README.html", [
      [ "Overview", "md_src_2fs_2tier_2README.html#autotoc_md199", null ],
      [ "Files", "md_src_2fs_2tier_2README.html#autotoc_md200", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2tier_2README.html#autotoc_md201", null ],
      [ "See also", "md_src_2fs_2tier_2README.html#autotoc_md202", null ]
    ] ],
    [ "fs/vfs — the VFS facade (public API + per-op implementations)", "md_src_2fs_2vfs_2README.html", [
      [ "Additional file", "md_src_2fs_2vfs_2README.html#autotoc_md204", null ]
    ] ],
    [ "<tt>src/fs/xfer/</tt> — unified durable-transfer engine", "md_src_2fs_2xfer_2README.html", [
      [ "Where it sits", "md_src_2fs_2xfer_2README.html#autotoc_md206", null ],
      [ "Files", "md_src_2fs_2xfer_2README.html#autotoc_md207", null ],
      [ "STAGE audit coverage — every upload mode", "md_src_2fs_2xfer_2README.html#autotoc_md208", null ],
      [ "Reload contract (§8b)", "md_src_2fs_2xfer_2README.html#autotoc_md209", [
        [ "The audit line (Phase 2)", "md_src_2fs_2xfer_2README.html#autotoc_md210", null ]
      ] ],
      [ "Durability (spec §7–§8)", "md_src_2fs_2xfer_2README.html#autotoc_md211", null ]
    ] ],
    [ "cms — XRootD CMS cluster membership (heartbeat client + manager-side server)", "md_src_2net_2cms_2README.html", [
      [ "Overview", "md_src_2net_2cms_2README.html#autotoc_md213", null ],
      [ "Files", "md_src_2net_2cms_2README.html#autotoc_md214", [
        [ "Heartbeat client (main module)", "md_src_2net_2cms_2README.html#autotoc_md215", null ],
        [ "Shared frame I/O", "md_src_2net_2cms_2README.html#autotoc_md216", null ],
        [ "Manager-side server (<tt>ngx_stream_brix_cms_srv_module</tt>)", "md_src_2net_2cms_2README.html#autotoc_md217", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2cms_2README.html#autotoc_md218", null ],
      [ "Control & data flow", "md_src_2net_2cms_2README.html#autotoc_md219", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2cms_2README.html#autotoc_md220", null ],
      [ "Entry points / extending", "md_src_2net_2cms_2README.html#autotoc_md221", null ],
      [ "See also", "md_src_2net_2cms_2README.html#autotoc_md222", null ]
    ] ],
    [ "net/guard — protocol-agnostic bad-actor classifier", "md_src_2net_2guard_2README.html", [
      [ "The <tt>guard_request_t</tt> contract", "md_src_2net_2guard_2README.html#autotoc_md224", null ],
      [ "Audit line (the fail2ban contract)", "md_src_2net_2guard_2README.html#autotoc_md225", null ],
      [ "Wire-level \"not speaking root\" check (<tt>guard_classify_handshake</tt>)", "md_src_2net_2guard_2README.html#autotoc_md226", null ],
      [ "CVMFS forward-proxy abuse check (<tt>signal=proxyabuse</tt>)", "md_src_2net_2guard_2README.html#autotoc_md227", null ],
      [ "CVMFS content-tamper check (<tt>signal=cvmfs_tamper</tt>)", "md_src_2net_2guard_2README.html#autotoc_md228", null ],
      [ "CVMFS token-gate check (<tt>signal=authfail</tt>)", "md_src_2net_2guard_2README.html#autotoc_md229", null ],
      [ "Testing", "md_src_2net_2guard_2README.html#autotoc_md230", null ]
    ] ],
    [ "net/httpguard — HTTP adapter for the bad-actor guard", "md_src_2net_2httpguard_2README.html", [
      [ "Directives", "md_src_2net_2httpguard_2README.html#autotoc_md232", null ],
      [ "ARC deployment recipe", "md_src_2net_2httpguard_2README.html#autotoc_md233", null ],
      [ "fail2ban wiring", "md_src_2net_2httpguard_2README.html#autotoc_md234", null ],
      [ "Tests", "md_src_2net_2httpguard_2README.html#autotoc_md235", null ]
    ] ],
    [ "manager — Cluster / redirector control plane (server registry, redirect cache, active health checks)", "md_src_2net_2manager_2README.html", [
      [ "Overview", "md_src_2net_2manager_2README.html#autotoc_md237", null ],
      [ "Files", "md_src_2net_2manager_2README.html#autotoc_md238", null ],
      [ "Key types & data structures", "md_src_2net_2manager_2README.html#autotoc_md239", null ],
      [ "Control & data flow", "md_src_2net_2manager_2README.html#autotoc_md240", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2manager_2README.html#autotoc_md241", null ],
      [ "Entry points / extending", "md_src_2net_2manager_2README.html#autotoc_md242", null ],
      [ "See also", "md_src_2net_2manager_2README.html#autotoc_md243", null ]
    ] ],
    [ "mirror — fire-and-forget traffic mirroring (shadow replay) for XRootD and WebDAV", "md_src_2net_2mirror_2README.html", [
      [ "Overview", "md_src_2net_2mirror_2README.html#autotoc_md245", null ],
      [ "Files", "md_src_2net_2mirror_2README.html#autotoc_md246", null ],
      [ "Key types & data structures", "md_src_2net_2mirror_2README.html#autotoc_md247", null ],
      [ "Control & data flow", "md_src_2net_2mirror_2README.html#autotoc_md248", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2mirror_2README.html#autotoc_md249", null ],
      [ "Entry points / extending", "md_src_2net_2mirror_2README.html#autotoc_md250", null ],
      [ "See also", "md_src_2net_2mirror_2README.html#autotoc_md251", null ]
    ] ],
    [ "proxy — Transparent XRootD reverse proxy (<tt>brix_proxy</tt>)", "md_src_2net_2proxy_2README.html", [
      [ "Overview", "md_src_2net_2proxy_2README.html#autotoc_md253", null ],
      [ "Files", "md_src_2net_2proxy_2README.html#autotoc_md254", null ],
      [ "Key types & data structures", "md_src_2net_2proxy_2README.html#autotoc_md255", null ],
      [ "Control & data flow", "md_src_2net_2proxy_2README.html#autotoc_md256", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2proxy_2README.html#autotoc_md257", null ],
      [ "Entry points / extending", "md_src_2net_2proxy_2README.html#autotoc_md258", null ],
      [ "See also", "md_src_2net_2proxy_2README.html#autotoc_md259", null ]
    ] ],
    [ "ratelimit — identity-aware leaky-bucket rate, bandwidth & concurrency limiting (Phase 25)", "md_src_2net_2ratelimit_2README.html", [
      [ "Overview", "md_src_2net_2ratelimit_2README.html#autotoc_md261", null ],
      [ "Files", "md_src_2net_2ratelimit_2README.html#autotoc_md262", null ],
      [ "Key types & data structures", "md_src_2net_2ratelimit_2README.html#autotoc_md263", null ],
      [ "Directive reference (configuration surface)", "md_src_2net_2ratelimit_2README.html#autotoc_md264", null ],
      [ "Control & data flow", "md_src_2net_2ratelimit_2README.html#autotoc_md265", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2ratelimit_2README.html#autotoc_md266", null ],
      [ "Entry points / extending", "md_src_2net_2ratelimit_2README.html#autotoc_md267", null ],
      [ "See also", "md_src_2net_2ratelimit_2README.html#autotoc_md268", null ]
    ] ],
    [ "net — clustering, proxying, shadowing, and connection defense", "md_src_2net_2README.html", null ],
    [ "tap — ngx-free protocol observation tap (decode + sink fan-out)", "md_src_2net_2tap_2README.html", [
      [ "Overview", "md_src_2net_2tap_2README.html#autotoc_md271", null ],
      [ "Files", "md_src_2net_2tap_2README.html#autotoc_md272", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2tap_2README.html#autotoc_md273", null ],
      [ "See also", "md_src_2net_2tap_2README.html#autotoc_md274", null ]
    ] ],
    [ "upstream — outbound XRootD redirector/proxy client (manager-side server-to-server query)", "md_src_2net_2upstream_2README.html", [
      [ "Overview", "md_src_2net_2upstream_2README.html#autotoc_md276", null ],
      [ "Files", "md_src_2net_2upstream_2README.html#autotoc_md277", null ],
      [ "Key types & data structures", "md_src_2net_2upstream_2README.html#autotoc_md278", null ],
      [ "Control & data flow", "md_src_2net_2upstream_2README.html#autotoc_md279", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2upstream_2README.html#autotoc_md280", null ],
      [ "Entry points / extending", "md_src_2net_2upstream_2README.html#autotoc_md281", null ],
      [ "See also", "md_src_2net_2upstream_2README.html#autotoc_md282", null ]
    ] ],
    [ "Access Logging", "md_src_2observability_2accesslog_2README.html", null ],
    [ "dashboard — live HTTPS transfer monitor + REST admin write API", "md_src_2observability_2dashboard_2README.html", [
      [ "Overview", "md_src_2observability_2dashboard_2README.html#autotoc_md285", null ],
      [ "Files", "md_src_2observability_2dashboard_2README.html#autotoc_md286", null ],
      [ "Key types & data structures", "md_src_2observability_2dashboard_2README.html#autotoc_md287", null ],
      [ "Control & data flow", "md_src_2observability_2dashboard_2README.html#autotoc_md288", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2dashboard_2README.html#autotoc_md289", null ],
      [ "Entry points / extending", "md_src_2observability_2dashboard_2README.html#autotoc_md290", null ],
      [ "See also", "md_src_2observability_2dashboard_2README.html#autotoc_md291", null ],
      [ "VFS export browser (<tt>brix_dashboard_vfs_browse on</tt>)", "md_src_2observability_2dashboard_2README.html#autotoc_md292", null ]
    ] ],
    [ "metrics — shared-memory counters and the Prometheus <tt>/metrics</tt> exporter", "md_src_2observability_2metrics_2README.html", [
      [ "Overview", "md_src_2observability_2metrics_2README.html#autotoc_md294", null ],
      [ "Files", "md_src_2observability_2metrics_2README.html#autotoc_md295", null ],
      [ "Key types & data structures", "md_src_2observability_2metrics_2README.html#autotoc_md296", null ],
      [ "Control & data flow", "md_src_2observability_2metrics_2README.html#autotoc_md297", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2metrics_2README.html#autotoc_md298", null ],
      [ "Entry points / extending", "md_src_2observability_2metrics_2README.html#autotoc_md299", null ],
      [ "See also", "md_src_2observability_2metrics_2README.html#autotoc_md300", null ]
    ] ],
    [ "pmark — SciTags packet marking", "md_src_2observability_2pmark_2README.html", [
      [ "Overview", "md_src_2observability_2pmark_2README.html#autotoc_md302", null ],
      [ "Files", "md_src_2observability_2pmark_2README.html#autotoc_md303", null ],
      [ "Configuration", "md_src_2observability_2pmark_2README.html#autotoc_md304", null ],
      [ "Control & data flow", "md_src_2observability_2pmark_2README.html#autotoc_md305", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2pmark_2README.html#autotoc_md306", null ],
      [ "See also", "md_src_2observability_2pmark_2README.html#autotoc_md307", null ]
    ] ],
    [ "observability — metrics, packet marking, dashboard, and access logs", "md_src_2observability_2README.html", null ],
    [ "Session Lifecycle Logging", "md_src_2observability_2sesslog_2README.html", null ],
    [ "cvmfs — the cvmfs:// site cache (+ experimental scvmfs:// TLS variant)", "md_src_2protocols_2cvmfs_2README.html", [
      [ "Overview", "md_src_2protocols_2cvmfs_2README.html#autotoc_md311", null ],
      [ "Files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md312", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2cvmfs_2README.html#autotoc_md313", null ],
      [ "See also", "md_src_2protocols_2cvmfs_2README.html#autotoc_md314", null ]
    ] ],
    [ "<tt>src/protocols/dig/</tt> — XrdDig-style remote diagnostics", "md_src_2protocols_2dig_2README.html", [
      [ "Overview", "md_src_2protocols_2dig_2README.html#autotoc_md316", null ],
      [ "Files", "md_src_2protocols_2dig_2README.html#autotoc_md317", null ],
      [ "See also", "md_src_2protocols_2dig_2README.html#autotoc_md318", null ]
    ] ],
    [ "GridFTP / FTP Gateway", "md_src_2protocols_2gridftp_2README.html", null ],
    [ "protocols — one subdirectory per wire protocol", "md_src_2protocols_2README.html", null ],
    [ "connection — TCP connection lifecycle, framing, and the async I/O state machine for <tt>root://</tt>", "md_src_2protocols_2root_2connection_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2connection_2README.html#autotoc_md322", null ],
      [ "Files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md323", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2connection_2README.html#autotoc_md324", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2connection_2README.html#autotoc_md325", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2connection_2README.html#autotoc_md326", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2connection_2README.html#autotoc_md327", null ],
      [ "See also", "md_src_2protocols_2root_2connection_2README.html#autotoc_md328", null ]
    ] ],
    [ "dirlist — XRootD <tt>kXR_dirlist</tt> directory enumeration (stream protocol)", "md_src_2protocols_2root_2dirlist_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md330", null ],
      [ "Files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md331", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md332", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md333", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md334", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md335", null ],
      [ "See also", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md336", null ]
    ] ],
    [ "fattr — XRootD <tt>kXR_fattr</tt> extended-attribute operations", "md_src_2protocols_2root_2fattr_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md338", null ],
      [ "Files", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md339", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md340", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md341", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md342", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md343", null ],
      [ "See also", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md344", null ]
    ] ],
    [ "handoff — single-port protocol handoff for the stream xrootd listener", "md_src_2protocols_2root_2handoff_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md346", null ],
      [ "Files", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md347", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md348", null ],
      [ "See also", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md349", null ]
    ] ],
    [ "handshake — XRootD stream request entry point and opcode dispatcher", "md_src_2protocols_2root_2handshake_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md351", null ],
      [ "Files", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md352", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md353", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md354", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md355", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md356", null ],
      [ "See also", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md357", null ]
    ] ],
    [ "path — wire-path extraction, sanitization, and stat formatting", "md_src_2protocols_2root_2path_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2path_2README.html#autotoc_md359", null ],
      [ "Files", "md_src_2protocols_2root_2path_2README.html#autotoc_md360", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2path_2README.html#autotoc_md361", null ],
      [ "See also", "md_src_2protocols_2root_2path_2README.html#autotoc_md362", null ]
    ] ],
    [ "protocol — XRootD <tt>root://</tt> wire-format constants & packed structs", "md_src_2protocols_2root_2protocol_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md364", [
        [ "Provenance & licensing", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md365", null ]
      ] ],
      [ "Files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md366", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md367", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md368", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md369", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md370", null ],
      [ "See also", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md371", null ]
    ] ],
    [ "query — XRootD <tt>kXR_query</tt> sub-protocol, <tt>kXR_prepare</tt> staging, and <tt>kXR_set</tt> hints", "md_src_2protocols_2root_2query_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2query_2README.html#autotoc_md373", null ],
      [ "Files", "md_src_2protocols_2root_2query_2README.html#autotoc_md374", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2query_2README.html#autotoc_md375", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2query_2README.html#autotoc_md376", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2query_2README.html#autotoc_md377", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2query_2README.html#autotoc_md378", null ],
      [ "See also", "md_src_2protocols_2root_2query_2README.html#autotoc_md379", null ]
    ] ],
    [ "read — XRootD read-side opcodes and the file-handle lifecycle", "md_src_2protocols_2root_2read_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2read_2README.html#autotoc_md381", null ],
      [ "Files", "md_src_2protocols_2root_2read_2README.html#autotoc_md382", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2read_2README.html#autotoc_md383", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2read_2README.html#autotoc_md384", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2read_2README.html#autotoc_md385", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2read_2README.html#autotoc_md386", null ],
      [ "See also", "md_src_2protocols_2root_2read_2README.html#autotoc_md387", null ]
    ] ],
    [ "root — the XRootD (<tt>root://</tt> / <tt>roots://</tt>) protocol plane", "md_src_2protocols_2root_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2README.html#autotoc_md389", null ],
      [ "Subdirectories", "md_src_2protocols_2root_2README.html#autotoc_md390", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2README.html#autotoc_md391", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2README.html#autotoc_md392", null ],
      [ "See also", "md_src_2protocols_2root_2README.html#autotoc_md393", null ]
    ] ],
    [ "relay — transparent pass-through relay with a passive observation tap", "md_src_2protocols_2root_2relay_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2relay_2README.html#autotoc_md395", null ],
      [ "Files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md396", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2relay_2README.html#autotoc_md397", null ],
      [ "See also", "md_src_2protocols_2root_2relay_2README.html#autotoc_md398", null ]
    ] ],
    [ "response — XRootD wire-response framing helpers", "md_src_2protocols_2root_2response_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2response_2README.html#autotoc_md400", null ],
      [ "Files", "md_src_2protocols_2root_2response_2README.html#autotoc_md401", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2response_2README.html#autotoc_md402", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2response_2README.html#autotoc_md403", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2response_2README.html#autotoc_md404", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2response_2README.html#autotoc_md405", null ],
      [ "See also", "md_src_2protocols_2root_2response_2README.html#autotoc_md406", null ]
    ] ],
    [ "session — XRootD session lifecycle, identity binding & cross-worker registry", "md_src_2protocols_2root_2session_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2session_2README.html#autotoc_md408", null ],
      [ "Files", "md_src_2protocols_2root_2session_2README.html#autotoc_md409", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2session_2README.html#autotoc_md410", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2session_2README.html#autotoc_md411", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2session_2README.html#autotoc_md412", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2session_2README.html#autotoc_md413", null ],
      [ "See also", "md_src_2protocols_2root_2session_2README.html#autotoc_md414", null ]
    ] ],
    [ "stream — <tt>ngx_stream_brix_module</tt> descriptor & directive table", "md_src_2protocols_2root_2stream_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2stream_2README.html#autotoc_md416", null ],
      [ "Files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md417", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2stream_2README.html#autotoc_md418", [
        [ "Directive groups (authoritative <tt>module.c</tt> set)", "md_src_2protocols_2root_2stream_2README.html#autotoc_md419", null ]
      ] ],
      [ "Control & data flow", "md_src_2protocols_2root_2stream_2README.html#autotoc_md420", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2stream_2README.html#autotoc_md421", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2stream_2README.html#autotoc_md422", null ],
      [ "See also", "md_src_2protocols_2root_2stream_2README.html#autotoc_md423", null ]
    ] ],
    [ "write — XRootD mutating-opcode handlers (the stream write path)", "md_src_2protocols_2root_2write_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2write_2README.html#autotoc_md425", null ],
      [ "Files", "md_src_2protocols_2root_2write_2README.html#autotoc_md426", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2write_2README.html#autotoc_md427", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2write_2README.html#autotoc_md428", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2write_2README.html#autotoc_md429", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2write_2README.html#autotoc_md430", null ],
      [ "See also", "md_src_2protocols_2root_2write_2README.html#autotoc_md431", null ]
    ] ],
    [ "src/protocols/root/zip — ZIP member access (phase-57 W2)", "md_src_2protocols_2root_2zip_2README.html", [
      [ "Status", "md_src_2protocols_2root_2zip_2README.html#autotoc_md433", null ],
      [ "zip_dir.c — the parser", "md_src_2protocols_2root_2zip_2README.html#autotoc_md434", null ],
      [ "Running the unit test (standalone, no nginx build)", "md_src_2protocols_2root_2zip_2README.html#autotoc_md435", null ]
    ] ],
    [ "s3 — S3-compatible REST endpoint over the local export root", "md_src_2protocols_2s3_2README.html", [
      [ "Overview", "md_src_2protocols_2s3_2README.html#autotoc_md437", null ],
      [ "Files", "md_src_2protocols_2s3_2README.html#autotoc_md438", null ],
      [ "Key types & data structures", "md_src_2protocols_2s3_2README.html#autotoc_md439", null ],
      [ "Control & data flow", "md_src_2protocols_2s3_2README.html#autotoc_md440", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2s3_2README.html#autotoc_md441", null ],
      [ "Entry points / extending", "md_src_2protocols_2s3_2README.html#autotoc_md442", null ],
      [ "See also", "md_src_2protocols_2s3_2README.html#autotoc_md443", null ]
    ] ],
    [ "shared — cross-protocol helper library (HTTP file serving + overflow-safe size math)", "md_src_2protocols_2shared_2README.html", [
      [ "Overview", "md_src_2protocols_2shared_2README.html#autotoc_md445", null ],
      [ "Files", "md_src_2protocols_2shared_2README.html#autotoc_md446", null ],
      [ "Key types & data structures", "md_src_2protocols_2shared_2README.html#autotoc_md447", null ],
      [ "Control & data flow", "md_src_2protocols_2shared_2README.html#autotoc_md448", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2shared_2README.html#autotoc_md449", null ],
      [ "Entry points / extending", "md_src_2protocols_2shared_2README.html#autotoc_md450", null ],
      [ "See also", "md_src_2protocols_2shared_2README.html#autotoc_md451", null ]
    ] ],
    [ "<tt>src/protocols/srr/</tt> — WLCG Storage Resource Reporting (SRR) endpoint", "md_src_2protocols_2srr_2README.html", [
      [ "Why this instead of the XRootD UDP monitoring stack", "md_src_2protocols_2srr_2README.html#autotoc_md453", null ],
      [ "Files", "md_src_2protocols_2srr_2README.html#autotoc_md454", null ],
      [ "Configuration", "md_src_2protocols_2srr_2README.html#autotoc_md455", null ],
      [ "Semantics & caveats", "md_src_2protocols_2srr_2README.html#autotoc_md456", null ],
      [ "Schema conformance", "md_src_2protocols_2srr_2README.html#autotoc_md457", null ]
    ] ],
    [ "<tt>src/protocols/ssi/</tt> — XrdSsi request/response service over <tt>root://</tt>", "md_src_2protocols_2ssi_2README.html", [
      [ "Overview", "md_src_2protocols_2ssi_2README.html#autotoc_md459", null ],
      [ "Phase 1: session multiplexing (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md460", null ],
      [ "Phase 2: async server-push via <tt>kXR_attn</tt> (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md461", null ],
      [ "Phase 3: streamed responses + delivered alerts (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md462", null ],
      [ "Phases 4–5: CTA flagship service (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md463", null ],
      [ "Phase 6: config, metrics, conformance (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md464", [
        [ "Directives (<tt>NGX_STREAM_SRV_CONF</tt>)", "md_src_2protocols_2ssi_2README.html#autotoc_md465", null ],
        [ "Metrics (low-cardinality — <tt>{port,auth}</tt> only)", "md_src_2protocols_2ssi_2README.html#autotoc_md466", null ],
        [ "Conformance", "md_src_2protocols_2ssi_2README.html#autotoc_md467", null ]
      ] ],
      [ "RRInfo wire layout", "md_src_2protocols_2ssi_2README.html#autotoc_md468", null ],
      [ "Files", "md_src_2protocols_2ssi_2README.html#autotoc_md469", null ],
      [ "See also", "md_src_2protocols_2ssi_2README.html#autotoc_md470", null ]
    ] ],
    [ "<tt>src/protocols/ssi/svc_cta/</tt> — flagship CTA tape service", "md_src_2protocols_2ssi_2svc__cta_2README.html", [
      [ "Layers", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md472", null ],
      [ "Request lifecycle", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md473", [
        [ "State machine", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md474", null ],
        [ "Executor", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md475", null ],
        [ "Security", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md476", null ],
        [ "Journal (restart recovery)", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md477", null ]
      ] ],
      [ "External contract — the pinned field table", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md478", null ],
      [ "Golden-vector provenance", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md479", null ],
      [ "Scope notes", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md480", null ]
    ] ],
    [ "webdav/fs — Confined local-filesystem copy engine for WebDAV COPY/MOVE", "md_src_2protocols_2webdav_2fs_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md482", null ],
      [ "Files", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md483", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md484", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md485", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md486", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md487", null ],
      [ "See also", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md488", null ]
    ] ],
    [ "webdav/locks — WebDAV LOCK request-header & body parsers", "md_src_2protocols_2webdav_2locks_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md490", null ],
      [ "Files", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md491", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md492", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md493", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md494", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md495", null ],
      [ "See also", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md496", null ]
    ] ],
    [ "webdav/methods — Per-method WebDAV precondition helpers", "md_src_2protocols_2webdav_2methods_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md498", null ],
      [ "Files", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md499", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md500", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md501", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md502", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md503", null ],
      [ "See also", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md504", null ]
    ] ],
    [ "webdav — HTTP/WebDAV/HTTPS gateway (<tt>davs://</tt>, <tt>http://</tt>) over the export root", "md_src_2protocols_2webdav_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2README.html#autotoc_md506", null ],
      [ "Files", "md_src_2protocols_2webdav_2README.html#autotoc_md507", [
        [ "Module wiring & configuration", "md_src_2protocols_2webdav_2README.html#autotoc_md508", null ],
        [ "Dispatch & generic helpers", "md_src_2protocols_2webdav_2README.html#autotoc_md509", null ],
        [ "HTTP method handlers", "md_src_2protocols_2webdav_2README.html#autotoc_md510", null ],
        [ "Authentication", "md_src_2protocols_2webdav_2README.html#autotoc_md511", null ],
        [ "HTTP-TPC (third-party copy)", "md_src_2protocols_2webdav_2README.html#autotoc_md512", null ],
        [ "Dynamic backend pool (admin API)", "md_src_2protocols_2webdav_2README.html#autotoc_md513", null ],
        [ "XrdHttp protocol extension", "md_src_2protocols_2webdav_2README.html#autotoc_md514", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2README.html#autotoc_md515", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2README.html#autotoc_md516", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2README.html#autotoc_md517", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2README.html#autotoc_md518", null ],
      [ "See also", "md_src_2protocols_2webdav_2README.html#autotoc_md519", null ]
    ] ],
    [ "webdav/util — WebDAV URI decoding and XML escaping helpers", "md_src_2protocols_2webdav_2util_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md521", null ],
      [ "Files", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md522", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md523", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md524", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md525", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md526", null ],
      [ "See also", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md527", null ]
    ] ],
    [ "src — nginx-xrootd Source Tree", "md_src_2README.html", [
      [ "Source map", "md_src_2README.html#autotoc_md530", [
        [ "Top-level files (now under <tt>core/</tt>)", "md_src_2README.html#autotoc_md531", null ],
        [ "Entry & dispatch", "md_src_2README.html#autotoc_md532", null ],
        [ "Protocol handlers", "md_src_2README.html#autotoc_md533", null ],
        [ "Data plane", "md_src_2README.html#autotoc_md534", null ],
        [ "Path & confinement", "md_src_2README.html#autotoc_md535", null ],
        [ "Authentication", "md_src_2README.html#autotoc_md536", null ],
        [ "Cluster & federation", "md_src_2README.html#autotoc_md537", null ],
        [ "Cross-cutting", "md_src_2README.html#autotoc_md538", null ],
        [ "WebDAV sub-helpers", "md_src_2README.html#autotoc_md539", null ]
      ] ],
      [ "The four request lifecycles", "md_src_2README.html#autotoc_md541", [
        [ "<tt>root://</tt> stream", "md_src_2README.html#autotoc_md542", null ],
        [ "<tt>davs://</tt> WebDAV", "md_src_2README.html#autotoc_md543", null ],
        [ "S3 REST", "md_src_2README.html#autotoc_md544", null ],
        [ "CMS cluster redirect", "md_src_2README.html#autotoc_md545", null ]
      ] ],
      [ "Cross-cutting invariants", "md_src_2README.html#autotoc_md547", null ],
      [ "How to navigate / where to start reading", "md_src_2README.html#autotoc_md549", null ]
    ] ],
    [ "tpc/common — Protocol-neutral third-party-copy (TPC) core", "md_src_2tpc_2common_2README.html", [
      [ "Overview", "md_src_2tpc_2common_2README.html#autotoc_md551", null ],
      [ "Files", "md_src_2tpc_2common_2README.html#autotoc_md552", null ],
      [ "Key types & data structures", "md_src_2tpc_2common_2README.html#autotoc_md553", null ],
      [ "Control & data flow", "md_src_2tpc_2common_2README.html#autotoc_md554", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2common_2README.html#autotoc_md555", null ],
      [ "Entry points / extending", "md_src_2tpc_2common_2README.html#autotoc_md556", null ],
      [ "See also", "md_src_2tpc_2common_2README.html#autotoc_md557", null ]
    ] ],
    [ "engine — native-TPC control plane (destination side)", "md_src_2tpc_2engine_2README.html", [
      [ "Overview", "md_src_2tpc_2engine_2README.html#autotoc_md559", null ],
      [ "Files", "md_src_2tpc_2engine_2README.html#autotoc_md560", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2engine_2README.html#autotoc_md561", null ],
      [ "See also", "md_src_2tpc_2engine_2README.html#autotoc_md562", null ]
    ] ],
    [ "gsi — outbound GSI authentication for the TPC pull socket", "md_src_2tpc_2gsi_2README.html", [
      [ "Overview", "md_src_2tpc_2gsi_2README.html#autotoc_md564", null ],
      [ "Files", "md_src_2tpc_2gsi_2README.html#autotoc_md565", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2gsi_2README.html#autotoc_md566", null ],
      [ "See also", "md_src_2tpc_2gsi_2README.html#autotoc_md567", null ]
    ] ],
    [ "outbound — the blocking source-session client for native TPC pulls", "md_src_2tpc_2outbound_2README.html", [
      [ "Overview", "md_src_2tpc_2outbound_2README.html#autotoc_md569", null ],
      [ "Files", "md_src_2tpc_2outbound_2README.html#autotoc_md570", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2outbound_2README.html#autotoc_md571", null ],
      [ "See also", "md_src_2tpc_2outbound_2README.html#autotoc_md572", null ]
    ] ],
    [ "tpc — Native XRootD third-party-copy (destination-side pull)", "md_src_2tpc_2README.html", [
      [ "Overview", "md_src_2tpc_2README.html#autotoc_md574", null ],
      [ "Files", "md_src_2tpc_2README.html#autotoc_md575", null ],
      [ "Key types & data structures", "md_src_2tpc_2README.html#autotoc_md576", null ],
      [ "Control & data flow", "md_src_2tpc_2README.html#autotoc_md577", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2README.html#autotoc_md578", null ],
      [ "Entry points / extending", "md_src_2tpc_2README.html#autotoc_md579", null ],
      [ "See also", "md_src_2tpc_2README.html#autotoc_md580", null ]
    ] ],
    [ "<tt>client/apps/</tt> — native client CLI tools", "md_client_2apps_2README.html", [
      [ "Data movement", "md_client_2apps_2README.html#autotoc_md582", null ],
      [ "Checksums & verification", "md_client_2apps_2README.html#autotoc_md583", null ],
      [ "Diagnostics & monitoring", "md_client_2apps_2README.html#autotoc_md584", null ],
      [ "Auth & security", "md_client_2apps_2README.html#autotoc_md585", null ],
      [ "Namespace / staging", "md_client_2apps_2README.html#autotoc_md586", null ],
      [ "Optional (built only when <tt>libfuse3</tt> is present — not in <tt>BINS</tt>)", "md_client_2apps_2README.html#autotoc_md587", null ],
      [ "Ceph operator tools (<tt>apps/ceph/</tt> — built only when the Ceph dev headers are present)", "md_client_2apps_2README.html#autotoc_md588", null ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2apps_2README.html#autotoc_md589", null ],
      [ "Man pages & bash completion", "md_client_2apps_2README.html#autotoc_md590", null ],
      [ "CLI compatibility contract (binding for all flag/env/output work)", "md_client_2apps_2README.html#autotoc_md591", null ],
      [ "See also", "md_client_2apps_2README.html#autotoc_md592", null ]
    ] ],
    [ "<tt>client/lib/sec/</tt> — native client authentication modules", "md_client_2lib_2auth_2sec_2README.html", [
      [ "Overview", "md_client_2lib_2auth_2sec_2README.html#autotoc_md594", null ],
      [ "Files", "md_client_2lib_2auth_2sec_2README.html#autotoc_md595", null ],
      [ "Invariants", "md_client_2lib_2auth_2sec_2README.html#autotoc_md596", null ],
      [ "See also", "md_client_2lib_2auth_2sec_2README.html#autotoc_md597", null ]
    ] ],
    [ "<tt>client/lib/</tt> — native XRootD client library (<tt>libbrix</tt>)", "md_client_2lib_2README.html", [
      [ "Concept buckets (phase-69)", "md_client_2lib_2README.html#autotoc_md599", null ],
      [ "File responsibilities (Phase-38 split groups)", "md_client_2lib_2README.html#autotoc_md600", null ]
    ] ],
    [ "<tt>client/preload/</tt> — LD_PRELOAD POSIX → XRootD shim", "md_client_2preload_2README.html", [
      [ "Overview", "md_client_2preload_2README.html#autotoc_md602", null ],
      [ "How it works", "md_client_2preload_2README.html#autotoc_md603", null ],
      [ "Scope", "md_client_2preload_2README.html#autotoc_md604", null ],
      [ "Files", "md_client_2preload_2README.html#autotoc_md605", null ],
      [ "See also", "md_client_2preload_2README.html#autotoc_md606", null ]
    ] ],
    [ "<tt>client/</tt> — native BriX client tools", "md_client_2README.html", [
      [ "Directory layout", "md_client_2README.html#autotoc_md608", null ],
      [ "Build", "md_client_2README.html#autotoc_md609", null ],
      [ "Feature summary (2026-07-05)", "md_client_2README.html#autotoc_md610", [
        [ "xrdcp", "md_client_2README.html#autotoc_md611", null ],
        [ "xrdfs", "md_client_2README.html#autotoc_md612", null ],
        [ "xrdcksum", "md_client_2README.html#autotoc_md613", null ],
        [ "xrddiag", "md_client_2README.html#autotoc_md614", null ],
        [ "Ceph operator tools", "md_client_2README.html#autotoc_md615", null ]
      ] ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2README.html#autotoc_md616", null ],
      [ "Man pages & bash completion", "md_client_2README.html#autotoc_md617", null ],
      [ "See also", "md_client_2README.html#autotoc_md618", null ]
    ] ],
    [ "Namespaces", "namespaces.html", [
      [ "Namespace List", "namespaces.html", "namespaces_dup" ],
      [ "Namespace Members", "namespacemembers.html", [
        [ "All", "namespacemembers.html", null ],
        [ "Functions", "namespacemembers_func.html", null ]
      ] ]
    ] ],
    [ "Data Structures", "annotated.html", [
      [ "Data Structures", "annotated.html", "annotated_dup" ],
      [ "Data Structure Index", "classes.html", null ],
      [ "Data Fields", "functions.html", [
        [ "All", "functions.html", "functions_dup" ],
        [ "Variables", "functions_vars.html", "functions_vars" ]
      ] ]
    ] ],
    [ "Files", "files.html", [
      [ "File List", "files.html", "files_dup" ],
      [ "Globals", "globals.html", [
        [ "All", "globals.html", "globals_dup" ],
        [ "Functions", "globals_func.html", "globals_func" ],
        [ "Variables", "globals_vars.html", "globals_vars" ],
        [ "Typedefs", "globals_type.html", null ],
        [ "Enumerations", "globals_enum.html", null ],
        [ "Enumerator", "globals_eval.html", "globals_eval" ],
        [ "Macros", "globals_defs.html", "globals_defs" ]
      ] ]
    ] ]
  ] ]
];

var NAVTREEINDEX =
[
"acc_8h.html",
"api_8c.html#a06223a7884ef85ab70f5edc6519884f7",
"auth_2gsi_2config_8c.html#ade90a7430aaa52f438e0227e836e5eeb",
"authdb__parse_8c.html#a5e2a4b9b4ff97040f3e12c4111fdd5a3",
"brix_8h.html#aa91bfe3781e5c55c76cbbc0e8ce63188",
"brix__ops_8h.html#a63bb4705b9d04843e4a40c48528fe76aaccf02c76cc8767f4090a7a91d4b4820b",
"brixcvmfs__internal_8h.html#ad373fcb536fe1716dea511f9b16e8a6f",
"broker__ops__ns_8c.html#ae5bbb6c017be390756f624da7ec7b8c3",
"cephfs__denc_8h.html#a2f9c49b5fd8cbd73b2efc8a05d908b55",
"cinfo_8c.html#afe063563d7374d7bb3d95b56a9baeecd",
"client_2lib_2net_2tls_8c.html#aed745c4d74701a1fadd035c808685258",
"cms__internal_8h.html#ac6147c03c99fdf46581e6afe10e0be3c",
"config__internal_8h_source.html",
"core_2compat_2crc32c_8c.html",
"cred__s3_8c.html#abe25e15ed5fe72dd0f09a59f7beab64d",
"cta__pb_8c.html#a1ed46886df40e9f316dd065eea890c0f",
"dashboard_8h.html#af53d8ad8add648ef8604d46d8315d241",
"delegation__gridsite__req_8c.html#a904cad683f122a94d82db07a48ba4ec9",
"diag__metabench_8c.html#a3c883b1e01e8d1be9e8728dc401e989c",
"dispatch__read_8c.html#a43a25074f9820769aecc6032fd964e47",
"fd__kind_8c.html#a3d26a561efd2151cc070137f940504db",
"forward__fh__translate_8c.html",
"fs_2path_2unified_8h.html#a6aa6ba3e667fbc09e9c3293a64da8b63",
"ftp__ev__reply_8c.html#ab302fe329cb66108686697dd2c6b73fd",
"globals_func_d.html",
"gsi__dh_8c.html#ada5598cc519b3ca91b5cbc3cb793ff42",
"handoff_8c.html#a0b02112090595058217ef0e38bea3b05",
"http__conditionals_8c.html#a668e15efc691ed6e2568fd26f359e0c9",
"http__xml_8h.html#a371f661d331173e693112df08f8d8714",
"integrity__info__internal_8h.html#addc8a43a5f24415aaad7a29971360912",
"launch_8c.html#a414a7304368ca8c3d7ae3c31a4678b4e",
"macaroon_8c_source.html",
"md_src_2auth_2token_2README.html#autotoc_md64",
"md_src_2protocols_2cvmfs_2README.html#autotoc_md313",
"merge__macros_8h.html#a9e4e9d1f6f97ba0007011c3bb4ae7fb8",
"metrics__s3_8h.html#a1ea4a9203ed1c7d2cf94a0d103937bd0",
"move_8c.html#a01c0ac1009fa773bcfc064a35025a4cc",
"net_2manager_2registry_8c.html#ae1e2eb85c77f4712dd998dc637f3868d",
"node__ops_8c.html#a4c6b204fa33af3cf5af7c7f1404afcd4",
"observability_2metrics_2unified_8c.html#aa939928fc73fa9238ad04c439dfe213b",
"opcodes_8h.html#a8720fa0d0a3cc91cfc8a65abb9b82015",
"ops__meta_8c.html#a742f93a165c331689e5bd4d926680183",
"parse__crypto__helpers_8c_source.html",
"pblock__xform_8c_source.html",
"post__policy_8c.html#a1c2828712d3006262e342fb2be5cbd9f",
"propfind_8c.html#add44d50dc16eab7f04e328ae50a0967d",
"protocols_2root_2response_2crc32c_8c.html#af8b90e7ddc933b6b639a60222e564485",
"protocols_2webdav_2module_8c.html",
"put__body__digest_8c.html#af2b2d21f34b87660173aea91c04cd237aeca5752c473d28802d2b04317434a368",
"ratelimit__stream_8c.html#a8375796bd220faccfd5122365931b801",
"relay__guard_8h.html#aeebf8fff284e6cdde563f8aaf970fe15",
"root__prepare_8h.html",
"s3__handler__internal_8h_source.html",
"scan__http_8c.html#a4195eb85fa4e5716a25985b4d5ec348e",
"sd__cache__forward_8c_source.html",
"sd__http_8h.html#a5c813c199fae19e6f35e482e2ad0aaf3",
"sd__pblock__unittest_8c.html#a840291bc02cba5474a4cb46a9b9566fe",
"sd__remote__internal_8h.html#acc3837861be4dad8614b94fec9854eab",
"sd__xroot__io_8c.html#ad61b1e720f81f7b9230a63c5bc2662fc",
"server__conf__merge__proxy__net_8c.html#ad2c18641ee18d4350ab344f34376c927",
"sesslog_8h.html#af296b50cd276eda633454fac47fd3fc7ae401bbd1b727468a011c0252736018af",
"src_2auth_2gsi_2auth_8c.html#a13a9d62e8d14737a14dfc63145d1c2ba",
"src_2protocols_2s3_2copy_8c.html#accb7c9f02ec9a64a7bded08b18d4fae5",
"stage__admit_8h.html#ab3c17cc231821acc18b19eefb82de86fa74e6e08e1865d9294dee24ede77bfdd7",
"staged__file__reap_8c.html#a835b07c881ef3da99e0f0996fec9d9e9",
"stream__mirror__config_8c.html#a8a0d8fac3d21d01fae9f898dec6814a2",
"structClientProtocolRequest.html#a82e364e91078eb47a43133f0c22d8045",
"structautofs__state__t.html#a239f6e5a73a28e9ce32d5b7a32112ace",
"structbrix__areq.html#a0d7025dab6388384e5559e0ae0724b29",
"structbrix__cache__read__range__t.html#a9aa35024cbd67cd131035c94e5ac0d87",
"structbrix__conn.html#ad7c4422e3928baa51bbbc7286d1338ec",
"structbrix__ctx__t.html#a0416cc9754f64b2261f56cd148e25311",
"structbrix__file__t.html#a18633597dbb665be6e4eab7f0cd16d5a",
"structbrix__http__cache__fill__ctx__t.html#a9766fbcc6996a85bfb4ed64681b0c09c",
"structbrix__mfile.html#a351cf7bf9c6723477caa75e675ca893a",
"structbrix__pelican__mem2__t.html#aa33addc8f2c682c160d03c9692bf69aa",
"structbrix__proxy__ctx__s.html#a73f3572749b65539fb83bf76f43505e1",
"structbrix__rl__val__t.html#a920eb1acec8a3eedc3c27029975a0ed5",
"structbrix__sess__err__entry__t.html#afe5a2237d6776760fd12b9104550d5fa",
"structbrix__stage__opts__t.html#a5b8103b4fc0a0f4a9eff9aedbd84bb90",
"structbrix__token__validate__args__t.html",
"structbrix__vfs__backend__info__t.html#acb099ca9a583a69bc7763e7df198389c",
"structbrix__write__aio__t.html#a09cf6a037f92c9d6259337ed98d38ad9",
"structcephfs__dentry__t.html#a8d385ace1728a2b46ebbbcd1ceb07449",
"structcta__exec__vtbl__t.html",
"structdx__cmd__t.html#aaa91912ea629716e11458eb2c7726685",
"structgsi__cert__chunks__t.html#ad2d7c450b27e44f6c602eb57bb5752c6",
"structmacaroon__vid__t.html#a4cc18fb9dc906e29201bd8ba3384d9e7",
"structngx__brix__metrics__t.html#acd963aaadddde77b98be6cb50ad21c65",
"structngx__http__brix__shared__conf__t.html#a2021d958027ea29eb5cab5ac6b476dd2",
"structngx__stream__brix__ftp__srv__conf__t.html#a8b2891a044427e2ba85a16243b9128b8",
"structprotocol__want__t.html#a836189d2a8ede49c96677fa1d767451f",
"structs3__lc__slot__t.html#a2c7d4ee8000d71795505b431addf8686",
"structsd__frm__staged__state.html#a7ec3f7b120b4df5e0cfa7746dc6a65da",
"structsrq__rec__t.html#a598d558cfc2c511750dc734fdf7ff0c0",
"structtpc__ms__progress__t.html#a060df93408cc7d03d9622f9f6084e185",
"structweb__upload__ctx.html#ae50cb15e0407f59865bf2de546860d22",
"structxmeta__encode__plan__t.html#aa1e07ac0d07e496cbcc3de5069a1b2ce",
"structxrdw__pgread__req__t.html",
"tap__stream_8c.html#a81c5982c221ad00f920b864d402f8740",
"tpc_2common_2registry_8c.html#a4e45de23d499d9a22ba43fa74367f130",
"tpc__marker_8c.html#a6797c598b5dc4d1314f83e8bee9bd9bd",
"ucred_8c.html#a7387294fba3a0cde679e72b5ed32f1c5",
"verify_8h.html#a9b00514f203efa83ffd986700969dfdca710b2d6c9ba82619c9857adb096f0cd2",
"vfs__dir_8c.html#aa30eaac8116a1da7f1689f699eebe964",
"vfs__s3__io_8c_source.html",
"webdav__auth_8h.html#af2c68e834bab3b9358f1efc3e781f7df",
"wire__codec_8h.html#ad7a3f2d0965305685a5b9085b14f7de7",
"wverify_8h.html",
"xmeta__unittest_8c.html#a82a49228da3eeb7bb74f2a7be14d48cf",
"xrdckverify_8c_source.html",
"xrdfs__fmt_8c.html#ae5fc94c533c07644744eb782233adff8",
"xrdhttp__tpc_8c.html",
"xrootdfs__internal_8h.html#a8ce91b38c414a0c31d40d4bf86a9c001",
"zip__internal_8h.html#a9e30a2cca496105742c61b51856434a8"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';