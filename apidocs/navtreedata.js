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
"api__admin_8c.html#a166197a7899a0d33631e20796bddbb7e",
"auth_2impersonate_2lifecycle_8c.html#aba40845cf4ba2da294eacd29f37c802a",
"authdb__parse_8c.html#ae578c2dab779036eed7175558a01c2c8",
"brix__fault__proxy_8c.html#a63c89c04d1feae07ca35558055155ffb",
"brix__ops_8h.html#ae160e891268c1603f8f86e1da54d7fe3",
"brixcvmfs__rw_8c.html#ad1b1185027e610861e7fe7a737e74976",
"cache__admit_8h.html#a517a94bb9140cdbe91701464b1017fbc",
"chain__helpers_8h.html",
"cks__verify_8c.html#aaa23b45adc484708899f48627566c37b",
"client_8c.html#acdcb9b263abbb339b6067a6d91eb2fa0",
"conditional_8c.html#a089fbbc3e68a5aa469a008d531af6973",
"copy__internal_8h.html#a9b31d6fb607e19df357cb60ecc389f8e",
"cpool_8h.html#a32d228f5b64d0fc15f8dd40f8ae4e31e",
"crypto_8c.html#a6c44bce67530888de2514118403487ee",
"cta__queue__unittest_8c.html#ac175e8ebcae65a524e83fb5d6397c1ee",
"dashboard__auth__login_8c.html",
"diag__internal_8h.html#a18527a2d426a27147edcac31112753ed",
"dir_c954a0ca4f35255a5b44f592084abe61.html",
"evict__policy_8c.html#af5b7ab75355de567a4deb41a5c46795d",
"flags_8h.html#a791c677977628f1ef186812baddb21ce",
"fs_2path_2helpers_8c.html",
"ftp__ev__data_8c.html#ab497a0343a24332c708ee5bece7da253",
"geo__answer_8c.html#ab8c2dc8064c1e68c45e88a66c427d12a",
"gsi__core_8h.html#a2bc60e38a415db532e9e5e011bb219bf",
"guard__http__req_8c.html#a80b1fbf5f26c5ad0c5b65a524e367bd3",
"http__cache__fill__internal_8h_source.html",
"http__serve__offload_8c.html",
"ini_8h.html",
"kv_8c.html#ae395db7613eb5a388ab9d662c52404a0",
"lock__discovery_8c.html#a62eb72c5f78b99a1279379000249e852",
"md_src_2auth_2crypto_2README.html#autotoc_md13",
"md_src_2net_2ratelimit_2README.html#autotoc_md263",
"md_src_2protocols_2webdav_2methods_2README.html#autotoc_md499",
"metrics__internal_8h.html#a7642890849bbaf944abe8e6c9566b8e5",
"module__dispatch_8c_source.html",
"net_2cms_2send_8c.html#a0a61eb8919fd0e411d632b029da3eaa5",
"ngx__brix__module_8h.html#a55ebe0d6e7750da2af3d961113f5baad",
"observability_2metrics_2metrics_8h.html#a8bf0d7534b78ed31c058776cae707cb9",
"opcodes_8h.html#a16b0e79dfcbdffd48351455633186883",
"ops__file__rw_8c.html#a36dc3928506f6e11719c0a123b755608",
"overlay__unittest_8c.html#a8930226b9309fd84d0f57389da20ff4d",
"pblock__store_8c.html#a14dbecdc5184f792b81bcbd2712e228f",
"posix__map_8h.html#a54685fa880a0f96e64e5d78a1f00bdb3",
"prop__xattr_8c.html#aea1f8a7e8eae995d4ba281afafce66d2",
"protocols_2root_2query_2space_8c_source.html",
"protocols_2webdav_2lock_8c.html#a34afa31253e4368138e0b53be245397c",
"proxy__req__unittest_8c.html#a84036889b43ac80da9f5cc649d07856d",
"ratelimit__keys_8c.html#a5c61d118cfd21b20b3791a03203b131e",
"relay_8c.html#a9d1e0766f3f554ffa79b9a415e0587b0",
"root_2session_2protocol_8c.html#a831cad9816114f6e1f4844270aaeca4e",
"s3__auth__internal_8h.html#aa61b59cafce62b3fe43cdde6d0ada37c",
"scan__http_8c.html#a54d641bf03602f62912340cd2f646c17",
"sd__cache__forward_8c.html#a00adca355b5cfe65a59170f7e8a99741",
"sd__http_8h.html#a5c813c199fae19e6f35e482e2ad0aaf3",
"sd__pblock__unittest_8c.html#a5ac68e08d1fb10ed351a3b4bcf1887e1",
"sd__s3__write_8c.html#a970038e8a76315d34e6b2737b3fd3afd",
"sec__pwd_8c.html#a9b81c641394173c97f13d86412d89d71",
"server__recv__parse_8c.html#ae2d5a69a0d99d005b456e37b24853baf",
"signature_8c.html#a9e0f11b081a8290c8a48d472861d18df",
"src_2fs_2vfs_2vfs_8h.html#a38dee1d6673760ee28b6904529562d2e",
"ssi__rrinfo__unittest_8c.html#a390bafe10e109c07d3848d2e7640c7ea",
"stage__request__registry_8h.html#a635be49192b6e32359fa24d1e284b815",
"store__policy_8h.html#a518375a1d67504221109acb48ce710ed",
"structClientChmodRequest.html#a3fc4295cd8b69f21bf067d3c039d9fe6",
"structServerResponseBody__ChkPoint.html#a48d95a117e1bd645d36607b775690899",
"structbrix__acc__http__t.html#ad2cfd9f5600db136a81f256e30dc7e36",
"structbrix__cache__evict__ctx__t.html#a5d1b2897f2645d16d3187b1d033b475d",
"structbrix__cms__rrdata__t.html#a465c196cf5db3ec820e859943648a212",
"structbrix__ctx__login__t.html#a44379b0011164f8846f6f394e9412660",
"structbrix__deleg__entry__t.html#a42722f5643a8c5a837288149a9fd9658",
"structbrix__gsi__buf__t.html",
"structbrix__kv__entry__t.html#af454cfddf55f6528338caf10c8db5de3",
"structbrix__open__args__t.html#a23b788fa9542a255a79700c85e4d7e02",
"structbrix__protocol__t.html",
"structbrix__relay__t.html#a32f5976d0920ab9a95adfb8429266003",
"structbrix__sd__http__ep__cfg__t.html#a37ac6c856504aca35b1478bab52b59e1",
"structbrix__ssi__provider__t.html",
"structbrix__tier__cfg__t.html#ae37423d9d29957e6d70fe9d504c9964c",
"structbrix__upstream__s.html#a38ffb5f7e9395fccbf0586259c187273",
"structbrix__vfs__writev__seg__t.html#a5a24d75ebc423b606a7a2a511c58aa5f",
"structbrix__zip__arc__t.html",
"structclone__item.html#a19f4f7475afa0d51390efa7a814c59cc",
"structdashboard__xfer__snapshot__t.html#a9525f751512f000a96241ee68e28e65a",
"structftp__ev__dc__s.html#afddc34e95464ee8bcf6b4de5b44e1749",
"structimp__req__t.html#ae52e220adc6707725386e03e4853d5a5",
"structngx__brix__cms__ctx__s.html#acf7574bff2539d4676e7cd7c3ab6f08b",
"structngx__brix__webdav__metrics__t.html",
"structngx__http__brix__webdav__req__ctx__t.html#a102518b83b59f2a2f159970b6e020a4a",
"structpc__target__t.html",
"structs3__child__paths__t.html",
"structscan__catalog__ctx__t.html#af8949e081774d4ba21a1200b7d266bc4",
"structsd__stage__wb__state.html#a04ec4ef88d4835760d364ae3952a9642",
"structtail__follow__t.html#a85318b90f7a5efc3839cfcdfbb4732a5",
"structvoms__data.html#a9b2bfbe2a31639923c93f4a99fca431f",
"structwebdav__tpc__pull__ctx__t.html#aa4ea040fe87410d1e4d97c128021afec",
"structxrdhttp__req__ctx__t.html",
"subprocess_8h.html#aaccad22e4991ce3ee6794eb2b24412b2",
"time_8h.html#a4586356480b3c1c7a19331fa3115ba7f",
"tpc__curl__internal_8h.html#a39f1bbc0b4c0442f89198b9f1b2b5bff",
"tunables_8h.html#a275b73a799e2f88b9c0b926284b768ea",
"url_8c.html#a8c8ad81aa26a1a539b0158b1c5fe1835",
"vfs__copy_8c.html#a8bbf77146db643e11a3ec3fcfd8b3707",
"vfs__posix_8c.html#a1474a54cd9ca72a72e78bc68687531df",
"webdav_2get_8c.html#aa6b4e120b9fd45633177aa976cc8e64d",
"wire_8c.html#a948491664f973ef319b748c2bf009b30",
"writer_8c.html#af6290319d353867cfaa183fe3c17e3cb",
"xmeta__carrier_8h.html#acca51c570198b7e0608f8ef780a17825",
"xrdcinfo_8c.html#a11735521644fa1ae0a7e11b022f3c493",
"xrdfs_8c.html#ababaff0c76a61453463b7344e828912d",
"xrdhttp_8c.html#ac0d274f302a4c56fb72c0077d7a8d2d8",
"xrootdfs_8c.html#ac620525a7f7b99bbdfb4ddc35c28e0c9",
"zip_8h.html#ab5686804f8bf258fc6ed3078a2a38ccb"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';