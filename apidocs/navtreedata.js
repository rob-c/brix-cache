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
      [ "Files", "md_src_2auth_2krb5_2README.html#autotoc_md38", [
        [ "Forwarded-TGT delegation (EXCHANGE path — phase-70 §5.7)", "md_src_2auth_2krb5_2README.html#autotoc_md39", null ]
      ] ],
      [ "Key types & data structures", "md_src_2auth_2krb5_2README.html#autotoc_md40", null ],
      [ "Control & data flow", "md_src_2auth_2krb5_2README.html#autotoc_md41", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2krb5_2README.html#autotoc_md42", null ],
      [ "Entry points / extending", "md_src_2auth_2krb5_2README.html#autotoc_md43", null ],
      [ "See also", "md_src_2auth_2krb5_2README.html#autotoc_md44", null ]
    ] ],
    [ "protbind — per-host authentication-protocol binding (XRootD <tt>sec.protbind</tt>)", "md_src_2auth_2protbind_2README.html", [
      [ "Overview", "md_src_2auth_2protbind_2README.html#autotoc_md46", null ],
      [ "Files", "md_src_2auth_2protbind_2README.html#autotoc_md47", null ]
    ] ],
    [ "pwd — password (<tt>XrdSecpwd</tt>) authentication for the <tt>root://</tt> stream protocol", "md_src_2auth_2pwd_2README.html", [
      [ "Overview", "md_src_2auth_2pwd_2README.html#autotoc_md49", null ],
      [ "The two-round exchange", "md_src_2auth_2pwd_2README.html#autotoc_md50", null ],
      [ "Files", "md_src_2auth_2pwd_2README.html#autotoc_md51", null ]
    ] ],
    [ "auth — identity and authorization", "md_src_2auth_2README.html", null ],
    [ "S3 STS Credential Exchange", "md_src_2auth_2s3_2README.html", null ],
    [ "sss — Simple Shared Secret authentication (Blowfish-CFB64 + CRC32)", "md_src_2auth_2sss_2README.html", [
      [ "Overview", "md_src_2auth_2sss_2README.html#autotoc_md55", null ],
      [ "Files", "md_src_2auth_2sss_2README.html#autotoc_md56", null ],
      [ "Key types & data structures", "md_src_2auth_2sss_2README.html#autotoc_md57", null ],
      [ "Control & data flow", "md_src_2auth_2sss_2README.html#autotoc_md58", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2sss_2README.html#autotoc_md59", null ],
      [ "Entry points / extending", "md_src_2auth_2sss_2README.html#autotoc_md60", null ],
      [ "See also", "md_src_2auth_2sss_2README.html#autotoc_md61", null ]
    ] ],
    [ "token — WLCG/SciToken JWT and macaroon bearer-token validation", "md_src_2auth_2token_2README.html", [
      [ "Overview", "md_src_2auth_2token_2README.html#autotoc_md63", null ],
      [ "Files", "md_src_2auth_2token_2README.html#autotoc_md64", null ],
      [ "Key types & data structures", "md_src_2auth_2token_2README.html#autotoc_md65", null ],
      [ "Control & data flow", "md_src_2auth_2token_2README.html#autotoc_md66", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2token_2README.html#autotoc_md67", null ],
      [ "Entry points / extending", "md_src_2auth_2token_2README.html#autotoc_md68", null ],
      [ "See also", "md_src_2auth_2token_2README.html#autotoc_md69", null ]
    ] ],
    [ "unix — XRootD <tt>unix</tt> (UNIX-name) authentication handler", "md_src_2auth_2unix_2README.html", [
      [ "Overview", "md_src_2auth_2unix_2README.html#autotoc_md71", null ],
      [ "Files", "md_src_2auth_2unix_2README.html#autotoc_md72", null ],
      [ "Key types & data structures", "md_src_2auth_2unix_2README.html#autotoc_md73", null ],
      [ "Control & data flow", "md_src_2auth_2unix_2README.html#autotoc_md74", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2unix_2README.html#autotoc_md75", null ],
      [ "Entry points / extending", "md_src_2auth_2unix_2README.html#autotoc_md76", null ],
      [ "See also", "md_src_2auth_2unix_2README.html#autotoc_md77", null ]
    ] ],
    [ "voms — Optional VOMS virtual-organisation extraction from X.509 proxies", "md_src_2auth_2voms_2README.html", [
      [ "Overview", "md_src_2auth_2voms_2README.html#autotoc_md79", null ],
      [ "Files", "md_src_2auth_2voms_2README.html#autotoc_md80", null ],
      [ "Key types & data structures", "md_src_2auth_2voms_2README.html#autotoc_md81", null ],
      [ "Control & data flow", "md_src_2auth_2voms_2README.html#autotoc_md82", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2voms_2README.html#autotoc_md83", null ],
      [ "Entry points / extending", "md_src_2auth_2voms_2README.html#autotoc_md84", null ],
      [ "See also", "md_src_2auth_2voms_2README.html#autotoc_md85", null ]
    ] ],
    [ "aio — Thread-pool async file I/O and shared response-chain builders", "md_src_2core_2aio_2README.html", [
      [ "Overview", "md_src_2core_2aio_2README.html#autotoc_md87", null ],
      [ "Optional io_uring backend (Phase 44 — <tt>uring.c</tt> / <tt>uring_submit.c</tt> / <tt>uring_admin.c</tt>)", "md_src_2core_2aio_2README.html#autotoc_md88", null ],
      [ "Thread-pool contract", "md_src_2core_2aio_2README.html#autotoc_md89", null ],
      [ "Files", "md_src_2core_2aio_2README.html#autotoc_md90", null ],
      [ "Key types & data structures", "md_src_2core_2aio_2README.html#autotoc_md91", null ],
      [ "Control & data flow", "md_src_2core_2aio_2README.html#autotoc_md92", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2aio_2README.html#autotoc_md93", null ],
      [ "Entry points / extending", "md_src_2core_2aio_2README.html#autotoc_md94", null ],
      [ "See also", "md_src_2core_2aio_2README.html#autotoc_md95", null ]
    ] ],
    [ "compat — Cross-protocol shared primitives (checksums, paths, filesystem, SSRF)", "md_src_2core_2compat_2README.html", [
      [ "Overview", "md_src_2core_2compat_2README.html#autotoc_md97", null ],
      [ "Files", "md_src_2core_2compat_2README.html#autotoc_md98", [
        [ "Checksums & hex", "md_src_2core_2compat_2README.html#autotoc_md99", null ],
        [ "HTTP-adjacent primitives", "md_src_2core_2compat_2README.html#autotoc_md100", null ],
        [ "Filesystem & namespace mutation", "md_src_2core_2compat_2README.html#autotoc_md101", null ],
        [ "Networking, async, time, logging, SHM", "md_src_2core_2compat_2README.html#autotoc_md102", null ]
      ] ],
      [ "Key types & data structures", "md_src_2core_2compat_2README.html#autotoc_md103", null ],
      [ "Control & data flow", "md_src_2core_2compat_2README.html#autotoc_md104", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2compat_2README.html#autotoc_md105", null ],
      [ "Entry points / extending", "md_src_2core_2compat_2README.html#autotoc_md106", null ],
      [ "See also", "md_src_2core_2compat_2README.html#autotoc_md107", null ]
    ] ],
    [ "config — directive lifecycle, startup validation, and per-worker resource init", "md_src_2core_2config_2README.html", [
      [ "Overview", "md_src_2core_2config_2README.html#autotoc_md109", null ],
      [ "Files", "md_src_2core_2config_2README.html#autotoc_md110", null ],
      [ "Key types & data structures", "md_src_2core_2config_2README.html#autotoc_md111", null ],
      [ "Control & data flow", "md_src_2core_2config_2README.html#autotoc_md112", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2config_2README.html#autotoc_md113", null ],
      [ "Entry points / extending", "md_src_2core_2config_2README.html#autotoc_md114", null ],
      [ "See also", "md_src_2core_2config_2README.html#autotoc_md115", null ]
    ] ],
    [ "http — Shared HTTP request/response semantics (headers, body, conditionals, ETag)", "md_src_2core_2http_2README.html", [
      [ "Overview", "md_src_2core_2http_2README.html#autotoc_md117", null ],
      [ "Files", "md_src_2core_2http_2README.html#autotoc_md118", null ],
      [ "Boundary — what stays in <tt>../compat</tt>", "md_src_2core_2http_2README.html#autotoc_md119", null ],
      [ "Control & data flow", "md_src_2core_2http_2README.html#autotoc_md120", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2http_2README.html#autotoc_md121", null ],
      [ "Entry points / extending", "md_src_2core_2http_2README.html#autotoc_md122", null ],
      [ "See also", "md_src_2core_2http_2README.html#autotoc_md123", null ]
    ] ],
    [ "Negative-Path Backoff (negcache)", "md_src_2core_2negcache_2README.html", null ],
    [ "core — platform primitives shared by every plane", "md_src_2core_2README.html", null ],
    [ "Worker seccomp-BPF Syscall Filter", "md_src_2core_2seccomp_2README.html", null ],
    [ "shm — generic cross-worker key/value store and token-bucket rate limiter in nginx shared memory", "md_src_2core_2shm_2README.html", [
      [ "Overview", "md_src_2core_2shm_2README.html#autotoc_md128", null ],
      [ "Files", "md_src_2core_2shm_2README.html#autotoc_md129", null ],
      [ "Key types & data structures", "md_src_2core_2shm_2README.html#autotoc_md130", null ],
      [ "Control & data flow", "md_src_2core_2shm_2README.html#autotoc_md131", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2shm_2README.html#autotoc_md132", null ],
      [ "Entry points / extending", "md_src_2core_2shm_2README.html#autotoc_md133", null ],
      [ "See also", "md_src_2core_2shm_2README.html#autotoc_md134", null ]
    ] ],
    [ "src/core/types — Core type definitions, tunables, and the canonical identity object", "md_src_2core_2types_2README.html", [
      [ "Overview", "md_src_2core_2types_2README.html#autotoc_md136", null ],
      [ "Files", "md_src_2core_2types_2README.html#autotoc_md137", null ],
      [ "Key types & data structures", "md_src_2core_2types_2README.html#autotoc_md138", null ],
      [ "Control & data flow", "md_src_2core_2types_2README.html#autotoc_md139", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2types_2README.html#autotoc_md140", null ],
      [ "Entry points / extending", "md_src_2core_2types_2README.html#autotoc_md141", null ],
      [ "See also", "md_src_2core_2types_2README.html#autotoc_md142", null ]
    ] ],
    [ "<tt>src/fs/backend/gsiftp/</tt> — outbound <tt>gsiftp://</tt> storage driver", "md_src_2fs_2backend_2gsiftp_2README.html", [
      [ "Seam", "md_src_2fs_2backend_2gsiftp_2README.html#autotoc_md144", null ],
      [ "Module map", "md_src_2fs_2backend_2gsiftp_2README.html#autotoc_md145", null ]
    ] ],
    [ "fs/backend — Storage Driver (SD) layer", "md_src_2fs_2backend_2README.html", [
      [ "Status — POSIX driver mediates the VFS handle data plane + lifecycle", "md_src_2fs_2backend_2README.html#autotoc_md147", null ],
      [ "Layout — one subdirectory per driver", "md_src_2fs_2backend_2README.html#autotoc_md148", null ],
      [ "Files", "md_src_2fs_2backend_2README.html#autotoc_md149", null ],
      [ "Contract", "md_src_2fs_2backend_2README.html#autotoc_md150", null ],
      [ "Adding a driver", "md_src_2fs_2backend_2README.html#autotoc_md151", null ],
      [ "See also", "md_src_2fs_2backend_2README.html#autotoc_md152", null ]
    ] ],
    [ "<tt>src/fs/cache/origin/</tt> — pluggable origin transports for the read-through cache", "md_src_2fs_2cache_2origin_2README.html", [
      [ "Overview", "md_src_2fs_2cache_2origin_2README.html#autotoc_md154", null ],
      [ "Files", "md_src_2fs_2cache_2origin_2README.html#autotoc_md155", null ],
      [ "Invariants", "md_src_2fs_2cache_2origin_2README.html#autotoc_md156", null ],
      [ "See also", "md_src_2fs_2cache_2origin_2README.html#autotoc_md157", null ]
    ] ],
    [ "<tt>src/fs/cache/</tt> — XCache-style read-through cache and write-through origin mirroring", "md_src_2fs_2cache_2README.html", [
      [ "Overview", "md_src_2fs_2cache_2README.html#autotoc_md159", null ],
      [ "Files", "md_src_2fs_2cache_2README.html#autotoc_md160", [
        [ "Read-through entry points & lifecycle", "md_src_2fs_2cache_2README.html#autotoc_md161", null ],
        [ "Slice cache (Phase 26)", "md_src_2fs_2cache_2README.html#autotoc_md162", null ],
        [ "Origin protocol client (thread-pool, blocking)", "md_src_2fs_2cache_2README.html#autotoc_md163", null ],
        [ "Integrity (checksum-on-fill)", "md_src_2fs_2cache_2README.html#autotoc_md164", null ],
        [ "Cache filesystem bookkeeping", "md_src_2fs_2cache_2README.html#autotoc_md165", null ],
        [ "Eviction", "md_src_2fs_2cache_2README.html#autotoc_md166", null ],
        [ "Unified state engine & parity", "md_src_2fs_2cache_2README.html#autotoc_md167", null ],
        [ "Write-through", "md_src_2fs_2cache_2README.html#autotoc_md168", null ],
        [ "Cache storage on a driver (exclusively-VFS)", "md_src_2fs_2cache_2README.html#autotoc_md169", null ],
        [ "Shared / config / build", "md_src_2fs_2cache_2README.html#autotoc_md170", null ]
      ] ],
      [ "Key types & data structures", "md_src_2fs_2cache_2README.html#autotoc_md171", null ],
      [ "Control & data flow", "md_src_2fs_2cache_2README.html#autotoc_md172", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2cache_2README.html#autotoc_md173", null ],
      [ "Entry points / extending", "md_src_2fs_2cache_2README.html#autotoc_md174", null ],
      [ "See also", "md_src_2fs_2cache_2README.html#autotoc_md175", null ]
    ] ],
    [ "src/fs/core — the shared <tt>vfs</tt> I/O verb layer", "md_src_2fs_2core_2README.html", null ],
    [ "meta — unified per-file metadata sidecar (xmeta)", "md_src_2fs_2meta_2README.html", [
      [ "Overview", "md_src_2fs_2meta_2README.html#autotoc_md178", null ],
      [ "Files", "md_src_2fs_2meta_2README.html#autotoc_md179", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2meta_2README.html#autotoc_md180", null ],
      [ "See also", "md_src_2fs_2meta_2README.html#autotoc_md181", null ]
    ] ],
    [ "path — untrusted-path confinement, resolution, ACL/auth gating, and access logging", "md_src_2fs_2path_2README.html", [
      [ "Overview", "md_src_2fs_2path_2README.html#autotoc_md183", null ],
      [ "Files", "md_src_2fs_2path_2README.html#autotoc_md184", null ],
      [ "Key types & data structures", "md_src_2fs_2path_2README.html#autotoc_md185", null ],
      [ "Control & data flow", "md_src_2fs_2path_2README.html#autotoc_md186", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2path_2README.html#autotoc_md187", null ],
      [ "Entry points / extending", "md_src_2fs_2path_2README.html#autotoc_md188", null ],
      [ "See also", "md_src_2fs_2path_2README.html#autotoc_md189", null ]
    ] ],
    [ "fs — Unified VFS: the single POSIX-filesystem data plane", "md_src_2fs_2README.html", [
      [ "Overview", "md_src_2fs_2README.html#autotoc_md191", null ],
      [ "Shared with the userland clients: <tt>module→vfs_server→vfs→backend</tt>", "md_src_2fs_2README.html#autotoc_md192", null ],
      [ "Files", "md_src_2fs_2README.html#autotoc_md193", null ],
      [ "Key types & data structures", "md_src_2fs_2README.html#autotoc_md194", null ],
      [ "Control & data flow", "md_src_2fs_2README.html#autotoc_md195", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2README.html#autotoc_md196", null ],
      [ "The CI seam guard (three tiers)", "md_src_2fs_2README.html#autotoc_md197", null ],
      [ "Entry points / extending", "md_src_2fs_2README.html#autotoc_md198", null ],
      [ "See also", "md_src_2fs_2README.html#autotoc_md199", null ]
    ] ],
    [ "<tt>src/fs/scan/</tt> — bulk storage scan / verify / inventory engine", "md_src_2fs_2scan_2README.html", [
      [ "Layering", "md_src_2fs_2scan_2README.html#autotoc_md201", null ],
      [ "Files", "md_src_2fs_2scan_2README.html#autotoc_md202", null ],
      [ "Endpoint", "md_src_2fs_2scan_2README.html#autotoc_md203", null ],
      [ "Status", "md_src_2fs_2scan_2README.html#autotoc_md204", null ]
    ] ],
    [ "tier — composable storage tiers (cache/stage decorators over backends)", "md_src_2fs_2tier_2README.html", [
      [ "Overview", "md_src_2fs_2tier_2README.html#autotoc_md206", null ],
      [ "Files", "md_src_2fs_2tier_2README.html#autotoc_md207", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2tier_2README.html#autotoc_md208", null ],
      [ "See also", "md_src_2fs_2tier_2README.html#autotoc_md209", null ]
    ] ],
    [ "fs/vfs — the VFS facade (public API + per-op implementations)", "md_src_2fs_2vfs_2README.html", [
      [ "Additional file", "md_src_2fs_2vfs_2README.html#autotoc_md211", null ]
    ] ],
    [ "<tt>src/fs/xfer/</tt> — unified durable-transfer engine", "md_src_2fs_2xfer_2README.html", [
      [ "Where it sits", "md_src_2fs_2xfer_2README.html#autotoc_md213", null ],
      [ "Files", "md_src_2fs_2xfer_2README.html#autotoc_md214", null ],
      [ "STAGE audit coverage — every upload mode", "md_src_2fs_2xfer_2README.html#autotoc_md215", null ],
      [ "Reload contract (§8b)", "md_src_2fs_2xfer_2README.html#autotoc_md216", [
        [ "The audit line (Phase 2)", "md_src_2fs_2xfer_2README.html#autotoc_md217", null ]
      ] ],
      [ "Durability (spec §7–§8)", "md_src_2fs_2xfer_2README.html#autotoc_md218", null ]
    ] ],
    [ "cms — XRootD CMS cluster membership (heartbeat client + manager-side server)", "md_src_2net_2cms_2README.html", [
      [ "Overview", "md_src_2net_2cms_2README.html#autotoc_md220", null ],
      [ "Files", "md_src_2net_2cms_2README.html#autotoc_md221", [
        [ "Heartbeat client (main module)", "md_src_2net_2cms_2README.html#autotoc_md222", null ],
        [ "Shared frame I/O", "md_src_2net_2cms_2README.html#autotoc_md223", null ],
        [ "Manager-side server (<tt>ngx_stream_brix_cms_srv_module</tt>)", "md_src_2net_2cms_2README.html#autotoc_md224", null ],
        [ "Manager namespace/staging planes (phase-89)", "md_src_2net_2cms_2README.html#autotoc_md225", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2cms_2README.html#autotoc_md226", null ],
      [ "Control & data flow", "md_src_2net_2cms_2README.html#autotoc_md227", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2cms_2README.html#autotoc_md228", null ],
      [ "Entry points / extending", "md_src_2net_2cms_2README.html#autotoc_md229", null ],
      [ "See also", "md_src_2net_2cms_2README.html#autotoc_md230", null ]
    ] ],
    [ "net/guard — protocol-agnostic bad-actor classifier", "md_src_2net_2guard_2README.html", [
      [ "The <tt>guard_request_t</tt> contract", "md_src_2net_2guard_2README.html#autotoc_md232", null ],
      [ "Audit line (the fail2ban contract)", "md_src_2net_2guard_2README.html#autotoc_md233", null ],
      [ "Wire-level \"not speaking root\" check (<tt>guard_classify_handshake</tt>)", "md_src_2net_2guard_2README.html#autotoc_md234", null ],
      [ "CVMFS forward-proxy abuse check (<tt>signal=proxyabuse</tt>)", "md_src_2net_2guard_2README.html#autotoc_md235", null ],
      [ "CVMFS content-tamper check (<tt>signal=cvmfs_tamper</tt>)", "md_src_2net_2guard_2README.html#autotoc_md236", null ],
      [ "CVMFS token-gate check (<tt>signal=authfail</tt>)", "md_src_2net_2guard_2README.html#autotoc_md237", null ],
      [ "Testing", "md_src_2net_2guard_2README.html#autotoc_md238", null ]
    ] ],
    [ "net/httpguard — HTTP adapter for the bad-actor guard", "md_src_2net_2httpguard_2README.html", [
      [ "Directives", "md_src_2net_2httpguard_2README.html#autotoc_md240", null ],
      [ "ARC deployment recipe", "md_src_2net_2httpguard_2README.html#autotoc_md241", null ],
      [ "fail2ban wiring", "md_src_2net_2httpguard_2README.html#autotoc_md242", null ],
      [ "Tests", "md_src_2net_2httpguard_2README.html#autotoc_md243", null ]
    ] ],
    [ "manager — Cluster / redirector control plane (server registry, redirect cache, active health checks)", "md_src_2net_2manager_2README.html", [
      [ "Overview", "md_src_2net_2manager_2README.html#autotoc_md245", null ],
      [ "Files", "md_src_2net_2manager_2README.html#autotoc_md246", null ],
      [ "Key types & data structures", "md_src_2net_2manager_2README.html#autotoc_md247", null ],
      [ "Control & data flow", "md_src_2net_2manager_2README.html#autotoc_md248", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2manager_2README.html#autotoc_md249", null ],
      [ "Entry points / extending", "md_src_2net_2manager_2README.html#autotoc_md250", null ],
      [ "See also", "md_src_2net_2manager_2README.html#autotoc_md251", null ]
    ] ],
    [ "mirror — fire-and-forget traffic mirroring (shadow replay) for XRootD and WebDAV", "md_src_2net_2mirror_2README.html", [
      [ "Overview", "md_src_2net_2mirror_2README.html#autotoc_md253", null ],
      [ "Files", "md_src_2net_2mirror_2README.html#autotoc_md254", null ],
      [ "Key types & data structures", "md_src_2net_2mirror_2README.html#autotoc_md255", null ],
      [ "Control & data flow", "md_src_2net_2mirror_2README.html#autotoc_md256", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2mirror_2README.html#autotoc_md257", null ],
      [ "Entry points / extending", "md_src_2net_2mirror_2README.html#autotoc_md258", null ],
      [ "Tests", "md_src_2net_2mirror_2README.html#autotoc_md259", null ],
      [ "See also", "md_src_2net_2mirror_2README.html#autotoc_md260", null ]
    ] ],
    [ "proxy — Transparent XRootD reverse proxy (<tt>brix_proxy</tt>)", "md_src_2net_2proxy_2README.html", [
      [ "Overview", "md_src_2net_2proxy_2README.html#autotoc_md262", null ],
      [ "Files", "md_src_2net_2proxy_2README.html#autotoc_md263", null ],
      [ "Key types & data structures", "md_src_2net_2proxy_2README.html#autotoc_md264", null ],
      [ "Control & data flow", "md_src_2net_2proxy_2README.html#autotoc_md265", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2proxy_2README.html#autotoc_md266", null ],
      [ "Entry points / extending", "md_src_2net_2proxy_2README.html#autotoc_md267", null ],
      [ "See also", "md_src_2net_2proxy_2README.html#autotoc_md268", null ]
    ] ],
    [ "ratelimit — identity-aware leaky-bucket rate, bandwidth & concurrency limiting (Phase 25)", "md_src_2net_2ratelimit_2README.html", [
      [ "Overview", "md_src_2net_2ratelimit_2README.html#autotoc_md270", null ],
      [ "Files", "md_src_2net_2ratelimit_2README.html#autotoc_md271", null ],
      [ "Key types & data structures", "md_src_2net_2ratelimit_2README.html#autotoc_md272", null ],
      [ "Directive reference (configuration surface)", "md_src_2net_2ratelimit_2README.html#autotoc_md273", null ],
      [ "Control & data flow", "md_src_2net_2ratelimit_2README.html#autotoc_md274", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2ratelimit_2README.html#autotoc_md275", null ],
      [ "Entry points / extending", "md_src_2net_2ratelimit_2README.html#autotoc_md276", null ],
      [ "See also", "md_src_2net_2ratelimit_2README.html#autotoc_md277", null ]
    ] ],
    [ "net — clustering, proxying, shadowing, and connection defense", "md_src_2net_2README.html", null ],
    [ "tap — ngx-free protocol observation tap (decode + sink fan-out)", "md_src_2net_2tap_2README.html", [
      [ "Overview", "md_src_2net_2tap_2README.html#autotoc_md280", null ],
      [ "Files", "md_src_2net_2tap_2README.html#autotoc_md281", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2tap_2README.html#autotoc_md282", null ],
      [ "See also", "md_src_2net_2tap_2README.html#autotoc_md283", null ]
    ] ],
    [ "upstream — outbound XRootD redirector/proxy client (manager-side server-to-server query)", "md_src_2net_2upstream_2README.html", [
      [ "Overview", "md_src_2net_2upstream_2README.html#autotoc_md285", null ],
      [ "Files", "md_src_2net_2upstream_2README.html#autotoc_md286", null ],
      [ "Key types & data structures", "md_src_2net_2upstream_2README.html#autotoc_md287", null ],
      [ "Control & data flow", "md_src_2net_2upstream_2README.html#autotoc_md288", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2upstream_2README.html#autotoc_md289", null ],
      [ "Entry points / extending", "md_src_2net_2upstream_2README.html#autotoc_md290", null ],
      [ "See also", "md_src_2net_2upstream_2README.html#autotoc_md291", null ]
    ] ],
    [ "Access Logging", "md_src_2observability_2accesslog_2README.html", null ],
    [ "dashboard — live HTTPS transfer monitor + REST admin write API", "md_src_2observability_2dashboard_2README.html", [
      [ "Overview", "md_src_2observability_2dashboard_2README.html#autotoc_md294", null ],
      [ "Files", "md_src_2observability_2dashboard_2README.html#autotoc_md295", null ],
      [ "Key types & data structures", "md_src_2observability_2dashboard_2README.html#autotoc_md296", null ],
      [ "Control & data flow", "md_src_2observability_2dashboard_2README.html#autotoc_md297", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2dashboard_2README.html#autotoc_md298", null ],
      [ "Entry points / extending", "md_src_2observability_2dashboard_2README.html#autotoc_md299", null ],
      [ "See also", "md_src_2observability_2dashboard_2README.html#autotoc_md300", null ],
      [ "VFS export browser (<tt>brix_dashboard_vfs_browse on</tt>)", "md_src_2observability_2dashboard_2README.html#autotoc_md301", null ]
    ] ],
    [ "metrics — shared-memory counters and the Prometheus <tt>/metrics</tt> exporter", "md_src_2observability_2metrics_2README.html", [
      [ "Overview", "md_src_2observability_2metrics_2README.html#autotoc_md303", null ],
      [ "Files", "md_src_2observability_2metrics_2README.html#autotoc_md304", null ],
      [ "Key types & data structures", "md_src_2observability_2metrics_2README.html#autotoc_md305", null ],
      [ "Control & data flow", "md_src_2observability_2metrics_2README.html#autotoc_md306", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2metrics_2README.html#autotoc_md307", null ],
      [ "Entry points / extending", "md_src_2observability_2metrics_2README.html#autotoc_md308", null ],
      [ "See also", "md_src_2observability_2metrics_2README.html#autotoc_md309", null ]
    ] ],
    [ "pmark — SciTags packet marking", "md_src_2observability_2pmark_2README.html", [
      [ "Overview", "md_src_2observability_2pmark_2README.html#autotoc_md311", null ],
      [ "Files", "md_src_2observability_2pmark_2README.html#autotoc_md312", null ],
      [ "Configuration", "md_src_2observability_2pmark_2README.html#autotoc_md313", null ],
      [ "Control & data flow", "md_src_2observability_2pmark_2README.html#autotoc_md314", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2pmark_2README.html#autotoc_md315", null ],
      [ "See also", "md_src_2observability_2pmark_2README.html#autotoc_md316", null ]
    ] ],
    [ "observability — metrics, packet marking, dashboard, and access logs", "md_src_2observability_2README.html", null ],
    [ "Session Lifecycle Logging", "md_src_2observability_2sesslog_2README.html", null ],
    [ "cvmfs — the cvmfs:// site cache (+ experimental scvmfs:// TLS variant)", "md_src_2protocols_2cvmfs_2README.html", [
      [ "Overview", "md_src_2protocols_2cvmfs_2README.html#autotoc_md320", null ],
      [ "Files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md321", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2cvmfs_2README.html#autotoc_md322", null ],
      [ "See also", "md_src_2protocols_2cvmfs_2README.html#autotoc_md323", null ]
    ] ],
    [ "<tt>src/protocols/dig/</tt> — XrdDig-style remote diagnostics", "md_src_2protocols_2dig_2README.html", [
      [ "Overview", "md_src_2protocols_2dig_2README.html#autotoc_md325", null ],
      [ "Files", "md_src_2protocols_2dig_2README.html#autotoc_md326", null ],
      [ "See also", "md_src_2protocols_2dig_2README.html#autotoc_md327", null ]
    ] ],
    [ "GridFTP / FTP Gateway", "md_src_2protocols_2gridftp_2README.html", null ],
    [ "protocols — one subdirectory per wire protocol", "md_src_2protocols_2README.html", null ],
    [ "connection — TCP connection lifecycle, framing, and the async I/O state machine for <tt>root://</tt>", "md_src_2protocols_2root_2connection_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2connection_2README.html#autotoc_md331", null ],
      [ "Files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md332", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2connection_2README.html#autotoc_md333", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2connection_2README.html#autotoc_md334", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2connection_2README.html#autotoc_md335", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2connection_2README.html#autotoc_md336", null ],
      [ "See also", "md_src_2protocols_2root_2connection_2README.html#autotoc_md337", null ]
    ] ],
    [ "dirlist — XRootD <tt>kXR_dirlist</tt> directory enumeration (stream protocol)", "md_src_2protocols_2root_2dirlist_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md339", null ],
      [ "Files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md340", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md341", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md342", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md343", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md344", null ],
      [ "See also", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md345", null ]
    ] ],
    [ "fattr — XRootD <tt>kXR_fattr</tt> extended-attribute operations", "md_src_2protocols_2root_2fattr_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md347", null ],
      [ "Files", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md348", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md349", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md350", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md351", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md352", null ],
      [ "See also", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md353", null ]
    ] ],
    [ "handoff — single-port protocol handoff for the stream xrootd listener", "md_src_2protocols_2root_2handoff_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md355", null ],
      [ "Files", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md356", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md357", null ],
      [ "See also", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md358", null ]
    ] ],
    [ "handshake — XRootD stream request entry point and opcode dispatcher", "md_src_2protocols_2root_2handshake_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md360", null ],
      [ "Files", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md361", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md362", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md363", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md364", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md365", null ],
      [ "See also", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md366", null ]
    ] ],
    [ "path — wire-path extraction, sanitization, and stat formatting", "md_src_2protocols_2root_2path_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2path_2README.html#autotoc_md368", null ],
      [ "Files", "md_src_2protocols_2root_2path_2README.html#autotoc_md369", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2path_2README.html#autotoc_md370", null ],
      [ "See also", "md_src_2protocols_2root_2path_2README.html#autotoc_md371", null ]
    ] ],
    [ "protocol — XRootD <tt>root://</tt> wire-format constants & packed structs", "md_src_2protocols_2root_2protocol_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md373", [
        [ "Provenance & licensing", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md374", null ]
      ] ],
      [ "Files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md375", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md376", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md377", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md378", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md379", null ],
      [ "See also", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md380", null ]
    ] ],
    [ "query — XRootD <tt>kXR_query</tt> sub-protocol, <tt>kXR_prepare</tt> staging, and <tt>kXR_set</tt> hints", "md_src_2protocols_2root_2query_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2query_2README.html#autotoc_md382", null ],
      [ "Files", "md_src_2protocols_2root_2query_2README.html#autotoc_md383", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2query_2README.html#autotoc_md384", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2query_2README.html#autotoc_md385", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2query_2README.html#autotoc_md386", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2query_2README.html#autotoc_md387", null ],
      [ "See also", "md_src_2protocols_2root_2query_2README.html#autotoc_md388", null ]
    ] ],
    [ "read — XRootD read-side opcodes and the file-handle lifecycle", "md_src_2protocols_2root_2read_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2read_2README.html#autotoc_md390", null ],
      [ "Files", "md_src_2protocols_2root_2read_2README.html#autotoc_md391", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2read_2README.html#autotoc_md392", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2read_2README.html#autotoc_md393", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2read_2README.html#autotoc_md394", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2read_2README.html#autotoc_md395", null ],
      [ "See also", "md_src_2protocols_2root_2read_2README.html#autotoc_md396", null ]
    ] ],
    [ "root — the XRootD (<tt>root://</tt> / <tt>roots://</tt>) protocol plane", "md_src_2protocols_2root_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2README.html#autotoc_md398", null ],
      [ "Subdirectories", "md_src_2protocols_2root_2README.html#autotoc_md399", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2README.html#autotoc_md400", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2README.html#autotoc_md401", null ],
      [ "See also", "md_src_2protocols_2root_2README.html#autotoc_md402", null ]
    ] ],
    [ "relay — transparent pass-through relay with a passive observation tap", "md_src_2protocols_2root_2relay_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2relay_2README.html#autotoc_md404", null ],
      [ "Files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md405", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2relay_2README.html#autotoc_md406", null ],
      [ "See also", "md_src_2protocols_2root_2relay_2README.html#autotoc_md407", null ]
    ] ],
    [ "response — XRootD wire-response framing helpers", "md_src_2protocols_2root_2response_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2response_2README.html#autotoc_md409", null ],
      [ "Files", "md_src_2protocols_2root_2response_2README.html#autotoc_md410", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2response_2README.html#autotoc_md411", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2response_2README.html#autotoc_md412", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2response_2README.html#autotoc_md413", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2response_2README.html#autotoc_md414", null ],
      [ "See also", "md_src_2protocols_2root_2response_2README.html#autotoc_md415", null ]
    ] ],
    [ "session — XRootD session lifecycle, identity binding & cross-worker registry", "md_src_2protocols_2root_2session_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2session_2README.html#autotoc_md417", null ],
      [ "Files", "md_src_2protocols_2root_2session_2README.html#autotoc_md418", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2session_2README.html#autotoc_md419", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2session_2README.html#autotoc_md420", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2session_2README.html#autotoc_md421", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2session_2README.html#autotoc_md422", null ],
      [ "See also", "md_src_2protocols_2root_2session_2README.html#autotoc_md423", null ]
    ] ],
    [ "stream — <tt>ngx_stream_brix_module</tt> descriptor & directive table", "md_src_2protocols_2root_2stream_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2stream_2README.html#autotoc_md425", null ],
      [ "Files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md426", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2stream_2README.html#autotoc_md427", [
        [ "Directive groups (authoritative <tt>module.c</tt> set)", "md_src_2protocols_2root_2stream_2README.html#autotoc_md428", null ]
      ] ],
      [ "Control & data flow", "md_src_2protocols_2root_2stream_2README.html#autotoc_md429", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2stream_2README.html#autotoc_md430", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2stream_2README.html#autotoc_md431", null ],
      [ "See also", "md_src_2protocols_2root_2stream_2README.html#autotoc_md432", null ]
    ] ],
    [ "write — XRootD mutating-opcode handlers (the stream write path)", "md_src_2protocols_2root_2write_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2write_2README.html#autotoc_md434", null ],
      [ "Files", "md_src_2protocols_2root_2write_2README.html#autotoc_md435", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2write_2README.html#autotoc_md436", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2write_2README.html#autotoc_md437", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2write_2README.html#autotoc_md438", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2write_2README.html#autotoc_md439", null ],
      [ "See also", "md_src_2protocols_2root_2write_2README.html#autotoc_md440", null ]
    ] ],
    [ "src/protocols/root/zip — ZIP member access (phase-57 W2)", "md_src_2protocols_2root_2zip_2README.html", [
      [ "Status", "md_src_2protocols_2root_2zip_2README.html#autotoc_md442", null ],
      [ "zip_dir.c — the parser", "md_src_2protocols_2root_2zip_2README.html#autotoc_md443", null ],
      [ "Running the unit test (standalone, no nginx build)", "md_src_2protocols_2root_2zip_2README.html#autotoc_md444", null ]
    ] ],
    [ "s3 — S3-compatible REST endpoint over the local export root", "md_src_2protocols_2s3_2README.html", [
      [ "Overview", "md_src_2protocols_2s3_2README.html#autotoc_md446", null ],
      [ "Files", "md_src_2protocols_2s3_2README.html#autotoc_md447", null ],
      [ "Key types & data structures", "md_src_2protocols_2s3_2README.html#autotoc_md448", null ],
      [ "Control & data flow", "md_src_2protocols_2s3_2README.html#autotoc_md449", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2s3_2README.html#autotoc_md450", null ],
      [ "Entry points / extending", "md_src_2protocols_2s3_2README.html#autotoc_md451", null ],
      [ "See also", "md_src_2protocols_2s3_2README.html#autotoc_md452", null ]
    ] ],
    [ "shared — cross-protocol helper library (HTTP file serving + overflow-safe size math)", "md_src_2protocols_2shared_2README.html", [
      [ "Overview", "md_src_2protocols_2shared_2README.html#autotoc_md454", null ],
      [ "Files", "md_src_2protocols_2shared_2README.html#autotoc_md455", null ],
      [ "Key types & data structures", "md_src_2protocols_2shared_2README.html#autotoc_md456", null ],
      [ "Control & data flow", "md_src_2protocols_2shared_2README.html#autotoc_md457", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2shared_2README.html#autotoc_md458", null ],
      [ "Entry points / extending", "md_src_2protocols_2shared_2README.html#autotoc_md459", null ],
      [ "See also", "md_src_2protocols_2shared_2README.html#autotoc_md460", null ]
    ] ],
    [ "<tt>src/protocols/srr/</tt> — WLCG Storage Resource Reporting (SRR) endpoint", "md_src_2protocols_2srr_2README.html", [
      [ "Why this instead of the XRootD UDP monitoring stack", "md_src_2protocols_2srr_2README.html#autotoc_md462", null ],
      [ "Files", "md_src_2protocols_2srr_2README.html#autotoc_md463", null ],
      [ "Configuration", "md_src_2protocols_2srr_2README.html#autotoc_md464", null ],
      [ "Semantics & caveats", "md_src_2protocols_2srr_2README.html#autotoc_md465", null ],
      [ "Schema conformance", "md_src_2protocols_2srr_2README.html#autotoc_md466", null ]
    ] ],
    [ "<tt>src/protocols/ssi/</tt> — XrdSsi request/response service over <tt>root://</tt>", "md_src_2protocols_2ssi_2README.html", [
      [ "Overview", "md_src_2protocols_2ssi_2README.html#autotoc_md468", null ],
      [ "Phase 1: session multiplexing (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md469", null ],
      [ "Phase 2: async server-push via <tt>kXR_attn</tt> (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md470", null ],
      [ "Phase 3: streamed responses + delivered alerts (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md471", null ],
      [ "Phases 4–5: CTA flagship service (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md472", null ],
      [ "Phase 6: config, metrics, conformance (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md473", [
        [ "Directives (<tt>NGX_STREAM_SRV_CONF</tt>)", "md_src_2protocols_2ssi_2README.html#autotoc_md474", null ],
        [ "Metrics (low-cardinality — <tt>{port,auth}</tt> only)", "md_src_2protocols_2ssi_2README.html#autotoc_md475", null ],
        [ "Conformance", "md_src_2protocols_2ssi_2README.html#autotoc_md476", null ]
      ] ],
      [ "RRInfo wire layout", "md_src_2protocols_2ssi_2README.html#autotoc_md477", null ],
      [ "Files", "md_src_2protocols_2ssi_2README.html#autotoc_md478", null ],
      [ "See also", "md_src_2protocols_2ssi_2README.html#autotoc_md479", null ]
    ] ],
    [ "<tt>src/protocols/ssi/svc_cta/</tt> — flagship CTA tape service", "md_src_2protocols_2ssi_2svc__cta_2README.html", [
      [ "Layers", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md481", null ],
      [ "Request lifecycle", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md482", [
        [ "State machine", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md483", null ],
        [ "Executor", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md484", null ],
        [ "Security", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md485", null ],
        [ "Journal (restart recovery)", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md486", null ]
      ] ],
      [ "External contract — the pinned field table", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md487", null ],
      [ "Golden-vector provenance", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md488", null ],
      [ "Scope notes", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md489", null ]
    ] ],
    [ "webdav/fs — Confined local-filesystem copy engine for WebDAV COPY/MOVE", "md_src_2protocols_2webdav_2fs_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md491", null ],
      [ "Files", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md492", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md493", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md494", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md495", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md496", null ],
      [ "See also", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md497", null ]
    ] ],
    [ "webdav/locks — WebDAV LOCK request-header & body parsers", "md_src_2protocols_2webdav_2locks_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md499", null ],
      [ "Files", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md500", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md501", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md502", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md503", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md504", null ],
      [ "See also", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md505", null ]
    ] ],
    [ "webdav/methods — Per-method WebDAV precondition helpers", "md_src_2protocols_2webdav_2methods_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md507", null ],
      [ "Files", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md508", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md509", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md510", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md511", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md512", null ],
      [ "See also", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md513", null ]
    ] ],
    [ "webdav — HTTP/WebDAV/HTTPS gateway (<tt>davs://</tt>, <tt>http://</tt>) over the export root", "md_src_2protocols_2webdav_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2README.html#autotoc_md515", null ],
      [ "Files", "md_src_2protocols_2webdav_2README.html#autotoc_md516", [
        [ "Module wiring & configuration", "md_src_2protocols_2webdav_2README.html#autotoc_md517", null ],
        [ "Dispatch & generic helpers", "md_src_2protocols_2webdav_2README.html#autotoc_md518", null ],
        [ "HTTP method handlers", "md_src_2protocols_2webdav_2README.html#autotoc_md519", null ],
        [ "Authentication", "md_src_2protocols_2webdav_2README.html#autotoc_md520", null ],
        [ "HTTP-TPC (third-party copy)", "md_src_2protocols_2webdav_2README.html#autotoc_md521", null ],
        [ "Dynamic backend pool (admin API)", "md_src_2protocols_2webdav_2README.html#autotoc_md522", null ],
        [ "XrdHttp protocol extension", "md_src_2protocols_2webdav_2README.html#autotoc_md523", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2README.html#autotoc_md524", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2README.html#autotoc_md525", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2README.html#autotoc_md526", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2README.html#autotoc_md527", null ],
      [ "See also", "md_src_2protocols_2webdav_2README.html#autotoc_md528", null ]
    ] ],
    [ "webdav/util — WebDAV URI decoding and XML escaping helpers", "md_src_2protocols_2webdav_2util_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md530", null ],
      [ "Files", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md531", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md532", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md533", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md534", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md535", null ],
      [ "See also", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md536", null ]
    ] ],
    [ "src — nginx-xrootd Source Tree", "md_src_2README.html", [
      [ "Source map", "md_src_2README.html#autotoc_md539", [
        [ "Top-level files (now under <tt>core/</tt>)", "md_src_2README.html#autotoc_md540", null ],
        [ "Entry & dispatch", "md_src_2README.html#autotoc_md541", null ],
        [ "Protocol handlers", "md_src_2README.html#autotoc_md542", null ],
        [ "Data plane", "md_src_2README.html#autotoc_md543", null ],
        [ "Path & confinement", "md_src_2README.html#autotoc_md544", null ],
        [ "Authentication", "md_src_2README.html#autotoc_md545", null ],
        [ "Cluster & federation", "md_src_2README.html#autotoc_md546", null ],
        [ "Cross-cutting", "md_src_2README.html#autotoc_md547", null ],
        [ "WebDAV sub-helpers", "md_src_2README.html#autotoc_md548", null ]
      ] ],
      [ "The four request lifecycles", "md_src_2README.html#autotoc_md550", [
        [ "<tt>root://</tt> stream", "md_src_2README.html#autotoc_md551", null ],
        [ "<tt>davs://</tt> WebDAV", "md_src_2README.html#autotoc_md552", null ],
        [ "S3 REST", "md_src_2README.html#autotoc_md553", null ],
        [ "CMS cluster redirect", "md_src_2README.html#autotoc_md554", null ]
      ] ],
      [ "Cross-cutting invariants", "md_src_2README.html#autotoc_md556", null ],
      [ "How to navigate / where to start reading", "md_src_2README.html#autotoc_md558", null ]
    ] ],
    [ "tpc/common — Protocol-neutral third-party-copy (TPC) core", "md_src_2tpc_2common_2README.html", [
      [ "Overview", "md_src_2tpc_2common_2README.html#autotoc_md560", null ],
      [ "Files", "md_src_2tpc_2common_2README.html#autotoc_md561", null ],
      [ "Key types & data structures", "md_src_2tpc_2common_2README.html#autotoc_md562", null ],
      [ "Control & data flow", "md_src_2tpc_2common_2README.html#autotoc_md563", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2common_2README.html#autotoc_md564", null ],
      [ "Entry points / extending", "md_src_2tpc_2common_2README.html#autotoc_md565", null ],
      [ "See also", "md_src_2tpc_2common_2README.html#autotoc_md566", null ]
    ] ],
    [ "engine — native-TPC control plane (destination side)", "md_src_2tpc_2engine_2README.html", [
      [ "Overview", "md_src_2tpc_2engine_2README.html#autotoc_md568", null ],
      [ "Files", "md_src_2tpc_2engine_2README.html#autotoc_md569", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2engine_2README.html#autotoc_md570", null ],
      [ "See also", "md_src_2tpc_2engine_2README.html#autotoc_md571", null ]
    ] ],
    [ "gsi — outbound GSI authentication for the TPC pull socket", "md_src_2tpc_2gsi_2README.html", [
      [ "Overview", "md_src_2tpc_2gsi_2README.html#autotoc_md573", null ],
      [ "Files", "md_src_2tpc_2gsi_2README.html#autotoc_md574", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2gsi_2README.html#autotoc_md575", null ],
      [ "See also", "md_src_2tpc_2gsi_2README.html#autotoc_md576", null ]
    ] ],
    [ "outbound — the blocking source-session client for native TPC pulls", "md_src_2tpc_2outbound_2README.html", [
      [ "Overview", "md_src_2tpc_2outbound_2README.html#autotoc_md578", null ],
      [ "Files", "md_src_2tpc_2outbound_2README.html#autotoc_md579", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2outbound_2README.html#autotoc_md580", null ],
      [ "See also", "md_src_2tpc_2outbound_2README.html#autotoc_md581", null ]
    ] ],
    [ "tpc — Native XRootD third-party-copy (destination-side pull)", "md_src_2tpc_2README.html", [
      [ "Overview", "md_src_2tpc_2README.html#autotoc_md583", null ],
      [ "Files", "md_src_2tpc_2README.html#autotoc_md584", null ],
      [ "Key types & data structures", "md_src_2tpc_2README.html#autotoc_md585", null ],
      [ "Control & data flow", "md_src_2tpc_2README.html#autotoc_md586", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2README.html#autotoc_md587", null ],
      [ "Entry points / extending", "md_src_2tpc_2README.html#autotoc_md588", null ],
      [ "See also", "md_src_2tpc_2README.html#autotoc_md589", null ]
    ] ],
    [ "<tt>client/apps/</tt> — native client CLI tools", "md_client_2apps_2README.html", [
      [ "Data movement", "md_client_2apps_2README.html#autotoc_md591", null ],
      [ "Checksums & verification", "md_client_2apps_2README.html#autotoc_md592", null ],
      [ "Diagnostics & monitoring", "md_client_2apps_2README.html#autotoc_md593", null ],
      [ "Auth & security", "md_client_2apps_2README.html#autotoc_md594", null ],
      [ "Namespace / staging", "md_client_2apps_2README.html#autotoc_md595", null ],
      [ "Optional (built only when <tt>libfuse3</tt> is present — not in <tt>BINS</tt>)", "md_client_2apps_2README.html#autotoc_md596", null ],
      [ "Ceph operator tools (<tt>apps/ceph/</tt> — built only when the Ceph dev headers are present)", "md_client_2apps_2README.html#autotoc_md597", null ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2apps_2README.html#autotoc_md598", null ],
      [ "Man pages & bash completion", "md_client_2apps_2README.html#autotoc_md599", null ],
      [ "CLI compatibility contract (binding for all flag/env/output work)", "md_client_2apps_2README.html#autotoc_md600", null ],
      [ "See also", "md_client_2apps_2README.html#autotoc_md601", null ]
    ] ],
    [ "<tt>client/lib/sec/</tt> — native client authentication modules", "md_client_2lib_2auth_2sec_2README.html", [
      [ "Overview", "md_client_2lib_2auth_2sec_2README.html#autotoc_md603", null ],
      [ "Files", "md_client_2lib_2auth_2sec_2README.html#autotoc_md604", null ],
      [ "Invariants", "md_client_2lib_2auth_2sec_2README.html#autotoc_md605", null ],
      [ "See also", "md_client_2lib_2auth_2sec_2README.html#autotoc_md606", null ]
    ] ],
    [ "<tt>client/lib/</tt> — native XRootD client library (<tt>libbrix</tt>)", "md_client_2lib_2README.html", [
      [ "Concept buckets (phase-69)", "md_client_2lib_2README.html#autotoc_md608", null ],
      [ "File responsibilities (Phase-38 split groups)", "md_client_2lib_2README.html#autotoc_md609", null ]
    ] ],
    [ "<tt>client/preload/</tt> — LD_PRELOAD POSIX → XRootD shim", "md_client_2preload_2README.html", [
      [ "Overview", "md_client_2preload_2README.html#autotoc_md611", null ],
      [ "How it works", "md_client_2preload_2README.html#autotoc_md612", null ],
      [ "Scope", "md_client_2preload_2README.html#autotoc_md613", null ],
      [ "Files", "md_client_2preload_2README.html#autotoc_md614", null ],
      [ "See also", "md_client_2preload_2README.html#autotoc_md615", null ]
    ] ],
    [ "<tt>client/</tt> — native BriX client tools", "md_client_2README.html", [
      [ "Directory layout", "md_client_2README.html#autotoc_md617", null ],
      [ "Build", "md_client_2README.html#autotoc_md618", null ],
      [ "Feature summary (2026-07-05)", "md_client_2README.html#autotoc_md619", [
        [ "xrdcp", "md_client_2README.html#autotoc_md620", null ],
        [ "xrdfs", "md_client_2README.html#autotoc_md621", null ],
        [ "xrdcksum", "md_client_2README.html#autotoc_md622", null ],
        [ "xrddiag", "md_client_2README.html#autotoc_md623", null ],
        [ "Ceph operator tools", "md_client_2README.html#autotoc_md624", null ]
      ] ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2README.html#autotoc_md625", null ],
      [ "Man pages & bash completion", "md_client_2README.html#autotoc_md626", null ],
      [ "See also", "md_client_2README.html#autotoc_md627", null ]
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
"aio__mgr_8c.html#ac3005c8d73a2e1dad861e5892ccaac67",
"audit_8c.html#a89bd2e797bf34092125fc1d9f64d924e",
"auth__request_8c_source.html",
"backend__async__queue_8c.html#aff9b0e70713820169fc7e60c65b520cd",
"brix__fault__http_8h.html",
"brix__fault__proxy__state_8h.html#a250624435d0cda0446c758c96ff9204c",
"brix__fault__route_8c.html#ac7d560d6fd53a35939c5cc3fb87af602",
"brix__ops_8h.html#a73ea1ceee36cbc4290ba9e8bea0348bb",
"brixcvmfs__ops_8c.html#a7356ee3caa4a92734c8ea33de60cf899",
"brixmount__unittest_8c.html#a79b34649d0b8d6cfc58e6859484fe1f2",
"cache__internal_8h.html#a21bcf6352445e789840244b9d331b7a0",
"checksum__ckscan__dispatch_8c.html",
"cli__cksum_8c_source.html",
"client_2lib_2xfer_2copy__internal_8h.html#a810eb971d5b17205760963266003481a",
"cns_8c.html#aad52645a213f88bea04f7ff8a519786a",
"config__download_8c.html#a96c71436bd5e76fdd5cdde5b63a54180",
"copy__recursive_8c.html#acfbad5f4f2a42e4ff454f11a618f29ed",
"cred_8c.html#a7759654e6581ebcfec992bf316b9ccee",
"csi__tagstore_8h.html#a71650ef828d5f6e3a972602d7f9c3a56",
"cvmfs_8c.html#a6a70f4b48cd96ff72b784d306cef6cbb",
"dashboard__auth__internal_8h.html#a83ecaed241b1c3009c8daa852300992c",
"diag__authsuite_8c.html#aa163d0bb9d4363f8ab84ae89c6629304",
"diag__doctor__json__unittest_8c.html#a840291bc02cba5474a4cb46a9b9566fe",
"diag__internal_8h.html#af48ae6c59feebc6595a8d484cdbced43",
"dir_eb1d7d51c60d8790150eb043bb834be0.html",
"evict__internal_8h_source.html",
"flags_8h.html#a0a1e5a5099d89cb4f68d1316419b0688",
"fs_2cache_2directives_8c.html#a1ec80a5d400d96da399b832781e37887",
"ftp__data_8c.html#a79a8266c27f4b58cd997bcb7c79f9efb",
"ftp__gsi__int_8h.html",
"globals_defs.html",
"gsi__core_8h.html#aa4ee3ab0511100a55c64d51d6ac5419b",
"guard__ruleset_8c.html#aed2d99460d3513fcc85d001514ecceb7",
"http__body__decode_8c.html#af215132d19fd54d1c672aa26109c7864",
"http__query_8h.html",
"impersonate_8h_source.html",
"keypool_8c.html#a0e03d5b285110a2928cf72d42ddf182d",
"list__common_8c.html#a69156488720d24859957611e08131c1e",
"mapping_8c.html#a6762d338d0c448497f1a30bb5f93ccd6",
"md_src_2fs_2cache_2README.html#autotoc_md167",
"md_src_2protocols_2root_2session_2README.html#autotoc_md422",
"meter_8c.html#ae9f17bb4921e14b3c40e13fea8b4ccd1",
"mirror_8h.html#a4c6f7bffad4f8bbcb709c87213629c0f",
"namespace_8c.html#a39881bba385b122691b7ab604d0a955f",
"net_2upstream_2request_8c.html#a27bb8b5516bc491ec7562a377374bb38",
"object_8c.html#a9379792d3629f6c4abd4301f8d977e12",
"observability_2metrics_2unified_8h.html#ad374041df577f4adf3585b57b6a1b80fa35fbd17319324dc3861fce590fc99b9e",
"opcodes_8h.html#af66010c45311c44bcef72b3191531b72",
"origin__connection_8c.html#acf6a72b49b4f9ab20adf3539c9f7c1e1",
"parse__x509__signed_8c.html",
"pelican__register_8c.html#a0b347fabede959ea2bdc1b0bd193cd27",
"post__policy_8c.html#af14ad7b87c1d6e78b92ac9c2c23897c1",
"propfind_8c.html#aa20574ccb0b7a59d95dc70c605718bbe",
"protocols_2root_2query_2space_8c.html",
"protocols_2webdav_2lock_8c.html#a4cfb52b8f40abfdea71bc3de464000a3",
"proxy__req__unittest_8c.html#a8f0ad7cb28d4d8a4380f7ea0f880e49a",
"ratelimit__http_8c_source.html",
"registry__select_8c.html#a40f097f462f968d92921a4944b3e72ee",
"root_2fattr_2dispatch_8c.html",
"s3_2put_8c_source.html",
"scan__drift_8h.html#a353076773999586b5ad99580c85e498d",
"sd__block_8c.html#acb7443046bcfc1a307c2b839bb99ec59",
"sd__cephfs__ro__resolve_8c_source.html",
"sd__http__mutate_8c.html#afe617b82e41be84496b475feeff4f75b",
"sd__pblock__unittest__dedup_8c.html#a51f4b9ca874fff5d2271755bd4f1d8d8",
"sd__remote__meta_8c.html#a8efd5276014d4b14c8ea2a05d80ec5ed",
"sd__xroot_8h.html",
"secure_8c.html#a3cb05a4fbb6427e2a2c32fcf2870e7fa",
"sesslog_8c.html#a47f459d4d5825b50487273ca2ae49f50",
"signing__policy_8h.html#a5e2f43cf64d8e01d8040beb9a90525f1",
"src_2fs_2vfs_2vfs_8h.html#a8624f191d8d0d21f18656e685eaaa448",
"ssi__service_8h.html#af7611b03962cc390b0d52d0c2fc699d9",
"stage__request__registry_8h_source.html",
"storascan__internal_8h.html#a8598e9ae6102d928bc4b2f38f4e0057f",
"stream__wmirror__internal_8h.html#af848fa23c6917e5c2460fe5ad4ddcbbaa493b5b72ec871da74f6fc9928074ca2e",
"structClientStatRequest.html#ab192d07b5969f508268169312e889252",
"structbench__worker.html#a2de028afa4b521b5e8a2901750e39f77",
"structbrix__baq__pending__t.html#a58cea0eb9c0db675e4b8586e997ca99b",
"structbrix__ckscan__aio__t.html#a1438bf903ebd788b3928c190cc5aaed2",
"structbrix__copy__opts.html#a66208605b605abc76d228b3b262cf6e4",
"structbrix__ctx__sigver__t.html#a5763cd5e1fad3ba370848430b67b1c5f",
"structbrix__dirlist__aio__t.html#af6538a745f8a09dd1f7f88015d0a335b",
"structbrix__gssapi__srv__s.html#a9eecbb3df7b8ed4a88d3554f4a132b76",
"structbrix__kv__header__t.html#af26819b4f2e9672f3b8bab8438b29217",
"structbrix__open__args__t.html#a352548e1bd374d8dbb6bd04644121e30",
"structbrix__prefetch__t.html#a7314e4eef3f28b9c8d0364d8f73e4e16",
"structbrix__readv__seg.html#a9a2b0681ce8092af0e5bd9208f314b67",
"structbrix__sd__driver__s.html#ab39d90bbcfc36c85bfc4709e62a1908e",
"structbrix__sreq__t.html#a4c78f524384189ebab8d7d1f4dbed7c0",
"structbrix__streamset.html#a58127b704663ebc459abf1a30e40187d",
"structbrix__tpc__transfer__t.html#a66811b8b16c56064336bf606f2b15f4e",
"structbrix__vfs__open__opts.html#aaf1a1e60c63372d31ca9a46a66e95f3b",
"structbrix__xfer__agent__t.html#a806538af90cae522bea7c7bc0fcbd110",
"structckp__pgwrite__drain__t.html#abc3f8918947f277df9e20c9e0cd7173a",
"structcvmfs__geo__entry__t.html",
"structdoctor__cmsloc.html",
"structfp__counters.html#a17fb6362da674db87f96fd53989d8d7f",
"structftp__ev__t.html#ab41b7b795ebeacda18ab17f0b8dd2dcf",
"structimp__stat__t.html#a36905b2478a1308da44088dc8df72bdd",
"structngx__brix__cms__ctx__s.html#aca295d28e631f3693e3faf465cb89ecd",
"structngx__brix__user__global__t.html#af46d1ffbd1348e8aaa32b770945dab61",
"structngx__http__brix__webdav__loc__conf__t.html#a7d6d6efabe4d02ace4ad787e1e54ef88",
"structpblock__obj__t.html#a6696ef175651fb0dfc4868f421c39ae0",
"structrec__t.html#a7d12f5a0ec010d56203c4954ae5a75fe",
"structs3__sign__req.html#a0dfcc850c68227b74d97e8a22fdc62ab",
"structsd__http__open__result__t.html",
"structsrq__rec__t.html#a9fbe079608418e7ebd290c1fb9288b29",
"structtpc__ms__progress__t.html#a060df93408cc7d03d9622f9f6084e185",
"structweb__scheme.html#a151d18a126072f071e1876c586b0273e",
"structxfs__slot.html",
"structxrdw__login__req__t.html#abb9a93afd37ed175778ebe979fa50f5b",
"tables_8c_source.html",
"tmp__path_8h.html#ad623b4cf4e7ebf487302264af3d78402",
"tpc__curl__pmark_8c.html#a87c2274bedbe403ec5acc23fd4f0f14a",
"tunables_8h.html#a3fce84e94cefe28b4a3add50d8e4a741",
"uring__probe_8c.html#a87945fa3ce8d6e9229bcce20df034b68",
"vfs__block_8c.html#a2e9b7bbf75c1ae794925d284c2ff47dd",
"vfs__open__adopt_8c_source.html",
"vfs__writer_8c.html#acbc8efaff350f55a73768c42a4a38d06",
"webdav__module__internal_8h.html#aeab8747159ca3ec7c5eb0887aec5862f",
"wire__codec__ns_8c.html#abc3b8f7020ffe558a940000b7a145abe",
"xfer__core_8c.html",
"xrd__battery_8c.html#a02af99a8ff4729091b708e41317952c4",
"xrdcp_8c.html#af090b82aff6106aacc9b77cb0d9bfc41",
"xrdfs__fmt_8c.html#af1250b3e481a4256dbdc204a5e97ec15",
"xrdmapc_8c.html#ab2c133ca8a85a56c67f89e14efcbe73c",
"xrootdfs__legacy_8c.html#a34c1a0d22d103ee70d8de9d2c0107381",
"zip__kernel_8c.html#aded8ad54d459de18c272b316c98e18ad"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';