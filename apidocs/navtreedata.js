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
    [ "host — host-based authentication for the <tt>root://</tt> stream protocol", "md_src_2auth_2host_2README.html", [
      [ "Overview", "md_src_2auth_2host_2README.html#autotoc_md26", null ],
      [ "Files", "md_src_2auth_2host_2README.html#autotoc_md27", null ]
    ] ],
    [ "<tt>src/auth/impersonate/</tt> — per-request UNIX impersonation (phase 40)", "md_src_2auth_2impersonate_2README.html", [
      [ "Operating modes (<tt>brix_impersonation off|single|map</tt>)", "md_src_2auth_2impersonate_2README.html#autotoc_md29", null ],
      [ "Architecture", "md_src_2auth_2impersonate_2README.html#autotoc_md30", null ],
      [ "Files", "md_src_2auth_2impersonate_2README.html#autotoc_md31", null ],
      [ "How a request routes through it", "md_src_2auth_2impersonate_2README.html#autotoc_md32", null ],
      [ "Safety invariants", "md_src_2auth_2impersonate_2README.html#autotoc_md33", null ],
      [ "Tests", "md_src_2auth_2impersonate_2README.html#autotoc_md34", null ]
    ] ],
    [ "krb5 — Kerberos 5 authentication for the <tt>root://</tt> stream protocol", "md_src_2auth_2krb5_2README.html", [
      [ "Overview", "md_src_2auth_2krb5_2README.html#autotoc_md36", null ],
      [ "Files", "md_src_2auth_2krb5_2README.html#autotoc_md37", null ],
      [ "Key types & data structures", "md_src_2auth_2krb5_2README.html#autotoc_md38", null ],
      [ "Control & data flow", "md_src_2auth_2krb5_2README.html#autotoc_md39", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2krb5_2README.html#autotoc_md40", null ],
      [ "Entry points / extending", "md_src_2auth_2krb5_2README.html#autotoc_md41", null ],
      [ "See also", "md_src_2auth_2krb5_2README.html#autotoc_md42", null ]
    ] ],
    [ "pwd — password (<tt>XrdSecpwd</tt>) authentication for the <tt>root://</tt> stream protocol", "md_src_2auth_2pwd_2README.html", [
      [ "Overview", "md_src_2auth_2pwd_2README.html#autotoc_md44", null ],
      [ "The two-round exchange", "md_src_2auth_2pwd_2README.html#autotoc_md45", null ],
      [ "Files", "md_src_2auth_2pwd_2README.html#autotoc_md46", null ]
    ] ],
    [ "auth — identity and authorization", "md_src_2auth_2README.html", null ],
    [ "sss — Simple Shared Secret authentication (Blowfish-CFB64 + CRC32)", "md_src_2auth_2sss_2README.html", [
      [ "Overview", "md_src_2auth_2sss_2README.html#autotoc_md49", null ],
      [ "Files", "md_src_2auth_2sss_2README.html#autotoc_md50", null ],
      [ "Key types & data structures", "md_src_2auth_2sss_2README.html#autotoc_md51", null ],
      [ "Control & data flow", "md_src_2auth_2sss_2README.html#autotoc_md52", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2sss_2README.html#autotoc_md53", null ],
      [ "Entry points / extending", "md_src_2auth_2sss_2README.html#autotoc_md54", null ],
      [ "See also", "md_src_2auth_2sss_2README.html#autotoc_md55", null ]
    ] ],
    [ "token — WLCG/SciToken JWT and macaroon bearer-token validation", "md_src_2auth_2token_2README.html", [
      [ "Overview", "md_src_2auth_2token_2README.html#autotoc_md57", null ],
      [ "Files", "md_src_2auth_2token_2README.html#autotoc_md58", null ],
      [ "Key types & data structures", "md_src_2auth_2token_2README.html#autotoc_md59", null ],
      [ "Control & data flow", "md_src_2auth_2token_2README.html#autotoc_md60", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2token_2README.html#autotoc_md61", null ],
      [ "Entry points / extending", "md_src_2auth_2token_2README.html#autotoc_md62", null ],
      [ "See also", "md_src_2auth_2token_2README.html#autotoc_md63", null ]
    ] ],
    [ "unix — XRootD <tt>unix</tt> (UNIX-name) authentication handler", "md_src_2auth_2unix_2README.html", [
      [ "Overview", "md_src_2auth_2unix_2README.html#autotoc_md65", null ],
      [ "Files", "md_src_2auth_2unix_2README.html#autotoc_md66", null ],
      [ "Key types & data structures", "md_src_2auth_2unix_2README.html#autotoc_md67", null ],
      [ "Control & data flow", "md_src_2auth_2unix_2README.html#autotoc_md68", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2unix_2README.html#autotoc_md69", null ],
      [ "Entry points / extending", "md_src_2auth_2unix_2README.html#autotoc_md70", null ],
      [ "See also", "md_src_2auth_2unix_2README.html#autotoc_md71", null ]
    ] ],
    [ "voms — Optional VOMS virtual-organisation extraction from X.509 proxies", "md_src_2auth_2voms_2README.html", [
      [ "Overview", "md_src_2auth_2voms_2README.html#autotoc_md73", null ],
      [ "Files", "md_src_2auth_2voms_2README.html#autotoc_md74", null ],
      [ "Key types & data structures", "md_src_2auth_2voms_2README.html#autotoc_md75", null ],
      [ "Control & data flow", "md_src_2auth_2voms_2README.html#autotoc_md76", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2voms_2README.html#autotoc_md77", null ],
      [ "Entry points / extending", "md_src_2auth_2voms_2README.html#autotoc_md78", null ],
      [ "See also", "md_src_2auth_2voms_2README.html#autotoc_md79", null ]
    ] ],
    [ "aio — Thread-pool async file I/O and shared response-chain builders", "md_src_2core_2aio_2README.html", [
      [ "Overview", "md_src_2core_2aio_2README.html#autotoc_md81", null ],
      [ "Optional io_uring backend (Phase 44 — <tt>uring.c</tt> / <tt>uring_submit.c</tt> / <tt>uring_admin.c</tt>)", "md_src_2core_2aio_2README.html#autotoc_md82", null ],
      [ "Thread-pool contract", "md_src_2core_2aio_2README.html#autotoc_md83", null ],
      [ "Files", "md_src_2core_2aio_2README.html#autotoc_md84", null ],
      [ "Key types & data structures", "md_src_2core_2aio_2README.html#autotoc_md85", null ],
      [ "Control & data flow", "md_src_2core_2aio_2README.html#autotoc_md86", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2aio_2README.html#autotoc_md87", null ],
      [ "Entry points / extending", "md_src_2core_2aio_2README.html#autotoc_md88", null ],
      [ "See also", "md_src_2core_2aio_2README.html#autotoc_md89", null ]
    ] ],
    [ "compat — Cross-protocol shared primitives (checksums, paths, filesystem, SSRF)", "md_src_2core_2compat_2README.html", [
      [ "Overview", "md_src_2core_2compat_2README.html#autotoc_md91", null ],
      [ "Files", "md_src_2core_2compat_2README.html#autotoc_md92", [
        [ "Checksums & hex", "md_src_2core_2compat_2README.html#autotoc_md93", null ],
        [ "HTTP-adjacent primitives", "md_src_2core_2compat_2README.html#autotoc_md94", null ],
        [ "Filesystem & namespace mutation", "md_src_2core_2compat_2README.html#autotoc_md95", null ],
        [ "Networking, async, time, logging, SHM", "md_src_2core_2compat_2README.html#autotoc_md96", null ]
      ] ],
      [ "Key types & data structures", "md_src_2core_2compat_2README.html#autotoc_md97", null ],
      [ "Control & data flow", "md_src_2core_2compat_2README.html#autotoc_md98", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2compat_2README.html#autotoc_md99", null ],
      [ "Entry points / extending", "md_src_2core_2compat_2README.html#autotoc_md100", null ],
      [ "See also", "md_src_2core_2compat_2README.html#autotoc_md101", null ]
    ] ],
    [ "config — directive lifecycle, startup validation, and per-worker resource init", "md_src_2core_2config_2README.html", [
      [ "Overview", "md_src_2core_2config_2README.html#autotoc_md103", null ],
      [ "Files", "md_src_2core_2config_2README.html#autotoc_md104", null ],
      [ "Key types & data structures", "md_src_2core_2config_2README.html#autotoc_md105", null ],
      [ "Control & data flow", "md_src_2core_2config_2README.html#autotoc_md106", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2config_2README.html#autotoc_md107", null ],
      [ "Entry points / extending", "md_src_2core_2config_2README.html#autotoc_md108", null ],
      [ "See also", "md_src_2core_2config_2README.html#autotoc_md109", null ]
    ] ],
    [ "http — Shared HTTP request/response semantics (headers, body, conditionals, ETag)", "md_src_2core_2http_2README.html", [
      [ "Overview", "md_src_2core_2http_2README.html#autotoc_md111", null ],
      [ "Files", "md_src_2core_2http_2README.html#autotoc_md112", null ],
      [ "Boundary — what stays in <tt>../compat</tt>", "md_src_2core_2http_2README.html#autotoc_md113", null ],
      [ "Control & data flow", "md_src_2core_2http_2README.html#autotoc_md114", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2http_2README.html#autotoc_md115", null ],
      [ "Entry points / extending", "md_src_2core_2http_2README.html#autotoc_md116", null ],
      [ "See also", "md_src_2core_2http_2README.html#autotoc_md117", null ]
    ] ],
    [ "core — platform primitives shared by every plane", "md_src_2core_2README.html", null ],
    [ "shm — generic cross-worker key/value store and token-bucket rate limiter in nginx shared memory", "md_src_2core_2shm_2README.html", [
      [ "Overview", "md_src_2core_2shm_2README.html#autotoc_md120", null ],
      [ "Files", "md_src_2core_2shm_2README.html#autotoc_md121", null ],
      [ "Key types & data structures", "md_src_2core_2shm_2README.html#autotoc_md122", null ],
      [ "Control & data flow", "md_src_2core_2shm_2README.html#autotoc_md123", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2shm_2README.html#autotoc_md124", null ],
      [ "Entry points / extending", "md_src_2core_2shm_2README.html#autotoc_md125", null ],
      [ "See also", "md_src_2core_2shm_2README.html#autotoc_md126", null ]
    ] ],
    [ "src/core/types — Core type definitions, tunables, and the canonical identity object", "md_src_2core_2types_2README.html", [
      [ "Overview", "md_src_2core_2types_2README.html#autotoc_md128", null ],
      [ "Files", "md_src_2core_2types_2README.html#autotoc_md129", null ],
      [ "Key types & data structures", "md_src_2core_2types_2README.html#autotoc_md130", null ],
      [ "Control & data flow", "md_src_2core_2types_2README.html#autotoc_md131", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2types_2README.html#autotoc_md132", null ],
      [ "Entry points / extending", "md_src_2core_2types_2README.html#autotoc_md133", null ],
      [ "See also", "md_src_2core_2types_2README.html#autotoc_md134", null ]
    ] ],
    [ "fs/backend — Storage Driver (SD) layer", "md_src_2fs_2backend_2README.html", [
      [ "Status — POSIX driver mediates the VFS handle data plane + lifecycle", "md_src_2fs_2backend_2README.html#autotoc_md136", null ],
      [ "Layout — one subdirectory per driver", "md_src_2fs_2backend_2README.html#autotoc_md137", null ],
      [ "Files", "md_src_2fs_2backend_2README.html#autotoc_md138", null ],
      [ "Contract", "md_src_2fs_2backend_2README.html#autotoc_md139", null ],
      [ "Adding a driver", "md_src_2fs_2backend_2README.html#autotoc_md140", null ],
      [ "See also", "md_src_2fs_2backend_2README.html#autotoc_md141", null ]
    ] ],
    [ "<tt>src/fs/cache/origin/</tt> — pluggable origin transports for the read-through cache", "md_src_2fs_2cache_2origin_2README.html", [
      [ "Overview", "md_src_2fs_2cache_2origin_2README.html#autotoc_md143", null ],
      [ "Files", "md_src_2fs_2cache_2origin_2README.html#autotoc_md144", null ],
      [ "Invariants", "md_src_2fs_2cache_2origin_2README.html#autotoc_md145", null ],
      [ "See also", "md_src_2fs_2cache_2origin_2README.html#autotoc_md146", null ]
    ] ],
    [ "<tt>src/fs/cache/</tt> — XCache-style read-through cache and write-through origin mirroring", "md_src_2fs_2cache_2README.html", [
      [ "Overview", "md_src_2fs_2cache_2README.html#autotoc_md148", null ],
      [ "Files", "md_src_2fs_2cache_2README.html#autotoc_md149", [
        [ "Read-through entry points & lifecycle", "md_src_2fs_2cache_2README.html#autotoc_md150", null ],
        [ "Slice cache (Phase 26)", "md_src_2fs_2cache_2README.html#autotoc_md151", null ],
        [ "Origin protocol client (thread-pool, blocking)", "md_src_2fs_2cache_2README.html#autotoc_md152", null ],
        [ "Integrity (checksum-on-fill)", "md_src_2fs_2cache_2README.html#autotoc_md153", null ],
        [ "Cache filesystem bookkeeping", "md_src_2fs_2cache_2README.html#autotoc_md154", null ],
        [ "Eviction", "md_src_2fs_2cache_2README.html#autotoc_md155", null ],
        [ "Unified state engine & parity", "md_src_2fs_2cache_2README.html#autotoc_md156", null ],
        [ "Write-through", "md_src_2fs_2cache_2README.html#autotoc_md157", null ],
        [ "Cache storage on a driver (exclusively-VFS)", "md_src_2fs_2cache_2README.html#autotoc_md158", null ],
        [ "Shared / config / build", "md_src_2fs_2cache_2README.html#autotoc_md159", null ]
      ] ],
      [ "Key types & data structures", "md_src_2fs_2cache_2README.html#autotoc_md160", null ],
      [ "Control & data flow", "md_src_2fs_2cache_2README.html#autotoc_md161", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2cache_2README.html#autotoc_md162", null ],
      [ "Entry points / extending", "md_src_2fs_2cache_2README.html#autotoc_md163", null ],
      [ "See also", "md_src_2fs_2cache_2README.html#autotoc_md164", null ]
    ] ],
    [ "src/fs/core — the shared <tt>vfs</tt> I/O verb layer", "md_src_2fs_2core_2README.html", null ],
    [ "meta — unified per-file metadata sidecar (xmeta)", "md_src_2fs_2meta_2README.html", [
      [ "Overview", "md_src_2fs_2meta_2README.html#autotoc_md167", null ],
      [ "Files", "md_src_2fs_2meta_2README.html#autotoc_md168", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2meta_2README.html#autotoc_md169", null ],
      [ "See also", "md_src_2fs_2meta_2README.html#autotoc_md170", null ]
    ] ],
    [ "path — untrusted-path confinement, resolution, ACL/auth gating, and access logging", "md_src_2fs_2path_2README.html", [
      [ "Overview", "md_src_2fs_2path_2README.html#autotoc_md172", null ],
      [ "Files", "md_src_2fs_2path_2README.html#autotoc_md173", null ],
      [ "Key types & data structures", "md_src_2fs_2path_2README.html#autotoc_md174", null ],
      [ "Control & data flow", "md_src_2fs_2path_2README.html#autotoc_md175", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2path_2README.html#autotoc_md176", null ],
      [ "Entry points / extending", "md_src_2fs_2path_2README.html#autotoc_md177", null ],
      [ "See also", "md_src_2fs_2path_2README.html#autotoc_md178", null ]
    ] ],
    [ "fs — Unified VFS: the single POSIX-filesystem data plane", "md_src_2fs_2README.html", [
      [ "Overview", "md_src_2fs_2README.html#autotoc_md180", null ],
      [ "Shared with the userland clients: <tt>module→vfs_server→vfs→backend</tt>", "md_src_2fs_2README.html#autotoc_md181", null ],
      [ "Files", "md_src_2fs_2README.html#autotoc_md182", null ],
      [ "Key types & data structures", "md_src_2fs_2README.html#autotoc_md183", null ],
      [ "Control & data flow", "md_src_2fs_2README.html#autotoc_md184", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2README.html#autotoc_md185", null ],
      [ "The CI seam guard (three tiers)", "md_src_2fs_2README.html#autotoc_md186", null ],
      [ "Entry points / extending", "md_src_2fs_2README.html#autotoc_md187", null ],
      [ "See also", "md_src_2fs_2README.html#autotoc_md188", null ]
    ] ],
    [ "<tt>src/fs/scan/</tt> — bulk storage scan / verify / inventory engine", "md_src_2fs_2scan_2README.html", [
      [ "Layering", "md_src_2fs_2scan_2README.html#autotoc_md190", null ],
      [ "Files", "md_src_2fs_2scan_2README.html#autotoc_md191", null ],
      [ "Endpoint", "md_src_2fs_2scan_2README.html#autotoc_md192", null ],
      [ "Status", "md_src_2fs_2scan_2README.html#autotoc_md193", null ]
    ] ],
    [ "tier — composable storage tiers (cache/stage decorators over backends)", "md_src_2fs_2tier_2README.html", [
      [ "Overview", "md_src_2fs_2tier_2README.html#autotoc_md195", null ],
      [ "Files", "md_src_2fs_2tier_2README.html#autotoc_md196", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2tier_2README.html#autotoc_md197", null ],
      [ "See also", "md_src_2fs_2tier_2README.html#autotoc_md198", null ]
    ] ],
    [ "fs/vfs — the VFS facade (public API + per-op implementations)", "md_src_2fs_2vfs_2README.html", null ],
    [ "<tt>src/fs/xfer/</tt> — unified durable-transfer engine", "md_src_2fs_2xfer_2README.html", [
      [ "Where it sits", "md_src_2fs_2xfer_2README.html#autotoc_md201", null ],
      [ "Files", "md_src_2fs_2xfer_2README.html#autotoc_md202", null ],
      [ "STAGE audit coverage — every upload mode", "md_src_2fs_2xfer_2README.html#autotoc_md203", null ],
      [ "Reload contract (§8b)", "md_src_2fs_2xfer_2README.html#autotoc_md204", [
        [ "The audit line (Phase 2)", "md_src_2fs_2xfer_2README.html#autotoc_md205", null ]
      ] ],
      [ "Durability (spec §7–§8)", "md_src_2fs_2xfer_2README.html#autotoc_md206", null ]
    ] ],
    [ "cms — XRootD CMS cluster membership (heartbeat client + manager-side server)", "md_src_2net_2cms_2README.html", [
      [ "Overview", "md_src_2net_2cms_2README.html#autotoc_md208", null ],
      [ "Files", "md_src_2net_2cms_2README.html#autotoc_md209", [
        [ "Heartbeat client (main module)", "md_src_2net_2cms_2README.html#autotoc_md210", null ],
        [ "Shared frame I/O", "md_src_2net_2cms_2README.html#autotoc_md211", null ],
        [ "Manager-side server (<tt>ngx_stream_brix_cms_srv_module</tt>)", "md_src_2net_2cms_2README.html#autotoc_md212", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2cms_2README.html#autotoc_md213", null ],
      [ "Control & data flow", "md_src_2net_2cms_2README.html#autotoc_md214", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2cms_2README.html#autotoc_md215", null ],
      [ "Entry points / extending", "md_src_2net_2cms_2README.html#autotoc_md216", null ],
      [ "See also", "md_src_2net_2cms_2README.html#autotoc_md217", null ]
    ] ],
    [ "net/guard — protocol-agnostic bad-actor classifier", "md_src_2net_2guard_2README.html", [
      [ "The <tt>guard_request_t</tt> contract", "md_src_2net_2guard_2README.html#autotoc_md219", null ],
      [ "Audit line (the fail2ban contract)", "md_src_2net_2guard_2README.html#autotoc_md220", null ],
      [ "Testing", "md_src_2net_2guard_2README.html#autotoc_md221", null ]
    ] ],
    [ "net/httpguard — HTTP adapter for the bad-actor guard", "md_src_2net_2httpguard_2README.html", [
      [ "Directives", "md_src_2net_2httpguard_2README.html#autotoc_md223", null ],
      [ "ARC deployment recipe", "md_src_2net_2httpguard_2README.html#autotoc_md224", null ],
      [ "fail2ban wiring", "md_src_2net_2httpguard_2README.html#autotoc_md225", null ],
      [ "Tests", "md_src_2net_2httpguard_2README.html#autotoc_md226", null ]
    ] ],
    [ "manager — Cluster / redirector control plane (server registry, redirect cache, active health checks)", "md_src_2net_2manager_2README.html", [
      [ "Overview", "md_src_2net_2manager_2README.html#autotoc_md228", null ],
      [ "Files", "md_src_2net_2manager_2README.html#autotoc_md229", null ],
      [ "Key types & data structures", "md_src_2net_2manager_2README.html#autotoc_md230", null ],
      [ "Control & data flow", "md_src_2net_2manager_2README.html#autotoc_md231", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2manager_2README.html#autotoc_md232", null ],
      [ "Entry points / extending", "md_src_2net_2manager_2README.html#autotoc_md233", null ],
      [ "See also", "md_src_2net_2manager_2README.html#autotoc_md234", null ]
    ] ],
    [ "mirror — fire-and-forget traffic mirroring (shadow replay) for XRootD and WebDAV", "md_src_2net_2mirror_2README.html", [
      [ "Overview", "md_src_2net_2mirror_2README.html#autotoc_md236", null ],
      [ "Files", "md_src_2net_2mirror_2README.html#autotoc_md237", null ],
      [ "Key types & data structures", "md_src_2net_2mirror_2README.html#autotoc_md238", null ],
      [ "Control & data flow", "md_src_2net_2mirror_2README.html#autotoc_md239", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2mirror_2README.html#autotoc_md240", null ],
      [ "Entry points / extending", "md_src_2net_2mirror_2README.html#autotoc_md241", null ],
      [ "See also", "md_src_2net_2mirror_2README.html#autotoc_md242", null ]
    ] ],
    [ "proxy — Transparent XRootD reverse proxy (<tt>brix_proxy</tt>)", "md_src_2net_2proxy_2README.html", [
      [ "Overview", "md_src_2net_2proxy_2README.html#autotoc_md244", null ],
      [ "Files", "md_src_2net_2proxy_2README.html#autotoc_md245", null ],
      [ "Key types & data structures", "md_src_2net_2proxy_2README.html#autotoc_md246", null ],
      [ "Control & data flow", "md_src_2net_2proxy_2README.html#autotoc_md247", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2proxy_2README.html#autotoc_md248", null ],
      [ "Entry points / extending", "md_src_2net_2proxy_2README.html#autotoc_md249", null ],
      [ "See also", "md_src_2net_2proxy_2README.html#autotoc_md250", null ]
    ] ],
    [ "ratelimit — identity-aware leaky-bucket rate, bandwidth & concurrency limiting (Phase 25)", "md_src_2net_2ratelimit_2README.html", [
      [ "Overview", "md_src_2net_2ratelimit_2README.html#autotoc_md252", null ],
      [ "Files", "md_src_2net_2ratelimit_2README.html#autotoc_md253", null ],
      [ "Key types & data structures", "md_src_2net_2ratelimit_2README.html#autotoc_md254", null ],
      [ "Directive reference (configuration surface)", "md_src_2net_2ratelimit_2README.html#autotoc_md255", null ],
      [ "Control & data flow", "md_src_2net_2ratelimit_2README.html#autotoc_md256", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2ratelimit_2README.html#autotoc_md257", null ],
      [ "Entry points / extending", "md_src_2net_2ratelimit_2README.html#autotoc_md258", null ],
      [ "See also", "md_src_2net_2ratelimit_2README.html#autotoc_md259", null ]
    ] ],
    [ "net — clustering, proxying, shadowing, and connection defense", "md_src_2net_2README.html", null ],
    [ "tap — ngx-free protocol observation tap (decode + sink fan-out)", "md_src_2net_2tap_2README.html", [
      [ "Overview", "md_src_2net_2tap_2README.html#autotoc_md262", null ],
      [ "Files", "md_src_2net_2tap_2README.html#autotoc_md263", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2tap_2README.html#autotoc_md264", null ],
      [ "See also", "md_src_2net_2tap_2README.html#autotoc_md265", null ]
    ] ],
    [ "upstream — outbound XRootD redirector/proxy client (manager-side server-to-server query)", "md_src_2net_2upstream_2README.html", [
      [ "Overview", "md_src_2net_2upstream_2README.html#autotoc_md267", null ],
      [ "Files", "md_src_2net_2upstream_2README.html#autotoc_md268", null ],
      [ "Key types & data structures", "md_src_2net_2upstream_2README.html#autotoc_md269", null ],
      [ "Control & data flow", "md_src_2net_2upstream_2README.html#autotoc_md270", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2upstream_2README.html#autotoc_md271", null ],
      [ "Entry points / extending", "md_src_2net_2upstream_2README.html#autotoc_md272", null ],
      [ "See also", "md_src_2net_2upstream_2README.html#autotoc_md273", null ]
    ] ],
    [ "dashboard — live HTTPS transfer monitor + REST admin write API", "md_src_2observability_2dashboard_2README.html", [
      [ "Overview", "md_src_2observability_2dashboard_2README.html#autotoc_md275", null ],
      [ "Files", "md_src_2observability_2dashboard_2README.html#autotoc_md276", null ],
      [ "Key types & data structures", "md_src_2observability_2dashboard_2README.html#autotoc_md277", null ],
      [ "Control & data flow", "md_src_2observability_2dashboard_2README.html#autotoc_md278", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2dashboard_2README.html#autotoc_md279", null ],
      [ "Entry points / extending", "md_src_2observability_2dashboard_2README.html#autotoc_md280", null ],
      [ "See also", "md_src_2observability_2dashboard_2README.html#autotoc_md281", null ],
      [ "VFS export browser (<tt>brix_dashboard_vfs_browse on</tt>)", "md_src_2observability_2dashboard_2README.html#autotoc_md282", null ]
    ] ],
    [ "metrics — shared-memory counters and the Prometheus <tt>/metrics</tt> exporter", "md_src_2observability_2metrics_2README.html", [
      [ "Overview", "md_src_2observability_2metrics_2README.html#autotoc_md284", null ],
      [ "Files", "md_src_2observability_2metrics_2README.html#autotoc_md285", null ],
      [ "Key types & data structures", "md_src_2observability_2metrics_2README.html#autotoc_md286", null ],
      [ "Control & data flow", "md_src_2observability_2metrics_2README.html#autotoc_md287", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2metrics_2README.html#autotoc_md288", null ],
      [ "Entry points / extending", "md_src_2observability_2metrics_2README.html#autotoc_md289", null ],
      [ "See also", "md_src_2observability_2metrics_2README.html#autotoc_md290", null ]
    ] ],
    [ "pmark — SciTags packet marking", "md_src_2observability_2pmark_2README.html", [
      [ "Overview", "md_src_2observability_2pmark_2README.html#autotoc_md292", null ],
      [ "Files", "md_src_2observability_2pmark_2README.html#autotoc_md293", null ],
      [ "Configuration", "md_src_2observability_2pmark_2README.html#autotoc_md294", null ],
      [ "Control & data flow", "md_src_2observability_2pmark_2README.html#autotoc_md295", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2pmark_2README.html#autotoc_md296", null ],
      [ "See also", "md_src_2observability_2pmark_2README.html#autotoc_md297", null ]
    ] ],
    [ "observability — metrics, packet marking, dashboard, and access logs", "md_src_2observability_2README.html", null ],
    [ "cvmfs — the cvmfs:// site cache (+ experimental scvmfs:// TLS variant)", "md_src_2protocols_2cvmfs_2README.html", [
      [ "Overview", "md_src_2protocols_2cvmfs_2README.html#autotoc_md300", null ],
      [ "Files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md301", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2cvmfs_2README.html#autotoc_md302", null ],
      [ "See also", "md_src_2protocols_2cvmfs_2README.html#autotoc_md303", null ]
    ] ],
    [ "<tt>src/protocols/dig/</tt> — XrdDig-style remote diagnostics", "md_src_2protocols_2dig_2README.html", [
      [ "Overview", "md_src_2protocols_2dig_2README.html#autotoc_md305", null ],
      [ "Files", "md_src_2protocols_2dig_2README.html#autotoc_md306", null ],
      [ "See also", "md_src_2protocols_2dig_2README.html#autotoc_md307", null ]
    ] ],
    [ "protocols — one subdirectory per wire protocol", "md_src_2protocols_2README.html", null ],
    [ "connection — TCP connection lifecycle, framing, and the async I/O state machine for <tt>root://</tt>", "md_src_2protocols_2root_2connection_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2connection_2README.html#autotoc_md310", null ],
      [ "Files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md311", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2connection_2README.html#autotoc_md312", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2connection_2README.html#autotoc_md313", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2connection_2README.html#autotoc_md314", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2connection_2README.html#autotoc_md315", null ],
      [ "See also", "md_src_2protocols_2root_2connection_2README.html#autotoc_md316", null ]
    ] ],
    [ "dirlist — XRootD <tt>kXR_dirlist</tt> directory enumeration (stream protocol)", "md_src_2protocols_2root_2dirlist_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md318", null ],
      [ "Files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md319", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md320", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md321", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md322", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md323", null ],
      [ "See also", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md324", null ]
    ] ],
    [ "fattr — XRootD <tt>kXR_fattr</tt> extended-attribute operations", "md_src_2protocols_2root_2fattr_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md326", null ],
      [ "Files", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md327", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md328", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md329", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md330", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md331", null ],
      [ "See also", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md332", null ]
    ] ],
    [ "handoff — single-port protocol handoff for the stream xrootd listener", "md_src_2protocols_2root_2handoff_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md334", null ],
      [ "Files", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md335", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md336", null ],
      [ "See also", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md337", null ]
    ] ],
    [ "handshake — XRootD stream request entry point and opcode dispatcher", "md_src_2protocols_2root_2handshake_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md339", null ],
      [ "Files", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md340", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md341", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md342", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md343", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md344", null ],
      [ "See also", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md345", null ]
    ] ],
    [ "path — wire-path extraction, sanitization, and stat formatting", "md_src_2protocols_2root_2path_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2path_2README.html#autotoc_md347", null ],
      [ "Files", "md_src_2protocols_2root_2path_2README.html#autotoc_md348", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2path_2README.html#autotoc_md349", null ],
      [ "See also", "md_src_2protocols_2root_2path_2README.html#autotoc_md350", null ]
    ] ],
    [ "protocol — XRootD <tt>root://</tt> wire-format constants & packed structs", "md_src_2protocols_2root_2protocol_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md352", [
        [ "Provenance & licensing", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md353", null ]
      ] ],
      [ "Files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md354", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md355", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md356", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md357", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md358", null ],
      [ "See also", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md359", null ]
    ] ],
    [ "query — XRootD <tt>kXR_query</tt> sub-protocol, <tt>kXR_prepare</tt> staging, and <tt>kXR_set</tt> hints", "md_src_2protocols_2root_2query_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2query_2README.html#autotoc_md361", null ],
      [ "Files", "md_src_2protocols_2root_2query_2README.html#autotoc_md362", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2query_2README.html#autotoc_md363", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2query_2README.html#autotoc_md364", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2query_2README.html#autotoc_md365", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2query_2README.html#autotoc_md366", null ],
      [ "See also", "md_src_2protocols_2root_2query_2README.html#autotoc_md367", null ]
    ] ],
    [ "read — XRootD read-side opcodes and the file-handle lifecycle", "md_src_2protocols_2root_2read_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2read_2README.html#autotoc_md369", null ],
      [ "Files", "md_src_2protocols_2root_2read_2README.html#autotoc_md370", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2read_2README.html#autotoc_md371", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2read_2README.html#autotoc_md372", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2read_2README.html#autotoc_md373", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2read_2README.html#autotoc_md374", null ],
      [ "See also", "md_src_2protocols_2root_2read_2README.html#autotoc_md375", null ]
    ] ],
    [ "root — the XRootD (<tt>root://</tt> / <tt>roots://</tt>) protocol plane", "md_src_2protocols_2root_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2README.html#autotoc_md377", null ],
      [ "Subdirectories", "md_src_2protocols_2root_2README.html#autotoc_md378", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2README.html#autotoc_md379", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2README.html#autotoc_md380", null ],
      [ "See also", "md_src_2protocols_2root_2README.html#autotoc_md381", null ]
    ] ],
    [ "relay — transparent pass-through relay with a passive observation tap", "md_src_2protocols_2root_2relay_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2relay_2README.html#autotoc_md383", null ],
      [ "Files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md384", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2relay_2README.html#autotoc_md385", null ],
      [ "See also", "md_src_2protocols_2root_2relay_2README.html#autotoc_md386", null ]
    ] ],
    [ "response — XRootD wire-response framing helpers", "md_src_2protocols_2root_2response_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2response_2README.html#autotoc_md388", null ],
      [ "Files", "md_src_2protocols_2root_2response_2README.html#autotoc_md389", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2response_2README.html#autotoc_md390", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2response_2README.html#autotoc_md391", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2response_2README.html#autotoc_md392", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2response_2README.html#autotoc_md393", null ],
      [ "See also", "md_src_2protocols_2root_2response_2README.html#autotoc_md394", null ]
    ] ],
    [ "session — XRootD session lifecycle, identity binding & cross-worker registry", "md_src_2protocols_2root_2session_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2session_2README.html#autotoc_md396", null ],
      [ "Files", "md_src_2protocols_2root_2session_2README.html#autotoc_md397", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2session_2README.html#autotoc_md398", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2session_2README.html#autotoc_md399", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2session_2README.html#autotoc_md400", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2session_2README.html#autotoc_md401", null ],
      [ "See also", "md_src_2protocols_2root_2session_2README.html#autotoc_md402", null ]
    ] ],
    [ "stream — <tt>ngx_stream_brix_module</tt> descriptor & directive table", "md_src_2protocols_2root_2stream_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2stream_2README.html#autotoc_md404", null ],
      [ "Files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md405", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2stream_2README.html#autotoc_md406", [
        [ "Directive groups (authoritative <tt>module.c</tt> set)", "md_src_2protocols_2root_2stream_2README.html#autotoc_md407", null ]
      ] ],
      [ "Control & data flow", "md_src_2protocols_2root_2stream_2README.html#autotoc_md408", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2stream_2README.html#autotoc_md409", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2stream_2README.html#autotoc_md410", null ],
      [ "See also", "md_src_2protocols_2root_2stream_2README.html#autotoc_md411", null ]
    ] ],
    [ "write — XRootD mutating-opcode handlers (the stream write path)", "md_src_2protocols_2root_2write_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2write_2README.html#autotoc_md413", null ],
      [ "Files", "md_src_2protocols_2root_2write_2README.html#autotoc_md414", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2write_2README.html#autotoc_md415", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2write_2README.html#autotoc_md416", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2write_2README.html#autotoc_md417", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2write_2README.html#autotoc_md418", null ],
      [ "See also", "md_src_2protocols_2root_2write_2README.html#autotoc_md419", null ]
    ] ],
    [ "src/protocols/root/zip — ZIP member access (phase-57 W2)", "md_src_2protocols_2root_2zip_2README.html", [
      [ "Status", "md_src_2protocols_2root_2zip_2README.html#autotoc_md421", null ],
      [ "zip_dir.c — the parser", "md_src_2protocols_2root_2zip_2README.html#autotoc_md422", null ],
      [ "Running the unit test (standalone, no nginx build)", "md_src_2protocols_2root_2zip_2README.html#autotoc_md423", null ]
    ] ],
    [ "s3 — S3-compatible REST endpoint over the local export root", "md_src_2protocols_2s3_2README.html", [
      [ "Overview", "md_src_2protocols_2s3_2README.html#autotoc_md425", null ],
      [ "Files", "md_src_2protocols_2s3_2README.html#autotoc_md426", null ],
      [ "Key types & data structures", "md_src_2protocols_2s3_2README.html#autotoc_md427", null ],
      [ "Control & data flow", "md_src_2protocols_2s3_2README.html#autotoc_md428", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2s3_2README.html#autotoc_md429", null ],
      [ "Entry points / extending", "md_src_2protocols_2s3_2README.html#autotoc_md430", null ],
      [ "See also", "md_src_2protocols_2s3_2README.html#autotoc_md431", null ]
    ] ],
    [ "shared — cross-protocol helper library (HTTP file serving + overflow-safe size math)", "md_src_2protocols_2shared_2README.html", [
      [ "Overview", "md_src_2protocols_2shared_2README.html#autotoc_md433", null ],
      [ "Files", "md_src_2protocols_2shared_2README.html#autotoc_md434", null ],
      [ "Key types & data structures", "md_src_2protocols_2shared_2README.html#autotoc_md435", null ],
      [ "Control & data flow", "md_src_2protocols_2shared_2README.html#autotoc_md436", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2shared_2README.html#autotoc_md437", null ],
      [ "Entry points / extending", "md_src_2protocols_2shared_2README.html#autotoc_md438", null ],
      [ "See also", "md_src_2protocols_2shared_2README.html#autotoc_md439", null ]
    ] ],
    [ "<tt>src/protocols/srr/</tt> — WLCG Storage Resource Reporting (SRR) endpoint", "md_src_2protocols_2srr_2README.html", [
      [ "Why this instead of the XRootD UDP monitoring stack", "md_src_2protocols_2srr_2README.html#autotoc_md441", null ],
      [ "Files", "md_src_2protocols_2srr_2README.html#autotoc_md442", null ],
      [ "Configuration", "md_src_2protocols_2srr_2README.html#autotoc_md443", null ],
      [ "Semantics & caveats", "md_src_2protocols_2srr_2README.html#autotoc_md444", null ],
      [ "Schema conformance", "md_src_2protocols_2srr_2README.html#autotoc_md445", null ]
    ] ],
    [ "<tt>src/protocols/ssi/</tt> — XrdSsi request/response service over <tt>root://</tt>", "md_src_2protocols_2ssi_2README.html", [
      [ "Overview", "md_src_2protocols_2ssi_2README.html#autotoc_md447", null ],
      [ "Phase 1: session multiplexing (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md448", null ],
      [ "Phase 2: async server-push via <tt>kXR_attn</tt> (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md449", null ],
      [ "Phase 3: streamed responses + delivered alerts (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md450", null ],
      [ "Phases 4–5: CTA flagship service (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md451", null ],
      [ "Phase 6: config, metrics, conformance (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md452", [
        [ "Directives (<tt>NGX_STREAM_SRV_CONF</tt>)", "md_src_2protocols_2ssi_2README.html#autotoc_md453", null ],
        [ "Metrics (low-cardinality — <tt>{port,auth}</tt> only)", "md_src_2protocols_2ssi_2README.html#autotoc_md454", null ],
        [ "Conformance", "md_src_2protocols_2ssi_2README.html#autotoc_md455", null ]
      ] ],
      [ "RRInfo wire layout", "md_src_2protocols_2ssi_2README.html#autotoc_md456", null ],
      [ "Files", "md_src_2protocols_2ssi_2README.html#autotoc_md457", null ],
      [ "See also", "md_src_2protocols_2ssi_2README.html#autotoc_md458", null ]
    ] ],
    [ "<tt>src/protocols/ssi/svc_cta/</tt> — flagship CTA tape service", "md_src_2protocols_2ssi_2svc__cta_2README.html", [
      [ "Layers", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md460", null ],
      [ "Request lifecycle", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md461", [
        [ "State machine", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md462", null ],
        [ "Executor", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md463", null ],
        [ "Security", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md464", null ],
        [ "Journal (restart recovery)", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md465", null ]
      ] ],
      [ "External contract — the pinned field table", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md466", null ],
      [ "Golden-vector provenance", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md467", null ],
      [ "Scope notes", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md468", null ]
    ] ],
    [ "webdav/fs — Confined local-filesystem copy engine for WebDAV COPY/MOVE", "md_src_2protocols_2webdav_2fs_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md470", null ],
      [ "Files", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md471", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md472", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md473", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md474", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md475", null ],
      [ "See also", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md476", null ]
    ] ],
    [ "webdav/locks — WebDAV LOCK request-header & body parsers", "md_src_2protocols_2webdav_2locks_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md478", null ],
      [ "Files", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md479", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md480", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md481", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md482", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md483", null ],
      [ "See also", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md484", null ]
    ] ],
    [ "webdav/methods — Per-method WebDAV precondition helpers", "md_src_2protocols_2webdav_2methods_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md486", null ],
      [ "Files", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md487", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md488", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md489", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md490", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md491", null ],
      [ "See also", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md492", null ]
    ] ],
    [ "webdav — HTTP/WebDAV/HTTPS gateway (<tt>davs://</tt>, <tt>http://</tt>) over the export root", "md_src_2protocols_2webdav_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2README.html#autotoc_md494", null ],
      [ "Files", "md_src_2protocols_2webdav_2README.html#autotoc_md495", [
        [ "Module wiring & configuration", "md_src_2protocols_2webdav_2README.html#autotoc_md496", null ],
        [ "Dispatch & generic helpers", "md_src_2protocols_2webdav_2README.html#autotoc_md497", null ],
        [ "HTTP method handlers", "md_src_2protocols_2webdav_2README.html#autotoc_md498", null ],
        [ "Authentication", "md_src_2protocols_2webdav_2README.html#autotoc_md499", null ],
        [ "HTTP-TPC (third-party copy)", "md_src_2protocols_2webdav_2README.html#autotoc_md500", null ],
        [ "Upstream proxy mode", "md_src_2protocols_2webdav_2README.html#autotoc_md501", null ],
        [ "XrdHttp protocol extension", "md_src_2protocols_2webdav_2README.html#autotoc_md502", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2README.html#autotoc_md503", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2README.html#autotoc_md504", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2README.html#autotoc_md505", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2README.html#autotoc_md506", null ],
      [ "See also", "md_src_2protocols_2webdav_2README.html#autotoc_md507", null ]
    ] ],
    [ "webdav/util — WebDAV URI decoding and XML escaping helpers", "md_src_2protocols_2webdav_2util_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md509", null ],
      [ "Files", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md510", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md511", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md512", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md513", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md514", null ],
      [ "See also", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md515", null ]
    ] ],
    [ "src — nginx-xrootd Source Tree", "md_src_2README.html", [
      [ "Source map", "md_src_2README.html#autotoc_md518", [
        [ "Top-level files (now under <tt>core/</tt>)", "md_src_2README.html#autotoc_md519", null ],
        [ "Entry & dispatch", "md_src_2README.html#autotoc_md520", null ],
        [ "Protocol handlers", "md_src_2README.html#autotoc_md521", null ],
        [ "Data plane", "md_src_2README.html#autotoc_md522", null ],
        [ "Path & confinement", "md_src_2README.html#autotoc_md523", null ],
        [ "Authentication", "md_src_2README.html#autotoc_md524", null ],
        [ "Cluster & federation", "md_src_2README.html#autotoc_md525", null ],
        [ "Cross-cutting", "md_src_2README.html#autotoc_md526", null ],
        [ "WebDAV sub-helpers", "md_src_2README.html#autotoc_md527", null ]
      ] ],
      [ "The four request lifecycles", "md_src_2README.html#autotoc_md529", [
        [ "<tt>root://</tt> stream", "md_src_2README.html#autotoc_md530", null ],
        [ "<tt>davs://</tt> WebDAV", "md_src_2README.html#autotoc_md531", null ],
        [ "S3 REST", "md_src_2README.html#autotoc_md532", null ],
        [ "CMS cluster redirect", "md_src_2README.html#autotoc_md533", null ]
      ] ],
      [ "Cross-cutting invariants", "md_src_2README.html#autotoc_md535", null ],
      [ "How to navigate / where to start reading", "md_src_2README.html#autotoc_md537", null ]
    ] ],
    [ "tpc/common — Protocol-neutral third-party-copy (TPC) core", "md_src_2tpc_2common_2README.html", [
      [ "Overview", "md_src_2tpc_2common_2README.html#autotoc_md539", null ],
      [ "Files", "md_src_2tpc_2common_2README.html#autotoc_md540", null ],
      [ "Key types & data structures", "md_src_2tpc_2common_2README.html#autotoc_md541", null ],
      [ "Control & data flow", "md_src_2tpc_2common_2README.html#autotoc_md542", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2common_2README.html#autotoc_md543", null ],
      [ "Entry points / extending", "md_src_2tpc_2common_2README.html#autotoc_md544", null ],
      [ "See also", "md_src_2tpc_2common_2README.html#autotoc_md545", null ]
    ] ],
    [ "engine — native-TPC control plane (destination side)", "md_src_2tpc_2engine_2README.html", [
      [ "Overview", "md_src_2tpc_2engine_2README.html#autotoc_md547", null ],
      [ "Files", "md_src_2tpc_2engine_2README.html#autotoc_md548", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2engine_2README.html#autotoc_md549", null ],
      [ "See also", "md_src_2tpc_2engine_2README.html#autotoc_md550", null ]
    ] ],
    [ "gsi — outbound GSI authentication for the TPC pull socket", "md_src_2tpc_2gsi_2README.html", [
      [ "Overview", "md_src_2tpc_2gsi_2README.html#autotoc_md552", null ],
      [ "Files", "md_src_2tpc_2gsi_2README.html#autotoc_md553", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2gsi_2README.html#autotoc_md554", null ],
      [ "See also", "md_src_2tpc_2gsi_2README.html#autotoc_md555", null ]
    ] ],
    [ "outbound — the blocking source-session client for native TPC pulls", "md_src_2tpc_2outbound_2README.html", [
      [ "Overview", "md_src_2tpc_2outbound_2README.html#autotoc_md557", null ],
      [ "Files", "md_src_2tpc_2outbound_2README.html#autotoc_md558", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2outbound_2README.html#autotoc_md559", null ],
      [ "See also", "md_src_2tpc_2outbound_2README.html#autotoc_md560", null ]
    ] ],
    [ "tpc — Native XRootD third-party-copy (destination-side pull)", "md_src_2tpc_2README.html", [
      [ "Overview", "md_src_2tpc_2README.html#autotoc_md562", null ],
      [ "Files", "md_src_2tpc_2README.html#autotoc_md563", null ],
      [ "Key types & data structures", "md_src_2tpc_2README.html#autotoc_md564", null ],
      [ "Control & data flow", "md_src_2tpc_2README.html#autotoc_md565", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2README.html#autotoc_md566", null ],
      [ "Entry points / extending", "md_src_2tpc_2README.html#autotoc_md567", null ],
      [ "See also", "md_src_2tpc_2README.html#autotoc_md568", null ]
    ] ],
    [ "<tt>client/apps/</tt> — native client CLI tools", "md_client_2apps_2README.html", [
      [ "Data movement", "md_client_2apps_2README.html#autotoc_md570", null ],
      [ "Checksums & verification", "md_client_2apps_2README.html#autotoc_md571", null ],
      [ "Diagnostics & monitoring", "md_client_2apps_2README.html#autotoc_md572", null ],
      [ "Auth & security", "md_client_2apps_2README.html#autotoc_md573", null ],
      [ "Namespace / staging", "md_client_2apps_2README.html#autotoc_md574", null ],
      [ "Optional (built only when <tt>libfuse3</tt> is present — not in <tt>BINS</tt>)", "md_client_2apps_2README.html#autotoc_md575", null ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2apps_2README.html#autotoc_md576", null ],
      [ "Man pages & bash completion", "md_client_2apps_2README.html#autotoc_md577", null ],
      [ "CLI compatibility contract (binding for all flag/env/output work)", "md_client_2apps_2README.html#autotoc_md578", null ],
      [ "See also", "md_client_2apps_2README.html#autotoc_md579", null ]
    ] ],
    [ "<tt>client/lib/sec/</tt> — native client authentication modules", "md_client_2lib_2auth_2sec_2README.html", [
      [ "Overview", "md_client_2lib_2auth_2sec_2README.html#autotoc_md581", null ],
      [ "Files", "md_client_2lib_2auth_2sec_2README.html#autotoc_md582", null ],
      [ "Invariants", "md_client_2lib_2auth_2sec_2README.html#autotoc_md583", null ],
      [ "See also", "md_client_2lib_2auth_2sec_2README.html#autotoc_md584", null ]
    ] ],
    [ "<tt>client/lib/</tt> — native XRootD client library (<tt>libbrix</tt>)", "md_client_2lib_2README.html", [
      [ "Concept buckets (phase-69)", "md_client_2lib_2README.html#autotoc_md586", null ],
      [ "File responsibilities (Phase-38 split groups)", "md_client_2lib_2README.html#autotoc_md587", null ]
    ] ],
    [ "<tt>client/preload/</tt> — LD_PRELOAD POSIX → XRootD shim", "md_client_2preload_2README.html", [
      [ "Overview", "md_client_2preload_2README.html#autotoc_md589", null ],
      [ "How it works", "md_client_2preload_2README.html#autotoc_md590", null ],
      [ "Scope", "md_client_2preload_2README.html#autotoc_md591", null ],
      [ "Files", "md_client_2preload_2README.html#autotoc_md592", null ],
      [ "See also", "md_client_2preload_2README.html#autotoc_md593", null ]
    ] ],
    [ "<tt>client/</tt> — native BriX client tools", "md_client_2README.html", [
      [ "Directory layout", "md_client_2README.html#autotoc_md595", null ],
      [ "Build", "md_client_2README.html#autotoc_md596", null ],
      [ "Feature summary (2026-07-05)", "md_client_2README.html#autotoc_md597", [
        [ "xrdcp", "md_client_2README.html#autotoc_md598", null ],
        [ "xrdfs", "md_client_2README.html#autotoc_md599", null ],
        [ "xrdcksum", "md_client_2README.html#autotoc_md600", null ],
        [ "xrddiag", "md_client_2README.html#autotoc_md601", null ]
      ] ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2README.html#autotoc_md602", null ],
      [ "Man pages & bash completion", "md_client_2README.html#autotoc_md603", null ],
      [ "See also", "md_client_2README.html#autotoc_md604", null ]
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
"api__admin__config_8c.html",
"auth__gate_8c.html#a19a46a784937bdad0f4fd038bd374813",
"brix__auth_8h.html#ae6aa49a0abef6221bcb4417bc0d2d926",
"brixcvmfs_8c.html#a7f41d3eeaa16ee6b8c97bda36c3f7204",
"buffers_8c.html#a85db65627b666d590a93f19d0a9949f1",
"checksum_8h.html#a07e6e7aacbcd45889ed3021a6ac373b9a8826761593f82249cff986aea32505c1",
"cli__opts_8c_source.html",
"cms__internal_8h.html#a622f8d407e009b3a7e7d47ed34adb8df",
"conn_8c.html#a44fea517d5cb4f3eb71c09b5b68f78a9",
"core_2compat_2xml_8c_source.html",
"csi__unittest_8c.html#a357d8cafa1ee34c5ef4da48dadf05e4f",
"cvmfs_8h.html#a59bac5b0bba86f3a651211be7af3ae66",
"delegation_8h.html#a0642e6491c9a01ce328781fafab9c7a9",
"dir_581f3915f9e1f7f984af5af41f44c9ce.html",
"ext__ops_8h.html#a27e33365fb3ff4af45a3f9d1ffd9d77c",
"forward__relay__dispatch_8c_source.html",
"functions_j.html",
"groups_8c.html#a4a8791bca260059feaafdfa2d93a4470",
"guard__classify_8c.html#a24713c70cb2f2ecd8a3573f67d7c472b",
"http__conditionals_8h_source.html",
"idmap_8c.html#a421ef67eff0da20c3ba528b9df5f509c",
"jwks_8c.html#a658a9814ab21d182590e127d71d328b2",
"macaroon_8h.html#a9b3e4c75c453249702c7325d9a27c5fb",
"md_src_2fs_2cache_2README.html#autotoc_md150",
"md_src_2protocols_2root_2stream_2README.html#autotoc_md405",
"metrics__cvmfs_8h.html#a7e0c0e4ea1afb7c6f0912e3500c0b8e0",
"module__directives_8c.html#a01dac593cf0ebac0cb229829265a3c99",
"net_2proxy_2proxy__internal_8h.html#a77348ffa9f8114c57369fb7a649f6358ae86d2b13e432650635cee82817245c1a",
"ns__status_8h.html#a3c7cec413616425d6bc17c99cf2c81bdaa9b36159e35f7c68dbc52c31635a6fd9",
"observability_2metrics_2unified_8h.html#ad374041df577f4adf3585b57b6a1b80fad38582c5f0853274b74a6dc20d7dd868",
"ops__file_8c.html#a8ffab9484c4bced3de1c98cda4aa5cf7",
"parse__x509_8c.html#a69aa056e0f08d92442699c8dfd699ac3",
"pmark_8h.html#ab87de76dc4571c43c70f1ac022f3ea3b",
"proto__exclusive_8c.html#aef7150a622d4cf42f191f693883442ce",
"protocols_2webdav_2config_8c.html#a93e05bd7d04062c63c9e25322c26f399",
"query__internal_8h.html#a49a9849556a40b4c718fbb55270d10d9",
"relay__guard_8c.html",
"router_8h.html#a83c8261c048ded1346d98f2dee2e81de",
"s3__put__internal_8h.html#abb299719e401967d71e1efa8e045c444",
"sd_8h.html#a9700d1570379236b0d95e96b3fee6a42",
"sd__http_8h.html#af0c735bf0c9527c116f6f09f950f190b",
"sd__stage_8c.html#a2dd9733df627881a53951f72b891b57c",
"server__recv_8c.html#a64e7f93749641a6a24636c21fc1d515e",
"src_2fs_2vfs_2vfs_8h.html#a04492b2ab0ffccf14640c88bd9fbd1f0",
"ssi__reply__unittest_8c.html#aba1590ff86288c886c47dc8a27b30467",
"stage__request__registry_8h.html#a109b496acb2a1ef71a1c71f9a6316e55",
"stream__mirror_8c.html#a9e17eac83c89909e43b35ade4fe6b689af8611448aa7de67aca7e23974cedfdae",
"structClientRequestHdr.html#ae5cc6dc9adf5ce2e60f33f42cfc2564c",
"structbrix__acc__named__t.html#a170604999987bc884eb4222bd3e6ef90",
"structbrix__cache__policy__t.html#a9ccbde18641b2b2ee9625072394cd21f",
"structbrix__cred__store.html#a3776b200d78e112aaa1926eca7d6af31",
"structbrix__cvmfs__conf__t.html#aff041135eff72a80f1602e92ea14bfae",
"structbrix__fuse__ctx__trunc.html",
"structbrix__mfile.html#a854c5f298326ab36d1f5cb6cc17563f8",
"structbrix__pmark__exp__def__t.html",
"structbrix__relay__guard__t.html",
"structbrix__sd__stat__t.html#ae053ca0e118a84bcc37a737e42ebfd04",
"structbrix__stream__mirror__t.html#a3fbace996312ad038c228b09ed324509",
"structbrix__transfer__slot__t.html#a2f20d25b56f0ef3b9ac8d84c6aaa3f87",
"structbrix__vfs__walk__opts__t.html#a4be960cf3af65f1b9b8d2397a97a05cc",
"structbrix__zip__member__t.html#a1f51561916d6bca3dfdbc98406e00424",
"structcurl__sink__t.html#aebf812d118c38cca322e8c3ae33b11d9",
"structmetabench__plan.html#a0c08528b8d8c3ba5f22935935c1be0de",
"structngx__brix__srv__metrics__t.html#a9926ea6949272dabd1897c8fae2d427e",
"structngx__http__brix__webdav__loc__conf__t.html#ac21786e1e5fcc899d354ff77ac5cf158",
"structngx__stream__brix__srv__conf__t.html#adb1baef0c209f7a55a849ad31d1047b9",
"structs3__put__aio__t.html#abe3cb274d07b2edaa3552a810129bbc6",
"structssi__resp__state__t.html#ab544bd3eaa45ef7e67188220d3d1ca1b",
"structwebdav__search__query__t.html#ad6cd1b301fd47690a1b82ff14173eb51",
"subject__map_8c_source.html",
"token_8h_source.html",
"trace_8c.html#ac28bfe5b82e579aa6b06e7efa857a4d8",
"verify_8c.html#a6b647a94a12673dc0170c8dad4efb275",
"vfs__open_8c.html#a6408ce9c1f39f6d8cdd249050c161ec0",
"webdav_8h.html#ad8c47b75c65fdfce2395b0209046685f",
"wire__codec_8h_source.html",
"xfer__ledger_8c.html#aba83e7c55b70035ebaf53c004d7b7e03",
"xrd__mount_8c.html#a3df62836c526e4fa9b8d582f10621a97",
"xrdfs__internal_8h.html#a5c85d92eb8c04cacf91e758384fb43a8",
"xrootdfs_8c.html#a4f3393f0a09a41782347d21226124053",
"zip_8h.html#ab5686804f8bf258fc6ed3078a2a38ccb"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';