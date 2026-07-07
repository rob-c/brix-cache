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
    [ "Session Lifecycle Logging", "md_src_2observability_2sesslog_2README.html", null ],
    [ "cvmfs — the cvmfs:// site cache (+ experimental scvmfs:// TLS variant)", "md_src_2protocols_2cvmfs_2README.html", [
      [ "Overview", "md_src_2protocols_2cvmfs_2README.html#autotoc_md301", null ],
      [ "Files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md302", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2cvmfs_2README.html#autotoc_md303", null ],
      [ "See also", "md_src_2protocols_2cvmfs_2README.html#autotoc_md304", null ]
    ] ],
    [ "<tt>src/protocols/dig/</tt> — XrdDig-style remote diagnostics", "md_src_2protocols_2dig_2README.html", [
      [ "Overview", "md_src_2protocols_2dig_2README.html#autotoc_md306", null ],
      [ "Files", "md_src_2protocols_2dig_2README.html#autotoc_md307", null ],
      [ "See also", "md_src_2protocols_2dig_2README.html#autotoc_md308", null ]
    ] ],
    [ "protocols — one subdirectory per wire protocol", "md_src_2protocols_2README.html", null ],
    [ "connection — TCP connection lifecycle, framing, and the async I/O state machine for <tt>root://</tt>", "md_src_2protocols_2root_2connection_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2connection_2README.html#autotoc_md311", null ],
      [ "Files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md312", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2connection_2README.html#autotoc_md313", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2connection_2README.html#autotoc_md314", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2connection_2README.html#autotoc_md315", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2connection_2README.html#autotoc_md316", null ],
      [ "See also", "md_src_2protocols_2root_2connection_2README.html#autotoc_md317", null ]
    ] ],
    [ "dirlist — XRootD <tt>kXR_dirlist</tt> directory enumeration (stream protocol)", "md_src_2protocols_2root_2dirlist_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md319", null ],
      [ "Files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md320", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md321", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md322", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md323", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md324", null ],
      [ "See also", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md325", null ]
    ] ],
    [ "fattr — XRootD <tt>kXR_fattr</tt> extended-attribute operations", "md_src_2protocols_2root_2fattr_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md327", null ],
      [ "Files", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md328", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md329", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md330", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md331", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md332", null ],
      [ "See also", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md333", null ]
    ] ],
    [ "handoff — single-port protocol handoff for the stream xrootd listener", "md_src_2protocols_2root_2handoff_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md335", null ],
      [ "Files", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md336", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md337", null ],
      [ "See also", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md338", null ]
    ] ],
    [ "handshake — XRootD stream request entry point and opcode dispatcher", "md_src_2protocols_2root_2handshake_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md340", null ],
      [ "Files", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md341", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md342", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md343", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md344", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md345", null ],
      [ "See also", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md346", null ]
    ] ],
    [ "path — wire-path extraction, sanitization, and stat formatting", "md_src_2protocols_2root_2path_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2path_2README.html#autotoc_md348", null ],
      [ "Files", "md_src_2protocols_2root_2path_2README.html#autotoc_md349", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2path_2README.html#autotoc_md350", null ],
      [ "See also", "md_src_2protocols_2root_2path_2README.html#autotoc_md351", null ]
    ] ],
    [ "protocol — XRootD <tt>root://</tt> wire-format constants & packed structs", "md_src_2protocols_2root_2protocol_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md353", [
        [ "Provenance & licensing", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md354", null ]
      ] ],
      [ "Files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md355", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md356", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md357", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md358", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md359", null ],
      [ "See also", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md360", null ]
    ] ],
    [ "query — XRootD <tt>kXR_query</tt> sub-protocol, <tt>kXR_prepare</tt> staging, and <tt>kXR_set</tt> hints", "md_src_2protocols_2root_2query_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2query_2README.html#autotoc_md362", null ],
      [ "Files", "md_src_2protocols_2root_2query_2README.html#autotoc_md363", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2query_2README.html#autotoc_md364", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2query_2README.html#autotoc_md365", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2query_2README.html#autotoc_md366", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2query_2README.html#autotoc_md367", null ],
      [ "See also", "md_src_2protocols_2root_2query_2README.html#autotoc_md368", null ]
    ] ],
    [ "read — XRootD read-side opcodes and the file-handle lifecycle", "md_src_2protocols_2root_2read_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2read_2README.html#autotoc_md370", null ],
      [ "Files", "md_src_2protocols_2root_2read_2README.html#autotoc_md371", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2read_2README.html#autotoc_md372", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2read_2README.html#autotoc_md373", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2read_2README.html#autotoc_md374", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2read_2README.html#autotoc_md375", null ],
      [ "See also", "md_src_2protocols_2root_2read_2README.html#autotoc_md376", null ]
    ] ],
    [ "root — the XRootD (<tt>root://</tt> / <tt>roots://</tt>) protocol plane", "md_src_2protocols_2root_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2README.html#autotoc_md378", null ],
      [ "Subdirectories", "md_src_2protocols_2root_2README.html#autotoc_md379", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2README.html#autotoc_md380", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2README.html#autotoc_md381", null ],
      [ "See also", "md_src_2protocols_2root_2README.html#autotoc_md382", null ]
    ] ],
    [ "relay — transparent pass-through relay with a passive observation tap", "md_src_2protocols_2root_2relay_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2relay_2README.html#autotoc_md384", null ],
      [ "Files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md385", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2relay_2README.html#autotoc_md386", null ],
      [ "See also", "md_src_2protocols_2root_2relay_2README.html#autotoc_md387", null ]
    ] ],
    [ "response — XRootD wire-response framing helpers", "md_src_2protocols_2root_2response_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2response_2README.html#autotoc_md389", null ],
      [ "Files", "md_src_2protocols_2root_2response_2README.html#autotoc_md390", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2response_2README.html#autotoc_md391", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2response_2README.html#autotoc_md392", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2response_2README.html#autotoc_md393", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2response_2README.html#autotoc_md394", null ],
      [ "See also", "md_src_2protocols_2root_2response_2README.html#autotoc_md395", null ]
    ] ],
    [ "session — XRootD session lifecycle, identity binding & cross-worker registry", "md_src_2protocols_2root_2session_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2session_2README.html#autotoc_md397", null ],
      [ "Files", "md_src_2protocols_2root_2session_2README.html#autotoc_md398", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2session_2README.html#autotoc_md399", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2session_2README.html#autotoc_md400", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2session_2README.html#autotoc_md401", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2session_2README.html#autotoc_md402", null ],
      [ "See also", "md_src_2protocols_2root_2session_2README.html#autotoc_md403", null ]
    ] ],
    [ "stream — <tt>ngx_stream_brix_module</tt> descriptor & directive table", "md_src_2protocols_2root_2stream_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2stream_2README.html#autotoc_md405", null ],
      [ "Files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md406", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2stream_2README.html#autotoc_md407", [
        [ "Directive groups (authoritative <tt>module.c</tt> set)", "md_src_2protocols_2root_2stream_2README.html#autotoc_md408", null ]
      ] ],
      [ "Control & data flow", "md_src_2protocols_2root_2stream_2README.html#autotoc_md409", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2stream_2README.html#autotoc_md410", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2stream_2README.html#autotoc_md411", null ],
      [ "See also", "md_src_2protocols_2root_2stream_2README.html#autotoc_md412", null ]
    ] ],
    [ "write — XRootD mutating-opcode handlers (the stream write path)", "md_src_2protocols_2root_2write_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2write_2README.html#autotoc_md414", null ],
      [ "Files", "md_src_2protocols_2root_2write_2README.html#autotoc_md415", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2write_2README.html#autotoc_md416", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2write_2README.html#autotoc_md417", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2write_2README.html#autotoc_md418", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2write_2README.html#autotoc_md419", null ],
      [ "See also", "md_src_2protocols_2root_2write_2README.html#autotoc_md420", null ]
    ] ],
    [ "src/protocols/root/zip — ZIP member access (phase-57 W2)", "md_src_2protocols_2root_2zip_2README.html", [
      [ "Status", "md_src_2protocols_2root_2zip_2README.html#autotoc_md422", null ],
      [ "zip_dir.c — the parser", "md_src_2protocols_2root_2zip_2README.html#autotoc_md423", null ],
      [ "Running the unit test (standalone, no nginx build)", "md_src_2protocols_2root_2zip_2README.html#autotoc_md424", null ]
    ] ],
    [ "s3 — S3-compatible REST endpoint over the local export root", "md_src_2protocols_2s3_2README.html", [
      [ "Overview", "md_src_2protocols_2s3_2README.html#autotoc_md426", null ],
      [ "Files", "md_src_2protocols_2s3_2README.html#autotoc_md427", null ],
      [ "Key types & data structures", "md_src_2protocols_2s3_2README.html#autotoc_md428", null ],
      [ "Control & data flow", "md_src_2protocols_2s3_2README.html#autotoc_md429", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2s3_2README.html#autotoc_md430", null ],
      [ "Entry points / extending", "md_src_2protocols_2s3_2README.html#autotoc_md431", null ],
      [ "See also", "md_src_2protocols_2s3_2README.html#autotoc_md432", null ]
    ] ],
    [ "shared — cross-protocol helper library (HTTP file serving + overflow-safe size math)", "md_src_2protocols_2shared_2README.html", [
      [ "Overview", "md_src_2protocols_2shared_2README.html#autotoc_md434", null ],
      [ "Files", "md_src_2protocols_2shared_2README.html#autotoc_md435", null ],
      [ "Key types & data structures", "md_src_2protocols_2shared_2README.html#autotoc_md436", null ],
      [ "Control & data flow", "md_src_2protocols_2shared_2README.html#autotoc_md437", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2shared_2README.html#autotoc_md438", null ],
      [ "Entry points / extending", "md_src_2protocols_2shared_2README.html#autotoc_md439", null ],
      [ "See also", "md_src_2protocols_2shared_2README.html#autotoc_md440", null ]
    ] ],
    [ "<tt>src/protocols/srr/</tt> — WLCG Storage Resource Reporting (SRR) endpoint", "md_src_2protocols_2srr_2README.html", [
      [ "Why this instead of the XRootD UDP monitoring stack", "md_src_2protocols_2srr_2README.html#autotoc_md442", null ],
      [ "Files", "md_src_2protocols_2srr_2README.html#autotoc_md443", null ],
      [ "Configuration", "md_src_2protocols_2srr_2README.html#autotoc_md444", null ],
      [ "Semantics & caveats", "md_src_2protocols_2srr_2README.html#autotoc_md445", null ],
      [ "Schema conformance", "md_src_2protocols_2srr_2README.html#autotoc_md446", null ]
    ] ],
    [ "<tt>src/protocols/ssi/</tt> — XrdSsi request/response service over <tt>root://</tt>", "md_src_2protocols_2ssi_2README.html", [
      [ "Overview", "md_src_2protocols_2ssi_2README.html#autotoc_md448", null ],
      [ "Phase 1: session multiplexing (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md449", null ],
      [ "Phase 2: async server-push via <tt>kXR_attn</tt> (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md450", null ],
      [ "Phase 3: streamed responses + delivered alerts (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md451", null ],
      [ "Phases 4–5: CTA flagship service (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md452", null ],
      [ "Phase 6: config, metrics, conformance (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md453", [
        [ "Directives (<tt>NGX_STREAM_SRV_CONF</tt>)", "md_src_2protocols_2ssi_2README.html#autotoc_md454", null ],
        [ "Metrics (low-cardinality — <tt>{port,auth}</tt> only)", "md_src_2protocols_2ssi_2README.html#autotoc_md455", null ],
        [ "Conformance", "md_src_2protocols_2ssi_2README.html#autotoc_md456", null ]
      ] ],
      [ "RRInfo wire layout", "md_src_2protocols_2ssi_2README.html#autotoc_md457", null ],
      [ "Files", "md_src_2protocols_2ssi_2README.html#autotoc_md458", null ],
      [ "See also", "md_src_2protocols_2ssi_2README.html#autotoc_md459", null ]
    ] ],
    [ "<tt>src/protocols/ssi/svc_cta/</tt> — flagship CTA tape service", "md_src_2protocols_2ssi_2svc__cta_2README.html", [
      [ "Layers", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md461", null ],
      [ "Request lifecycle", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md462", [
        [ "State machine", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md463", null ],
        [ "Executor", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md464", null ],
        [ "Security", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md465", null ],
        [ "Journal (restart recovery)", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md466", null ]
      ] ],
      [ "External contract — the pinned field table", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md467", null ],
      [ "Golden-vector provenance", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md468", null ],
      [ "Scope notes", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md469", null ]
    ] ],
    [ "webdav/fs — Confined local-filesystem copy engine for WebDAV COPY/MOVE", "md_src_2protocols_2webdav_2fs_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md471", null ],
      [ "Files", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md472", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md473", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md474", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md475", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md476", null ],
      [ "See also", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md477", null ]
    ] ],
    [ "webdav/locks — WebDAV LOCK request-header & body parsers", "md_src_2protocols_2webdav_2locks_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md479", null ],
      [ "Files", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md480", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md481", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md482", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md483", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md484", null ],
      [ "See also", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md485", null ]
    ] ],
    [ "webdav/methods — Per-method WebDAV precondition helpers", "md_src_2protocols_2webdav_2methods_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md487", null ],
      [ "Files", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md488", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md489", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md490", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md491", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md492", null ],
      [ "See also", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md493", null ]
    ] ],
    [ "webdav — HTTP/WebDAV/HTTPS gateway (<tt>davs://</tt>, <tt>http://</tt>) over the export root", "md_src_2protocols_2webdav_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2README.html#autotoc_md495", null ],
      [ "Files", "md_src_2protocols_2webdav_2README.html#autotoc_md496", [
        [ "Module wiring & configuration", "md_src_2protocols_2webdav_2README.html#autotoc_md497", null ],
        [ "Dispatch & generic helpers", "md_src_2protocols_2webdav_2README.html#autotoc_md498", null ],
        [ "HTTP method handlers", "md_src_2protocols_2webdav_2README.html#autotoc_md499", null ],
        [ "Authentication", "md_src_2protocols_2webdav_2README.html#autotoc_md500", null ],
        [ "HTTP-TPC (third-party copy)", "md_src_2protocols_2webdav_2README.html#autotoc_md501", null ],
        [ "Upstream proxy mode", "md_src_2protocols_2webdav_2README.html#autotoc_md502", null ],
        [ "XrdHttp protocol extension", "md_src_2protocols_2webdav_2README.html#autotoc_md503", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2README.html#autotoc_md504", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2README.html#autotoc_md505", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2README.html#autotoc_md506", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2README.html#autotoc_md507", null ],
      [ "See also", "md_src_2protocols_2webdav_2README.html#autotoc_md508", null ]
    ] ],
    [ "webdav/util — WebDAV URI decoding and XML escaping helpers", "md_src_2protocols_2webdav_2util_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md510", null ],
      [ "Files", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md511", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md512", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md513", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md514", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md515", null ],
      [ "See also", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md516", null ]
    ] ],
    [ "src — nginx-xrootd Source Tree", "md_src_2README.html", [
      [ "Source map", "md_src_2README.html#autotoc_md519", [
        [ "Top-level files (now under <tt>core/</tt>)", "md_src_2README.html#autotoc_md520", null ],
        [ "Entry & dispatch", "md_src_2README.html#autotoc_md521", null ],
        [ "Protocol handlers", "md_src_2README.html#autotoc_md522", null ],
        [ "Data plane", "md_src_2README.html#autotoc_md523", null ],
        [ "Path & confinement", "md_src_2README.html#autotoc_md524", null ],
        [ "Authentication", "md_src_2README.html#autotoc_md525", null ],
        [ "Cluster & federation", "md_src_2README.html#autotoc_md526", null ],
        [ "Cross-cutting", "md_src_2README.html#autotoc_md527", null ],
        [ "WebDAV sub-helpers", "md_src_2README.html#autotoc_md528", null ]
      ] ],
      [ "The four request lifecycles", "md_src_2README.html#autotoc_md530", [
        [ "<tt>root://</tt> stream", "md_src_2README.html#autotoc_md531", null ],
        [ "<tt>davs://</tt> WebDAV", "md_src_2README.html#autotoc_md532", null ],
        [ "S3 REST", "md_src_2README.html#autotoc_md533", null ],
        [ "CMS cluster redirect", "md_src_2README.html#autotoc_md534", null ]
      ] ],
      [ "Cross-cutting invariants", "md_src_2README.html#autotoc_md536", null ],
      [ "How to navigate / where to start reading", "md_src_2README.html#autotoc_md538", null ]
    ] ],
    [ "tpc/common — Protocol-neutral third-party-copy (TPC) core", "md_src_2tpc_2common_2README.html", [
      [ "Overview", "md_src_2tpc_2common_2README.html#autotoc_md540", null ],
      [ "Files", "md_src_2tpc_2common_2README.html#autotoc_md541", null ],
      [ "Key types & data structures", "md_src_2tpc_2common_2README.html#autotoc_md542", null ],
      [ "Control & data flow", "md_src_2tpc_2common_2README.html#autotoc_md543", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2common_2README.html#autotoc_md544", null ],
      [ "Entry points / extending", "md_src_2tpc_2common_2README.html#autotoc_md545", null ],
      [ "See also", "md_src_2tpc_2common_2README.html#autotoc_md546", null ]
    ] ],
    [ "engine — native-TPC control plane (destination side)", "md_src_2tpc_2engine_2README.html", [
      [ "Overview", "md_src_2tpc_2engine_2README.html#autotoc_md548", null ],
      [ "Files", "md_src_2tpc_2engine_2README.html#autotoc_md549", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2engine_2README.html#autotoc_md550", null ],
      [ "See also", "md_src_2tpc_2engine_2README.html#autotoc_md551", null ]
    ] ],
    [ "gsi — outbound GSI authentication for the TPC pull socket", "md_src_2tpc_2gsi_2README.html", [
      [ "Overview", "md_src_2tpc_2gsi_2README.html#autotoc_md553", null ],
      [ "Files", "md_src_2tpc_2gsi_2README.html#autotoc_md554", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2gsi_2README.html#autotoc_md555", null ],
      [ "See also", "md_src_2tpc_2gsi_2README.html#autotoc_md556", null ]
    ] ],
    [ "outbound — the blocking source-session client for native TPC pulls", "md_src_2tpc_2outbound_2README.html", [
      [ "Overview", "md_src_2tpc_2outbound_2README.html#autotoc_md558", null ],
      [ "Files", "md_src_2tpc_2outbound_2README.html#autotoc_md559", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2outbound_2README.html#autotoc_md560", null ],
      [ "See also", "md_src_2tpc_2outbound_2README.html#autotoc_md561", null ]
    ] ],
    [ "tpc — Native XRootD third-party-copy (destination-side pull)", "md_src_2tpc_2README.html", [
      [ "Overview", "md_src_2tpc_2README.html#autotoc_md563", null ],
      [ "Files", "md_src_2tpc_2README.html#autotoc_md564", null ],
      [ "Key types & data structures", "md_src_2tpc_2README.html#autotoc_md565", null ],
      [ "Control & data flow", "md_src_2tpc_2README.html#autotoc_md566", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2README.html#autotoc_md567", null ],
      [ "Entry points / extending", "md_src_2tpc_2README.html#autotoc_md568", null ],
      [ "See also", "md_src_2tpc_2README.html#autotoc_md569", null ]
    ] ],
    [ "<tt>client/apps/</tt> — native client CLI tools", "md_client_2apps_2README.html", [
      [ "Data movement", "md_client_2apps_2README.html#autotoc_md571", null ],
      [ "Checksums & verification", "md_client_2apps_2README.html#autotoc_md572", null ],
      [ "Diagnostics & monitoring", "md_client_2apps_2README.html#autotoc_md573", null ],
      [ "Auth & security", "md_client_2apps_2README.html#autotoc_md574", null ],
      [ "Namespace / staging", "md_client_2apps_2README.html#autotoc_md575", null ],
      [ "Optional (built only when <tt>libfuse3</tt> is present — not in <tt>BINS</tt>)", "md_client_2apps_2README.html#autotoc_md576", null ],
      [ "Ceph operator tools (<tt>apps/ceph/</tt> — built only when the Ceph dev headers are present)", "md_client_2apps_2README.html#autotoc_md577", null ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2apps_2README.html#autotoc_md578", null ],
      [ "Man pages & bash completion", "md_client_2apps_2README.html#autotoc_md579", null ],
      [ "CLI compatibility contract (binding for all flag/env/output work)", "md_client_2apps_2README.html#autotoc_md580", null ],
      [ "See also", "md_client_2apps_2README.html#autotoc_md581", null ]
    ] ],
    [ "<tt>client/lib/sec/</tt> — native client authentication modules", "md_client_2lib_2auth_2sec_2README.html", [
      [ "Overview", "md_client_2lib_2auth_2sec_2README.html#autotoc_md583", null ],
      [ "Files", "md_client_2lib_2auth_2sec_2README.html#autotoc_md584", null ],
      [ "Invariants", "md_client_2lib_2auth_2sec_2README.html#autotoc_md585", null ],
      [ "See also", "md_client_2lib_2auth_2sec_2README.html#autotoc_md586", null ]
    ] ],
    [ "<tt>client/lib/</tt> — native XRootD client library (<tt>libbrix</tt>)", "md_client_2lib_2README.html", [
      [ "Concept buckets (phase-69)", "md_client_2lib_2README.html#autotoc_md588", null ],
      [ "File responsibilities (Phase-38 split groups)", "md_client_2lib_2README.html#autotoc_md589", null ]
    ] ],
    [ "<tt>client/preload/</tt> — LD_PRELOAD POSIX → XRootD shim", "md_client_2preload_2README.html", [
      [ "Overview", "md_client_2preload_2README.html#autotoc_md591", null ],
      [ "How it works", "md_client_2preload_2README.html#autotoc_md592", null ],
      [ "Scope", "md_client_2preload_2README.html#autotoc_md593", null ],
      [ "Files", "md_client_2preload_2README.html#autotoc_md594", null ],
      [ "See also", "md_client_2preload_2README.html#autotoc_md595", null ]
    ] ],
    [ "<tt>client/</tt> — native BriX client tools", "md_client_2README.html", [
      [ "Directory layout", "md_client_2README.html#autotoc_md597", null ],
      [ "Build", "md_client_2README.html#autotoc_md598", null ],
      [ "Feature summary (2026-07-05)", "md_client_2README.html#autotoc_md599", [
        [ "xrdcp", "md_client_2README.html#autotoc_md600", null ],
        [ "xrdfs", "md_client_2README.html#autotoc_md601", null ],
        [ "xrdcksum", "md_client_2README.html#autotoc_md602", null ],
        [ "xrddiag", "md_client_2README.html#autotoc_md603", null ],
        [ "Ceph operator tools", "md_client_2README.html#autotoc_md604", null ]
      ] ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2README.html#autotoc_md605", null ],
      [ "Man pages & bash completion", "md_client_2README.html#autotoc_md606", null ],
      [ "See also", "md_client_2README.html#autotoc_md607", null ]
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
"api__admin_8h.html#ae59fc3f158e5c3703c77ab9e21a1500e",
"auth__crypto__helpers_8c.html#a6556b1b0d5f99f98b563aa4f5ea72ff1",
"brix__auth_8h.html#a11e482f72cda66e2cdf23509b8062e82",
"brixcvmfs_8c.html#a3c04138a5bfe5d72780bb7e82a18e627",
"buffers_8c.html",
"chain__helpers_8h_source.html",
"cli__hint_8h.html#ab229d8583af77de87a43b94d804d6d05",
"cms__internal_8h.html#a434efb4c03b93d6d3adbeaa653e22765",
"config__download_8c.html#a986c8e5b914bfc615b655fd3a7126f5e",
"core_2compat_2xml_8c.html#a2d0c0bc5b13e421ca9329cd196f0a114",
"csi__tagstore_8h.html#a5b418098a3c5678c5ed6d4698522fa25",
"cvmfs_8h.html#a0dc058ee430b1e805daaec390a3746c7aea678cd3bccaecb23a66afbba11a8852",
"del_8c_source.html",
"dir_467860735a4a74398db4a8c79362a6a2.html",
"evict__policy_8c.html#a05ffba65b38843a84500ce9268ac2658",
"flowlabel_8c_source.html",
"fs__walk_8h.html#a84e68c23a5a599986a31f399b3a72c7f",
"group__policy_8c.html#a27821a7b9be1499ebb0d9698b88ee735",
"guard_8h.html#a984af347685fbe23d386014847eaea69aa77295b99daa58458f99a4f00f63184d",
"http__conditionals_8c.html#a2efc36359eb0a613207724f97c63108f",
"identity_8h.html#ac0abf7cb8084f3d2c5265933f6f2e5a8",
"jsonout_8c.html#a113311d523971fd7331dc2e4b3022944",
"macaroon_8c.html#a33cea43ff70d578bce7d182f2dca1f3f",
"md_src_2core_2types_2README.html#autotoc_md133",
"md_src_2protocols_2root_2relay_2README.html",
"metadata_8c.html#a9507f4ab92a1b8e5c17d0ab3cc66a8c9",
"module__acc__directives_8c.html#ad2a0bdfbf81cdaa50fb9aa156c05790c",
"net_2manager_2registry_8h.html#af8ba6c820f5011754b69aafc262fc7c5",
"node__ops_8h.html#aac5b828a1171150b2c14ac459c58b9dfa0bea32b1d8e4cad122c3f9b303928dbc",
"observability_2metrics_2unified_8h.html#a3a3309c28f2a7f9b32e5716348af9831",
"open__request_8c.html#abb229f5468890a3e3bad16b19479c289",
"overlay__unittest_8c.html#a018b6a74538785ad73db6990b66e4518",
"pki__load_8c.html",
"propfind__internal_8h.html#a69c91040992f1debc50d89ab4aa7eb8a",
"protocols_2s3_2module_8c.html#aa3ebe1b6782bf4652135fb0c0bcd9489",
"proxy__response_8c_source.html",
"redir__cache_8h.html#ada26833c1852a70e5a9c7d435b47bd80",
"root_2query_2util_8c.html",
"s3__auth__internal_8h.html#aa61b59cafce62b3fe43cdde6d0ada37c",
"scitag_8c.html",
"sd__frm__mss_8h.html#a816dce89b1956197fa1fe7ba276d1b5f",
"sd__s3_8c.html#a45e610f048eaa8deef486fb2203e2b71",
"server_8h.html#a4a878fa6f354154a93256a4774c0cf58",
"sesslog__ngx_8h.html#a21cc973d9beffc9dd7241828b404c870",
"src_2fs_2vfs_2vfs_8h.html#a3f50a1f2cddbeae1c90811800cb6b8ca",
"ssi__rrinfo_8h.html#abe6899a4de6e6d58c8a0a5ec73ac4dc8",
"stage__request__registry_8h.html#a7e5a649e9e9226a5beb0525d7fe1d455af73fcfc58dde1f6464646c7aa9759920",
"stream__mirror_8h.html#ae3cf1ce4addb5f355bfa4c154d2ae5c9",
"structClientSetattrRequest.html#a0d4ea212dfdb0bd69c6a9a99c06d810a",
"structbrix__acc__tables__t.html#aa2003d115a3de0bd7bdf421a683d054e",
"structbrix__cache__sink__t.html#aac3f788d0456a1df0b368ea54325ccfc",
"structbrix__credential__t.html",
"structbrix__dashboard__event__t.html#a767c70f2ca63ab7b1b1198f2e62e8ea9",
"structbrix__group__rule__t.html#acda5598d13467c884d4a0b1c2071bf23",
"structbrix__mfile.html#ac835958e03872576a9f888f6b4c5296c",
"structbrix__pmark__exp__def__t.html#a4c28a89158f61000294989afaaaa14cb",
"structbrix__relay__guard__t.html#a81f55d66c65bb40d8990abfe5dacc4b8",
"structbrix__sec__module.html",
"structbrix__statinfo.html",
"structbrix__tpc__registry__entry__t.html#acf65abd7606c8c65f4766cd63985cfbf",
"structbrix__vfs__readv__seg__t.html#a35becf5db9375de251ea1dd832b0e00e",
"structbrix__xmeta__t.html#a729f0f5d18b47b11f4b2a416f7c1c49a",
"structcta__request__t.html#a69df9fb5814df60ae5171607c6902b58",
"structimp__req__t.html#ad940c24ae4885d0c32466922065182eb",
"structngx__brix__s3__metrics__t.html#a5fcbcb8849b807194e21ac5cef02bead",
"structngx__http__brix__webdav__loc__conf__t.html#a3dfca5c6b6c3c801659d3489ecd3793f",
"structngx__stream__brix__srv__conf__t.html#a93ce0e91374ce2dbe48db0933729f2d3",
"structs3__lc__entry__t.html#a7c1456b5d118708da9cbc2f79c2be836",
"structsigv4__components__t.html#ab80f08955cc0407be63207cc3ac3a31d",
"structwebdav__copy__collection__task__t.html#a2d794ac5e3ec76ce91d43c194ea80b2f",
"structxrdw__read__req__t.html#a34ada07f17ca50ce938de29cf05a8a0c",
"tier__directives_8h_source.html",
"tpc__internal_8h.html#a5162c7139e6ef3519c36265127e64a44",
"uring__submit_8c.html",
"vfs__io__core_8c.html#a2a0447c0dfa19caa790d0107c7158c39",
"webdav_2put_8c.html",
"wire__codec_8h.html#a1b8eb0020867f47295f1bd0b1889395d",
"writev_8c.html",
"xrd__clockskew_8c.html#a630198bec8ee604e25cee722f0ab0179",
"xrdfs_8c.html#a61d2a3c205164e3f4e78bc921152bdb9",
"xrdmapc_8c.html#a28999b7bf77e817ab21c70002c3ad233",
"xrootdfs__legacy_8c.html#aad6be08d5db34de7343fec21e2bf67fd"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';