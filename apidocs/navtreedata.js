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
    [ "fs/vfs — the VFS facade (public API + per-op implementations)", "md_src_2fs_2vfs_2README.html", [
      [ "Additional file", "md_src_2fs_2vfs_2README.html#autotoc_md200", null ]
    ] ],
    [ "<tt>src/fs/xfer/</tt> — unified durable-transfer engine", "md_src_2fs_2xfer_2README.html", [
      [ "Where it sits", "md_src_2fs_2xfer_2README.html#autotoc_md202", null ],
      [ "Files", "md_src_2fs_2xfer_2README.html#autotoc_md203", null ],
      [ "STAGE audit coverage — every upload mode", "md_src_2fs_2xfer_2README.html#autotoc_md204", null ],
      [ "Reload contract (§8b)", "md_src_2fs_2xfer_2README.html#autotoc_md205", [
        [ "The audit line (Phase 2)", "md_src_2fs_2xfer_2README.html#autotoc_md206", null ]
      ] ],
      [ "Durability (spec §7–§8)", "md_src_2fs_2xfer_2README.html#autotoc_md207", null ]
    ] ],
    [ "cms — XRootD CMS cluster membership (heartbeat client + manager-side server)", "md_src_2net_2cms_2README.html", [
      [ "Overview", "md_src_2net_2cms_2README.html#autotoc_md209", null ],
      [ "Files", "md_src_2net_2cms_2README.html#autotoc_md210", [
        [ "Heartbeat client (main module)", "md_src_2net_2cms_2README.html#autotoc_md211", null ],
        [ "Shared frame I/O", "md_src_2net_2cms_2README.html#autotoc_md212", null ],
        [ "Manager-side server (<tt>ngx_stream_brix_cms_srv_module</tt>)", "md_src_2net_2cms_2README.html#autotoc_md213", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2cms_2README.html#autotoc_md214", null ],
      [ "Control & data flow", "md_src_2net_2cms_2README.html#autotoc_md215", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2cms_2README.html#autotoc_md216", null ],
      [ "Entry points / extending", "md_src_2net_2cms_2README.html#autotoc_md217", null ],
      [ "See also", "md_src_2net_2cms_2README.html#autotoc_md218", null ]
    ] ],
    [ "net/guard — protocol-agnostic bad-actor classifier", "md_src_2net_2guard_2README.html", [
      [ "The <tt>guard_request_t</tt> contract", "md_src_2net_2guard_2README.html#autotoc_md220", null ],
      [ "Audit line (the fail2ban contract)", "md_src_2net_2guard_2README.html#autotoc_md221", null ],
      [ "Wire-level \"not speaking root\" check (<tt>guard_classify_handshake</tt>)", "md_src_2net_2guard_2README.html#autotoc_md222", null ],
      [ "CVMFS forward-proxy abuse check (<tt>signal=proxyabuse</tt>)", "md_src_2net_2guard_2README.html#autotoc_md223", null ],
      [ "CVMFS content-tamper check (<tt>signal=cvmfs_tamper</tt>)", "md_src_2net_2guard_2README.html#autotoc_md224", null ],
      [ "CVMFS token-gate check (<tt>signal=authfail</tt>)", "md_src_2net_2guard_2README.html#autotoc_md225", null ],
      [ "Testing", "md_src_2net_2guard_2README.html#autotoc_md226", null ]
    ] ],
    [ "net/httpguard — HTTP adapter for the bad-actor guard", "md_src_2net_2httpguard_2README.html", [
      [ "Directives", "md_src_2net_2httpguard_2README.html#autotoc_md228", null ],
      [ "ARC deployment recipe", "md_src_2net_2httpguard_2README.html#autotoc_md229", null ],
      [ "fail2ban wiring", "md_src_2net_2httpguard_2README.html#autotoc_md230", null ],
      [ "Tests", "md_src_2net_2httpguard_2README.html#autotoc_md231", null ]
    ] ],
    [ "manager — Cluster / redirector control plane (server registry, redirect cache, active health checks)", "md_src_2net_2manager_2README.html", [
      [ "Overview", "md_src_2net_2manager_2README.html#autotoc_md233", null ],
      [ "Files", "md_src_2net_2manager_2README.html#autotoc_md234", null ],
      [ "Key types & data structures", "md_src_2net_2manager_2README.html#autotoc_md235", null ],
      [ "Control & data flow", "md_src_2net_2manager_2README.html#autotoc_md236", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2manager_2README.html#autotoc_md237", null ],
      [ "Entry points / extending", "md_src_2net_2manager_2README.html#autotoc_md238", null ],
      [ "See also", "md_src_2net_2manager_2README.html#autotoc_md239", null ]
    ] ],
    [ "mirror — fire-and-forget traffic mirroring (shadow replay) for XRootD and WebDAV", "md_src_2net_2mirror_2README.html", [
      [ "Overview", "md_src_2net_2mirror_2README.html#autotoc_md241", null ],
      [ "Files", "md_src_2net_2mirror_2README.html#autotoc_md242", null ],
      [ "Key types & data structures", "md_src_2net_2mirror_2README.html#autotoc_md243", null ],
      [ "Control & data flow", "md_src_2net_2mirror_2README.html#autotoc_md244", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2mirror_2README.html#autotoc_md245", null ],
      [ "Entry points / extending", "md_src_2net_2mirror_2README.html#autotoc_md246", null ],
      [ "See also", "md_src_2net_2mirror_2README.html#autotoc_md247", null ]
    ] ],
    [ "proxy — Transparent XRootD reverse proxy (<tt>brix_proxy</tt>)", "md_src_2net_2proxy_2README.html", [
      [ "Overview", "md_src_2net_2proxy_2README.html#autotoc_md249", null ],
      [ "Files", "md_src_2net_2proxy_2README.html#autotoc_md250", null ],
      [ "Key types & data structures", "md_src_2net_2proxy_2README.html#autotoc_md251", null ],
      [ "Control & data flow", "md_src_2net_2proxy_2README.html#autotoc_md252", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2proxy_2README.html#autotoc_md253", null ],
      [ "Entry points / extending", "md_src_2net_2proxy_2README.html#autotoc_md254", null ],
      [ "See also", "md_src_2net_2proxy_2README.html#autotoc_md255", null ]
    ] ],
    [ "ratelimit — identity-aware leaky-bucket rate, bandwidth & concurrency limiting (Phase 25)", "md_src_2net_2ratelimit_2README.html", [
      [ "Overview", "md_src_2net_2ratelimit_2README.html#autotoc_md257", null ],
      [ "Files", "md_src_2net_2ratelimit_2README.html#autotoc_md258", null ],
      [ "Key types & data structures", "md_src_2net_2ratelimit_2README.html#autotoc_md259", null ],
      [ "Directive reference (configuration surface)", "md_src_2net_2ratelimit_2README.html#autotoc_md260", null ],
      [ "Control & data flow", "md_src_2net_2ratelimit_2README.html#autotoc_md261", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2ratelimit_2README.html#autotoc_md262", null ],
      [ "Entry points / extending", "md_src_2net_2ratelimit_2README.html#autotoc_md263", null ],
      [ "See also", "md_src_2net_2ratelimit_2README.html#autotoc_md264", null ]
    ] ],
    [ "net — clustering, proxying, shadowing, and connection defense", "md_src_2net_2README.html", null ],
    [ "tap — ngx-free protocol observation tap (decode + sink fan-out)", "md_src_2net_2tap_2README.html", [
      [ "Overview", "md_src_2net_2tap_2README.html#autotoc_md267", null ],
      [ "Files", "md_src_2net_2tap_2README.html#autotoc_md268", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2tap_2README.html#autotoc_md269", null ],
      [ "See also", "md_src_2net_2tap_2README.html#autotoc_md270", null ]
    ] ],
    [ "upstream — outbound XRootD redirector/proxy client (manager-side server-to-server query)", "md_src_2net_2upstream_2README.html", [
      [ "Overview", "md_src_2net_2upstream_2README.html#autotoc_md272", null ],
      [ "Files", "md_src_2net_2upstream_2README.html#autotoc_md273", null ],
      [ "Key types & data structures", "md_src_2net_2upstream_2README.html#autotoc_md274", null ],
      [ "Control & data flow", "md_src_2net_2upstream_2README.html#autotoc_md275", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2upstream_2README.html#autotoc_md276", null ],
      [ "Entry points / extending", "md_src_2net_2upstream_2README.html#autotoc_md277", null ],
      [ "See also", "md_src_2net_2upstream_2README.html#autotoc_md278", null ]
    ] ],
    [ "dashboard — live HTTPS transfer monitor + REST admin write API", "md_src_2observability_2dashboard_2README.html", [
      [ "Overview", "md_src_2observability_2dashboard_2README.html#autotoc_md280", null ],
      [ "Files", "md_src_2observability_2dashboard_2README.html#autotoc_md281", null ],
      [ "Key types & data structures", "md_src_2observability_2dashboard_2README.html#autotoc_md282", null ],
      [ "Control & data flow", "md_src_2observability_2dashboard_2README.html#autotoc_md283", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2dashboard_2README.html#autotoc_md284", null ],
      [ "Entry points / extending", "md_src_2observability_2dashboard_2README.html#autotoc_md285", null ],
      [ "See also", "md_src_2observability_2dashboard_2README.html#autotoc_md286", null ],
      [ "VFS export browser (<tt>brix_dashboard_vfs_browse on</tt>)", "md_src_2observability_2dashboard_2README.html#autotoc_md287", null ]
    ] ],
    [ "metrics — shared-memory counters and the Prometheus <tt>/metrics</tt> exporter", "md_src_2observability_2metrics_2README.html", [
      [ "Overview", "md_src_2observability_2metrics_2README.html#autotoc_md289", null ],
      [ "Files", "md_src_2observability_2metrics_2README.html#autotoc_md290", null ],
      [ "Key types & data structures", "md_src_2observability_2metrics_2README.html#autotoc_md291", null ],
      [ "Control & data flow", "md_src_2observability_2metrics_2README.html#autotoc_md292", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2metrics_2README.html#autotoc_md293", null ],
      [ "Entry points / extending", "md_src_2observability_2metrics_2README.html#autotoc_md294", null ],
      [ "See also", "md_src_2observability_2metrics_2README.html#autotoc_md295", null ]
    ] ],
    [ "pmark — SciTags packet marking", "md_src_2observability_2pmark_2README.html", [
      [ "Overview", "md_src_2observability_2pmark_2README.html#autotoc_md297", null ],
      [ "Files", "md_src_2observability_2pmark_2README.html#autotoc_md298", null ],
      [ "Configuration", "md_src_2observability_2pmark_2README.html#autotoc_md299", null ],
      [ "Control & data flow", "md_src_2observability_2pmark_2README.html#autotoc_md300", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2pmark_2README.html#autotoc_md301", null ],
      [ "See also", "md_src_2observability_2pmark_2README.html#autotoc_md302", null ]
    ] ],
    [ "observability — metrics, packet marking, dashboard, and access logs", "md_src_2observability_2README.html", null ],
    [ "Session Lifecycle Logging", "md_src_2observability_2sesslog_2README.html", null ],
    [ "cvmfs — the cvmfs:// site cache (+ experimental scvmfs:// TLS variant)", "md_src_2protocols_2cvmfs_2README.html", [
      [ "Overview", "md_src_2protocols_2cvmfs_2README.html#autotoc_md306", null ],
      [ "Files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md307", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2cvmfs_2README.html#autotoc_md308", null ],
      [ "See also", "md_src_2protocols_2cvmfs_2README.html#autotoc_md309", null ]
    ] ],
    [ "<tt>src/protocols/dig/</tt> — XrdDig-style remote diagnostics", "md_src_2protocols_2dig_2README.html", [
      [ "Overview", "md_src_2protocols_2dig_2README.html#autotoc_md311", null ],
      [ "Files", "md_src_2protocols_2dig_2README.html#autotoc_md312", null ],
      [ "See also", "md_src_2protocols_2dig_2README.html#autotoc_md313", null ]
    ] ],
    [ "protocols — one subdirectory per wire protocol", "md_src_2protocols_2README.html", null ],
    [ "connection — TCP connection lifecycle, framing, and the async I/O state machine for <tt>root://</tt>", "md_src_2protocols_2root_2connection_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2connection_2README.html#autotoc_md316", null ],
      [ "Files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md317", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2connection_2README.html#autotoc_md318", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2connection_2README.html#autotoc_md319", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2connection_2README.html#autotoc_md320", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2connection_2README.html#autotoc_md321", null ],
      [ "See also", "md_src_2protocols_2root_2connection_2README.html#autotoc_md322", null ]
    ] ],
    [ "dirlist — XRootD <tt>kXR_dirlist</tt> directory enumeration (stream protocol)", "md_src_2protocols_2root_2dirlist_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md324", null ],
      [ "Files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md325", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md326", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md327", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md328", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md329", null ],
      [ "See also", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md330", null ]
    ] ],
    [ "fattr — XRootD <tt>kXR_fattr</tt> extended-attribute operations", "md_src_2protocols_2root_2fattr_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md332", null ],
      [ "Files", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md333", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md334", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md335", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md336", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md337", null ],
      [ "See also", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md338", null ]
    ] ],
    [ "handoff — single-port protocol handoff for the stream xrootd listener", "md_src_2protocols_2root_2handoff_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md340", null ],
      [ "Files", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md341", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md342", null ],
      [ "See also", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md343", null ]
    ] ],
    [ "handshake — XRootD stream request entry point and opcode dispatcher", "md_src_2protocols_2root_2handshake_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md345", null ],
      [ "Files", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md346", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md347", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md348", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md349", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md350", null ],
      [ "See also", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md351", null ]
    ] ],
    [ "path — wire-path extraction, sanitization, and stat formatting", "md_src_2protocols_2root_2path_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2path_2README.html#autotoc_md353", null ],
      [ "Files", "md_src_2protocols_2root_2path_2README.html#autotoc_md354", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2path_2README.html#autotoc_md355", null ],
      [ "See also", "md_src_2protocols_2root_2path_2README.html#autotoc_md356", null ]
    ] ],
    [ "protocol — XRootD <tt>root://</tt> wire-format constants & packed structs", "md_src_2protocols_2root_2protocol_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md358", [
        [ "Provenance & licensing", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md359", null ]
      ] ],
      [ "Files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md360", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md361", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md362", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md363", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md364", null ],
      [ "See also", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md365", null ]
    ] ],
    [ "query — XRootD <tt>kXR_query</tt> sub-protocol, <tt>kXR_prepare</tt> staging, and <tt>kXR_set</tt> hints", "md_src_2protocols_2root_2query_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2query_2README.html#autotoc_md367", null ],
      [ "Files", "md_src_2protocols_2root_2query_2README.html#autotoc_md368", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2query_2README.html#autotoc_md369", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2query_2README.html#autotoc_md370", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2query_2README.html#autotoc_md371", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2query_2README.html#autotoc_md372", null ],
      [ "See also", "md_src_2protocols_2root_2query_2README.html#autotoc_md373", null ]
    ] ],
    [ "read — XRootD read-side opcodes and the file-handle lifecycle", "md_src_2protocols_2root_2read_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2read_2README.html#autotoc_md375", null ],
      [ "Files", "md_src_2protocols_2root_2read_2README.html#autotoc_md376", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2read_2README.html#autotoc_md377", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2read_2README.html#autotoc_md378", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2read_2README.html#autotoc_md379", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2read_2README.html#autotoc_md380", null ],
      [ "See also", "md_src_2protocols_2root_2read_2README.html#autotoc_md381", null ]
    ] ],
    [ "root — the XRootD (<tt>root://</tt> / <tt>roots://</tt>) protocol plane", "md_src_2protocols_2root_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2README.html#autotoc_md383", null ],
      [ "Subdirectories", "md_src_2protocols_2root_2README.html#autotoc_md384", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2README.html#autotoc_md385", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2README.html#autotoc_md386", null ],
      [ "See also", "md_src_2protocols_2root_2README.html#autotoc_md387", null ]
    ] ],
    [ "relay — transparent pass-through relay with a passive observation tap", "md_src_2protocols_2root_2relay_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2relay_2README.html#autotoc_md389", null ],
      [ "Files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md390", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2relay_2README.html#autotoc_md391", null ],
      [ "See also", "md_src_2protocols_2root_2relay_2README.html#autotoc_md392", null ]
    ] ],
    [ "response — XRootD wire-response framing helpers", "md_src_2protocols_2root_2response_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2response_2README.html#autotoc_md394", null ],
      [ "Files", "md_src_2protocols_2root_2response_2README.html#autotoc_md395", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2response_2README.html#autotoc_md396", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2response_2README.html#autotoc_md397", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2response_2README.html#autotoc_md398", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2response_2README.html#autotoc_md399", null ],
      [ "See also", "md_src_2protocols_2root_2response_2README.html#autotoc_md400", null ]
    ] ],
    [ "session — XRootD session lifecycle, identity binding & cross-worker registry", "md_src_2protocols_2root_2session_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2session_2README.html#autotoc_md402", null ],
      [ "Files", "md_src_2protocols_2root_2session_2README.html#autotoc_md403", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2session_2README.html#autotoc_md404", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2session_2README.html#autotoc_md405", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2session_2README.html#autotoc_md406", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2session_2README.html#autotoc_md407", null ],
      [ "See also", "md_src_2protocols_2root_2session_2README.html#autotoc_md408", null ]
    ] ],
    [ "stream — <tt>ngx_stream_brix_module</tt> descriptor & directive table", "md_src_2protocols_2root_2stream_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2stream_2README.html#autotoc_md410", null ],
      [ "Files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md411", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2stream_2README.html#autotoc_md412", [
        [ "Directive groups (authoritative <tt>module.c</tt> set)", "md_src_2protocols_2root_2stream_2README.html#autotoc_md413", null ]
      ] ],
      [ "Control & data flow", "md_src_2protocols_2root_2stream_2README.html#autotoc_md414", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2stream_2README.html#autotoc_md415", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2stream_2README.html#autotoc_md416", null ],
      [ "See also", "md_src_2protocols_2root_2stream_2README.html#autotoc_md417", null ]
    ] ],
    [ "write — XRootD mutating-opcode handlers (the stream write path)", "md_src_2protocols_2root_2write_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2write_2README.html#autotoc_md419", null ],
      [ "Files", "md_src_2protocols_2root_2write_2README.html#autotoc_md420", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2write_2README.html#autotoc_md421", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2write_2README.html#autotoc_md422", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2write_2README.html#autotoc_md423", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2write_2README.html#autotoc_md424", null ],
      [ "See also", "md_src_2protocols_2root_2write_2README.html#autotoc_md425", null ]
    ] ],
    [ "src/protocols/root/zip — ZIP member access (phase-57 W2)", "md_src_2protocols_2root_2zip_2README.html", [
      [ "Status", "md_src_2protocols_2root_2zip_2README.html#autotoc_md427", null ],
      [ "zip_dir.c — the parser", "md_src_2protocols_2root_2zip_2README.html#autotoc_md428", null ],
      [ "Running the unit test (standalone, no nginx build)", "md_src_2protocols_2root_2zip_2README.html#autotoc_md429", null ]
    ] ],
    [ "s3 — S3-compatible REST endpoint over the local export root", "md_src_2protocols_2s3_2README.html", [
      [ "Overview", "md_src_2protocols_2s3_2README.html#autotoc_md431", null ],
      [ "Files", "md_src_2protocols_2s3_2README.html#autotoc_md432", null ],
      [ "Key types & data structures", "md_src_2protocols_2s3_2README.html#autotoc_md433", null ],
      [ "Control & data flow", "md_src_2protocols_2s3_2README.html#autotoc_md434", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2s3_2README.html#autotoc_md435", null ],
      [ "Entry points / extending", "md_src_2protocols_2s3_2README.html#autotoc_md436", null ],
      [ "See also", "md_src_2protocols_2s3_2README.html#autotoc_md437", null ]
    ] ],
    [ "shared — cross-protocol helper library (HTTP file serving + overflow-safe size math)", "md_src_2protocols_2shared_2README.html", [
      [ "Overview", "md_src_2protocols_2shared_2README.html#autotoc_md439", null ],
      [ "Files", "md_src_2protocols_2shared_2README.html#autotoc_md440", null ],
      [ "Key types & data structures", "md_src_2protocols_2shared_2README.html#autotoc_md441", null ],
      [ "Control & data flow", "md_src_2protocols_2shared_2README.html#autotoc_md442", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2shared_2README.html#autotoc_md443", null ],
      [ "Entry points / extending", "md_src_2protocols_2shared_2README.html#autotoc_md444", null ],
      [ "See also", "md_src_2protocols_2shared_2README.html#autotoc_md445", null ]
    ] ],
    [ "<tt>src/protocols/srr/</tt> — WLCG Storage Resource Reporting (SRR) endpoint", "md_src_2protocols_2srr_2README.html", [
      [ "Why this instead of the XRootD UDP monitoring stack", "md_src_2protocols_2srr_2README.html#autotoc_md447", null ],
      [ "Files", "md_src_2protocols_2srr_2README.html#autotoc_md448", null ],
      [ "Configuration", "md_src_2protocols_2srr_2README.html#autotoc_md449", null ],
      [ "Semantics & caveats", "md_src_2protocols_2srr_2README.html#autotoc_md450", null ],
      [ "Schema conformance", "md_src_2protocols_2srr_2README.html#autotoc_md451", null ]
    ] ],
    [ "<tt>src/protocols/ssi/</tt> — XrdSsi request/response service over <tt>root://</tt>", "md_src_2protocols_2ssi_2README.html", [
      [ "Overview", "md_src_2protocols_2ssi_2README.html#autotoc_md453", null ],
      [ "Phase 1: session multiplexing (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md454", null ],
      [ "Phase 2: async server-push via <tt>kXR_attn</tt> (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md455", null ],
      [ "Phase 3: streamed responses + delivered alerts (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md456", null ],
      [ "Phases 4–5: CTA flagship service (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md457", null ],
      [ "Phase 6: config, metrics, conformance (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md458", [
        [ "Directives (<tt>NGX_STREAM_SRV_CONF</tt>)", "md_src_2protocols_2ssi_2README.html#autotoc_md459", null ],
        [ "Metrics (low-cardinality — <tt>{port,auth}</tt> only)", "md_src_2protocols_2ssi_2README.html#autotoc_md460", null ],
        [ "Conformance", "md_src_2protocols_2ssi_2README.html#autotoc_md461", null ]
      ] ],
      [ "RRInfo wire layout", "md_src_2protocols_2ssi_2README.html#autotoc_md462", null ],
      [ "Files", "md_src_2protocols_2ssi_2README.html#autotoc_md463", null ],
      [ "See also", "md_src_2protocols_2ssi_2README.html#autotoc_md464", null ]
    ] ],
    [ "<tt>src/protocols/ssi/svc_cta/</tt> — flagship CTA tape service", "md_src_2protocols_2ssi_2svc__cta_2README.html", [
      [ "Layers", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md466", null ],
      [ "Request lifecycle", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md467", [
        [ "State machine", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md468", null ],
        [ "Executor", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md469", null ],
        [ "Security", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md470", null ],
        [ "Journal (restart recovery)", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md471", null ]
      ] ],
      [ "External contract — the pinned field table", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md472", null ],
      [ "Golden-vector provenance", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md473", null ],
      [ "Scope notes", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md474", null ]
    ] ],
    [ "webdav/fs — Confined local-filesystem copy engine for WebDAV COPY/MOVE", "md_src_2protocols_2webdav_2fs_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md476", null ],
      [ "Files", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md477", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md478", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md479", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md480", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md481", null ],
      [ "See also", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md482", null ]
    ] ],
    [ "webdav/locks — WebDAV LOCK request-header & body parsers", "md_src_2protocols_2webdav_2locks_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md484", null ],
      [ "Files", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md485", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md486", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md487", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md488", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md489", null ],
      [ "See also", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md490", null ]
    ] ],
    [ "webdav/methods — Per-method WebDAV precondition helpers", "md_src_2protocols_2webdav_2methods_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md492", null ],
      [ "Files", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md493", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md494", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md495", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md496", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md497", null ],
      [ "See also", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md498", null ]
    ] ],
    [ "webdav — HTTP/WebDAV/HTTPS gateway (<tt>davs://</tt>, <tt>http://</tt>) over the export root", "md_src_2protocols_2webdav_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2README.html#autotoc_md500", null ],
      [ "Files", "md_src_2protocols_2webdav_2README.html#autotoc_md501", [
        [ "Module wiring & configuration", "md_src_2protocols_2webdav_2README.html#autotoc_md502", null ],
        [ "Dispatch & generic helpers", "md_src_2protocols_2webdav_2README.html#autotoc_md503", null ],
        [ "HTTP method handlers", "md_src_2protocols_2webdav_2README.html#autotoc_md504", null ],
        [ "Authentication", "md_src_2protocols_2webdav_2README.html#autotoc_md505", null ],
        [ "HTTP-TPC (third-party copy)", "md_src_2protocols_2webdav_2README.html#autotoc_md506", null ],
        [ "Upstream proxy mode", "md_src_2protocols_2webdav_2README.html#autotoc_md507", null ],
        [ "XrdHttp protocol extension", "md_src_2protocols_2webdav_2README.html#autotoc_md508", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2README.html#autotoc_md509", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2README.html#autotoc_md510", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2README.html#autotoc_md511", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2README.html#autotoc_md512", null ],
      [ "See also", "md_src_2protocols_2webdav_2README.html#autotoc_md513", null ]
    ] ],
    [ "webdav/util — WebDAV URI decoding and XML escaping helpers", "md_src_2protocols_2webdav_2util_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md515", null ],
      [ "Files", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md516", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md517", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md518", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md519", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md520", null ],
      [ "See also", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md521", null ]
    ] ],
    [ "src — nginx-xrootd Source Tree", "md_src_2README.html", [
      [ "Source map", "md_src_2README.html#autotoc_md524", [
        [ "Top-level files (now under <tt>core/</tt>)", "md_src_2README.html#autotoc_md525", null ],
        [ "Entry & dispatch", "md_src_2README.html#autotoc_md526", null ],
        [ "Protocol handlers", "md_src_2README.html#autotoc_md527", null ],
        [ "Data plane", "md_src_2README.html#autotoc_md528", null ],
        [ "Path & confinement", "md_src_2README.html#autotoc_md529", null ],
        [ "Authentication", "md_src_2README.html#autotoc_md530", null ],
        [ "Cluster & federation", "md_src_2README.html#autotoc_md531", null ],
        [ "Cross-cutting", "md_src_2README.html#autotoc_md532", null ],
        [ "WebDAV sub-helpers", "md_src_2README.html#autotoc_md533", null ]
      ] ],
      [ "The four request lifecycles", "md_src_2README.html#autotoc_md535", [
        [ "<tt>root://</tt> stream", "md_src_2README.html#autotoc_md536", null ],
        [ "<tt>davs://</tt> WebDAV", "md_src_2README.html#autotoc_md537", null ],
        [ "S3 REST", "md_src_2README.html#autotoc_md538", null ],
        [ "CMS cluster redirect", "md_src_2README.html#autotoc_md539", null ]
      ] ],
      [ "Cross-cutting invariants", "md_src_2README.html#autotoc_md541", null ],
      [ "How to navigate / where to start reading", "md_src_2README.html#autotoc_md543", null ]
    ] ],
    [ "tpc/common — Protocol-neutral third-party-copy (TPC) core", "md_src_2tpc_2common_2README.html", [
      [ "Overview", "md_src_2tpc_2common_2README.html#autotoc_md545", null ],
      [ "Files", "md_src_2tpc_2common_2README.html#autotoc_md546", null ],
      [ "Key types & data structures", "md_src_2tpc_2common_2README.html#autotoc_md547", null ],
      [ "Control & data flow", "md_src_2tpc_2common_2README.html#autotoc_md548", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2common_2README.html#autotoc_md549", null ],
      [ "Entry points / extending", "md_src_2tpc_2common_2README.html#autotoc_md550", null ],
      [ "See also", "md_src_2tpc_2common_2README.html#autotoc_md551", null ]
    ] ],
    [ "engine — native-TPC control plane (destination side)", "md_src_2tpc_2engine_2README.html", [
      [ "Overview", "md_src_2tpc_2engine_2README.html#autotoc_md553", null ],
      [ "Files", "md_src_2tpc_2engine_2README.html#autotoc_md554", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2engine_2README.html#autotoc_md555", null ],
      [ "See also", "md_src_2tpc_2engine_2README.html#autotoc_md556", null ]
    ] ],
    [ "gsi — outbound GSI authentication for the TPC pull socket", "md_src_2tpc_2gsi_2README.html", [
      [ "Overview", "md_src_2tpc_2gsi_2README.html#autotoc_md558", null ],
      [ "Files", "md_src_2tpc_2gsi_2README.html#autotoc_md559", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2gsi_2README.html#autotoc_md560", null ],
      [ "See also", "md_src_2tpc_2gsi_2README.html#autotoc_md561", null ]
    ] ],
    [ "outbound — the blocking source-session client for native TPC pulls", "md_src_2tpc_2outbound_2README.html", [
      [ "Overview", "md_src_2tpc_2outbound_2README.html#autotoc_md563", null ],
      [ "Files", "md_src_2tpc_2outbound_2README.html#autotoc_md564", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2outbound_2README.html#autotoc_md565", null ],
      [ "See also", "md_src_2tpc_2outbound_2README.html#autotoc_md566", null ]
    ] ],
    [ "tpc — Native XRootD third-party-copy (destination-side pull)", "md_src_2tpc_2README.html", [
      [ "Overview", "md_src_2tpc_2README.html#autotoc_md568", null ],
      [ "Files", "md_src_2tpc_2README.html#autotoc_md569", null ],
      [ "Key types & data structures", "md_src_2tpc_2README.html#autotoc_md570", null ],
      [ "Control & data flow", "md_src_2tpc_2README.html#autotoc_md571", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2README.html#autotoc_md572", null ],
      [ "Entry points / extending", "md_src_2tpc_2README.html#autotoc_md573", null ],
      [ "See also", "md_src_2tpc_2README.html#autotoc_md574", null ]
    ] ],
    [ "<tt>client/apps/</tt> — native client CLI tools", "md_client_2apps_2README.html", [
      [ "Data movement", "md_client_2apps_2README.html#autotoc_md576", null ],
      [ "Checksums & verification", "md_client_2apps_2README.html#autotoc_md577", null ],
      [ "Diagnostics & monitoring", "md_client_2apps_2README.html#autotoc_md578", null ],
      [ "Auth & security", "md_client_2apps_2README.html#autotoc_md579", null ],
      [ "Namespace / staging", "md_client_2apps_2README.html#autotoc_md580", null ],
      [ "Optional (built only when <tt>libfuse3</tt> is present — not in <tt>BINS</tt>)", "md_client_2apps_2README.html#autotoc_md581", null ],
      [ "Ceph operator tools (<tt>apps/ceph/</tt> — built only when the Ceph dev headers are present)", "md_client_2apps_2README.html#autotoc_md582", null ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2apps_2README.html#autotoc_md583", null ],
      [ "Man pages & bash completion", "md_client_2apps_2README.html#autotoc_md584", null ],
      [ "CLI compatibility contract (binding for all flag/env/output work)", "md_client_2apps_2README.html#autotoc_md585", null ],
      [ "See also", "md_client_2apps_2README.html#autotoc_md586", null ]
    ] ],
    [ "<tt>client/lib/sec/</tt> — native client authentication modules", "md_client_2lib_2auth_2sec_2README.html", [
      [ "Overview", "md_client_2lib_2auth_2sec_2README.html#autotoc_md588", null ],
      [ "Files", "md_client_2lib_2auth_2sec_2README.html#autotoc_md589", null ],
      [ "Invariants", "md_client_2lib_2auth_2sec_2README.html#autotoc_md590", null ],
      [ "See also", "md_client_2lib_2auth_2sec_2README.html#autotoc_md591", null ]
    ] ],
    [ "<tt>client/lib/</tt> — native XRootD client library (<tt>libbrix</tt>)", "md_client_2lib_2README.html", [
      [ "Concept buckets (phase-69)", "md_client_2lib_2README.html#autotoc_md593", null ],
      [ "File responsibilities (Phase-38 split groups)", "md_client_2lib_2README.html#autotoc_md594", null ]
    ] ],
    [ "<tt>client/preload/</tt> — LD_PRELOAD POSIX → XRootD shim", "md_client_2preload_2README.html", [
      [ "Overview", "md_client_2preload_2README.html#autotoc_md596", null ],
      [ "How it works", "md_client_2preload_2README.html#autotoc_md597", null ],
      [ "Scope", "md_client_2preload_2README.html#autotoc_md598", null ],
      [ "Files", "md_client_2preload_2README.html#autotoc_md599", null ],
      [ "See also", "md_client_2preload_2README.html#autotoc_md600", null ]
    ] ],
    [ "<tt>client/</tt> — native BriX client tools", "md_client_2README.html", [
      [ "Directory layout", "md_client_2README.html#autotoc_md602", null ],
      [ "Build", "md_client_2README.html#autotoc_md603", null ],
      [ "Feature summary (2026-07-05)", "md_client_2README.html#autotoc_md604", [
        [ "xrdcp", "md_client_2README.html#autotoc_md605", null ],
        [ "xrdfs", "md_client_2README.html#autotoc_md606", null ],
        [ "xrdcksum", "md_client_2README.html#autotoc_md607", null ],
        [ "xrddiag", "md_client_2README.html#autotoc_md608", null ],
        [ "Ceph operator tools", "md_client_2README.html#autotoc_md609", null ]
      ] ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2README.html#autotoc_md610", null ],
      [ "Man pages & bash completion", "md_client_2README.html#autotoc_md611", null ],
      [ "See also", "md_client_2README.html#autotoc_md612", null ]
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
"auth_2krb5_2config_8c_source.html",
"authfile_8c.html#a72824660e2e41d2dd50f0751cc523aaa",
"brix__net_8h.html#a90d44cbb5d33daaaac358f93f64dfe19",
"brixcvmfs_8c.html#a32330861fad234fbb69e04eb5d910868",
"broker__creds_8c.html#a8cf65818cf204d59699fe53e93e12a6b",
"cache__storage_8c.html#aeb8cb307c03f1c30a59b4269901d5e92",
"chkpoint_8c.html#ac657ea50117e50590c8cedafc6ecbba7",
"client_2lib_2core_2aio_2uring_8c_source.html",
"cms__internal_8h.html#adc1b65b0001521639efbb96df91a480a",
"config__merge_8c.html#a66115f014d0bb699e15f741ed98f5867",
"copy__remote_8c.html#a5a9a572aebe3215a9bc8dd295bf6f5dd",
"cred__krb5_8c.html#aba524b75f8f7e927f5654cb2429da308",
"cta__exec_8c.html",
"dashboard_8h.html#a2ca22c78a3b7cf96f0752fa6d8e7f215",
"deadline_8h.html#ab80b4ef7ec72d994544a55d512df0132",
"diag__topology_8c.html#aed0a9d3bb240ee83e5028fe2ce08c964",
"entity_8c.html#abe87cb6078f3162db034ccaa3730f7ab",
"file__serve_8c.html",
"forward__request_8c_source.html",
"fs__walk_8c.html#abe8cb5e1000b27bb5d8a7733633b4825",
"functions_vars_t.html",
"groups_8c.html#a9e1d7dbabde253791b43e72987131d49",
"guard_8h.html#a0f89a0e2fe6eabea9293becbffddab5caaca2a9965cb794617c01361d06329501",
"http_8c.html#a136b61a13304c4b3e1427d2b4e15cbba",
"http__mirror_8h.html#a2d60b009597c929dd48df709c0afb485",
"impersonate_8h.html#a2b43d404c71b1da7f3959a0de8438dcb",
"jwks_8c_source.html",
"list__walk_8c.html",
"md_client_2lib_2auth_2sec_2README.html#autotoc_md590",
"md_src_2net_2guard_2README.html#autotoc_md223",
"md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md474",
"metrics__internal_8h.html#a93a7c325566a1ed4cc53ea1ccfe63e25",
"module__dispatch_8c.html#afb4134dfd58d57a6aba730c10f5f4364",
"net_2cms_2send_8c.html#a348f0b39f400e396c942268c7468737d",
"nettmo_8c_source.html",
"observability_2metrics_2metrics_8h.html#a17abce2eb0f4aa975a4953ff1bb71ccba37dc67d9900c47e7983a0b698408630d",
"opaque__validate_8c.html#ad1ad523395eabf18b66ddcd177eaac20",
"ops__ext_8c.html#aa32bb4f08730668e5c222f1a0c87cef3",
"overlay_8h.html#ad8f5ea60d47d4708f449942150426859",
"pblock__refs_8h.html#a271a9c41fc3f41a74a4ab92df938b009",
"pmark_8h.html#abb3ed6a1c57837da9e36873765f50c2ca7535e95ded0f2a7acbbb5af9dea6fecb",
"process__timers_8c_source.html",
"protocols_2root_2query_2config_8c.html#a8fa33d0092e04bf116881302a7f68f5a",
"protocols_2webdav_2delegation_8h.html#a6618602516a3e674f628ad2aeaee599b",
"put__chunk_8c.html#a03155c30eef2b729ee8d158a7bd82dc6",
"ratelimit__stream_8c.html#ad29fd32edae37f78b57c655451bc4d45",
"resilient_8c.html#a0dde6ad467d081432ade3442f6ae7a38",
"router__unittest_8c.html#a65d7b4a2cf7a4264e81daaf7fe713ebf",
"s3__post__internal_8h_source.html",
"scoped_8h.html#a99602e133c279a52718b4de1c629b3e4",
"sd__ceph_8c.html#a168fba5daa4deb3c88d469b67e128f0c",
"sd__pblock__catalog_8h.html",
"sd__posix__io_8c_source.html",
"sd__xroot__internal_8h.html#a69d6a27965ce8e189e4cb67c59f2156d",
"server__conf__merge__cluster_8c.html#a14f34015dc5145448b48665ebe196699",
"sesslog__conn_8h.html",
"src_2auth_2unix_2auth_8c.html#af30cafe97e085c07492dbbf0c64d14a3",
"srr_8h.html#a2acec8a685f52a667b741d9824ecbb13",
"stage__engine_8h.html#a4e65b53a38ab5edfc3f9f391d192db59",
"stat_8c.html#aefbb9764d131cac77db927ace9a277cd",
"stream__proxy_8c.html#ad8e0ed980bff49b4c3d2a39bd91dc92d",
"structClientRmdirRequest.html#aea2f43179ff286e67dae3687f8027e5a",
"structbdg__ctx.html#af4448f62810ff766bde8adc77a8a3869",
"structbrix__authdb__query__t.html#a0b6fcc0e1e93f832298af98d1728e866",
"structbrix__cksum__aio__t.html#ad884f1f8f5ea58de5880bc39a242439b",
"structbrix__csi__t.html#a76ca584ca0b8ce7a0a57a65ca643ce62",
"structbrix__dashboard__history__bucket__t.html#a01a60cbd0b83e8fe54313f95f350b348",
"structbrix__ftp__dc__sec__t.html#a08d34e477c7fe92324b8cfe101632e52",
"structbrix__iobuf.html#abf39dedbc9e711161e40e4bb403e86c9",
"structbrix__ns__result__t.html#a06421e92f3c185cc9b47dc5c03391abb",
"structbrix__poll__slot.html#a2101f21733fbd7c625a48e32c0014ff6",
"structbrix__readv__seg.html#ae64d8e4b8430a1d77ec8d680356bac09",
"structbrix__sd__driver__s.html#adf7e3f955f49fd7976fc4d78a71da540",
"structbrix__srv__entry__t.html#aa5c106b81182b7f3e5e4e42f631111a9",
"structbrix__throttle__conf__t.html#ac74b573683d2f6e5143c8053c7bc6eed",
"structbrix__transfer__table__t.html",
"structbrix__vfs__walk__opts__t.html#af241b8dcf11a6b73c0f998ce5d2f6c59",
"structbrix__xmeta__t.html#a34311fd49aa6b9ef1ce51d456f9dfc08",
"structckv__cinfo.html#a9ac723b6bcff359fad336d406fcfd039",
"structdash__cookie__parse__t.html#aed61afe74e1aa562a0560c8a7530f7c6",
"structftp__eb__range__t.html#adde0632edeafd2a0101c8dac44561cc0",
"structimp__broker__fds__t.html#a33bd662ce35d0afba271bb76142ee121",
"structngx__brix__cms__ctx__s.html#a165b1722dd3c4b2369833af337256dac",
"structngx__brix__user__global__t.html",
"structngx__http__brix__webdav__loc__conf__t.html#ad4781bb7b8eb38d2240d5270fbb0f617",
"structpblock__state__t.html#a18112997448e58cef7d734de2a9e201a",
"structrw__lowcount__t.html#a4f9b64335f6dfbdcb718bd73735931c6",
"structscan__arg__spec__t.html#ab2a246a46cd990a65a6b43c07d86974e",
"structsd__stage__inst__state.html#ab4fc860a960a8fe50613e9f155e3ef3e",
"structtail__args__t.html#a879fc80d8b0d50297a528896b9d8d75a",
"structvfs__walk__step__t.html#ab45b1e998fd02d0f86df758a9059e4ce",
"structwebdav__tpc__pull__ctx__t.html#a061d9baf3c2723577584480fa661670f",
"structxrdcp__transfer__ctx.html#abcbe79538e19aa5cbf36965e49effaaf",
"subject__map_8c_source.html",
"tier__config_8c.html#af2f3f6f80196421a71367dcfd5ecb446",
"tpc__curl_8c.html#a73023b5c4f58f7214f11b63aa724bcdd",
"transport_8h.html#ab86a43f3bf946d9be4f2ead5599aec53",
"uring__submit_8c_source.html",
"vfs__browse_8c.html#aac00662b2d8be75f216d5bf2148783a6",
"vfs__ops_8h.html#ab26c0fa6906b9935264036afad808a1c",
"webdav_2get_8c.html#a056ca1e584a76c7b01ee172efe88d589",
"weblist_8c.html#a2ed2447773c3a4688bddd30a10fbb01e",
"write__staged_8c.html#a3d81d6a38774a49c7dc8a474bb778cc0",
"xmeta_8h.html#ae51da6a0e3953ea75d8bc693485c1eb4",
"xrdceph__migrate__config_8h.html#a3dabe26250c55b50ef1a564d6d4ab939",
"xrddiag_8c.html#af1b5200d5f0accae774fc846de6977a5",
"xrdgsiproxy_8c.html#a8f8fd1892cbc367e052e2a33bc776342",
"xrootdfs_8c.html#a5d8efd46eb947be0adaf6f9343d94960",
"zip_8h.html#a2e0e7b404974b6fb3b6735683ecccb71"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';