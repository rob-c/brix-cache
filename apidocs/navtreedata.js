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
        [ "Dynamic backend pool (admin API)", "md_src_2protocols_2webdav_2README.html#autotoc_md507", null ],
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
"auth_2impersonate_2lifecycle_8c.html#aba40845cf4ba2da294eacd29f37c802a",
"authdb__parse_8c.html#ae578c2dab779036eed7175558a01c2c8",
"brix__net_8h.html",
"brixautofs_8c.html#a49287a136e9c00716e4a7fca47472cfd",
"brixposix__preload_8c.html#a1aa3037b164c5b99bcc46cd326202d7a",
"cache__internal_8h.html#a80b938fa9e754d1c155e681c53ed501e",
"checksum__core_8c.html#a3517608bcd4af2ff9825633a75ef4255",
"cli__opts_8c.html#a88fa222cdc1f075e762fc66c771dd03e",
"cms__internal_8h.html#a3e80a38a4f5282c42eecbcec0ed19116",
"config__download_8c.html#ab352180b62cae00ba31dda68e20aa6fb",
"copy__range_8c.html#a250e00266369ad85db85bfa57f80ef2f",
"cred_8c.html#a7759654e6581ebcfec992bf316b9ccee",
"cstore_8c.html#a87732d50a1140bea8d8504aff69870ba",
"cvmfs_8h.html#ae5e327d164061bf35863353ea6f63042a58d19f72ef75aefd3126e96f817a26ba",
"dcksm_8c.html#a455698b9d5fa1389ff0bf53624ba080c",
"diag__internal_8h.html#acd64e9fcc40d86912d237b498ff7f115a685fbda6e3363f5a8c4a640c90ccc6b5",
"disconnect__report_8c.html",
"fd__table_8c_source.html",
"forward__relay__dispatch_8c.html#accf3824e4284ec09b362ea0db373bc84",
"fs_2path_2unified__internal_8h.html#a76f01d745cbe4bb0e9f42e88787319e2",
"ftp__module_8c.html#ad7f47e3251dce85b1e0439a7705cb79d",
"globals_vars_o.html",
"gsi__outbound__common_8c.html#a68558f9d7f5809432e61104faf0f13fe",
"health__check_8h.html#a8eb4d5d6a3a3814a18e8a13bab3ce02a",
"http__headers__set_8c.html#a003b84cfa9137bcdf3b77927381f59c1",
"idmap__denylist_8c.html#a3d1f9e01469fcf1a2904f66ba4920b64",
"json_8h.html#a6cb393ec9fb86c116aeff4d933908d09",
"lifecycle__worker_8c.html#a07bd13a4a8f5a2ad89268eeb9c523614",
"macaroon__parse_8c.html#a7f141213b1ba92810dda9124ceb17a07",
"md_src_2fs_2cache_2README.html#autotoc_md158",
"md_src_2protocols_2root_2stream_2README.html#autotoc_md413",
"methods__proppatch_8c.html#acd1bbee5be3cba6429986aa42bd40b8e",
"module__acc__directives_8h.html#a55f577e58dc5e0b2e25bc7ccb34012f7",
"negcache_8h.html#a47c280646046a6d24daa0a5262f8bd69",
"nettmo_8c.html#aad37385cfbd244a7fb68e3ee38248dfd",
"observability_2metrics_2metrics_8h.html#a028c60a678ed9fdcf45ae86a16984769",
"opaque__validate_8c.html#a2a21a1c92acf0f967bd21baf812b69e5",
"openssl__auto_8h.html#acffebaae967dce56fdefbc1707952c5d",
"overlay_8h.html#aa53666dd100c32a9c8b3a6d5abba8fcb",
"pblock__quota_8h.html#a39ae92d2f9c2293c75aee63b40a639d2",
"pmark_8h.html#aa743054bb7c79d4348978039fe30d99ea63a138891cea58a8234e9d6d07f09816",
"process__timers_8c.html#a5919edaa6a3aa525fc0a7ab9eab2a16d",
"protocols_2root_2handshake_2policy_8c_source.html",
"protocols_2webdav_2delegation_8c.html#a8d0e1d5a0f5d8110e87511776dcc5216",
"proxy__req__internal_8h.html#a65af27f3a82deb9f6eaae49530be7d14",
"ratelimit_8h.html#a829706c6369783398ef86df980e0aec0",
"registry__unittest_8c_source.html",
"root_2session_2session_8h.html#a1efc7f7d4518d556a8e200b9280c8c6e",
"s3__handlers_8h.html",
"scan__record_8c.html#a7b86c3050f9523a4cf3644e4683647e8",
"sd__cache__forward_8c.html#aac14dc0e146fa5a1933acc3f8434eef1",
"sd__http__internal_8h.html#a56017b15471a82f4b0089f25482ed36f",
"sd__pblock__unittest_8c.html#a9d8bf992733e1f83b58026a8f4720bda",
"sd__stage_8c.html#a98b404474fbcb6a2e9622aff41deae95",
"sec__token_8c_source.html",
"sesslog_8c.html#a9440d02905751495bfb2035fe0ecf385",
"site__n2n_8h.html#a107e84872c6e513966253571f0f423c5",
"src_2fs_2vfs_2vfs_8h.html#aea04cf3bb9ec8459167efcc1d4889346",
"sss_8h.html#a8e0f5aeefd27dc5c1ed867d40b6cac9e",
"stage__request__registry__mutate_8c.html#a1e49583b0807bef01d4d0263425b4fe4",
"str__dup_8h.html",
"structClientLinkRequest.html#afbef90d6b8fae040bf653f78f38feee9",
"structacc__parse__ctx__t.html",
"structbrix__access__event__t.html#ac4c5ca7d6e9504c01c1e1f06ad493121",
"structbrix__cache__meta__t.html",
"structbrix__conn.html#ad7c4422e3928baa51bbbc7286d1338ec",
"structbrix__ctx__t.html#a0416cc9754f64b2261f56cd148e25311",
"structbrix__file__t.html#a1a65ab5d8dadbc6e813bf46c53742cc3",
"structbrix__http__content__range__t.html",
"structbrix__mgr.html#a050160c7daf31e77b7804addf8234673",
"structbrix__pgread__aio__t.html#a0e8d6621d20b22e7853187ce961dc3c6",
"structbrix__proxy__ctx__s.html#ac23271909edeb77f2f88defc8c5608c5",
"structbrix__s3__sts__conf__t.html#a86dbac67a26063de1f347d70c5919689",
"structbrix__sess__t.html#ae56d41897d7f683bf99c4a6a647a72d2",
"structbrix__stage__request__view__t.html#a15584bff6fbce1c9c9cb71eb75bc086d",
"structbrix__tpc__key__table__t.html#a1d360db5eafdd08787bc20625315b033",
"structbrix__vfs__ctx__t.html#a96b4dce13c0a4e03640e76150fd24a35",
"structbrix__writev__aio__t.html#a1b95077c48cfd0c6a6527559bd9aef21",
"structcephfs__layout__t.html#a173c84b20fb2a9242cc5679607d0aed4",
"structcta__progress__t.html#a9ef3645eda5d87ee482ae722a0eb1ca0",
"structdx__finding.html",
"structgsi__cresp__ctx.html#a9a64131ac8e2e6ffac3402e39a351255",
"structmb__worker.html#acc113878849607d1014ad1ad0fb4ef30",
"structngx__brix__proxy__metrics__t.html#a207d7ba2f57c2e0bad3150436d6dd634",
"structngx__http__brix__shared__conf__t.html#a5d2aacb365b2a70ccabd74afa1574128",
"structocsp__query__t.html#ade6cd34068bde968777be81f96633dfb",
"structproxy__build__ctx.html#ae0dae44373f8496cefd2d749967e775a",
"structs3__list__req__t.html#ab126a8c0488a5581d650856377aa42d5",
"structsd__http__inst__state.html#a5aae711349fe3c3007509d3e01fdda76",
"structsrv__family__desc__t.html#a2fb72f46e8c7d391d8f88f4adcbe9bd8",
"structtpc__params__t.html#a9cac8be4b780589675345cf6052eef36",
"structwebdav__copy__req__t.html#af8315e19c63dd890933026897f6c4ebf",
"structxmeta__state__wire__t.html#a7322bdc5786857f7c707be746560c808",
"structxrdw__read__req__t.html#a3fd75680da466312314512b9e52044e0",
"tape__rest_8c.html#ab731212a44880c065da7e2ca1bc8e476",
"tpc_2common_2registry_8h.html#aa2b630e3a264b5ae908559193582495a",
"tpc__pull_8c.html#a9dfb8038e5ba6cbf423aff1595cc6103",
"ucred_8h.html#afe89ae88bf905f4d835b2329d3b2a355",
"vfs_8c.html#af86e0a68cbeaa7d031b02db4a6505fc2",
"vfs__io__core_8c.html",
"vfs__walk_8c.html#a2f5aba8e586f9329840a080e48023449",
"webdav__module__internal_8h.html",
"wire__codec__ns_8c.html#a22a315db7cad7b48f3cb1c4429a9f133",
"xfer__ledger_8c.html#aba83e7c55b70035ebaf53c004d7b7e03",
"xrd__battery_8c.html#a8cf2c1bd39a0ddd8a1d432c7b2293f46",
"xrdcp_8c.html#af88aafdedf1d8e6cdacdfc9a627e67aa",
"xrdfs__internal_8h.html#a6a54560430a44696c8133bc826c96de2",
"xrdrc_8c.html",
"xrootdfs__legacy_8c.html#a066648e75e7e358a7a3d127688b6addf",
"zip__member_8c.html#a1bb988b72fba73d83a675cabeae68efc"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';