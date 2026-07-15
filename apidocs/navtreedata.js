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
      [ "Testing", "md_src_2net_2guard_2README.html#autotoc_md222", null ]
    ] ],
    [ "net/httpguard — HTTP adapter for the bad-actor guard", "md_src_2net_2httpguard_2README.html", [
      [ "Directives", "md_src_2net_2httpguard_2README.html#autotoc_md224", null ],
      [ "ARC deployment recipe", "md_src_2net_2httpguard_2README.html#autotoc_md225", null ],
      [ "fail2ban wiring", "md_src_2net_2httpguard_2README.html#autotoc_md226", null ],
      [ "Tests", "md_src_2net_2httpguard_2README.html#autotoc_md227", null ]
    ] ],
    [ "manager — Cluster / redirector control plane (server registry, redirect cache, active health checks)", "md_src_2net_2manager_2README.html", [
      [ "Overview", "md_src_2net_2manager_2README.html#autotoc_md229", null ],
      [ "Files", "md_src_2net_2manager_2README.html#autotoc_md230", null ],
      [ "Key types & data structures", "md_src_2net_2manager_2README.html#autotoc_md231", null ],
      [ "Control & data flow", "md_src_2net_2manager_2README.html#autotoc_md232", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2manager_2README.html#autotoc_md233", null ],
      [ "Entry points / extending", "md_src_2net_2manager_2README.html#autotoc_md234", null ],
      [ "See also", "md_src_2net_2manager_2README.html#autotoc_md235", null ]
    ] ],
    [ "mirror — fire-and-forget traffic mirroring (shadow replay) for XRootD and WebDAV", "md_src_2net_2mirror_2README.html", [
      [ "Overview", "md_src_2net_2mirror_2README.html#autotoc_md237", null ],
      [ "Files", "md_src_2net_2mirror_2README.html#autotoc_md238", null ],
      [ "Key types & data structures", "md_src_2net_2mirror_2README.html#autotoc_md239", null ],
      [ "Control & data flow", "md_src_2net_2mirror_2README.html#autotoc_md240", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2mirror_2README.html#autotoc_md241", null ],
      [ "Entry points / extending", "md_src_2net_2mirror_2README.html#autotoc_md242", null ],
      [ "See also", "md_src_2net_2mirror_2README.html#autotoc_md243", null ]
    ] ],
    [ "proxy — Transparent XRootD reverse proxy (<tt>brix_proxy</tt>)", "md_src_2net_2proxy_2README.html", [
      [ "Overview", "md_src_2net_2proxy_2README.html#autotoc_md245", null ],
      [ "Files", "md_src_2net_2proxy_2README.html#autotoc_md246", null ],
      [ "Key types & data structures", "md_src_2net_2proxy_2README.html#autotoc_md247", null ],
      [ "Control & data flow", "md_src_2net_2proxy_2README.html#autotoc_md248", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2proxy_2README.html#autotoc_md249", null ],
      [ "Entry points / extending", "md_src_2net_2proxy_2README.html#autotoc_md250", null ],
      [ "See also", "md_src_2net_2proxy_2README.html#autotoc_md251", null ]
    ] ],
    [ "ratelimit — identity-aware leaky-bucket rate, bandwidth & concurrency limiting (Phase 25)", "md_src_2net_2ratelimit_2README.html", [
      [ "Overview", "md_src_2net_2ratelimit_2README.html#autotoc_md253", null ],
      [ "Files", "md_src_2net_2ratelimit_2README.html#autotoc_md254", null ],
      [ "Key types & data structures", "md_src_2net_2ratelimit_2README.html#autotoc_md255", null ],
      [ "Directive reference (configuration surface)", "md_src_2net_2ratelimit_2README.html#autotoc_md256", null ],
      [ "Control & data flow", "md_src_2net_2ratelimit_2README.html#autotoc_md257", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2ratelimit_2README.html#autotoc_md258", null ],
      [ "Entry points / extending", "md_src_2net_2ratelimit_2README.html#autotoc_md259", null ],
      [ "See also", "md_src_2net_2ratelimit_2README.html#autotoc_md260", null ]
    ] ],
    [ "net — clustering, proxying, shadowing, and connection defense", "md_src_2net_2README.html", null ],
    [ "tap — ngx-free protocol observation tap (decode + sink fan-out)", "md_src_2net_2tap_2README.html", [
      [ "Overview", "md_src_2net_2tap_2README.html#autotoc_md263", null ],
      [ "Files", "md_src_2net_2tap_2README.html#autotoc_md264", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2tap_2README.html#autotoc_md265", null ],
      [ "See also", "md_src_2net_2tap_2README.html#autotoc_md266", null ]
    ] ],
    [ "upstream — outbound XRootD redirector/proxy client (manager-side server-to-server query)", "md_src_2net_2upstream_2README.html", [
      [ "Overview", "md_src_2net_2upstream_2README.html#autotoc_md268", null ],
      [ "Files", "md_src_2net_2upstream_2README.html#autotoc_md269", null ],
      [ "Key types & data structures", "md_src_2net_2upstream_2README.html#autotoc_md270", null ],
      [ "Control & data flow", "md_src_2net_2upstream_2README.html#autotoc_md271", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2upstream_2README.html#autotoc_md272", null ],
      [ "Entry points / extending", "md_src_2net_2upstream_2README.html#autotoc_md273", null ],
      [ "See also", "md_src_2net_2upstream_2README.html#autotoc_md274", null ]
    ] ],
    [ "dashboard — live HTTPS transfer monitor + REST admin write API", "md_src_2observability_2dashboard_2README.html", [
      [ "Overview", "md_src_2observability_2dashboard_2README.html#autotoc_md276", null ],
      [ "Files", "md_src_2observability_2dashboard_2README.html#autotoc_md277", null ],
      [ "Key types & data structures", "md_src_2observability_2dashboard_2README.html#autotoc_md278", null ],
      [ "Control & data flow", "md_src_2observability_2dashboard_2README.html#autotoc_md279", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2dashboard_2README.html#autotoc_md280", null ],
      [ "Entry points / extending", "md_src_2observability_2dashboard_2README.html#autotoc_md281", null ],
      [ "See also", "md_src_2observability_2dashboard_2README.html#autotoc_md282", null ],
      [ "VFS export browser (<tt>brix_dashboard_vfs_browse on</tt>)", "md_src_2observability_2dashboard_2README.html#autotoc_md283", null ]
    ] ],
    [ "metrics — shared-memory counters and the Prometheus <tt>/metrics</tt> exporter", "md_src_2observability_2metrics_2README.html", [
      [ "Overview", "md_src_2observability_2metrics_2README.html#autotoc_md285", null ],
      [ "Files", "md_src_2observability_2metrics_2README.html#autotoc_md286", null ],
      [ "Key types & data structures", "md_src_2observability_2metrics_2README.html#autotoc_md287", null ],
      [ "Control & data flow", "md_src_2observability_2metrics_2README.html#autotoc_md288", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2metrics_2README.html#autotoc_md289", null ],
      [ "Entry points / extending", "md_src_2observability_2metrics_2README.html#autotoc_md290", null ],
      [ "See also", "md_src_2observability_2metrics_2README.html#autotoc_md291", null ]
    ] ],
    [ "pmark — SciTags packet marking", "md_src_2observability_2pmark_2README.html", [
      [ "Overview", "md_src_2observability_2pmark_2README.html#autotoc_md293", null ],
      [ "Files", "md_src_2observability_2pmark_2README.html#autotoc_md294", null ],
      [ "Configuration", "md_src_2observability_2pmark_2README.html#autotoc_md295", null ],
      [ "Control & data flow", "md_src_2observability_2pmark_2README.html#autotoc_md296", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2pmark_2README.html#autotoc_md297", null ],
      [ "See also", "md_src_2observability_2pmark_2README.html#autotoc_md298", null ]
    ] ],
    [ "observability — metrics, packet marking, dashboard, and access logs", "md_src_2observability_2README.html", null ],
    [ "Session Lifecycle Logging", "md_src_2observability_2sesslog_2README.html", null ],
    [ "cvmfs — the cvmfs:// site cache (+ experimental scvmfs:// TLS variant)", "md_src_2protocols_2cvmfs_2README.html", [
      [ "Overview", "md_src_2protocols_2cvmfs_2README.html#autotoc_md302", null ],
      [ "Files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md303", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2cvmfs_2README.html#autotoc_md304", null ],
      [ "See also", "md_src_2protocols_2cvmfs_2README.html#autotoc_md305", null ]
    ] ],
    [ "<tt>src/protocols/dig/</tt> — XrdDig-style remote diagnostics", "md_src_2protocols_2dig_2README.html", [
      [ "Overview", "md_src_2protocols_2dig_2README.html#autotoc_md307", null ],
      [ "Files", "md_src_2protocols_2dig_2README.html#autotoc_md308", null ],
      [ "See also", "md_src_2protocols_2dig_2README.html#autotoc_md309", null ]
    ] ],
    [ "protocols — one subdirectory per wire protocol", "md_src_2protocols_2README.html", null ],
    [ "connection — TCP connection lifecycle, framing, and the async I/O state machine for <tt>root://</tt>", "md_src_2protocols_2root_2connection_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2connection_2README.html#autotoc_md312", null ],
      [ "Files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md313", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2connection_2README.html#autotoc_md314", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2connection_2README.html#autotoc_md315", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2connection_2README.html#autotoc_md316", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2connection_2README.html#autotoc_md317", null ],
      [ "See also", "md_src_2protocols_2root_2connection_2README.html#autotoc_md318", null ]
    ] ],
    [ "dirlist — XRootD <tt>kXR_dirlist</tt> directory enumeration (stream protocol)", "md_src_2protocols_2root_2dirlist_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md320", null ],
      [ "Files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md321", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md322", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md323", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md324", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md325", null ],
      [ "See also", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md326", null ]
    ] ],
    [ "fattr — XRootD <tt>kXR_fattr</tt> extended-attribute operations", "md_src_2protocols_2root_2fattr_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md328", null ],
      [ "Files", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md329", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md330", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md331", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md332", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md333", null ],
      [ "See also", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md334", null ]
    ] ],
    [ "handoff — single-port protocol handoff for the stream xrootd listener", "md_src_2protocols_2root_2handoff_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md336", null ],
      [ "Files", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md337", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md338", null ],
      [ "See also", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md339", null ]
    ] ],
    [ "handshake — XRootD stream request entry point and opcode dispatcher", "md_src_2protocols_2root_2handshake_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md341", null ],
      [ "Files", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md342", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md343", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md344", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md345", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md346", null ],
      [ "See also", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md347", null ]
    ] ],
    [ "path — wire-path extraction, sanitization, and stat formatting", "md_src_2protocols_2root_2path_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2path_2README.html#autotoc_md349", null ],
      [ "Files", "md_src_2protocols_2root_2path_2README.html#autotoc_md350", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2path_2README.html#autotoc_md351", null ],
      [ "See also", "md_src_2protocols_2root_2path_2README.html#autotoc_md352", null ]
    ] ],
    [ "protocol — XRootD <tt>root://</tt> wire-format constants & packed structs", "md_src_2protocols_2root_2protocol_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md354", [
        [ "Provenance & licensing", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md355", null ]
      ] ],
      [ "Files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md356", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md357", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md358", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md359", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md360", null ],
      [ "See also", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md361", null ]
    ] ],
    [ "query — XRootD <tt>kXR_query</tt> sub-protocol, <tt>kXR_prepare</tt> staging, and <tt>kXR_set</tt> hints", "md_src_2protocols_2root_2query_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2query_2README.html#autotoc_md363", null ],
      [ "Files", "md_src_2protocols_2root_2query_2README.html#autotoc_md364", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2query_2README.html#autotoc_md365", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2query_2README.html#autotoc_md366", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2query_2README.html#autotoc_md367", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2query_2README.html#autotoc_md368", null ],
      [ "See also", "md_src_2protocols_2root_2query_2README.html#autotoc_md369", null ]
    ] ],
    [ "read — XRootD read-side opcodes and the file-handle lifecycle", "md_src_2protocols_2root_2read_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2read_2README.html#autotoc_md371", null ],
      [ "Files", "md_src_2protocols_2root_2read_2README.html#autotoc_md372", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2read_2README.html#autotoc_md373", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2read_2README.html#autotoc_md374", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2read_2README.html#autotoc_md375", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2read_2README.html#autotoc_md376", null ],
      [ "See also", "md_src_2protocols_2root_2read_2README.html#autotoc_md377", null ]
    ] ],
    [ "root — the XRootD (<tt>root://</tt> / <tt>roots://</tt>) protocol plane", "md_src_2protocols_2root_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2README.html#autotoc_md379", null ],
      [ "Subdirectories", "md_src_2protocols_2root_2README.html#autotoc_md380", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2README.html#autotoc_md381", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2README.html#autotoc_md382", null ],
      [ "See also", "md_src_2protocols_2root_2README.html#autotoc_md383", null ]
    ] ],
    [ "relay — transparent pass-through relay with a passive observation tap", "md_src_2protocols_2root_2relay_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2relay_2README.html#autotoc_md385", null ],
      [ "Files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md386", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2relay_2README.html#autotoc_md387", null ],
      [ "See also", "md_src_2protocols_2root_2relay_2README.html#autotoc_md388", null ]
    ] ],
    [ "response — XRootD wire-response framing helpers", "md_src_2protocols_2root_2response_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2response_2README.html#autotoc_md390", null ],
      [ "Files", "md_src_2protocols_2root_2response_2README.html#autotoc_md391", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2response_2README.html#autotoc_md392", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2response_2README.html#autotoc_md393", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2response_2README.html#autotoc_md394", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2response_2README.html#autotoc_md395", null ],
      [ "See also", "md_src_2protocols_2root_2response_2README.html#autotoc_md396", null ]
    ] ],
    [ "session — XRootD session lifecycle, identity binding & cross-worker registry", "md_src_2protocols_2root_2session_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2session_2README.html#autotoc_md398", null ],
      [ "Files", "md_src_2protocols_2root_2session_2README.html#autotoc_md399", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2session_2README.html#autotoc_md400", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2session_2README.html#autotoc_md401", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2session_2README.html#autotoc_md402", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2session_2README.html#autotoc_md403", null ],
      [ "See also", "md_src_2protocols_2root_2session_2README.html#autotoc_md404", null ]
    ] ],
    [ "stream — <tt>ngx_stream_brix_module</tt> descriptor & directive table", "md_src_2protocols_2root_2stream_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2stream_2README.html#autotoc_md406", null ],
      [ "Files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md407", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2stream_2README.html#autotoc_md408", [
        [ "Directive groups (authoritative <tt>module.c</tt> set)", "md_src_2protocols_2root_2stream_2README.html#autotoc_md409", null ]
      ] ],
      [ "Control & data flow", "md_src_2protocols_2root_2stream_2README.html#autotoc_md410", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2stream_2README.html#autotoc_md411", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2stream_2README.html#autotoc_md412", null ],
      [ "See also", "md_src_2protocols_2root_2stream_2README.html#autotoc_md413", null ]
    ] ],
    [ "write — XRootD mutating-opcode handlers (the stream write path)", "md_src_2protocols_2root_2write_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2write_2README.html#autotoc_md415", null ],
      [ "Files", "md_src_2protocols_2root_2write_2README.html#autotoc_md416", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2write_2README.html#autotoc_md417", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2write_2README.html#autotoc_md418", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2write_2README.html#autotoc_md419", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2write_2README.html#autotoc_md420", null ],
      [ "See also", "md_src_2protocols_2root_2write_2README.html#autotoc_md421", null ]
    ] ],
    [ "src/protocols/root/zip — ZIP member access (phase-57 W2)", "md_src_2protocols_2root_2zip_2README.html", [
      [ "Status", "md_src_2protocols_2root_2zip_2README.html#autotoc_md423", null ],
      [ "zip_dir.c — the parser", "md_src_2protocols_2root_2zip_2README.html#autotoc_md424", null ],
      [ "Running the unit test (standalone, no nginx build)", "md_src_2protocols_2root_2zip_2README.html#autotoc_md425", null ]
    ] ],
    [ "s3 — S3-compatible REST endpoint over the local export root", "md_src_2protocols_2s3_2README.html", [
      [ "Overview", "md_src_2protocols_2s3_2README.html#autotoc_md427", null ],
      [ "Files", "md_src_2protocols_2s3_2README.html#autotoc_md428", null ],
      [ "Key types & data structures", "md_src_2protocols_2s3_2README.html#autotoc_md429", null ],
      [ "Control & data flow", "md_src_2protocols_2s3_2README.html#autotoc_md430", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2s3_2README.html#autotoc_md431", null ],
      [ "Entry points / extending", "md_src_2protocols_2s3_2README.html#autotoc_md432", null ],
      [ "See also", "md_src_2protocols_2s3_2README.html#autotoc_md433", null ]
    ] ],
    [ "shared — cross-protocol helper library (HTTP file serving + overflow-safe size math)", "md_src_2protocols_2shared_2README.html", [
      [ "Overview", "md_src_2protocols_2shared_2README.html#autotoc_md435", null ],
      [ "Files", "md_src_2protocols_2shared_2README.html#autotoc_md436", null ],
      [ "Key types & data structures", "md_src_2protocols_2shared_2README.html#autotoc_md437", null ],
      [ "Control & data flow", "md_src_2protocols_2shared_2README.html#autotoc_md438", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2shared_2README.html#autotoc_md439", null ],
      [ "Entry points / extending", "md_src_2protocols_2shared_2README.html#autotoc_md440", null ],
      [ "See also", "md_src_2protocols_2shared_2README.html#autotoc_md441", null ]
    ] ],
    [ "<tt>src/protocols/srr/</tt> — WLCG Storage Resource Reporting (SRR) endpoint", "md_src_2protocols_2srr_2README.html", [
      [ "Why this instead of the XRootD UDP monitoring stack", "md_src_2protocols_2srr_2README.html#autotoc_md443", null ],
      [ "Files", "md_src_2protocols_2srr_2README.html#autotoc_md444", null ],
      [ "Configuration", "md_src_2protocols_2srr_2README.html#autotoc_md445", null ],
      [ "Semantics & caveats", "md_src_2protocols_2srr_2README.html#autotoc_md446", null ],
      [ "Schema conformance", "md_src_2protocols_2srr_2README.html#autotoc_md447", null ]
    ] ],
    [ "<tt>src/protocols/ssi/</tt> — XrdSsi request/response service over <tt>root://</tt>", "md_src_2protocols_2ssi_2README.html", [
      [ "Overview", "md_src_2protocols_2ssi_2README.html#autotoc_md449", null ],
      [ "Phase 1: session multiplexing (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md450", null ],
      [ "Phase 2: async server-push via <tt>kXR_attn</tt> (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md451", null ],
      [ "Phase 3: streamed responses + delivered alerts (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md452", null ],
      [ "Phases 4–5: CTA flagship service (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md453", null ],
      [ "Phase 6: config, metrics, conformance (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md454", [
        [ "Directives (<tt>NGX_STREAM_SRV_CONF</tt>)", "md_src_2protocols_2ssi_2README.html#autotoc_md455", null ],
        [ "Metrics (low-cardinality — <tt>{port,auth}</tt> only)", "md_src_2protocols_2ssi_2README.html#autotoc_md456", null ],
        [ "Conformance", "md_src_2protocols_2ssi_2README.html#autotoc_md457", null ]
      ] ],
      [ "RRInfo wire layout", "md_src_2protocols_2ssi_2README.html#autotoc_md458", null ],
      [ "Files", "md_src_2protocols_2ssi_2README.html#autotoc_md459", null ],
      [ "See also", "md_src_2protocols_2ssi_2README.html#autotoc_md460", null ]
    ] ],
    [ "<tt>src/protocols/ssi/svc_cta/</tt> — flagship CTA tape service", "md_src_2protocols_2ssi_2svc__cta_2README.html", [
      [ "Layers", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md462", null ],
      [ "Request lifecycle", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md463", [
        [ "State machine", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md464", null ],
        [ "Executor", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md465", null ],
        [ "Security", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md466", null ],
        [ "Journal (restart recovery)", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md467", null ]
      ] ],
      [ "External contract — the pinned field table", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md468", null ],
      [ "Golden-vector provenance", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md469", null ],
      [ "Scope notes", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md470", null ]
    ] ],
    [ "webdav/fs — Confined local-filesystem copy engine for WebDAV COPY/MOVE", "md_src_2protocols_2webdav_2fs_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md472", null ],
      [ "Files", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md473", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md474", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md475", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md476", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md477", null ],
      [ "See also", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md478", null ]
    ] ],
    [ "webdav/locks — WebDAV LOCK request-header & body parsers", "md_src_2protocols_2webdav_2locks_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md480", null ],
      [ "Files", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md481", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md482", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md483", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md484", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md485", null ],
      [ "See also", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md486", null ]
    ] ],
    [ "webdav/methods — Per-method WebDAV precondition helpers", "md_src_2protocols_2webdav_2methods_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md488", null ],
      [ "Files", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md489", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md490", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md491", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md492", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md493", null ],
      [ "See also", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md494", null ]
    ] ],
    [ "webdav — HTTP/WebDAV/HTTPS gateway (<tt>davs://</tt>, <tt>http://</tt>) over the export root", "md_src_2protocols_2webdav_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2README.html#autotoc_md496", null ],
      [ "Files", "md_src_2protocols_2webdav_2README.html#autotoc_md497", [
        [ "Module wiring & configuration", "md_src_2protocols_2webdav_2README.html#autotoc_md498", null ],
        [ "Dispatch & generic helpers", "md_src_2protocols_2webdav_2README.html#autotoc_md499", null ],
        [ "HTTP method handlers", "md_src_2protocols_2webdav_2README.html#autotoc_md500", null ],
        [ "Authentication", "md_src_2protocols_2webdav_2README.html#autotoc_md501", null ],
        [ "HTTP-TPC (third-party copy)", "md_src_2protocols_2webdav_2README.html#autotoc_md502", null ],
        [ "Upstream proxy mode", "md_src_2protocols_2webdav_2README.html#autotoc_md503", null ],
        [ "XrdHttp protocol extension", "md_src_2protocols_2webdav_2README.html#autotoc_md504", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2README.html#autotoc_md505", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2README.html#autotoc_md506", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2README.html#autotoc_md507", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2README.html#autotoc_md508", null ],
      [ "See also", "md_src_2protocols_2webdav_2README.html#autotoc_md509", null ]
    ] ],
    [ "webdav/util — WebDAV URI decoding and XML escaping helpers", "md_src_2protocols_2webdav_2util_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md511", null ],
      [ "Files", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md512", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md513", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md514", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md515", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md516", null ],
      [ "See also", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md517", null ]
    ] ],
    [ "src — nginx-xrootd Source Tree", "md_src_2README.html", [
      [ "Source map", "md_src_2README.html#autotoc_md520", [
        [ "Top-level files (now under <tt>core/</tt>)", "md_src_2README.html#autotoc_md521", null ],
        [ "Entry & dispatch", "md_src_2README.html#autotoc_md522", null ],
        [ "Protocol handlers", "md_src_2README.html#autotoc_md523", null ],
        [ "Data plane", "md_src_2README.html#autotoc_md524", null ],
        [ "Path & confinement", "md_src_2README.html#autotoc_md525", null ],
        [ "Authentication", "md_src_2README.html#autotoc_md526", null ],
        [ "Cluster & federation", "md_src_2README.html#autotoc_md527", null ],
        [ "Cross-cutting", "md_src_2README.html#autotoc_md528", null ],
        [ "WebDAV sub-helpers", "md_src_2README.html#autotoc_md529", null ]
      ] ],
      [ "The four request lifecycles", "md_src_2README.html#autotoc_md531", [
        [ "<tt>root://</tt> stream", "md_src_2README.html#autotoc_md532", null ],
        [ "<tt>davs://</tt> WebDAV", "md_src_2README.html#autotoc_md533", null ],
        [ "S3 REST", "md_src_2README.html#autotoc_md534", null ],
        [ "CMS cluster redirect", "md_src_2README.html#autotoc_md535", null ]
      ] ],
      [ "Cross-cutting invariants", "md_src_2README.html#autotoc_md537", null ],
      [ "How to navigate / where to start reading", "md_src_2README.html#autotoc_md539", null ]
    ] ],
    [ "tpc/common — Protocol-neutral third-party-copy (TPC) core", "md_src_2tpc_2common_2README.html", [
      [ "Overview", "md_src_2tpc_2common_2README.html#autotoc_md541", null ],
      [ "Files", "md_src_2tpc_2common_2README.html#autotoc_md542", null ],
      [ "Key types & data structures", "md_src_2tpc_2common_2README.html#autotoc_md543", null ],
      [ "Control & data flow", "md_src_2tpc_2common_2README.html#autotoc_md544", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2common_2README.html#autotoc_md545", null ],
      [ "Entry points / extending", "md_src_2tpc_2common_2README.html#autotoc_md546", null ],
      [ "See also", "md_src_2tpc_2common_2README.html#autotoc_md547", null ]
    ] ],
    [ "engine — native-TPC control plane (destination side)", "md_src_2tpc_2engine_2README.html", [
      [ "Overview", "md_src_2tpc_2engine_2README.html#autotoc_md549", null ],
      [ "Files", "md_src_2tpc_2engine_2README.html#autotoc_md550", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2engine_2README.html#autotoc_md551", null ],
      [ "See also", "md_src_2tpc_2engine_2README.html#autotoc_md552", null ]
    ] ],
    [ "gsi — outbound GSI authentication for the TPC pull socket", "md_src_2tpc_2gsi_2README.html", [
      [ "Overview", "md_src_2tpc_2gsi_2README.html#autotoc_md554", null ],
      [ "Files", "md_src_2tpc_2gsi_2README.html#autotoc_md555", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2gsi_2README.html#autotoc_md556", null ],
      [ "See also", "md_src_2tpc_2gsi_2README.html#autotoc_md557", null ]
    ] ],
    [ "outbound — the blocking source-session client for native TPC pulls", "md_src_2tpc_2outbound_2README.html", [
      [ "Overview", "md_src_2tpc_2outbound_2README.html#autotoc_md559", null ],
      [ "Files", "md_src_2tpc_2outbound_2README.html#autotoc_md560", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2outbound_2README.html#autotoc_md561", null ],
      [ "See also", "md_src_2tpc_2outbound_2README.html#autotoc_md562", null ]
    ] ],
    [ "tpc — Native XRootD third-party-copy (destination-side pull)", "md_src_2tpc_2README.html", [
      [ "Overview", "md_src_2tpc_2README.html#autotoc_md564", null ],
      [ "Files", "md_src_2tpc_2README.html#autotoc_md565", null ],
      [ "Key types & data structures", "md_src_2tpc_2README.html#autotoc_md566", null ],
      [ "Control & data flow", "md_src_2tpc_2README.html#autotoc_md567", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2README.html#autotoc_md568", null ],
      [ "Entry points / extending", "md_src_2tpc_2README.html#autotoc_md569", null ],
      [ "See also", "md_src_2tpc_2README.html#autotoc_md570", null ]
    ] ],
    [ "<tt>client/apps/</tt> — native client CLI tools", "md_client_2apps_2README.html", [
      [ "Data movement", "md_client_2apps_2README.html#autotoc_md572", null ],
      [ "Checksums & verification", "md_client_2apps_2README.html#autotoc_md573", null ],
      [ "Diagnostics & monitoring", "md_client_2apps_2README.html#autotoc_md574", null ],
      [ "Auth & security", "md_client_2apps_2README.html#autotoc_md575", null ],
      [ "Namespace / staging", "md_client_2apps_2README.html#autotoc_md576", null ],
      [ "Optional (built only when <tt>libfuse3</tt> is present — not in <tt>BINS</tt>)", "md_client_2apps_2README.html#autotoc_md577", null ],
      [ "Ceph operator tools (<tt>apps/ceph/</tt> — built only when the Ceph dev headers are present)", "md_client_2apps_2README.html#autotoc_md578", null ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2apps_2README.html#autotoc_md579", null ],
      [ "Man pages & bash completion", "md_client_2apps_2README.html#autotoc_md580", null ],
      [ "CLI compatibility contract (binding for all flag/env/output work)", "md_client_2apps_2README.html#autotoc_md581", null ],
      [ "See also", "md_client_2apps_2README.html#autotoc_md582", null ]
    ] ],
    [ "<tt>client/lib/sec/</tt> — native client authentication modules", "md_client_2lib_2auth_2sec_2README.html", [
      [ "Overview", "md_client_2lib_2auth_2sec_2README.html#autotoc_md584", null ],
      [ "Files", "md_client_2lib_2auth_2sec_2README.html#autotoc_md585", null ],
      [ "Invariants", "md_client_2lib_2auth_2sec_2README.html#autotoc_md586", null ],
      [ "See also", "md_client_2lib_2auth_2sec_2README.html#autotoc_md587", null ]
    ] ],
    [ "<tt>client/lib/</tt> — native XRootD client library (<tt>libbrix</tt>)", "md_client_2lib_2README.html", [
      [ "Concept buckets (phase-69)", "md_client_2lib_2README.html#autotoc_md589", null ],
      [ "File responsibilities (Phase-38 split groups)", "md_client_2lib_2README.html#autotoc_md590", null ]
    ] ],
    [ "<tt>client/preload/</tt> — LD_PRELOAD POSIX → XRootD shim", "md_client_2preload_2README.html", [
      [ "Overview", "md_client_2preload_2README.html#autotoc_md592", null ],
      [ "How it works", "md_client_2preload_2README.html#autotoc_md593", null ],
      [ "Scope", "md_client_2preload_2README.html#autotoc_md594", null ],
      [ "Files", "md_client_2preload_2README.html#autotoc_md595", null ],
      [ "See also", "md_client_2preload_2README.html#autotoc_md596", null ]
    ] ],
    [ "<tt>client/</tt> — native BriX client tools", "md_client_2README.html", [
      [ "Directory layout", "md_client_2README.html#autotoc_md598", null ],
      [ "Build", "md_client_2README.html#autotoc_md599", null ],
      [ "Feature summary (2026-07-05)", "md_client_2README.html#autotoc_md600", [
        [ "xrdcp", "md_client_2README.html#autotoc_md601", null ],
        [ "xrdfs", "md_client_2README.html#autotoc_md602", null ],
        [ "xrdcksum", "md_client_2README.html#autotoc_md603", null ],
        [ "xrddiag", "md_client_2README.html#autotoc_md604", null ],
        [ "Ceph operator tools", "md_client_2README.html#autotoc_md605", null ]
      ] ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2README.html#autotoc_md606", null ],
      [ "Man pages & bash completion", "md_client_2README.html#autotoc_md607", null ],
      [ "See also", "md_client_2README.html#autotoc_md608", null ]
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
"authfile__internal_8h.html#a696af52ab3811b12daba35bc89b21685",
"brix__net_8h.html#a9aef7ed10b3d5b7ed01e2af806e4606b",
"brixcvmfs__rw_8c.html#a402165799cfaa4cb151c466f6705dde1",
"buffers__internal_8h.html#aa053ef1efef8909f691a067bb5d2e01b",
"cephfs__layout_8h.html",
"cinfo__l1_8c.html#adbdd09646b5200cf3e5771a444210439",
"client_8c.html#a1583ff660afb481526fa3fc5b8bcc5a1",
"codec__lz4_8c.html",
"copy__internal_8h.html#a08fc786ed54e4f4a0caa02e637c56cdd",
"core_2config_2policy_8c.html#abcefa95fc39e67a159d6907090facbde",
"crypto_8h_source.html",
"cta__service_8h_source.html",
"dashboard__http_8h.html#a8f418326c7d525c5f1a438634b2440a3",
"diag__internal_8h.html#a66fbe8fcb6c98ecd1a9f4552856b4e12",
"dirlist_8c.html",
"ext__ops_8h.html#ae3f7d5979afb94f753fde8acd209f86a",
"flags_8h.html#af1e52e7a5bc07ab7cb307185c5868c59",
"fs_2path_2path_8h.html#abcbfa58a543ee47700c33cc88c03beee",
"globals_defs_j.html",
"gsi__core__cresp_8c.html#a504985d9b0a54ea72ed2bc6174e1ad9c",
"handshake_8h.html#a0b41c1c3a730ceea98a83b1100e18f56",
"http__file__response_8h.html#ab97f902d76728d415c895e3e65276dbb",
"identity_8h.html#a969d73f2e7d975ccacff0052ec73a41d",
"issuer__registry_8c.html#a67350f002015de73679ae61d53ac2a04",
"lifecycle__broker_8c.html#a6e40e908e08683c7e3551beb67cc3a4f",
"macaroon__issue_8c.html#a08a9fa1b84190e338d0fa39bcbc079ee",
"md_src_2fs_2README.html#autotoc_md185",
"md_src_2protocols_2root_2response_2README.html#autotoc_md391",
"metadata_8c.html#afada799ea666bb97b3ccbe3a646ef00d",
"module__acc__directives_8c.html#a641a7f34c170391489f20507b9ca006c",
"net_2cms_2connect_8c.html#a90ce1ed8b63e053286a655f7c286dd6b",
"netconnect_8h.html#adb0a148a8187f41e65bcef03d9834ef0ad9bde46458b4359ba9e314110891302b",
"observability_2dashboard_2noop_8c.html#a4e9fbc4f6d996396b56e5249b314a80a",
"op__path_8c.html#a8e80ad16299eac221abaff6a04bda92d",
"open__tpc_8c.html#a2a8fcafd62179eb06357d746d629c3cd",
"overlay_8h.html#a899c302da8c704cfb1b6751bdfa78d88",
"pgio_8h.html#aebfa7de39e896caf9d0abefe52a6e787",
"prepare_8c.html#aae38f70db65c3bc083d02eb8fab735ed",
"protocol__caps_8h_source.html",
"protocols_2s3_2module_8c.html#acea91af943c62ace1cb2bec12d94dab9",
"proxy__pool_8c_source.html",
"range__vector_8c.html#adcab9fc0d17fb62edc5f7ddaa83095bb",
"refresh_8c.html#a5fb3b244d3965a2035e9d72e5ec7761e",
"root_2fattr_2dispatch_8c.html#a96f5d1bc80a0ec5e57fe67a3d4481b69",
"s3_8h.html#a942cdb2e7943b0680d3183f43fd513d5",
"scan__engine__catalog_8c.html#ae0dfab515f501699fd91ca42b9c2f8ef",
"sd__cache__forward_8c.html#a5baf07f412c5350db587a7a71b39fe10",
"sd__http__internal_8h.html#a93110c9d0c55ad0f6af6a13ed43edb07",
"sd__posix__io_8c.html#ac516fb2dc5ed1106d59a59e53b21da3b",
"sd__xroot__internal_8h.html#a8f52a65bb59c6ef5115c4485474189b1",
"server__handler_8c.html#acc8f9bca4574fa8ac152c4abc13739a4",
"sesslog__ngx_8h.html#a33d3cff15ddb8b93d133df5527d5eb18",
"src_2core_2aio_2uring_8h.html",
"ssi__dispatch_8c.html#ac1c57d7a88949574a0d2970633a56b9c",
"stage__engine__scheduler_8c.html#ab0c65aad58f37fd81b6b2f5a229223e9",
"storascan__core_8c.html#a1fbd0afea59d9ca4e0aadce580a085d1",
"stream__wmirror__state_8c.html#a41350a5053de15c6c1a35c28a44f4fdb",
"structClientSyncRequest.html#aa7728c86067e80e8c07acb50a7696889",
"structbrix__acc__http__t.html#a09566e791b15c9403fe7459d50595029",
"structbrix__cache__dirlist__t.html#a0595374e0ea28258fbd6155f30485da0",
"structbrix__cms__srv__ctx__t.html#ae94ea08c41bc6b69417e1b335586c971",
"structbrix__ctx__rd__t.html#a89e1801ba51172930ba20b0c0bb0a541",
"structbrix__dirlist__walk__t.html#addfe088700275181445faf9646ee3423",
"structbrix__http__cache__fill__ctx__t.html#a127652ced750d67a89512ebe2c5665e8",
"structbrix__mgr.html#ac1e84053952004d219a962d01f903cf7",
"structbrix__pgread__run__t.html#a35528bb4510b638d2e81338421ddb06d",
"structbrix__qcksum__req__t.html",
"structbrix__scan__tb__t.html#aca7364f607c6b8350bd04fdecb68971a",
"structbrix__shared__handle__entry__t.html#aec676faf766ac2f4b8e7fb3461978045",
"structbrix__stream__mirror__t.html#a4ca781b3700d54ee9f5a5a5dc3889cb6",
"structbrix__tpc__registry__entry__t.html#acf65abd7606c8c65f4766cd63985cfbf",
"structbrix__vfs__job__t.html#aca3ef6464ab909997bb129b3c4decc11",
"structbrix__xfer__audit__t.html#a0f4f50b17d96a6938d8f539a9eeed612",
"structckscan__walk__ctx__t.html#a3803ffcb2f364a4b7bc73b57fe7c0827",
"structcvmfs__probe__ctx__t.html#ac6225475c2a80da6db8b492d69e93d34",
"structfix__t.html#a1dd524ebd74245926bfeb92352b2fffa",
"structkxr__name__entry__t.html#a9b7b0bee9a59a5cc35211f0df4c265f6",
"structngx__brix__frm__metrics__t.html#a8b5e4f9d2fbb15c5ea2fb2cca045ae75",
"structngx__http__brix__dashboard__loc__conf__t.html#aea19401376d9449ecc7dbe08e7c5808b",
"structngx__http__s3__req__ctx__t.html#aad5efe1e62d5a2112185602ea0334e08",
"structreap__ctx__t.html#ae59f6bc89ad96650f72bfdcfd2db96c8",
"structs3__upcp__req__t.html#a841dcf568ed64e8e2fbed86fe2da6661",
"structsd__s3__meta__buf.html",
"structstorascan__bench__result.html#acfc9081cbad36ba379b28c9cd6b712c8",
"structvfs__copy__ctx__t.html#a9b6e8ddeec420228ae85b4d616ba9170",
"structwebdav__tpc__curl__ctx__t.html",
"structxrdcp__lists__t.html#a2f513f7abe5fe1ddd6ccbd8fff9324aa",
"structzw__entry.html#a5991b72c6c287cf39317becb8aeffd55",
"tier_8h.html#ae91c616eaa52d1722aa891a5d82bcc0a",
"tpc__cred_8h.html#a60b3cd37ef95e1b184ff6ae6c1867ba5a200076e08d0587df69abaccb0b962cfd",
"tracking_8c.html#a684f308c4b22da5c661a8abf716404ac",
"upstream__internal_8h.html#af75c2d80dc459083e9c83b3d84b19239",
"vfs__backend__registry__source_8c.html",
"vfs__ops_8h.html#a2f5aba8e586f9329840a080e48023449",
"webdav_8c.html#a2182f5192f6915f630c01c1aaa2714f8",
"wire__codec_8h.html#a104744206f046f65952e735441237b17",
"writethrough__decision_8h.html#a1a3d5ce6e9eee946d1bce6241b3ffe38a96595d35011be16084cbea1f94c49bbe",
"xmeta__internal_8h.html#a578c95b4691f9e6ea07c160adc2973e5",
"xrdcksum_8c.html#a520225720ba4e6b9f31c3d78bda00729",
"xrdfs__data_8c.html#a7986f5ec35a7af689ac6fa7eb1fedb12",
"xrdhttp__filter_8c.html#a4fd8b60b870caa27fd92cf153044f04f",
"xrootdfs__internal_8h.html#a3acaaba7612baa1ae598aa151884c9b4",
"zip__dir__unittest_8c_source.html"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';