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
"brix__fault__proxy_8c.html#a73f3f7b6803f3263b3673503e26fac49",
"brix__ops_8h.html#ae806b2c0cd9c07925a196b14bc97299b",
"brixcvmfs__rw_8c.html#adc77665179ecbd39f435dd19c7e7211a",
"cache__admit_8h.html#ada93982f9cdf1874f4195c300cbd5e12",
"checksum_8h.html",
"cks__verify_8c.html#af273a8763b1d83fc643d0ea5644ceb53",
"client_8c_source.html",
"conditional_8c.html#aa1f1d1fc32fdad2c06521a215876a226",
"copy__internal_8h.html#aa163c6a61e7677b55288fdde66607a51",
"cpool__unittest_8c.html#a4317f539a1b85be8116490a7d97c3c1a",
"crypto_8c.html#ae5e200e57096d3437d4d96d7c3e27021",
"cta__service_8c.html#a16f9c1705fc5e5ce7c73e8f47a81fe9e",
"dashboard__auth__login_8c.html#a6640fefb45c4d12eda161d8152fc6d4e",
"diag__internal_8h.html#a2f1d2429b693de1aa29fbd3e7ed03413",
"dir_ce3aa255f0d0e2a628573fc3b1b82afb.html",
"exchange_8c.html#a237badbc569499673fda7d232b145b5a",
"flags_8h.html#a89762a5bbb327d75144fe9154294e9f7",
"fs_2path_2mkdir_8c.html#a0c732669ff6299f4df782dd35555366d",
"ftp__ev__dispatch_8c.html#a3e08f0a48aee5aa97b39a5f4c7affa17",
"glob_8c.html#a3bf28e24574a8ddd968f4110791655f5",
"gsi__core_8h.html#a793799f3d9604d87af6087c4d99c9160",
"guard__ruleset_8c.html#afb0f859adb923aaece19313afdf6c9ae",
"http__common_8c.html#a751f992e7fd71272d10fe5d977f24c32",
"http__tracking_8c.html#a69839bf975d5f7a64e68bc0c02b3568d",
"ini__unittest_8c.html#ae66e6e9d27b058b63231939015d5bfc9",
"kv_8h.html#af8e8d5e94a19337005a4f507db0a1ef4",
"log_8c_source.html",
"md_src_2auth_2impersonate_2README.html",
"md_src_2observability_2README.html",
"md_src_2tpc_2README.html#autotoc_md574",
"metrics__macros_8h.html#a3446760b3448af56bde25407e0db37ec",
"module__enums_8h.html#a41de5be27f54cf3e3bbb53214e1f0ce5",
"net_2httpguard_2module_8c.html#afee0a951fd6ac38f86682e547cb854d7",
"ngx__brix__module_8h.html#abee79be17182f2c4faa2e70cba35fa81",
"observability_2metrics_2module_8c.html#a68bc07f9beef4ace5545bd2b7a40760f",
"opcodes_8h.html#a615a80889a06b571df4f61a7f61853c6",
"ops__internal_8h.html",
"parse_8c.html#ac8ff94c29aeb1e4496326c1f9217d4a9",
"pblock__store_8h.html#ab1c1372dee836272f1bba01b4184452a",
"post__object_8c_source.html",
"propfind__internal_8h.html#a3877e53ad66658431e161b0bbcd2ab04",
"protocols_2root_2session_2lifecycle_8c.html#a1efc7f7d4518d556a8e200b9280c8c6e",
"protocols_2webdav_2metrics_8c.html#a516fbf197fed2ba7c96a762ed5568d2b",
"put__body_8c.html#aba610e7c820964b99764ae853f488905",
"ratelimit__keys__rules_8c.html#a87a110a01956579938699fb06b59f98a",
"relay__guard_8h.html#a892b31dbb076e59e1bcb54dcffcff63c",
"router_8c.html",
"s3__ops_8h.html",
"scan__record_8h.html#af3f4a23a2c78f0c55ae1807a2d3fd56b",
"sd__cache__internal_8h.html#a59e0ea7ca6775e7df2d8206cae1a1576",
"sd__http__internal_8h.html#aba3341b0a9d1dc3361411cacf65dfd08",
"sd__pblock__unittest_8c.html#ac73a89a99e2664a4d89d08186a833576",
"sd__stage_8c.html#abbd7e2658a77a2b50bf0a575394b7c21",
"sec__unix_8c.html#aca02d519599b297a5857be97e4b9a338",
"session__unittest_8c.html#aba1590ff86288c886c47dc8a27b30467",
"signing__policy_8h.html#a20df7abb9f755709f4159584151aa50aadf2071f9ac2df458331743768feec504",
"src_2fs_2vfs_2vfs_8h.html#a959e44f8f8dd57fdbd37519e9a7772bb",
"ssi__service_8h.html#af7611b03962cc390b0d52d0c2fc699d9",
"stage__request__registry__internal_8h.html#a418b9e1f43d3d423ffaa85603d9f3ee0",
"store__policy__conformance_8c.html#ae1e7f1391a42c04d6b6b1630fc4c0655",
"structClientEndsessRequest.html#ac57fc5c5410f4f036e4f81253f66e880",
"structServerStatusResponse__pgWrite.html#aaab32398742733808a6e58dac6838c02",
"structbrix__acc__tables__t.html#a3aca6abb9d9d6807d3ac84449988de2b",
"structbrix__cache__fill__t.html#a5dabfe93816ab9434ce261a77756a223",
"structbrix__cms__srv__ctx__t.html#a72cad6e111f3d40fadb551892dbd6194",
"structbrix__ctx__pmark__t.html#a63c1af5a6c3ee7eeaa7c8b018dec3f1c",
"structbrix__dig__export__t.html",
"structbrix__gssapi__srv__s.html#af73a4ede4b7dc59848a9cacf74c92c3d",
"structbrix__kxr__errno__entry__t.html#a0f85d4430596626181a786d8ea3a805d",
"structbrix__opts.html",
"structbrix__proxy__be__snapshot__t.html",
"structbrix__resp__slot__t.html#a3e2748839e98e38634f95718d4a206a6",
"structbrix__sd__remote__cfg__t.html#aa089d137ca11a20bb1e4c85bc3aa7ebb",
"structbrix__ssi__respbuf__t.html",
"structbrix__token__claims__t.html#aedea0472b9bff6c66957edb31a787ed8",
"structbrix__vfs__adopt__attrs__t.html#a98b7dd33b119d1cfd35b015a1157c483",
"structbrix__webfile.html#a6754d76d4691e4cbda55cbc5377cb361",
"structbrix__zip__entry.html#ab66a80a1c355d8abea4a7486c350bd23",
"structcodec__ctx__t.html#a0b7d8f1066bd01c153703ef45b23401a",
"structdiag__args.html#accdcd28c18462c4ecc6dd2dee2016fc3",
"structftp__ev__t.html#a6bfbcf625c4eeb221570575948f674b7",
"structimp__stat__t.html#afe69b9341e1e75cbaaa83afdc7f02e5a",
"structngx__brix__cvmfs__repo__metrics__t.html#abae8c6a5d19f31019cdaba7be5ffd9b9",
"structngx__http__brix__cvmfs__ctx__t.html#ab8901bdb9489aaba6e783e401514fb3e",
"structngx__http__brix__webdav__tls__auth__cache__t.html#af398f7976a1b722474c6f5ed7cb48e62",
"structplace__ctx__t.html#a56b2caf64215e85577b7b59e2de73fb7",
"structs3__chunk__ctx__t.html#aaa96beb456cfe9c59f69fd6937142952",
"structscan__verify__obj__ctx__t.html#a5cab10050d714c7d919d780166789842",
"structsd__xroot__origin__open__req__t.html#a55b1110cafdf763cd4c4a8b78fd6a502",
"structtokenauth__state__t.html#a632023942246083d840aac900396edfb",
"structvoms__entry.html#aefcf616990d0decf03dcda969a521b3f",
"structweblist__acc__t.html#aab5c4c067d4706fa560a5137d32a8ecf",
"structxrdp__setattr__t.html",
"tagging_8c.html#a63fd5e8fddc1c58684c9e65cebf7393f",
"token_8c.html",
"tpc__headers_8c.html#a8f0ef42f257d0e4e80bc3b977cf10b77",
"tunables_8h.html#a82cc2f363f38d700babd057edb37e814",
"validate_8c.html#a5fd66fdf922456273823ee70947fb942",
"vfs__core__unittest_8c.html#a840291bc02cba5474a4cb46a9b9566fe",
"vfs__s3_8c.html#aa15dafcfec5177ea8bd2043d46fc53c7",
"webdav_8h.html#a221b5a93b07534609671dbac0f0d19c7",
"wire__codec_8h.html#a303cddd69c9fc6f6fc99a232dc7481df",
"writethrough__metrics_8h.html#ab1cff404de3c168debe17828f2393afe",
"xmeta__internal_8h.html",
"xrdcksum_8c.html#a3c04138a5bfe5d72780bb7e82a18e627",
"xrdfs__data_8c.html#a704256c15be1129f4c98dceb93e67fa9",
"xrdhttp__filter_8c.html",
"xrootdfs__internal_8h.html#a21b5a906962d323015131d83ebf47bb7",
"zip__dir_8h.html#adb92f8bca6ed995fb1e3a8c980665fa7"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';