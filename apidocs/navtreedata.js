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
      [ "Files", "md_src_2auth_2authz_2README.html#autotoc_md6", [
        [ "Other files", "md_src_2auth_2authz_2README.html#autotoc_md7", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2auth_2authz_2README.html#autotoc_md8", null ],
      [ "See also", "md_src_2auth_2authz_2README.html#autotoc_md9", null ]
    ] ],
    [ "crypto — shared OpenSSL X.509 / PKI core for GSI and WebDAV certificate auth", "md_src_2auth_2crypto_2README.html", [
      [ "Overview", "md_src_2auth_2crypto_2README.html#autotoc_md11", null ],
      [ "Files", "md_src_2auth_2crypto_2README.html#autotoc_md12", [
        [ "Other files", "md_src_2auth_2crypto_2README.html#autotoc_md13", null ]
      ] ],
      [ "Key types & data structures", "md_src_2auth_2crypto_2README.html#autotoc_md14", null ],
      [ "Control & data flow", "md_src_2auth_2crypto_2README.html#autotoc_md15", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2crypto_2README.html#autotoc_md16", null ],
      [ "Entry points / extending", "md_src_2auth_2crypto_2README.html#autotoc_md17", null ],
      [ "See also", "md_src_2auth_2crypto_2README.html#autotoc_md18", null ]
    ] ],
    [ "gsi — XRootD <tt>kXR_auth</tt> dispatcher and GSI/x509 proxy-certificate authentication", "md_src_2auth_2gsi_2README.html", [
      [ "Overview", "md_src_2auth_2gsi_2README.html#autotoc_md20", null ],
      [ "Files", "md_src_2auth_2gsi_2README.html#autotoc_md21", [
        [ "Other files", "md_src_2auth_2gsi_2README.html#autotoc_md22", null ]
      ] ],
      [ "Key types & data structures", "md_src_2auth_2gsi_2README.html#autotoc_md23", null ],
      [ "Control & data flow", "md_src_2auth_2gsi_2README.html#autotoc_md24", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2gsi_2README.html#autotoc_md25", null ],
      [ "Entry points / extending", "md_src_2auth_2gsi_2README.html#autotoc_md26", null ],
      [ "See also", "md_src_2auth_2gsi_2README.html#autotoc_md27", null ]
    ] ],
    [ "GSI GSSAPI Accept Engine", "md_src_2auth_2gssapi_2README.html", null ],
    [ "host — host-based authentication for the <tt>root://</tt> stream protocol", "md_src_2auth_2host_2README.html", [
      [ "Overview", "md_src_2auth_2host_2README.html#autotoc_md30", null ],
      [ "Files", "md_src_2auth_2host_2README.html#autotoc_md31", null ]
    ] ],
    [ "<tt>src/auth/impersonate/</tt> — per-request UNIX impersonation (phase 40)", "md_src_2auth_2impersonate_2README.html", [
      [ "Operating modes (<tt>brix_idmap off|single|map</tt>)", "md_src_2auth_2impersonate_2README.html#autotoc_md33", null ],
      [ "Architecture", "md_src_2auth_2impersonate_2README.html#autotoc_md34", null ],
      [ "Files", "md_src_2auth_2impersonate_2README.html#autotoc_md35", null ],
      [ "How a request routes through it", "md_src_2auth_2impersonate_2README.html#autotoc_md36", null ],
      [ "Safety invariants", "md_src_2auth_2impersonate_2README.html#autotoc_md37", null ],
      [ "Tests", "md_src_2auth_2impersonate_2README.html#autotoc_md38", [
        [ "Other files", "md_src_2auth_2impersonate_2README.html#autotoc_md39", null ]
      ] ]
    ] ],
    [ "krb5 — Kerberos 5 authentication for the <tt>root://</tt> stream protocol", "md_src_2auth_2krb5_2README.html", [
      [ "Overview", "md_src_2auth_2krb5_2README.html#autotoc_md41", null ],
      [ "Files", "md_src_2auth_2krb5_2README.html#autotoc_md42", [
        [ "Forwarded-TGT delegation (EXCHANGE path — phase-70 §5.7)", "md_src_2auth_2krb5_2README.html#autotoc_md43", null ],
        [ "Other files", "md_src_2auth_2krb5_2README.html#autotoc_md44", null ]
      ] ],
      [ "Key types & data structures", "md_src_2auth_2krb5_2README.html#autotoc_md45", null ],
      [ "Control & data flow", "md_src_2auth_2krb5_2README.html#autotoc_md46", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2krb5_2README.html#autotoc_md47", null ],
      [ "Entry points / extending", "md_src_2auth_2krb5_2README.html#autotoc_md48", null ],
      [ "See also", "md_src_2auth_2krb5_2README.html#autotoc_md49", null ]
    ] ],
    [ "protbind — per-host authentication-protocol binding (XRootD <tt>sec.protbind</tt>)", "md_src_2auth_2protbind_2README.html", [
      [ "Overview", "md_src_2auth_2protbind_2README.html#autotoc_md51", null ],
      [ "Files", "md_src_2auth_2protbind_2README.html#autotoc_md52", null ]
    ] ],
    [ "pwd — password (<tt>XrdSecpwd</tt>) authentication for the <tt>root://</tt> stream protocol", "md_src_2auth_2pwd_2README.html", [
      [ "Overview", "md_src_2auth_2pwd_2README.html#autotoc_md54", null ],
      [ "The two-round exchange", "md_src_2auth_2pwd_2README.html#autotoc_md55", null ],
      [ "Files", "md_src_2auth_2pwd_2README.html#autotoc_md56", null ]
    ] ],
    [ "auth — identity and authorization", "md_src_2auth_2README.html", null ],
    [ "S3 STS Credential Exchange", "md_src_2auth_2s3_2README.html", null ],
    [ "sss — Simple Shared Secret authentication (Blowfish-CFB64 + CRC32)", "md_src_2auth_2sss_2README.html", [
      [ "Overview", "md_src_2auth_2sss_2README.html#autotoc_md60", null ],
      [ "Files", "md_src_2auth_2sss_2README.html#autotoc_md61", [
        [ "Other files", "md_src_2auth_2sss_2README.html#autotoc_md62", null ]
      ] ],
      [ "Key types & data structures", "md_src_2auth_2sss_2README.html#autotoc_md63", null ],
      [ "Control & data flow", "md_src_2auth_2sss_2README.html#autotoc_md64", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2sss_2README.html#autotoc_md65", null ],
      [ "Entry points / extending", "md_src_2auth_2sss_2README.html#autotoc_md66", null ],
      [ "See also", "md_src_2auth_2sss_2README.html#autotoc_md67", null ]
    ] ],
    [ "token — WLCG/SciToken JWT and macaroon bearer-token validation", "md_src_2auth_2token_2README.html", [
      [ "Overview", "md_src_2auth_2token_2README.html#autotoc_md69", null ],
      [ "Files", "md_src_2auth_2token_2README.html#autotoc_md70", [
        [ "Other files", "md_src_2auth_2token_2README.html#autotoc_md71", null ]
      ] ],
      [ "Key types & data structures", "md_src_2auth_2token_2README.html#autotoc_md72", null ],
      [ "Control & data flow", "md_src_2auth_2token_2README.html#autotoc_md73", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2token_2README.html#autotoc_md74", null ],
      [ "Entry points / extending", "md_src_2auth_2token_2README.html#autotoc_md75", null ],
      [ "See also", "md_src_2auth_2token_2README.html#autotoc_md76", null ]
    ] ],
    [ "unix — XRootD <tt>unix</tt> (UNIX-name) authentication handler", "md_src_2auth_2unix_2README.html", [
      [ "Overview", "md_src_2auth_2unix_2README.html#autotoc_md78", null ],
      [ "Files", "md_src_2auth_2unix_2README.html#autotoc_md79", null ],
      [ "Key types & data structures", "md_src_2auth_2unix_2README.html#autotoc_md80", null ],
      [ "Control & data flow", "md_src_2auth_2unix_2README.html#autotoc_md81", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2unix_2README.html#autotoc_md82", null ],
      [ "Entry points / extending", "md_src_2auth_2unix_2README.html#autotoc_md83", null ],
      [ "See also", "md_src_2auth_2unix_2README.html#autotoc_md84", null ]
    ] ],
    [ "voms — Optional VOMS virtual-organisation extraction from X.509 proxies", "md_src_2auth_2voms_2README.html", [
      [ "Overview", "md_src_2auth_2voms_2README.html#autotoc_md86", null ],
      [ "Files", "md_src_2auth_2voms_2README.html#autotoc_md87", [
        [ "Other files", "md_src_2auth_2voms_2README.html#autotoc_md88", null ]
      ] ],
      [ "Key types & data structures", "md_src_2auth_2voms_2README.html#autotoc_md89", null ],
      [ "Control & data flow", "md_src_2auth_2voms_2README.html#autotoc_md90", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2voms_2README.html#autotoc_md91", null ],
      [ "Entry points / extending", "md_src_2auth_2voms_2README.html#autotoc_md92", null ],
      [ "See also", "md_src_2auth_2voms_2README.html#autotoc_md93", null ]
    ] ],
    [ "aio — Thread-pool async file I/O and shared response-chain builders", "md_src_2core_2aio_2README.html", [
      [ "Overview", "md_src_2core_2aio_2README.html#autotoc_md95", null ],
      [ "Optional io_uring backend (Phase 44 — <tt>uring.c</tt> / <tt>uring_submit.c</tt> / <tt>uring_admin.c</tt>)", "md_src_2core_2aio_2README.html#autotoc_md96", null ],
      [ "Thread-pool contract", "md_src_2core_2aio_2README.html#autotoc_md97", null ],
      [ "Files", "md_src_2core_2aio_2README.html#autotoc_md98", [
        [ "Other files", "md_src_2core_2aio_2README.html#autotoc_md99", null ]
      ] ],
      [ "Key types & data structures", "md_src_2core_2aio_2README.html#autotoc_md100", null ],
      [ "Control & data flow", "md_src_2core_2aio_2README.html#autotoc_md101", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2aio_2README.html#autotoc_md102", null ],
      [ "Entry points / extending", "md_src_2core_2aio_2README.html#autotoc_md103", null ],
      [ "See also", "md_src_2core_2aio_2README.html#autotoc_md104", null ]
    ] ],
    [ "compat — Cross-protocol shared primitives (checksums, paths, filesystem, SSRF)", "md_src_2core_2compat_2README.html", [
      [ "Overview", "md_src_2core_2compat_2README.html#autotoc_md106", null ],
      [ "Files", "md_src_2core_2compat_2README.html#autotoc_md107", [
        [ "Checksums & hex", "md_src_2core_2compat_2README.html#autotoc_md108", null ],
        [ "HTTP-adjacent primitives", "md_src_2core_2compat_2README.html#autotoc_md109", null ],
        [ "Filesystem & namespace mutation", "md_src_2core_2compat_2README.html#autotoc_md110", null ],
        [ "Networking, async, time, logging, SHM", "md_src_2core_2compat_2README.html#autotoc_md111", null ],
        [ "Other files", "md_src_2core_2compat_2README.html#autotoc_md112", null ]
      ] ],
      [ "Key types & data structures", "md_src_2core_2compat_2README.html#autotoc_md113", null ],
      [ "Control & data flow", "md_src_2core_2compat_2README.html#autotoc_md114", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2compat_2README.html#autotoc_md115", null ],
      [ "Entry points / extending", "md_src_2core_2compat_2README.html#autotoc_md116", null ],
      [ "See also", "md_src_2core_2compat_2README.html#autotoc_md117", null ]
    ] ],
    [ "config — directive lifecycle, startup validation, and per-worker resource init", "md_src_2core_2config_2README.html", [
      [ "Overview", "md_src_2core_2config_2README.html#autotoc_md119", null ],
      [ "Files", "md_src_2core_2config_2README.html#autotoc_md120", [
        [ "Other files", "md_src_2core_2config_2README.html#autotoc_md121", null ]
      ] ],
      [ "Key types & data structures", "md_src_2core_2config_2README.html#autotoc_md122", null ],
      [ "Control & data flow", "md_src_2core_2config_2README.html#autotoc_md123", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2config_2README.html#autotoc_md124", null ],
      [ "Entry points / extending", "md_src_2core_2config_2README.html#autotoc_md125", null ],
      [ "See also", "md_src_2core_2config_2README.html#autotoc_md126", null ]
    ] ],
    [ "http — Shared HTTP request/response semantics (headers, body, conditionals, ETag)", "md_src_2core_2http_2README.html", [
      [ "Overview", "md_src_2core_2http_2README.html#autotoc_md128", null ],
      [ "Files", "md_src_2core_2http_2README.html#autotoc_md129", null ],
      [ "Boundary — what stays in <tt>../compat</tt>", "md_src_2core_2http_2README.html#autotoc_md130", [
        [ "Other files", "md_src_2core_2http_2README.html#autotoc_md131", null ]
      ] ],
      [ "Control & data flow", "md_src_2core_2http_2README.html#autotoc_md132", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2http_2README.html#autotoc_md133", null ],
      [ "Entry points / extending", "md_src_2core_2http_2README.html#autotoc_md134", null ],
      [ "See also", "md_src_2core_2http_2README.html#autotoc_md135", null ]
    ] ],
    [ "Negative-Path Backoff (negcache)", "md_src_2core_2negcache_2README.html", null ],
    [ "core — platform primitives shared by every plane", "md_src_2core_2README.html", null ],
    [ "Worker seccomp-BPF Syscall Filter", "md_src_2core_2seccomp_2README.html", null ],
    [ "shm — generic cross-worker key/value store and token-bucket rate limiter in nginx shared memory", "md_src_2core_2shm_2README.html", [
      [ "Overview", "md_src_2core_2shm_2README.html#autotoc_md141", null ],
      [ "Files", "md_src_2core_2shm_2README.html#autotoc_md142", [
        [ "Other files", "md_src_2core_2shm_2README.html#autotoc_md143", null ]
      ] ],
      [ "Key types & data structures", "md_src_2core_2shm_2README.html#autotoc_md144", null ],
      [ "Control & data flow", "md_src_2core_2shm_2README.html#autotoc_md145", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2shm_2README.html#autotoc_md146", null ],
      [ "Entry points / extending", "md_src_2core_2shm_2README.html#autotoc_md147", null ],
      [ "See also", "md_src_2core_2shm_2README.html#autotoc_md148", null ]
    ] ],
    [ "src/core/types — Core type definitions, tunables, and the canonical identity object", "md_src_2core_2types_2README.html", [
      [ "Overview", "md_src_2core_2types_2README.html#autotoc_md150", null ],
      [ "Files", "md_src_2core_2types_2README.html#autotoc_md151", null ],
      [ "Key types & data structures", "md_src_2core_2types_2README.html#autotoc_md152", null ],
      [ "Control & data flow", "md_src_2core_2types_2README.html#autotoc_md153", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2types_2README.html#autotoc_md154", null ],
      [ "Entry points / extending", "md_src_2core_2types_2README.html#autotoc_md155", null ],
      [ "See also", "md_src_2core_2types_2README.html#autotoc_md156", null ]
    ] ],
    [ "<tt>src/fs/backend/gsiftp/</tt> — outbound <tt>gsiftp://</tt> storage driver", "md_src_2fs_2backend_2gsiftp_2README.html", [
      [ "Seam", "md_src_2fs_2backend_2gsiftp_2README.html#autotoc_md158", null ],
      [ "Module map", "md_src_2fs_2backend_2gsiftp_2README.html#autotoc_md159", null ]
    ] ],
    [ "fs/backend — Storage Driver (SD) layer", "md_src_2fs_2backend_2README.html", [
      [ "Status — POSIX driver mediates the VFS handle data plane + lifecycle", "md_src_2fs_2backend_2README.html#autotoc_md161", null ],
      [ "Layout — one subdirectory per driver", "md_src_2fs_2backend_2README.html#autotoc_md162", null ],
      [ "Files", "md_src_2fs_2backend_2README.html#autotoc_md163", null ],
      [ "Contract", "md_src_2fs_2backend_2README.html#autotoc_md164", null ],
      [ "Adding a driver", "md_src_2fs_2backend_2README.html#autotoc_md165", [
        [ "Other files", "md_src_2fs_2backend_2README.html#autotoc_md166", null ]
      ] ],
      [ "See also", "md_src_2fs_2backend_2README.html#autotoc_md167", null ]
    ] ],
    [ "<tt>src/fs/cache/origin/</tt> — origin transport + Pelican advertisement for the read-through cache", "md_src_2fs_2cache_2origin_2README.html", [
      [ "Overview", "md_src_2fs_2cache_2origin_2README.html#autotoc_md169", null ],
      [ "Files", "md_src_2fs_2cache_2origin_2README.html#autotoc_md170", null ],
      [ "Invariants", "md_src_2fs_2cache_2origin_2README.html#autotoc_md171", null ],
      [ "See also", "md_src_2fs_2cache_2origin_2README.html#autotoc_md172", null ]
    ] ],
    [ "<tt>src/fs/cache/</tt> — XCache-style read-through cache and write-through origin mirroring", "md_src_2fs_2cache_2README.html", [
      [ "Overview", "md_src_2fs_2cache_2README.html#autotoc_md174", null ],
      [ "Files", "md_src_2fs_2cache_2README.html#autotoc_md175", [
        [ "Read-through entry points & lifecycle", "md_src_2fs_2cache_2README.html#autotoc_md176", null ],
        [ "Cache store adapter & state (phase-64)", "md_src_2fs_2cache_2README.html#autotoc_md177", null ],
        [ "Origin protocol client (thread-pool, blocking)", "md_src_2fs_2cache_2README.html#autotoc_md178", null ],
        [ "Integrity (checksum-on-fill)", "md_src_2fs_2cache_2README.html#autotoc_md179", null ],
        [ "Cache filesystem bookkeeping", "md_src_2fs_2cache_2README.html#autotoc_md180", null ],
        [ "Eviction", "md_src_2fs_2cache_2README.html#autotoc_md181", null ],
        [ "Unified state engine & parity", "md_src_2fs_2cache_2README.html#autotoc_md182", null ],
        [ "Write-through", "md_src_2fs_2cache_2README.html#autotoc_md183", null ],
        [ "Cache storage on a driver (exclusively-VFS)", "md_src_2fs_2cache_2README.html#autotoc_md184", null ],
        [ "Shared / config / build", "md_src_2fs_2cache_2README.html#autotoc_md185", null ],
        [ "Other files", "md_src_2fs_2cache_2README.html#autotoc_md186", null ]
      ] ],
      [ "Key types & data structures", "md_src_2fs_2cache_2README.html#autotoc_md187", null ],
      [ "Control & data flow", "md_src_2fs_2cache_2README.html#autotoc_md188", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2cache_2README.html#autotoc_md189", null ],
      [ "Entry points / extending", "md_src_2fs_2cache_2README.html#autotoc_md190", null ],
      [ "See also", "md_src_2fs_2cache_2README.html#autotoc_md191", null ]
    ] ],
    [ "src/fs/core — the shared <tt>vfs</tt> I/O verb layer", "md_src_2fs_2core_2README.html", null ],
    [ "meta — unified per-file metadata sidecar (xmeta)", "md_src_2fs_2meta_2README.html", [
      [ "Overview", "md_src_2fs_2meta_2README.html#autotoc_md194", null ],
      [ "Files", "md_src_2fs_2meta_2README.html#autotoc_md195", [
        [ "Other files", "md_src_2fs_2meta_2README.html#autotoc_md196", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2fs_2meta_2README.html#autotoc_md197", null ],
      [ "See also", "md_src_2fs_2meta_2README.html#autotoc_md198", null ]
    ] ],
    [ "path — untrusted-path confinement, resolution, ACL/auth gating, and access logging", "md_src_2fs_2path_2README.html", [
      [ "Overview", "md_src_2fs_2path_2README.html#autotoc_md200", null ],
      [ "Files", "md_src_2fs_2path_2README.html#autotoc_md201", [
        [ "Other files", "md_src_2fs_2path_2README.html#autotoc_md202", null ]
      ] ],
      [ "Key types & data structures", "md_src_2fs_2path_2README.html#autotoc_md203", null ],
      [ "Control & data flow", "md_src_2fs_2path_2README.html#autotoc_md204", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2path_2README.html#autotoc_md205", null ],
      [ "Entry points / extending", "md_src_2fs_2path_2README.html#autotoc_md206", null ],
      [ "See also", "md_src_2fs_2path_2README.html#autotoc_md207", null ]
    ] ],
    [ "fs — Unified VFS: the single POSIX-filesystem data plane", "md_src_2fs_2README.html", [
      [ "Overview", "md_src_2fs_2README.html#autotoc_md209", null ],
      [ "Shared with the userland clients: <tt>module→vfs_server→vfs→backend</tt>", "md_src_2fs_2README.html#autotoc_md210", null ],
      [ "Files", "md_src_2fs_2README.html#autotoc_md211", null ],
      [ "Key types & data structures", "md_src_2fs_2README.html#autotoc_md212", null ],
      [ "Control & data flow", "md_src_2fs_2README.html#autotoc_md213", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2README.html#autotoc_md214", null ],
      [ "The CI seam guard (three tiers)", "md_src_2fs_2README.html#autotoc_md215", null ],
      [ "Entry points / extending", "md_src_2fs_2README.html#autotoc_md216", null ],
      [ "See also", "md_src_2fs_2README.html#autotoc_md217", null ]
    ] ],
    [ "<tt>src/fs/scan/</tt> — bulk storage scan / verify / inventory engine", "md_src_2fs_2scan_2README.html", [
      [ "Layering", "md_src_2fs_2scan_2README.html#autotoc_md219", null ],
      [ "Files", "md_src_2fs_2scan_2README.html#autotoc_md220", null ],
      [ "Endpoint", "md_src_2fs_2scan_2README.html#autotoc_md221", null ],
      [ "Status", "md_src_2fs_2scan_2README.html#autotoc_md222", [
        [ "Other files", "md_src_2fs_2scan_2README.html#autotoc_md223", null ]
      ] ]
    ] ],
    [ "tier — composable storage tiers (cache/stage decorators over backends)", "md_src_2fs_2tier_2README.html", [
      [ "Overview", "md_src_2fs_2tier_2README.html#autotoc_md225", null ],
      [ "Files", "md_src_2fs_2tier_2README.html#autotoc_md226", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2tier_2README.html#autotoc_md227", null ],
      [ "See also", "md_src_2fs_2tier_2README.html#autotoc_md228", null ]
    ] ],
    [ "fs/vfs — the VFS facade (public API + per-op implementations)", "md_src_2fs_2vfs_2README.html", [
      [ "Additional file", "md_src_2fs_2vfs_2README.html#autotoc_md230", [
        [ "Other files", "md_src_2fs_2vfs_2README.html#autotoc_md231", null ]
      ] ]
    ] ],
    [ "<tt>src/fs/xfer/</tt> — unified durable-transfer engine", "md_src_2fs_2xfer_2README.html", [
      [ "Where it sits", "md_src_2fs_2xfer_2README.html#autotoc_md233", null ],
      [ "Files", "md_src_2fs_2xfer_2README.html#autotoc_md234", null ],
      [ "STAGE audit coverage — every upload mode", "md_src_2fs_2xfer_2README.html#autotoc_md235", null ],
      [ "Reload contract (§8b)", "md_src_2fs_2xfer_2README.html#autotoc_md236", [
        [ "The audit line (Phase 2)", "md_src_2fs_2xfer_2README.html#autotoc_md237", null ]
      ] ],
      [ "Durability (spec §7–§8)", "md_src_2fs_2xfer_2README.html#autotoc_md238", [
        [ "Other files", "md_src_2fs_2xfer_2README.html#autotoc_md239", null ]
      ] ]
    ] ],
    [ "admin — the unix control-socket transport shared by every admin plane", "md_src_2net_2admin_2README.html", [
      [ "Overview", "md_src_2net_2admin_2README.html#autotoc_md241", null ],
      [ "Files", "md_src_2net_2admin_2README.html#autotoc_md242", null ],
      [ "The verb-match rule", "md_src_2net_2admin_2README.html#autotoc_md243", null ],
      [ "The reply arena", "md_src_2net_2admin_2README.html#autotoc_md244", null ],
      [ "The privilege boundary, and the audit divergence", "md_src_2net_2admin_2README.html#autotoc_md245", null ],
      [ "Testing", "md_src_2net_2admin_2README.html#autotoc_md246", null ]
    ] ],
    [ "cms — XRootD CMS cluster membership (heartbeat client + manager-side server)", "md_src_2net_2cms_2README.html", [
      [ "Overview", "md_src_2net_2cms_2README.html#autotoc_md248", null ],
      [ "Files", "md_src_2net_2cms_2README.html#autotoc_md249", [
        [ "Heartbeat client (main module)", "md_src_2net_2cms_2README.html#autotoc_md250", null ],
        [ "Shared frame I/O", "md_src_2net_2cms_2README.html#autotoc_md251", null ],
        [ "Manager-side server (<tt>ngx_stream_brix_cms_srv_module</tt>)", "md_src_2net_2cms_2README.html#autotoc_md252", null ],
        [ "Manager namespace/staging planes (phase-89)", "md_src_2net_2cms_2README.html#autotoc_md253", null ],
        [ "Other files", "md_src_2net_2cms_2README.html#autotoc_md254", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2cms_2README.html#autotoc_md255", null ],
      [ "Control & data flow", "md_src_2net_2cms_2README.html#autotoc_md256", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2cms_2README.html#autotoc_md257", null ],
      [ "Entry points / extending", "md_src_2net_2cms_2README.html#autotoc_md258", null ],
      [ "See also", "md_src_2net_2cms_2README.html#autotoc_md259", null ]
    ] ],
    [ "net/dns — runtime DNS (phase 116)", "md_src_2net_2dns_2README.html", null ],
    [ "net/guard — protocol-agnostic bad-actor classifier", "md_src_2net_2guard_2README.html", [
      [ "The <tt>guard_request_t</tt> contract", "md_src_2net_2guard_2README.html#autotoc_md262", null ],
      [ "Audit line (the fail2ban contract)", "md_src_2net_2guard_2README.html#autotoc_md263", null ],
      [ "Wire-level \"not speaking root\" check (<tt>guard_classify_handshake</tt>)", "md_src_2net_2guard_2README.html#autotoc_md264", null ],
      [ "CVMFS forward-proxy abuse check (<tt>signal=proxyabuse</tt>)", "md_src_2net_2guard_2README.html#autotoc_md265", null ],
      [ "CVMFS content-tamper check (<tt>signal=cvmfs_tamper</tt>)", "md_src_2net_2guard_2README.html#autotoc_md266", null ],
      [ "CVMFS token-gate check (<tt>signal=authfail</tt>)", "md_src_2net_2guard_2README.html#autotoc_md267", null ],
      [ "Testing", "md_src_2net_2guard_2README.html#autotoc_md268", null ]
    ] ],
    [ "net/httpguard — HTTP adapter for the bad-actor guard", "md_src_2net_2httpguard_2README.html", [
      [ "Directives", "md_src_2net_2httpguard_2README.html#autotoc_md270", null ],
      [ "ARC deployment recipe", "md_src_2net_2httpguard_2README.html#autotoc_md271", null ],
      [ "fail2ban wiring", "md_src_2net_2httpguard_2README.html#autotoc_md272", null ],
      [ "Tests", "md_src_2net_2httpguard_2README.html#autotoc_md273", null ]
    ] ],
    [ "manager — Cluster / redirector control plane (server registry, redirect cache, active health checks)", "md_src_2net_2manager_2README.html", [
      [ "Overview", "md_src_2net_2manager_2README.html#autotoc_md275", null ],
      [ "Files", "md_src_2net_2manager_2README.html#autotoc_md276", null ],
      [ "Key types & data structures", "md_src_2net_2manager_2README.html#autotoc_md277", null ],
      [ "Control & data flow", "md_src_2net_2manager_2README.html#autotoc_md278", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2manager_2README.html#autotoc_md279", null ],
      [ "Entry points / extending", "md_src_2net_2manager_2README.html#autotoc_md280", null ],
      [ "See also", "md_src_2net_2manager_2README.html#autotoc_md281", null ]
    ] ],
    [ "mirror — fire-and-forget traffic mirroring (shadow replay) for XRootD and WebDAV", "md_src_2net_2mirror_2README.html", [
      [ "Overview", "md_src_2net_2mirror_2README.html#autotoc_md283", null ],
      [ "Files", "md_src_2net_2mirror_2README.html#autotoc_md284", [
        [ "Other files", "md_src_2net_2mirror_2README.html#autotoc_md285", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2mirror_2README.html#autotoc_md286", null ],
      [ "Control & data flow", "md_src_2net_2mirror_2README.html#autotoc_md287", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2mirror_2README.html#autotoc_md288", null ],
      [ "Entry points / extending", "md_src_2net_2mirror_2README.html#autotoc_md289", null ],
      [ "Tests", "md_src_2net_2mirror_2README.html#autotoc_md290", null ],
      [ "See also", "md_src_2net_2mirror_2README.html#autotoc_md291", null ]
    ] ],
    [ "proxy — Transparent XRootD reverse proxy (<tt>brix_proxy</tt>)", "md_src_2net_2proxy_2README.html", [
      [ "Overview", "md_src_2net_2proxy_2README.html#autotoc_md293", null ],
      [ "Files", "md_src_2net_2proxy_2README.html#autotoc_md294", [
        [ "Other files", "md_src_2net_2proxy_2README.html#autotoc_md295", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2proxy_2README.html#autotoc_md296", null ],
      [ "Control & data flow", "md_src_2net_2proxy_2README.html#autotoc_md297", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2proxy_2README.html#autotoc_md298", null ],
      [ "Entry points / extending", "md_src_2net_2proxy_2README.html#autotoc_md299", null ],
      [ "See also", "md_src_2net_2proxy_2README.html#autotoc_md300", null ]
    ] ],
    [ "ratelimit — identity-aware leaky-bucket rate, bandwidth & concurrency limiting (Phase 25)", "md_src_2net_2ratelimit_2README.html", [
      [ "Overview", "md_src_2net_2ratelimit_2README.html#autotoc_md302", null ],
      [ "Files", "md_src_2net_2ratelimit_2README.html#autotoc_md303", [
        [ "Other files", "md_src_2net_2ratelimit_2README.html#autotoc_md304", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2ratelimit_2README.html#autotoc_md305", null ],
      [ "Directive reference (configuration surface)", "md_src_2net_2ratelimit_2README.html#autotoc_md306", null ],
      [ "Control & data flow", "md_src_2net_2ratelimit_2README.html#autotoc_md307", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2ratelimit_2README.html#autotoc_md308", null ],
      [ "Entry points / extending", "md_src_2net_2ratelimit_2README.html#autotoc_md309", null ],
      [ "See also", "md_src_2net_2ratelimit_2README.html#autotoc_md310", null ]
    ] ],
    [ "net — clustering, proxying, shadowing, and connection defense", "md_src_2net_2README.html", null ],
    [ "tap — ngx-free protocol observation tap (decode + sink fan-out)", "md_src_2net_2tap_2README.html", [
      [ "Overview", "md_src_2net_2tap_2README.html#autotoc_md313", null ],
      [ "Files", "md_src_2net_2tap_2README.html#autotoc_md314", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2tap_2README.html#autotoc_md315", null ],
      [ "See also", "md_src_2net_2tap_2README.html#autotoc_md316", null ]
    ] ],
    [ "upstream — outbound XRootD redirector/proxy client (manager-side server-to-server query)", "md_src_2net_2upstream_2README.html", [
      [ "Overview", "md_src_2net_2upstream_2README.html#autotoc_md318", null ],
      [ "Files", "md_src_2net_2upstream_2README.html#autotoc_md319", null ],
      [ "Key types & data structures", "md_src_2net_2upstream_2README.html#autotoc_md320", null ],
      [ "Control & data flow", "md_src_2net_2upstream_2README.html#autotoc_md321", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2upstream_2README.html#autotoc_md322", null ],
      [ "Entry points / extending", "md_src_2net_2upstream_2README.html#autotoc_md323", null ],
      [ "See also", "md_src_2net_2upstream_2README.html#autotoc_md324", null ]
    ] ],
    [ "Access Logging", "md_src_2observability_2accesslog_2README.html", null ],
    [ "dashboard — live HTTPS transfer monitor + REST admin write API", "md_src_2observability_2dashboard_2README.html", [
      [ "Overview", "md_src_2observability_2dashboard_2README.html#autotoc_md328", null ],
      [ "Files", "md_src_2observability_2dashboard_2README.html#autotoc_md329", null ],
      [ "Key types & data structures", "md_src_2observability_2dashboard_2README.html#autotoc_md330", null ],
      [ "Control & data flow", "md_src_2observability_2dashboard_2README.html#autotoc_md331", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2dashboard_2README.html#autotoc_md332", null ],
      [ "Entry points / extending", "md_src_2observability_2dashboard_2README.html#autotoc_md333", null ],
      [ "See also", "md_src_2observability_2dashboard_2README.html#autotoc_md334", null ],
      [ "VFS export browser (<tt>brix_dashboard_vfs_browse on</tt>)", "md_src_2observability_2dashboard_2README.html#autotoc_md335", null ]
    ] ],
    [ "metrics — shared-memory counters and the Prometheus <tt>/metrics</tt> exporter", "md_src_2observability_2metrics_2README.html", [
      [ "Overview", "md_src_2observability_2metrics_2README.html#autotoc_md337", null ],
      [ "Label schema", "md_src_2observability_2metrics_2README.html#autotoc_md338", null ],
      [ "Files", "md_src_2observability_2metrics_2README.html#autotoc_md339", [
        [ "Other files", "md_src_2observability_2metrics_2README.html#autotoc_md340", null ]
      ] ],
      [ "Key types & data structures", "md_src_2observability_2metrics_2README.html#autotoc_md341", null ],
      [ "Control & data flow", "md_src_2observability_2metrics_2README.html#autotoc_md342", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2metrics_2README.html#autotoc_md343", null ],
      [ "Entry points / extending", "md_src_2observability_2metrics_2README.html#autotoc_md344", null ],
      [ "See also", "md_src_2observability_2metrics_2README.html#autotoc_md345", null ]
    ] ],
    [ "pmark — SciTags packet marking", "md_src_2observability_2pmark_2README.html", [
      [ "Overview", "md_src_2observability_2pmark_2README.html#autotoc_md347", null ],
      [ "Files", "md_src_2observability_2pmark_2README.html#autotoc_md348", null ],
      [ "Configuration", "md_src_2observability_2pmark_2README.html#autotoc_md349", null ],
      [ "Control & data flow", "md_src_2observability_2pmark_2README.html#autotoc_md350", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2pmark_2README.html#autotoc_md351", null ],
      [ "See also", "md_src_2observability_2pmark_2README.html#autotoc_md352", null ]
    ] ],
    [ "observability — metrics, packet marking, dashboard, and access logs", "md_src_2observability_2README.html", null ],
    [ "Session Lifecycle Logging", "md_src_2observability_2sesslog_2README.html", null ],
    [ "Darwin platform adapters", "md_src_2platform_2darwin_2README.html", [
      [ "Build and validation", "md_src_2platform_2darwin_2README.html#autotoc_md357", null ]
    ] ],
    [ "Linux platform adapters", "md_src_2platform_2linux_2README.html", [
      [ "Build and validation", "md_src_2platform_2linux_2README.html#autotoc_md359", null ]
    ] ],
    [ "Platform abstraction layer", "md_src_2platform_2README.html", [
      [ "Implementation status", "md_src_2platform_2README.html#autotoc_md361", null ],
      [ "Build integration", "md_src_2platform_2README.html#autotoc_md362", null ],
      [ "Tests", "md_src_2platform_2README.html#autotoc_md363", null ]
    ] ],
    [ "Windows Platform Abstraction Layer", "md_src_2platform_2windows_2README.html", [
      [ "Overview", "md_src_2platform_2windows_2README.html#autotoc_md365", null ],
      [ "Important Limitations", "md_src_2platform_2windows_2README.html#autotoc_md366", null ],
      [ "Build Requirements", "md_src_2platform_2windows_2README.html#autotoc_md367", null ],
      [ "File Structure", "md_src_2platform_2windows_2README.html#autotoc_md368", null ],
      [ "Implementation Status", "md_src_2platform_2windows_2README.html#autotoc_md369", null ],
      [ "Key Design Decisions", "md_src_2platform_2windows_2README.html#autotoc_md370", [
        [ "1. HANDLE vs File Descriptor Abstraction", "md_src_2platform_2windows_2README.html#autotoc_md371", null ],
        [ "2. Event Loop Strategy", "md_src_2platform_2windows_2README.html#autotoc_md372", null ],
        [ "3. Security Model", "md_src_2platform_2windows_2README.html#autotoc_md373", null ]
      ] ],
      [ "Testing", "md_src_2platform_2windows_2README.html#autotoc_md374", null ],
      [ "Future Enhancements", "md_src_2platform_2windows_2README.html#autotoc_md375", null ],
      [ "References", "md_src_2platform_2windows_2README.html#autotoc_md376", null ]
    ] ],
    [ "cvmfs — the cvmfs:// site cache (+ experimental scvmfs:// TLS variant)", "md_src_2protocols_2cvmfs_2README.html", [
      [ "Overview", "md_src_2protocols_2cvmfs_2README.html#autotoc_md378", null ],
      [ "Files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md379", [
        [ "Other files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md380", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2cvmfs_2README.html#autotoc_md381", null ],
      [ "See also", "md_src_2protocols_2cvmfs_2README.html#autotoc_md382", null ]
    ] ],
    [ "<tt>src/protocols/dig/</tt> — XrdDig-style remote diagnostics", "md_src_2protocols_2dig_2README.html", [
      [ "Overview", "md_src_2protocols_2dig_2README.html#autotoc_md384", null ],
      [ "Files", "md_src_2protocols_2dig_2README.html#autotoc_md385", null ],
      [ "See also", "md_src_2protocols_2dig_2README.html#autotoc_md386", null ]
    ] ],
    [ "GridFTP / FTP Gateway", "md_src_2protocols_2gridftp_2README.html", [
      [ "Observability", "md_src_2protocols_2gridftp_2README.html#autotoc_md388", [
        [ "Other files", "md_src_2protocols_2gridftp_2README.html#autotoc_md389", null ]
      ] ]
    ] ],
    [ "oci — the OCI Distribution plane: pull-through mirror + local registry", "md_src_2protocols_2oci_2README.html", [
      [ "Overview", "md_src_2protocols_2oci_2README.html#autotoc_md391", null ],
      [ "Files", "md_src_2protocols_2oci_2README.html#autotoc_md392", [
        [ "The shared grammar", "md_src_2protocols_2oci_2README.html#autotoc_md393", null ],
        [ "The mirror surface (<tt>brix_oci_mirror</tt>)", "md_src_2protocols_2oci_2README.html#autotoc_md394", null ],
        [ "The registry surface (<tt>brix_oci_registry</tt>)", "md_src_2protocols_2oci_2README.html#autotoc_md395", null ]
      ] ],
      [ "Gating and invariants", "md_src_2protocols_2oci_2README.html#autotoc_md396", null ],
      [ "See also", "md_src_2protocols_2oci_2README.html#autotoc_md397", null ]
    ] ],
    [ "protocols — one subdirectory per wire protocol", "md_src_2protocols_2README.html", null ],
    [ "connection — TCP connection lifecycle, framing, and the async I/O state machine for <tt>root://</tt>", "md_src_2protocols_2root_2connection_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2connection_2README.html#autotoc_md400", null ],
      [ "Files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md401", [
        [ "Other files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md402", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2connection_2README.html#autotoc_md403", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2connection_2README.html#autotoc_md404", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2connection_2README.html#autotoc_md405", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2connection_2README.html#autotoc_md406", null ],
      [ "See also", "md_src_2protocols_2root_2connection_2README.html#autotoc_md407", null ]
    ] ],
    [ "dirlist — XRootD <tt>kXR_dirlist</tt> directory enumeration (stream protocol)", "md_src_2protocols_2root_2dirlist_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md409", null ],
      [ "Files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md410", [
        [ "Other files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md411", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md412", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md413", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md414", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md415", null ],
      [ "See also", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md416", null ]
    ] ],
    [ "fattr — XRootD <tt>kXR_fattr</tt> extended-attribute operations", "md_src_2protocols_2root_2fattr_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md418", null ],
      [ "Files", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md419", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md420", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md421", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md422", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md423", null ],
      [ "See also", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md424", null ]
    ] ],
    [ "handoff — single-port protocol handoff for the stream xrootd listener", "md_src_2protocols_2root_2handoff_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md426", null ],
      [ "Files", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md427", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md428", null ],
      [ "See also", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md429", null ]
    ] ],
    [ "handshake — XRootD stream request entry point and opcode dispatcher", "md_src_2protocols_2root_2handshake_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md431", null ],
      [ "Files", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md432", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md433", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md434", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md435", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md436", null ],
      [ "See also", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md437", null ]
    ] ],
    [ "path — wire-path extraction, sanitization, and stat formatting", "md_src_2protocols_2root_2path_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2path_2README.html#autotoc_md439", null ],
      [ "Files", "md_src_2protocols_2root_2path_2README.html#autotoc_md440", [
        [ "Other files", "md_src_2protocols_2root_2path_2README.html#autotoc_md441", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2path_2README.html#autotoc_md442", null ],
      [ "See also", "md_src_2protocols_2root_2path_2README.html#autotoc_md443", null ]
    ] ],
    [ "protocol — XRootD <tt>root://</tt> wire-format constants & packed structs", "md_src_2protocols_2root_2protocol_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md445", [
        [ "Provenance & licensing", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md446", null ]
      ] ],
      [ "Files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md447", [
        [ "Other files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md448", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md449", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md450", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md451", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md452", null ],
      [ "See also", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md453", null ]
    ] ],
    [ "query — XRootD <tt>kXR_query</tt> sub-protocol, <tt>kXR_prepare</tt> staging, and <tt>kXR_set</tt> hints", "md_src_2protocols_2root_2query_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2query_2README.html#autotoc_md455", null ],
      [ "Files", "md_src_2protocols_2root_2query_2README.html#autotoc_md456", [
        [ "Other files", "md_src_2protocols_2root_2query_2README.html#autotoc_md457", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2query_2README.html#autotoc_md458", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2query_2README.html#autotoc_md459", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2query_2README.html#autotoc_md460", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2query_2README.html#autotoc_md461", null ],
      [ "See also", "md_src_2protocols_2root_2query_2README.html#autotoc_md462", null ]
    ] ],
    [ "read — XRootD read-side opcodes and the file-handle lifecycle", "md_src_2protocols_2root_2read_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2read_2README.html#autotoc_md464", null ],
      [ "Files", "md_src_2protocols_2root_2read_2README.html#autotoc_md465", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2read_2README.html#autotoc_md466", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2read_2README.html#autotoc_md467", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2read_2README.html#autotoc_md468", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2read_2README.html#autotoc_md469", null ],
      [ "See also", "md_src_2protocols_2root_2read_2README.html#autotoc_md470", null ]
    ] ],
    [ "root — the XRootD (<tt>root://</tt> / <tt>roots://</tt>) protocol plane", "md_src_2protocols_2root_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2README.html#autotoc_md472", null ],
      [ "Subdirectories", "md_src_2protocols_2root_2README.html#autotoc_md473", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2README.html#autotoc_md474", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2README.html#autotoc_md475", null ],
      [ "See also", "md_src_2protocols_2root_2README.html#autotoc_md476", null ]
    ] ],
    [ "relay — transparent pass-through relay with a passive observation tap", "md_src_2protocols_2root_2relay_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2relay_2README.html#autotoc_md478", null ],
      [ "Files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md479", [
        [ "Other files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md480", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2relay_2README.html#autotoc_md481", null ],
      [ "See also", "md_src_2protocols_2root_2relay_2README.html#autotoc_md482", null ]
    ] ],
    [ "response — XRootD wire-response framing helpers", "md_src_2protocols_2root_2response_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2response_2README.html#autotoc_md484", null ],
      [ "Files", "md_src_2protocols_2root_2response_2README.html#autotoc_md485", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2response_2README.html#autotoc_md486", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2response_2README.html#autotoc_md487", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2response_2README.html#autotoc_md488", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2response_2README.html#autotoc_md489", null ],
      [ "See also", "md_src_2protocols_2root_2response_2README.html#autotoc_md490", null ]
    ] ],
    [ "session — XRootD session lifecycle, identity binding & cross-worker registry", "md_src_2protocols_2root_2session_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2session_2README.html#autotoc_md492", null ],
      [ "Files", "md_src_2protocols_2root_2session_2README.html#autotoc_md493", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2session_2README.html#autotoc_md494", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2session_2README.html#autotoc_md495", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2session_2README.html#autotoc_md496", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2session_2README.html#autotoc_md497", null ],
      [ "See also", "md_src_2protocols_2root_2session_2README.html#autotoc_md498", null ]
    ] ],
    [ "stream — <tt>ngx_stream_brix_module</tt> descriptor & directive table", "md_src_2protocols_2root_2stream_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2stream_2README.html#autotoc_md500", null ],
      [ "Files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md501", [
        [ "Other files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md502", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2stream_2README.html#autotoc_md503", [
        [ "Directive groups (authoritative <tt>module.c</tt> set)", "md_src_2protocols_2root_2stream_2README.html#autotoc_md504", null ]
      ] ],
      [ "Control & data flow", "md_src_2protocols_2root_2stream_2README.html#autotoc_md505", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2stream_2README.html#autotoc_md506", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2stream_2README.html#autotoc_md507", null ],
      [ "See also", "md_src_2protocols_2root_2stream_2README.html#autotoc_md508", null ]
    ] ],
    [ "write — XRootD mutating-opcode handlers (the stream write path)", "md_src_2protocols_2root_2write_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2write_2README.html#autotoc_md510", null ],
      [ "Files", "md_src_2protocols_2root_2write_2README.html#autotoc_md511", [
        [ "Other files", "md_src_2protocols_2root_2write_2README.html#autotoc_md512", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2write_2README.html#autotoc_md513", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2write_2README.html#autotoc_md514", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2write_2README.html#autotoc_md515", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2write_2README.html#autotoc_md516", null ],
      [ "See also", "md_src_2protocols_2root_2write_2README.html#autotoc_md517", null ]
    ] ],
    [ "src/protocols/root/zip — ZIP member access (phase-57 W2)", "md_src_2protocols_2root_2zip_2README.html", [
      [ "Status", "md_src_2protocols_2root_2zip_2README.html#autotoc_md519", null ],
      [ "zip_dir.c — the parser", "md_src_2protocols_2root_2zip_2README.html#autotoc_md520", null ],
      [ "Running the unit test (standalone, no nginx build)", "md_src_2protocols_2root_2zip_2README.html#autotoc_md521", null ]
    ] ],
    [ "rpm — the RPM/dnf pull-through mirror (phase-104 D11 / D15.9)", "md_src_2protocols_2rpm_2README.html", [
      [ "Overview", "md_src_2protocols_2rpm_2README.html#autotoc_md523", null ],
      [ "Files", "md_src_2protocols_2rpm_2README.html#autotoc_md524", null ],
      [ "Gating and invariants", "md_src_2protocols_2rpm_2README.html#autotoc_md525", null ],
      [ "See also", "md_src_2protocols_2rpm_2README.html#autotoc_md526", null ]
    ] ],
    [ "s3 — S3-compatible REST endpoint over the local export root", "md_src_2protocols_2s3_2README.html", [
      [ "Overview", "md_src_2protocols_2s3_2README.html#autotoc_md528", null ],
      [ "Files", "md_src_2protocols_2s3_2README.html#autotoc_md529", [
        [ "Other files", "md_src_2protocols_2s3_2README.html#autotoc_md530", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2s3_2README.html#autotoc_md531", null ],
      [ "Control & data flow", "md_src_2protocols_2s3_2README.html#autotoc_md532", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2s3_2README.html#autotoc_md533", null ],
      [ "Entry points / extending", "md_src_2protocols_2s3_2README.html#autotoc_md534", null ],
      [ "See also", "md_src_2protocols_2s3_2README.html#autotoc_md535", null ]
    ] ],
    [ "shared — cross-protocol helper library (HTTP file serving + overflow-safe size math)", "md_src_2protocols_2shared_2README.html", [
      [ "Overview", "md_src_2protocols_2shared_2README.html#autotoc_md537", null ],
      [ "Files", "md_src_2protocols_2shared_2README.html#autotoc_md538", null ],
      [ "Key types & data structures", "md_src_2protocols_2shared_2README.html#autotoc_md539", null ],
      [ "Control & data flow", "md_src_2protocols_2shared_2README.html#autotoc_md540", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2shared_2README.html#autotoc_md541", null ],
      [ "Entry points / extending", "md_src_2protocols_2shared_2README.html#autotoc_md542", null ],
      [ "See also", "md_src_2protocols_2shared_2README.html#autotoc_md543", null ]
    ] ],
    [ "<tt>src/protocols/srr/</tt> — WLCG Storage Resource Reporting (SRR) endpoint", "md_src_2protocols_2srr_2README.html", [
      [ "Why this instead of the XRootD UDP monitoring stack", "md_src_2protocols_2srr_2README.html#autotoc_md545", null ],
      [ "Files", "md_src_2protocols_2srr_2README.html#autotoc_md546", null ],
      [ "Configuration", "md_src_2protocols_2srr_2README.html#autotoc_md547", null ],
      [ "Semantics & caveats", "md_src_2protocols_2srr_2README.html#autotoc_md548", null ],
      [ "Schema conformance", "md_src_2protocols_2srr_2README.html#autotoc_md549", null ]
    ] ],
    [ "<tt>src/protocols/ssi/</tt> — XrdSsi request/response service over <tt>root://</tt>", "md_src_2protocols_2ssi_2README.html", [
      [ "Overview", "md_src_2protocols_2ssi_2README.html#autotoc_md551", null ],
      [ "Phase 1: session multiplexing (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md552", null ],
      [ "Phase 2: async server-push via <tt>kXR_attn</tt> (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md553", null ],
      [ "Phase 3: streamed responses + delivered alerts (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md554", null ],
      [ "Phases 4–5: CTA flagship service (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md555", null ],
      [ "Phase 6: config, metrics, conformance (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md556", [
        [ "Directives (<tt>NGX_STREAM_SRV_CONF</tt>)", "md_src_2protocols_2ssi_2README.html#autotoc_md557", null ],
        [ "Metrics (low-cardinality — <tt>{port,auth}</tt> only)", "md_src_2protocols_2ssi_2README.html#autotoc_md558", null ],
        [ "Conformance", "md_src_2protocols_2ssi_2README.html#autotoc_md559", null ]
      ] ],
      [ "RRInfo wire layout", "md_src_2protocols_2ssi_2README.html#autotoc_md560", null ],
      [ "Files", "md_src_2protocols_2ssi_2README.html#autotoc_md561", [
        [ "Other files", "md_src_2protocols_2ssi_2README.html#autotoc_md562", null ]
      ] ],
      [ "See also", "md_src_2protocols_2ssi_2README.html#autotoc_md563", null ]
    ] ],
    [ "<tt>src/protocols/ssi/svc_cta/</tt> — flagship CTA tape service", "md_src_2protocols_2ssi_2svc__cta_2README.html", [
      [ "Layers", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md565", null ],
      [ "Request lifecycle", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md566", [
        [ "State machine", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md567", null ],
        [ "Executor", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md568", null ],
        [ "Security", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md569", null ],
        [ "The queue is cross-worker (phase 115 W8.6)", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md570", null ],
        [ "Journal (restart recovery)", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md571", null ]
      ] ],
      [ "External contract — the pinned field table", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md572", null ],
      [ "Golden-vector provenance", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md573", null ],
      [ "Scope notes", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md574", [
        [ "Other files", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md575", null ]
      ] ]
    ] ],
    [ "webdav/fs — Confined local-filesystem copy engine for WebDAV COPY/MOVE", "md_src_2protocols_2webdav_2fs_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md577", null ],
      [ "Files", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md578", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md579", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md580", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md581", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md582", null ],
      [ "See also", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md583", null ]
    ] ],
    [ "webdav/locks — WebDAV LOCK request-header & body parsers", "md_src_2protocols_2webdav_2locks_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md585", null ],
      [ "Files", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md586", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md587", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md588", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md589", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md590", null ],
      [ "See also", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md591", null ]
    ] ],
    [ "webdav/methods — Per-method WebDAV precondition helpers", "md_src_2protocols_2webdav_2methods_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md593", null ],
      [ "Files", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md594", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md595", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md596", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md597", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md598", null ],
      [ "See also", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md599", null ]
    ] ],
    [ "webdav — HTTP/WebDAV/HTTPS gateway (<tt>davs://</tt>, <tt>http://</tt>) over the export root", "md_src_2protocols_2webdav_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2README.html#autotoc_md601", null ],
      [ "Files", "md_src_2protocols_2webdav_2README.html#autotoc_md602", [
        [ "Module wiring & configuration", "md_src_2protocols_2webdav_2README.html#autotoc_md603", null ],
        [ "Dispatch & generic helpers", "md_src_2protocols_2webdav_2README.html#autotoc_md604", null ],
        [ "HTTP method handlers", "md_src_2protocols_2webdav_2README.html#autotoc_md605", null ],
        [ "Authentication", "md_src_2protocols_2webdav_2README.html#autotoc_md606", null ],
        [ "HTTP-TPC (third-party copy)", "md_src_2protocols_2webdav_2README.html#autotoc_md607", null ],
        [ "Dynamic backend pool (admin API)", "md_src_2protocols_2webdav_2README.html#autotoc_md608", null ],
        [ "XrdHttp protocol extension", "md_src_2protocols_2webdav_2README.html#autotoc_md609", null ],
        [ "Other files", "md_src_2protocols_2webdav_2README.html#autotoc_md610", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2README.html#autotoc_md611", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2README.html#autotoc_md612", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2README.html#autotoc_md613", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2README.html#autotoc_md614", null ],
      [ "See also", "md_src_2protocols_2webdav_2README.html#autotoc_md615", null ]
    ] ],
    [ "webdav/util — WebDAV URI decoding and XML escaping helpers", "md_src_2protocols_2webdav_2util_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md617", null ],
      [ "Files", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md618", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md619", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md620", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md621", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md622", null ],
      [ "See also", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md623", null ]
    ] ],
    [ "src — nginx-xrootd Source Tree", "md_src_2README.html", [
      [ "Source map", "md_src_2README.html#autotoc_md626", [
        [ "Top-level files (now under <tt>core/</tt>)", "md_src_2README.html#autotoc_md627", null ],
        [ "Entry & dispatch", "md_src_2README.html#autotoc_md628", null ],
        [ "Protocol handlers", "md_src_2README.html#autotoc_md629", null ],
        [ "Data plane", "md_src_2README.html#autotoc_md630", null ],
        [ "Path & confinement", "md_src_2README.html#autotoc_md631", null ],
        [ "Authentication", "md_src_2README.html#autotoc_md632", null ],
        [ "Cluster & federation", "md_src_2README.html#autotoc_md633", null ],
        [ "Cross-cutting", "md_src_2README.html#autotoc_md634", null ],
        [ "WebDAV sub-helpers", "md_src_2README.html#autotoc_md635", null ]
      ] ],
      [ "The four request lifecycles", "md_src_2README.html#autotoc_md637", [
        [ "<tt>root://</tt> stream", "md_src_2README.html#autotoc_md638", null ],
        [ "<tt>davs://</tt> WebDAV", "md_src_2README.html#autotoc_md639", null ],
        [ "S3 REST", "md_src_2README.html#autotoc_md640", null ],
        [ "CMS cluster redirect", "md_src_2README.html#autotoc_md641", null ]
      ] ],
      [ "Cross-cutting invariants", "md_src_2README.html#autotoc_md643", null ],
      [ "How to navigate / where to start reading", "md_src_2README.html#autotoc_md645", null ]
    ] ],
    [ "tpc/common — Protocol-neutral third-party-copy (TPC) core", "md_src_2tpc_2common_2README.html", [
      [ "Overview", "md_src_2tpc_2common_2README.html#autotoc_md647", null ],
      [ "Files", "md_src_2tpc_2common_2README.html#autotoc_md648", null ],
      [ "Key types & data structures", "md_src_2tpc_2common_2README.html#autotoc_md649", null ],
      [ "Control & data flow", "md_src_2tpc_2common_2README.html#autotoc_md650", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2common_2README.html#autotoc_md651", null ],
      [ "Entry points / extending", "md_src_2tpc_2common_2README.html#autotoc_md652", null ],
      [ "See also", "md_src_2tpc_2common_2README.html#autotoc_md653", null ]
    ] ],
    [ "engine — native-TPC control plane (destination side)", "md_src_2tpc_2engine_2README.html", [
      [ "Overview", "md_src_2tpc_2engine_2README.html#autotoc_md655", null ],
      [ "Files", "md_src_2tpc_2engine_2README.html#autotoc_md656", [
        [ "Other files", "md_src_2tpc_2engine_2README.html#autotoc_md657", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2engine_2README.html#autotoc_md658", null ],
      [ "See also", "md_src_2tpc_2engine_2README.html#autotoc_md659", null ]
    ] ],
    [ "gsi — outbound GSI authentication for the TPC pull socket", "md_src_2tpc_2gsi_2README.html", [
      [ "Overview", "md_src_2tpc_2gsi_2README.html#autotoc_md661", null ],
      [ "Files", "md_src_2tpc_2gsi_2README.html#autotoc_md662", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2gsi_2README.html#autotoc_md663", null ],
      [ "See also", "md_src_2tpc_2gsi_2README.html#autotoc_md664", null ]
    ] ],
    [ "outbound — the blocking source-session client for native TPC pulls", "md_src_2tpc_2outbound_2README.html", [
      [ "Overview", "md_src_2tpc_2outbound_2README.html#autotoc_md666", null ],
      [ "Files", "md_src_2tpc_2outbound_2README.html#autotoc_md667", [
        [ "Other files", "md_src_2tpc_2outbound_2README.html#autotoc_md668", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2outbound_2README.html#autotoc_md669", null ],
      [ "See also", "md_src_2tpc_2outbound_2README.html#autotoc_md670", null ]
    ] ],
    [ "tpc — Native XRootD third-party-copy (destination-side pull)", "md_src_2tpc_2README.html", [
      [ "Overview", "md_src_2tpc_2README.html#autotoc_md672", null ],
      [ "Files", "md_src_2tpc_2README.html#autotoc_md673", null ],
      [ "Key types & data structures", "md_src_2tpc_2README.html#autotoc_md674", null ],
      [ "Control & data flow", "md_src_2tpc_2README.html#autotoc_md675", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2README.html#autotoc_md676", null ],
      [ "Entry points / extending", "md_src_2tpc_2README.html#autotoc_md677", null ],
      [ "See also", "md_src_2tpc_2README.html#autotoc_md678", null ]
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
        [ "Functions", "functions_func.html", null ],
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
"__brix__net__ext_8h.html",
"aio__conn_8c.html#a82302c356305b4aae269991bb3b071c7",
"api__cvmfs_8c.html#ae4f79cf53a0691dc50a564656e654183",
"auth_2krb5_2deleg__capture_8c.html#a6c6699c5d69a28c612176b2599511c48",
"auth__token_8c.html#a7a3f4de2b2dc8bdef3fc7f04acaa3265",
"beneath_8c.html#a2ca52e7d2857dd2beb20b38ba2a4c03c",
"brix__fault__cmd__dpi_8c.html#ac55812b7b7d1d9b29112b2f97b3f7172",
"brix__fault__proxy_8c.html#ad62bff063cc0802feb2a389bc5c402c3",
"brix__fault__pump_8c.html#a95e41ab659c7ab5af652eb242d93a3c9",
"brix__net_8h.html#af63faa7bc2b6a7728a73c4b4ce50c0ac",
"brixcvmfs__curl__pin_8c.html#a963a164af566e3e99915d69c4a7f975e",
"brixcvmfs__repo_8c.html#a30b1e2fe1a5715c1ef7651eec43e6f4a",
"brixoci__convert_8c.html#ac1c2411ff0ab433b9152a765d1900d34",
"broker__ops_8c.html#a70d802a966a95429b816e1b298bdcbec",
"cache__storage_8h.html#a52049244721db78795a0d6ebd329eba6",
"checksum__plugin_8c.html#afd6c94e09ecf15b41ab75f1f6f0b18d5",
"cli__hint_8c.html#a25a81de44adada9ed0ffeac32951692b",
"client_2lib_2xfer_2copy__internal_8h.html#a5198d138aeb32f610a44be27a7c7c9f5",
"cms__internal_8h.html#ab495b842edbe6dc59663be792c16f458",
"common_8c.html#a93b8f8f1853e821c4370e7a45f4dcf85",
"copy__cksum__verify_8c.html",
"copy__xcp_8c.html#a76817c3e3cc8a902960615ff6ab5dd6b",
"crc32__ieee_8h_source.html",
"credential__block_8h.html#a2e49b65a02a996980f002a53e6933f6a",
"cta__pb_8c.html#a66dc973112dafb932d7d560970335cc8",
"cvmfs__module__georank_8c.html",
"dashboard__auth__parse_8c.html",
"diag__bench_8c.html#a3f4604117fe5dd078522603bdc9a8de7",
"diag__doctor__latency_8c.html#a811cbd7153c2fcebe0dd359f4c1ad061",
"diag__misc_8c.html",
"dir_afd760938acfe1bc9552e8ce0d07f566.html",
"dns_8h.html#acf9427d89e77e0293da1cc2bd9bf8388",
"ext__ops_8c_source.html",
"flags_8h.html#a791c677977628f1ef186812baddb21ce",
"frm__metrics_8c.html",
"fs_2path_2unified__internal_8h.html#a80c78443635e67ea9bd3bd06eaa7abac",
"ftp__ev__data__setup_8c.html#ab5b2788eae27bd5b7125c13da7d3165d",
"functions_vars_p.html",
"gftp__feat_8c.html#a2e763bf53a6f5e595041d11452db7042",
"group__policy_8c.html#a46eb542e23ddd06f58922c2d83485f24",
"gsi__outbound__exchange_8c.html",
"handoff_8c_source.html",
"http__compress_8c.html#a152e58895a57869b24be42c85de38ca5",
"http__rootfd_8c_source.html",
"identity__matrix_8h.html#aceae5b8ac189cb1dbb98bed26baac057",
"ini__unittest_8c.html#a6ba7accee151d806fa5f4cf8ce2c0e4f",
"key__registry_8h.html#a2e1c6f64a274d8fbf866f1d3530a4d44",
"lifecycle__broker_8c.html#a00212d666a3508d4f7b0c3fd29f8f1eb",
"log__diag_8h.html#aac0a55cf03a8073cd85b1b2df3ae35ab",
"md_src_2auth_2protbind_2README.html#autotoc_md51",
"md_src_2net_2ratelimit_2README.html#autotoc_md302",
"md_src_2protocols_2ssi_2README.html#autotoc_md555",
"metalink__lex_8c.html#a120d50f9d7e4c9dcab291ddcacde3200",
"metrics__s3_8h.html#aaa6aee53fe3820a8b5326e4320235ccc",
"multipart__complete__body_8c.html#ab9af63f4837e099f3cd06ddf5a8aae6c",
"net_2httpguard_2module_8c.html#ae348bdb15cac1a6892bd6fe193a0ab64",
"ngx__brix__module_8h.html#a537a0a25c67cf0ef97883e4ed357ec3c",
"observability_2metrics_2config_8c.html#a6fe2134b02a48c2d0078ba2e6dcef565",
"observability_2metrics_2unified__internal_8h.html#aec0991ca811840b00259d069a0f24812",
"oci__module_8c.html#a9fe9eda7419a5de021f1529d07d9d5ed",
"offload__registry_8h.html#a9cf103f5b42b818b02433d2635305f9c",
"open__or__fill_8c.html",
"origin__id_8c.html#aa268f05e5e0321afad408b328ece7789",
"parse_8c.html#a4762ec89263092b25012fd5b76b721a4",
"pblock__store_8c.html#a2bef6cd5466f982d357cbdebe9afa911",
"pgwrite__helpers_8c.html#adaf12807ccda275547dcaf0f47370b67",
"pmark_8h.html#a38837b66a0e1ab9a0485c725dad6002f",
"privs_8h.html#a5515e34fcee361910935b0a21ad8aece",
"protocols_2cvmfs_2module_8c.html#a22fb6a0f19e3d114f4d08f31af224c3e",
"protocols_2s3_2metrics_8c.html#a5daea6f468a968aef3252f422806d17e",
"proxy_8h.html#ae4c239b0082a8cbc428afe987e5d7abc",
"put__internal_8h.html#a94e33c95f2664b80e25191b794314f05",
"ratelimit__zone_8c.html#a7a9d694b0e967542cd875102cb3d5826",
"ref_8h_source.html",
"reqid__map_8h.html#a47f3b28f8606430d0f5bfecdef41b917",
"resume_8c_source.html",
"rpm__classify_8h.html#a4380d7093c0e0df01065a927ccf6967ea7f5f1ca26599e5510f3ccbfd7b923b66",
"s3__auth__internal_8h.html#aa61b59cafce62b3fe43cdde6d0ada37c",
"scan__engine__catalog_8c.html#ab257084991e08884ac345fcf0aa628ec",
"sd__cache_8c.html#af03d90495718d5e92d1f128aec43fa94",
"sd__ceph_8h.html#a168fba5daa4deb3c88d469b67e128f0c",
"sd__frm__arc__store_8c.html",
"sd__gsiftp__internal_8h.html#a0476c781021ac73971a073dba08d50ff",
"sd__http__nearline_8c.html#abe64d6505b17e101bbefc9e09886337a",
"sd__pblock__internal_8h.html#a25f1a17b65ad596bd6ac95bf74fc6eae",
"sd__posix__dedup_8c_source.html",
"sd__remote__internal_8h.html#a0ee9e2b63063b36b1a7053908bf9f3fd",
"sd__s3__sign__ext_8c.html#a128659231c1e37cdcf6c7c06c46a2c0f",
"sd__xroot__fwd__key_8c.html#acf45e8e5d19283ccfe1179d75cc3f6e5",
"sec__krb5_8c.html#aa6c45cbf7f123c4b54c0c7418949f171",
"server__recv_8c.html#a2b993910d7f982032d51fa57710798fe",
"sesslog__err_8c_source.html",
"shared__conf__fields__policy_8h.html#afc342728c97694458194b968c12c53a7",
"src_2core_2aio_2aio_8h.html#a39f5dbca7fdbe5189db309126b31c006",
"src_2protocols_2webdav_2copy_8c.html#a450bdb10890e4aecf04ab162b3bcd34c",
"ssi_8h.html",
"sss__id_8h.html#ab0caa50822982e0f19af6f2de5c9dd1b",
"stage__request__registry_8h.html#a529343fc71c472749962c1e4228fed0facf678e79378d46153720ea2e0056fae3",
"storascan__bench_8c.html#ad5c6d489cb47d1bc139864dacd80f0f3",
"stream__mirror_8c.html#ae710b61b62fec14972c4be7b3aaca8c4",
"structClientDirlistRequest.html#a63f393b3e79d7c70605a747c439557ad",
"structServerResponseHdr.html#ac890a5022e34300029fc3c6c63fb903b",
"structbreak__arg.html#a89e5c3a283db4a8d2b8796f95bb96b28",
"structbrix__baq__pending__t.html#aa1e6d42eb35b78db7421e34cb4786b6e",
"structbrix__cache__transport__t.html#aced76708261bb27569900296ad4934f3",
"structbrix__cms__srv__ctx__t.html#a566cb2cc7ba70e43573a752159bebec6",
"structbrix__ctx__gsi__t.html",
"structbrix__cvmfs__conf__t.html#a87c11094df98ea118e71a4b1d8547b8b",
"structbrix__dns__rev__req__s.html#a5b7210b001fd29910dab2ce75f8d5518",
"structbrix__fuse__ctx__setattr.html",
"structbrix__imp__state__t.html",
"structbrix__mirror__conf__t.html#a331201ef15f7c2d90c2a1187b01fbb71",
"structbrix__open__request__t.html#a0b559d83a78f1f48f76e89c2ca53485a",
"structbrix__poll__slot.html#a27a750f6985c5129eea41c9a252e6b1d",
"structbrix__read__aio__t.html#a6662a8fc72c5f393c153c339c703a091",
"structbrix__scan__opts__t.html#a8c8ed22b39c0893be6148e788bca322e",
"structbrix__sd__setattr__t.html#ada33501e1d5744457bb251e7577e82a6",
"structbrix__srv__sched__t.html#a2206dfeefeabcb41944279aa51be5c40",
"structbrix__stream__mirror__t.html#a3fbace996312ad038c228b09ed324509",
"structbrix__tpc__params__t.html#af28f65082d858b4cd6384816a1cb605e",
"structbrix__vfs__backend__entry__t.html#a55a8341295445419f9feefde2ff0491b",
"structbrix__vfs__walk__opts__t.html#a4be960cf3af65f1b9b8d2397a97a05cc",
"structbrix__xmeta__astat__t.html",
"structcinfo__l1__impl__t.html",
"structcta__request__t.html",
"structdashboard__xfer__snapshot__t.html#a0a137325e924ae0f368d71bb5f07c7fd",
"structdoctor__recon.html#a3bc0b51a2155f5c6996602f76a86393b",
"structfp__http__stats.html",
"structget__range__hop__t.html#a0f79a3d38c80cd2e4a5850fc969a0395",
"structhttpx__exchange__t.html#a3a3be6358294135a391953fbdd4906b1",
"structlp__page__t.html#a7b3038b083f82d2f76032198ad901c2f",
"structngx__brix__frm__metrics__t.html#a4ae80e22f33fb62769c650075ae12cef",
"structngx__brix__webdav__metrics__t.html#a58e2688de1e286303a9c6ad2b81a25aa",
"structngx__http__brix__webdav__tls__auth__cache__t.html#a17d582b3d7b99a6317cf6db71e321ca6",
"structpblock__opts__t.html#afdf6a311ed1fa7c65849a88b34d7196b",
"structreadahead__list.html#ab292dbd65a91482923521c16589c517f",
"structs3__list__out__t.html#ac54d07640acb17b8a25ca76f675bfae5",
"structsd__cache__partial__t.html",
"structsd__s3__file.html#a012a28996d001eb7fe9ddaf4196a0ecd",
"structsss__cred__t.html#a675ac656e5ab322d8947aab723c3900c",
"structtpc__multi__round__t.html#a4a5bf2eed99a50e81872397c879d32ab",
"structwc__args__t.html",
"structwebdav__walk__task__t.html#afe10b9257d40498a743ac0451cc8aa61",
"structxrdcp__transfer__ctx.html#aec886eec820ed1f2148beed8df8d9416",
"sts__http_8c.html#ab8e947e1fd6dbbf55f9cec3bcc1ec121",
"tape__rest_8c.html#ae9bcc80c347c6289b695867e63db95c3",
"tmp__path_8c.html#a5c3c89401640b172bc2b94a224f01a50",
"tpc__cred__oidc_8c.html#abc5234083906b555e6eab9037c71e496",
"tpc__user__proxy_8h_source.html",
"tunables__cluster_8h.html#aea6ca432e70c8dd68223fb5644d81524",
"tunables__metrics_8h.html#ac755ff820966a30827959aa1c06eceb6",
"tunables__s3_8h.html#a18cc93b852dd74d75487f593ad7d77c2",
"tunables__webdav_8h.html#a049e96fccb3c20549aaf69eb1ccf018f",
"upstream__internal_8h.html#a9e2ef0cd5432ad54ef610a991f2da24b",
"vfs__authz__types_8h.html#ad3deca4f970615e60e8d7229b2d94242acb96948d3dec1ea0f7f28261fa69c008",
"vfs__cred_8c.html#a84a4a35df60873f154f6aa3af4fbb951",
"vfs__open__handle_8c.html#a6afc82e33ee2cc090a866474b35e33e9",
"vfs__secgate_8c_source.html",
"web__ka_8c.html#a6e148298ec9e79db0ca7cc2293141203",
"webfile_8c_source.html",
"wire__codec__ns_8c.html#a78f6804483f6196fe18afe9421caa1b2",
"wrts__journal_8h_source.html",
"xmeta_8h.html#aa0e5cb4f5f7dbdf6a520d781f1e7cad1",
"xrd__mount_8c.html#a7e6c3b5046f6d7f6a803aeb83d8472ee",
"xrdcp__transfer_8c.html#acde972a09b6d6aa6b629e418a10953c5",
"xrdfs__meta__ls_8c.html",
"xrdstorascan_8c.html",
"xrootdfs__legacy__ext_8c.html#a3e1a710f7fb1098324889a4d45384e8c",
"zip__member_8h.html#a0a2785f4800ff923fe595ae11f48dbcb"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';