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
    [ "cms — XRootD CMS cluster membership (heartbeat client + manager-side server)", "md_src_2net_2cms_2README.html", [
      [ "Overview", "md_src_2net_2cms_2README.html#autotoc_md241", null ],
      [ "Files", "md_src_2net_2cms_2README.html#autotoc_md242", [
        [ "Heartbeat client (main module)", "md_src_2net_2cms_2README.html#autotoc_md243", null ],
        [ "Shared frame I/O", "md_src_2net_2cms_2README.html#autotoc_md244", null ],
        [ "Manager-side server (<tt>ngx_stream_brix_cms_srv_module</tt>)", "md_src_2net_2cms_2README.html#autotoc_md245", null ],
        [ "Manager namespace/staging planes (phase-89)", "md_src_2net_2cms_2README.html#autotoc_md246", null ],
        [ "Other files", "md_src_2net_2cms_2README.html#autotoc_md247", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2cms_2README.html#autotoc_md248", null ],
      [ "Control & data flow", "md_src_2net_2cms_2README.html#autotoc_md249", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2cms_2README.html#autotoc_md250", null ],
      [ "Entry points / extending", "md_src_2net_2cms_2README.html#autotoc_md251", null ],
      [ "See also", "md_src_2net_2cms_2README.html#autotoc_md252", null ]
    ] ],
    [ "net/guard — protocol-agnostic bad-actor classifier", "md_src_2net_2guard_2README.html", [
      [ "The <tt>guard_request_t</tt> contract", "md_src_2net_2guard_2README.html#autotoc_md254", null ],
      [ "Audit line (the fail2ban contract)", "md_src_2net_2guard_2README.html#autotoc_md255", null ],
      [ "Wire-level \"not speaking root\" check (<tt>guard_classify_handshake</tt>)", "md_src_2net_2guard_2README.html#autotoc_md256", null ],
      [ "CVMFS forward-proxy abuse check (<tt>signal=proxyabuse</tt>)", "md_src_2net_2guard_2README.html#autotoc_md257", null ],
      [ "CVMFS content-tamper check (<tt>signal=cvmfs_tamper</tt>)", "md_src_2net_2guard_2README.html#autotoc_md258", null ],
      [ "CVMFS token-gate check (<tt>signal=authfail</tt>)", "md_src_2net_2guard_2README.html#autotoc_md259", null ],
      [ "Testing", "md_src_2net_2guard_2README.html#autotoc_md260", null ]
    ] ],
    [ "net/httpguard — HTTP adapter for the bad-actor guard", "md_src_2net_2httpguard_2README.html", [
      [ "Directives", "md_src_2net_2httpguard_2README.html#autotoc_md262", null ],
      [ "ARC deployment recipe", "md_src_2net_2httpguard_2README.html#autotoc_md263", null ],
      [ "fail2ban wiring", "md_src_2net_2httpguard_2README.html#autotoc_md264", null ],
      [ "Tests", "md_src_2net_2httpguard_2README.html#autotoc_md265", null ]
    ] ],
    [ "manager — Cluster / redirector control plane (server registry, redirect cache, active health checks)", "md_src_2net_2manager_2README.html", [
      [ "Overview", "md_src_2net_2manager_2README.html#autotoc_md267", null ],
      [ "Files", "md_src_2net_2manager_2README.html#autotoc_md268", null ],
      [ "Key types & data structures", "md_src_2net_2manager_2README.html#autotoc_md269", null ],
      [ "Control & data flow", "md_src_2net_2manager_2README.html#autotoc_md270", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2manager_2README.html#autotoc_md271", null ],
      [ "Entry points / extending", "md_src_2net_2manager_2README.html#autotoc_md272", null ],
      [ "See also", "md_src_2net_2manager_2README.html#autotoc_md273", null ]
    ] ],
    [ "mirror — fire-and-forget traffic mirroring (shadow replay) for XRootD and WebDAV", "md_src_2net_2mirror_2README.html", [
      [ "Overview", "md_src_2net_2mirror_2README.html#autotoc_md275", null ],
      [ "Files", "md_src_2net_2mirror_2README.html#autotoc_md276", [
        [ "Other files", "md_src_2net_2mirror_2README.html#autotoc_md277", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2mirror_2README.html#autotoc_md278", null ],
      [ "Control & data flow", "md_src_2net_2mirror_2README.html#autotoc_md279", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2mirror_2README.html#autotoc_md280", null ],
      [ "Entry points / extending", "md_src_2net_2mirror_2README.html#autotoc_md281", null ],
      [ "Tests", "md_src_2net_2mirror_2README.html#autotoc_md282", null ],
      [ "See also", "md_src_2net_2mirror_2README.html#autotoc_md283", null ]
    ] ],
    [ "proxy — Transparent XRootD reverse proxy (<tt>brix_proxy</tt>)", "md_src_2net_2proxy_2README.html", [
      [ "Overview", "md_src_2net_2proxy_2README.html#autotoc_md285", null ],
      [ "Files", "md_src_2net_2proxy_2README.html#autotoc_md286", [
        [ "Other files", "md_src_2net_2proxy_2README.html#autotoc_md287", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2proxy_2README.html#autotoc_md288", null ],
      [ "Control & data flow", "md_src_2net_2proxy_2README.html#autotoc_md289", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2proxy_2README.html#autotoc_md290", null ],
      [ "Entry points / extending", "md_src_2net_2proxy_2README.html#autotoc_md291", null ],
      [ "See also", "md_src_2net_2proxy_2README.html#autotoc_md292", null ]
    ] ],
    [ "ratelimit — identity-aware leaky-bucket rate, bandwidth & concurrency limiting (Phase 25)", "md_src_2net_2ratelimit_2README.html", [
      [ "Overview", "md_src_2net_2ratelimit_2README.html#autotoc_md294", null ],
      [ "Files", "md_src_2net_2ratelimit_2README.html#autotoc_md295", [
        [ "Other files", "md_src_2net_2ratelimit_2README.html#autotoc_md296", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2ratelimit_2README.html#autotoc_md297", null ],
      [ "Directive reference (configuration surface)", "md_src_2net_2ratelimit_2README.html#autotoc_md298", null ],
      [ "Control & data flow", "md_src_2net_2ratelimit_2README.html#autotoc_md299", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2ratelimit_2README.html#autotoc_md300", null ],
      [ "Entry points / extending", "md_src_2net_2ratelimit_2README.html#autotoc_md301", null ],
      [ "See also", "md_src_2net_2ratelimit_2README.html#autotoc_md302", null ]
    ] ],
    [ "net — clustering, proxying, shadowing, and connection defense", "md_src_2net_2README.html", null ],
    [ "tap — ngx-free protocol observation tap (decode + sink fan-out)", "md_src_2net_2tap_2README.html", [
      [ "Overview", "md_src_2net_2tap_2README.html#autotoc_md305", null ],
      [ "Files", "md_src_2net_2tap_2README.html#autotoc_md306", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2tap_2README.html#autotoc_md307", null ],
      [ "See also", "md_src_2net_2tap_2README.html#autotoc_md308", null ]
    ] ],
    [ "upstream — outbound XRootD redirector/proxy client (manager-side server-to-server query)", "md_src_2net_2upstream_2README.html", [
      [ "Overview", "md_src_2net_2upstream_2README.html#autotoc_md310", null ],
      [ "Files", "md_src_2net_2upstream_2README.html#autotoc_md311", null ],
      [ "Key types & data structures", "md_src_2net_2upstream_2README.html#autotoc_md312", null ],
      [ "Control & data flow", "md_src_2net_2upstream_2README.html#autotoc_md313", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2upstream_2README.html#autotoc_md314", null ],
      [ "Entry points / extending", "md_src_2net_2upstream_2README.html#autotoc_md315", null ],
      [ "See also", "md_src_2net_2upstream_2README.html#autotoc_md316", null ]
    ] ],
    [ "Access Logging", "md_src_2observability_2accesslog_2README.html", null ],
    [ "dashboard — live HTTPS transfer monitor + REST admin write API", "md_src_2observability_2dashboard_2README.html", [
      [ "Overview", "md_src_2observability_2dashboard_2README.html#autotoc_md320", null ],
      [ "Files", "md_src_2observability_2dashboard_2README.html#autotoc_md321", null ],
      [ "Key types & data structures", "md_src_2observability_2dashboard_2README.html#autotoc_md322", null ],
      [ "Control & data flow", "md_src_2observability_2dashboard_2README.html#autotoc_md323", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2dashboard_2README.html#autotoc_md324", null ],
      [ "Entry points / extending", "md_src_2observability_2dashboard_2README.html#autotoc_md325", null ],
      [ "See also", "md_src_2observability_2dashboard_2README.html#autotoc_md326", null ],
      [ "VFS export browser (<tt>brix_dashboard_vfs_browse on</tt>)", "md_src_2observability_2dashboard_2README.html#autotoc_md327", null ]
    ] ],
    [ "metrics — shared-memory counters and the Prometheus <tt>/metrics</tt> exporter", "md_src_2observability_2metrics_2README.html", [
      [ "Overview", "md_src_2observability_2metrics_2README.html#autotoc_md329", null ],
      [ "Label schema", "md_src_2observability_2metrics_2README.html#autotoc_md330", null ],
      [ "Files", "md_src_2observability_2metrics_2README.html#autotoc_md331", [
        [ "Other files", "md_src_2observability_2metrics_2README.html#autotoc_md332", null ]
      ] ],
      [ "Key types & data structures", "md_src_2observability_2metrics_2README.html#autotoc_md333", null ],
      [ "Control & data flow", "md_src_2observability_2metrics_2README.html#autotoc_md334", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2metrics_2README.html#autotoc_md335", null ],
      [ "Entry points / extending", "md_src_2observability_2metrics_2README.html#autotoc_md336", null ],
      [ "See also", "md_src_2observability_2metrics_2README.html#autotoc_md337", null ]
    ] ],
    [ "pmark — SciTags packet marking", "md_src_2observability_2pmark_2README.html", [
      [ "Overview", "md_src_2observability_2pmark_2README.html#autotoc_md339", null ],
      [ "Files", "md_src_2observability_2pmark_2README.html#autotoc_md340", null ],
      [ "Configuration", "md_src_2observability_2pmark_2README.html#autotoc_md341", null ],
      [ "Control & data flow", "md_src_2observability_2pmark_2README.html#autotoc_md342", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2pmark_2README.html#autotoc_md343", null ],
      [ "See also", "md_src_2observability_2pmark_2README.html#autotoc_md344", null ]
    ] ],
    [ "observability — metrics, packet marking, dashboard, and access logs", "md_src_2observability_2README.html", null ],
    [ "Session Lifecycle Logging", "md_src_2observability_2sesslog_2README.html", null ],
    [ "cvmfs — the cvmfs:// site cache (+ experimental scvmfs:// TLS variant)", "md_src_2protocols_2cvmfs_2README.html", [
      [ "Overview", "md_src_2protocols_2cvmfs_2README.html#autotoc_md349", null ],
      [ "Files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md350", [
        [ "Other files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md351", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2cvmfs_2README.html#autotoc_md352", null ],
      [ "See also", "md_src_2protocols_2cvmfs_2README.html#autotoc_md353", null ]
    ] ],
    [ "<tt>src/protocols/dig/</tt> — XrdDig-style remote diagnostics", "md_src_2protocols_2dig_2README.html", [
      [ "Overview", "md_src_2protocols_2dig_2README.html#autotoc_md355", null ],
      [ "Files", "md_src_2protocols_2dig_2README.html#autotoc_md356", null ],
      [ "See also", "md_src_2protocols_2dig_2README.html#autotoc_md357", null ]
    ] ],
    [ "GridFTP / FTP Gateway", "md_src_2protocols_2gridftp_2README.html", [
      [ "Observability", "md_src_2protocols_2gridftp_2README.html#autotoc_md359", [
        [ "Other files", "md_src_2protocols_2gridftp_2README.html#autotoc_md360", null ]
      ] ]
    ] ],
    [ "oci — the OCI Distribution plane: pull-through mirror + local registry", "md_src_2protocols_2oci_2README.html", [
      [ "Overview", "md_src_2protocols_2oci_2README.html#autotoc_md362", null ],
      [ "Files", "md_src_2protocols_2oci_2README.html#autotoc_md363", [
        [ "The shared grammar", "md_src_2protocols_2oci_2README.html#autotoc_md364", null ],
        [ "The mirror surface (<tt>brix_oci_mirror</tt>)", "md_src_2protocols_2oci_2README.html#autotoc_md365", null ],
        [ "The registry surface (<tt>brix_oci_registry</tt>)", "md_src_2protocols_2oci_2README.html#autotoc_md366", null ]
      ] ],
      [ "Gating and invariants", "md_src_2protocols_2oci_2README.html#autotoc_md367", null ],
      [ "See also", "md_src_2protocols_2oci_2README.html#autotoc_md368", null ]
    ] ],
    [ "protocols — one subdirectory per wire protocol", "md_src_2protocols_2README.html", null ],
    [ "connection — TCP connection lifecycle, framing, and the async I/O state machine for <tt>root://</tt>", "md_src_2protocols_2root_2connection_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2connection_2README.html#autotoc_md371", null ],
      [ "Files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md372", [
        [ "Other files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md373", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2connection_2README.html#autotoc_md374", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2connection_2README.html#autotoc_md375", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2connection_2README.html#autotoc_md376", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2connection_2README.html#autotoc_md377", null ],
      [ "See also", "md_src_2protocols_2root_2connection_2README.html#autotoc_md378", null ]
    ] ],
    [ "dirlist — XRootD <tt>kXR_dirlist</tt> directory enumeration (stream protocol)", "md_src_2protocols_2root_2dirlist_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md380", null ],
      [ "Files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md381", [
        [ "Other files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md382", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md383", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md384", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md385", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md386", null ],
      [ "See also", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md387", null ]
    ] ],
    [ "fattr — XRootD <tt>kXR_fattr</tt> extended-attribute operations", "md_src_2protocols_2root_2fattr_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md389", null ],
      [ "Files", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md390", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md391", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md392", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md393", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md394", null ],
      [ "See also", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md395", null ]
    ] ],
    [ "handoff — single-port protocol handoff for the stream xrootd listener", "md_src_2protocols_2root_2handoff_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md397", null ],
      [ "Files", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md398", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md399", null ],
      [ "See also", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md400", null ]
    ] ],
    [ "handshake — XRootD stream request entry point and opcode dispatcher", "md_src_2protocols_2root_2handshake_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md402", null ],
      [ "Files", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md403", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md404", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md405", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md406", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md407", null ],
      [ "See also", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md408", null ]
    ] ],
    [ "path — wire-path extraction, sanitization, and stat formatting", "md_src_2protocols_2root_2path_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2path_2README.html#autotoc_md410", null ],
      [ "Files", "md_src_2protocols_2root_2path_2README.html#autotoc_md411", [
        [ "Other files", "md_src_2protocols_2root_2path_2README.html#autotoc_md412", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2path_2README.html#autotoc_md413", null ],
      [ "See also", "md_src_2protocols_2root_2path_2README.html#autotoc_md414", null ]
    ] ],
    [ "protocol — XRootD <tt>root://</tt> wire-format constants & packed structs", "md_src_2protocols_2root_2protocol_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md416", [
        [ "Provenance & licensing", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md417", null ]
      ] ],
      [ "Files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md418", [
        [ "Other files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md419", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md420", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md421", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md422", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md423", null ],
      [ "See also", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md424", null ]
    ] ],
    [ "query — XRootD <tt>kXR_query</tt> sub-protocol, <tt>kXR_prepare</tt> staging, and <tt>kXR_set</tt> hints", "md_src_2protocols_2root_2query_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2query_2README.html#autotoc_md426", null ],
      [ "Files", "md_src_2protocols_2root_2query_2README.html#autotoc_md427", [
        [ "Other files", "md_src_2protocols_2root_2query_2README.html#autotoc_md428", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2query_2README.html#autotoc_md429", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2query_2README.html#autotoc_md430", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2query_2README.html#autotoc_md431", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2query_2README.html#autotoc_md432", null ],
      [ "See also", "md_src_2protocols_2root_2query_2README.html#autotoc_md433", null ]
    ] ],
    [ "read — XRootD read-side opcodes and the file-handle lifecycle", "md_src_2protocols_2root_2read_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2read_2README.html#autotoc_md435", null ],
      [ "Files", "md_src_2protocols_2root_2read_2README.html#autotoc_md436", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2read_2README.html#autotoc_md437", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2read_2README.html#autotoc_md438", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2read_2README.html#autotoc_md439", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2read_2README.html#autotoc_md440", null ],
      [ "See also", "md_src_2protocols_2root_2read_2README.html#autotoc_md441", null ]
    ] ],
    [ "root — the XRootD (<tt>root://</tt> / <tt>roots://</tt>) protocol plane", "md_src_2protocols_2root_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2README.html#autotoc_md443", null ],
      [ "Subdirectories", "md_src_2protocols_2root_2README.html#autotoc_md444", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2README.html#autotoc_md445", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2README.html#autotoc_md446", null ],
      [ "See also", "md_src_2protocols_2root_2README.html#autotoc_md447", null ]
    ] ],
    [ "relay — transparent pass-through relay with a passive observation tap", "md_src_2protocols_2root_2relay_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2relay_2README.html#autotoc_md449", null ],
      [ "Files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md450", [
        [ "Other files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md451", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2relay_2README.html#autotoc_md452", null ],
      [ "See also", "md_src_2protocols_2root_2relay_2README.html#autotoc_md453", null ]
    ] ],
    [ "response — XRootD wire-response framing helpers", "md_src_2protocols_2root_2response_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2response_2README.html#autotoc_md455", null ],
      [ "Files", "md_src_2protocols_2root_2response_2README.html#autotoc_md456", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2response_2README.html#autotoc_md457", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2response_2README.html#autotoc_md458", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2response_2README.html#autotoc_md459", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2response_2README.html#autotoc_md460", null ],
      [ "See also", "md_src_2protocols_2root_2response_2README.html#autotoc_md461", null ]
    ] ],
    [ "session — XRootD session lifecycle, identity binding & cross-worker registry", "md_src_2protocols_2root_2session_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2session_2README.html#autotoc_md463", null ],
      [ "Files", "md_src_2protocols_2root_2session_2README.html#autotoc_md464", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2session_2README.html#autotoc_md465", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2session_2README.html#autotoc_md466", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2session_2README.html#autotoc_md467", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2session_2README.html#autotoc_md468", null ],
      [ "See also", "md_src_2protocols_2root_2session_2README.html#autotoc_md469", null ]
    ] ],
    [ "stream — <tt>ngx_stream_brix_module</tt> descriptor & directive table", "md_src_2protocols_2root_2stream_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2stream_2README.html#autotoc_md471", null ],
      [ "Files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md472", [
        [ "Other files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md473", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2stream_2README.html#autotoc_md474", [
        [ "Directive groups (authoritative <tt>module.c</tt> set)", "md_src_2protocols_2root_2stream_2README.html#autotoc_md475", null ]
      ] ],
      [ "Control & data flow", "md_src_2protocols_2root_2stream_2README.html#autotoc_md476", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2stream_2README.html#autotoc_md477", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2stream_2README.html#autotoc_md478", null ],
      [ "See also", "md_src_2protocols_2root_2stream_2README.html#autotoc_md479", null ]
    ] ],
    [ "write — XRootD mutating-opcode handlers (the stream write path)", "md_src_2protocols_2root_2write_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2write_2README.html#autotoc_md481", null ],
      [ "Files", "md_src_2protocols_2root_2write_2README.html#autotoc_md482", [
        [ "Other files", "md_src_2protocols_2root_2write_2README.html#autotoc_md483", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2write_2README.html#autotoc_md484", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2write_2README.html#autotoc_md485", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2write_2README.html#autotoc_md486", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2write_2README.html#autotoc_md487", null ],
      [ "See also", "md_src_2protocols_2root_2write_2README.html#autotoc_md488", null ]
    ] ],
    [ "src/protocols/root/zip — ZIP member access (phase-57 W2)", "md_src_2protocols_2root_2zip_2README.html", [
      [ "Status", "md_src_2protocols_2root_2zip_2README.html#autotoc_md490", null ],
      [ "zip_dir.c — the parser", "md_src_2protocols_2root_2zip_2README.html#autotoc_md491", null ],
      [ "Running the unit test (standalone, no nginx build)", "md_src_2protocols_2root_2zip_2README.html#autotoc_md492", null ]
    ] ],
    [ "rpm — the RPM/dnf pull-through mirror (phase-104 D11 / D15.9)", "md_src_2protocols_2rpm_2README.html", [
      [ "Overview", "md_src_2protocols_2rpm_2README.html#autotoc_md494", null ],
      [ "Files", "md_src_2protocols_2rpm_2README.html#autotoc_md495", null ],
      [ "Gating and invariants", "md_src_2protocols_2rpm_2README.html#autotoc_md496", null ],
      [ "See also", "md_src_2protocols_2rpm_2README.html#autotoc_md497", null ]
    ] ],
    [ "s3 — S3-compatible REST endpoint over the local export root", "md_src_2protocols_2s3_2README.html", [
      [ "Overview", "md_src_2protocols_2s3_2README.html#autotoc_md499", null ],
      [ "Files", "md_src_2protocols_2s3_2README.html#autotoc_md500", [
        [ "Other files", "md_src_2protocols_2s3_2README.html#autotoc_md501", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2s3_2README.html#autotoc_md502", null ],
      [ "Control & data flow", "md_src_2protocols_2s3_2README.html#autotoc_md503", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2s3_2README.html#autotoc_md504", null ],
      [ "Entry points / extending", "md_src_2protocols_2s3_2README.html#autotoc_md505", null ],
      [ "See also", "md_src_2protocols_2s3_2README.html#autotoc_md506", null ]
    ] ],
    [ "shared — cross-protocol helper library (HTTP file serving + overflow-safe size math)", "md_src_2protocols_2shared_2README.html", [
      [ "Overview", "md_src_2protocols_2shared_2README.html#autotoc_md508", null ],
      [ "Files", "md_src_2protocols_2shared_2README.html#autotoc_md509", null ],
      [ "Key types & data structures", "md_src_2protocols_2shared_2README.html#autotoc_md510", null ],
      [ "Control & data flow", "md_src_2protocols_2shared_2README.html#autotoc_md511", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2shared_2README.html#autotoc_md512", null ],
      [ "Entry points / extending", "md_src_2protocols_2shared_2README.html#autotoc_md513", null ],
      [ "See also", "md_src_2protocols_2shared_2README.html#autotoc_md514", null ]
    ] ],
    [ "<tt>src/protocols/srr/</tt> — WLCG Storage Resource Reporting (SRR) endpoint", "md_src_2protocols_2srr_2README.html", [
      [ "Why this instead of the XRootD UDP monitoring stack", "md_src_2protocols_2srr_2README.html#autotoc_md516", null ],
      [ "Files", "md_src_2protocols_2srr_2README.html#autotoc_md517", null ],
      [ "Configuration", "md_src_2protocols_2srr_2README.html#autotoc_md518", null ],
      [ "Semantics & caveats", "md_src_2protocols_2srr_2README.html#autotoc_md519", null ],
      [ "Schema conformance", "md_src_2protocols_2srr_2README.html#autotoc_md520", null ]
    ] ],
    [ "<tt>src/protocols/ssi/</tt> — XrdSsi request/response service over <tt>root://</tt>", "md_src_2protocols_2ssi_2README.html", [
      [ "Overview", "md_src_2protocols_2ssi_2README.html#autotoc_md522", null ],
      [ "Phase 1: session multiplexing (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md523", null ],
      [ "Phase 2: async server-push via <tt>kXR_attn</tt> (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md524", null ],
      [ "Phase 3: streamed responses + delivered alerts (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md525", null ],
      [ "Phases 4–5: CTA flagship service (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md526", null ],
      [ "Phase 6: config, metrics, conformance (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md527", [
        [ "Directives (<tt>NGX_STREAM_SRV_CONF</tt>)", "md_src_2protocols_2ssi_2README.html#autotoc_md528", null ],
        [ "Metrics (low-cardinality — <tt>{port,auth}</tt> only)", "md_src_2protocols_2ssi_2README.html#autotoc_md529", null ],
        [ "Conformance", "md_src_2protocols_2ssi_2README.html#autotoc_md530", null ]
      ] ],
      [ "RRInfo wire layout", "md_src_2protocols_2ssi_2README.html#autotoc_md531", null ],
      [ "Files", "md_src_2protocols_2ssi_2README.html#autotoc_md532", [
        [ "Other files", "md_src_2protocols_2ssi_2README.html#autotoc_md533", null ]
      ] ],
      [ "See also", "md_src_2protocols_2ssi_2README.html#autotoc_md534", null ]
    ] ],
    [ "<tt>src/protocols/ssi/svc_cta/</tt> — flagship CTA tape service", "md_src_2protocols_2ssi_2svc__cta_2README.html", [
      [ "Layers", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md536", null ],
      [ "Request lifecycle", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md537", [
        [ "State machine", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md538", null ],
        [ "Executor", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md539", null ],
        [ "Security", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md540", null ],
        [ "Journal (restart recovery)", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md541", null ]
      ] ],
      [ "External contract — the pinned field table", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md542", null ],
      [ "Golden-vector provenance", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md543", null ],
      [ "Scope notes", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md544", [
        [ "Other files", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md545", null ]
      ] ]
    ] ],
    [ "webdav/fs — Confined local-filesystem copy engine for WebDAV COPY/MOVE", "md_src_2protocols_2webdav_2fs_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md547", null ],
      [ "Files", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md548", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md549", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md550", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md551", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md552", null ],
      [ "See also", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md553", null ]
    ] ],
    [ "webdav/locks — WebDAV LOCK request-header & body parsers", "md_src_2protocols_2webdav_2locks_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md555", null ],
      [ "Files", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md556", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md557", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md558", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md559", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md560", null ],
      [ "See also", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md561", null ]
    ] ],
    [ "webdav/methods — Per-method WebDAV precondition helpers", "md_src_2protocols_2webdav_2methods_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md563", null ],
      [ "Files", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md564", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md565", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md566", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md567", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md568", null ],
      [ "See also", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md569", null ]
    ] ],
    [ "webdav — HTTP/WebDAV/HTTPS gateway (<tt>davs://</tt>, <tt>http://</tt>) over the export root", "md_src_2protocols_2webdav_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2README.html#autotoc_md571", null ],
      [ "Files", "md_src_2protocols_2webdav_2README.html#autotoc_md572", [
        [ "Module wiring & configuration", "md_src_2protocols_2webdav_2README.html#autotoc_md573", null ],
        [ "Dispatch & generic helpers", "md_src_2protocols_2webdav_2README.html#autotoc_md574", null ],
        [ "HTTP method handlers", "md_src_2protocols_2webdav_2README.html#autotoc_md575", null ],
        [ "Authentication", "md_src_2protocols_2webdav_2README.html#autotoc_md576", null ],
        [ "HTTP-TPC (third-party copy)", "md_src_2protocols_2webdav_2README.html#autotoc_md577", null ],
        [ "Dynamic backend pool (admin API)", "md_src_2protocols_2webdav_2README.html#autotoc_md578", null ],
        [ "XrdHttp protocol extension", "md_src_2protocols_2webdav_2README.html#autotoc_md579", null ],
        [ "Other files", "md_src_2protocols_2webdav_2README.html#autotoc_md580", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2README.html#autotoc_md581", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2README.html#autotoc_md582", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2README.html#autotoc_md583", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2README.html#autotoc_md584", null ],
      [ "See also", "md_src_2protocols_2webdav_2README.html#autotoc_md585", null ]
    ] ],
    [ "webdav/util — WebDAV URI decoding and XML escaping helpers", "md_src_2protocols_2webdav_2util_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md587", null ],
      [ "Files", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md588", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md589", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md590", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md591", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md592", null ],
      [ "See also", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md593", null ]
    ] ],
    [ "src — nginx-xrootd Source Tree", "md_src_2README.html", [
      [ "Source map", "md_src_2README.html#autotoc_md596", [
        [ "Top-level files (now under <tt>core/</tt>)", "md_src_2README.html#autotoc_md597", null ],
        [ "Entry & dispatch", "md_src_2README.html#autotoc_md598", null ],
        [ "Protocol handlers", "md_src_2README.html#autotoc_md599", null ],
        [ "Data plane", "md_src_2README.html#autotoc_md600", null ],
        [ "Path & confinement", "md_src_2README.html#autotoc_md601", null ],
        [ "Authentication", "md_src_2README.html#autotoc_md602", null ],
        [ "Cluster & federation", "md_src_2README.html#autotoc_md603", null ],
        [ "Cross-cutting", "md_src_2README.html#autotoc_md604", null ],
        [ "WebDAV sub-helpers", "md_src_2README.html#autotoc_md605", null ]
      ] ],
      [ "The four request lifecycles", "md_src_2README.html#autotoc_md607", [
        [ "<tt>root://</tt> stream", "md_src_2README.html#autotoc_md608", null ],
        [ "<tt>davs://</tt> WebDAV", "md_src_2README.html#autotoc_md609", null ],
        [ "S3 REST", "md_src_2README.html#autotoc_md610", null ],
        [ "CMS cluster redirect", "md_src_2README.html#autotoc_md611", null ]
      ] ],
      [ "Cross-cutting invariants", "md_src_2README.html#autotoc_md613", null ],
      [ "How to navigate / where to start reading", "md_src_2README.html#autotoc_md615", null ]
    ] ],
    [ "tpc/common — Protocol-neutral third-party-copy (TPC) core", "md_src_2tpc_2common_2README.html", [
      [ "Overview", "md_src_2tpc_2common_2README.html#autotoc_md617", null ],
      [ "Files", "md_src_2tpc_2common_2README.html#autotoc_md618", null ],
      [ "Key types & data structures", "md_src_2tpc_2common_2README.html#autotoc_md619", null ],
      [ "Control & data flow", "md_src_2tpc_2common_2README.html#autotoc_md620", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2common_2README.html#autotoc_md621", null ],
      [ "Entry points / extending", "md_src_2tpc_2common_2README.html#autotoc_md622", null ],
      [ "See also", "md_src_2tpc_2common_2README.html#autotoc_md623", null ]
    ] ],
    [ "engine — native-TPC control plane (destination side)", "md_src_2tpc_2engine_2README.html", [
      [ "Overview", "md_src_2tpc_2engine_2README.html#autotoc_md625", null ],
      [ "Files", "md_src_2tpc_2engine_2README.html#autotoc_md626", [
        [ "Other files", "md_src_2tpc_2engine_2README.html#autotoc_md627", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2engine_2README.html#autotoc_md628", null ],
      [ "See also", "md_src_2tpc_2engine_2README.html#autotoc_md629", null ]
    ] ],
    [ "gsi — outbound GSI authentication for the TPC pull socket", "md_src_2tpc_2gsi_2README.html", [
      [ "Overview", "md_src_2tpc_2gsi_2README.html#autotoc_md631", null ],
      [ "Files", "md_src_2tpc_2gsi_2README.html#autotoc_md632", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2gsi_2README.html#autotoc_md633", null ],
      [ "See also", "md_src_2tpc_2gsi_2README.html#autotoc_md634", null ]
    ] ],
    [ "outbound — the blocking source-session client for native TPC pulls", "md_src_2tpc_2outbound_2README.html", [
      [ "Overview", "md_src_2tpc_2outbound_2README.html#autotoc_md636", null ],
      [ "Files", "md_src_2tpc_2outbound_2README.html#autotoc_md637", [
        [ "Other files", "md_src_2tpc_2outbound_2README.html#autotoc_md638", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2outbound_2README.html#autotoc_md639", null ],
      [ "See also", "md_src_2tpc_2outbound_2README.html#autotoc_md640", null ]
    ] ],
    [ "tpc — Native XRootD third-party-copy (destination-side pull)", "md_src_2tpc_2README.html", [
      [ "Overview", "md_src_2tpc_2README.html#autotoc_md642", null ],
      [ "Files", "md_src_2tpc_2README.html#autotoc_md643", null ],
      [ "Key types & data structures", "md_src_2tpc_2README.html#autotoc_md644", null ],
      [ "Control & data flow", "md_src_2tpc_2README.html#autotoc_md645", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2README.html#autotoc_md646", null ],
      [ "Entry points / extending", "md_src_2tpc_2README.html#autotoc_md647", null ],
      [ "See also", "md_src_2tpc_2README.html#autotoc_md648", null ]
    ] ],
    [ "<tt>client/apps/</tt> — native client CLI tools", "md_client_2apps_2README.html", [
      [ "Data movement", "md_client_2apps_2README.html#autotoc_md650", null ],
      [ "Checksums & verification", "md_client_2apps_2README.html#autotoc_md651", null ],
      [ "Diagnostics & monitoring", "md_client_2apps_2README.html#autotoc_md652", null ],
      [ "Auth & security", "md_client_2apps_2README.html#autotoc_md653", null ],
      [ "Namespace / staging", "md_client_2apps_2README.html#autotoc_md654", null ],
      [ "Optional (built only when <tt>libfuse3</tt> is present — not in <tt>BINS</tt>)", "md_client_2apps_2README.html#autotoc_md655", null ],
      [ "Ceph operator tools (<tt>apps/ceph/</tt> — built only when the Ceph dev headers are present)", "md_client_2apps_2README.html#autotoc_md656", null ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2apps_2README.html#autotoc_md657", null ],
      [ "Man pages & bash completion", "md_client_2apps_2README.html#autotoc_md658", null ],
      [ "CLI compatibility contract (binding for all flag/env/output work)", "md_client_2apps_2README.html#autotoc_md659", null ],
      [ "See also", "md_client_2apps_2README.html#autotoc_md660", null ]
    ] ],
    [ "<tt>client/lib/sec/</tt> — native client authentication modules", "md_client_2lib_2auth_2sec_2README.html", [
      [ "Overview", "md_client_2lib_2auth_2sec_2README.html#autotoc_md662", null ],
      [ "Files", "md_client_2lib_2auth_2sec_2README.html#autotoc_md663", null ],
      [ "Invariants", "md_client_2lib_2auth_2sec_2README.html#autotoc_md664", null ],
      [ "See also", "md_client_2lib_2auth_2sec_2README.html#autotoc_md665", null ]
    ] ],
    [ "<tt>client/lib/</tt> — native XRootD client library (<tt>libbrix</tt>)", "md_client_2lib_2README.html", [
      [ "Concept buckets (phase-69)", "md_client_2lib_2README.html#autotoc_md667", null ],
      [ "File responsibilities (Phase-38 split groups)", "md_client_2lib_2README.html#autotoc_md668", [
        [ "Other files", "md_client_2lib_2README.html#autotoc_md669", null ]
      ] ]
    ] ],
    [ "<tt>client/preload/</tt> — LD_PRELOAD POSIX → XRootD shim", "md_client_2preload_2README.html", [
      [ "Overview", "md_client_2preload_2README.html#autotoc_md671", null ],
      [ "How it works", "md_client_2preload_2README.html#autotoc_md672", null ],
      [ "Scope", "md_client_2preload_2README.html#autotoc_md673", null ],
      [ "Files", "md_client_2preload_2README.html#autotoc_md674", null ],
      [ "See also", "md_client_2preload_2README.html#autotoc_md675", null ]
    ] ],
    [ "<tt>client/</tt> — native BriX client tools", "md_client_2README.html", [
      [ "Directory layout", "md_client_2README.html#autotoc_md677", null ],
      [ "Build", "md_client_2README.html#autotoc_md678", null ],
      [ "Feature summary (2026-07-05)", "md_client_2README.html#autotoc_md679", [
        [ "xrdcp", "md_client_2README.html#autotoc_md680", null ],
        [ "xrdfs", "md_client_2README.html#autotoc_md681", null ],
        [ "xrdcksum", "md_client_2README.html#autotoc_md682", null ],
        [ "xrddiag", "md_client_2README.html#autotoc_md683", null ],
        [ "Ceph operator tools", "md_client_2README.html#autotoc_md684", null ]
      ] ],
      [ "Configuration — <tt>~/.xrdrc</tt>", "md_client_2README.html#autotoc_md685", null ],
      [ "Man pages & bash completion", "md_client_2README.html#autotoc_md686", null ],
      [ "See also", "md_client_2README.html#autotoc_md687", null ]
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
"__brix__net__ext_8h.html",
"aio__engine__cqe_8c_source.html",
"api__snapshot_8c.html#a2b420c29a522c98e604f04b915c918a2",
"auth_2protbind_2config_8c.html#ae87cae79b046bd982a6550d5ffdba8d2",
"authdb__parse_8c.html#ab62bc4d025bf2e0b1d81963db0a2f106",
"bind__migrate_8c_source.html",
"brix__fault__ext_8c.html#aaa42b09a1dcc09a4e4a17e4e0a23f1c0",
"brix__fault__proxy__json_8c.html#a85d5995f0eb64cba872653f04225ccab",
"brix__fault__replay_8c.html#aa69cf42b6216c9e2beea9b801d1fb320",
"brix__ops_8h.html#a72bfca5a66cf7bce22caa47bac639cc3",
"brixcvmfs__ingest__image_8c.html#af33c2913ab434111028574054707cf33",
"brixcvmfs__rw__ext_8c.html#a5149e9fff7f84646389d9597ec2a85df",
"brixposix__preload_8c.html#aafbcde67669a1b96577e735ddebd8634",
"cache__admit_8h.html#ada93982f9cdf1874f4195c300cbd5e12",
"checksum_8h.html#a07e6e7aacbcd45889ed3021a6ac373b9a399921aa1a97b7ef673ff2109ca8b406",
"cks__verify_8c.html#a7b0dbc5dc74bb349dbebc8441a55c973",
"client_2lib_2xfer_2copy_8c.html#af1d153b01b49223f4842756467bfbc1f",
"cms__internal_8h.html#ac5896cd7345a9bcccd469734f6c8ab56",
"conf__structs_8h.html#a0009d996d829b837709e140bd9f58316",
"copy__engine_8h_source.html",
"core_2aio_2write_8c.html#ac053d8cd563d71903be1b39541f4430d",
"cred__mint__internal_8h.html#a1cd91990d71e21e7e5cbefd394547015",
"cstore_8c.html#ada86e75d6750996a12aeb75437d5cb55",
"cvmfs_8h.html#a42efcd26a81f76e7899e5ea502e32640",
"dashboard__http_8h.html#a4711a5b9f875d4cfbee9ac04627c9ce7",
"diag__check_8c.html#aa5c973039e7f7f799f5d7a2b0f0c4850",
"diag__doctor__latency__unittest_8c.html#a369266c24eacffb87046522897a570d5",
"diag__misc_8c.html#aef689df7dfb41d4b586a530604444bbf",
"dir_c72b25b75abe208498b36a3e44a3726c.html",
"events__bootstrap__auth_8c.html#ae1aba67ff12c708818cac31273c55102",
"file__serve_8c.html#a7580f2aa926c217199c866f65036b97b",
"forward__relay__response__lazy_8c.html#abee49d557c23eb1998f4a225917d11f4",
"fs__list_8h.html#ad6b5c47182a5e6e0be76ab031d46a845a45c6af21d4630196698d68d6a263203c",
"ftp__ev__io_8c.html",
"fuse__ops_8c.html#ab6bbf0eca81c570163081c781cfa55c9",
"globals_defs_k.html",
"gsi__core_8h.html#ada5598cc519b3ca91b5cbc3cb793ff42",
"guard__ruleset_8c.html",
"http__body_8h.html#abd90f7ea078fc227c986f555b3e9078d",
"http__mirror_8c.html",
"identity_8h.html#a2f6ae2b7c9d76c959903009dcbd86ce3",
"io__monitor_8h.html#ac22fbb3c975f941972ec32628f7634c7",
"kv__config_8c.html#a67d25e5fce3a407cb4bb3853fc3804eb",
"list__common_8c.html#af5fdc8846c0410c5097e8aab8d1c96d9",
"macaroon__internal_8h_source.html",
"md_src_2core_2http_2README.html#autotoc_md129",
"md_src_2protocols_2root_2connection_2README.html#autotoc_md377",
"merge__export_8c_source.html",
"metrics__internal_8h.html",
"mirror__common_8h.html#a56006567b3fbd5ffe06a71aa6b851446",
"namespace__ops__copy_8c.html#a758c1ec53838b9e3e8deda2140f147e0",
"net__target__dns_8c.html#aedbe639a61206d35b0d8f247928a9097",
"object_8c.html#acf38a840346283033bdfaf131e8fe8cd",
"observability_2metrics_2unified_8h.html#a74d1440f12b6d53aafff8fe47377350f",
"oci__gc_8c.html#af61a8b8773989ea4f14eb3e3b198e379",
"oci__upstream__auth_8c.html#abb8d0d27b489a641edc397a5e584129b",
"opcodes_8h.html#af66010c45311c44bcef72b3191531b72",
"ops__meta_8c.html#ac5b344ebd8aaf06716ad227bdf27a866",
"overlay__unittest_8c.html#a840291bc02cba5474a4cb46a9b9566fe",
"pblock__refs_8h.html#a122b501e0195bdf8b479c36a470b1cef",
"pgwrite_8c.html#a6422248518099a58ee81f9499a07bafe",
"prepare__cmd_8c.html#ac0fb6d48028f7ec331c7d6b2ef70ef80",
"protbind_8h.html#a251acbe6990c7303f086524d2ae73d51",
"protocols_2root_2stream_2module_8c.html#a458030812f5e03ab5c0ec3743448e9d9",
"provider__unittest_8c.html#a1901adb94fd0de553ba236fc3fe0c3d4",
"put__internal_8h.html#a529c74a319142e8414ac1b34a236b790",
"ratelimit__zone_8c.html#a489f737191456eac2f83aa1b56c57dbd",
"ref_8c.html#a12db58dcdf8d804a33b5fdec0863da3d",
"reqid__map_8c_source.html",
"root_2session_2protocol_8c_source.html",
"rrdata__unittest_8c.html#a14b9fe617e435e9038a80fbaa64bb571",
"s3__put__internal_8h.html#a96c091def73e99ca966bb70b952f6b73",
"scopes_8c.html#a8282efb3769a62f02766535cf2f644c0",
"sd__cache__internal_8h.html#a22ba5f8cae0bac5bfd225d4698f5f64a",
"sd__frm_8c.html#aa7112783b2a30c618408bf1ce0bcdb99",
"sd__gsiftp__staged_8c_source.html",
"sd__http__xattr_8c.html#a3e783459d90a727d8a60da7d2921902c",
"sd__pblock__unittest__block_8c.html#a869da0fe15c8ec333db56247bf94a0e6",
"sd__registry_8c.html#af8a058ea090c61cc140ca177e21572a4",
"sd__s3__internal_8h.html#a3ef1c585355c55ac6c05bf8ade9543ef",
"sd__xroot__internal_8h.html#a0de7ff6ced3d855cf1b41c494088aa19",
"seccomp__core_8h.html#a3e2bc5128d662b3bbdc32c6793aa1552",
"server__send_8c.html#a9003f0125034d670ed3cada345ebd5fc",
"shared__conf__fields_8h.html#a0d24b455c4b2d67f893cd0afcb28812a",
"sock_8c.html#ab849f69b357f1e75e8d2c8ecc3950d34",
"src_2fs_2vfs_2vfs_8h.html#af2225adb5908fcee7e0f117ce6b70766",
"srv__conf__fields__cache_8h.html#ae7d4720f737cb0a664376bcfe4f7e57a",
"sss__keytab_8h.html#a8953ac1839d6c8894fb3ed81e9bdaa5e",
"staged__file_8c.html#a6dd07dc3c045808d56c91e8cfd64bb49",
"store__policy_8h.html#a65a8e67a68aca1da1c6535c1f2d28038",
"stream__wmirror_8c.html#a0285a30a175c26a643d4eb4773614bc8",
"structClientSetRequest.html#afb5f7c7a0b8c6da266967cfbce3df5c8",
"structbdg__ctx.html#ada3e9cb1f112a8b6946a5bc511cbc4fe",
"structbrix__authdb__query__t.html#a0b6fcc0e1e93f832298af98d1728e866",
"structbrix__cache__policy__t.html#aedb91dbb51523159b1d3a1defec35b04",
"structbrix__cms__srv__ctx__t.html#a1a697f424eeb95c4101251dea8700b48",
"structbrix__cta__queue__t.html#aeefb3ba632676c428bf23c2ba60f0c4d",
"structbrix__cvmfs__conf__t.html#a715f0189d4acf49e6eb589f2b3877745",
"structbrix__file__t.html#a81117098e52477e58923222d2881d38e",
"structbrix__http__cache__fill__ctx__t.html#a85061bce383d9b2619a1901e4797f019",
"structbrix__loc__entry__t.html#a0a9800b68f79c14bbdc01081fa28daed",
"structbrix__oci__reg__t.html#a0a496a252f4c84e7ca3a67a4a0ba257b",
"structbrix__phase__timer__t.html#abd648db94faac8b6a319193ff9356890",
"structbrix__proxy__fh__entry__t.html#aceb78a8d2d00d297c06973415f31bad4",
"structbrix__s3__resp__t.html#a559aa33209e5300c932869adc4080826",
"structbrix__sd__stat__t.html#ab2279e75b065455107707c4aeb4c78c5",
"structbrix__ssi__req__t.html#a61bd5e8c6004a59dbedc2c01bc810e49",
"structbrix__tier__stack__t.html#ac000a7dd9c20493a0331f87773e025e2",
"structbrix__upstream__s.html#a7c435d85a874bdc2f0c74611a15caa9c",
"structbrix__vfs__ops.html#ae944644f7046ffdd8e73e3b428b78107",
"structbrix__wt__flush__t.html#a316b219bd5d90a5a99208b903ad7e5be",
"structcephfsro__state__t.html#a9118c3797f42267a625594a9a96d149a",
"structcta__req__t.html#a62836cdaab65c696309e5110d918743c",
"structdashboard__xfer__snapshot__t.html#a487c518da42ff1056b5eb5f4d7e6ad63",
"structdx__rule.html#a328a948365fe07f59481bc12e591097b",
"structfp__udp__cfg.html#a4f3e109b4cbc64b0c7ca72857816181e",
"structgsi__cresp__state__t.html#a7db6f44cc2f4db730c042ae8b1398607",
"structlever__t.html#a3cff87060edc023402af1513d620ced0",
"structngx__brix__cms__ctx__s.html#a94cd9fab0979c3327887a6fcc0548708",
"structngx__brix__unified__metrics__t.html#a4a8afea38e8750c108cb11c261c9f6e7",
"structngx__http__brix__webdav__loc__conf__t.html#a633df2bb2432a54780b3ca4566a7aeae",
"structpblock__lock__rng__t.html#ac632fdec49eaa2f40ceaa4b4fb5c7222",
"structpump__remote__t.html",
"structs3__get__reenter__t.html#ac2360915bae1b628dc4137e4ea8baaad",
"structsd__cache__fill__state__t.html#a65f964405bcbf704bcad91dcd2612bdc",
"structsd__s3__meta__buf.html#a10f669e1968db2f80db37a9accb051f9",
"structstorascan__bench__result.html#a0a1a9a233883fea896cdf133a42e2885",
"structu32__walk__t.html#a7626b1eb67b7cda67d366084d806aa87",
"structwebdav__lock__walk__t.html#a68349e61f011b6f4528a9267f211066b",
"structxmeta__state__wire__t.html#acd3ada5a19ef5c2e803d9a32339b9807",
"structxrdw__protocol__req__t.html#a3eab3f94c4bd5612613554b57f5ced4c",
"tagging_8h.html#a3167fea7d81d4b674938f1f44f565626",
"tmp__path_8h.html",
"tpc__curl__internal_8h.html#aeb3967f4e60ee4ee8d421e5531e396cd",
"transport_8h.html#a8cd640f8b8a9ec148578ebfe7088b03da6d0c1d59e352bbc92041a51e0a6b4582",
"upstream__internal_8h.html#a1a37ecdc99deb7901368ebd66bb04c12",
"vfs__authz__bind_8c.html#a43c97e0d4f7dcb10cb5a5831cbb55c73",
"vfs__cred_8c.html#ad81cd48480f2aff343101acc3e58a50e",
"vfs__ops_8h.html#a2359ff9ed7968c92e02ea1a45aa0abd0",
"vfs__staged_8c.html#a4c68d63ae0d9bf95a8775ddb81f9bca7",
"webdav_2dispatch_8c.html#a0ff7a56b6ec86c1acc71613ac53fedea",
"webfile__io_8c.html#ac9c8d453976d7d4eebf09409317b1064",
"write_8h.html",
"xfer__resume__sweep_8c.html#ab95d9284acbf75b605f299f05bb25e83",
"xrd__clockskew_8c.html#a97bef057ad9f22e76a3cd2776ea3b2d5",
"xrdcp__internal_8h.html#a24c06f82fc52ea926ddb2359340e527a",
"xrdfs__internal_8h.html#a3f84bd65b5ad6a32856356f82ba85723",
"xrdmapc_8c.html#a74029f5ddf259bc6930ec5801a25357c",
"xrootdfs__legacy_8c.html#a16ce69fd578c2a3929a7c1f00c34bf8a",
"zip__kernel_8c.html#a426acfc925d25f7e1af948c8700c8a39"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';