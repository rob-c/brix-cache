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
    [ "voms — VO / FQAN extraction from verified X.509 proxies (native verifier)", "md_src_2auth_2voms_2README.html", [
      [ "Overview", "md_src_2auth_2voms_2README.html#autotoc_md86", null ],
      [ "Files", "md_src_2auth_2voms_2README.html#autotoc_md87", null ],
      [ "Key types & data structures", "md_src_2auth_2voms_2README.html#autotoc_md88", null ],
      [ "Control & data flow", "md_src_2auth_2voms_2README.html#autotoc_md89", null ],
      [ "Invariants, security & gotchas", "md_src_2auth_2voms_2README.html#autotoc_md90", null ],
      [ "Entry points / extending", "md_src_2auth_2voms_2README.html#autotoc_md91", null ],
      [ "See also", "md_src_2auth_2voms_2README.html#autotoc_md92", null ]
    ] ],
    [ "aio — Thread-pool async file I/O and shared response-chain builders", "md_src_2core_2aio_2README.html", [
      [ "Overview", "md_src_2core_2aio_2README.html#autotoc_md94", null ],
      [ "Optional io_uring backend (Phase 44 — <tt>uring.c</tt> / <tt>uring_submit.c</tt> / <tt>uring_admin.c</tt>)", "md_src_2core_2aio_2README.html#autotoc_md95", null ],
      [ "Thread-pool contract", "md_src_2core_2aio_2README.html#autotoc_md96", null ],
      [ "Files", "md_src_2core_2aio_2README.html#autotoc_md97", [
        [ "Other files", "md_src_2core_2aio_2README.html#autotoc_md98", null ]
      ] ],
      [ "Key types & data structures", "md_src_2core_2aio_2README.html#autotoc_md99", null ],
      [ "Control & data flow", "md_src_2core_2aio_2README.html#autotoc_md100", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2aio_2README.html#autotoc_md101", null ],
      [ "Entry points / extending", "md_src_2core_2aio_2README.html#autotoc_md102", null ],
      [ "See also", "md_src_2core_2aio_2README.html#autotoc_md103", null ]
    ] ],
    [ "compat — Cross-protocol shared primitives (checksums, paths, filesystem, SSRF)", "md_src_2core_2compat_2README.html", [
      [ "Overview", "md_src_2core_2compat_2README.html#autotoc_md105", null ],
      [ "Files", "md_src_2core_2compat_2README.html#autotoc_md106", [
        [ "Checksums & hex", "md_src_2core_2compat_2README.html#autotoc_md107", null ],
        [ "HTTP-adjacent primitives", "md_src_2core_2compat_2README.html#autotoc_md108", null ],
        [ "Filesystem & namespace mutation", "md_src_2core_2compat_2README.html#autotoc_md109", null ],
        [ "Networking, async, time, logging, SHM", "md_src_2core_2compat_2README.html#autotoc_md110", null ],
        [ "Other files", "md_src_2core_2compat_2README.html#autotoc_md111", null ]
      ] ],
      [ "Key types & data structures", "md_src_2core_2compat_2README.html#autotoc_md112", null ],
      [ "Control & data flow", "md_src_2core_2compat_2README.html#autotoc_md113", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2compat_2README.html#autotoc_md114", null ],
      [ "Entry points / extending", "md_src_2core_2compat_2README.html#autotoc_md115", null ],
      [ "See also", "md_src_2core_2compat_2README.html#autotoc_md116", null ]
    ] ],
    [ "config — directive lifecycle, startup validation, and per-worker resource init", "md_src_2core_2config_2README.html", [
      [ "Overview", "md_src_2core_2config_2README.html#autotoc_md118", null ],
      [ "Files", "md_src_2core_2config_2README.html#autotoc_md119", [
        [ "Other files", "md_src_2core_2config_2README.html#autotoc_md120", null ]
      ] ],
      [ "Key types & data structures", "md_src_2core_2config_2README.html#autotoc_md121", null ],
      [ "Control & data flow", "md_src_2core_2config_2README.html#autotoc_md122", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2config_2README.html#autotoc_md123", null ],
      [ "Entry points / extending", "md_src_2core_2config_2README.html#autotoc_md124", null ],
      [ "See also", "md_src_2core_2config_2README.html#autotoc_md125", null ]
    ] ],
    [ "http — Shared HTTP request/response semantics (headers, body, conditionals, ETag)", "md_src_2core_2http_2README.html", [
      [ "Overview", "md_src_2core_2http_2README.html#autotoc_md127", null ],
      [ "Files", "md_src_2core_2http_2README.html#autotoc_md128", null ],
      [ "Boundary — what stays in <tt>../compat</tt>", "md_src_2core_2http_2README.html#autotoc_md129", [
        [ "Other files", "md_src_2core_2http_2README.html#autotoc_md130", null ]
      ] ],
      [ "Control & data flow", "md_src_2core_2http_2README.html#autotoc_md131", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2http_2README.html#autotoc_md132", null ],
      [ "Entry points / extending", "md_src_2core_2http_2README.html#autotoc_md133", null ],
      [ "See also", "md_src_2core_2http_2README.html#autotoc_md134", null ]
    ] ],
    [ "Negative-Path Backoff (negcache)", "md_src_2core_2negcache_2README.html", null ],
    [ "core — platform primitives shared by every plane", "md_src_2core_2README.html", null ],
    [ "Worker seccomp-BPF Syscall Filter", "md_src_2core_2seccomp_2README.html", null ],
    [ "shm — generic cross-worker key/value store and token-bucket rate limiter in nginx shared memory", "md_src_2core_2shm_2README.html", [
      [ "Overview", "md_src_2core_2shm_2README.html#autotoc_md140", null ],
      [ "Files", "md_src_2core_2shm_2README.html#autotoc_md141", [
        [ "Other files", "md_src_2core_2shm_2README.html#autotoc_md142", null ]
      ] ],
      [ "Key types & data structures", "md_src_2core_2shm_2README.html#autotoc_md143", null ],
      [ "Control & data flow", "md_src_2core_2shm_2README.html#autotoc_md144", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2shm_2README.html#autotoc_md145", null ],
      [ "Entry points / extending", "md_src_2core_2shm_2README.html#autotoc_md146", null ],
      [ "See also", "md_src_2core_2shm_2README.html#autotoc_md147", null ]
    ] ],
    [ "src/core/types — Core type definitions, tunables, and the canonical identity object", "md_src_2core_2types_2README.html", [
      [ "Overview", "md_src_2core_2types_2README.html#autotoc_md149", null ],
      [ "Files", "md_src_2core_2types_2README.html#autotoc_md150", null ],
      [ "Key types & data structures", "md_src_2core_2types_2README.html#autotoc_md151", null ],
      [ "Control & data flow", "md_src_2core_2types_2README.html#autotoc_md152", null ],
      [ "Invariants, security & gotchas", "md_src_2core_2types_2README.html#autotoc_md153", null ],
      [ "Entry points / extending", "md_src_2core_2types_2README.html#autotoc_md154", null ],
      [ "See also", "md_src_2core_2types_2README.html#autotoc_md155", null ]
    ] ],
    [ "<tt>src/fs/backend/gsiftp/</tt> — outbound <tt>gsiftp://</tt> storage driver", "md_src_2fs_2backend_2gsiftp_2README.html", [
      [ "Seam", "md_src_2fs_2backend_2gsiftp_2README.html#autotoc_md157", null ],
      [ "Module map", "md_src_2fs_2backend_2gsiftp_2README.html#autotoc_md158", null ]
    ] ],
    [ "fs/backend — Storage Driver (SD) layer", "md_src_2fs_2backend_2README.html", [
      [ "Status — POSIX driver mediates the VFS handle data plane + lifecycle", "md_src_2fs_2backend_2README.html#autotoc_md160", null ],
      [ "Layout — one subdirectory per driver", "md_src_2fs_2backend_2README.html#autotoc_md161", null ],
      [ "Files", "md_src_2fs_2backend_2README.html#autotoc_md162", null ],
      [ "Contract", "md_src_2fs_2backend_2README.html#autotoc_md163", null ],
      [ "Adding a driver", "md_src_2fs_2backend_2README.html#autotoc_md164", [
        [ "Other files", "md_src_2fs_2backend_2README.html#autotoc_md165", null ]
      ] ],
      [ "See also", "md_src_2fs_2backend_2README.html#autotoc_md166", null ]
    ] ],
    [ "<tt>src/fs/cache/origin/</tt> — origin transport + Pelican advertisement for the read-through cache", "md_src_2fs_2cache_2origin_2README.html", [
      [ "Overview", "md_src_2fs_2cache_2origin_2README.html#autotoc_md168", null ],
      [ "Files", "md_src_2fs_2cache_2origin_2README.html#autotoc_md169", null ],
      [ "Invariants", "md_src_2fs_2cache_2origin_2README.html#autotoc_md170", null ],
      [ "See also", "md_src_2fs_2cache_2origin_2README.html#autotoc_md171", null ]
    ] ],
    [ "<tt>src/fs/cache/</tt> — XCache-style read-through cache and write-through origin mirroring", "md_src_2fs_2cache_2README.html", [
      [ "Overview", "md_src_2fs_2cache_2README.html#autotoc_md173", null ],
      [ "Files", "md_src_2fs_2cache_2README.html#autotoc_md174", [
        [ "Read-through entry points & lifecycle", "md_src_2fs_2cache_2README.html#autotoc_md175", null ],
        [ "Cache store adapter & state (phase-64)", "md_src_2fs_2cache_2README.html#autotoc_md176", null ],
        [ "Origin protocol client (thread-pool, blocking)", "md_src_2fs_2cache_2README.html#autotoc_md177", null ],
        [ "Integrity (checksum-on-fill)", "md_src_2fs_2cache_2README.html#autotoc_md178", null ],
        [ "Cache filesystem bookkeeping", "md_src_2fs_2cache_2README.html#autotoc_md179", null ],
        [ "Eviction", "md_src_2fs_2cache_2README.html#autotoc_md180", null ],
        [ "Unified state engine & parity", "md_src_2fs_2cache_2README.html#autotoc_md181", null ],
        [ "Write-through", "md_src_2fs_2cache_2README.html#autotoc_md182", null ],
        [ "Cache storage on a driver (exclusively-VFS)", "md_src_2fs_2cache_2README.html#autotoc_md183", null ],
        [ "Shared / config / build", "md_src_2fs_2cache_2README.html#autotoc_md184", null ],
        [ "Other files", "md_src_2fs_2cache_2README.html#autotoc_md185", null ]
      ] ],
      [ "Key types & data structures", "md_src_2fs_2cache_2README.html#autotoc_md186", null ],
      [ "Control & data flow", "md_src_2fs_2cache_2README.html#autotoc_md187", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2cache_2README.html#autotoc_md188", null ],
      [ "Entry points / extending", "md_src_2fs_2cache_2README.html#autotoc_md189", null ],
      [ "See also", "md_src_2fs_2cache_2README.html#autotoc_md190", null ]
    ] ],
    [ "src/fs/core — the shared <tt>vfs</tt> I/O verb layer", "md_src_2fs_2core_2README.html", null ],
    [ "meta — unified per-file metadata sidecar (xmeta)", "md_src_2fs_2meta_2README.html", [
      [ "Overview", "md_src_2fs_2meta_2README.html#autotoc_md193", null ],
      [ "Files", "md_src_2fs_2meta_2README.html#autotoc_md194", [
        [ "Other files", "md_src_2fs_2meta_2README.html#autotoc_md195", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2fs_2meta_2README.html#autotoc_md196", null ],
      [ "See also", "md_src_2fs_2meta_2README.html#autotoc_md197", null ]
    ] ],
    [ "path — untrusted-path confinement, resolution, ACL/auth gating, and access logging", "md_src_2fs_2path_2README.html", [
      [ "Overview", "md_src_2fs_2path_2README.html#autotoc_md199", null ],
      [ "Files", "md_src_2fs_2path_2README.html#autotoc_md200", [
        [ "Other files", "md_src_2fs_2path_2README.html#autotoc_md201", null ]
      ] ],
      [ "Key types & data structures", "md_src_2fs_2path_2README.html#autotoc_md202", null ],
      [ "Control & data flow", "md_src_2fs_2path_2README.html#autotoc_md203", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2path_2README.html#autotoc_md204", null ],
      [ "Entry points / extending", "md_src_2fs_2path_2README.html#autotoc_md205", null ],
      [ "See also", "md_src_2fs_2path_2README.html#autotoc_md206", null ]
    ] ],
    [ "fs — Unified VFS: the single POSIX-filesystem data plane", "md_src_2fs_2README.html", [
      [ "Overview", "md_src_2fs_2README.html#autotoc_md208", null ],
      [ "Shared with the userland clients: <tt>module→vfs_server→vfs→backend</tt>", "md_src_2fs_2README.html#autotoc_md209", null ],
      [ "Files", "md_src_2fs_2README.html#autotoc_md210", null ],
      [ "Key types & data structures", "md_src_2fs_2README.html#autotoc_md211", null ],
      [ "Control & data flow", "md_src_2fs_2README.html#autotoc_md212", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2README.html#autotoc_md213", null ],
      [ "The CI seam guard (three tiers)", "md_src_2fs_2README.html#autotoc_md214", null ],
      [ "Entry points / extending", "md_src_2fs_2README.html#autotoc_md215", null ],
      [ "See also", "md_src_2fs_2README.html#autotoc_md216", null ]
    ] ],
    [ "<tt>src/fs/scan/</tt> — bulk storage scan / verify / inventory engine", "md_src_2fs_2scan_2README.html", [
      [ "Layering", "md_src_2fs_2scan_2README.html#autotoc_md218", null ],
      [ "Files", "md_src_2fs_2scan_2README.html#autotoc_md219", null ],
      [ "Endpoint", "md_src_2fs_2scan_2README.html#autotoc_md220", null ],
      [ "Status", "md_src_2fs_2scan_2README.html#autotoc_md221", [
        [ "Other files", "md_src_2fs_2scan_2README.html#autotoc_md222", null ]
      ] ]
    ] ],
    [ "tier — composable storage tiers (cache/stage decorators over backends)", "md_src_2fs_2tier_2README.html", [
      [ "Overview", "md_src_2fs_2tier_2README.html#autotoc_md224", null ],
      [ "Files", "md_src_2fs_2tier_2README.html#autotoc_md225", null ],
      [ "Invariants, security & gotchas", "md_src_2fs_2tier_2README.html#autotoc_md226", null ],
      [ "See also", "md_src_2fs_2tier_2README.html#autotoc_md227", null ]
    ] ],
    [ "fs/vfs — the VFS facade (public API + per-op implementations)", "md_src_2fs_2vfs_2README.html", [
      [ "Additional file", "md_src_2fs_2vfs_2README.html#autotoc_md229", [
        [ "Other files", "md_src_2fs_2vfs_2README.html#autotoc_md230", null ]
      ] ]
    ] ],
    [ "<tt>src/fs/xfer/</tt> — unified durable-transfer engine", "md_src_2fs_2xfer_2README.html", [
      [ "Where it sits", "md_src_2fs_2xfer_2README.html#autotoc_md232", null ],
      [ "Files", "md_src_2fs_2xfer_2README.html#autotoc_md233", null ],
      [ "STAGE audit coverage — every upload mode", "md_src_2fs_2xfer_2README.html#autotoc_md234", null ],
      [ "Reload contract (§8b)", "md_src_2fs_2xfer_2README.html#autotoc_md235", [
        [ "The audit line (Phase 2)", "md_src_2fs_2xfer_2README.html#autotoc_md236", null ]
      ] ],
      [ "Durability (spec §7–§8)", "md_src_2fs_2xfer_2README.html#autotoc_md237", [
        [ "Other files", "md_src_2fs_2xfer_2README.html#autotoc_md238", null ]
      ] ]
    ] ],
    [ "admin — the unix control-socket transport shared by every admin plane", "md_src_2net_2admin_2README.html", [
      [ "Overview", "md_src_2net_2admin_2README.html#autotoc_md240", null ],
      [ "Files", "md_src_2net_2admin_2README.html#autotoc_md241", null ],
      [ "The verb-match rule", "md_src_2net_2admin_2README.html#autotoc_md242", null ],
      [ "The reply arena", "md_src_2net_2admin_2README.html#autotoc_md243", null ],
      [ "The privilege boundary, and the audit divergence", "md_src_2net_2admin_2README.html#autotoc_md244", null ],
      [ "Testing", "md_src_2net_2admin_2README.html#autotoc_md245", null ]
    ] ],
    [ "cms — XRootD CMS cluster membership (heartbeat client + manager-side server)", "md_src_2net_2cms_2README.html", [
      [ "Overview", "md_src_2net_2cms_2README.html#autotoc_md247", null ],
      [ "Files", "md_src_2net_2cms_2README.html#autotoc_md248", [
        [ "Heartbeat client (main module)", "md_src_2net_2cms_2README.html#autotoc_md249", null ],
        [ "Shared frame I/O", "md_src_2net_2cms_2README.html#autotoc_md250", null ],
        [ "Manager-side server (<tt>ngx_stream_brix_cms_srv_module</tt>)", "md_src_2net_2cms_2README.html#autotoc_md251", null ],
        [ "Manager namespace/staging planes (phase-89)", "md_src_2net_2cms_2README.html#autotoc_md252", null ],
        [ "Other files", "md_src_2net_2cms_2README.html#autotoc_md253", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2cms_2README.html#autotoc_md254", null ],
      [ "Control & data flow", "md_src_2net_2cms_2README.html#autotoc_md255", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2cms_2README.html#autotoc_md256", null ],
      [ "Entry points / extending", "md_src_2net_2cms_2README.html#autotoc_md257", null ],
      [ "See also", "md_src_2net_2cms_2README.html#autotoc_md258", null ]
    ] ],
    [ "net/dns — runtime DNS (phase 116)", "md_src_2net_2dns_2README.html", null ],
    [ "net/guard — protocol-agnostic bad-actor classifier", "md_src_2net_2guard_2README.html", [
      [ "The <tt>guard_request_t</tt> contract", "md_src_2net_2guard_2README.html#autotoc_md261", null ],
      [ "Audit line (the fail2ban contract)", "md_src_2net_2guard_2README.html#autotoc_md262", null ],
      [ "Wire-level \"not speaking root\" check (<tt>guard_classify_handshake</tt>)", "md_src_2net_2guard_2README.html#autotoc_md263", null ],
      [ "CVMFS forward-proxy abuse check (<tt>signal=proxyabuse</tt>)", "md_src_2net_2guard_2README.html#autotoc_md264", null ],
      [ "CVMFS content-tamper check (<tt>signal=cvmfs_tamper</tt>)", "md_src_2net_2guard_2README.html#autotoc_md265", null ],
      [ "CVMFS token-gate check (<tt>signal=authfail</tt>)", "md_src_2net_2guard_2README.html#autotoc_md266", null ],
      [ "Testing", "md_src_2net_2guard_2README.html#autotoc_md267", null ]
    ] ],
    [ "net/httpguard — HTTP adapter for the bad-actor guard", "md_src_2net_2httpguard_2README.html", [
      [ "Directives", "md_src_2net_2httpguard_2README.html#autotoc_md269", null ],
      [ "ARC deployment recipe", "md_src_2net_2httpguard_2README.html#autotoc_md270", null ],
      [ "fail2ban wiring", "md_src_2net_2httpguard_2README.html#autotoc_md271", null ],
      [ "Tests", "md_src_2net_2httpguard_2README.html#autotoc_md272", null ]
    ] ],
    [ "manager — Cluster / redirector control plane (server registry, redirect cache, active health checks)", "md_src_2net_2manager_2README.html", [
      [ "Overview", "md_src_2net_2manager_2README.html#autotoc_md274", null ],
      [ "Files", "md_src_2net_2manager_2README.html#autotoc_md275", null ],
      [ "Key types & data structures", "md_src_2net_2manager_2README.html#autotoc_md276", null ],
      [ "Control & data flow", "md_src_2net_2manager_2README.html#autotoc_md277", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2manager_2README.html#autotoc_md278", null ],
      [ "Entry points / extending", "md_src_2net_2manager_2README.html#autotoc_md279", null ],
      [ "See also", "md_src_2net_2manager_2README.html#autotoc_md280", null ]
    ] ],
    [ "mirror — fire-and-forget traffic mirroring (shadow replay) for XRootD and WebDAV", "md_src_2net_2mirror_2README.html", [
      [ "Overview", "md_src_2net_2mirror_2README.html#autotoc_md282", null ],
      [ "Files", "md_src_2net_2mirror_2README.html#autotoc_md283", [
        [ "Other files", "md_src_2net_2mirror_2README.html#autotoc_md284", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2mirror_2README.html#autotoc_md285", null ],
      [ "Control & data flow", "md_src_2net_2mirror_2README.html#autotoc_md286", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2mirror_2README.html#autotoc_md287", null ],
      [ "Entry points / extending", "md_src_2net_2mirror_2README.html#autotoc_md288", null ],
      [ "Tests", "md_src_2net_2mirror_2README.html#autotoc_md289", null ],
      [ "See also", "md_src_2net_2mirror_2README.html#autotoc_md290", null ]
    ] ],
    [ "proxy — Transparent XRootD reverse proxy (<tt>brix_proxy</tt>)", "md_src_2net_2proxy_2README.html", [
      [ "Overview", "md_src_2net_2proxy_2README.html#autotoc_md292", null ],
      [ "Files", "md_src_2net_2proxy_2README.html#autotoc_md293", [
        [ "Other files", "md_src_2net_2proxy_2README.html#autotoc_md294", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2proxy_2README.html#autotoc_md295", null ],
      [ "Control & data flow", "md_src_2net_2proxy_2README.html#autotoc_md296", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2proxy_2README.html#autotoc_md297", null ],
      [ "Entry points / extending", "md_src_2net_2proxy_2README.html#autotoc_md298", null ],
      [ "See also", "md_src_2net_2proxy_2README.html#autotoc_md299", null ]
    ] ],
    [ "ratelimit — identity-aware leaky-bucket rate, bandwidth & concurrency limiting (Phase 25)", "md_src_2net_2ratelimit_2README.html", [
      [ "Overview", "md_src_2net_2ratelimit_2README.html#autotoc_md301", null ],
      [ "Files", "md_src_2net_2ratelimit_2README.html#autotoc_md302", [
        [ "Other files", "md_src_2net_2ratelimit_2README.html#autotoc_md303", null ]
      ] ],
      [ "Key types & data structures", "md_src_2net_2ratelimit_2README.html#autotoc_md304", null ],
      [ "Directive reference (configuration surface)", "md_src_2net_2ratelimit_2README.html#autotoc_md305", null ],
      [ "Control & data flow", "md_src_2net_2ratelimit_2README.html#autotoc_md306", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2ratelimit_2README.html#autotoc_md307", null ],
      [ "Entry points / extending", "md_src_2net_2ratelimit_2README.html#autotoc_md308", null ],
      [ "See also", "md_src_2net_2ratelimit_2README.html#autotoc_md309", null ]
    ] ],
    [ "net — clustering, proxying, shadowing, and connection defense", "md_src_2net_2README.html", null ],
    [ "tap — ngx-free protocol observation tap (decode + sink fan-out)", "md_src_2net_2tap_2README.html", [
      [ "Overview", "md_src_2net_2tap_2README.html#autotoc_md312", null ],
      [ "Files", "md_src_2net_2tap_2README.html#autotoc_md313", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2tap_2README.html#autotoc_md314", null ],
      [ "See also", "md_src_2net_2tap_2README.html#autotoc_md315", null ]
    ] ],
    [ "upstream — outbound XRootD redirector/proxy client (manager-side server-to-server query)", "md_src_2net_2upstream_2README.html", [
      [ "Overview", "md_src_2net_2upstream_2README.html#autotoc_md317", null ],
      [ "Files", "md_src_2net_2upstream_2README.html#autotoc_md318", null ],
      [ "Key types & data structures", "md_src_2net_2upstream_2README.html#autotoc_md319", null ],
      [ "Control & data flow", "md_src_2net_2upstream_2README.html#autotoc_md320", null ],
      [ "Invariants, security & gotchas", "md_src_2net_2upstream_2README.html#autotoc_md321", null ],
      [ "Entry points / extending", "md_src_2net_2upstream_2README.html#autotoc_md322", null ],
      [ "See also", "md_src_2net_2upstream_2README.html#autotoc_md323", null ]
    ] ],
    [ "Access Logging", "md_src_2observability_2accesslog_2README.html", null ],
    [ "dashboard — live HTTPS transfer monitor + REST admin write API", "md_src_2observability_2dashboard_2README.html", [
      [ "Overview", "md_src_2observability_2dashboard_2README.html#autotoc_md327", null ],
      [ "Files", "md_src_2observability_2dashboard_2README.html#autotoc_md328", null ],
      [ "Key types & data structures", "md_src_2observability_2dashboard_2README.html#autotoc_md329", null ],
      [ "Control & data flow", "md_src_2observability_2dashboard_2README.html#autotoc_md330", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2dashboard_2README.html#autotoc_md331", null ],
      [ "Entry points / extending", "md_src_2observability_2dashboard_2README.html#autotoc_md332", null ],
      [ "See also", "md_src_2observability_2dashboard_2README.html#autotoc_md333", null ],
      [ "VFS export browser (<tt>brix_dashboard_vfs_browse on</tt>)", "md_src_2observability_2dashboard_2README.html#autotoc_md334", null ]
    ] ],
    [ "metrics — shared-memory counters and the Prometheus <tt>/metrics</tt> exporter", "md_src_2observability_2metrics_2README.html", [
      [ "Overview", "md_src_2observability_2metrics_2README.html#autotoc_md336", null ],
      [ "Label schema", "md_src_2observability_2metrics_2README.html#autotoc_md337", null ],
      [ "Files", "md_src_2observability_2metrics_2README.html#autotoc_md338", [
        [ "Other files", "md_src_2observability_2metrics_2README.html#autotoc_md339", null ]
      ] ],
      [ "Key types & data structures", "md_src_2observability_2metrics_2README.html#autotoc_md340", null ],
      [ "Control & data flow", "md_src_2observability_2metrics_2README.html#autotoc_md341", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2metrics_2README.html#autotoc_md342", null ],
      [ "Entry points / extending", "md_src_2observability_2metrics_2README.html#autotoc_md343", null ],
      [ "See also", "md_src_2observability_2metrics_2README.html#autotoc_md344", null ]
    ] ],
    [ "pmark — SciTags packet marking", "md_src_2observability_2pmark_2README.html", [
      [ "Overview", "md_src_2observability_2pmark_2README.html#autotoc_md346", null ],
      [ "Files", "md_src_2observability_2pmark_2README.html#autotoc_md347", null ],
      [ "Configuration", "md_src_2observability_2pmark_2README.html#autotoc_md348", null ],
      [ "Control & data flow", "md_src_2observability_2pmark_2README.html#autotoc_md349", null ],
      [ "Invariants, security & gotchas", "md_src_2observability_2pmark_2README.html#autotoc_md350", null ],
      [ "See also", "md_src_2observability_2pmark_2README.html#autotoc_md351", null ]
    ] ],
    [ "observability — metrics, packet marking, dashboard, and access logs", "md_src_2observability_2README.html", null ],
    [ "Session Lifecycle Logging", "md_src_2observability_2sesslog_2README.html", null ],
    [ "Darwin platform adapters", "md_src_2platform_2darwin_2README.html", [
      [ "Build and validation", "md_src_2platform_2darwin_2README.html#autotoc_md356", null ]
    ] ],
    [ "Linux platform adapters", "md_src_2platform_2linux_2README.html", [
      [ "Build and validation", "md_src_2platform_2linux_2README.html#autotoc_md358", null ]
    ] ],
    [ "Platform abstraction layer", "md_src_2platform_2README.html", [
      [ "Implementation status", "md_src_2platform_2README.html#autotoc_md360", null ],
      [ "Build integration", "md_src_2platform_2README.html#autotoc_md361", null ],
      [ "Tests", "md_src_2platform_2README.html#autotoc_md362", null ]
    ] ],
    [ "Windows Platform Abstraction Layer", "md_src_2platform_2windows_2README.html", [
      [ "Overview", "md_src_2platform_2windows_2README.html#autotoc_md364", null ],
      [ "Important Limitations", "md_src_2platform_2windows_2README.html#autotoc_md365", null ],
      [ "Build Requirements", "md_src_2platform_2windows_2README.html#autotoc_md366", null ],
      [ "File Structure", "md_src_2platform_2windows_2README.html#autotoc_md367", null ],
      [ "Implementation Status", "md_src_2platform_2windows_2README.html#autotoc_md368", null ],
      [ "Key Design Decisions", "md_src_2platform_2windows_2README.html#autotoc_md369", [
        [ "1. HANDLE vs File Descriptor Abstraction", "md_src_2platform_2windows_2README.html#autotoc_md370", null ],
        [ "2. Event Loop Strategy", "md_src_2platform_2windows_2README.html#autotoc_md371", null ],
        [ "3. Security Model", "md_src_2platform_2windows_2README.html#autotoc_md372", null ]
      ] ],
      [ "Testing", "md_src_2platform_2windows_2README.html#autotoc_md373", null ],
      [ "Future Enhancements", "md_src_2platform_2windows_2README.html#autotoc_md374", null ],
      [ "References", "md_src_2platform_2windows_2README.html#autotoc_md375", null ]
    ] ],
    [ "cvmfs — the cvmfs:// site cache (+ experimental scvmfs:// TLS variant)", "md_src_2protocols_2cvmfs_2README.html", [
      [ "Overview", "md_src_2protocols_2cvmfs_2README.html#autotoc_md377", null ],
      [ "Files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md378", [
        [ "Other files", "md_src_2protocols_2cvmfs_2README.html#autotoc_md379", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2cvmfs_2README.html#autotoc_md380", null ],
      [ "See also", "md_src_2protocols_2cvmfs_2README.html#autotoc_md381", null ]
    ] ],
    [ "<tt>src/protocols/dig/</tt> — XrdDig-style remote diagnostics", "md_src_2protocols_2dig_2README.html", [
      [ "Overview", "md_src_2protocols_2dig_2README.html#autotoc_md383", null ],
      [ "Files", "md_src_2protocols_2dig_2README.html#autotoc_md384", null ],
      [ "See also", "md_src_2protocols_2dig_2README.html#autotoc_md385", null ]
    ] ],
    [ "GridFTP / FTP Gateway", "md_src_2protocols_2gridftp_2README.html", [
      [ "Observability", "md_src_2protocols_2gridftp_2README.html#autotoc_md387", [
        [ "Other files", "md_src_2protocols_2gridftp_2README.html#autotoc_md388", null ]
      ] ]
    ] ],
    [ "oci — the OCI Distribution plane: pull-through mirror + local registry", "md_src_2protocols_2oci_2README.html", [
      [ "Overview", "md_src_2protocols_2oci_2README.html#autotoc_md390", null ],
      [ "Files", "md_src_2protocols_2oci_2README.html#autotoc_md391", [
        [ "The shared grammar", "md_src_2protocols_2oci_2README.html#autotoc_md392", null ],
        [ "The mirror surface (<tt>brix_oci_mirror</tt>)", "md_src_2protocols_2oci_2README.html#autotoc_md393", null ],
        [ "The registry surface (<tt>brix_oci_registry</tt>)", "md_src_2protocols_2oci_2README.html#autotoc_md394", null ]
      ] ],
      [ "Gating and invariants", "md_src_2protocols_2oci_2README.html#autotoc_md395", null ],
      [ "See also", "md_src_2protocols_2oci_2README.html#autotoc_md396", null ]
    ] ],
    [ "protocols — one subdirectory per wire protocol", "md_src_2protocols_2README.html", null ],
    [ "connection — TCP connection lifecycle, framing, and the async I/O state machine for <tt>root://</tt>", "md_src_2protocols_2root_2connection_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2connection_2README.html#autotoc_md399", null ],
      [ "Files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md400", [
        [ "Other files", "md_src_2protocols_2root_2connection_2README.html#autotoc_md401", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2connection_2README.html#autotoc_md402", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2connection_2README.html#autotoc_md403", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2connection_2README.html#autotoc_md404", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2connection_2README.html#autotoc_md405", null ],
      [ "See also", "md_src_2protocols_2root_2connection_2README.html#autotoc_md406", null ]
    ] ],
    [ "dirlist — XRootD <tt>kXR_dirlist</tt> directory enumeration (stream protocol)", "md_src_2protocols_2root_2dirlist_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md408", null ],
      [ "Files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md409", [
        [ "Other files", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md410", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md411", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md412", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md413", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md414", null ],
      [ "See also", "md_src_2protocols_2root_2dirlist_2README.html#autotoc_md415", null ]
    ] ],
    [ "fattr — XRootD <tt>kXR_fattr</tt> extended-attribute operations", "md_src_2protocols_2root_2fattr_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md417", null ],
      [ "Files", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md418", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md419", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md420", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md421", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md422", null ],
      [ "See also", "md_src_2protocols_2root_2fattr_2README.html#autotoc_md423", null ]
    ] ],
    [ "handoff — single-port protocol handoff for the stream xrootd listener", "md_src_2protocols_2root_2handoff_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md425", null ],
      [ "Files", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md426", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md427", null ],
      [ "See also", "md_src_2protocols_2root_2handoff_2README.html#autotoc_md428", null ]
    ] ],
    [ "handshake — XRootD stream request entry point and opcode dispatcher", "md_src_2protocols_2root_2handshake_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md430", null ],
      [ "Files", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md431", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md432", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md433", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md434", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md435", null ],
      [ "See also", "md_src_2protocols_2root_2handshake_2README.html#autotoc_md436", null ]
    ] ],
    [ "path — wire-path extraction, sanitization, and stat formatting", "md_src_2protocols_2root_2path_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2path_2README.html#autotoc_md438", null ],
      [ "Files", "md_src_2protocols_2root_2path_2README.html#autotoc_md439", [
        [ "Other files", "md_src_2protocols_2root_2path_2README.html#autotoc_md440", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2path_2README.html#autotoc_md441", null ],
      [ "See also", "md_src_2protocols_2root_2path_2README.html#autotoc_md442", null ]
    ] ],
    [ "protocol — XRootD <tt>root://</tt> wire-format constants & packed structs", "md_src_2protocols_2root_2protocol_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md444", [
        [ "Provenance & licensing", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md445", null ]
      ] ],
      [ "Files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md446", [
        [ "Other files", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md447", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md448", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md449", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md450", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md451", null ],
      [ "See also", "md_src_2protocols_2root_2protocol_2README.html#autotoc_md452", null ]
    ] ],
    [ "query — XRootD <tt>kXR_query</tt> sub-protocol, <tt>kXR_prepare</tt> staging, and <tt>kXR_set</tt> hints", "md_src_2protocols_2root_2query_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2query_2README.html#autotoc_md454", null ],
      [ "Files", "md_src_2protocols_2root_2query_2README.html#autotoc_md455", [
        [ "Other files", "md_src_2protocols_2root_2query_2README.html#autotoc_md456", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2query_2README.html#autotoc_md457", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2query_2README.html#autotoc_md458", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2query_2README.html#autotoc_md459", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2query_2README.html#autotoc_md460", null ],
      [ "See also", "md_src_2protocols_2root_2query_2README.html#autotoc_md461", null ]
    ] ],
    [ "read — XRootD read-side opcodes and the file-handle lifecycle", "md_src_2protocols_2root_2read_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2read_2README.html#autotoc_md463", null ],
      [ "Files", "md_src_2protocols_2root_2read_2README.html#autotoc_md464", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2read_2README.html#autotoc_md465", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2read_2README.html#autotoc_md466", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2read_2README.html#autotoc_md467", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2read_2README.html#autotoc_md468", null ],
      [ "See also", "md_src_2protocols_2root_2read_2README.html#autotoc_md469", null ]
    ] ],
    [ "root — the XRootD (<tt>root://</tt> / <tt>roots://</tt>) protocol plane", "md_src_2protocols_2root_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2README.html#autotoc_md471", null ],
      [ "Subdirectories", "md_src_2protocols_2root_2README.html#autotoc_md472", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2README.html#autotoc_md473", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2README.html#autotoc_md474", null ],
      [ "See also", "md_src_2protocols_2root_2README.html#autotoc_md475", null ]
    ] ],
    [ "relay — transparent pass-through relay with a passive observation tap", "md_src_2protocols_2root_2relay_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2relay_2README.html#autotoc_md477", null ],
      [ "Files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md478", [
        [ "Other files", "md_src_2protocols_2root_2relay_2README.html#autotoc_md479", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2relay_2README.html#autotoc_md480", null ],
      [ "See also", "md_src_2protocols_2root_2relay_2README.html#autotoc_md481", null ]
    ] ],
    [ "response — XRootD wire-response framing helpers", "md_src_2protocols_2root_2response_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2response_2README.html#autotoc_md483", null ],
      [ "Files", "md_src_2protocols_2root_2response_2README.html#autotoc_md484", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2response_2README.html#autotoc_md485", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2response_2README.html#autotoc_md486", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2response_2README.html#autotoc_md487", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2response_2README.html#autotoc_md488", null ],
      [ "See also", "md_src_2protocols_2root_2response_2README.html#autotoc_md489", null ]
    ] ],
    [ "session — XRootD session lifecycle, identity binding & cross-worker registry", "md_src_2protocols_2root_2session_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2session_2README.html#autotoc_md491", null ],
      [ "Files", "md_src_2protocols_2root_2session_2README.html#autotoc_md492", null ],
      [ "Key types & data structures", "md_src_2protocols_2root_2session_2README.html#autotoc_md493", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2session_2README.html#autotoc_md494", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2session_2README.html#autotoc_md495", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2session_2README.html#autotoc_md496", null ],
      [ "See also", "md_src_2protocols_2root_2session_2README.html#autotoc_md497", null ]
    ] ],
    [ "stream — <tt>ngx_stream_brix_module</tt> descriptor & directive table", "md_src_2protocols_2root_2stream_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2stream_2README.html#autotoc_md499", null ],
      [ "Files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md500", [
        [ "Other files", "md_src_2protocols_2root_2stream_2README.html#autotoc_md501", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2stream_2README.html#autotoc_md502", [
        [ "Directive groups (authoritative <tt>module.c</tt> set)", "md_src_2protocols_2root_2stream_2README.html#autotoc_md503", null ]
      ] ],
      [ "Control & data flow", "md_src_2protocols_2root_2stream_2README.html#autotoc_md504", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2stream_2README.html#autotoc_md505", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2stream_2README.html#autotoc_md506", null ],
      [ "See also", "md_src_2protocols_2root_2stream_2README.html#autotoc_md507", null ]
    ] ],
    [ "write — XRootD mutating-opcode handlers (the stream write path)", "md_src_2protocols_2root_2write_2README.html", [
      [ "Overview", "md_src_2protocols_2root_2write_2README.html#autotoc_md509", null ],
      [ "Files", "md_src_2protocols_2root_2write_2README.html#autotoc_md510", [
        [ "Other files", "md_src_2protocols_2root_2write_2README.html#autotoc_md511", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2root_2write_2README.html#autotoc_md512", null ],
      [ "Control & data flow", "md_src_2protocols_2root_2write_2README.html#autotoc_md513", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2root_2write_2README.html#autotoc_md514", null ],
      [ "Entry points / extending", "md_src_2protocols_2root_2write_2README.html#autotoc_md515", null ],
      [ "See also", "md_src_2protocols_2root_2write_2README.html#autotoc_md516", null ]
    ] ],
    [ "src/protocols/root/zip — ZIP member access (phase-57 W2)", "md_src_2protocols_2root_2zip_2README.html", [
      [ "Status", "md_src_2protocols_2root_2zip_2README.html#autotoc_md518", null ],
      [ "zip_dir.c — the parser", "md_src_2protocols_2root_2zip_2README.html#autotoc_md519", null ],
      [ "Running the unit test (standalone, no nginx build)", "md_src_2protocols_2root_2zip_2README.html#autotoc_md520", null ]
    ] ],
    [ "rpm — the RPM/dnf pull-through mirror (phase-104 D11 / D15.9)", "md_src_2protocols_2rpm_2README.html", [
      [ "Overview", "md_src_2protocols_2rpm_2README.html#autotoc_md522", null ],
      [ "Files", "md_src_2protocols_2rpm_2README.html#autotoc_md523", null ],
      [ "Gating and invariants", "md_src_2protocols_2rpm_2README.html#autotoc_md524", null ],
      [ "See also", "md_src_2protocols_2rpm_2README.html#autotoc_md525", null ]
    ] ],
    [ "s3 — S3-compatible REST endpoint over the local export root", "md_src_2protocols_2s3_2README.html", [
      [ "Overview", "md_src_2protocols_2s3_2README.html#autotoc_md527", null ],
      [ "Files", "md_src_2protocols_2s3_2README.html#autotoc_md528", [
        [ "Other files", "md_src_2protocols_2s3_2README.html#autotoc_md529", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2s3_2README.html#autotoc_md530", null ],
      [ "Control & data flow", "md_src_2protocols_2s3_2README.html#autotoc_md531", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2s3_2README.html#autotoc_md532", null ],
      [ "Entry points / extending", "md_src_2protocols_2s3_2README.html#autotoc_md533", null ],
      [ "See also", "md_src_2protocols_2s3_2README.html#autotoc_md534", null ]
    ] ],
    [ "shared — cross-protocol helper library (HTTP file serving + overflow-safe size math)", "md_src_2protocols_2shared_2README.html", [
      [ "Overview", "md_src_2protocols_2shared_2README.html#autotoc_md536", null ],
      [ "Files", "md_src_2protocols_2shared_2README.html#autotoc_md537", null ],
      [ "Key types & data structures", "md_src_2protocols_2shared_2README.html#autotoc_md538", null ],
      [ "Control & data flow", "md_src_2protocols_2shared_2README.html#autotoc_md539", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2shared_2README.html#autotoc_md540", null ],
      [ "Entry points / extending", "md_src_2protocols_2shared_2README.html#autotoc_md541", null ],
      [ "See also", "md_src_2protocols_2shared_2README.html#autotoc_md542", null ]
    ] ],
    [ "<tt>src/protocols/srr/</tt> — WLCG Storage Resource Reporting (SRR) endpoint", "md_src_2protocols_2srr_2README.html", [
      [ "Why this instead of the XRootD UDP monitoring stack", "md_src_2protocols_2srr_2README.html#autotoc_md544", null ],
      [ "Files", "md_src_2protocols_2srr_2README.html#autotoc_md545", null ],
      [ "Configuration", "md_src_2protocols_2srr_2README.html#autotoc_md546", null ],
      [ "Semantics & caveats", "md_src_2protocols_2srr_2README.html#autotoc_md547", null ],
      [ "Schema conformance", "md_src_2protocols_2srr_2README.html#autotoc_md548", null ]
    ] ],
    [ "<tt>src/protocols/ssi/</tt> — XrdSsi request/response service over <tt>root://</tt>", "md_src_2protocols_2ssi_2README.html", [
      [ "Overview", "md_src_2protocols_2ssi_2README.html#autotoc_md550", null ],
      [ "Phase 1: session multiplexing (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md551", null ],
      [ "Phase 2: async server-push via <tt>kXR_attn</tt> (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md552", null ],
      [ "Phase 3: streamed responses + delivered alerts (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md553", null ],
      [ "Phases 4–5: CTA flagship service (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md554", null ],
      [ "Phase 6: config, metrics, conformance (implemented)", "md_src_2protocols_2ssi_2README.html#autotoc_md555", [
        [ "Directives (<tt>NGX_STREAM_SRV_CONF</tt>)", "md_src_2protocols_2ssi_2README.html#autotoc_md556", null ],
        [ "Metrics (low-cardinality — <tt>{port,auth}</tt> only)", "md_src_2protocols_2ssi_2README.html#autotoc_md557", null ],
        [ "Conformance", "md_src_2protocols_2ssi_2README.html#autotoc_md558", null ]
      ] ],
      [ "RRInfo wire layout", "md_src_2protocols_2ssi_2README.html#autotoc_md559", null ],
      [ "Files", "md_src_2protocols_2ssi_2README.html#autotoc_md560", [
        [ "Other files", "md_src_2protocols_2ssi_2README.html#autotoc_md561", null ]
      ] ],
      [ "See also", "md_src_2protocols_2ssi_2README.html#autotoc_md562", null ]
    ] ],
    [ "<tt>src/protocols/ssi/svc_cta/</tt> — flagship CTA tape service", "md_src_2protocols_2ssi_2svc__cta_2README.html", [
      [ "Layers", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md564", null ],
      [ "Request lifecycle", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md565", [
        [ "State machine", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md566", null ],
        [ "Executor", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md567", null ],
        [ "Security", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md568", null ],
        [ "The queue is cross-worker (phase 115 W8.6)", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md569", null ],
        [ "Journal (restart recovery)", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md570", null ]
      ] ],
      [ "External contract — the pinned field table", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md571", null ],
      [ "Golden-vector provenance", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md572", null ],
      [ "Scope notes", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md573", [
        [ "Other files", "md_src_2protocols_2ssi_2svc__cta_2README.html#autotoc_md574", null ]
      ] ]
    ] ],
    [ "webdav/fs — Confined local-filesystem copy engine for WebDAV COPY/MOVE", "md_src_2protocols_2webdav_2fs_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md576", null ],
      [ "Files", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md577", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md578", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md579", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md580", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md581", null ],
      [ "See also", "md_src_2protocols_2webdav_2fs_2README.html#autotoc_md582", null ]
    ] ],
    [ "webdav/locks — WebDAV LOCK request-header & body parsers", "md_src_2protocols_2webdav_2locks_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md584", null ],
      [ "Files", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md585", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md586", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md587", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md588", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md589", null ],
      [ "See also", "md_src_2protocols_2webdav_2locks_2README.html#autotoc_md590", null ]
    ] ],
    [ "webdav/methods — Per-method WebDAV precondition helpers", "md_src_2protocols_2webdav_2methods_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md592", null ],
      [ "Files", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md593", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md594", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md595", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md596", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md597", null ],
      [ "See also", "md_src_2protocols_2webdav_2methods_2README.html#autotoc_md598", null ]
    ] ],
    [ "webdav — HTTP/WebDAV/HTTPS gateway (<tt>davs://</tt>, <tt>http://</tt>) over the export root", "md_src_2protocols_2webdav_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2README.html#autotoc_md600", null ],
      [ "Files", "md_src_2protocols_2webdav_2README.html#autotoc_md601", [
        [ "Module wiring & configuration", "md_src_2protocols_2webdav_2README.html#autotoc_md602", null ],
        [ "Dispatch & generic helpers", "md_src_2protocols_2webdav_2README.html#autotoc_md603", null ],
        [ "HTTP method handlers", "md_src_2protocols_2webdav_2README.html#autotoc_md604", null ],
        [ "Authentication", "md_src_2protocols_2webdav_2README.html#autotoc_md605", null ],
        [ "HTTP-TPC (third-party copy)", "md_src_2protocols_2webdav_2README.html#autotoc_md606", null ],
        [ "Dynamic backend pool (admin API)", "md_src_2protocols_2webdav_2README.html#autotoc_md607", null ],
        [ "XrdHttp protocol extension", "md_src_2protocols_2webdav_2README.html#autotoc_md608", null ],
        [ "Other files", "md_src_2protocols_2webdav_2README.html#autotoc_md609", null ]
      ] ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2README.html#autotoc_md610", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2README.html#autotoc_md611", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2README.html#autotoc_md612", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2README.html#autotoc_md613", null ],
      [ "See also", "md_src_2protocols_2webdav_2README.html#autotoc_md614", null ]
    ] ],
    [ "webdav/util — WebDAV URI decoding and XML escaping helpers", "md_src_2protocols_2webdav_2util_2README.html", [
      [ "Overview", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md616", null ],
      [ "Files", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md617", null ],
      [ "Key types & data structures", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md618", null ],
      [ "Control & data flow", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md619", null ],
      [ "Invariants, security & gotchas", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md620", null ],
      [ "Entry points / extending", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md621", null ],
      [ "See also", "md_src_2protocols_2webdav_2util_2README.html#autotoc_md622", null ]
    ] ],
    [ "src — nginx-xrootd Source Tree", "md_src_2README.html", [
      [ "Source map", "md_src_2README.html#autotoc_md625", [
        [ "Top-level files (now under <tt>core/</tt>)", "md_src_2README.html#autotoc_md626", null ],
        [ "Entry & dispatch", "md_src_2README.html#autotoc_md627", null ],
        [ "Protocol handlers", "md_src_2README.html#autotoc_md628", null ],
        [ "Data plane", "md_src_2README.html#autotoc_md629", null ],
        [ "Path & confinement", "md_src_2README.html#autotoc_md630", null ],
        [ "Authentication", "md_src_2README.html#autotoc_md631", null ],
        [ "Cluster & federation", "md_src_2README.html#autotoc_md632", null ],
        [ "Cross-cutting", "md_src_2README.html#autotoc_md633", null ],
        [ "WebDAV sub-helpers", "md_src_2README.html#autotoc_md634", null ]
      ] ],
      [ "The four request lifecycles", "md_src_2README.html#autotoc_md636", [
        [ "<tt>root://</tt> stream", "md_src_2README.html#autotoc_md637", null ],
        [ "<tt>davs://</tt> WebDAV", "md_src_2README.html#autotoc_md638", null ],
        [ "S3 REST", "md_src_2README.html#autotoc_md639", null ],
        [ "CMS cluster redirect", "md_src_2README.html#autotoc_md640", null ]
      ] ],
      [ "Cross-cutting invariants", "md_src_2README.html#autotoc_md642", null ],
      [ "How to navigate / where to start reading", "md_src_2README.html#autotoc_md644", null ]
    ] ],
    [ "tpc/common — Protocol-neutral third-party-copy (TPC) core", "md_src_2tpc_2common_2README.html", [
      [ "Overview", "md_src_2tpc_2common_2README.html#autotoc_md646", null ],
      [ "Files", "md_src_2tpc_2common_2README.html#autotoc_md647", null ],
      [ "Key types & data structures", "md_src_2tpc_2common_2README.html#autotoc_md648", null ],
      [ "Control & data flow", "md_src_2tpc_2common_2README.html#autotoc_md649", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2common_2README.html#autotoc_md650", null ],
      [ "Entry points / extending", "md_src_2tpc_2common_2README.html#autotoc_md651", null ],
      [ "See also", "md_src_2tpc_2common_2README.html#autotoc_md652", null ]
    ] ],
    [ "engine — native-TPC control plane (destination side)", "md_src_2tpc_2engine_2README.html", [
      [ "Overview", "md_src_2tpc_2engine_2README.html#autotoc_md654", null ],
      [ "Files", "md_src_2tpc_2engine_2README.html#autotoc_md655", [
        [ "Other files", "md_src_2tpc_2engine_2README.html#autotoc_md656", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2engine_2README.html#autotoc_md657", null ],
      [ "See also", "md_src_2tpc_2engine_2README.html#autotoc_md658", null ]
    ] ],
    [ "gsi — outbound GSI authentication for the TPC pull socket", "md_src_2tpc_2gsi_2README.html", [
      [ "Overview", "md_src_2tpc_2gsi_2README.html#autotoc_md660", null ],
      [ "Files", "md_src_2tpc_2gsi_2README.html#autotoc_md661", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2gsi_2README.html#autotoc_md662", null ],
      [ "See also", "md_src_2tpc_2gsi_2README.html#autotoc_md663", null ]
    ] ],
    [ "outbound — the blocking source-session client for native TPC pulls", "md_src_2tpc_2outbound_2README.html", [
      [ "Overview", "md_src_2tpc_2outbound_2README.html#autotoc_md665", null ],
      [ "Files", "md_src_2tpc_2outbound_2README.html#autotoc_md666", [
        [ "Other files", "md_src_2tpc_2outbound_2README.html#autotoc_md667", null ]
      ] ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2outbound_2README.html#autotoc_md668", null ],
      [ "See also", "md_src_2tpc_2outbound_2README.html#autotoc_md669", null ]
    ] ],
    [ "tpc — Native XRootD third-party-copy (destination-side pull)", "md_src_2tpc_2README.html", [
      [ "Overview", "md_src_2tpc_2README.html#autotoc_md671", null ],
      [ "Files", "md_src_2tpc_2README.html#autotoc_md672", null ],
      [ "Key types & data structures", "md_src_2tpc_2README.html#autotoc_md673", null ],
      [ "Control & data flow", "md_src_2tpc_2README.html#autotoc_md674", null ],
      [ "Invariants, security & gotchas", "md_src_2tpc_2README.html#autotoc_md675", null ],
      [ "Entry points / extending", "md_src_2tpc_2README.html#autotoc_md676", null ],
      [ "See also", "md_src_2tpc_2README.html#autotoc_md677", null ]
    ] ],
    [ "Client platform abstraction layer", "md_client_2lib_2platform_2README.html", null ],
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
"aio__conn_8c.html#a65d892a21c090c393dc0eabaed18b163",
"api__admin__routing_8c.html#a2724cee7e91b1f6f769d5d60457d88c3",
"auth_2impersonate_2lifecycle_8c.html#a10898bb4cdb4366733ff1ccb543fba1b",
"auth__sigv4__verify__time_8c.html#a3dc584ee035c74d32b0ab2c4d43afa89",
"basic_8c.html#a3bb0965e1cf62be0fa2a2681fdb9095d",
"brix__fault__cmd__attack_8c.html#a8f8f80d37794cde9472343e4487ba3eb",
"brix__fault__proxy_8c.html#aa92dab98559c65b9546accdf96a0a2c9",
"brix__fault__proxy__state_8h.html#afa1aebeea9949477018a874ea3c7238c",
"brix__net_8h.html#aa592df33acdd628a8195e4973a6ae134",
"brixcvmfs_8c.html#aaa8016287a04892f13bfc84126402f4c",
"brixcvmfs__publish_8c.html#a1f246c2185a5da54e50bfdf651567d20",
"brixoci_8c.html#ad7898851444f0c108e750b0e366995df",
"broker__internal_8h.html#a42c75ff96b5c08496283cf522aeac6b1",
"cache__storage_8c.html#a12c9d036eef3494af4ce147b46b504a0",
"checksum__core_8h.html#ac5dd18ca31c782ab2fc1638510b55a7d",
"cktree__internal_8h.html#aed9838a8352c5188b9fea4bbcfdfe813",
"client_2lib_2protocols_2shared_2checksum_8c.html#aae561c1ad8267cd4a0f65a41bffdf7e7",
"cms__internal_8h.html#a21cbb048efc3b49db444628dde3db4cb",
"codec__core_8c_source.html",
"conn__explain_8c.html#a5042b44ac6030680c37a32c0620681b2",
"copy__upload_8c.html#aad1f51798d9615656513ce211ec329a8",
"core_2types_2file_8h.html#ac78c7f6c9bb9e38df6b653c5517846ed",
"cred__stage_8h.html#adb7838a555e59693a9c9840580e78462",
"cstore__scan_8c.html",
"cvmfs_8c.html#a01a71ca20b1da3637e5d90e13fc2e15a",
"darwin_2process__wrapper_8c.html",
"dead__props__internal_8h.html",
"diag__doctor__audit_8c.html#a879b949a72e9fe2a25e253c8aedf8ec3",
"diag__doctor__recon__unittest_8c.html#aa17043dd7f55a5a8dc9975d658cbe4f7",
"diag__watch_8c.html#a78c646c3b65b25dfab0cc148543ebfac",
"directives__auth_8h_source.html",
"err__strings_8h.html#a5a1b0921176da04b9fe2159572ca20d5",
"fd__table_8h.html#abbe59bf396156d0ef11300290b50a0c3",
"flowlabel_8c.html#a38162c5477a20269ea96bbc581013a1a",
"frm__zip_8h.html#afb9f7c04958da9594a953da5aeef8497",
"fs__walk__remove_8c.html#a7715484e911e0f752d61540bb4f3babf",
"ftp__ev__mode__e__recv_8c.html#aa894670981e889bd4bf6002582709dca",
"gate_8c.html#a85625e6de9d5c3217a7cfd14b40ad00b",
"gftp__mode__e_8c.html#a8278f42def12832c366d4ff814c86cd9",
"gsi_8h.html#ab27716674dab1b71a9919ac91ab50df7",
"guard_8h.html#a1049d842401f65762856072fc1836d0d",
"health__check__internal_8h.html#a2bf47fe122c23a2c60350fa2b80e2893a3a790de8feb13f91036dc42c0fbe41dc",
"http__conditionals_8h.html#a6d144e96765a27bc336f7fee60863be7",
"http__upload_8c.html#a7d6a48cd836b8ea085d3100a8c76e949",
"identity__matrix__unittest_8c.html#af0b1013021f346e782746597b997a436",
"integrity__info_8h.html#adadf03ab23b6c6ee498678d80e185b42",
"kv_8c.html#a18ea635440aed1f06248c58058d8da28",
"lifecycle__timing_8c_source.html",
"lock__record_8h.html#a0353526a9f42125bbea6b4c5a8b80861",
"md_src_2auth_2impersonate_2README.html",
"md_src_2net_2mirror_2README.html#autotoc_md283",
"md_src_2protocols_2shared_2README.html#autotoc_md536",
"metalink_8c.html#af5f12981338c67196b2ff86d98267ff1",
"metrics__s3_8h.html#a364a63e59bd671497c029942d32f5ac2",
"mpxstats_8c.html",
"net_2dns_2metrics_8c.html#ab55c57b13065fbe01edbc8173bb82136",
"ngx__brix__module_8h.html#a0bea9dcc3e54280dc197c64bb61e588d",
"observability_2dashboard_2noop_8c.html#a3373f9cdbc18a7995ee883d36167dd43",
"observability_2metrics_2unified_8h.html#afdeab43ce73650496dddbb1487cfc213",
"oci__mirror_8c.html#a224cff50564f5ad5750915fe18fb5aa0",
"ocsp__transport_8c.html#a6faa4cbff4333364e564256098cf1e2d",
"open__flags_8h.html#a34096b8f99bbada7dc93780247e55d14",
"origin__auth_8c_source.html",
"overlay__unittest_8c.html#a18f3bccc60190731f0ee0cadb4066f00",
"pblock__refs_8c.html#a369266c24eacffb87046522897a570d5",
"pgw__fob_8c.html#aaabde9803dd18de1d96e9075f3b0c6a9",
"platform__api__xattr_8h.html#ac67d4b3f1f0e9c5f6bc063c79b71c103",
"privs_8c.html#a659adfa469644ec6d10b8d47e1ada1e8",
"proto__list_8h.html",
"protocols_2root_2stream_2module_8c.html#acfd9a7f03ff6a3480b77691c01415b18",
"provider_8c_source.html",
"put__body__digest_8c_source.html",
"ratelimit__keys__rules_8c.html#a11435365fb383d4d6b501a8ed5208d57",
"redir__registry_8c.html#a08a4ecf7ecc22ce35fc8230fcf51fdb6",
"relay_8h.html#a1d0ba109a90a59160b917ae183033b19",
"respbuf__unittest_8c.html#aba1590ff86288c886c47dc8a27b30467",
"router_8c.html#aff31d1b5112b124b33b01a79bb1883df",
"runtime__server__backend__stage_8c.html#abdeed4591fee90256d9ceb4d7ddeecd0",
"safe__size_8h.html#aabd4ba979171f07d987af1d1ecf1313d",
"sd__accessors_8h.html#af8a058ea090c61cc140ca177e21572a4",
"sd__cache__maint_8c.html#a3ef18ec77d917799758c68f7072fb8c2",
"sd__frm__adapter_8c.html#af203bfe0940318c3e239876a7472de9e",
"sd__frm__recall_8c_source.html",
"sd__http__internal_8h.html#a94a7f1dcbbbf7cb6e78834cf375d3494",
"sd__pblock__catalog_8h_source.html",
"sd__pblock__unittest__internal_8h.html#a51f4b9ca874fff5d2271755bd4f1d8d8",
"sd__registry_8h.html#a19073b9b7197e97b4492761b0f22fc03",
"sd__s3__internal_8h.html#a5d60e10967248dc7677fc508f4df18fe",
"sd__xroot__fwd_8c.html#a8521e5b81be0551c48969b415a48e1cc",
"sd__xroot__ns__dir_8c.html#a0de7ff6ced3d855cf1b41c494088aa19",
"server__conf__internal_8h.html",
"sesslog_8h.html#a423ea74f1f8a2e20c2e6c87f5c12113faa80c297568d4dec27398bde4e6eda2fd",
"shared__conf__fields__policy_8h.html#a1a74ba8ed8a08d1a08f3137fc9fece5d",
"source__internal_8h_source.html",
"src_2fs_2vfs_2vfs_8h.html#ac951e5ed30fc4c3bf88f45d545a16cbf",
"srv__conf__fields__auth_8h.html#a594fa2172ffbe9aa8bf6c3bcf250f429",
"ssi__dispatch_8c.html#a809c38361cc45b6a9abe4ba9e1626866",
"sss__keytab_8h.html#ab8cff675e34063ed0f0737857357e71f",
"stage__request__registry__mutate_8c.html#a1e49583b0807bef01d4d0263425b4fe4",
"storascan__scan_8c.html#a8b2cc2a99a756f468414e8d02cbe037f",
"stream__mirror__launch_8c.html#aab12841a41670dbd8d42346784f01d5c",
"structClientLoginRequest.html#a5078964d63ad3a85294cc5c3b7287b2f",
"structacc__sel__ctx__t.html",
"structbrix__acc__http__t.html#ad2cfd9f5600db136a81f256e30dc7e36",
"structbrix__baq__root__park__t.html#a65861343ff862ef084234538b61e9e3f",
"structbrix__cinfo__l1__t.html",
"structbrix__cns__entry__t.html",
"structbrix__ctx__login__t.html#a4191d7d7d7efd118484b10b91cf69991",
"structbrix__cvmfs__coord__t.html#afb2b068295e5124125405cc92885d90b",
"structbrix__dns__target__s.html#a8b09256f7001cdc790eb7345f7942498",
"structbrix__gsi__buf__t.html#a64b8a94159786a8e0823b9d52773e67f",
"structbrix__io.html#ab0fdf563077f7c2ec5744982b7f47243",
"structbrix__mkdir__walk__s.html#ab6add23c73108e6f8364a26214c5e4e2",
"structbrix__opts.html#acade3be86867499f55749adbcb6592a2",
"structbrix__prefetch__t.html#a7bc87fba9f7b24d146fe67d0ecc77dbb",
"structbrix__readv__aio__t.html#a18acc798c2f69ea98d41809ca849d09d",
"structbrix__sd__cache__peer__t.html#ad6b573731cffe9be0dcd8a22aa848813",
"structbrix__sd__ucred__t.html#a457630f8403512cde10fb3da1c65b553",
"structbrix__srv__snapshot__entry__t.html#ac5e4abe9e6acdfc857d435e3716afb62",
"structbrix__streamset.html",
"structbrix__tpc__pull__t.html#a556187d923fddbae61d71add922bd659",
"structbrix__vfs__backend__entry__t.html#aad4aabec3797c7aa4b3f8dc84da0cf7e",
"structbrix__vfs__writev__seg__t.html#ad8309821189d3085042910b4868e649d",
"structbrix__xmeta__t.html#a516bfe2b77682a23d14fbe40819aa28a",
"structckp__write__desc__t.html#acf0dec26192bccacde82fb339e797ff2",
"structctx__falist.html#abd9d7fb092937ecdd966809498b9e125",
"structdd__sink__t.html",
"structdoctor__recon.html#a82d166e432e2c1e00feeda6f11e5e957",
"structfp__hostpair.html#a74aa6056ea32f6cb05cef45197d58574",
"structftp__ev__t.html#a7498c5f9a171890ab35c3ea957c1594c",
"structhttp__get__ctx.html#ad0dbd297db7d0215b2f9a8fb1b40815f",
"structlocate__ctx__t.html#a3f472ceadf15e57c5d532193ea06a674",
"structngx__brix__cvmfs__repo__metrics__t.html#aa33da650841d5e6c640dce25d76437a9",
"structngx__brix__unified__metrics__t.html#af8e3202ba638e3fef1fe3c790af4c018",
"structngx__http__brix__webdav__req__ctx__t.html#a0f16225b28e0af2fbabcfc5a57710a84",
"structpblock__obj__t.html#a7f9e741d3756df98aba107401f89a16d",
"structpxr__ctx.html#ae1d899e01bc153f52f8c93a85984b3e9",
"structs3__get__serve__t.html#a3987e1745c6fcc76dc6482203d98c604",
"structsd__cache__fill__state__t.html#abf0a2540aec26cdbd0bb334e4279d1fd",
"structsd__remote__dir__state.html#af51ac860f5faa03cf5ff91c97cbc95ac",
"structsrr__cap__t.html",
"structtpc__marker__start__args__t.html#a315f6d53f6acf1aca45d46e5ff82d0b3",
"structwatch__sample.html#acd41ccea43c6274392c1850692939675",
"structwebdav__walk__task__t.html#abb2e7ee08ff8c5974c5e83a3d791c78a",
"structxrdcp__transfer__ctx.html#adb80ef219b4e723a56a130ea12090e2e",
"sts__http_8c.html#aa45cd0c7a308d42c6343cbb57eae1e65",
"tape__rest_8c_source.html",
"tmp__path_8c.html#a46771185f0049641bfc40ceaab4f6cc8",
"tpc__cred__oidc_8c.html#aa56901372350192b5226df3fec7c2b05",
"tpc__user__proxy_8h.html",
"tunables__cluster_8h.html#ab0b3fd2206f37f08c9066bd247cbd304",
"tunables__metrics_8h.html#a9f0014cab0ea16f43cc5704812007bc5",
"tunables__root__wire_8h.html#aeda9750594c4994e06987716ebdb0dbe",
"tunables__tpc_8h.html#aa952c6b45232563bd4c02e615753aad8",
"upstream__internal_8h.html#a5e813ef7a2930210850cf7e201ac7d99",
"vfs__authz__bind_8c.html",
"vfs__core_8h.html#a49ed1dbe87bde0c4c08c511c63e05bd3",
"vfs__open_8c_source.html",
"vfs__s3__io_8c.html#ad5ecd4746d02f870b3de3b3bd8dff487",
"web__ka_8c.html#a0a092fb7edf0661641797f8c51c3fdbf",
"webfile_8c.html#ab446660e643f7854a6655eb15837bca3",
"wire__codec__file_8c.html#abcd634fbf6f6d4b77e62ff37259fb244",
"writethrough__metrics_8h.html",
"xmeta_8c.html#a578c95b4691f9e6ea07c160adc2973e5",
"xrd__internal_8h.html#a559a2b1891641606c322b1b0a02b7723",
"xrdcp__parse__transport_8c.html#a926d69de5993d2380f02d428aeff7242",
"xrdfs__internal_8h.html#abb021ab95e3b38ed4f8de711d9afea46",
"xrdrc_8c.html#a5f40488d4f111b9e9dbd47c78c243c54",
"xrootdfs__legacy_8c.html#a55370e0214e95f7b94f7b0ca0c36086c",
"zip__kernel_8c.html#aded8ad54d459de18c272b316c98e18ad"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';