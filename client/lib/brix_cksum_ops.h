/*
 * brix_cksum_ops.h - checksum family decls (cksum_manifest / checksum / cks_verify / cli_cksum)
 * Split from the 647-line brix_ops.h at phase-103; #included by brix_ops.h at
 * the exact position the block occupied, so declaration order is identical.
 * Do not include this directly — go through brix.h.
 */
#pragma once

/* ---- cksum_manifest.c ---- */
/* Parse one line of the sha256sum-style tree-audit manifest: "<hex>  <rel>\n".
 * Two spaces separate the hex digest from the relative path; the trailing newline
 * (or CRLF) is stripped.  Returns 0 on success with hex[hexsz] and rel[relsz]
 * filled (NUL-terminated); returns -1 when the line is malformed (no double-space
 * separator, non-hex digest chars, empty rel, oversized fields) or when the rel
 * path is unsafe (brix_rel_is_unsafe: absolute or contains ".."). */
int brix_ckmf_parse_line(const char *line, char *hex, size_t hexsz,
                         char *rel, size_t relsz);

/* ---- checksum.c ---- */
typedef enum {
    XRDC_CK_ADLER32 = 0,
    XRDC_CK_CRC32C,
    XRDC_CK_MD5,
    XRDC_CK_CRC64,      /* CRC-64/XZ   */
    XRDC_CK_CRC64NVME,  /* CRC-64/NVME */
    XRDC_CK_ZCRC32,     /* zlib CRC-32 — XRootD "zcrc32" (8 hex) */
    XRDC_CK_SHA1,       /* §7.13 sha family — LOCAL digests (literal/:print
                         * modes); the server Qcksum plane does not speak
                         * them, so :source comparison is a usage error */
    XRDC_CK_SHA256,
    XRDC_CK_SHA512
} brix_cksum_algo;

/* Map an algorithm name ("adler32"/"crc32c"/"md5") to the enum. 0 / -1. */
int brix_cksum_algo_parse(const char *name, brix_cksum_algo *out);
/* Streaming local checksum over a file descriptor; writes a lowercase hex digest
 * (NUL-terminated) into hex[hexsz] (need ≥33 for md5). 0 / -1. */
int brix_cksum_fd(int fd, brix_cksum_algo algo, char *hex, size_t hexsz,
                  brix_status *st);
/* Ask the server for a file's checksum via kXR_query/kXR_Qcksum (redirect-aware).
 * On success writes the server's hex digest into hex[hexsz]. 0 / -1. */
int brix_query_cksum(brix_conn *c, const char *path, const char *algo_name,
                     char *hex, size_t hexsz, brix_status *st);

/* ---- cks_verify.c (verify a file on disk against its recorded checksum) ---- */
#define XRDC_CKV_HEX_MAX 129

/* Which recorded-checksum sources to consult. */
typedef enum {
    XRDC_CKV_AUTO = 0,   /* cache sidecars (.cinfo/.meta) AND storage (xattr/.cks) */
    XRDC_CKV_CACHE,      /* proxy cache only: <file>.cinfo / <file>.meta cks fields */
    XRDC_CKV_STORAGE     /* storage only: user.XrdCks.<alg> xattr + <file>.cks sidecar */
} brix_ckv_mode;

/* Outcome of a verification. */
typedef enum {
    XRDC_CKV_OK = 0,        /* a recorded checksum was found and matches */
    XRDC_CKV_MISMATCH,      /* recorded != recomputed (corruption) */
    XRDC_CKV_NO_RECORD,     /* no recorded checksum found for this file/algo */
    XRDC_CKV_UNSUPPORTED,   /* recorded with an algorithm this engine cannot compute */
    XRDC_CKV_ERROR          /* I/O / access error */
} brix_ckv_result;

/* Filled with the decisive record (the match, or the mismatch). */
typedef struct {
    char source[16];                 /* "xattr" | "cks" | "cinfo" | "meta" */
    char algo[16];
    char recorded[XRDC_CKV_HEX_MAX];
    char computed[XRDC_CKV_HEX_MAX];
} brix_ckv_report;

/* Recompute `path`'s checksum and compare it to the value recorded on disk.
 * want_algo NULL ⇒ verify every recorded checksum; non-NULL ⇒ only that algo.
 * `rep` (may be NULL) receives the decisive record. See cks_verify.c. */
brix_ckv_result brix_cks_verify_file(const char *path, const char *want_algo,
    brix_ckv_mode mode, brix_ckv_report *rep, brix_status *st);

/* ---- cli_cksum.c (shared checksum-tool front-end) ---- */
/* Process-exit conventions shared by the front-end tools (phase-49):
 *   USAGE — bad arguments / URL parse / local open  (was the bare `return 50`)
 *   IO    — runtime I/O failure
 *   AUTH  — authentication/authorization failure
 * Runtime failures prefer brix_shellcode(st), which maps a status to a stable
 * code; these are for the cases that never produced a status. */
#define XRDC_EXIT_USAGE  50
#define XRDC_EXIT_IO     51
#define XRDC_EXIT_AUTH   53

/* The whole body of xrdcrc32c / xrdcrc64 / xrdadler32: checksum a LOCAL file or a
 * root:// file with `algo` (local enum) / `algo_name` (wire name) and print
 * "<hex> <path>". Returns the process exit code. `arg` is the single CLI argument
 * (NULL ⇒ usage). `err_exit` is the tool's process exit code for ANY failure to
 * produce a checksum (connect/query/open/digest), chosen to match the stock tool
 * byte-for-byte: xrdadler32 → 1, xrdcrc32c → 3, xrdcrc64 → 1. Argument/URL-parse
 * errors still return XRDC_EXIT_USAGE. */
int brix_cli_cksum_main(const char *prog, const char *algo_name,
                        brix_cksum_algo algo, const char *arg, int err_exit);
