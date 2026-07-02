#ifndef XROOTD_CACHE_VERIFY_H
#define XROOTD_CACHE_VERIFY_H

/*
 * verify.h — checksum-on-fill integrity for the read-through cache.
 *
 * WHAT: After a fill has streamed a complete file into its ".part" staging file
 *       (but BEFORE the atomic rename that publishes it), recompute the file's
 *       content checksum locally and compare it to the digest the origin
 *       advertised.  A mismatch discards the part so a corrupted transfer never
 *       becomes a served cache entry; a match records the verified digest in the
 *       file's .cinfo (XROOTD_CINFO_F_VERIFIED) for durable provenance.
 *
 * WHY:  The cache previously trusted whatever bytes arrived from the origin.  A
 *       truncated, bit-rotted, or man-in-the-middled transfer would be cached
 *       and served to every subsequent client.  Verifying against the origin's
 *       own checksum closes that gap and is the integrity half of XrdPfc that
 *       the module lacked.  The policy is FAIL-CLOSED, BEST-EFFORT (the default):
 *       verify whenever the origin can supply a digest we can compute; commit
 *       (flagged unverified) when it cannot; never serve a proven-bad file.
 *
 * HOW:  The transport (origin/transport.h) reports the origin's advertised
 *       algorithm+hex via its checksum() op.  This module opens the part file
 *       (O_RDONLY|O_NOFOLLOW), drives the shared checksum kernel
 *       (xrootd_checksum_hex_name_fd) for the SAME algorithm name, and compares
 *       the two hex strings case-insensitively.  It is transport-agnostic: the
 *       xroot:// driver feeds it a kXR_Qcksum reply, the HTTP driver a Digest
 *       header — the verify logic is identical.
 */

#include "cache_internal.h"
#include "fs/cache/origin/transport.h"


/* Verification policy (config: xrootd_cache_verify off|best-effort|require,
 * plus the phase-68 self-verifying mode cvmfs-cas). */
typedef enum {
    XROOTD_CACHE_VERIFY_OFF = 0,    /* never verify (legacy behaviour)          */
    XROOTD_CACHE_VERIFY_BESTEFFORT, /* verify if a digest is available (default)*/
    XROOTD_CACHE_VERIFY_REQUIRE,    /* a usable digest is mandatory; else fail  */
    XROOTD_CACHE_VERIFY_CVMFS_CAS   /* phase-68: the object NAME is the digest
                                       (CVMFS content-addressed storage) — no
                                       origin digest needed                     */
} xrootd_cache_verify_mode_e;

/* Outcome of a verification attempt. */
typedef enum {
    XROOTD_CACHE_VERIFY_VERIFIED = 0, /* computed == origin digest               */
    XROOTD_CACHE_VERIFY_UNVERIFIED,   /* no origin digest; committed best-effort  */
    XROOTD_CACHE_VERIFY_MISMATCH,     /* computed != origin digest (reject fill)  */
    XROOTD_CACHE_VERIFY_ERROR         /* could not compute / I/O error            */
} xrootd_cache_verify_result_e;

/*
 * Verify the staged part file at `part_path` against `origin` under `mode`.
 *
 * Returns:
 *   VERIFIED    — origin digest present and matched; out_alg / out_hex hold the
 *                 canonical algorithm name and computed hex (for the sidecar).
 *   UNVERIFIED  — origin offered no usable digest AND mode==BESTEFFORT: the
 *                 caller commits the file but records it unverified. (In
 *                 mode==REQUIRE this case returns ERROR instead.)
 *   MISMATCH    — origin digest present but differs: caller MUST discard the
 *                 part. t error is set (kXR_ChkSumErr).
 *   ERROR       — could not compute (open/read failure) or REQUIRE with no
 *                 digest. t error is set.
 *
 * mode==OFF short-circuits to UNVERIFIED without touching the file.
 * out_alg (>=16 bytes) / out_hex (>=129 bytes) may be NULL if the caller does
 * not need the computed values.  On VERIFIED the caller persists out_alg/out_hex
 * into the .meta sidecar (xrootd_cache_meta_t.cks_alg/cks_hex) it already writes.
 */
xrootd_cache_verify_result_e xrootd_cache_verify_part(xrootd_cache_fill_t *t,
    const char *part_path, const xrootd_cache_digest_t *origin,
    xrootd_cache_verify_mode_e mode, char *out_alg, char *out_hex);

/*
 * Phase-68 CVMFS-CAS self-verification: the CAS object NAME in the fill's own
 * export-relative key is the SHA-1 of the served bytes (raw-bytes convention,
 * spike-verified 2026-07-02), so no origin digest is needed. Independent of any
 * fill engine — usable from both the legacy fetch.c fill and the sd_cache tier
 * fill. Returns VERIFIED (out_alg/out_hex filled when non-NULL), MISMATCH
 * (caller must discard/quarantine), ERROR (could not compute), or UNVERIFIED
 * for keys that do not classify as CAS (manifests, geo — not content-
 * addressed). `log` may be NULL.
 */
xrootd_cache_verify_result_e xrootd_cache_verify_cvmfs_cas(
    const char *part_path, const char *key, ngx_log_t *log,
    char *out_alg, char *out_hex);

/*
 * Quarantine a failed part: rename it into <quarantine_dir>/<basename>.<ts>
 * instead of unlinking, when a quarantine dir is configured ("" / NULL ⇒
 * plain unlink). Best-effort — the caller's fill_abort tolerates the part
 * being gone. Quarantined files are the operator's corruption evidence.
 */
void xrootd_cache_quarantine_part(const char *part_path,
    const char *quarantine_dir, ngx_log_t *log);


#endif /* XROOTD_CACHE_VERIFY_H */
