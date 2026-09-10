#ifndef BRIX_CACHE_VERIFY_H
#define BRIX_CACHE_VERIFY_H

/*
 * verify.h — checksum-on-fill integrity for the read-through cache.
 *
 * WHAT: After a fill has streamed a complete file into its ".part" staging file
 *       (but BEFORE the atomic rename that publishes it), recompute the file's
 *       content checksum locally and compare it to the digest the origin
 *       advertised.  A mismatch discards the part so a corrupted transfer never
 *       becomes a served cache entry; a match records the verified digest in the
 *       file's .cinfo (BRIX_CINFO_F_VERIFIED) for durable provenance.
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
 *       (brix_checksum_hex_name_fd) for the SAME algorithm name, and compares
 *       the two hex strings case-insensitively.  It is transport-agnostic: the
 *       xroot:// driver feeds it a kXR_Qcksum reply, the HTTP driver a Digest
 *       header — the verify logic is identical.
 */

#include "cache_internal.h"
#include "fs/cache/origin/transport.h"


/* Verification policy (config: brix_cache_verify off|best-effort|require,
 * plus the phase-68 self-verifying mode cvmfs-cas). */
typedef enum {
    BRIX_CACHE_VERIFY_OFF = 0,    /* never verify (legacy behaviour)          */
    BRIX_CACHE_VERIFY_BESTEFFORT, /* verify if a digest is available (default)*/
    BRIX_CACHE_VERIFY_REQUIRE,    /* a usable digest is mandatory; else fail  */
    BRIX_CACHE_VERIFY_CVMFS_CAS,  /* phase-68: the object NAME is the digest
                                       (CVMFS content-addressed storage) — no
                                       origin digest needed                     */
    BRIX_CACHE_VERIFY_OCI_DIGEST, /* phase-104 D2.3: the OCI cache key names a
                                       sha256 content digest — same
                                       self-verifying shape, different grammar  */
    BRIX_CACHE_VERIFY_RPM_REPODATA /* phase-104 D15.9: createrepo names every
                                       metadata file `<checksum>-<name>`, so an
                                       RPM repodata key names its own digest —
                                       the third self-addressing grammar        */
} brix_cache_verify_mode_e;

/* brix_cache_verify_effective — read the configured policy the ONE way the
 * standalone (brix_cache + brix_cache_export) fill spine may read it.  brix_cache_verify
 * writes common.cache_verify_mode, which stays NGX_CONF_UNSET_UINT until an
 * operator sets it; this cache has always defaulted to best-effort, so an
 * unset value keeps that default while an explicit `off`/`require` is now
 * honoured (before 2.0 the spine read a field no directive could write, so
 * every standalone cache verified best-effort whatever the config said).
 * The composed tier stack maps the same field in
 * runtime_server_backend_cache.c, where unset means off. */
static ngx_inline brix_cache_verify_mode_e
brix_cache_verify_effective(ngx_uint_t mode)
{
    return (mode == NGX_CONF_UNSET_UINT)
         ? BRIX_CACHE_VERIFY_BESTEFFORT
         : (brix_cache_verify_mode_e) mode;
}

/*
 * Phase-115 W4.3 — PER-PAGE origin verification, the second integrity axis.
 *
 * brix_cache_verify (above) checks a COMPLETED fill against the origin's
 * advertised whole-file digest.  That leaves two holes: a partial/slice fill
 * has no whole file to hash, and an origin that cannot answer kXR_Qcksum has
 * no digest to compare against.  Per-page verification closes both by asking
 * for the bytes with kXR_pgread, whose reply carries a CRC32c for every 4 KiB
 * page, and checking each page BEFORE it is written (origin_pgread.c).
 *
 * It is armed per ORIGIN, not per cache — `verify_pages` on the root:// store
 * line — because it is a property of the link to that origin and of what that
 * origin can do, not of the store the bytes land in.
 *
 * BESTEFFORT falls back to kXR_read when the origin cannot do page reads;
 * REQUIRE fails the read instead, so "require" cannot be silently downgraded
 * by an origin that simply declines the request.
 */
typedef enum {
    BRIX_PGVERIFY_OFF = 0,      /* plain kXR_read (default)                  */
    BRIX_PGVERIFY_BESTEFFORT,   /* pgread when the origin can; else kXR_read */
    BRIX_PGVERIFY_REQUIRE       /* pgread or fail — never an unverified byte */
} brix_pgverify_mode_e;

/* 1 iff `mode` is a SELF-ADDRESSING scheme: the cache key itself names the
 * expected digest, so the fill needs no origin-advertised checksum at all.
 * The three such modes share one dispatcher, one fail-closed policy and one
 * local-posix-store requirement; asking here is what keeps the three call
 * sites that care from each enumerating the list and drifting apart. */
#define brix_cache_verify_is_selfaddr(mode)                                  \
    ((mode) == BRIX_CACHE_VERIFY_CVMFS_CAS                                   \
     || (mode) == BRIX_CACHE_VERIFY_OCI_DIGEST                               \
     || (mode) == BRIX_CACHE_VERIFY_RPM_REPODATA)

/* The config spelling of `mode` — the token an operator wrote after
 * brix_cache_verify. Every diagnostic that names a mode reads it from here so
 * a log line and the directive that produced it cannot disagree. */
const char *brix_cache_verify_mode_str(ngx_uint_t mode);

/* Outcome of a verification attempt. */
typedef enum {
    BRIX_CACHE_VERIFY_VERIFIED = 0, /* computed == origin digest               */
    BRIX_CACHE_VERIFY_UNVERIFIED,   /* no origin digest; committed best-effort  */
    BRIX_CACHE_VERIFY_MISMATCH,     /* computed != origin digest (reject fill)  */
    BRIX_CACHE_VERIFY_ERROR         /* could not compute / I/O error            */
} brix_cache_verify_result_e;

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
 * into the .meta sidecar (brix_cache_meta_t.cks_alg/cks_hex) it already writes.
 */
brix_cache_verify_result_e brix_cache_verify_part(brix_cache_fill_t *t,
    const char *part_path, const brix_cache_digest_t *origin,
    brix_cache_verify_mode_e mode, char *out_alg, char *out_hex);

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
brix_cache_verify_result_e brix_cache_verify_cvmfs_cas(
    const char *part_path, const char *key, ngx_log_t *log,
    char *out_alg, char *out_hex);

/*
 * Phase-104 D2.3 OCI digest self-verification: a digest-addressed OCI cache key
 * ("/v2/<name>/blobs/sha256:<hex>", or a manifest fetched by digest) names both
 * the algorithm and the digest of the bytes it stores, so — exactly like
 * cvmfs-cas — the staged part is checkable with no origin digest at all. Returns VERIFIED (out_alg/out_hex
 * filled when non-NULL), MISMATCH (caller must quarantine: the registry or its
 * CDN served something other than what we asked for), ERROR (could not
 * compute), or UNVERIFIED for keys that are not digest-addressed (tag
 * manifests, the tags list). `log` may be NULL.
 */
brix_cache_verify_result_e brix_cache_verify_oci_digest(
    const char *part_path, const char *key, ngx_log_t *log,
    char *out_alg, char *out_hex);

/*
 * Phase-104 D15.9 RPM repodata self-verification: createrepo writes every file
 * beside repomd.xml as `<checksum>-<name>`, so a digest-named metadata key
 * carries the digest of the bytes it stores — the same self-addressing shape
 * as cvmfs-cas and oci-digest, over a third grammar. The hex LENGTH names the
 * algorithm (sha1/sha256/sha384/sha512), and that is the one the part is
 * hashed under. Returns VERIFIED (out_alg/out_hex filled when non-NULL),
 * MISMATCH (caller must quarantine: the mirror upstream served metadata that
 * is not what the repository index names), ERROR (could not compute), or
 * UNVERIFIED for every other route — repomd.xml is mutable by definition and
 * packages carry their proof inside the RPM header, not in the path.
 * `log` may be NULL.
 */
brix_cache_verify_result_e brix_cache_verify_rpm_repodata(
    const char *part_path, const char *key, ngx_log_t *log,
    char *out_alg, char *out_hex);

/*
 * Quarantine a failed part: rename it into <quarantine_dir>/<basename>.<ts>
 * instead of unlinking, when a quarantine dir is configured ("" / NULL ⇒
 * plain unlink). Best-effort — the caller's fill_abort tolerates the part
 * being gone. Quarantined files are the operator's corruption evidence.
 */
void brix_cache_quarantine_part(const char *part_path,
    const char *quarantine_dir, ngx_log_t *log);


#endif /* BRIX_CACHE_VERIFY_H */
