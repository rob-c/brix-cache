/*
 * auth_sigv4_verify_internal.h — cross-file declarations for the S3 SigV4
 * verification split (auth_sigv4_verify.c / _time.c / _crypto.c).
 *
 * WHAT: Declares the two result structs threaded through one SigV4
 *       verification (the resolved request timestamp and the server-computed
 *       signature material) plus the handful of functions that cross a
 *       translation-unit boundary after the phase-79 file-size split: the
 *       auth-result metric sink, the timestamp resolver, and the two crypto
 *       steps (canonical-request signature compute + constant-time compare).
 *       It also re-exports the two sibling SigV4 entry points the split files
 *       consume (the canonical query-string builder and the header getter).
 * WHY:  auth_sigv4_verify.c exceeded the ~500-line file-size guard, so it was
 *       carved into three cohesive units — the verifier orchestrator (verify.c),
 *       the timestamp parse + clock-skew rules (verify_time.c), and the
 *       byte-frozen canonicalisation + HMAC signing-key + signature compare
 *       (verify_crypto.c). Grouping the shared structs and the crossing entry
 *       points here keeps every definition in exactly one place while preserving
 *       byte-identical canonical-request construction, string-to-sign, HMAC
 *       signing-key derivation, and constant-time signature comparison of the
 *       original single-file implementation. INVARIANT §6: this is SigV4-only
 *       machinery — it shares no logic with WLCG bearer-token auth.
 * HOW:  Requires "s3.h" (nginx request types, ngx_http_s3_loc_conf_t, u_char,
 *       ngx_uint_t) and "s3_auth_internal.h" (sigv4_components_t) before
 *       inclusion; both are included here. Every SigV4-verify .c file includes
 *       this header. The declared symbols are non-static at their definitions so
 *       the split links (a symbol defined in one file and referenced from
 *       another must carry external linkage AND appear here).
 */
#ifndef BRIX_S3_AUTH_SIGV4_VERIFY_INTERNAL_H
#define BRIX_S3_AUTH_SIGV4_VERIFY_INTERNAL_H

#include "s3.h"
#include "s3_auth_internal.h"

/*
 * s3_amz_date_out_t — resolved SigV4 request timestamp.
 *
 * WHAT:  Carries the amz timestamp resolved by s3_sigv4_resolve_request_time:
 *        an inline storage buffer for the header path plus the (buf, len) view
 *        the string-to-sign consumes.
 * WHY:   Bundles the header-scratch buffer and its two out-params into one
 *        object so the resolver stays under the 5-param gate and the buffer's
 *        lifetime (it must outlive the resolve call) is explicit at the callsite.
 * HOW:   For the header path `date` points into `buf`; for the presigned path it
 *        points into comp's own storage. `len` is the strlen of `date`.
 */
typedef struct {
    char        buf[32];   /* header-path scratch; must outlive resolve */
    const char *date;      /* resolved timestamp (into buf or comp) */
    size_t      len;       /* strlen(date) */
} s3_amz_date_out_t;

/*
 * s3_sigv4_sig_out_t — server-computed SigV4 signature material.
 *
 * WHAT:  Outputs of s3_sigv4_compute_signature: the derived signing key (k4)
 *        and the 64-char lowercase-hex server signature.
 * WHY:   Bundles the two crypto outputs so the computer stays under the 5-param
 *        gate; k4 is later needed by s3_sigv4_finish for chunk-sig retention.
 * HOW:   Zero-initialise at declaration; populated only on the NGX_OK return.
 */
typedef struct {
    u_char k4[32];             /* derived signing key */
    char   computed_hex[65];   /* server signature, 64 hex + NUL */
} s3_sigv4_sig_out_t;

/* ---- Cross-translation-unit entry points (defined once, called across the split) ---- */

/* Defined in auth_sigv4_verify.c — record the SigV4 auth outcome into the S3
 * auth-result counters and the unified auth metric. Called from every SigV4
 * verify unit on both the success and rejection edges. */
void s3_record_auth_result(ngx_uint_t result);

/* Defined in auth_sigv4_verify_time.c — parse the SigV4 request timestamp
 * (presigned X-Amz-Date query param or the x-amz-date header), enforce the
 * clock-skew / presigned-expiry limits, and return the full amz timestamp view
 * (out->date/out->len) used in the string-to-sign. Returns NGX_OK on success,
 * otherwise the terminal ngx_int_t result (response already emitted). Called by
 * s3_verify_sigv4 (auth_sigv4_verify.c). */
ngx_int_t s3_sigv4_resolve_request_time(ngx_http_request_t *r,
    const sigv4_components_t *comp, s3_amz_date_out_t *out);

/* Defined in auth_sigv4_verify_crypto.c — build the canonical request and
 * compute the 64-char lowercase-hex server-side SigV4 signature (out->computed_hex)
 * plus the derived signing key (out->k4). Returns NGX_OK on success, NGX_ERROR
 * (result already recorded) on an internal crypto failure. Called by
 * s3_verify_sigv4 (auth_sigv4_verify.c). */
ngx_int_t s3_sigv4_compute_signature(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, const sigv4_components_t *comp,
    const s3_amz_date_out_t *amz, s3_sigv4_sig_out_t *out);

/* Defined in auth_sigv4_verify_crypto.c — the single constant-time signature
 * decision: fold the deferred access-key match (key_ok) and CRYPTO_memcmp of the
 * computed vs client signature into one branch so an unknown key and a bad
 * signature are indistinguishable. Returns NGX_OK when authentic, otherwise the
 * terminal ngx_int_t result. Called by s3_verify_sigv4 (auth_sigv4_verify.c). */
ngx_int_t s3_sigv4_compare(ngx_http_request_t *r, const sigv4_components_t *comp,
    const char computed_hex[65], int key_ok);

/* ---- Sibling SigV4 entry points consumed by the split files ---- */

/* Canonical query-string builder — defined in auth_sigv4_canonical.c. */
size_t build_canonical_qs(const u_char *qs, size_t qslen,
    ngx_flag_t skip_signature, u_char *out, size_t outsz);

/* Request header getter (lowercased name) — defined in auth_sigv4_parse.c. */
ngx_str_t get_header(ngx_http_request_t *r, const char *name);

#endif /* BRIX_S3_AUTH_SIGV4_VERIFY_INTERNAL_H */
