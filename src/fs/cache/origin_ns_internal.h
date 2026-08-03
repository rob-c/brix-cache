#ifndef BRIX_CACHE_ORIGIN_NS_INTERNAL_H
#define BRIX_CACHE_ORIGIN_NS_INTERNAL_H

/*
 * origin_ns_internal.h — the one helper shared between origin_ns.c and
 * origin_ns_dirlist.c.
 *
 * The two TUs are one logical unit (origin-side namespace operations) split
 * only because origin_ns.c crossed the 600-line cap (coding-standards §1).
 * This header exists so the split costs exactly one shared symbol instead of a
 * duplicated errno mapping — every origin op has to translate the same kXR
 * error frame the same way, and two copies would drift.
 *
 * Not part of the cache module's public surface: cache_internal.h declares
 * what other subsystems call. Nothing outside src/fs/cache/origin_ns*.c should
 * include this.
 */

#include <stdint.h>

#include <ngx_core.h>

/* Map a non-ok origin response to errno. A failure is a kXR_error frame whose
 * body is [int32 errnum][msg]; the kXR errnum (kXR_NotFound, …) is decoded from
 * it. Some servers instead place the kXR code directly in the status word, so
 * `status` is used as the fallback code. */
int brix_cache_origin_status_errno(uint16_t status, const u_char *body,
    uint32_t dlen);

#endif /* BRIX_CACHE_ORIGIN_NS_INTERNAL_H */
