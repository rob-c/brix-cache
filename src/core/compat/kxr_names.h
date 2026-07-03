/*
 * kxr_names.h — kXR wire-vocabulary name tables (single source of truth).
 *
 * WHAT: Pure int -> const char* lookups for kXR request opcodes, response status
 *       codes, and error codes, keyed on the constants in src/protocol/opcodes.h.
 * WHY:  Both the native client (wire-trace + status reporting) and, in future, the
 *       module's logging want human names for the same wire codes; keeping ONE
 *       table next to opcodes.h prevents the two sides drifting.
 * HOW:  Plain switch statements over the opcodes.h #defines — no allocation, no
 *       ngx, no OpenSSL. Compiles unchanged into libxrdproto (ngx-free core).
 *
 * Clean-room: names come from the documented XRootD wire protocol, not XrdCl.
 */
#ifndef BRIX_COMPAT_KXR_NAMES_H
#define BRIX_COMPAT_KXR_NAMES_H

/* kXR request opcode -> "kXR_open" (kXR_-prefixed); "req?" if unknown. */
const char *brix_kxr_request_name(int reqid);

/* response status -> "ok" / "redirect" / "wait" / ...; "status?" if unknown. */
const char *brix_kxr_response_status_name(int status);

/* kXR error code -> short name "NotFound" (NO kXR_ prefix); "Unknown" if unknown. */
const char *brix_kxr_error_name(int kxr);

#endif /* BRIX_COMPAT_KXR_NAMES_H */
