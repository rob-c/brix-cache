/* ---------------------------------------------------------------------------
 * fnv.h — single source of truth for the FNV-1a hash constants.
 *
 * WHAT: The two magic values that define each FNV-1a variant — the offset
 *       basis (seed) and the prime (per-byte multiplier) — in both the 64-bit
 *       and 32-bit widths the tree uses.
 *
 * WHY:  These constants were duplicated as bare literals across five hashers
 *       (config fingerprint, cvmfs geo/gate routing, SHM kv, per-VO metrics,
 *       negcache), some in hex and some in decimal, so a reader could not tell
 *       at a glance that two sites hash identically.  One named home keeps the
 *       algorithm's identity obvious and the values impossible to mistype.
 *
 * HOW:  Compile-time integer macros only — a hasher seeds `h` with the offset
 *       basis, then `h = (h ^ byte) * PRIME` per byte (FNV-1a byte order).
 *       These are the canonical published FNV-1a constants; do not "tune" them.
 * ------------------------------------------------------------------------- */

#ifndef BRIX_CORE_FNV_H
#define BRIX_CORE_FNV_H

/* FNV-1a, 64-bit. */
#define BRIX_FNV1A64_OFFSET_BASIS  0xcbf29ce484222325ULL
#define BRIX_FNV1A64_PRIME         0x100000001b3ULL

/* FNV-1a, 32-bit. */
#define BRIX_FNV1A32_OFFSET_BASIS  0x811c9dc5u
#define BRIX_FNV1A32_PRIME         0x01000193u

#endif /* BRIX_CORE_FNV_H */
