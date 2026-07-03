/*
 * fattr_codec.h — kXR_fattr name-vector (nvec) wire codec (shared).
 *
 * WHAT: parse one nvec entry — [int16 BE rc][name NUL-terminated] — the unit
 *       repeated in kXR_fattr request bodies and echoed in replies.
 * WHY:  the module parses the request nvec (src/fattr/helpers.c) and the native
 *       client parses the reply nvec (client/lib/fattr.c) with the same scan; one
 *       shared, READ-ONLY parser keeps the layout in one place.
 * HOW:  pure ptr+len, no allocation, no policy. The parser is read-only: it never
 *       writes the rc slot, so the server keeps its mark-then-rewrite of that slot
 *       (rc_ptr = buf + entry_off) and its `user.U.` xkey naming entirely on its
 *       side; the caller enforces any name-length policy. (libxrdproto)
 */
#ifndef BRIX_COMPAT_FATTR_CODEC_H
#define BRIX_COMPAT_FATTR_CODEC_H

#include <stddef.h>
#include <stdint.h>

/*
 * Parse one nvec entry at buf+off (buf is `len` bytes total).
 *   *rc       (optional) ← the 2-byte big-endian per-attribute status field
 *   *name     (optional) ← pointer to the name bytes (into buf; not copied)
 *   *nlen     (optional) ← name length, excluding the NUL
 *   *next_off (optional) ← offset just past the name's NUL (start of next entry)
 * Returns 0 on success, -1 if the entry is truncated or the name is unterminated.
 * The 2-byte rc slot lives at buf+off — a caller that must rewrite it in place
 * (the server) holds that pointer itself; this function never mutates buf.
 */
int xrdp_fattr_nvec_parse(const uint8_t *buf, size_t len, size_t off,
                          uint16_t *rc, const uint8_t **name, size_t *nlen,
                          size_t *next_off);

#endif /* BRIX_COMPAT_FATTR_CODEC_H */
