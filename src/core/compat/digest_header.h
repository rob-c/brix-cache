#ifndef BRIX_COMPAT_DIGEST_HEADER_H
#define BRIX_COMPAT_DIGEST_HEADER_H

/*
 * digest_header.h — the RFC-3230 `Digest:` header grammar, in both directions.
 *
 * One header carries a comma-separated list of `token=value` pairs, where the
 * token names a checksum algorithm and the encoding of the value depends on it:
 * md5/sha-* are base64 (RFC 3230 + RFC 1864), adler32/crc32* are lowercase hex
 * (the WLCG/dCache convention XRootD and dCache interoperate on). This module
 * owns that grammar so the two directions cannot drift:
 *
 *   inbound  — a WebDAV PUT asserting what the client sent (put_body_digest.c)
 *   outbound — a `Want-Digest:` request to an HTTP origin, and the `Digest:`
 *              it answers with (the sd_http checksum-offload slot)
 *
 * Pool-free by design (a storage driver runs on AIO threads with no request
 * pool), so every value is normalised through caller-provided buffers.
 */

#include <ngx_config.h>
#include <ngx_core.h>

/* Longest value the grammar yields: sha-512 = 128 hex chars + NUL. */
#define BRIX_DIGEST_HEX_MAX  129

typedef enum {
    BRIX_DIGEST_NONE = 0,   /* no algorithm we support was named             */
    BRIX_DIGEST_FOUND,      /* supported algorithm parsed; hex_out is filled */
    BRIX_DIGEST_BAD         /* supported algorithm named, value unusable     */
} brix_digest_kind_t;

/*
 * brix_digest_wire_token — the RFC-3230 token that names a canonical algorithm.
 *
 * WHAT: Maps a canonical brix algorithm name ("sha256", "adler32") to the token
 *       an origin expects in `Want-Digest:` ("sha-256", "adler32"); NULL when the
 *       algorithm has no registered token (the CRC-64 family).
 * WHY:  Canonical names and wire tokens differ exactly where RFC 3230 hyphenates
 *       the SHA family; asking an origin for "sha256" gets a shrug from a
 *       compliant one.
 */
const char *brix_digest_wire_token(const char *canon_alg);

/*
 * brix_digest_header_scan — find a usable digest in a `Digest:` header value.
 *
 * WHAT: Walks the comma-separated `token=value` pairs. With want_canon NULL the
 *       FIRST pair naming a supported algorithm decides; with want_canon set,
 *       only a pair naming exactly that canonical algorithm does (others are
 *       skipped, so an origin listing several digests still answers). Returns
 *       FOUND with hex_out holding the lowercase-hex value (and *alg_out, when
 *       non-NULL, pointing at the static canonical name), BAD when a supported
 *       algorithm carries an unusable value, or NONE.
 * WHY:  Both directions need "is the digest I can use in here, and what is it in
 *       hex" — the encoding split (base64 vs hex) is per-algorithm and is the
 *       part everyone gets wrong.
 */
brix_digest_kind_t brix_digest_header_scan(const u_char *val, size_t len,
    const char *want_canon, const char **alg_out, char *hex_out, size_t hex_sz);

/*
 * brix_digest_value_hex — normalise one digest value into lowercase hex.
 *
 * WHAT: A base64 value (is_b64) is decoded then hex-encoded; a hex value is
 *       validated and lowercased. NGX_ERROR on an empty, malformed or over-long
 *       value. WHY: exported because the legacy `Content-MD5:` header carries a
 *       bare base64 value with no token to scan for.
 */
ngx_int_t brix_digest_value_hex(const u_char *val, size_t vlen, int is_b64,
    char *out, size_t outsz);

/*
 * brix_digest_hex_pad — left-pad a hex value to its algorithm's fixed width.
 *
 * WHAT: Zero-extends `hex` in place to the canonical width of `canon_alg`
 *       (adler32/crc32* → 8, md5 → 32, sha-1 → 40, sha-256 → 64, sha-512 → 128);
 *       a no-op for an unknown algorithm or a value already at least that long.
 * WHY:  An origin may drop leading zeros from an adler32 ("1a2b3c"), but a
 *       checksum we hand back as authoritative is compared literally by clients
 *       against a zero-padded computation.
 */
void brix_digest_hex_pad(const char *canon_alg, char *hex, size_t hex_sz);

#endif /* BRIX_COMPAT_DIGEST_HEADER_H */
