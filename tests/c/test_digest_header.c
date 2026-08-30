/* test_digest_header.c — unit test for the shared RFC-3230 Digest grammar
 * (src/core/compat/digest_header.c).
 *
 * One header, two directions: the WebDAV PUT path parses a client's asserted
 * `Digest:` before committing the body, and the sd_http checksum-offload slot
 * parses an origin's `Digest:` reply instead of dragging the object across the
 * network to hash it. Both go through this grammar, so a client and an origin
 * are never understood by two different parsers — which is exactly why the
 * grammar is pinned here on its own rather than only through its two callers.
 *
 * It proves:
 *   1 (success)      — base64 values (md5/sha-1/sha-256/sha-512) transcode to
 *                      lowercase hex and hex values pass through lowercased;
 *                      the canonical->wire token map returns the REGISTERED
 *                      hyphenated spelling; an origin-trimmed adler32 is
 *                      re-padded to the algorithm width; a multi-valued header
 *                      yields the requested algorithm, and with no request the
 *                      first understood one.
 *   2 (error)        — an unknown token is NONE (not BAD: best-effort interop);
 *                      a known token with an unusable value is BAD; an empty or
 *                      malformed header is NONE; a value too wide for the
 *                      caller's buffer is BAD, never truncated; a zero-capacity
 *                      output is refused.
 *   3 (security-neg) — asking for one algorithm never returns another's digest;
 *                      a token that merely PREFIXES a supported one does not
 *                      match; a non-hex crc value is refused rather than
 *                      half-copied; and a padded sha-512 (the widest value,
 *                      whose base64 decode bound exceeds the digest width)
 *                      parses whole instead of being rejected as unusable.
 *
 * Run via `python3 -m cmdscripts.c_regression_units digest_header`.
 */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "core/compat/digest_header.h"

/* Fixed vectors: bytes 0x00.. of each digest's width, base64 on the wire. The
 * grammar never hashes anything, so these need not be digests of any body. */
#define B64_MD5     "AAECAwQFBgcICQoLDA0ODw=="
#define HEX_MD5     "000102030405060708090a0b0c0d0e0f"
#define B64_SHA1    "AAECAwQFBgcICQoLDA0ODxAREhM="
#define HEX_SHA1    "000102030405060708090a0b0c0d0e0f10111213"
#define B64_SHA256  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
#define HEX_SHA256  "000102030405060708090a0b0c0d0e0f" \
                    "101112131415161718191a1b1c1d1e1f"
#define B64_SHA512  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" \
                    "gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="
#define HEX_SHA512  "000102030405060708090a0b0c0d0e0f" \
                    "101112131415161718191a1b1c1d1e1f" \
                    "202122232425262728292a2b2c2d2e2f" \
                    "303132333435363738393a3b3c3d3e3f"

/* The grammar is pool-free and ngx-string-only, but nginx's string kernel is
 * linked for ngx_decode_base64 — and ngx_alloc.c logs on failure. */
volatile ngx_cycle_t *ngx_cycle = NULL;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

static brix_digest_kind_t
scan(const char *hdr, const char *want, const char **alg, char *hex,
    size_t hex_sz)
{
    memset(hex, 'Z', hex_sz);
    hex[hex_sz - 1] = '\0';
    return brix_digest_header_scan((const u_char *) hdr, strlen(hdr), want, alg,
                                   hex, hex_sz);
}

static void
expect_found(const char *hdr, const char *want, const char *want_hex)
{
    char        hex[BRIX_DIGEST_HEX_MAX];
    const char *alg = NULL;

    assert(scan(hdr, want, &alg, hex, sizeof(hex)) == BRIX_DIGEST_FOUND);
    assert(strcmp(hex, want_hex) == 0);
    assert(alg != NULL);
    if (want != NULL) {
        assert(strcmp(alg, want) == 0);
    }
}

static void
expect_kind(const char *hdr, const char *want, brix_digest_kind_t want_kind)
{
    char hex[BRIX_DIGEST_HEX_MAX];

    assert(scan(hdr, want, NULL, hex, sizeof(hex)) == want_kind);
    if (want_kind != BRIX_DIGEST_FOUND) {
        assert(hex[0] == 'Z');       /* nothing written unless a digest was found */
    }
}

/* Test 1 (success). */
static void
test_grammar_success(void)
{
    char hex[BRIX_DIGEST_HEX_MAX];

    /* base64 per RFC 3230 / RFC 1864, both spellings of each SHA name. */
    expect_found("md5=" B64_MD5, "md5", HEX_MD5);
    expect_found("sha1=" B64_SHA1, "sha1", HEX_SHA1);
    expect_found("SHA-256=" B64_SHA256, "sha256", HEX_SHA256);
    expect_found("sha256=" B64_SHA256, "sha256", HEX_SHA256);
    expect_found("sha-512=" B64_SHA512, "sha512", HEX_SHA512);

    /* the CRC family is hex on the wire (the WLCG/dCache convention). */
    expect_found("adler32=1A2B3C4D", "adler32", "1a2b3c4d");
    expect_found("crc32c=DEADBEEF", "crc32c", "deadbeef");

    /* a multi-valued header: the requested algorithm, wherever it sits... */
    expect_found("adler32=00000001, SHA-256=" B64_SHA256 " ,md5=" B64_MD5,
                 "sha256", HEX_SHA256);
    /* ...and with no request, the first one we understand. */
    expect_found("whirlpool=ff, adler32=00000001", NULL, "00000001");

    /* canonical -> registered wire token (what a Want-Digest asks for). */
    assert(strcmp(brix_digest_wire_token("sha256"), "sha-256") == 0);
    assert(strcmp(brix_digest_wire_token("sha512"), "sha-512") == 0);
    assert(strcmp(brix_digest_wire_token("sha1"), "sha-1") == 0);
    assert(strcmp(brix_digest_wire_token("md5"), "md5") == 0);
    assert(strcmp(brix_digest_wire_token("adler32"), "adler32") == 0);
    assert(brix_digest_wire_token("crc64nvme") == NULL);

    /* origins trim an adler32's leading zeros; a value handed on as
     * authoritative is compared literally, so re-pad to the alg width. */
    snprintf(hex, sizeof(hex), "1a2b3c");
    brix_digest_hex_pad("adler32", hex, sizeof(hex));
    assert(strcmp(hex, "001a2b3c") == 0);

    snprintf(hex, sizeof(hex), "deadbeef");     /* already full width */
    brix_digest_hex_pad("adler32", hex, sizeof(hex));
    assert(strcmp(hex, "deadbeef") == 0);

    snprintf(hex, sizeof(hex), "abc");          /* unknown alg: left alone */
    brix_digest_hex_pad("crc64nvme", hex, sizeof(hex));
    assert(strcmp(hex, "abc") == 0);

    printf("  ok   1: b64+hex values transcode, tokens map to the registered"
           " spelling, trimmed values re-pad\n");
}

/* Test 2 (error). */
static void
test_grammar_error(void)
{
    char hex[BRIX_DIGEST_HEX_MAX];
    char narrow[8];

    /* an algorithm we cannot compute is skipped, not rejected — a PUT naming
     * only unknown algorithms must read as "no digest asserted". */
    expect_kind("whirlpool=deadbeef", NULL, BRIX_DIGEST_NONE);
    expect_kind("", NULL, BRIX_DIGEST_NONE);
    expect_kind("md5", NULL, BRIX_DIGEST_NONE);          /* no '=' at all   */
    expect_kind("md5=", NULL, BRIX_DIGEST_BAD);          /* empty value     */

    /* a known algorithm with an unusable value is BAD: the caller must refuse
     * the transfer rather than treat it as unasserted. */
    expect_kind("md5=@@not-base64@@", NULL, BRIX_DIGEST_BAD);
    expect_kind("adler32=nothex!!", NULL, BRIX_DIGEST_BAD);

    /* the value does not fit the caller's buffer: BAD, never truncated. */
    memset(narrow, 'Z', sizeof(narrow));
    narrow[sizeof(narrow) - 1] = '\0';
    assert(brix_digest_header_scan((const u_char *) "sha-256=" B64_SHA256,
               sizeof("sha-256=" B64_SHA256) - 1, "sha256", NULL, narrow,
               sizeof(narrow)) == BRIX_DIGEST_BAD);
    assert(narrow[0] == 'Z');

    /* degenerate outputs are refused outright. */
    assert(brix_digest_header_scan((const u_char *) "md5=" B64_MD5,
               sizeof("md5=" B64_MD5) - 1, NULL, NULL, hex, 0)
           == BRIX_DIGEST_NONE);
    assert(brix_digest_value_hex((const u_char *) "ab", 2, 0, hex, 0)
           == NGX_ERROR);
    assert(brix_digest_value_hex((const u_char *) "", 0, 0, hex, sizeof(hex))
           == NGX_ERROR);

    printf("  ok   2: unknown alg -> NONE, unusable value -> BAD, narrow or"
           " zero-capacity output refused whole\n");
}

/* Test 3 (security-negative). */
static void
test_grammar_security_neg(void)
{
    char hex[BRIX_DIGEST_HEX_MAX];

    /* asking for one algorithm must never return another's digest — the value
     * would then be compared against a hash of a different function. */
    expect_kind("md5=" B64_MD5, "sha256", BRIX_DIGEST_NONE);
    expect_kind("adler32=00000001,crc32c=deadbeef", "crc32", BRIX_DIGEST_NONE);

    /* a token that merely prefixes (or extends) a supported one is not that
     * algorithm: the match is exact-length, not a prefix compare. */
    expect_kind("sha-25=" B64_SHA256, "sha256", BRIX_DIGEST_NONE);
    expect_kind("md=" B64_MD5, "md5", BRIX_DIGEST_NONE);
    expect_kind("md5x=" B64_MD5, "md5", BRIX_DIGEST_NONE);

    /* a hex value that goes bad partway is refused, not accepted short. */
    expect_kind("crc32=dead!!ef", "crc32", BRIX_DIGEST_BAD);

    /* The widest value, padded: ngx_base64_decoded_length("...==") is 66 for a
     * 64-byte sha-512, so a decode buffer sized at the DIGEST width silently
     * turns every sha-512 into an unusable value — a PUT asserting one would
     * then be refused, and an origin advertising one ignored. */
    assert(scan("sha-512=" B64_SHA512, "sha512", NULL, hex, sizeof(hex))
           == BRIX_DIGEST_FOUND);
    assert(strlen(hex) == 128);
    assert(strcmp(hex, HEX_SHA512) == 0);

    printf("  ok   3: no cross-algorithm answer, exact-length token match, no"
           " short hex, and a padded sha-512 parses whole\n");
}

int
main(void)
{
    test_grammar_success();
    test_grammar_error();
    test_grammar_security_neg();
    printf("test_digest_header: ALL PASS\n");
    return 0;
}
