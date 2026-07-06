/* WLCG token signature/claims conformance — Layer-1 unit (ngx-free).
 *
 * WHAT: Standalone unit tests for the token b64url+JSON parsing layer.
 * WHY:  Verifies base64url decoding, JSON claim extraction, audience matching,
 *       wlcg.ver presence, and the temporal skew formula as a foundation for
 *       the full JWT conformance validated in later wire-level pytest layers.
 * HOW:  Links b64url.c + json.c; no nginx headers.  Feed hand-written JSON
 *       payload strings — NOT full JWTs — to the extractor API.
 *
 * WIRE-ONLY (not C-reachable here):
 *   SIG-01  alg=none block       — needs full JWT verify path in validate.c
 *   SIG-02  HS256-confusion      — needs EVP + HMAC key material
 *   SIG-10..14 kid selection/multi-key — needs keystore + signature.c
 *   ES256/RS256 signature verify — needs EVP RSA/EC keys
 *   See pytest Tasks 8 and 12 for these.
 *
 * NOTE: b64url_decode takes uint8_t *out (not u_char *); we use uint8_t
 *       throughout to match the declared prototype and avoid
 *       -Wincompatible-pointer-types.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "auth/token/b64url.h"
#include "auth/token/json.h"

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                            \
    g_checks++;                                                           \
    if (cond) { printf("  ok   %s\n", name); }                           \
    else { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

/* --------------------------------------------------------------------------
 * Intended temporal formula (Task 6 implements this in validate.c with a
 * configurable skew replacing the hardcoded BRIX_TOKEN_CLOCK_SKEW_SECS).
 * These local copies lock the arithmetic the wire tests then verify end-to-end.
 * -------------------------------------------------------------------------- */
static int token_exp_ok(int64_t exp, int64_t now, int skew)
{
    return now <= exp + skew;
}

static int token_nbf_ok(int64_t nbf, int64_t now, int skew)
{
    return nbf <= 0 || now >= nbf - skew;
}

/* --------------------------------------------------------------------------
 * SIG — algorithm string extraction (C-reachable cases only)
 * -------------------------------------------------------------------------- */
static void test_sig(void)
{
    char    buf[64];
    ssize_t n;

    /* SIG-alg-extract: canonical upper-case algorithm strings round-trip as-is */
    const char *j_rs256 = "{\"alg\":\"RS256\"}";
    n = json_get_string(j_rs256, strlen(j_rs256), "alg", buf, sizeof(buf));
    CHECK(n == 5 && strcmp(buf, "RS256") == 0, "SIG-alg-RS256");

    const char *j_es256 = "{\"alg\":\"ES256\"}";
    n = json_get_string(j_es256, strlen(j_es256), "alg", buf, sizeof(buf));
    CHECK(n == 5 && strcmp(buf, "ES256") == 0, "SIG-alg-ES256");

    /* SIG-03: lower-case "rs256" is extracted verbatim — the wire validator
     * compares against "RS256"/"ES256" (exact) and will therefore reject it. */
    const char *j_lc = "{\"alg\":\"rs256\"}";
    n = json_get_string(j_lc, strlen(j_lc), "alg", buf, sizeof(buf));
    CHECK(n >= 0 && strcmp(buf, "RS256") != 0, "SIG-03-lowercase-ne-RS256");
    CHECK(n >= 0 && strcmp(buf, "rs256") == 0, "SIG-03-lowercase-eq-rs256");
}

/* --------------------------------------------------------------------------
 * CLM — numeric claim extraction and type enforcement
 * -------------------------------------------------------------------------- */
static void test_clm(void)
{
    int64_t val;
    int     rc;

    /* exp extraction: valid integer value */
    const char *j_exp = "{\"exp\":1893456000}";
    rc = json_get_int64(j_exp, strlen(j_exp), "exp", &val);
    CHECK(rc == 0 && val == 1893456000LL, "CLM-exp-extract");

    /* exp wrong type: string "1893456000" must fail — a string is non-integer */
    const char *j_exp_str = "{\"exp\":\"1893456000\"}";
    rc = json_get_int64(j_exp_str, strlen(j_exp_str), "exp", &val);
    CHECK(rc == -1, "CLM-exp-string-fails");

    /* exp missing key entirely */
    const char *j_no_exp = "{\"iss\":\"x\"}";
    rc = json_get_int64(j_no_exp, strlen(j_no_exp), "exp", &val);
    CHECK(rc == -1, "CLM-exp-missing");

    /* nbf extraction: valid integer value */
    const char *j_nbf = "{\"nbf\":1700000000}";
    rc = json_get_int64(j_nbf, strlen(j_nbf), "nbf", &val);
    CHECK(rc == 0 && val == 1700000000LL, "CLM-nbf-extract");

    /* iat extraction: valid integer value */
    const char *j_iat = "{\"iat\":1699900000}";
    rc = json_get_int64(j_iat, strlen(j_iat), "iat", &val);
    CHECK(rc == 0 && val == 1699900000LL, "CLM-iat-extract");
}

/* --------------------------------------------------------------------------
 * CLM temporal — skew formula locked by local helpers (not calling validate.c)
 * -------------------------------------------------------------------------- */
static void test_clm_temporal(void)
{
    const int SKEW = 60;

    /* exp==now: exactly at boundary — ok */
    CHECK(token_exp_ok(1000, 1000, SKEW), "CLM-exp-boundary-ok");

    /* now==exp+skew: still within tolerance — ok */
    CHECK(token_exp_ok(1000, 1060, SKEW), "CLM-exp-plus-skew-ok");

    /* now==exp+skew+1: one second beyond skew — NOT ok */
    CHECK(!token_exp_ok(1000, 1061, SKEW), "CLM-exp-plus-skew-plus1-fail");

    /* nbf==now: exactly at not-before boundary — ok */
    CHECK(token_nbf_ok(1000, 1000, SKEW), "CLM-nbf-boundary-ok");

    /* nbf==now+skew: future but within skew tolerance — ok */
    CHECK(token_nbf_ok(1060, 1000, SKEW), "CLM-nbf-future-within-skew-ok");

    /* nbf==now+skew+1: one second beyond skew in the future — NOT ok */
    CHECK(!token_nbf_ok(1061, 1000, SKEW), "CLM-nbf-future-beyond-skew-fail");

    /* nbf==0: absent / zero — always ok regardless of now */
    CHECK(token_nbf_ok(0, 1000, SKEW), "CLM-nbf-zero-always-ok");
}

/* --------------------------------------------------------------------------
 * b64url edge cases (structural layer beneath JWT payload parsing)
 * -------------------------------------------------------------------------- */
static void test_b64url(void)
{
    uint8_t out[128];
    char    encoded[64];
    ssize_t n;

    /* Known-vector: "hello" → "aGVsbG8" (no trailing padding) */
    n = b64url_decode("aGVsbG8", 7, out, sizeof(out));
    CHECK(n == 5 && memcmp(out, "hello", 5) == 0, "b64url-known-vector");

    /* Padding-free round-trip: encode then decode must recover original bytes */
    b64url_encode("world", 5, encoded, sizeof(encoded));
    n = b64url_decode(encoded, strlen(encoded), out, sizeof(out));
    CHECK(n == 5 && memcmp(out, "world", 5) == 0, "b64url-round-trip");

    /* Invalid character in base64url alphabet → decode failure */
    n = b64url_decode("aG!sbG8", 7, out, sizeof(out));
    CHECK(n == -1, "b64url-invalid-char");

    /* Empty input → 0 decoded bytes */
    n = b64url_decode("", 0, out, sizeof(out));
    CHECK(n == 0, "b64url-empty");
}

/* --------------------------------------------------------------------------
 * AUD — audience matching via json_string_or_array_contains
 * -------------------------------------------------------------------------- */
static void test_aud(void)
{
    /* Scalar aud string: exact match and miss */
    const char *j_scalar = "{\"aud\":\"nginx-xrootd\"}";
    CHECK(json_string_or_array_contains(j_scalar, strlen(j_scalar),
          "aud", "nginx-xrootd") == 1, "AUD-scalar-match");
    CHECK(json_string_or_array_contains(j_scalar, strlen(j_scalar),
          "aud", "other") == 0, "AUD-scalar-miss");

    /* Array: target needle at first position */
    const char *j_arr_first = "{\"aud\":[\"nginx-xrootd\",\"b\",\"c\"]}";
    CHECK(json_string_or_array_contains(j_arr_first, strlen(j_arr_first),
          "aud", "nginx-xrootd") == 1, "AUD-array-first");

    /* Array: target needle at middle position */
    const char *j_arr_mid = "{\"aud\":[\"a\",\"nginx-xrootd\",\"c\"]}";
    CHECK(json_string_or_array_contains(j_arr_mid, strlen(j_arr_mid),
          "aud", "nginx-xrootd") == 1, "AUD-array-middle");

    /* Array: target needle at last position */
    const char *j_arr_last = "{\"aud\":[\"a\",\"b\",\"nginx-xrootd\"]}";
    CHECK(json_string_or_array_contains(j_arr_last, strlen(j_arr_last),
          "aud", "nginx-xrootd") == 1, "AUD-array-last");

    /* Array present but needle absent */
    const char *j_arr_miss = "{\"aud\":[\"a\",\"b\"]}";
    CHECK(json_string_or_array_contains(j_arr_miss, strlen(j_arr_miss),
          "aud", "nginx-xrootd") == 0, "AUD-array-miss");

    /* Empty array — nothing can match */
    const char *j_empty = "{\"aud\":[]}";
    CHECK(json_string_or_array_contains(j_empty, strlen(j_empty),
          "aud", "nginx-xrootd") == 0, "AUD-empty-array");

    /* Key absent entirely */
    const char *j_no_aud = "{\"iss\":\"x\"}";
    CHECK(json_string_or_array_contains(j_no_aud, strlen(j_no_aud),
          "aud", "nginx-xrootd") == 0, "AUD-missing-key");
}

/* --------------------------------------------------------------------------
 * VER — wlcg.ver field extraction
 * -------------------------------------------------------------------------- */
static void test_ver(void)
{
    char    buf[32];
    ssize_t n;

    /* VER-01: key present with expected version string */
    const char *j_ver = "{\"wlcg.ver\":\"1.0\"}";
    n = json_get_string(j_ver, strlen(j_ver), "wlcg.ver", buf, sizeof(buf));
    CHECK(n == 3 && strcmp(buf, "1.0") == 0, "VER-01-present");

    /* VER-02: key missing — extraction must fail */
    const char *j_no_ver = "{\"iss\":\"x\"}";
    n = json_get_string(j_no_ver, strlen(j_no_ver), "wlcg.ver", buf, sizeof(buf));
    CHECK(n == -1, "VER-02-missing");

    /* VER-03: alternate version — extraction works; whether "2.0" is accepted
     * is an enforcement decision tested at the wire level (pytest), not here. */
    const char *j_ver2 = "{\"wlcg.ver\":\"2.0\"}";
    n = json_get_string(j_ver2, strlen(j_ver2), "wlcg.ver", buf, sizeof(buf));
    CHECK(n == 3 && strcmp(buf, "2.0") == 0, "VER-03-alt-version-extracted");
}

int main(void)
{
    /* Task-3 skeleton check (preserved) */
    uint8_t  out[64];
    ssize_t  n = b64url_decode("aGVsbG8", 7, out, sizeof(out)); /* "hello" */
    CHECK(n == 5 && memcmp(out, "hello", 5) == 0, "b64url decode hello");

    printf("\n--- SIG ---\n");
    test_sig();

    printf("\n--- CLM ---\n");
    test_clm();

    printf("\n--- CLM temporal (skew formula) ---\n");
    test_clm_temporal();

    printf("\n--- b64url edge cases ---\n");
    test_b64url();

    printf("\n--- AUD ---\n");
    test_aud();

    printf("\n--- VER ---\n");
    test_ver();

    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
