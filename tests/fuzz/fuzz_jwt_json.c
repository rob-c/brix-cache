/* tests/fuzz/fuzz_jwt_json.c — libFuzzer target for the JWT/JWKS JSON helpers.
 *
 * WHAT: Feeds arbitrary bytes as the JSON document to every extraction helper in
 *       src/auth/token/json.c — json_get_string, json_get_string_array,
 *       json_get_int64, json_string_or_array_contains, json_has_member — under
 *       ASan + UBSan.
 *
 * WHY:  These helpers parse the JWT header/claim set and the JWKS key document,
 *       both of which are attacker-controlled bytes decoded from a bearer token
 *       BEFORE the signature is verified (the parse must run to find `alg`/`kid`
 *       and the claims). A crash, overflow, or leak here is pre-auth
 *       remote-reachable (hyper-hardening C-1, target 2). The helpers are thin
 *       wrappers over jansson, but they own the bounds that matter: the
 *       out_max-1 copy cap in json_get_string, the fixed [256] per-item
 *       truncation in json_get_string_array, the fractional-NumericDate handling
 *       in json_get_int64, and the exact string/array-of-strings match in
 *       json_string_or_array_contains — this exercises all of them plus jansson
 *       itself on hostile input. (Note: json.c is jansson-backed, not the
 *       hand-rolled parser the plan text predates.)
 *
 * Build: see tests/fuzz/README.md (clang -fsanitize=fuzzer,address,undefined,
 *        links json.c + -ljansson). Driven in CI by cmdscripts.fuzz_all.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/auth/token/json.h"

/* Keys chosen to hit the real JWT/JWKS parse paths: a claim string (sub), the
 * dual string-or-array audience claim (aud), a NumericDate (exp), and a header
 * member probe (crit, RFC 7515 §4.1.11). */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char        strbuf[512];
    char        arr[8][256];
    int64_t     num;
    size_t      out_max;
    const char *json;
    size_t      json_len;

    if (size < 2) {
        return 0;
    }

    /* First byte derives the string output cap so both exact-fit and
     * deliberately-undersized destinations are exercised (the copy must clamp to
     * out_max-1, never overflow strbuf). */
    out_max = (size_t) data[0] % sizeof(strbuf);
    if (out_max == 0) {
        out_max = 1;
    }

    json     = (const char *) data + 1;
    json_len = size - 1;

    (void) json_get_string(json, json_len, "sub", strbuf, out_max);
    (void) json_get_string_array(json, json_len, "aud", arr,
                                 (int) (sizeof(arr) / sizeof(arr[0])));
    (void) json_get_int64(json, json_len, "exp", &num);
    (void) json_string_or_array_contains(json, json_len, "aud", "any");
    (void) json_has_member(json, json_len, "crit");

    return 0;
}
