/* WLCG token signature/claims conformance — Layer-1 unit (ngx-free).
 *
 * WHAT: Standalone unit tests for the token b64url+JSON parsing layer.
 * WHY:  Verifies base64url decoding round-trips correctly as a foundation for
 *       JWT header/payload parsing in later conformance layers.
 * HOW:  Links b64url.c + json.c; no nginx headers.  One skeleton check (b64url).
 *
 * NOTE: b64url_decode takes uint8_t *out (not u_char *); we use uint8_t throughout
 *       to match the declared prototype and avoid -Wincompatible-pointer-types.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "auth/token/b64url.h"

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                            \
    g_checks++;                                                           \
    if (cond) { printf("  ok   %s\n", name); }                           \
    else { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

int main(void)
{
    uint8_t  out[64];
    ssize_t  n = b64url_decode("aGVsbG8", 7, out, sizeof(out)); /* "hello" */
    CHECK(n == 5 && memcmp(out, "hello", 5) == 0, "b64url decode hello");
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
