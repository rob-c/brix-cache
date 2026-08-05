#include "../../src/auth/token/b64url.h"
#include <stdio.h>
#include <string.h>

static int failures;

static void
check(int ok, const char *what)
{
    if (!ok) {
        printf("b64url_decode FAILED: %s\n", what);
        failures++;
    }
}

/* Happy path: a padless base64url token round-trips to its plaintext. */
static void
test_roundtrip(void)
{
    const char *b64url = "SGVsbG8td29ybGQ";
    uint8_t     out[32];
    ssize_t     len = b64url_decode(b64url, strlen(b64url), out, sizeof(out));

    check(len == 11 && memcmp(out, "Hello-world", 11) == 0, "round-trip");
}

/*
 * Security regression (2026-08-05, tests/fuzz/fuzz_b64url): the decode used to
 * run straight into the caller's buffer. OpenSSL writes three bytes for every
 * four base64 characters and subtracts the padding from the *reported* count
 * only, so a padded token wrote up to two bytes past the length it decodes to —
 * while the capacity check explicitly admitted a caller who sized out_max to
 * exactly that length. Pre-auth: every bearer token decodes through here.
 *
 * Each case sizes out_max to the true decoded length and leaves a canary in the
 * bytes just past it, so the overrun is caught without a sanitizer. The
 * unpadded cases ("QUJD", the round-trip above) never overran — padding is what
 * makes the reported length smaller than what OpenSSL writes.
 *
 * These canaries only *fire* where OpenSSL still writes the padding bytes:
 * 3.0.x does (the CI runner), 3.5 does not, so on a newer library they pass
 * against the old code too. That asymmetry is the bug's whole history — it hid
 * from every EL9 dev box for as long as it existed.
 */
static void
test_padded_exact_fit_does_not_overrun(void)
{
    static const struct {
        const char *in;         /* base64url, as it arrives on the wire */
        const char *want;
        size_t      want_len;   /* == out_max: the exact-fit caller          */
    } cases[] = {
        { "QUJD", "ABC", 3 },   /* pad 0 — no padding to mis-account for     */
        { "QUI=", "AB",  2 },   /* pad 1 — one byte written past the return  */
        { "QQ==", "A",   1 },   /* pad 2 — two bytes written past the return */
        { "QUI",  "AB",  2 },   /* pad 1, supplied by our own padding step   */
        { "QQ",   "A",   1 },   /* pad 2, supplied by our own padding step   */
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t out[8];
        ssize_t len;

        memset(out, 0xAA, sizeof(out));
        len = b64url_decode(cases[i].in, strlen(cases[i].in), out,
                            cases[i].want_len);

        check(len == (ssize_t) cases[i].want_len
              && memcmp(out, cases[i].want, cases[i].want_len) == 0,
              cases[i].in);
        check(out[cases[i].want_len] == 0xAA
              && out[cases[i].want_len + 1] == 0xAA,
              "canary past out_max intact");
    }
}

/*
 * Valid base64 never carries more than two padding characters. Inputs that do
 * must be refused outright rather than decoded on a best-effort basis — the
 * capacity arithmetic (padded_len/4*3 - pad) is only meaningful for pad <= 2,
 * and it underflows for a run of '=' longer than the data it follows.
 */
static void
test_overlong_padding_is_rejected(void)
{
    static const char *const cases[] = {
        "AAAA====",          /* full pad group after one data group        */
        "AAAAAAAA====",      /* ... after two                              */
        "AAAA=",             /* our own padding tops it up to four         */
        "AAAA===",           /* three '=' — still more than base64 allows  */
        "========",          /* nothing but padding: pad > decoded width   */
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t out[8];
        ssize_t len;

        memset(out, 0xAA, sizeof(out));
        len = b64url_decode(cases[i], strlen(cases[i]), out, 2);
        check(len < 0, cases[i]);
        check(out[2] == 0xAA && out[3] == 0xAA, "canary past out_max intact");
    }
}

/* An output buffer smaller than the decode must be refused, not truncated. */
static void
test_short_buffer_is_rejected(void)
{
    uint8_t out[32];
    ssize_t len = b64url_decode("SGVsbG8td29ybGQ", 15, out, 4);

    check(len < 0, "short buffer rejected");
}

int
main(void)
{
    test_roundtrip();
    test_padded_exact_fit_does_not_overrun();
    test_overlong_padding_is_rejected();
    test_short_buffer_is_rejected();

    if (failures != 0) {
        printf("b64url_decode: %d check(s) failed\n", failures);
        return 1;
    }
    printf("b64url_decode passed\n");
    return 0;
}
