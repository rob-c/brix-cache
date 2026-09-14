/* Actual issuer/parser round trips with a fixture-only key and fixed clock.
 * No token is printed, persisted, or sent to an authentication endpoint. */
#include <assert.h>
#include <string.h>
#include "auth/token/b64url.h"
#include "auth/token/macaroon_frame.h"
#include "auth/token/macaroon_internal.h"
#include "auth/token/macaroon_issue.h"

#define FIXTURE_ROOT_KEY "native-roundtrip-key"
#define FIXTURE_NOW ((time_t) 1789357971)
#define FIXTURE_EXPIRY (FIXTURE_NOW + 86400)

/* WHAT: Own the isolated clock. WHY: Expiry tests must not depend on wall time.
 * HOW: 1. Start at a fixed epoch. 2. Let the expired case advance this value. */
static time_t *
fixture_clock(void)
{
    static time_t now = FIXTURE_NOW;
    return &now;
}

/* WHAT: Replace the parser's time call. WHY: Exercise actual expiry handling.
 * HOW: 1. Read the fixture clock. 2. Preserve time(2)'s optional output value. */
time_t
__wrap_time(time_t *result)
{
    time_t now = *fixture_clock();
    if (result != NULL) {
        *result = now;
    }
    return now;
}

/* WHAT: Accept parser diagnostics. WHY: Expected errors need a valid log sink.
 * HOW: 1. Assert nginx supplied a log and format; no token data is emitted. */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
    const char *format, ...)
{
    assert(log != NULL && format != NULL);
    (void) level;
    (void) error;
}

/* WHAT: Issue and decode one valid fixture token. WHY: Reuse the real encoder.
 * HOW: 1. Issue scoped credentials. 2. Decode with the production b64 helper. */
static size_t
issue_fixture(ngx_log_t *log, const char *subject, u_char *binary, size_t capacity)
{
    char token[BRIX_MACAROON_ISSUE_OUT_MAX];
    ssize_t length;

    assert(brix_macaroon_issue(log, (const u_char *) FIXTURE_ROOT_KEY,
        sizeof(FIXTURE_ROOT_KEY) - 1, "fixture-origin", subject,
        "DOWNLOAD", "/", FIXTURE_EXPIRY, token, sizeof(token)) == NGX_OK);
    length = b64url_decode(token, strlen(token), binary, capacity);
    assert(length > 46);
    assert(brix_macaroon_packet_len(binary + length - 46) == 46);
    return (size_t) length;
}

/* WHAT: Validate one root token. WHY: Root expiry and signature checks must run.
 * HOW: 1. Supply empty claims and capture storage. 2. Call the actual parser. */
static int
validate_fixture(ngx_log_t *log, const u_char *binary, size_t length,
    brix_token_claims_t *claims)
{
    brix_macaroon_tp_t caveats[1];
    int count = 0;
    macaroon_parse_input_t input = {
        .log = log,
        .key = (const u_char *) FIXTURE_ROOT_KEY,
        .key_len = sizeof(FIXTURE_ROOT_KEY) - 1,
        .claims = claims,
        .tp_arr = caveats,
        .n_tp = &count,
        .max_tp = 1
    };

    memset(claims, 0, sizeof(*claims));
    return macaroon_parse_core(&input, binary, length);
}

/* WHAT: Check trusted claims. WHY: Accepting the signature must retain scope.
 * HOW: 1. Check attribution and expiry. 2. Require the requested read-only scope. */
static void
assert_fixture_claims(const brix_token_claims_t *claims, const char *subject)
{
    assert(strcmp(claims->sub, subject) == 0);
    assert(strcmp(claims->iss, "fixture-origin") == 0);
    assert(claims->exp == FIXTURE_EXPIRY && claims->groups[0] == '\0');
    assert(claims->scope_count == 1);
    assert(strcmp(claims->scopes[0].path, "/") == 0);
    assert(claims->scopes[0].read && !claims->scopes[0].write);
    assert(!claims->scopes[0].create && !claims->scopes[0].modify);
}

/* WHAT: Check binary signatures and rejection paths. WHY: Never weaken auth.
 * HOW: 1. Issue a deterministic valid token. 2. Apply one case. 3. Check verdict. */
int
main(int argc, char **argv)
{
    ngx_log_t log = {.log_level = NGX_LOG_INFO};
    brix_token_claims_t claims;
    u_char binary[BRIX_MACAROON_ISSUE_OUT_MAX];
    const char *subject;
    size_t length;

    assert(argc == 2);
    /* These fixed identifiers produce final HMAC bytes 0xaa and 0x0a,
     * respectively, with the fixture key/caveats/clock above. */
    subject = strcmp(argv[1], "normal") == 0 ? "roundtrip-0" : "roundtrip-72";
    length = issue_fixture(&log, subject, binary, sizeof(binary));
    assert(binary[length - 1] == (strcmp(argv[1], "normal") == 0 ? 0xaa : 0x0a));
    assert(validate_fixture(&log, binary, length, &claims) == 0);
    assert_fixture_claims(&claims, subject);

    if (strcmp(argv[1], "tampered") == 0) {
        binary[length - 1] ^= 1;
        assert(validate_fixture(&log, binary, length, &claims) == -1);
    } else if (strcmp(argv[1], "truncated") == 0) {
        assert(validate_fixture(&log, binary, length - 1, &claims) == -1);
    } else if (strcmp(argv[1], "expired") == 0) {
        *fixture_clock() = FIXTURE_EXPIRY + 1;
        assert(validate_fixture(&log, binary, length, &claims) == -1);
    }
    return 0;
}
