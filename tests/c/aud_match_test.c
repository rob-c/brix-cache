/* Unit test for the backend audience gate (P90-70.9, phase-70 §5.2):
 * brix_token_backend_aud_ok() in src/auth/token/aud_match.c.
 *
 * Links the REAL aud_match.o + b64url.o + json.o (jansson). Tokens are
 * crafted in-test via b64url_encode — no signature work is involved, the gate
 * is purely syntactic by contract.
 *
 * Ritual: success (no-gate back-compat; string aud; array aud; WLCG any
 * wildcard) + error (non-JWS bearer; undecodable payload; no aud claim) +
 * security-negative (aud names a DIFFERENT backend; empty bearer under a
 * configured gate — both fail closed). */

#include <ngx_config.h>
#include <ngx_core.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "auth/token/aud_match.h"
#include "auth/token/b64url.h"

/* ---- nginx surface stubs -------------------------------------------------- */

static ngx_log_t test_log;   /* log_level 0: ngx_log_error() bodies skipped */

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

/* ---- token forging -------------------------------------------------------- */

/* Build "b64url(header).b64url(payload).c2ln" into buf; returns its ngx_str_t
 * view. The signature segment is inert filler — the gate never reads it. */
static ngx_str_t
forge_jwt(const char *payload_json, char *buf, size_t bufsz)
{
    static const char *header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
    char       h64[128], p64[8192];
    int        n;
    ngx_str_t  tok;

    b64url_encode(header, strlen(header), h64, sizeof(h64));
    b64url_encode(payload_json, strlen(payload_json), p64, sizeof(p64));
    n = snprintf(buf, bufsz, "%s.%s.c2ln", h64, p64);
    assert(n > 0 && (size_t) n < bufsz);
    tok.data = (u_char *) buf;
    tok.len  = (size_t) n;
    return tok;
}

static ngx_array_t
gate_list(ngx_str_t *ents, ngx_uint_t n)
{
    ngx_array_t a;

    memset(&a, 0, sizeof(a));
    a.elts   = ents;
    a.nelts  = n;
    a.size   = sizeof(ngx_str_t);
    a.nalloc = n;
    return a;
}

int
main(void)
{
    char         buf[8192];
    ngx_str_t    tok, garbage;
    ngx_array_t  gate;
    ngx_str_t    ents[2] = {
        ngx_string("https://dcache.example.org"),
        ngx_string("https://eos.example.org"),
    };

    gate = gate_list(ents, 2);

    /* 1. success: no gate configured — anything (even a non-JWS) passes. */
    garbage.data = (u_char *) "not-a-jwt";
    garbage.len  = 9;
    assert(brix_token_backend_aud_ok(&garbage, NULL, &test_log) == 1);
    {
        ngx_array_t empty = gate_list(ents, 0);
        assert(brix_token_backend_aud_ok(&garbage, &empty, &test_log) == 1);
    }

    /* 2. success: string-form aud naming a listed backend. */
    tok = forge_jwt("{\"sub\":\"alice\",\"aud\":\"https://eos.example.org\"}",
                    buf, sizeof(buf));
    assert(brix_token_backend_aud_ok(&tok, &gate, &test_log) == 1);

    /* 3. success: RFC 7519 array-form aud, match in second position. */
    tok = forge_jwt("{\"aud\":[\"https://other.example\","
                    "\"https://dcache.example.org\"],\"sub\":\"alice\"}",
                    buf, sizeof(buf));
    assert(brix_token_backend_aud_ok(&tok, &gate, &test_log) == 1);

    /* 4. success: WLCG any-endpoint wildcard beats a non-matching list. */
    tok = forge_jwt("{\"aud\":\"https://wlcg.cern.ch/jwt/v1/any\"}",
                    buf, sizeof(buf));
    assert(brix_token_backend_aud_ok(&tok, &gate, &test_log) == 1);

    /* 5. error: configured gate + bearer that is not a compact JWS. */
    assert(brix_token_backend_aud_ok(&garbage, &gate, &test_log) == 0);

    /* 6. error: undecodable payload segment (not base64url). */
    tok.data = (u_char *) "eyJhbGciOiJub25lIn0.!!!not-b64url!!!.c2ln";
    tok.len  = strlen((const char *) tok.data);
    assert(brix_token_backend_aud_ok(&tok, &gate, &test_log) == 0);

    /* 7. error: well-formed token with NO aud claim — fail closed. */
    tok = forge_jwt("{\"sub\":\"alice\",\"scope\":\"storage.read:/\"}",
                    buf, sizeof(buf));
    assert(brix_token_backend_aud_ok(&tok, &gate, &test_log) == 0);

    /* 8. security-neg: aud audienced for a DIFFERENT backend (string and
     *    array forms) must not be forwardable. */
    tok = forge_jwt("{\"aud\":\"https://evil.example.org\"}", buf, sizeof(buf));
    assert(brix_token_backend_aud_ok(&tok, &gate, &test_log) == 0);
    tok = forge_jwt("{\"aud\":[\"https://evil.example.org\","
                    "\"https://also-wrong.example\"]}", buf, sizeof(buf));
    assert(brix_token_backend_aud_ok(&tok, &gate, &test_log) == 0);

    /* 9. security-neg: empty/NULL bearer under a configured gate. */
    assert(brix_token_backend_aud_ok(NULL, &gate, &test_log) == 0);
    tok.data = (u_char *) "";
    tok.len  = 0;
    assert(brix_token_backend_aud_ok(&tok, &gate, &test_log) == 0);

    /* 10. security-neg: a listed value appearing only as a SUBSTRING of the
     *     token's aud must not match (exact membership, not strstr). */
    tok = forge_jwt("{\"aud\":\"https://eos.example.org.evil.com\"}",
                    buf, sizeof(buf));
    assert(brix_token_backend_aud_ok(&tok, &gate, &test_log) == 0);

    printf("aud_match: all cases passed\n");
    return 0;
}
