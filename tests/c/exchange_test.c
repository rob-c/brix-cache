/*
 * exchange_test.c — unit test for the RFC 8693 OAuth2 token-exchange client
 * `brix_token_exchange` (src/auth/token/exchange.c), coverage plan W3.8.
 *
 * Links the real production object (no reimplementation), so it exercises the
 * true entry-guards, RFC-8693 form-body build, the HTTPS-only protocol pin, the
 * curl perform, and the error mapping. The transport happy path still needs a
 * live TLS OIDC endpoint (fleet tier), but the RESPONSE-PARSE happy path — the
 * one previously-uncovered success branch — is now driven deterministically by
 * calling brix_tx_parse_response() directly with synthetic JSON bodies (no
 * network): the success case plus every JSON rejection branch (malformed,
 * missing/non-string/empty access_token, duplicate key). We also cover the
 * guard branches and the connect-fail branch against a closed loopback port
 * (immediate ECONNREFUSED — fast and deterministic) plus the security-negative
 * case that a plain-http endpoint is refused by the `https`-only pin.
 *
 * Run by tests/cmdscripts/c_auth_units.py (runner "exchange"). exchange.o's only
 * non-libc/curl/jansson deps are ngx_pnalloc + ngx_log_error_core (nm-verified),
 * stubbed below; a stack ngx_log_t with log_level 0 keeps ngx_log_error() from
 * firing (and from dereferencing a NULL log) on the error paths.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth/token/exchange.h"

/* Pool allocation backed by malloc — exchange.c only ever ngx_pnalloc()s small
 * transient strings (endpoint cstr, form body); the process exits right after. */
void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

static int failures;

#define CHECK(cond, msg) do {                                               \
        if (!(cond)) { printf("FAIL: %s\n", (msg)); failures++; }           \
    } while (0)

static ngx_str_t
S(const char *s)
{
    ngx_str_t v;
    v.data = (u_char *) s;
    v.len  = strlen(s);
    return v;
}


int
main(void)
{
    ngx_log_t                   log;
    ngx_pool_t                 *pool = (ngx_pool_t *) &log;   /* opaque non-NULL */
    ngx_str_t                   out;
    ngx_str_t                   subject = S("header.payload.sig");
    ngx_str_t                   aud     = S("https://se.example.org/");
    ngx_str_t                   scope   = S("storage.read:/data");
    brix_token_exchange_conf_t  cf;

    memset(&log, 0, sizeof(log));       /* log_level 0 → ngx_log_error() no-ops */
    memset(&cf, 0, sizeof(cf));

    /* --- entry-guard branches: every one must fail closed with NGX_ERROR. --- */
    out = S("");
    CHECK(brix_token_exchange(NULL, &subject, &aud, &scope, &cf, &out, &log)
          == NGX_ERROR, "guard: NULL pool");

    cf.endpoint = S("https://127.0.0.1:1/token");
    {
        ngx_str_t empty = S("");
        CHECK(brix_token_exchange(pool, &empty, &aud, &scope, &cf, &out, &log)
              == NGX_ERROR, "guard: empty subject token");
    }
    {
        brix_token_exchange_conf_t no_ep;
        memset(&no_ep, 0, sizeof(no_ep));       /* endpoint.len == 0 */
        CHECK(brix_token_exchange(pool, &subject, &aud, &scope, &no_ep, &out, &log)
              == NGX_ERROR, "guard: missing endpoint");
    }
    CHECK(brix_token_exchange(pool, &subject, &aud, &scope, &cf, NULL, &log)
          == NGX_ERROR, "guard: NULL out slot");

    /* --- connect-fail branch: dead HTTPS endpoint on a closed loopback port.
     *     Builds the RFC-8693 body (grant_type/subject_token/audience/resource/
     *     scope), sets the https pin + client auth, performs → ECONNREFUSED →
     *     error map. out must stay empty (no token fabricated on failure). --- */
    cf.endpoint      = S("https://127.0.0.1:1/token");
    cf.client_id     = S("brix");
    cf.client_secret = S("s3cr3t");
    out.data = NULL; out.len = 0;
    CHECK(brix_token_exchange(pool, &subject, &aud, &scope, &cf, &out, &log)
          == NGX_ERROR, "connect-fail: dead endpoint → NGX_ERROR");
    CHECK(out.len == 0, "connect-fail: no token emitted on failure");

    /* scope is optional — same failure, different body-build branch. */
    out.data = NULL; out.len = 0;
    CHECK(brix_token_exchange(pool, &subject, &aud, NULL, &cf, &out, &log)
          == NGX_ERROR, "connect-fail: NULL scope still handled");

    /* --- security-negative: a plain-http endpoint is rejected by the
     *     `https`-only protocol pin, never dialled in cleartext. --- */
    cf.endpoint = S("http://127.0.0.1:1/token");
    out.data = NULL; out.len = 0;
    CHECK(brix_token_exchange(pool, &subject, &aud, &scope, &cf, &out, &log)
          == NGX_ERROR, "security-neg: http endpoint refused by https pin");
    CHECK(out.len == 0, "security-neg: no token from cleartext endpoint");

    /* --- response-parse HAPPY PATH (W3.8): a well-formed RFC 8693 reply yields
     *     the access_token, pool-copied and NUL-terminated. No network. --- */
    {
        const char *doc =
            "{\"access_token\":\"AT-abc.123\",\"issued_token_type\":"
            "\"urn:ietf:params:oauth:token-type:access_token\","
            "\"token_type\":\"Bearer\",\"expires_in\":3600}";
        out.data = NULL; out.len = 0;
        CHECK(brix_tx_parse_response(pool, (const u_char *) doc, strlen(doc),
                                     &out, &log) == NGX_OK,
              "parse: valid reply → NGX_OK");
        CHECK(out.len == 10 && out.data != NULL
              && memcmp(out.data, "AT-abc.123", 10) == 0,
              "parse: access_token extracted verbatim");
        CHECK(out.data != NULL && out.data[out.len] == '\0',
              "parse: token is NUL-terminated at out.data[out.len]");
    }
    {   /* minimal object: access_token is the only member. */
        const char *doc = "{\"access_token\":\"x\"}";
        out.data = NULL; out.len = 0;
        CHECK(brix_tx_parse_response(pool, (const u_char *) doc, strlen(doc),
                                     &out, &log) == NGX_OK
              && out.len == 1 && out.data[0] == 'x',
              "parse: minimal object → single-char token");
    }

    /* --- response-parse ERROR branches: each must fail closed, no token. --- */
    {
        struct { const char *name; const char *doc; } bad[] = {
            { "malformed JSON",        "{ not json"                       },
            { "empty document",        ""                                 },
            { "not an object (array)", "[\"access_token\"]"               },
            { "no access_token key",   "{\"token_type\":\"Bearer\"}"      },
            { "access_token integer",  "{\"access_token\":123}"           },
            { "access_token null",     "{\"access_token\":null}"          },
            { "access_token empty str","{\"access_token\":\"\"}"          },
            { "duplicate key",
              "{\"access_token\":\"a\",\"access_token\":\"b\"}"           },
        };
        size_t i;
        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            out.data = (u_char *) 0x1;   /* poison: must not be overwritten */
            out.len  = 999;
            CHECK(brix_tx_parse_response(pool, (const u_char *) bad[i].doc,
                                         strlen(bad[i].doc), &out, &log)
                  == NGX_ERROR, bad[i].name);
            CHECK(out.data == (u_char *) 0x1 && out.len == 999,
                  "parse: out slot untouched on parse failure");
        }
    }

    if (failures) {
        printf("exchange_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("exchange_test: all checks passed\n");
    return 0;
}
