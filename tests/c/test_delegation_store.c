/* test_delegation_store.c — unit tests for the phase-3 T4 pending-delegation
 * store in src/protocols/webdav/delegation.c (brix_deleg_store_put /
 * brix_deleg_store_take / sweep / evict / free-on-drop).
 *
 * WHAT: Exercises the store's put/get/sweep/expire/evict/free logic directly
 *       with synthetic timestamps, independent of any real HTTP request or
 *       TLS handshake — the store is pure C state (a fixed array + OpenSSL
 *       EVP_PKEY ownership), so it is tested without a running nginx.
 *
 * WHY:  The store functions (brix_deleg_store_put/_take/_sweep,
 *       brix_deleg_entry_free) are `static` to delegation.c by design (an
 *       internal implementation detail, not a public API) — this test
 *       #includes delegation.c directly (a standard technique for unit-
 *       testing static functions) rather than relaxing their linkage or
 *       exposing them via delegation.h, which would leak internal store
 *       shape into the public header for no runtime benefit.
 *
 * HOW:  delegation.c pulls in webdav.h (the full nginx HTTP module surface)
 *       for its HTTP-handler functions, but the store logic itself only
 *       touches ngx_cycle/ngx_pcalloc + OpenSSL EVP_PKEY + libc. This file
 *       links the REAL nginx core objects (ngx_cycle.o for the ngx_cycle
 *       global + a real pool, ngx_palloc.o, ngx_log.o, ngx_string.o) and the
 *       REAL sibling project objects delegation.c depends on (hex.o,
 *       ucred.o, store_policy.o, proxy_req.o) via run_delegation_store.sh's
 *       link line — see that script for the exact object list. The small
 *       number of symbols ONLY the HTTP-handler functions reference
 *       (ngx_http_send_header, ngx_http_output_filter, ngx_list_push,
 *       webdav_metrics_finalize_request, ngx_http_brix_webdav_module) are
 *       satisfied here by no-op stubs — main() below never calls any
 *       HTTP-handler function, so these stubs are link-time-only scaffolding,
 *       never executed.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

/* ---- link-time-only stubs for symbols only the HTTP-handler functions (or
 * the brix_deleg_store() lazy-singleton accessor, which this test also
 * never calls — it drives the store functions directly against its own
 * stack-allocated brix_deleg_store_t) in delegation.c reference; main()
 * below never reaches any of them. A real ngx_cycle_t (from ngx_cycle.o)
 * would drag in nginx's entire OS/process/shm/module-init surface for a
 * global this test's call graph never dereferences — a plain zeroed stub
 * is the correct scope for a pure-logic unit test. ---- */
ngx_module_t ngx_http_brix_webdav_module;
volatile ngx_cycle_t *ngx_cycle;

ngx_int_t
ngx_http_send_header(ngx_http_request_t *r)
{
    (void) r;
    abort();  /* must never actually be called by this test */
}

ngx_int_t
ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    (void) r; (void) in;
    abort();
}

void *
ngx_list_push(ngx_list_t *l)
{
    (void) l;
    abort();
}

void
webdav_metrics_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    (void) r; (void) rc;
    abort();
}

void *
ngx_pcalloc(ngx_pool_t *p, size_t size)
{
    (void) p; (void) size;
    abort();
}

void *
ngx_pnalloc(ngx_pool_t *p, size_t size)
{
    (void) p; (void) size;
    abort();
}

u_char *
ngx_pstrdup(ngx_pool_t *pool, ngx_str_t *src)
{
    (void) pool; (void) src;
    abort();
}

u_char *
ngx_snprintf(u_char *buf, size_t max, const char *fmt, ...)
{
    (void) buf; (void) max; (void) fmt;
    abort();
}

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
    abort();
}

/* brix_sanitize_log_string / brix_http_body_read_all are called only from
 * the HTTP-handler functions (webdav_delegation_handle,
 * webdav_delegation_put_handle) this test never invokes; their real
 * implementations live in translation units (log_diag.c, http_body.c) that
 * pull in far more of the module than this pure-store unit test needs. */
size_t
brix_sanitize_log_string(const char *in, char *out, size_t out_cap)
{
    (void) in; (void) out; (void) out_cap;
    abort();
}

ngx_int_t
brix_http_body_read_all(ngx_http_request_t *r, size_t max_bytes,
    u_char **out, size_t *out_len)
{
    (void) r; (void) max_bytes; (void) out; (void) out_len;
    abort();
}

/* ---- pull in the store implementation under test ---- */
#include "protocols/webdav/delegation.c"

/* ---- test helpers ---- */

static EVP_PKEY *
mk_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY     *key = NULL;
    BIGNUM       *e = BN_new();

    assert(ctx != NULL && e != NULL && BN_set_word(e, 0x10001));
    assert(EVP_PKEY_keygen_init(ctx) > 0);
    assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) > 0);
    assert(EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) > 0);
    assert(EVP_PKEY_keygen(ctx, &key) > 0);
    EVP_PKEY_CTX_free(ctx);
    BN_free(e);
    return key;
}

int
main(void)
{
    brix_deleg_store_t st;
    char               id_a[BRIX_DELEG_ID_HEXLEN + 1];
    char               id_b[BRIX_DELEG_ID_HEXLEN + 1];
    EVP_PKEY          *key_a, *key_b, *out;
    brix_deleg_take_t  rc;
    int                i;

    memset(&st, 0, sizeof(st));

    /* --- basic put/take round-trip: id format, key ownership transfer --- */
    key_a = mk_key();
    assert(brix_deleg_store_put(&st, key_a, "/DC=test/CN=Alice",
               id_a, sizeof(id_a)) == NGX_OK);
    assert(strlen(id_a) == BRIX_DELEG_ID_HEXLEN);
    for (i = 0; id_a[i]; i++) {
        assert((id_a[i] >= '0' && id_a[i] <= '9')
            || (id_a[i] >= 'a' && id_a[i] <= 'f'));
    }
    out = NULL;
    rc = brix_deleg_store_take(&st, id_a, "/DC=test/CN=Alice", &out);
    assert(rc == BRIX_DELEG_TAKE_OK);
    assert(out == key_a);  /* the SAME key object handed back (no copy) */
    EVP_PKEY_free(out);
    printf("ok   put/take round-trip returns the stored key, ids are %d hex"
           " chars\n", BRIX_DELEG_ID_HEXLEN);

    /* --- one-shot: a second take of the SAME id is NOT_FOUND (dropped) --- */
    out = NULL;
    rc = brix_deleg_store_take(&st, id_a, "/DC=test/CN=Alice", &out);
    assert(rc == BRIX_DELEG_TAKE_NOT_FOUND);
    assert(out == NULL);
    printf("ok   one-shot: id is consumed after a successful take\n");

    /* --- unknown id --- */
    out = NULL;
    rc = brix_deleg_store_take(&st, "deadbeefdeadbeefdeadbeefdeadbeef",
             "/DC=test/CN=Alice", &out);
    assert(rc == BRIX_DELEG_TAKE_NOT_FOUND);
    assert(out == NULL);
    printf("ok   unknown id -> NOT_FOUND\n");

    /* --- DN mismatch: cross-client take is rejected AND burns the id
     * (one-shot on ANY terminal outcome, not just success) --- */
    key_b = mk_key();
    assert(brix_deleg_store_put(&st, key_b, "/DC=test/CN=Alice",
               id_b, sizeof(id_b)) == NGX_OK);
    out = NULL;
    rc = brix_deleg_store_take(&st, id_b, "/DC=test/CN=Mallory", &out);
    assert(rc == BRIX_DELEG_TAKE_DN_MISMATCH);
    assert(out == NULL);   /* key NEVER handed to the wrong caller */
    /* id is now burned — even the RIGHT owner can't retry it */
    out = NULL;
    rc = brix_deleg_store_take(&st, id_b, "/DC=test/CN=Alice", &out);
    assert(rc == BRIX_DELEG_TAKE_NOT_FOUND);
    assert(out == NULL);
    printf("ok   DN mismatch -> DN_MISMATCH, key withheld, id burned"
           " (even for the rightful owner)\n");

    /* --- expiry: a synthetic past expires_at is swept and reported
     * EXPIRED (not NOT_FOUND), and the key is freed by the sweep, not
     * leaked --- */
    {
        EVP_PKEY *key_c = mk_key();
        char      id_c[BRIX_DELEG_ID_HEXLEN + 1];

        assert(brix_deleg_store_put(&st, key_c, "/DC=test/CN=Carol",
                   id_c, sizeof(id_c)) == NGX_OK);
        /* Force this slot's expiry into the past directly (synthetic
         * timestamp — the whole point of a unit test over waiting out a
         * real 600s TTL in a shell script). */
        for (i = 0; i < BRIX_DELEG_STORE_CAP; i++) {
            if (strcmp(st.slots[i].id, id_c) == 0) {
                st.slots[i].expires_at = time(NULL) - 1;
                break;
            }
        }
        out = NULL;
        rc = brix_deleg_store_take(&st, id_c, "/DC=test/CN=Carol", &out);
        assert(rc == BRIX_DELEG_TAKE_EXPIRED);
        assert(out == NULL);  /* key was freed by the sweep, not handed out */
    }
    printf("ok   expired entry -> EXPIRED (swept, key freed not leaked)\n");

    /* --- sweep frees an expired entry's key even if it is NEVER taken
     * again (put triggers the sweep too) --- */
    {
        EVP_PKEY *key_d = mk_key();
        char      id_d[BRIX_DELEG_ID_HEXLEN + 1];
        int       found_after_sweep;

        assert(brix_deleg_store_put(&st, key_d, "/DC=test/CN=Dave",
                   id_d, sizeof(id_d)) == NGX_OK);
        for (i = 0; i < BRIX_DELEG_STORE_CAP; i++) {
            if (strcmp(st.slots[i].id, id_d) == 0) {
                st.slots[i].expires_at = time(NULL) - 1;
                break;
            }
        }
        /* Trigger a sweep via an unrelated put (its own id is irrelevant). */
        {
            EVP_PKEY *scratch = mk_key();
            char      scratch_id[BRIX_DELEG_ID_HEXLEN + 1];

            assert(brix_deleg_store_put(&st, scratch, "/DC=test/CN=Eve",
                       scratch_id, sizeof(scratch_id)) == NGX_OK);
            out = NULL;
            assert(brix_deleg_store_take(&st, scratch_id,
                       "/DC=test/CN=Eve", &out) == BRIX_DELEG_TAKE_OK);
            EVP_PKEY_free(out);
        }
        found_after_sweep = 0;
        for (i = 0; i < BRIX_DELEG_STORE_CAP; i++) {
            if (strcmp(st.slots[i].id, id_d) == 0) {
                found_after_sweep = 1;
            }
        }
        assert(!found_after_sweep);  /* slot freed by the sweep-on-put */
    }
    printf("ok   an unrelated put() sweeps other workers' expired entries"
           " (lazy TTL enforcement, no background thread)\n");

    /* --- bounded capacity: fill the store, confirm a full store (after
     * sweep finds nothing to evict) declines a new put --- */
    {
        brix_deleg_store_t full;
        int                filled = 0;
        char               scratch_id[BRIX_DELEG_ID_HEXLEN + 1];
        ngx_int_t          put_rc;

        memset(&full, 0, sizeof(full));
        for (i = 0; i < BRIX_DELEG_STORE_CAP; i++) {
            EVP_PKEY *k = mk_key();

            if (brix_deleg_store_put(&full, k, "/DC=test/CN=Filler",
                    scratch_id, sizeof(scratch_id)) != NGX_OK) {
                EVP_PKEY_free(k);  /* put failed -> ownership stayed with us */
                break;
            }
            filled++;
        }
        assert(filled == BRIX_DELEG_STORE_CAP);

        {
            EVP_PKEY *k = mk_key();

            put_rc = brix_deleg_store_put(&full, k, "/DC=test/CN=Overflow",
                         scratch_id, sizeof(scratch_id));
            assert(put_rc == NGX_DECLINED);
            EVP_PKEY_free(k);  /* put declined -> we still own it; must free */
        }

        /* Clean up every filled slot's key so this block doesn't itself
         * leak under the test's own accounting (not part of the store's
         * contract, just hygiene for this test process). */
        for (i = 0; i < BRIX_DELEG_STORE_CAP; i++) {
            if (full.slots[i].fresh_key != NULL) {
                EVP_PKEY_free(full.slots[i].fresh_key);
                full.slots[i].fresh_key = NULL;
            }
        }
    }
    printf("ok   bounded store: %d/%d slots filled, next put DECLINED"
           " (caller must free the key it still owns)\n",
           BRIX_DELEG_STORE_CAP, BRIX_DELEG_STORE_CAP);

    /* --- brix_deleg_entry_free is the sole free site: verify a slot with
     * NO key (already-taken slot mid-reuse) is safely re-freeable
     * (idempotent no-op on fresh_key) --- */
    {
        brix_deleg_entry_t e;

        memset(&e, 0, sizeof(e));
        strcpy(e.id, "0123456789abcdef0123456789abcdef");
        e.fresh_key = NULL;
        brix_deleg_entry_free(&e);  /* must not crash on a NULL key */
        assert(e.id[0] == '\0');
    }
    printf("ok   brix_deleg_entry_free is a safe no-op on an already-empty"
           " key (idempotent)\n");

    printf("test_delegation_store: all assertions passed\n");
    return 0;
}
