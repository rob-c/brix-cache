/* client/lib/cred.c
 *
 * WHAT: Credential store — per-kind handler registry, view cache, expiry gate,
 *       and refresh machinery for all five credential kinds (X.509, bearer,
 *       Kerberos, SSS, S3 keys).
 * WHY:  Discovery and refresh logic was scattered across the per-protocol sec
 *       modules (sec_gsi.c / sec_token.c / …) and duplicated for the HTTP/S3
 *       transports. One store removes the drift and makes auto-refresh uniform.
 * HOW:  Per-kind handler accessors are declared __attribute__((weak)) here so
 *       the library and unit-test binaries compile before any handler (B3-B6)
 *       exists. brix_cred_store_new() calls each non-NULL weak accessor and
 *       stores the returned handler pointer in a fixed-size per-kind slot array.
 *       A per-kind cache slot (loaded flag + owned string copies + not_after)
 *       is checked on every brix_cred_acquire; if auto_refresh is set and the
 *       credential is within min_remaining_s of its expiry, handler->refresh
 *       (if non-NULL) then handler->acquire are called and the cache is updated.
 *       ngx-free; no goto; functional/modular design (one job per function).
 */

/* _GNU_SOURCE: pull in strdup (POSIX.1-2008) — the Makefile HARDEN block
 * already sets -D_GNU_SOURCE; this guard handles standalone unit-test builds
 * that compile this TU directly without the full HARDEN flags. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cred.h"
#include "brix.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Forward declaration: cfg_copy_free is used inside the DUP_FIELD macro in
 * cfg_copy_alloc, which appears earlier in the file. */
static void cfg_copy_free(brix_cred_config *c);

/* weak accessor declarations */
/*
 * Per-kind handler accessors, declared weak so libbrix.{a,so} (and any test
 * binary that provides only a subset) links cleanly without all B3-B6 objects.
 * A unit test that needs a specific kind overrides one accessor with a STRONG
 * definition (the linker prefers a strong symbol over a weak one).
 *
 * Guarded checks against NULL before any call — a NULL weak symbol means the
 * compilation unit that would have provided it was not linked.
 */
extern const brix_cred_handler *brix_cred_x509(void)   __attribute__((weak));
extern const brix_cred_handler *brix_cred_bearer(void)  __attribute__((weak));
extern const brix_cred_handler *brix_cred_krb5(void)    __attribute__((weak));
extern const brix_cred_handler *brix_cred_sss(void)     __attribute__((weak));
extern const brix_cred_handler *brix_cred_s3keys(void)  __attribute__((weak));

/* config deep-copy helpers */
/*
 * cfg_copy_alloc — deep-copy the caller's brix_cred_config onto the heap.
 *
 * WHAT: allocates a new brix_cred_config whose string fields are independent
 *       heap copies of the originals so the store outlives the caller's cfg.
 * WHY:  safe design: store OWNS all strings → no lifetime coupling to caller.
 * HOW:  struct copy + individual strdup for every const char * field.
 *       Returns NULL on any allocation failure; partial copies are freed.
 */
static brix_cred_config *
cfg_copy_alloc(const brix_cred_config *src)
{
    brix_cred_config *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }

    c->auto_refresh = src->auto_refresh;

/* Helper: strdup one field; on failure free already-allocated fields and c. */
#define DUP_FIELD(field)                                                    \
    do {                                                                    \
        if (src->field != NULL) {                                           \
            c->field = strdup(src->field);                                  \
            if (c->field == NULL) {                                         \
                cfg_copy_free(c);                                           \
                return NULL;                                                \
            }                                                               \
        }                                                                   \
    } while (0)

    DUP_FIELD(proxy_path);
    DUP_FIELD(bearer_literal);
    DUP_FIELD(bearer_path);
    DUP_FIELD(keytab_path);
    DUP_FIELD(ccache);
    DUP_FIELD(s3_access);
    DUP_FIELD(s3_secret);
    DUP_FIELD(oidc_account);

#undef DUP_FIELD
    return c;
}

/*
 * cfg_copy_free — release all heap memory in a deep-copied config.
 *
 * WHAT: frees every strdup'd string field, then the config itself.
 * WHY:  companion to cfg_copy_alloc; ensures no leaks on store teardown.
 * HOW:  explicit free for each field (safe on NULL; free(NULL) is a no-op).
 */
static void
cfg_copy_free(brix_cred_config *c)
{
    if (c == NULL) {
        return;
    }
    free((char *)c->proxy_path);
    free((char *)c->bearer_literal);
    free((char *)c->bearer_path);
    free((char *)c->keytab_path);
    free((char *)c->ccache);
    free((char *)c->s3_access);
    free((char *)c->s3_secret);
    free((char *)c->oidc_account);
    free(c);
}

/* per-kind cache slot */
/*
 * cred_slot — one per brix_cred_kind; holds the cached view + owned strings.
 *
 * The brix_cred_view.s3_access / .s3_secret / .path / .token fields point at
 * the owned[] array below (valid until the SAME kind's next acquire), exactly
 * as documented in cred.h: "valid until the next acquire of the SAME kind on
 * the SAME store."
 */
typedef struct {
    int             loaded;
    brix_cred_view  view;
    int64_t         not_after;   /* unix epoch expiry; 0 = no expiry known  */

    /* Heap-owned copies of view strings — view.* pointers alias into these. */
    char           *owned_path;
    char           *owned_token;
    char           *owned_s3_access;
    char           *owned_s3_secret;
} cred_slot;

/* store struct */
struct brix_cred_store {
    brix_cred_config          *cfg;                         /* deep copy         */
    const brix_cred_handler   *handlers[XRDC_CRED_KIND_COUNT]; /* may be NULL   */
    cred_slot                  slots[XRDC_CRED_KIND_COUNT];
};

/* slot helpers */
/*
 * slot_clear_owned — free the owned string copies in a cache slot.
 *
 * WHAT: releases path/token/s3_access/s3_secret heap copies; zeroes the slot.
 * WHY:  called before writing a fresh acquire result so old strings don't leak.
 * HOW:  individual free + NULL-out; preserves .loaded and .not_after (cleared
 *       by the caller after this, so the order doesn't matter).
 */
static void
slot_clear_owned(cred_slot *sl)
{
    free(sl->owned_path);
    free(sl->owned_token);
    free(sl->owned_s3_access);
    free(sl->owned_s3_secret);
    sl->owned_path      = NULL;
    sl->owned_token     = NULL;
    sl->owned_s3_access = NULL;
    sl->owned_s3_secret = NULL;
}

/*
 * slot_store_view — deep-copy a transient view into the cache slot.
 *
 * WHAT: copies each non-NULL string from *v into slot-owned buffers, then
 *       points sl->view.* at those buffers and records not_after.
 * WHY:  handler->acquire fills a view whose string pointers may be stack or
 *       handler-internal; the store must outlive that call frame.
 * HOW:  strdup each field; on any allocation failure free the partial set and
 *       return -1.  The caller marks sl->loaded on success.
 */
static int
slot_store_view(cred_slot *sl, const brix_cred_view *v, int64_t not_after)
{
    slot_clear_owned(sl);
    /* Synchronise view pointers so any early-return (OOM) path leaves the slot
     * in a valid (not-loaded) state rather than with dangling pointers. */
    sl->view.path      = NULL;
    sl->view.token     = NULL;
    sl->view.s3_access = NULL;
    sl->view.s3_secret = NULL;
    sl->loaded         = 0;

    if (v->path != NULL) {
        sl->owned_path = strdup(v->path);
        if (sl->owned_path == NULL) {
            slot_clear_owned(sl);
            return -1;
        }
    }
    if (v->token != NULL) {
        sl->owned_token = strdup(v->token);
        if (sl->owned_token == NULL) {
            slot_clear_owned(sl);
            return -1;
        }
    }
    if (v->s3_access != NULL) {
        sl->owned_s3_access = strdup(v->s3_access);
        if (sl->owned_s3_access == NULL) {
            slot_clear_owned(sl);
            return -1;
        }
    }
    if (v->s3_secret != NULL) {
        sl->owned_s3_secret = strdup(v->s3_secret);
        if (sl->owned_s3_secret == NULL) {
            slot_clear_owned(sl);
            return -1;
        }
    }

    sl->view.kind      = v->kind;
    sl->view.path      = sl->owned_path;
    sl->view.token     = sl->owned_token;
    sl->view.s3_access = sl->owned_s3_access;
    sl->view.s3_secret = sl->owned_s3_secret;
    sl->view.not_after = not_after;
    sl->not_after      = not_after;
    sl->loaded         = 1;
    return 0;
}

/* kind name table (for error messages) */
static const char *
kind_name(brix_cred_kind k)
{
    switch (k) {
    case XRDC_CRED_X509_PROXY: return "x509_proxy";
    case XRDC_CRED_BEARER:     return "bearer";
    case XRDC_CRED_KRB5:       return "krb5";
    case XRDC_CRED_SSS:        return "sss";
    case XRDC_CRED_S3KEYS:     return "s3keys";
    default:                   return "unknown";
    }
}

/* public API */
/*
 * brix_cred_store_new — allocate and initialise a credential store.
 *
 * WHAT: deep-copies cfg, queries each weak accessor for its handler, and
 *       stores non-NULL results in the per-kind slot array.
 * WHY:  the caller's cfg may be stack-allocated and go out of scope; deep copy
 *       is the safe option (documented contract).
 * HOW:  calloc the store; cfg_copy_alloc; call each weak accessor (guarding
 *       NULL) and store the returned handler pointer. Returns NULL on OOM.
 */
brix_cred_store *
brix_cred_store_new(const brix_cred_config *cfg)
{
    brix_cred_store *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }

    s->cfg = cfg_copy_alloc(cfg);
    if (s->cfg == NULL) {
        free(s);
        return NULL;
    }

    /* Populate handler slots from the (possibly weak-NULL) accessors. */
    if (brix_cred_x509 != NULL) {
        s->handlers[XRDC_CRED_X509_PROXY] = brix_cred_x509();
    }
    if (brix_cred_bearer != NULL) {
        s->handlers[XRDC_CRED_BEARER] = brix_cred_bearer();
    }
    if (brix_cred_krb5 != NULL) {
        s->handlers[XRDC_CRED_KRB5] = brix_cred_krb5();
    }
    if (brix_cred_sss != NULL) {
        s->handlers[XRDC_CRED_SSS] = brix_cred_sss();
    }
    if (brix_cred_s3keys != NULL) {
        s->handlers[XRDC_CRED_S3KEYS] = brix_cred_s3keys();
    }

    return s;
}

/*
 * brix_cred_store_free — release all store resources.
 *
 * WHAT: frees the per-kind owned strings, the deep-copied config, and the
 *       store itself.
 * WHY:  public teardown; matches brix_cred_store_new.
 * HOW:  iterate slots calling slot_clear_owned; then cfg_copy_free; then free.
 */
void
brix_cred_store_free(brix_cred_store *s)
{
    int i;

    if (s == NULL) {
        return;
    }
    for (i = 0; i < XRDC_CRED_KIND_COUNT; i++) {
        slot_clear_owned(&s->slots[i]);
    }
    cfg_copy_free(s->cfg);
    free(s);
}

/*
 * brix_cred_available — probe whether a credential of `kind` appears usable.
 *
 * WHAT: returns 1 if a handler is registered for `kind` AND handler->available
 *       returns non-zero; 0 otherwise. Does NOT load or cache anything.
 * WHY:  auth pre-flight diagnostic: predict server auth without a network call.
 * HOW:  bounds-check kind; guard NULL handler; delegate to available(cfg).
 */
int
brix_cred_available(brix_cred_store *s, brix_cred_kind kind)
{
    const brix_cred_handler *h;

    if (s == NULL || (unsigned)kind >= XRDC_CRED_KIND_COUNT) {
        return 0;
    }
    h = s->handlers[kind];
    if (h == NULL || h->available == NULL) {
        return 0;
    }
    return h->available(s->cfg) != 0 ? 1 : 0;
}

/*
 * should_refresh — decide whether the cached credential needs re-acquisition.
 *
 * WHAT: returns 1 when auto_refresh is enabled, an expiry is known, and the
 *       credential expires within min_remaining_s seconds.
 * WHY:  centralises the expiry-gate logic so brix_cred_acquire is readable.
 * HOW:  pure predicate; no side effects.  min_remaining_s<=0 disables the check.
 *       Called only from the `else if (sl->loaded)` branch in brix_cred_acquire,
 *       so no redundant loaded-check here.
 */
static int
should_refresh(const brix_cred_store *s, const cred_slot *sl, int min_remaining_s)
{
    int64_t now;

    if (!s->cfg->auto_refresh) {
        return 0;
    }
    if (sl->not_after == 0) {
        return 0;
    }
    if (min_remaining_s <= 0) {
        return 0;
    }
    now = (int64_t)time(NULL);
    return (now + (int64_t)min_remaining_s >= sl->not_after) ? 1 : 0;
}

/*
 * do_acquire — call handler->acquire and cache the result in the slot.
 *
 * WHAT: invokes handler->acquire(cfg, &raw, &not_after, st); on success
 *       deep-copies the view into the slot via slot_store_view.
 * WHY:  factored out so both the cold-miss and the expiry-triggered paths
 *       share one acquire site.
 * HOW:  calls acquire; on -1 propagates the error.  On OOM during
 *       slot_store_view sets XRDC_EAUTH + message.  Returns 0 on success.
 */
static int
do_acquire(brix_cred_store *s, brix_cred_kind kind,
           const brix_cred_handler *h, cred_slot *sl, brix_status *st)
{
    brix_cred_view raw = {0};
    int64_t not_after  = 0;
    int rc;

    rc = h->acquire(s->cfg, &raw, &not_after, st);
    if (rc != 0) {
        return -1;
    }
    if (slot_store_view(sl, &raw, not_after) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "cred store: OOM caching %s credential",
                        kind_name(kind));
        return -1;
    }
    return 0;
}

/*
 * brix_cred_acquire — discover, cache, and return a credential view.
 *
 * WHAT: resolves the handler for `kind`; returns the cached view unless the
 *       slot is empty (cold miss) or auto_refresh is set and the credential
 *       is within min_remaining_s of its expiry. On cache hit returns *view
 *       pointing at the store-owned strings. Returns 0 / -1 (st set).
 * WHY:  single authoritative acquire path for all code that needs a cred.
 * HOW:  1) guard NULL handler → XRDC_EAUTH.
 *       2) cold miss → do_acquire.
 *       3) warm hit: check should_refresh; if so, handler->refresh (if non-
 *          NULL) then do_acquire.
 *       4) fill *view from the cached slot.
 */
int
brix_cred_acquire(brix_cred_store *s, brix_cred_kind kind,
                  int min_remaining_s, brix_cred_view *view, brix_status *st)
{
    const brix_cred_handler *h;
    cred_slot *sl;

    if (s == NULL || (unsigned)kind >= XRDC_CRED_KIND_COUNT) {
        brix_status_set(st, XRDC_EUSAGE, 0, "cred_acquire: invalid store or kind");
        return -1;
    }

    h = s->handlers[kind];
    if (h == NULL) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "no %s credential handler available",
                        kind_name(kind));
        return -1;
    }

    sl = &s->slots[kind];

    /* Cold miss — no cached result yet. */
    if (!sl->loaded) {
        if (do_acquire(s, kind, h, sl, st) != 0) {
            return -1;
        }
    } else if (should_refresh(s, sl, min_remaining_s)) {
        /* Near-expiry refresh: call refresh (if available), then re-acquire. */
        if (h->refresh != NULL) {
            (void)h->refresh(s->cfg, st);   /* best-effort; non-fatal on -1 */
        }
        if (do_acquire(s, kind, h, sl, st) != 0) {
            return -1;
        }
    }

    *view = sl->view;
    return 0;
}
