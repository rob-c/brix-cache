/* Real private Kerberos caches; no KDC, network, or user credentials involved. */
#include "auth/cred/cred.h"
#include <krb5.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fault(const char *name)
{
    const char *selected = getenv("BRIX_TEST_KRB5_FAULT");
    return selected && !strcmp(selected, name);
}

krb5_error_code __real_krb5_init_context(krb5_context *);
/* WHAT: Refuse library context creation. WHY: Discovery must fail closed.
 * HOW: Arm the fault only after the private cache has been seeded. */
krb5_error_code __wrap_krb5_init_context(krb5_context *ctx)
{
    return fault("context") ? ENOMEM : __real_krb5_init_context(ctx);
}

krb5_error_code __real_krb5_cc_start_seq_get(krb5_context, krb5_ccache, krb5_cc_cursor *);
/* WHAT: Refuse ticket enumeration. WHY: Missing expiry is distinct from no identity.
 * HOW: Leave principal discovery real and return an explicit cursor error. */
krb5_error_code __wrap_krb5_cc_start_seq_get(krb5_context ctx, krb5_ccache cc, krb5_cc_cursor *cursor)
{
    return fault("cursor") ? KRB5_CC_IO : __real_krb5_cc_start_seq_get(ctx, cc, cursor);
}

const char *__real_krb5_cc_get_type(krb5_context, krb5_ccache);
const char *__real_krb5_cc_get_name(krb5_context, krb5_ccache);
/* WHAT: Exercise optional cache display metadata. WHY: It must remain bounded.
 * HOW: Suppress only the named metadata field after normal cache resolution. */
const char *__wrap_krb5_cc_get_type(krb5_context ctx, krb5_ccache cc)
{
    return fault("no-type") ? NULL : __real_krb5_cc_get_type(ctx, cc);
}
const char *__wrap_krb5_cc_get_name(krb5_context ctx, krb5_ccache cc)
{
    return fault("no-name") ? NULL : __real_krb5_cc_get_name(ctx, cc);
}

/* WHAT: Add synthetic, locally encoded ticket records.
 * WHY: Endtime discovery must skip service tickets and identify the TGT.
 * HOW: Use the real Kerberos cache writer with explicitly fictitious bytes. */
static void ticket(krb5_context ctx, krb5_ccache cc, krb5_principal me, const char *server)
{
    krb5_creds credentials = {0};
    credentials.client = me;
    assert(krb5_parse_name(ctx, server, &credentials.server) == 0);
    credentials.times.endtime = 123456789;
    credentials.ticket.data = "fixture-ticket"; credentials.ticket.length = 14;
    assert(krb5_cc_store_cred(ctx, cc, &credentials) == 0);
    krb5_free_principal(ctx, credentials.server);
}

/* WHAT: Create a credential cache owned by this test.
 * WHY: Tests must never inspect the device user's default Kerberos cache.
 * HOW: Initialize FILE state and optionally add service and TGT records. */
static void seed(const char *name, const char *contents)
{
    krb5_context ctx; krb5_ccache cc; krb5_principal me;
    assert(krb5_init_context(&ctx) == 0);
    assert(krb5_cc_resolve(ctx, name, &cc) == 0);
    assert(krb5_parse_name(ctx, "fixture@EXAMPLE.TEST", &me) == 0);
    assert(krb5_cc_initialize(ctx, cc, me) == 0);
    if (strcmp(contents, "empty")) { ticket(ctx, cc, me, "host/service@EXAMPLE.TEST"); }
    if (!strcmp(contents, "tgt")) { ticket(ctx, cc, me, "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST"); }
    krb5_free_principal(ctx, me); assert(krb5_cc_close(ctx, cc) == 0); krb5_free_context(ctx);
}

/* WHAT: Check acquisition after explicit/env/default selection.
 * WHY: Cache precedence must not silently select unrelated credentials.
 * HOW: Compare exact path and expiry, and require errors to preserve outputs. */
int main(int argc, char **argv)
{
    assert(argc == 6); unsetenv("BRIX_TEST_KRB5_FAULT");
    seed(argv[1], argv[3]);
    brix_cred_config conf = {0}; const brix_cred_config *selected = &conf;
    if (!strcmp(argv[2], "explicit")) {
        conf.ccache = argv[1]; assert(setenv("KRB5CCNAME", "UNKNOWN:unused", 1) == 0);
    } else if (!strcmp(argv[2], "environment")) {
        assert(setenv("KRB5CCNAME", argv[1], 1) == 0); selected = NULL;
    } else { assert(!strcmp(argv[2], "default")); unsetenv("KRB5CCNAME"); }
    if (!strcmp(argv[4], "bad-type")) { conf.ccache = "UNKNOWN:fixture"; selected = &conf; }
    if (!strcmp(argv[4], "missing")) { conf.ccache = "MEMORY:uninitialized-fixture"; selected = &conf; }
    assert(setenv("BRIX_TEST_KRB5_FAULT", argv[4], 1) == 0);
    const brix_cred_handler *handler = brix_cred_krb5(); assert(handler && !handler->refresh);
    int expected = atoi(argv[5]); assert(handler->available(selected) == (expected == 0));
    brix_cred_view view = {0}; brix_status status = {0}; int64_t expiry = -17;
    assert(handler->acquire(selected, &view, &expiry, &status) == expected);
    if (expected) { assert(!view.path && expiry == -17); }
    else {
        assert(view.kind == XRDC_CRED_KRB5 && !view.token && !view.s3_access && !view.s3_secret);
        int64_t want = !strcmp(argv[3], "tgt") && strcmp(argv[4], "cursor") ? 123456789 : 0;
        assert(expiry == want);
        const char *path = argv[1];
        if (!strcmp(argv[4], "no-type")) { path += 5; }
        if (!strcmp(argv[4], "no-name")) { path = "(unknown-ccache)"; }
        assert(!strcmp(view.path, path));
    }
    unsetenv("BRIX_TEST_KRB5_FAULT"); return 0;
}
