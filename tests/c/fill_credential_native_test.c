/* Detached cache-fill credentials must own bytes across request lifetime. */
#include "protocols/shared/http_cache_fill_internal.h"
#include "fs/vfs/vfs_internal.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    unsigned index, calls, wipes;
    char *payload;
} fixture;

static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Address each declared borrowed credential field.
 * WHY: Every auth family must detach from the request's original storage.
 * HOW: Enumerate the public credential slots once in the test boundary. */
static const char **field(brix_sd_cred_t *cred, unsigned index)
{
    const char **fields[] = {&cred->x509_proxy, &cred->bearer, &cred->s3_ak,
        &cred->s3_sk, &cred->s3_region, &cred->s3_session, &cred->ceph_keyring,
        &cred->ceph_user, &cred->sss_keytab, &cred->krb5_ccache, &cred->krb5_princ,
        &cred->key, &cred->principal, &cred->vos, &cred->cred_dir};
    assert(index < sizeof(fields) / sizeof(fields[0])); return fields[index];
}

/* WHAT: Resolve one borrowed field through the normal credential gate seam.
 * WHY: Credential ownership is separate from auth-file selection.
 * HOW: Return an exact byte view or a finite authorization refusal. */
ngx_int_t __wrap_brix_vfs_backend_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use, int *error)
{
    assert(ctx); fixture *f = state(); f->calls++;
    memset(store, 0xa5, sizeof(*store));
    if (mode("denied")) { *error = EACCES; return NGX_ERROR; }
    if (mode("gate-error")) { *error = 0; errno = EIO; return NGX_ERROR; }
    *use = !mode("service"); *field(cred, f->index) = f->payload;
    cred->mode = BRIX_CRED_EXCHANGE; cred->fallback_deny = 1;
    return NGX_OK;
}

void __real_brix_sd_ucred_wipe(brix_sd_ucred_t *);
/* WHAT: Verify temporary secret cleanup even on failure.
 * WHY: Stack credentials must not retain bearer/S3 secrets after resolution.
 * HOW: Invoke the actual wipe and inspect every byte of its secret fields. */
void __wrap_brix_sd_ucred_wipe(brix_sd_ucred_t *cred)
{
    state()->wipes++; __real_brix_sd_ucred_wipe(cred);
    const unsigned char *fields[] = {(unsigned char *) cred->bearer,
        (unsigned char *) cred->s3_sk, (unsigned char *) cred->ceph_keyring};
    const size_t sizes[] = {sizeof(cred->bearer), sizeof(cred->s3_sk), sizeof(cred->ceph_keyring)};
    for (size_t i = 0; i < 3; i++) {
        for (size_t j = 0; j < sizes[i]; j++) { assert(fields[i][j] == 0); }
    }
}

/* WHAT: Obtain declared detached capacities without guessing limits.
 * WHY: Test the byte immediately below and at each field boundary.
 * HOW: Use sizeof the actual public detached-storage members. */
static size_t capacity(unsigned index)
{
    brix_http_fill_cred_t *c = NULL;
    const size_t capacities[] = {sizeof(c->x509_proxy), sizeof(c->bearer), sizeof(c->s3_ak),
        sizeof(c->s3_sk), sizeof(c->s3_region), sizeof(c->s3_session), sizeof(c->ceph_keyring),
        sizeof(c->ceph_user), sizeof(c->sss_keytab), sizeof(c->krb5_ccache), sizeof(c->krb5_princ),
        sizeof(c->key), sizeof(c->principal), sizeof(c->vos), sizeof(c->cred_dir)};
    assert(index < sizeof(capacities) / sizeof(capacities[0])); return capacities[index];
}

/* WHAT: Verify a successful detached snapshot and coalescing identity.
 * WHY: Caller reuse must not mutate bytes or mix distinct authorization scopes.
 * HOW: Overwrite the source, rebuild a view, compare copies, then cleanse all bytes. */
static void copied(brix_http_fill_cred_t *owned, size_t length)
{
    fixture *f = state(); memset(f->payload, 'x', length);
    brix_sd_cred_t view; memset(&view, 0xa5, sizeof(view));
    brix_http_fill_cred_view(owned, &view);
    const char *value = *field(&view, f->index);
    if (length) {
        assert(value && strlen(value) == length);
        for (size_t i = 0; i < length; i++) { assert(value[i] == 'a'); }
    } else { assert(value == NULL); }
    assert(view.mode == BRIX_CRED_EXCHANGE && view.fallback_deny && owned->use_cred);
    brix_http_fill_cred_t copy = *owned;
    assert(brix_http_fill_cred_equal(owned, &copy));
    copy.fallback_deny = 0; assert(!brix_http_fill_cred_equal(owned, &copy));
    copy = *owned; copy.mode = BRIX_CRED_SELECT; assert(!brix_http_fill_cred_equal(owned, &copy));
    brix_http_fill_cred_wipe(&copy);
}

int main(int argc, char **argv)
{
    assert(argc == 4); fixture f = {0}; ngx_cycle = &f.cycle;
    f.mode = argv[1]; f.index = (unsigned) atoi(argv[2]);
    size_t cap = capacity(f.index), length = atoi(argv[3]) ? cap : cap - 1;
    if (mode("empty")) { length = 0; }
    f.payload = malloc(length + 1); assert(f.payload);
    memset(f.payload, 'a', length); f.payload[length] = 0;
    brix_http_fill_cred_t *owned = malloc(sizeof(*owned)); assert(owned);
    memset(owned, 0xa5, sizeof(*owned)); brix_vfs_ctx_t ctx = {0};
    ngx_int_t rc = brix_http_fill_cred_resolve(mode("null-context") ? NULL : &ctx, owned);
    if (mode("denied") || mode("gate-error")) {
        assert(rc == NGX_ERROR && errno == (mode("denied") ? EACCES : EIO) && !owned->use_cred);
    } else if (mode("service") || mode("null-context")) {
        brix_http_fill_cred_t empty = {0}; assert(rc == NGX_OK && !memcmp(owned, &empty, sizeof(empty)));
    } else if (length == cap) {
        assert(rc == NGX_ERROR && errno == ENAMETOOLONG && !owned->use_cred);
    } else { assert(rc == NGX_OK); copied(owned, length); }
    assert(f.calls == f.wipes && f.calls == (mode("null-context") ? 0U : 1U));
    brix_http_fill_cred_wipe(owned);
    const unsigned char *bytes = (const unsigned char *) owned;
    for (size_t i = 0; i < sizeof(*owned); i++) { assert(bytes[i] == 0); }
    free(owned); free(f.payload); return 0;
}
