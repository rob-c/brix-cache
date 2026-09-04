/*
 * test_tier_s3_creds.c — F2: an S3 storage *tier* threads its §14 credential's
 * static S3 service keys into the remote-origin conf, so a private bucket signs
 * SigV4 instead of every S3 tier being anonymous/public-read only.
 *
 * Before phase-92 tier_build_s3() dropped the credential's s3_access_key /
 * s3_secret_key / s3_region, so cfg.access_key stayed empty and the driver was
 * always anonymous. The copy now lives in brix_tier_s3_apply_creds(), exercised
 * here directly (tier_build_s3() itself ends in a live brix_sd_remote_create()).
 *
 * Asserts:
 *   success:      a credential carrying all three fields lands them verbatim.
 *   edge:         a NULL credential, and empty (len==0) fields, leave the conf
 *                 untouched — region is optional and defaults in the driver.
 *   security-neg: an empty access_key leaves cfg.access_key[0] == '\0', so the
 *                 origin stays anonymous (never a partially-signed request).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "core/config/credential_block.h"
#include "fs/backend/remote/sd_remote.h"
#include "fs/tier/tier.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Unit under test — non-static in tier_build.c; declared locally so the test
 * needs neither tier.h nor the sd_remote include threaded through it. */
void brix_tier_s3_apply_creds(brix_sd_remote_cfg_t *cfg,
                              const brix_credential_t *c);

/* ---- link doubles: tier_build.o's build-closure symbols, none reached here -- */
void ngx_log_error_core(ngx_uint_t l, ngx_log_t *g, ngx_err_t e,
    const char *f, ...) { (void) l; (void) g; (void) e; (void) f; }

u_char *ngx_cpystrn(u_char *d, u_char *s, size_t n)
{ (void) s; (void) n; if (n) *d = '\0'; return d; }

ngx_uint_t ngx_process;   /* tier_build's pblock path reads it; never run here */

/* SD-factory + credential-bearer surfaces referenced by tier_build.o only from
 * the live tier_build_* paths, never from brix_tier_s3_apply_creds(). The two
 * with prototypes visible through sd_remote.h match those signatures; the rest
 * have no reachable declaration so opaque stubs satisfy the linker alone. */
brix_sd_instance_t *
brix_sd_remote_create(const brix_sd_remote_cfg_t *cfg, ngx_log_t *log)
{ (void) cfg; (void) log; return NULL; }

brix_sd_instance_t *
brix_sd_instance_create(ngx_log_t *log, const char *name, void *conf, int *err)
{ (void) log; (void) name; (void) conf; (void) err; return NULL; }

brix_sd_instance_t *
brix_tier_build_gsiftp(const brix_tier_cfg_t *tier, ngx_log_t *log)
{ (void) tier; (void) log; return NULL; }

#define STUB_SD(name) \
    void *name(void *a, void *b) { (void) a; (void) b; return NULL; }
STUB_SD(brix_sd_http_create)
STUB_SD(brix_sd_cache_create)
STUB_SD(brix_sd_frm_create)
STUB_SD(brix_sd_stage_create)
STUB_SD(brix_sd_xroot_create_origin)
void *brix_s3_origin_curl_transport(void) { return NULL; }
ngx_int_t brix_credential_bearer(const brix_credential_t *c, char *o, size_t n,
    ngx_log_t *l) { (void) c; (void) o; (void) n; (void) l; return NGX_ERROR; }
ngx_int_t
brix_imp_worker_runtime_ids(ngx_uid_t conf_uid, ngx_gid_t conf_gid,
    uid_t *runtime_uid, gid_t *runtime_gid)
{
    (void) conf_uid;
    (void) conf_gid;
    (void) runtime_uid;
    (void) runtime_gid;
    return NGX_OK;
}

static ngx_str_t S(char *s) { ngx_str_t v; v.data = (u_char *) s; v.len = strlen(s); return v; }

int
main(void)
{
    brix_sd_remote_cfg_t  cfg;
    brix_credential_t     cred;

    /* edge — a NULL credential is a no-op: the conf stays fully anonymous. */
    memset(&cfg, 0, sizeof(cfg));
    brix_tier_s3_apply_creds(&cfg, NULL);
    assert(cfg.access_key[0] == '\0' && cfg.secret_key[0] == '\0'
           && cfg.region[0] == '\0');
    /* a NULL cfg must also not crash. */
    brix_tier_s3_apply_creds(NULL, &cred);

    /* success — all three fields carried by the credential land verbatim. */
    memset(&cfg, 0, sizeof(cfg));
    memset(&cred, 0, sizeof(cred));
    cred.s3_access_key = S("AKIAEXAMPLE");
    cred.s3_secret_key = S("wSecretKey/1234");
    cred.s3_region     = S("us-east-1");
    brix_tier_s3_apply_creds(&cfg, &cred);
    assert(strcmp(cfg.access_key, "AKIAEXAMPLE") == 0);
    assert(strcmp(cfg.secret_key, "wSecretKey/1234") == 0);
    assert(strcmp(cfg.region, "us-east-1") == 0);

    /* edge — empty region is left untouched (driver default), keys still copied. */
    memset(&cfg, 0, sizeof(cfg));
    memset(&cred, 0, sizeof(cred));
    cred.s3_access_key = S("AKIA2");
    cred.s3_secret_key = S("secret2");
    /* s3_region stays {0,NULL} */
    brix_tier_s3_apply_creds(&cfg, &cred);
    assert(strcmp(cfg.access_key, "AKIA2") == 0);
    assert(strcmp(cfg.secret_key, "secret2") == 0);
    assert(cfg.region[0] == '\0');

    /* security-neg — an empty access_key must leave the origin anonymous, never
     * a half-signed conf (secret present but no key id). */
    memset(&cfg, 0, sizeof(cfg));
    memset(&cred, 0, sizeof(cred));
    cred.s3_secret_key = S("orphan-secret");
    cred.s3_region     = S("eu-west-2");
    brix_tier_s3_apply_creds(&cfg, &cred);
    assert(cfg.access_key[0] == '\0');   /* still anonymous */

    printf("test_tier_s3_creds: ALL PASS\n");
    return 0;
}
