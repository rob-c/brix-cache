/* Observe credential/policy boundaries while retaining real storage factories. */
#include "fs/tier/tier.h"
#include "fs/backend/xroot/sd_xroot.h"
#include "fs/backend/http/sd_http.h"
#include "fs/backend/remote/sd_remote.h"
#include "fs/backend/gsiftp/sd_gsiftp.h"
#include "native_alloc_fail.h"

static const char *text(const char *value) { return value ? value : "<none>"; }

brix_sd_instance_t *__real_brix_sd_xroot_create_origin(const brix_sd_xroot_origin_cfg_t *, ngx_log_t *);
brix_sd_instance_t *
__wrap_brix_sd_xroot_create_origin(const brix_sd_xroot_origin_cfg_t *c, ngx_log_t *log)
{
    printf("ROOT %s:%d tls=%d nearline=%d verify=%d\n", c->host, c->port,
           c->tls, c->nearline, c->verify_pages);
    printf("TOKEN %s\nPROXY %s\nKEY %s\nCA %s\n", text(c->bearer),
           text(c->x509_proxy), text(c->x509_key), text(c->ca_dir));
    return __real_brix_sd_xroot_create_origin(c, log);
}

brix_sd_instance_t *__real_brix_sd_http_create(const brix_sd_http_cfg_t *, ngx_log_t *);
brix_sd_instance_t *
__wrap_brix_sd_http_create(const brix_sd_http_cfg_t *c, ngx_log_t *log)
{
    printf("HTTP %s:%d tls=%d path=%s\nTOKEN %s\nCA %s\n", c->host, c->port,
           c->tls, c->base_path, text(c->bearer_token), text(c->ca_path));
    assert(c->transport != NULL && c->timeout_ms > 0);
    return __real_brix_sd_http_create(c, log);
}

brix_sd_instance_t *__real_brix_sd_remote_create(const brix_sd_remote_cfg_t *, ngx_log_t *);
brix_sd_instance_t *
__wrap_brix_sd_remote_create(const brix_sd_remote_cfg_t *c, ngx_log_t *log)
{
    printf("S3 %s:%d tls=%d bucket=%s nearline=%d\nACCESS %s\nSECRET %s\nREGION %s\n",
           c->host, c->port, c->tls, c->bucket, c->nearline,
           c->access_key, c->secret_key, c->region);
    assert(c->transport != NULL && c->timeout_ms > 0);
    return __real_brix_sd_remote_create(c, log);
}

brix_sd_instance_t *__real_brix_sd_gsiftp_create(const brix_sd_gsiftp_cfg_t *, ngx_log_t *);
brix_sd_instance_t *
__wrap_brix_sd_gsiftp_create(const brix_sd_gsiftp_cfg_t *c, ngx_log_t *log)
{
    printf("FTP %s:%d gsi=%d path=%s streams=%u\nPROXY %s\nCA %s\n",
           c->host, c->port, c->require_gsi, c->base_path, c->streams,
           text(c->x509_proxy), text(c->ca_dir));
    assert(c->mode == GFTP_DMODE_E && c->prot == GFTP_DPROT_P && c->timeout_ms > 0);
    return __real_brix_sd_gsiftp_create(c, log);
}

static ngx_str_t
string(char *value)
{
    ngx_str_t result = {strlen(value), (u_char *) value};
    return result;
}

static void
credential(brix_credential_t *c, const char *mode, char *ca)
{
    memset(c, 0, sizeof(*c));
    if (strcmp(mode, "empty") == 0 || strcmp(mode, "anonymous") == 0) { return; }
    c->token = string("fixture-token");
    c->x509_cert = string("fixture-cert.pem");
    c->x509_key = string("fixture-key.pem");
    c->ca_dir = string(ca);
    c->s3_access_key = string("fixture-access");
    c->s3_secret_key = string("fixture-secret");
    c->s3_region = string("fixture-region");
    if (strcmp(mode, "proxy") == 0) { c->x509_proxy = string("fixture-proxy.pem"); }
}

static void
destroy(brix_sd_instance_t *instance, const char *driver)
{
    if (strcmp(driver, "xroot") == 0) { brix_sd_xroot_destroy(instance); return; }
    if (strcmp(driver, "http") == 0) { brix_sd_http_destroy(instance); return; }
    if (strcmp(driver, "s3") == 0) { brix_sd_remote_destroy(instance); return; }
    brix_sd_gsiftp_destroy(instance);
}

int
main(int argc, char **argv)
{
    ngx_log_t log = {0};
    ngx_cycle_t cycle = {0};
    brix_tier_cfg_t t = {0};
    brix_credential_t c;
    brix_sd_instance_t *instance;
    assert(argc == 8);
    cycle.log = &log; ngx_cycle = &cycle; ngx_os_argv = argv;
    ngx_time_init(); assert(ngx_os_init(&log) == NGX_OK);
    credential(&c, argv[2], argv[3]);
    snprintf(t.driver, sizeof(t.driver), "%s", argv[1]);
    snprintf(t.host, sizeof(t.host), "127.0.0.1");
    snprintf(t.path, sizeof(t.path), "%s", argv[4]);
    t.port = 443; t.tls = 1; t.configured = 1; t.nearline = 1;
    t.verify_pages = BRIX_PGVERIFY_REQUIRE;
    t.ftp_streams = 3; t.ftp_mode_e = 1; t.ftp_prot_p = 1;
    t.credential = strcmp(argv[2], "anonymous") == 0 ? NULL : &c;
    if (strcmp(argv[5], "unconfigured") == 0) { t.configured = 0; }
    if (strcmp(argv[5], "host") == 0) { t.host[0] = 0; }
    if (strcmp(argv[5], "port") == 0) { t.port = 0; }
    if (strcmp(argv[5], "calloc") == 0 || strcmp(argv[5], "malloc") == 0) {
        native_alloc_arm(argv[5], (unsigned) atoi(argv[6]));
    }
    instance = brix_tier_build(strcmp(argv[5], "null") == 0 ? NULL : &t, &log);
    native_alloc_disarm();
    assert((instance != NULL) == atoi(argv[7]));
    if (instance != NULL) {
        assert(instance->domain == BRIX_VFS_DOMAIN_EXPORT);
        assert(instance->driver != NULL && instance->state != NULL && instance->caps != 0);
        destroy(instance, argv[1]);
    }
    return 0;
}
