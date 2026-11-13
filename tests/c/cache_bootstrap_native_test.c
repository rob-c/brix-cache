/* Exercise the real three-phase wire bootstrap. Authentication engines and TLS
 * are finite boundaries here; their crypto/wire contracts have separate tests. */
#include "fs/cache/cache_internal.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    const char *fault;
    unsigned sends, tls, auth;
} fixture_t;

static fixture_t *state(void) { return (fixture_t *)ngx_cycle->conf_ctx; }
int __real_brix_cache_io_send(brix_cache_origin_conn_t *, const void *, size_t);

/* WHAT: Fail one selected send. WHY: Later phases must never start after it.
 * HOW: Count production sends, otherwise preserve real socket transport. */
int __wrap_brix_cache_io_send(brix_cache_origin_conn_t *oc, const void *p, size_t n)
{
    fixture_t *f = state();
    f->sends++;
    if (atoi(f->fault) == (int)f->sends) { errno = EPIPE; return -1; }
    return __real_brix_cache_io_send(oc, p, n);
}

/* WHAT: Observe the selected credential boundary. WHY: No silent fallback.
 * HOW: Emit exact identity and inject a terminal provider refusal if requested. */
static int auth(brix_cache_fill_t *t, const char *kind, const char *value,
    const char *extra)
{
    fixture_t *f = state();
    assert(f->sends == 3 && f->auth++ == 0);
    printf("auth=%s\nvalue=%s\nextra=%s\n", kind, value, extra ? extra : "");
    if (strcmp(f->fault, "auth") == 0) {
        brix_cache_set_error(t, kXR_AuthFailed, EACCES, "provider refused");
        return -1;
    }
    return 0;
}

int __wrap_brix_cache_origin_auth_ztn(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const ngx_str_t *token)
{
    (void)oc;
    char text[128];
    assert(token->len < sizeof(text));
    memcpy(text, token->data, token->len); text[token->len] = 0;
    return auth(t, "ztn", text, NULL);
}

int __wrap_brix_cache_origin_auth_gsi(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *parms, const char *proxy)
{
    (void)oc;
    return auth(t, "gsi", proxy, parms);
}

int __wrap_brix_cache_origin_auth_sss(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *keytab, const char *user)
{
    (void)oc;
    return auth(t, "sss", keytab, user);
}

int __wrap_brix_cache_origin_auth_krb5_raw(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *ccache, const char *spn)
{
    (void)oc;
    return auth(t, "krb5", ccache, spn);
}

int __wrap_brix_cache_origin_tls_upgrade(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const ngx_str_t *host)
{
    (void)oc;
    fixture_t *f = state();
    assert(f->sends == 2 && f->tls++ == 0);
    assert(host->len == 14 && memcmp(host->data, "origin.invalid", 14) == 0);
    if (strcmp(f->fault, "tls") == 0) {
        brix_cache_set_error(t, kXR_TLSRequired, EACCES, "certificate refused");
        return -1;
    }
    return 0;
}

/* WHAT: Carry independent caller and service credentials into the real task.
 * WHY: Tests must prove caller identity outranks every configured service key.
 * HOW: Set exactly named fields; selection remains entirely production code. */
static void credentials(brix_cache_fill_t *t, const char *user, const char *service)
{
    if (strstr(user, "gsi")) strcpy(t->cred_x509_proxy, "caller.proxy");
    if (strstr(user, "krb5")) {
        strcpy(t->cred_krb5_ccache, "caller.ccache");
        if (!strstr(user, "no-spn")) strcpy(t->cred_krb5_princ, "root/carried@REALM");
    }
    if (strstr(user, "ztn")) strcpy(t->cred_bearer, "caller.token");
    if (strstr(user, "sss")) {
        strcpy(t->cred_sss_keytab, "caller.keytab");
        strcpy(t->cred_principal, "alice");
    }
    if (strstr(service, "gsi")) { ngx_str_set(&t->conf->cache_origin_x509_proxy, "service.proxy"); }
    if (strstr(service, "ztn")) { ngx_str_set(&t->conf->cache_origin_bearer, "service.token"); }
    if (strstr(service, "sss")) { ngx_str_set(&t->conf->cache_origin_sss_keytab, "service.keytab"); }
}

int main(int argc, char **argv)
{
    assert(argc == 6);
    signal(SIGPIPE, SIG_IGN); ngx_time_init();
    fixture_t f = {.fault = argv[5]};
    ngx_cycle_t cycle = {0}; cycle.conf_ctx = (void ****)&f; ngx_cycle = &cycle;
    brix_cache_fill_t *t = calloc(1, sizeof(*t)); assert(t);
    ngx_stream_brix_srv_conf_t conf = {0}; t->conf = &conf;
    conf.cache_origin_tls = atoi(argv[4]);
    ngx_str_set(&conf.cache_origin_host, "origin.invalid");
    credentials(t, argv[2], argv[3]);
    brix_cache_origin_conn_t oc = {.fd = atoi(argv[1])};
    int rc = brix_cache_origin_bootstrap(t, &oc);
    close(oc.fd);
    printf("rc=%d\nerror=%d\nmessage=%s\nsends=%u\ntls=%u\nauth_count=%u\nflags=%u\n",
        rc, t->xrd_error, t->err_msg, f.sends, f.tls, f.auth, oc.srv_flags);
    free(t); ngx_cycle = NULL;
    return 0;
}
