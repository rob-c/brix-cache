/* Real umbrella CLI, with finite endpoint and credential-provider boundaries.
 * No user credential store or remote service is consulted. Observed provider
 * calls make cleanup and read/write intent independently assertable. */
#include "apps/diag/xrd_internal.h"
#include <assert.h>

static int mode(const char *name) { return !strcmp(getenv("BRIX_POSTURE_MODE"), name); }
static void event(const char *name) { fprintf(stderr, "event=%s\n", name); }
int __wrap_brix_cred_autorefresh(int write, const char *account, int verbose, FILE *out)
{
    assert(out == stderr); event("refresh");
    printf("provider=%d,%s,%d\n", write, account ? account : "", verbose); return 2;
}
int __wrap_brix_cred_diagnose(int write, const char *prefix, FILE *out)
{ assert(out == stdout && !strcmp(prefix, "  ")); event("diagnose"); printf("posture-write=%d\n", write); return 0; }
int __wrap_brix_connect(brix_conn *c, const brix_url *url, const brix_opts *opts, brix_status *st)
{
    assert(!strcmp(url->host, "origin.invalid") && opts->verify_host == 1); event("connect");
    if (mode("connect-error")) { brix_status_set(st, kXR_NotAuthorized, 0, "fixture denied"); return -1; }
    memset(c, 0, sizeof(*c)); c->next_sid = 100;
    c->server_flags = (uint32_t) strtoul(getenv("BRIX_POSTURE_FLAGS"), NULL, 10);
    if (mode("authenticated")) { c->diag.chosen_auth = "ztn"; strcpy(c->sec_list, "&P=ztn"); }
    return 0;
}
void __wrap_brix_close(brix_conn *c) { assert(c->next_sid >= 100); event("close"); }
int __wrap_brix_stat(brix_conn *c, const char *path, brix_statinfo *out, brix_status *st)
{
    assert(!strcmp(path, "/")); event("stat"); c->next_sid++;
    if (mode("stat-error") || (mode("partial") && c->next_sid % 2)) {
        brix_status_set(st, kXR_NotAuthorized, 0, "fixture denied"); return -1;
    }
    memset(out, 0, sizeof(*out)); return 0;
}
int __wrap_brix_query(brix_conn *c, int type, const char *argument, char *out, size_t cap, brix_status *st)
{
    assert(c && type == kXR_Qconfig); event("query");
    if (mode("query-error")) { brix_status_set(st, kXR_Unsupported, 0, "unsupported"); return -1; }
    snprintf(out, cap, mode("bare") ? "fixture-value" : "%s=fixture-value\nignored-tail", argument); return 0;
}
int __wrap_brix_tls_info(const brix_conn *c, const char **version, const char **cipher)
{
    assert(c); *cipher = "fixture-cipher";
    *version = mode("tls") ? "TLSv1.3" : NULL;
    return mode("tls") || mode("tls-unnamed");
}
char *__wrap_brix_token_discover(void)
{ event("token-discover"); return mode("authenticated") ? strdup("fixture-token") : NULL; }
void __wrap_brix_token_explain(const char *token, FILE *out)
{ assert(!strcmp(token, "fixture-token") && out == stdout); event("token-explain"); }
void __wrap_brix_proxy_default_path(char *out, size_t cap)
{ snprintf(out, cap, "%s", getenv("BRIX_POSTURE_PROXY")); }
void __wrap_brix_gsi_cert_explain(const char *path, FILE *out)
{ assert(!strcmp(path, getenv("BRIX_POSTURE_PROXY")) && out == stdout); event("proxy-explain"); }
