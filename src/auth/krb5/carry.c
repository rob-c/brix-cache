/*
 * carry_macos.c — stub implementation for macOS Heimdal.
 *
 * macOS uses Heimdal Kerberos which lacks the MIT Kerberos-specific
 * GSSAPI extensions (gss_store_cred_into, gss_krb5_import_cred, etc.).
 * This stub allows compilation but reports functionality as unavailable.
 */

#include "auth/krb5/carry.h"
#include <ngx_core.h>

ngx_int_t
brix_krb5_cred_to_ccache(void *deleg_gss_cred, const char *path, ngx_log_t *log)
{
    (void)deleg_gss_cred; (void)path; (void)log;
    return NGX_ERROR;  /* Heimdal lacks gss_store_cred_into */
}

ngx_int_t
brix_krb5_cred_from_ccache(const char *path, void **out_gss_cred,
    void **out_hold, ngx_log_t *log)
{
    (void)path; (void)out_gss_cred; (void)out_hold; (void)log;
    return NGX_ERROR;  /* Heimdal lacks gss_krb5_import_cred */
}

void
brix_krb5_cred_carry_release(void *gss_cred, void *hold_v, ngx_log_t *log)
{
    (void)gss_cred; (void)hold_v; (void)log;
    /* Nothing to release on Heimdal */
}
