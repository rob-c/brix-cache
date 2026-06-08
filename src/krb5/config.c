#include "../config/config.h"

#if (XROOTD_HAVE_KRB5)
static const char *
xrootd_krb5_error(ngx_stream_xrootd_srv_conf_t *xcf, krb5_error_code rc)
{
    return xcf->krb5_context != NULL
           ? krb5_get_error_message(xcf->krb5_context, rc)
           : NULL;
}

static void
xrootd_krb5_free_error(ngx_stream_xrootd_srv_conf_t *xcf, const char *msg)
{
    if (xcf->krb5_context != NULL && msg != NULL) {
        krb5_free_error_message(xcf->krb5_context, msg);
    }
}
#endif

ngx_int_t
xrootd_configure_krb5_auth(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf)
{
#if (XROOTD_HAVE_KRB5)
    krb5_error_code rc;
    const char     *kmsg;
    krb5_kt_cursor  cursor;
    char            kt_name[1024];
    char           *principal = NULL;

    if (xcf->auth != XROOTD_AUTH_KRB5) {
        return NGX_OK;
    }

    if (xcf->krb5_principal.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_auth krb5 requires "
                           "xrootd_krb5_principal");
        return NGX_ERROR;
    }

    rc = krb5_init_context(&xcf->krb5_context);
    if (rc != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd: krb5_init_context failed (%d)",
                           (int) rc);
        return NGX_ERROR;
    }

    rc = krb5_parse_name(xcf->krb5_context,
                         (const char *) xcf->krb5_principal.data,
                         &xcf->krb5_principal_obj);
    if (rc != 0) {
        kmsg = xrootd_krb5_error(xcf, rc);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd: cannot parse krb5 principal \"%V\": %s",
                           &xcf->krb5_principal, kmsg ? kmsg : "unknown");
        xrootd_krb5_free_error(xcf, kmsg);
        return NGX_ERROR;
    }

    if (xcf->krb5_keytab.len > 0) {
        rc = krb5_kt_resolve(xcf->krb5_context,
                             (const char *) xcf->krb5_keytab.data,
                             &xcf->krb5_keytab_obj);
    } else {
        rc = krb5_kt_default(xcf->krb5_context, &xcf->krb5_keytab_obj);
    }
    if (rc != 0) {
        kmsg = xrootd_krb5_error(xcf, rc);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd: cannot open krb5 keytab \"%V\": %s",
                           &xcf->krb5_keytab, kmsg ? kmsg : "unknown");
        xrootd_krb5_free_error(xcf, kmsg);
        return NGX_ERROR;
    }

    rc = krb5_kt_start_seq_get(xcf->krb5_context, xcf->krb5_keytab_obj,
                               &cursor);
    if (rc != 0) {
        kmsg = xrootd_krb5_error(xcf, rc);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd: cannot read krb5 keytab: %s",
                           kmsg ? kmsg : "unknown");
        xrootd_krb5_free_error(xcf, kmsg);
        return NGX_ERROR;
    }
    (void) krb5_kt_end_seq_get(xcf->krb5_context, xcf->krb5_keytab_obj,
                               &cursor);

    if (krb5_kt_get_name(xcf->krb5_context, xcf->krb5_keytab_obj,
                         kt_name, sizeof(kt_name)) != 0)
    {
        ngx_cpystrn((u_char *) kt_name, (u_char *) "(unknown)",
                    sizeof(kt_name));
    }

    if (krb5_unparse_name(xcf->krb5_context, xcf->krb5_principal_obj,
                          &principal) != 0)
    {
        principal = NULL;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "xrootd: krb5 auth configured - principal=%s "
                       "keytab=%s ip_check=%s",
                       principal != NULL ? principal
                                         : (const char *) xcf->krb5_principal.data,
                       kt_name, xcf->krb5_ip_check ? "on" : "off");

    if (principal != NULL) {
        krb5_free_unparsed_name(xcf->krb5_context, principal);
    }

    return NGX_OK;
#else
    if (xcf->auth == XROOTD_AUTH_KRB5) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_auth krb5 requested, but this build "
                           "was configured without Kerberos 5 support");
        return NGX_ERROR;
    }

    return NGX_OK;
#endif
}
