#include "../config/config.h"

/*
 * config.c — configure-time Kerberos 5 (krb5) auth setup for the stream server
 *
 * WHAT: Implements xrootd_configure_krb5_auth(), invoked from server-conf
 *       post-processing to validate and pre-load the Kerberos state a server
 *       needs before it can accept "krb5" logins: the krb5_context, the parsed
 *       acceptor principal (krb5_principal_obj) and the keytab handle
 *       (krb5_keytab_obj). These are consumed at run time by
 *       xrootd_handle_krb5_auth() in auth.c.
 *
 * WHY: Doing this once at config time (rather than per connection) means
 *      misconfiguration — missing principal, unparseable name, unreadable
 *      keytab — fails the server fast with a clear ngx_conf_log_error at
 *      startup instead of denying every client later. It also avoids repeated
 *      keytab opens on the hot auth path.
 *
 * HOW: Returns NGX_OK immediately unless xcf->auth == XROOTD_AUTH_KRB5. It
 *      requires xrootd_krb5_principal, then krb5_init_context, krb5_parse_name,
 *      and resolves the keytab (krb5_kt_resolve when xrootd_krb5_keytab is set,
 *      else krb5_kt_default). It probes the keytab with a start/end seq_get to
 *      confirm readability and logs the effective principal, keytab name and
 *      ip_check flag at NOTICE. All krb5 code is gated on XROOTD_HAVE_KRB5; a
 *      build without it that nonetheless requests krb5 auth fails with EMERG.
 *      Errors are decoded via xrootd_krb5_error()/xrootd_krb5_free_error().
 */

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

/* ---- Function: xrootd_configure_krb5_auth() -------------------------------
 *
 * WHAT: Validate krb5 directives and pre-load the krb5_context, acceptor
 *       principal and keytab into xcf for later use by the auth handler.
 *
 * WHY: Surfaces all Kerberos misconfiguration at config time so the server
 *      either starts ready to authenticate or fails to start with a precise
 *      diagnostic — clients never see an avoidable auth failure.
 *
 * HOW: No-op (NGX_OK) unless xcf->auth == XROOTD_AUTH_KRB5. Otherwise it
 *      requires xrootd_krb5_principal, inits the context, parses the principal,
 *      resolves/opens the keytab (configured path or default), confirms the
 *      keytab is readable, and logs the resolved principal/keytab/ip_check.
 *      Returns NGX_ERROR on any failure (and EMERG when krb5 was requested in a
 *      build compiled without Kerberos support).
 */
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
