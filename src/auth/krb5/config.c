#include "core/config/config.h"
#include "core/compat/log_diag.h"

/*
 * config.c — configure-time Kerberos 5 (krb5) auth setup for the stream server
 *
 * WHAT: Implements brix_configure_krb5_auth(), invoked from server-conf
 *       post-processing to validate and pre-load the Kerberos state a server
 *       needs before it can accept "krb5" logins: the krb5_context, the parsed
 *       acceptor principal (krb5_principal_obj) and the keytab handle
 *       (krb5_keytab_obj). These are consumed at run time by
 *       brix_handle_krb5_auth() in auth.c.
 *
 * WHY: Doing this once at config time (rather than per connection) means
 *      misconfiguration — missing principal, unparseable name, unreadable
 *      keytab — fails the server fast with a clear ngx_conf_log_error at
 *      startup instead of denying every client later. It also avoids repeated
 *      keytab opens on the hot auth path.
 *
 * HOW: Returns NGX_OK immediately unless xcf->auth == BRIX_AUTH_KRB5. It
 *      requires brix_krb5_principal, then krb5_init_context, krb5_parse_name,
 *      and resolves the keytab (krb5_kt_resolve when brix_krb5_keytab is set,
 *      else krb5_kt_default). It probes the keytab with a start/end seq_get to
 *      confirm readability and logs the effective principal, keytab name and
 *      ip_check flag at NOTICE. All krb5 code is gated on BRIX_HAVE_KRB5; a
 *      build without it that nonetheless requests krb5 auth fails with EMERG.
 *      Errors are decoded via brix_krb5_error()/brix_krb5_free_error().
 */

#if (BRIX_HAVE_KRB5)
static const char *
brix_krb5_error(ngx_stream_brix_srv_conf_t *xcf, krb5_error_code rc)
{
    return xcf->krb5.context != NULL
           ? krb5_get_error_message(xcf->krb5.context, rc)
           : NULL;
}

static void
brix_krb5_free_error(ngx_stream_brix_srv_conf_t *xcf, const char *msg)
{
    if (xcf->krb5.context != NULL && msg != NULL) {
        krb5_free_error_message(xcf->krb5.context, msg);
    }
}

/* ---- Require that a service principal was configured ----
 *
 * WHAT: Returns NGX_OK when brix_krb5_principal is set; otherwise logs an
 *       EMERG remediation diagnostic and returns NGX_ERROR.
 *
 * WHY: krb5 auth cannot present an acceptor identity to clients without a
 *      principal, so this precondition is checked before touching any krb5
 *      library state and fails the server startup with a precise hint.
 *
 * HOW: (1) If xcf->krb5.principal.len is non-zero, return NGX_OK. (2) Else emit
 *      the BRIX_DIAG_CONF EMERG guidance and return NGX_ERROR.
 */
static ngx_int_t
brix_krb5_require_principal(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->krb5.principal.len != 0) {
        return NGX_OK;
    }

    BRIX_DIAG_CONF(NGX_LOG_EMERG, cf, 0,
        "brix: krb5 auth is enabled but no service principal is set",
        "brix_auth krb5 needs the service principal it presents to "
        "clients, but brix_krb5_principal is missing",
        "add e.g. brix_krb5_principal \"xrootd/host.example.org@REALM\"; "
        "it must match a key in the keytab");
    return NGX_ERROR;
}

/* ---- Initialise the krb5_context ----
 *
 * WHAT: Creates xcf->krb5.context via krb5_init_context; returns NGX_OK on
 *       success or NGX_ERROR (after an EMERG log) on failure.
 *
 * WHY: Every subsequent krb5 call needs a context; establishing it in one place
 *      keeps the orchestrator flat and gives a single, clear failure point.
 *
 * HOW: (1) Call krb5_init_context. (2) On non-zero rc, log the numeric code at
 *      EMERG and return NGX_ERROR. (3) Otherwise return NGX_OK.
 */
static ngx_int_t
brix_krb5_init_context(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    krb5_error_code  rc;

    rc = krb5_init_context(&xcf->krb5.context);
    if (rc != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix: krb5_init_context failed (%d)",
                           (int) rc);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Parse the configured principal into a krb5_principal_obj ----
 *
 * WHAT: Parses xcf->krb5.principal into xcf->krb5.principal_obj; returns NGX_OK
 *       on success or NGX_ERROR (after an EMERG log with the decoded krb5 error)
 *       on failure.
 *
 * WHY: The acceptor principal must be a valid krb5 name before it can be used to
 *      match keytab entries; parsing here surfaces malformed names at startup.
 *
 * HOW: (1) Call krb5_parse_name on the principal string. (2) On non-zero rc,
 *      decode the message with brix_krb5_error, log at EMERG, free the message,
 *      and return NGX_ERROR. (3) Otherwise return NGX_OK.
 */
static ngx_int_t
brix_krb5_parse_principal(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    krb5_error_code  rc;
    const char      *kmsg;

    rc = krb5_parse_name(xcf->krb5.context,
                         (const char *) xcf->krb5.principal.data,
                         &xcf->krb5.principal_obj);
    if (rc != 0) {
        kmsg = brix_krb5_error(xcf, rc);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix: cannot parse krb5 principal \"%V\": %s",
                           &xcf->krb5.principal, kmsg ? kmsg : "unknown");
        brix_krb5_free_error(xcf, kmsg);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Resolve and open the keytab ----
 *
 * WHAT: Opens xcf->krb5.keytab_obj from the configured keytab path, or the krb5
 *       default keytab when none is set; returns NGX_OK on success or NGX_ERROR
 *       (after an EMERG remediation log) on failure.
 *
 * WHY: The keytab holds the acceptor's long-term key; opening it at config time
 *      turns a missing/unreadable keytab into a fast startup failure rather than
 *      a per-connection auth error, and avoids repeated opens on the hot path.
 *
 * HOW: (1) If a keytab path is configured, krb5_kt_resolve it; else
 *      krb5_kt_default. (2) On non-zero rc, decode the message, emit the
 *      BRIX_DIAG_CONF EMERG guidance, free the message, and return NGX_ERROR.
 *      (3) Otherwise return NGX_OK.
 */
static ngx_int_t
brix_krb5_open_keytab(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    krb5_error_code  rc;
    const char      *kmsg;

    if (xcf->krb5.keytab.len > 0) {
        rc = krb5_kt_resolve(xcf->krb5.context,
                             (const char *) xcf->krb5.keytab.data,
                             &xcf->krb5.keytab_obj);
    } else {
        rc = krb5_kt_default(xcf->krb5.context, &xcf->krb5.keytab_obj);
    }
    if (rc != 0) {
        kmsg = brix_krb5_error(xcf, rc);
        BRIX_DIAG_CONF(NGX_LOG_EMERG, cf, 0,
            "brix: cannot open krb5 keytab \"%V\": %s",
            "the keytab path is wrong, unreadable by the nginx user, or has "
            "no key for the configured principal",
            "point brix_krb5_keytab at the service keytab and grant the "
            "nginx user read access (chmod 0400, correct owner); verify with "
            "klist -k",
            &xcf->krb5.keytab, kmsg ? kmsg : "unknown");
        brix_krb5_free_error(xcf, kmsg);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Confirm the keytab is readable ----
 *
 * WHAT: Probes xcf->krb5.keytab_obj with a start/end sequence traversal to
 *       confirm it can actually be read; returns NGX_OK on success or NGX_ERROR
 *       (after an EMERG log) on failure.
 *
 * WHY: krb5_kt_resolve/default succeed lazily without touching the file, so an
 *      explicit start_seq_get is the earliest point a truly unreadable keytab is
 *      detected — still at config time, before any client connects.
 *
 * HOW: (1) krb5_kt_start_seq_get; on non-zero rc decode+log at EMERG, free the
 *      message, return NGX_ERROR. (2) On success, release the cursor with
 *      krb5_kt_end_seq_get and return NGX_OK.
 */
static ngx_int_t
brix_krb5_probe_keytab(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    krb5_error_code  rc;
    const char      *kmsg;
    krb5_kt_cursor   cursor;

    rc = krb5_kt_start_seq_get(xcf->krb5.context, xcf->krb5.keytab_obj,
                               &cursor);
    if (rc != 0) {
        kmsg = brix_krb5_error(xcf, rc);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix: cannot read krb5 keytab: %s",
                           kmsg ? kmsg : "unknown");
        brix_krb5_free_error(xcf, kmsg);
        return NGX_ERROR;
    }
    (void) krb5_kt_end_seq_get(xcf->krb5.context, xcf->krb5.keytab_obj,
                               &cursor);

    return NGX_OK;
}

/* ---- Log the resolved krb5 auth configuration at NOTICE ----
 *
 * WHAT: Emits a single NOTICE line reporting the effective acceptor principal,
 *       keytab name, and ip_check flag. No return value; purely diagnostic.
 *
 * WHY: A one-line confirmation of the exact principal/keytab actually resolved
 *      lets operators verify the running configuration matches intent without
 *      guessing at defaults.
 *
 * HOW: (1) Resolve the keytab name via krb5_kt_get_name, substituting
 *      "(unknown)" on failure. (2) Unparse the principal object, falling back to
 *      the configured principal string when unparse fails. (3) Log the NOTICE
 *      line. (4) Free the unparsed name if one was produced.
 */
static void
brix_krb5_log_configured(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    char   kt_name[1024];
    char  *principal = NULL;

    if (krb5_kt_get_name(xcf->krb5.context, xcf->krb5.keytab_obj,
                         kt_name, sizeof(kt_name)) != 0)
    {
        ngx_cpystrn((u_char *) kt_name, (u_char *) "(unknown)",
                    sizeof(kt_name));
    }

    if (krb5_unparse_name(xcf->krb5.context, xcf->krb5.principal_obj,
                          &principal) != 0)
    {
        principal = NULL;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "brix: krb5 auth configured - principal=%s "
                       "keytab=%s ip_check=%s",
                       principal != NULL ? principal
                                         : (const char *) xcf->krb5.principal.data,
                       kt_name, xcf->krb5.ip_check ? "on" : "off");

    if (principal != NULL) {
        krb5_free_unparsed_name(xcf->krb5.context, principal);
    }
}
#endif

/*
 *
 * WHAT: Validate krb5 directives and pre-load the krb5_context, acceptor
 *       principal and keytab into xcf for later use by the auth handler.
 *
 * WHY: Surfaces all Kerberos misconfiguration at config time so the server
 *      either starts ready to authenticate or fails to start with a precise
 *      diagnostic — clients never see an avoidable auth failure.
 *
 * HOW: No-op (NGX_OK) unless xcf->auth == BRIX_AUTH_KRB5. Otherwise it
 *      requires brix_krb5_principal, inits the context, parses the principal,
 *      resolves/opens the keytab (configured path or default), confirms the
 *      keytab is readable, and logs the resolved principal/keytab/ip_check.
 *      Returns NGX_ERROR on any failure (and EMERG when krb5 was requested in a
 *      build compiled without Kerberos support).
 */
ngx_int_t
brix_configure_krb5_auth(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
#if (BRIX_HAVE_KRB5)
    ngx_int_t  rc;

    if (xcf->auth != BRIX_AUTH_KRB5) {
        return NGX_OK;
    }

    rc = brix_krb5_require_principal(cf, xcf);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = brix_krb5_init_context(cf, xcf);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = brix_krb5_parse_principal(cf, xcf);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = brix_krb5_open_keytab(cf, xcf);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = brix_krb5_probe_keytab(cf, xcf);
    if (rc != NGX_OK) {
        return rc;
    }

    brix_krb5_log_configured(cf, xcf);

    return NGX_OK;
#else
    if (xcf->auth == BRIX_AUTH_KRB5) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_auth krb5 requested, but this build "
                           "was configured without Kerberos 5 support");
        return NGX_ERROR;
    }

    return NGX_OK;
#endif
}
