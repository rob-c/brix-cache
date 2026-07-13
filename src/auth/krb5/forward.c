#include "auth/krb5/forward.h"

/*
 * forward.c — krb5 GSSAPI credential forwarding (phase-70 §5.7).
 *
 * WHAT: Implements brix_krb5_forward_available() and brix_krb5_deleg_to_origin()
 *       declared in forward.h — a single GSSAPI init-context step that presents a
 *       delegated Kerberos credential to an upstream/origin service principal.
 *
 * WHY: Lets a node re-authenticate to the backend AS the inbound user when the
 *      client supplied a forwardable ticket, instead of using a static service
 *      credential (EXCHANGE strategy). Best-effort: callers fall to SELECT when
 *      forwarding is unavailable.
 *
 * HOW: Under BRIX_HAVE_KRB5 we import the origin principal with the GSSAPI
 *      krb5 NT_HOSTBASED_SERVICE name type, then call gss_init_sec_context()
 *      exactly once using the supplied delegated cred as the initiator identity,
 *      requesting mutual auth. The resulting output token is copied into the
 *      caller's pool. Any partially-built context is deleted on error so no GSS
 *      resources leak; the caller never sees a half-open context handle. GSSAPI
 *      status is surfaced via a local gss display-status helper (auth.c's
 *      brix_krb5_error() is krb5-not-GSS and file-static, so it is not reused
 *      here; the mechanics — capture major/minor, log, free — mirror it).
 *      Without BRIX_HAVE_KRB5 the file still compiles: the API reports
 *      unavailable and returns NGX_ERROR.
 */

#if (BRIX_HAVE_KRB5)

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

int
brix_krb5_forward_available(void)
{
    return 1;
}

/*
 * Log a GSSAPI major/minor status pair as human-readable text. Walks both the
 * GSS and mechanism status chains via gss_display_status(), emitting each
 * message at WARN. Mirrors auth.c's error-string pattern (capture code, render,
 * free) but for the GSS status API rather than krb5_get_error_message().
 */
static void
brix_gss_log_status(ngx_log_t *log, const char *what,
    OM_uint32 major, OM_uint32 minor)
{
    OM_uint32 types[2];
    ngx_uint_t i;

    types[0] = GSS_C_GSS_CODE;
    types[1] = GSS_C_MECH_CODE;

    for (i = 0; i < 2; i++) {
        OM_uint32   status = (types[i] == GSS_C_GSS_CODE) ? major : minor;
        OM_uint32   msg_ctx = 0;

        do {
            OM_uint32     dmaj, dmin;
            gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;

            dmaj = gss_display_status(&dmin, status, (int) types[i],
                                      GSS_C_NO_OID, &msg_ctx, &msg);
            if (GSS_ERROR(dmaj)) {
                break;
            }

            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix: krb5 gss %s: %*s", what,
                          (int) msg.length,
                          msg.value ? (char *) msg.value : "");
            gss_release_buffer(&dmin, &msg);
        } while (msg_ctx != 0);
    }
}

/*
 * Import the origin service principal string into a GSS name using the krb5
 * host-based service name type. Returns NGX_OK with *out set (caller releases),
 * or NGX_ERROR (status logged). Does not take ownership of princ.
 */
static ngx_int_t
brix_gss_import_service(const char *princ, gss_name_t *out, ngx_log_t *log)
{
    OM_uint32       major, minor;
    gss_buffer_desc name_buf;

    if (princ == NULL || princ[0] == '\0') {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 forward: empty origin service principal");
        return NGX_ERROR;
    }

    name_buf.value = (void *) princ;
    name_buf.length = ngx_strlen(princ);

    major = gss_import_name(&minor, &name_buf,
                            (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME, out);
    if (GSS_ERROR(major)) {
        brix_gss_log_status(log, "import_name", major, minor);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * Copy a GSS output token into the caller's pool as an ngx_str_t. Returns
 * NGX_OK, or NGX_ERROR on allocation failure (caller still releases the GSS
 * buffer). Empty tokens are treated as an error since a first-leg init context
 * must produce output to send to the origin.
 */
static ngx_int_t
brix_gss_token_to_pool(ngx_pool_t *pool, gss_buffer_desc *tok,
    ngx_str_t *out, ngx_log_t *log)
{
    u_char *copy;

    if (tok->value == NULL || tok->length == 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: krb5 forward: empty gss output token");
        return NGX_ERROR;
    }

    copy = ngx_pnalloc(pool, tok->length);
    if (copy == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(copy, tok->value, tok->length);
    out->data = copy;
    out->len = tok->length;
    return NGX_OK;
}

ngx_int_t
brix_krb5_deleg_to_origin(ngx_pool_t *pool, void *deleg_gss_cred,
    const char *origin_service_princ, ngx_str_t *out_token, ngx_log_t *log)
{
    OM_uint32        major, minor;
    OM_uint32        req_flags, ret_flags;
    gss_name_t       target;
    gss_ctx_id_t     gss_ctx;
    gss_cred_id_t    init_cred;
    gss_buffer_desc  out_buf;
    ngx_int_t        rc;

    if (pool == NULL || out_token == NULL) {
        return NGX_ERROR;
    }

    target = GSS_C_NO_NAME;
    if (brix_gss_import_service(origin_service_princ, &target, log) != NGX_OK) {
        return NGX_ERROR;
    }

    gss_ctx = GSS_C_NO_CONTEXT;
    init_cred = (gss_cred_id_t) deleg_gss_cred;   /* GSS_C_NO_CREDENTIAL == NULL */
    out_buf = (gss_buffer_desc) GSS_C_EMPTY_BUFFER;
    req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;
    ret_flags = 0;

    major = gss_init_sec_context(&minor, init_cred, &gss_ctx, target,
                                 GSS_C_NO_OID, req_flags, 0,
                                 GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER, NULL,
                                 &out_buf, &ret_flags, NULL);

    /*
     * A single init step legitimately returns GSS_S_CONTINUE_NEEDED (the origin
     * must reply); only a hard GSS_ERROR is a failure. Either way an output
     * token is produced on the first leg and handed to the caller, which drives
     * the remaining legs.
     */
    if (GSS_ERROR(major)) {
        brix_gss_log_status(log, "init_sec_context", major, minor);
        rc = NGX_ERROR;
    } else {
        rc = brix_gss_token_to_pool(pool, &out_buf, out_token, log);
    }

    if (out_buf.length != 0) {
        OM_uint32 dmin;
        gss_release_buffer(&dmin, &out_buf);
    }
    if (gss_ctx != GSS_C_NO_CONTEXT) {
        OM_uint32 dmin;
        gss_delete_sec_context(&dmin, &gss_ctx, GSS_C_NO_BUFFER);
    }
    {
        OM_uint32 dmin;
        gss_release_name(&dmin, &target);
    }

    return rc;
}

#else /* !BRIX_HAVE_KRB5 */

int
brix_krb5_forward_available(void)
{
    return 0;
}

ngx_int_t
brix_krb5_deleg_to_origin(ngx_pool_t *pool, void *deleg_gss_cred,
    const char *origin_service_princ, ngx_str_t *out_token, ngx_log_t *log)
{
    (void) pool;
    (void) deleg_gss_cred;
    (void) origin_service_princ;
    (void) out_token;

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix: krb5 credential forwarding not compiled in");
    return NGX_ERROR;
}

#endif /* BRIX_HAVE_KRB5 */
