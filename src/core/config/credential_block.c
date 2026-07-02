/*
 * credential_block.c — the `xrootd_credential <name> { … }` block (phase-63 §14).
 * See credential_block.h for the WHAT/WHY/HOW.
 */
#include "credential_block.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* Credentials are few (one per upstream identity); a small fixed, process-wide
 * table avoids allocation and is scanned linearly by name. Interned strings live
 * on cf->pool (stable for the process lifetime). */
#define XROOTD_CREDENTIAL_MAX 32
static xrootd_credential_t  xrootd_credentials[XROOTD_CREDENTIAL_MAX];
static ngx_uint_t           xrootd_credential_count;

const xrootd_credential_t *
xrootd_credential_lookup(const char *name)
{
    ngx_uint_t i;

    if (name == NULL || name[0] == '\0') {
        return NULL;
    }
    for (i = 0; i < xrootd_credential_count; i++) {
        if (xrootd_credentials[i].name.len == ngx_strlen(name)
            && ngx_strncmp(xrootd_credentials[i].name.data, name,
                           xrootd_credentials[i].name.len) == 0)
        {
            return &xrootd_credentials[i];
        }
    }
    return NULL;
}

/* ---- the per-line handler -------------------------------------------------
 * One nested directive per call. value[0] is the directive name, value[1] its
 * single argument (for the str/flag fields). Table-driven so adding a field is a
 * one-line edit. */

typedef struct {
    const char  *key;
    size_t       str_off;   /* offsetof(ngx_str_t field), or (size_t)-1 if a flag */
    size_t       flag_off;  /* offsetof(ngx_flag_t field), or (size_t)-1          */
} xrootd_credential_field_t;

#define CRED_STR(k, f)  { k, offsetof(xrootd_credential_t, f), (size_t) -1 }
#define CRED_FLAG(k, f) { k, (size_t) -1, offsetof(xrootd_credential_t, f) }

static const xrootd_credential_field_t  xrootd_credential_fields[] = {
    CRED_STR("x509_proxy",    x509_proxy),
    CRED_STR("x509_cert",     x509_cert),
    CRED_STR("x509_key",      x509_key),
    CRED_STR("ca_dir",        ca_dir),
    CRED_STR("token",         token),
    CRED_STR("token_file",    token_file),
    CRED_STR("vo",            vo),
    CRED_STR("s3_access_key", s3_access_key),
    CRED_STR("s3_secret_key", s3_secret_key),
    CRED_STR("s3_region",     s3_region),
    CRED_STR("sss_keytab",    sss_keytab),
    CRED_FLAG("token_forward", token_forward),
    CRED_FLAG("tls",          tls),
    { NULL, 0, 0 },
};

static char *
xrootd_credential_line(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    xrootd_credential_t             *cred = conf;
    ngx_str_t                       *value = cf->args->elts;
    const xrootd_credential_field_t *fld;

    for (fld = xrootd_credential_fields; fld->key != NULL; fld++) {
        if (value[0].len != ngx_strlen(fld->key)
            || ngx_strncmp(value[0].data, fld->key, value[0].len) != 0)
        {
            continue;
        }

        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_credential: \"%V\" takes exactly one argument",
                &value[0]);
            return NGX_CONF_ERROR;
        }

        if (fld->flag_off != (size_t) -1) {
            ngx_flag_t *flag = (ngx_flag_t *) ((char *) cred + fld->flag_off);

            if (value[1].len == 2 && ngx_strncmp(value[1].data, "on", 2) == 0) {
                *flag = 1;
            } else if (value[1].len == 3
                       && ngx_strncmp(value[1].data, "off", 3) == 0) {
                *flag = 0;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_credential: \"%V\" expects on|off", &value[0]);
                return NGX_CONF_ERROR;
            }
            return NGX_CONF_OK;
        }

        {
            ngx_str_t *dst = (ngx_str_t *) ((char *) cred + fld->str_off);

            dst->data = ngx_pnalloc(cf->pool, value[1].len + 1);
            if (dst->data == NULL) {
                return NGX_CONF_ERROR;
            }
            ngx_memcpy(dst->data, value[1].data, value[1].len);
            dst->data[value[1].len] = '\0';
            dst->len = value[1].len;
        }
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "xrootd_credential: unknown directive \"%V\"", &value[0]);
    return NGX_CONF_ERROR;
}

char *
xrootd_conf_credential_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t           *value = cf->args->elts;
    xrootd_credential_t *cred;
    ngx_conf_t           save;
    char                *rv;

    /* Dedup by name (last write wins), so a reload re-parsing the whole conf
     * updates the credential in place rather than appending or erroring. */
    {
        char                       name_z[256];
        const xrootd_credential_t *existing;

        ngx_cpystrn((u_char *) name_z, value[1].data,
                    ngx_min(value[1].len + 1, sizeof(name_z)));
        existing = xrootd_credential_lookup(name_z);
        if (existing != NULL) {
            cred = (xrootd_credential_t *) existing;
        } else if (xrootd_credential_count >= XROOTD_CREDENTIAL_MAX) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_credential: too many credential blocks (max %d)",
                XROOTD_CREDENTIAL_MAX);
            return NGX_CONF_ERROR;
        } else {
            cred = &xrootd_credentials[xrootd_credential_count++];
        }
    }

    ngx_memzero(cred, sizeof(*cred));
    cred->name.data = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (cred->name.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(cred->name.data, value[1].data, value[1].len);
    cred->name.data[value[1].len] = '\0';
    cred->name.len = value[1].len;

    save = *cf;
    cf->handler = xrootd_credential_line;
    cf->handler_conf = (char *) cred;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;
    return rv;
}

ngx_int_t
xrootd_credential_bearer(const xrootd_credential_t *cred, char *out, size_t cap,
    ngx_log_t *log)
{
    int     fd;
    ssize_t n;
    size_t  i;

    if (cap == 0) {
        return NGX_ERROR;
    }
    out[0] = '\0';

    if (cred == NULL) {
        return NGX_OK;                  /* anonymous */
    }
    if (cred->token.len > 0) {
        ngx_cpystrn((u_char *) out, cred->token.data,
                    ngx_min(cred->token.len + 1, cap));
        return NGX_OK;
    }
    if (cred->token_file.len == 0) {
        return NGX_OK;                  /* no bearer configured */
    }

    /* Read the bearer from token_file (a trusted config path, not export data:
     * O_NOFOLLOW so a planted symlink cannot redirect it). First line only. */
    fd = open((const char *) cred->token_file.data,    /* vfs-seam-allow: config-domain bearer token file (not export storage) */
              O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "xrootd_credential: cannot open token_file \"%V\"",
            &cred->token_file);
        return NGX_ERROR;
    }
    n = read(fd, out, cap - 1);
    close(fd);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "xrootd_credential: cannot read token_file \"%V\"",
            &cred->token_file);
        out[0] = '\0';
        return NGX_ERROR;
    }
    out[n] = '\0';
    for (i = 0; i < (size_t) n; i++) {     /* trim at the first CR/LF/space */
        if (out[i] == '\r' || out[i] == '\n' || out[i] == ' '
            || out[i] == '\t')
        {
            out[i] = '\0';
            break;
        }
    }
    return NGX_OK;
}
