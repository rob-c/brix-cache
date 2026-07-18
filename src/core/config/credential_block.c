/*
 * credential_block.c — the `brix_credential <name> { … }` block (phase-63 §14).
 * See credential_block.h for the WHAT/WHY/HOW.
 */
#include "credential_block.h"
#include "core/compat/cstr.h"
#include "fs/vfs/vfs_backend_registry.h"   /* brix_vfs_backend_cred_t */
#include "fs/backend/sd.h"                 /* enum brix_cred_mode (mode directive) */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* Credentials are few (one per upstream identity); a small fixed, process-wide
 * table avoids allocation and is scanned linearly by name. Interned strings live
 * on cf->pool (stable for the process lifetime). */
#define BRIX_CREDENTIAL_MAX 32
static brix_credential_t  brix_credentials[BRIX_CREDENTIAL_MAX];
static ngx_uint_t           brix_credential_count;

const brix_credential_t *
brix_credential_lookup(const char *name)
{
    ngx_uint_t i;

    if (name == NULL || name[0] == '\0') {
        return NULL;
    }
    for (i = 0; i < brix_credential_count; i++) {
        if (brix_credentials[i].name.len == ngx_strlen(name)
            && ngx_strncmp(brix_credentials[i].name.data, name,
                           brix_credentials[i].name.len) == 0)
        {
            return &brix_credentials[i];
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
} brix_credential_field_t;

#define CRED_STR(k, f)  { k, offsetof(brix_credential_t, f), (size_t) -1 }
#define CRED_FLAG(k, f) { k, (size_t) -1, offsetof(brix_credential_t, f) }

static const brix_credential_field_t  brix_credential_fields[] = {
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

/* Map a `mode` token to its brix_cred_mode value, or -1 when unrecognised. The
 * tokens name the delegation strategy the consuming subsystem uses to present
 * this identity to the upstream (sd.h §"How the per-open credential was
 * obtained"): "passthrough" replays the user's own credential unmodified (a full
 * X.509 proxy is a passthrough credential), "exchange" trades it for a backend-
 * audienced one, "delegate"/"mint" obtain a fresh proxy, "select" forces the
 * directory-based service credential, "auto" dispatches by the identity's auth
 * method. */
static ngx_int_t
brix_credential_mode_token(const ngx_str_t *tok)
{
    static const struct { const char *k; enum brix_cred_mode v; } modes[] = {
        { "select",      BRIX_CRED_SELECT },
        { "passthrough", BRIX_CRED_PASSTHROUGH },
        { "exchange",    BRIX_CRED_EXCHANGE },
        { "delegate",    BRIX_CRED_DELEGATE },
        { "mint",        BRIX_CRED_MINT },
        { "auto",        BRIX_CRED_AUTO },
    };
    ngx_uint_t i;

    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        if (tok->len == ngx_strlen(modes[i].k)
            && ngx_strncmp(tok->data, modes[i].k, tok->len) == 0)
        {
            return (ngx_int_t) modes[i].v;
        }
    }
    return -1;
}

static char *
brix_credential_line(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    brix_credential_t             *cred = conf;
    ngx_str_t                       *value = cf->args->elts;
    const brix_credential_field_t *fld;

    /* `mode` is not a str/flag field — it parses a fixed token set into an enum. */
    if (value[0].len == 4 && ngx_strncmp(value[0].data, "mode", 4) == 0) {
        ngx_int_t m;

        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_credential: \"mode\" takes exactly one argument");
            return NGX_CONF_ERROR;
        }
        m = brix_credential_mode_token(&value[1]);
        if (m < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_credential: unknown mode \"%V\" (want select|passthrough|"
                "exchange|delegate|mint|auto)", &value[1]);
            return NGX_CONF_ERROR;
        }
        cred->mode = m;
        return NGX_CONF_OK;
    }

    for (fld = brix_credential_fields; fld->key != NULL; fld++) {
        if (value[0].len != ngx_strlen(fld->key)
            || ngx_strncmp(value[0].data, fld->key, value[0].len) != 0)
        {
            continue;
        }

        if (cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_credential: \"%V\" takes exactly one argument",
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
                    "brix_credential: \"%V\" expects on|off", &value[0]);
                return NGX_CONF_ERROR;
            }
            return NGX_CONF_OK;
        }

        {
            ngx_str_t *dst = (ngx_str_t *) ((char *) cred + fld->str_off);

            dst->data = (u_char *) brix_pstrdup_z(cf->pool, &value[1]);
            if (dst->data == NULL) {
                return NGX_CONF_ERROR;
            }
            dst->len = value[1].len;
        }
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "brix_credential: unknown directive \"%V\"", &value[0]);
    return NGX_CONF_ERROR;
}

char *
brix_conf_credential_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t           *value = cf->args->elts;
    brix_credential_t *cred;
    ngx_conf_t           save;
    char                *rv;
    ngx_flag_t           dup_in_this_config = 0;

    /* Dedup by name (last write wins), so a reload re-parsing the whole conf
     * updates the credential in place rather than appending or erroring.
     *
     * A name defined AGAIN within the SAME config parse (same cf->cycle) is a
     * genuine duplicate, NOT a reload update: the second block silently zeroes
     * and overrides the first, so any field the first set (e.g. x509_proxy) is
     * lost if the second omits it.  brix_credential is a single GLOBAL,
     * name-keyed registry — a block in stream{} and another in http{}/conf.d
     * with the same name collapse to ONE entry.  This exact shape (stream block
     * with x509_proxy, http/conf.d block with x509_cert+x509_key) silently broke
     * remote-origin GSI auth for hours; warn loudly so it never recurs.  A
     * reload re-parse has a different cf->cycle, so it does NOT warn. */
    {
        char                       name_z[256];
        const brix_credential_t *existing;

        ngx_cpystrn((u_char *) name_z, value[1].data,
                    ngx_min(value[1].len + 1, sizeof(name_z)));
        existing = brix_credential_lookup(name_z);
        if (existing != NULL) {
            cred = (brix_credential_t *) existing;
            dup_in_this_config = (existing->last_def_cycle == (void *) cf->cycle);
        } else if (brix_credential_count >= BRIX_CREDENTIAL_MAX) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_credential: too many credential blocks (max %d)",
                BRIX_CREDENTIAL_MAX);
            return NGX_CONF_ERROR;
        } else {
            cred = &brix_credentials[brix_credential_count++];
        }
    }

    if (dup_in_this_config) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix_credential \"%V\" is defined more than once in this "
            "configuration. brix_credential is a single global name-keyed "
            "registry (shared across stream{} and http{}), so the LAST "
            "definition silently overrides the earlier one(s) — fields the "
            "earlier block set are LOST if this block omits them. Make every "
            "\"brix_credential %V { ... }\" block IDENTICAL, or give them "
            "distinct names.", &value[1], &value[1]);
    }

    ngx_memzero(cred, sizeof(*cred));
    cred->mode = NGX_CONF_UNSET;   /* distinguish "unset" from an explicit select */
    cred->name.data = (u_char *) brix_pstrdup_z(cf->pool, &value[1]);
    if (cred->name.data == NULL) {
        return NGX_CONF_ERROR;
    }
    cred->name.len = value[1].len;
    cred->last_def_cycle = (void *) cf->cycle;   /* stamp this parse's cycle */

    save = *cf;
    cf->handler = brix_credential_line;
    cf->handler_conf = (char *) cred;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;
    return rv;
}

/* ---- NUL-terminated view of a credential field, or NULL when unset ----
 *
 * WHAT: Returns s->data as a C string when the field is set, NULL otherwise.
 *
 * WHY: The backend-cred struct wants "unset" as NULL (the registry setter
 * treats NULL as clear-to-empty); credential fields are interned with a
 * trailing NUL (brix_pstrdup_z), so the cast is safe.
 *
 * HOW: 1. len > 0 ⇒ the interned, NUL-terminated data pointer; else NULL.
 */
static const char *
brix_credential_str_or_null(const ngx_str_t *s)
{
    return (s->len > 0) ? (const char *) s->data : NULL;
}

/* ---- THE credential_t → backend_cred_t mapper (P80.1) ----
 *
 * WHAT: Maps every consumable field of a brix_credential into a
 * brix_vfs_backend_cred_t for brix_vfs_backend_set_credential. Returns NGX_OK,
 * or NGX_ERROR when the credential's token_file is set but unreadable.
 *
 * WHY: Four call sites (WebDAV parse, stream parse, S3-front parse, stream
 * worker replay) each hand-copied this mapping and drifted: the worker replay
 * dropped bearer + all three s3 fields, and because the registry setter
 * unconditionally overwrites all 8 slots, the parse-time S3 keys were wiped to
 * "" on every worker spawn (phase-80 finding 1.1). One mapper makes that drift
 * class impossible.
 *
 * HOW:
 *   1. Zero *out; NULL cred ⇒ anonymous, done.
 *   2. Derive the bearer (inline token or token_file) into the caller's
 *      bearer_buf; error out if a configured token_file is unreadable.
 *   3. x509: prefer the proxy PEM (key bundled inside); else cert + key.
 *   4. Straight str-or-NULL for ca_dir, the three s3 fields, and sss_keytab.
 */
ngx_int_t
brix_credential_to_backend_cred(const brix_credential_t *cred,
    char *bearer_buf, size_t bearer_cap,
    struct brix_vfs_backend_cred_s *out, ngx_log_t *log)
{
    ngx_memzero(out, sizeof(*out));

    if (cred == NULL) {
        return NGX_OK;                  /* anonymous */
    }
    if (brix_credential_bearer(cred, bearer_buf, bearer_cap, log) != NGX_OK) {
        return NGX_ERROR;
    }
    out->bearer = (bearer_buf[0] != '\0') ? bearer_buf : NULL;

    if (cred->x509_proxy.len > 0) {
        out->x509_proxy = (const char *) cred->x509_proxy.data;
    } else {
        out->x509_proxy = brix_credential_str_or_null(&cred->x509_cert);
        out->x509_key   = brix_credential_str_or_null(&cred->x509_key);
    }
    out->ca_dir        = brix_credential_str_or_null(&cred->ca_dir);
    out->s3_access_key = brix_credential_str_or_null(&cred->s3_access_key);
    out->s3_secret_key = brix_credential_str_or_null(&cred->s3_secret_key);
    out->s3_region     = brix_credential_str_or_null(&cred->s3_region);
    out->sss_keytab    = brix_credential_str_or_null(&cred->sss_keytab);
    return NGX_OK;
}

ngx_int_t
brix_credential_bearer(const brix_credential_t *cred, char *out, size_t cap,
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
            "brix_credential: cannot open token_file \"%V\"",
            &cred->token_file);
        return NGX_ERROR;
    }
    n = read(fd, out, cap - 1);
    close(fd);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
            "brix_credential: cannot read token_file \"%V\"",
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
