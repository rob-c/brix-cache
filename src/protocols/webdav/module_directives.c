/*
 * module_directives.c - extracted concern
 * Phase-38 split of module.c; behavior-identical.
 */
#include "webdav_module_internal.h"
#include "fs/path/path.h"        /* brix_parse_authdb, brix_normalize_policy_path, rule types */
#include "core/config/config.h"  /* brix_copy_conf_string */

#include <openssl/pem.h>         /* PEM_read_bio_X509 (client-cert-folder resolve) */
#include <openssl/x509.h>

/*
 * brix_webdav_authdb <file> — parse a native u/g/p authorization-rule file into
 * conf->authdb_rules. Enforced for READ methods in the access phase (webdav_access),
 * giving WebDAV per-DN/per-VO/per-host read authorization at parity with root://.
 * Reuses the stream authdb parser; the same file format works for both protocols.
 */
char *
webdav_conf_authdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf = conf;
    ngx_str_t                         *value;

    (void) cmd;
    value = cf->args->elts;   /* value[1] = authdb file path */

    if (wlcf->authdb_rules == NGX_CONF_UNSET_PTR || wlcf->authdb_rules == NULL) {
        wlcf->authdb_rules = ngx_array_create(cf->pool, 4,
                                              sizeof(brix_authdb_rule_t));
        if (wlcf->authdb_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (brix_parse_authdb(cf, &value[1], wlcf->authdb_rules) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * brix_webdav_require_vo <path> <vo> — append a VO ACL rule (mirrors the stream
 * brix_require_vo). The rule path is normalized here; the realpath is finalized at
 * startup (brix_finalize_vo_rules, from merge_loc_conf).
 */
char *
webdav_conf_require_vo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf = conf;
    ngx_str_t                         *value;
    brix_vo_rule_t                   *rule;

    (void) cmd;
    value = cf->args->elts;   /* value[1] = path, value[2] = vo */

    if (wlcf->vo_rules == NGX_CONF_UNSET_PTR || wlcf->vo_rules == NULL) {
        wlcf->vo_rules = ngx_array_create(cf->pool, 2, sizeof(brix_vo_rule_t));
        if (wlcf->vo_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(wlcf->vo_rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(rule, sizeof(*rule));

    if (brix_normalize_policy_path(cf->pool, &value[1], &rule->path) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_webdav_require_vo: invalid path \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (brix_copy_conf_string(cf, &value[2], &rule->vo) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char *
webdav_conf_add_cors_origin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf = conf;
    ngx_str_t                         *value;
    ngx_str_t                         *origin;

    (void) cmd;

    if (wlcf->cors_origins == NULL) {
        wlcf->cors_origins = ngx_array_create(cf->pool, 2,
                                              sizeof(ngx_str_t));
        if (wlcf->cors_origins == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    origin = ngx_array_push(wlcf->cors_origins);
    if (origin == NULL) {
        return NGX_CONF_ERROR;
    }

    *origin = value[1];

    return NGX_CONF_OK;
}


/*
 * brix_webdav_dig_export <name> <dir> — register a named read-only diagnostic
 * export (§3). The dir is realpath'd at config time into the export's `canon` (the
 * RESOLVE_BENEATH anchor); a non-existent dir is a config error so misconfiguration
 * is caught at startup, not at request time.
 */
char *
webdav_conf_dig_export(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf = conf;
    ngx_str_t                         *value;
    brix_dig_export_t               *ex;
    char                               rp[PATH_MAX];

    (void) cmd;

    if (wlcf->dig_exports == NGX_CONF_UNSET_PTR || wlcf->dig_exports == NULL) {
        wlcf->dig_exports = ngx_array_create(cf->pool, 2,
                                             sizeof(brix_dig_export_t));
        if (wlcf->dig_exports == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;   /* value[1]=name value[2]=dir */

    if (realpath((const char *) value[2].data, rp) == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix_webdav_dig_export: cannot resolve \"%V\"",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

    ex = ngx_array_push(wlcf->dig_exports);
    if (ex == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(ex, sizeof(*ex));
    ex->name = value[1];
    ex->dir  = value[2];
    ex->canon.len  = ngx_strlen(rp);
    ex->canon.data = ngx_pnalloc(cf->pool, ex->canon.len + 1);
    if (ex->canon.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(ex->canon.data, rp, ex->canon.len + 1);

    return NGX_CONF_OK;
}


/*
 * Parse one "brix_webdav_open_file_cache" parameter token. Recognised tokens:
 *   max=N       -> *max     (must be > 0)
 *   inactive=T  -> *inactive (nginx time spec)
 *   off         -> *off = 1
 * Returns NGX_OK if the token was recognised and valid, NGX_ERROR for an unknown
 * token or an out-of-range value; the caller logs the offending token on error.
 */
ngx_int_t
webdav_open_file_cache_arg(ngx_str_t *arg, ngx_int_t *max, time_t *inactive,
    ngx_flag_t *off)
{
    ngx_str_t  s;

    if (ngx_strncmp(arg->data, "max=", 4) == 0) {
        *max = ngx_atoi(arg->data + 4, arg->len - 4);
        return (*max <= 0) ? NGX_ERROR : NGX_OK;
    }

    if (ngx_strncmp(arg->data, "inactive=", 9) == 0) {
        s.len  = arg->len - 9;
        s.data = arg->data + 9;
        *inactive = ngx_parse_time(&s, 1);
        return (*inactive == (time_t) NGX_ERROR) ? NGX_ERROR : NGX_OK;
    }

    if (ngx_strcmp(arg->data, "off") == 0) {
        *off = 1;
        return NGX_OK;
    }

    return NGX_ERROR;   /* unknown token */
}


char *
webdav_conf_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf = conf;

    time_t       inactive;
    ngx_str_t   *value;
    ngx_int_t    max;
    ngx_uint_t   i;
    ngx_flag_t   off;

    if (wlcf->open_file_cache != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 60;
    off = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        if (webdav_open_file_cache_arg(&value[i], &max, &inactive, &off)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid \"brix_webdav_open_file_cache\" "
                               "parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    /* "off" disables the cache outright. */
    if (off) {
        wlcf->open_file_cache = NULL;
    }

    if (wlcf->open_file_cache == NULL) {
        return NGX_CONF_OK;
    }

    if (max == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "\"brix_webdav_open_file_cache\" must have the \"max\" parameter");
        return NGX_CONF_ERROR;
    }

    wlcf->open_file_cache = ngx_open_file_cache_init(cf->pool, max, inactive);
    if (wlcf->open_file_cache) {
        return NGX_CONF_OK;
    }

    return NGX_CONF_ERROR;
}


/*
 * Load the FIRST PEM certificate from a file (leaf-first chain convention:
 * for a full-chain ssl_certificate the server's own cert comes first, so
 * this always yields the entity cert whose issuer we must trust).
 * Logs an EMERG and returns NULL on open/parse failure; caller owns the X509.
 */
static X509 *
webdav_conf_load_leaf_cert(ngx_conf_t *cf, ngx_str_t *path)
{
    BIO   *bio;
    X509  *cert;

    bio = BIO_new_file((const char *) path->data, "r");
    if (bio == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix_client_certificate_folder: cannot open "
                           "ssl_certificate \"%V\"", path);
        return NULL;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (cert == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_client_certificate_folder: no PEM certificate "
                           "found in ssl_certificate \"%V\"", path);
    }

    return cert;
}


/*
 * Probe <folder>/<issuer_subject_hash>.0 … .9 (the OpenSSL hashed-directory
 * layout the IGTF distribution installs) for a certificate whose SUBJECT
 * equals `issuer` — hash collisions make the suffix scan and the name
 * comparison both necessary. On a match *found receives a pool-allocated,
 * NUL-terminated path and NGX_OK is returned; NGX_DECLINED means no file in
 * the folder matched (the caller reports it — the directive is the trust
 * perimeter, so a miss is fatal); NGX_ERROR is an allocation failure.
 */
static ngx_int_t
webdav_conf_probe_issuer_file(ngx_conf_t *cf, ngx_str_t *folder,
                              X509_NAME *issuer, ngx_str_t *found)
{
    u_char         *buf, *p;
    BIO            *bio;
    X509           *cand;
    size_t          buflen;
    ngx_int_t       match;
    ngx_uint_t      i;
    unsigned long   hash;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    hash = X509_NAME_hash_ex(issuer, NULL, NULL, NULL);
#else
    hash = X509_NAME_hash(issuer);
#endif

    buflen = folder->len + sizeof("/xxxxxxxx.9");
    buf = ngx_pnalloc(cf->pool, buflen);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < 10; i++) {
        p = ngx_snprintf(buf, buflen - 1, "%V/%08xl.%ui", folder, hash, i);
        *p = '\0';

        bio = BIO_new_file((const char *) buf, "r");
        if (bio == NULL) {
            continue;   /* suffix not present — normal */
        }

        cand = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (cand == NULL) {
            continue;   /* not a PEM cert — skip, keep scanning suffixes */
        }

        match = (X509_NAME_cmp(X509_get_subject_name(cand), issuer) == 0);
        X509_free(cand);

        if (match) {
            found->data = buf;
            found->len = p - buf;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


/*
 * brix_client_certificate_folder <dir> — auto-pick ssl_client_certificate.
 *
 * WHAT: resolves, at config-parse time, the CA file in an OpenSSL hashed
 * directory (/etc/grid-security/certificates layout) whose subject equals
 * the ISSUER of this server's own ssl_certificate leaf, and assigns it as
 * the stock ssl_client_certificate value.
 *
 * WHY: grid hosts ship only the hashed IGTF dir — no bundle file exists —
 * yet nginx's `ssl_verify_client on` hard-requires a non-empty
 * ssl_client_certificate, checked in the core ssl module's merge (BEFORE
 * postconfiguration). Resolving here, in the directive handler, and handing
 * the result to the stock machinery keeps every core semantic (trust load,
 * advertised-CA list, the verify-on check) untouched.
 *
 * HOW: needs the server's own cert to hash its issuer, so it must appear
 * AFTER ssl_certificate in the same server{} — enforced with a directed
 * error. Explicit ssl_client_certificate coexistence is a config error
 * (one source of truth). An unresolvable folder or a missing issuer file
 * is FATAL: this feeds the client-verify trust store.
 */
char *
webdav_conf_client_cert_folder(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t  *sslcf;
    ngx_str_t                *value, folder, certpath, found;
    ngx_file_info_t           fi;
    X509                     *leaf;
    X509_NAME                *issuer;
    ngx_int_t                 rc;
    char                      dn[512];

    (void) cmd;
    (void) conf;

    value = cf->args->elts;   /* value[1] = hashed CA directory */

    folder = value[1];
    if (ngx_conf_full_name(cf->cycle, &folder, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_file_info(folder.data, &fi) != 0 || !ngx_is_dir(&fi)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix_client_certificate_folder \"%V\" is not an "
                           "accessible directory", &folder);
        return NGX_CONF_ERROR;
    }

    sslcf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

    if (sslcf == NULL
        || sslcf->certificates == NGX_CONF_UNSET_PTR
        || sslcf->certificates == NULL
        || sslcf->certificates->nelts == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_client_certificate_folder needs the server's "
                           "own certificate to resolve its issuer: place it "
                           "AFTER ssl_certificate in the same server block");
        return NGX_CONF_ERROR;
    }

    if (sslcf->client_certificate.len != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_client_certificate_folder conflicts with an "
                           "ssl_client_certificate already set for this "
                           "server (or is itself a duplicate) — configure "
                           "exactly one of the two");
        return NGX_CONF_ERROR;
    }

    certpath = ((ngx_str_t *) sslcf->certificates->elts)[0];

    if (ngx_strlchr(certpath.data, certpath.data + certpath.len, '$') != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_client_certificate_folder cannot resolve a "
                           "variable ssl_certificate \"%V\" at config time",
                           &certpath);
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_full_name(cf->cycle, &certpath, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    leaf = webdav_conf_load_leaf_cert(cf, &certpath);
    if (leaf == NULL) {
        return NGX_CONF_ERROR;
    }

    issuer = X509_get_issuer_name(leaf);

    rc = webdav_conf_probe_issuer_file(cf, &folder, issuer, &found);

    if (rc == NGX_DECLINED) {
        X509_NAME_oneline(issuer, dn, sizeof(dn));
        X509_free(leaf);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_client_certificate_folder: no <hash>.N file "
                           "in \"%V\" matches the issuer of \"%V\" (%s)",
                           &folder, &certpath, dn);
        return NGX_CONF_ERROR;
    }

    X509_free(leaf);

    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    sslcf->client_certificate = found;

    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                       "brix_client_certificate_folder: using \"%V\" as "
                       "ssl_client_certificate", &found);

    return NGX_CONF_OK;
}


/* The stock proxy module — its command table is the injection point for
 * brix_proxy_ssl_capath (see below); the module object itself is a global
 * symbol even though its loc-conf struct is private. */
extern ngx_module_t  ngx_http_proxy_module;


/*
 * Pick one CA certificate file (<8-hex-hash>.<digits> — the OpenSSL hashed
 * layout; CRLs are <hash>.r<N> and never match) out of `folder`, returning
 * the lexicographically smallest match as a pool-allocated, NUL-terminated
 * full path in *picked.  NGX_DECLINED = no CA file in the folder,
 * NGX_ERROR = unreadable folder or allocation failure (logged).
 */
static ngx_int_t
webdav_conf_pick_ca_file(ngx_conf_t *cf, ngx_str_t *folder, ngx_str_t *picked)
{
    ngx_dir_t   dir;
    ngx_str_t   best;
    u_char     *name, *p;
    size_t      len, i;

    if (ngx_open_dir(folder, &dir) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix_proxy_ssl_capath: cannot open \"%V\"", folder);
        return NGX_ERROR;
    }

    ngx_str_null(&best);

    for ( ;; ) {
        ngx_set_errno(0);
        if (ngx_read_dir(&dir) != NGX_OK) {
            break;
        }

        name = ngx_de_name(&dir);
        len = ngx_de_namelen(&dir);

        if (len < sizeof("00000000.0") - 1 || name[8] != '.') {
            continue;
        }
        for (i = 0; i < 8; i++) {
            if (!((name[i] >= '0' && name[i] <= '9')
                  || (name[i] >= 'a' && name[i] <= 'f')))
            {
                break;
            }
        }
        if (i < 8) {
            continue;
        }
        for (i = 9; i < len; i++) {
            if (name[i] < '0' || name[i] > '9') {
                break;
            }
        }
        if (i < len) {
            continue;                     /* .r0 CRLs, .signing_policy, ... */
        }

        if (best.data == NULL
            || ngx_memn2cmp(name, best.data, len, best.len) < 0)
        {
            best.data = ngx_pnalloc(cf->pool, len);
            if (best.data == NULL) {
                ngx_close_dir(&dir);
                return NGX_ERROR;
            }
            ngx_memcpy(best.data, name, len);
            best.len = len;
        }
    }

    ngx_close_dir(&dir);

    if (best.data == NULL) {
        return NGX_DECLINED;
    }

    picked->len = folder->len + 1 + best.len;
    picked->data = ngx_pnalloc(cf->pool, picked->len + 1);
    if (picked->data == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(picked->data, folder->data, folder->len);
    *p++ = '/';
    p = ngx_cpymem(p, best.data, best.len);
    *p = '\0';

    return NGX_OK;
}


/*
 * brix_proxy_ssl_capath <dir> — hashed CA directory for the proxy back leg.
 *
 * WHAT: makes proxy_ssl_verify consume an OpenSSL hashed CA directory
 * (/etc/grid-security/certificates) instead of the file-only
 * proxy_ssl_trusted_certificate.
 *
 * WHY: stock nginx demands a non-empty proxy_ssl_trusted_certificate when
 * proxy_ssl_verify is on (checked in the proxy module's merge, before
 * postconfiguration) and cannot load a directory — the same gap
 * brix_ssl_client_capath closes on the front leg.
 *
 * HOW: two halves.  Here, at parse time: validate the folder, remember it in
 * wlcf->proxy_ssl_capath (location-exact, never merged), and satisfy the
 * mandatory-file check by injecting one CA file from the folder through the
 * proxy module's OWN proxy_ssl_trusted_certificate command entry — the
 * loc-conf struct is private, but the command's setter+offset are not, so
 * this reuses stock machinery with no struct-layout assumptions.  (Any file
 * from the folder is sound: the trust it adds is a subset of the folder's.)
 * The stock slot also makes an explicit proxy_ssl_trusted_certificate in the
 * same location an automatic "is duplicate" conflict.  At postconfiguration
 * (postconfig.c) the folder itself is added to the location's upstream
 * SSL_CTX as a hashed lookup.
 */
char *
webdav_conf_proxy_ssl_capath(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_webdav_loc_conf_t *wlcf = conf;
    ngx_str_t                         *value, folder, picked, args_buf[2];
    ngx_command_t                     *pcmd;
    ngx_array_t                        args, *saved;
    ngx_file_info_t                    fi;
    ngx_int_t                          rc;
    void                              *plcf;
    char                              *rv;

    (void) cmd;

    if (wlcf->proxy_ssl_capath.len > 0) {
        return "is duplicate";
    }

    value = cf->args->elts;   /* value[1] = hashed CA directory */

    folder = value[1];
    if (ngx_conf_full_name(cf->cycle, &folder, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_file_info(folder.data, &fi) != 0 || !ngx_is_dir(&fi)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix_proxy_ssl_capath \"%V\" is not an "
                           "accessible directory", &folder);
        return NGX_CONF_ERROR;
    }

    rc = webdav_conf_pick_ca_file(cf, &folder, &picked);
    if (rc == NGX_DECLINED) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_proxy_ssl_capath \"%V\" contains no "
                           "<hash>.N CA files", &folder);
        return NGX_CONF_ERROR;
    }
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (pcmd = ngx_http_proxy_module.commands;
         pcmd != NULL && pcmd->name.len != 0;
         pcmd++)
    {
        if (ngx_strcmp(pcmd->name.data, "proxy_ssl_trusted_certificate") == 0) {
            break;
        }
    }
    if (pcmd == NULL || pcmd->name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_proxy_ssl_capath requires the http proxy "
                           "module with SSL support");
        return NGX_CONF_ERROR;
    }

    plcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_module);

    args_buf[0] = pcmd->name;
    args_buf[1] = picked;
    args.elts = args_buf;
    args.nelts = 2;
    args.size = sizeof(ngx_str_t);
    args.nalloc = 2;
    args.pool = cf->pool;

    saved = cf->args;
    cf->args = &args;
    rv = pcmd->set(cf, pcmd, plcf);
    cf->args = saved;

    if (rv != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_proxy_ssl_capath conflicts with an explicit "
                           "proxy_ssl_trusted_certificate in the same "
                           "location (proxy_ssl_trusted_certificate %s) — "
                           "configure exactly one of the two", rv);
        return NGX_CONF_ERROR;
    }

    wlcf->proxy_ssl_capath = folder;

    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                       "brix_proxy_ssl_capath: trusted-certificate seed "
                       "\"%V\"; hashed dir added at postconfiguration",
                       &picked);

    return NGX_CONF_OK;
}
