/* reg_client.c — registry transport core: endpoint setup, auth material,
 * the WWW-Authenticate Bearer token dance, and the authed-request wrapper.
 * The verbs live in reg_verbs.c / reg_blob.c (see reg_client.h). */
#include "oci/reg_internal.h"

#include "oci/challenge.h"
#include "oci/name.h"
#include "core/compat/json_iter.h"
#include "core/compat/json_min.h"
#include "protocols/ftp/ftp_client.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
regc_fail(char *err, size_t errlen, int code, const char *fmt, ...)
{
    if (err != NULL && errlen > 0) {
        va_list ap;

        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return code;
}

static int
regc_status_code(int status)
{
    if (status == 401 || status == 403) {
        return BRIX_OCI_REG_EAUTH;
    }
    if (status == 404) {
        return BRIX_OCI_REG_ENOTFOUND;
    }
    return BRIX_OCI_REG_EPROTO;
}

int
regc_status_fail(int status, const char *what, char *err, size_t errlen)
{
    return regc_fail(err, errlen, regc_status_code(status),
                     "%s: registry returned HTTP %d", what, status);
}

int
regc_status_fail_resp(const brix_http_resp *resp, const char *what,
                      char *err, size_t errlen)
{
    const char *arr, *el;
    size_t      an, en, cur = 0;
    char        msg[256];

    /* Surface the registry's own words from the OCI error envelope
     * ({"errors":[{"code":…,"message":…}]}) when the body carries one. */
    if (resp->body != NULL && resp->body_len > 0 &&
        brix_json_get_raw(resp->body, resp->body_len, "errors", &arr,
                          &an) == 1 &&
        brix_json_arr_next(arr, an, &cur, &el, &en) == 1 &&
        brix_json_get_str(el, en, "message", msg, sizeof(msg)) == 1 &&
        msg[0] != '\0') {
        return regc_fail(err, errlen, regc_status_code(resp->status),
                         "%s: registry returned HTTP %d (%s)", what,
                         resp->status, msg);
    }
    return regc_status_fail(resp->status, what, err, errlen);
}

int
regc_eff_name(const brix_oci_reg_t *r, const char *name, char *out,
              size_t outlen)
{
    int n;

    /* DockerHub serves official images under library/ — the docker-CLI
     * normalization, applied at the transport so refs stay grammar-pure. */
    if (strcmp(r->host, "registry-1.docker.io") == 0 &&
        brix_oci_name_components(name, strlen(name)) == 1) {
        n = snprintf(out, outlen, "library/%s", name);
    } else {
        n = snprintf(out, outlen, "%s", name);
    }
    return (n < 0 || (size_t) n >= outlen) ? -1 : 0;
}

/* Copy a relative URL onto the request's existing origin. */
static int
regc_url_relative(const char *url, const char *def_host, int def_port,
                  int def_tls, char *host, size_t hostlen, int *port,
                  int *tls, char *path, size_t pathlen)
{
    if (snprintf(host, hostlen, "%s", def_host) >= (int) hostlen ||
        snprintf(path, pathlen, "%s", url) >= (int) pathlen) {
        return -1;
    }
    *port = def_port;
    *tls = def_tls;
    return 0;
}

/* Recognize the two explicitly supported registry URL schemes. */
static const char
*regc_url_scheme(const char *url, int *tls)
{
    if (strncmp(url, "https://", 8) == 0) {
        *tls = 1;
        return url + 8;
    }
    if (strncmp(url, "http://", 7) == 0) {
        *tls = 0;
        return url + 7;
    }
    return NULL;
}

/* Parse host[:port] authority with the scheme's default port. */
static int
regc_url_authority(const char *start, const char *slash, int tls,
                   char *host, size_t hostlen, int *port)
{
    const char *port_mark;
    size_t      len = slash != NULL ? (size_t) (slash - start) : strlen(start);
    size_t      host_len;

    port_mark = memchr(start, ':', len);
    host_len = port_mark != NULL ? (size_t) (port_mark - start) : len;
    if (host_len == 0 || host_len >= hostlen) {
        return -1;
    }
    memcpy(host, start, host_len);
    host[host_len] = '\0';
    *port = tls ? 443 : 80;
    if (port_mark != NULL) {
        char *end = NULL;
        long  value = strtol(port_mark + 1, &end, 10);

        if (end != start + len || value <= 0 || value > 65535) {
            return -1;
        }
        *port = (int) value;
    }
    return 0;
}

int
regc_url_split(const char *url, const char *def_host, int def_port,
               int def_tls, char *host, size_t hostlen, int *port, int *tls,
               char *path, size_t pathlen)
{
    const char *p;
    const char *slash;

    if (url[0] == '/') {
        return regc_url_relative(url, def_host, def_port, def_tls, host,
                                 hostlen, port, tls, path, pathlen);
    }
    p = regc_url_scheme(url, tls);
    if (p == NULL) {
        return -1;
    }
    slash = strchr(p, '/');
    if (regc_url_authority(p, slash, *tls, host, hostlen, port) != 0) {
        return -1;
    }
    if (snprintf(path, pathlen, "%s", slash != NULL ? slash : "/") >=
        (int) pathlen) {
        return -1;
    }
    return 0;
}

/* Percent-encode everything but RFC-3986 unreserved. 0 / -1 (short buf). */
static int
regc_urlenc(const char *s, char *out, size_t outlen)
{
    size_t o = 0;

    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char) *s;

        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
            c == '~') {
            if (o + 2 > outlen) {
                return -1;
            }
            out[o++] = (char) c;
        } else {
            if (o + 4 > outlen) {
                return -1;
            }
            snprintf(out + o, 4, "%%%02X", c);
            o += 3;
        }
    }
    out[o] = '\0';
    return 0;
}

static const char *
tok_find(brix_oci_reg_t *r, const char *scope)
{
    unsigned i;

    for (i = 0; i < 4; i++) {
        if (r->tok[i].live && strcmp(r->tok[i].scope, scope) == 0) {
            return r->tok[i].token;
        }
    }
    return NULL;
}

static void
tok_store(brix_oci_reg_t *r, const char *scope, const char *token)
{
    unsigned i, slot;

    for (i = 0; i < 4; i++) {
        if (r->tok[i].live && strcmp(r->tok[i].scope, scope) == 0) {
            break;
        }
    }
    slot = i < 4 ? i : r->tok_next++ % 4;
    snprintf(r->tok[slot].scope, sizeof(r->tok[slot].scope), "%s", scope);
    snprintf(r->tok[slot].token, sizeof(r->tok[slot].token), "%s", token);
    r->tok[slot].live = 1;
}

void
regc_auth_header(brix_oci_reg_t *r, const char *scope, char *out,
                 size_t outlen)
{
    const char *t = scope != NULL ? tok_find(r, scope) : NULL;

    if (t == NULL && r->bearer[0] != '\0') {
        t = r->bearer;
    }
    if (t != NULL) {
        snprintf(out, outlen, "Authorization: Bearer %s\r\n", t);
    } else {
        out[0] = '\0';
    }
}

/* The D1 allowlist, client mirror: the realm may be the registry itself or
 * its well-known auth endpoint — never an arbitrary third party (that would
 * let a compromised upstream aim our Basic credentials anywhere). */
static int
realm_host_ok(const brix_oci_reg_t *r, const char *realm_host)
{
    if (strcmp(realm_host, r->host) == 0) {
        return 1;
    }
    return strcmp(r->host, "registry-1.docker.io") == 0 &&
           strcmp(realm_host, "auth.docker.io") == 0;
}

/* Split and policy-check a Bearer realm before credentials can reach it. */
static int
regc_token_realm(brix_oci_reg_t *r, const brix_oci_challenge_t *c,
                 char *host, size_t hostlen, int *port, int *tls,
                 char *path, size_t pathlen, char *err, size_t errlen)
{
    if (regc_url_split(c->realm, r->host, r->port, !r->plain_http, host,
                       hostlen, port, tls, path, pathlen) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EAUTH,
                         "bad realm URL \"%s\"", c->realm);
    }
    if (!*tls && !r->plain_http) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EAUTH,
                         "refusing non-https token realm \"%s\"", c->realm);
    }
    if (!realm_host_ok(r, host)) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EAUTH,
                         "token realm host \"%s\" is neither the registry "
                         "nor its known auth endpoint — refusing", host);
    }
    return BRIX_OCI_REG_OK;
}

/* Add one pre-formatted query part and retain the appropriate separator. */
static int
regc_query_add(char *query, size_t qlen, int *used, char *sep,
               const char *key, const char *value)
{
    int n = snprintf(query + *used, qlen - (size_t) *used, "%c%s=%s", *sep,
                     key, value);

    if (n < 0 || (size_t) n >= qlen - (size_t) *used) {
        return -1;
    }
    *used += n;
    *sep = '&';
    return 0;
}

/* Build a token endpoint request path from the server's challenge fields. */
static int
regc_token_query(const brix_oci_challenge_t *c, const char *path,
                 char *query, size_t qlen, char *err, size_t errlen)
{
    char service[768];
    char sep = '?';
    int  used = snprintf(query, qlen, "%s", path);

    if (used < 0 || (size_t) used >= qlen) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EAUTH, "token URL too long");
    }
    if (strchr(path, '?') != NULL) {
        sep = '&';
    }
    if (c->service[0] != '\0') {
        if (regc_urlenc(c->service, service, sizeof(service)) != 0 ||
            regc_query_add(query, qlen, &used, &sep, "service", service) != 0) {
            return regc_fail(err, errlen, BRIX_OCI_REG_EAUTH,
                             "challenge service too long");
        }
    }
    if (c->scope[0] != '\0' &&
        regc_query_add(query, qlen, &used, &sep, "scope", c->scope) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EAUTH, "token URL too long");
    }
    return BRIX_OCI_REG_OK;
}

/* Basic credentials are formatted only for the pre-approved token realm. */
static int
regc_basic_header(const brix_oci_reg_t *r, char *basic, size_t basiclen,
                  char *err, size_t errlen)
{
    char  user_pass[400];
    char *b64;

    basic[0] = '\0';
    if (r->user[0] == '\0') {
        return BRIX_OCI_REG_OK;
    }
    snprintf(user_pass, sizeof(user_pass), "%s:%s", r->user, r->pass);
    b64 = brix_ftp_b64_encode((const uint8_t *) user_pass,
                              strlen(user_pass));
    if (b64 == NULL) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT, "out of memory");
    }
    snprintf(basic, basiclen, "Authorization: Basic %s\r\n", b64);
    free(b64);
    return BRIX_OCI_REG_OK;
}

/* Extract either registry-standard token spelling from a successful response. */
static int
regc_token_extract(const brix_http_resp *resp, char *token, size_t tokenlen,
                   char *err, size_t errlen)
{
    token[0] = '\0';
    if (resp->body != NULL &&
        (brix_json_get_str(resp->body, resp->body_len, "token", token,
                           tokenlen) ||
         brix_json_get_str(resp->body, resp->body_len, "access_token", token,
                           tokenlen)) && token[0] != '\0') {
        return BRIX_OCI_REG_OK;
    }
    return regc_fail(err, errlen, BRIX_OCI_REG_EAUTH,
                     "token endpoint returned no token");
}

int
regc_token_dance(brix_oci_reg_t *r, const char *challenge,
                 const char *cache_scope, char *err, size_t errlen)
{
    brix_oci_challenge_t c;
    brix_http_resp       resp;
    brix_status          st;
    char                 rhost[256], rpath[1024], q[2600];
    char                 basic[640], tok[4096];
    int                  rport, rtls, rc;

    if (brix_oci_challenge_parse(challenge, strlen(challenge), &c) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EAUTH,
                         "unparseable WWW-Authenticate challenge");
    }
    rc = regc_token_realm(r, &c, rhost, sizeof(rhost), &rport, &rtls, rpath,
                          sizeof(rpath), err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    rc = regc_token_query(&c, rpath, q, sizeof(q), err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    rc = regc_basic_header(r, basic, sizeof(basic), err, errlen);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }

    memset(&st, 0, sizeof(st));
    if (brix_http_req(rhost, rport, rtls, "GET", q,
                      basic[0] != '\0' ? basic : NULL, NULL, 0,
                      r->timeout_ms, r->verify, r->ca_dir, r->client_cert,
                      &resp, &st) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                         "token endpoint: %s", st.msg);
    }
    if (resp.status != 200) {
        rc = regc_fail(err, errlen, BRIX_OCI_REG_EAUTH,
                       "token endpoint returned HTTP %d", resp.status);
        brix_http_resp_free(&resp);
        return rc;
    }
    rc = regc_token_extract(&resp, tok, sizeof(tok), err, errlen);
    brix_http_resp_free(&resp);
    if (rc != BRIX_OCI_REG_OK) {
        return rc;
    }
    tok_store(r, cache_scope != NULL ? cache_scope : "", tok);
    return BRIX_OCI_REG_OK;
}

int
regc_call(brix_oci_reg_t *r, const char *method, const char *path,
          const char *scope, const char *extra_headers, const void *body,
          size_t blen, brix_http_resp *resp, char *err, size_t errlen)
{
    int attempt, rc;

    for (attempt = 0; attempt < 2; attempt++) {
        char        auth[4200], hdrs[8192], chal[2048];
        brix_status st;

        regc_auth_header(r, scope, auth, sizeof(auth));
        if (snprintf(hdrs, sizeof(hdrs), "%s%s",
                     extra_headers != NULL ? extra_headers : "", auth) >=
            (int) sizeof(hdrs)) {
            return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                             "request header block too long");
        }
        memset(&st, 0, sizeof(st));
        if (brix_http_req(r->host, r->port, !r->plain_http, method, path,
                          hdrs[0] != '\0' ? hdrs : NULL, body, blen,
                          r->timeout_ms, r->verify, r->ca_dir,
                          r->client_cert, resp, &st) != 0) {
            return regc_fail(err, errlen, BRIX_OCI_REG_ETRANSPORT,
                             "%s %s: %s", method, path, st.msg);
        }
        if (resp->status != 401 || attempt == 1) {
            return BRIX_OCI_REG_OK;
        }
        /* 401 → run the dance once (also refreshes a stale cached token),
         * then retry. A 401 with no challenge is the caller's to map. */
        if (!brix_http_header(resp, "WWW-Authenticate", chal,
                              sizeof(chal))) {
            return BRIX_OCI_REG_OK;
        }
        brix_http_resp_free(resp);
        rc = regc_token_dance(r, chal, scope, err, errlen);
        if (rc != BRIX_OCI_REG_OK) {
            return rc;
        }
    }
    return BRIX_OCI_REG_OK;
}

void
brix_oci_desc_free(brix_oci_desc_t *d)
{
    if (d == NULL) {
        return;
    }
    free(d->body);
    d->body = NULL;
    d->body_len = 0;
}

int
brix_oci_reg_from_ref(brix_oci_reg_t *r, const brix_oci_ref_t *ref,
                      int insecure, char *name, size_t namelen, char *err,
                      size_t errlen)
{
    memset(r, 0, sizeof(*r));
    if (ref->host[0] == '\0' || strcmp(ref->host, "docker.io") == 0) {
        snprintf(r->host, sizeof(r->host), "registry-1.docker.io");
    } else {
        snprintf(r->host, sizeof(r->host), "%s", ref->host);
    }
    r->plain_http = insecure ? 1 : 0;
    r->verify = insecure ? 0 : 1;
    r->port = ref->port != 0 ? ref->port : (r->plain_http ? 80 : 443);
    r->timeout_ms = 30000;
    if (regc_eff_name(r, ref->name, name, namelen) != 0) {
        return regc_fail(err, errlen, BRIX_OCI_REG_EPROTO,
                         "repository name too long");
    }
    return BRIX_OCI_REG_OK;
}
