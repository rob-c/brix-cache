/*
 * sec_token.c — WLCG bearer token (ztn) auth module.
 *
 * WHAT: Discover a JWT from the environment and send it as the kXR_auth payload.
 * WHY:  Token auth is the simplest XRootD credential — a single round, no crypto
 *       (TLS provides confidentiality where required).
 * HOW:  Discovery order: $BEARER_TOKEN, $BEARER_TOKEN_FILE,
 *       $XDG_RUNTIME_DIR/bt_u<uid>, /tmp/bt_u<uid>. Payload = "ztn\0" + JWT
 *       (the server skips the 4-byte tag and strips trailing whitespace/NULs).
 *
 * wire: XProtocol.hh kXR_auth — credtype "ztn", payload repeats "ztn\0" then JWT.
 */
#include "sec.h"
#include "auth/cred/cred.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
rstrip(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'
                     || s[n - 1] == ' ' || s[n - 1] == '\t')) {
        s[--n] = '\0';
    }
}

static char *
slurp(const char *path)
{
    FILE  *fp;
    char  *buf;
    long   sz;
    size_t got;
    int    fd;

    /* Discovery probe (st=NULL): a missing OR unsafe file is silently skipped so
     * the caller falls through to the next location. O_NOFOLLOW + owner check
     * stop an attacker pre-planting /tmp/bt_u<uid> as a symlink (secret leak) or
     * a regular file they own (confused-deputy auth). */
    fd = brix_open_credfile(path, 0, NULL);
    if (fd < 0) {
        return NULL;
    }
    fp = fdopen(fd, "rb");
    if (fp == NULL) {
        close(fd);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0 || (sz = ftell(fp)) < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    if (sz > (1 << 20)) {          /* a JWT is never a megabyte */
        fclose(fp);
        return NULL;
    }
    buf = (char *) malloc((size_t) sz + 1);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }
    got = fread(buf, 1, (size_t) sz, fp);
    fclose(fp);
    buf[got] = '\0';
    rstrip(buf);
    if (buf[0] == '\0') {
        free(buf);
        return NULL;
    }
    return buf;
}

/* Return a malloc'd token string, or NULL if none found. Shared with credinfo.c
 * (the explain/diagnostics path) so token discovery lives in one place. */
char *
brix_token_discover(void)
{
    const char *env;
    char        path[256];
    uid_t       uid = geteuid();

    env = getenv("BEARER_TOKEN");
    if (env != NULL && env[0] != '\0') {
        char *t = strdup(env);
        if (t != NULL) {
            rstrip(t);
        }
        return t;
    }

    env = getenv("BEARER_TOKEN_FILE");
    if (env != NULL && env[0] != '\0') {
        return slurp(env);
    }

    env = getenv("XDG_RUNTIME_DIR");
    if (env != NULL && env[0] != '\0') {
        char *t;
        snprintf(path, sizeof(path), "%s/bt_u%u", env, (unsigned) uid);
        t = slurp(path);
        if (t != NULL) {
            return t;
        }
    }

    snprintf(path, sizeof(path), "/tmp/bt_u%u", (unsigned) uid);
    return slurp(path);
}

static int
token_have(brix_conn *c)
{
    /* Store is a fast "yes"; a store miss falls through to env discovery so a
     * tool whose store lacks the bearer handler still finds a $BEARER_TOKEN. */
    if (c != NULL && c->opts.cred != NULL
        && brix_cred_available(c->opts.cred, XRDC_CRED_BEARER)) {
        return 1;
    }
    char *t = brix_token_discover();
    if (t == NULL) {
        return 0;
    }
    free(t);
    return 1;
}

static int
token_first(brix_conn *c, const char *parms, uint8_t **payload, uint32_t *plen,
            brix_status *st)
{
    char    *tok = NULL;
    size_t   tl;
    uint8_t *p;

    (void) parms;

    /* Try the credential store when present; fall back to env discovery on
     * failure so env-sourced tokens behave identically to today. */
    if (c != NULL && c->opts.cred != NULL) {
        brix_cred_view v;
        if (brix_cred_acquire(c->opts.cred, XRDC_CRED_BEARER, 0, &v, st) == 0
            && v.token != NULL) {
            tok = strdup(v.token);
        } else {
            brix_status_clear(st);
        }
    }
    if (tok == NULL) {
        tok = brix_token_discover();
    }
    if (tok == NULL) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "no bearer token (set BEARER_TOKEN or BEARER_TOKEN_FILE)");
        return -1;
    }
    tl = strlen(tok);
    p = (uint8_t *) malloc(4 + tl);
    if (p == NULL) {
        free(tok);
        brix_status_set(st, XRDC_EAUTH, 0, "out of memory");
        return -1;
    }
    memcpy(p, "ztn\0", 4);
    memcpy(p + 4, tok, tl);
    free(tok);

    *payload = p;
    *plen = (uint32_t) (4 + tl);
    return 0;
}

const brix_sec_module *
brix_sec_token(void)
{
    static const brix_sec_module m = {
        "ztn",
        { 'z', 't', 'n', 0 },
        token_have,
        token_first,
        NULL,   /* single round */
        NULL,
    };
    return &m;
}
