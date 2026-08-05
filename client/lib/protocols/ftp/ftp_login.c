/*
 * ftp_login.c — GridFTP client login: RFC 2228 AUTH GSSAPI/ADAT, or anonymous.
 *
 * WHAT: negotiate the session credential immediately after the greeting, then
 *       settle the data-channel protection parameters the server expects.
 * WHY:  which credential a transfer runs under is a security decision, so it is
 *       made in one place with one rule: a gsiftp:// URL means GSI, and a GSI
 *       endpoint is never downgraded to anonymous because the proxy is missing or
 *       the handshake failed — the copy fails instead, loudly.
 * HOW:  AUTH GSSAPI (334) opens the token loop; each 335 reply carries the peer's
 *       ADAT token, which the initiator (ftp_gsi.c) consumes and answers until the
 *       server returns 235. From then on the control channel is protected and
 *       ftp_ctl.c wraps every command transparently.
 */
#include "ftp_client.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Extract the base64 argument of an "…ADAT=<token>…" reply text. */
static char *
adat_token(const char *text)
{
    const char *p = strstr(text, "ADAT=");
    const char *e;
    char       *tok;
    size_t      n;

    if (p == NULL) {
        return NULL;
    }
    p += 5;
    for (e = p; *e != '\0' && *e != ' ' && *e != '\r' && *e != '\n'; e++) {
        /* token runs to the first whitespace */
    }
    n = (size_t) (e - p);
    if (n == 0) {
        return NULL;
    }
    tok = malloc(n + 1);
    if (tok == NULL) {
        return NULL;
    }
    memcpy(tok, p, n);
    tok[n] = '\0';
    return tok;
}


/* Send one ADAT token (base64 of `tok`) and read the server's reply. */
static int
adat_send(brix_ftp_sess *s, const uint8_t *tok, size_t len, brix_status *st)
{
    char *b64 = brix_ftp_b64_encode(tok, len);
    int   rc;

    if (b64 == NULL) {
        brix_status_set(st, XRDC_EAUTH, 0, "gsiftp: cannot encode ADAT token");
        return -1;
    }
    rc = brix_ftp_cmd(s, st, "ADAT %s", b64);
    free(b64);
    return rc;
}


/* Decode the peer's ADAT token from the current reply (absent ⇒ empty token). */
static int
adat_recv(brix_ftp_sess *s, uint8_t **in, size_t *in_len, brix_status *st)
{
    char *b64;

    *in = NULL;
    *in_len = 0;
    b64 = adat_token(s->text);
    if (b64 == NULL) {
        return 0;
    }
    *in = brix_ftp_b64_decode(b64, in_len);
    free(b64);
    if (*in == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "gsiftp: server ADAT token is not base64");
        return -1;
    }
    return 0;
}


/*
 * Run the ADAT loop until the server reports completion (235). Bounded: a peer
 * that keeps answering 335 without converging must not spin the client forever.
 */
static int
gsi_token_loop(brix_ftp_sess *s, brix_status *st)
{
    uint8_t *out = NULL;
    size_t   out_len = 0;
    int      rounds;
    int      more;

    more = brix_ftp_gss_step(s->gss, NULL, 0, &out, &out_len, st);
    if (more < 0) {
        return -1;
    }
    for (rounds = 0; rounds < 16; rounds++) {
        int rc;

        if (out_len == 0) {
            free(out);
            brix_status_set(st, XRDC_EAUTH, 0,
                            "gsiftp: GSI handshake produced no token");
            return -1;
        }
        rc = adat_send(s, out, out_len, st);
        free(out);
        out = NULL;
        out_len = 0;
        if (rc != 0) {
            return -1;
        }
        if (s->code == 235) {
            s->secure = 1;
            return 0;
        }
        if (s->code != 335) {
            brix_status_set(st, XRDC_EAUTH, 0, "gsiftp: %d %s", s->code,
                            s->text);
            return -1;
        }
        {
            uint8_t *in = NULL;
            size_t   in_len = 0;

            if (adat_recv(s, &in, &in_len, st) != 0) {
                return -1;
            }
            more = brix_ftp_gss_step(s->gss, in, in_len, &out, &out_len, st);
            free(in);
        }
        if (more < 0) {
            return -1;
        }
    }
    brix_status_set(st, XRDC_EAUTH, 0,
                    "gsiftp: GSI handshake did not converge");
    return -1;
}


/*
 * The RFC 959 access sequence: USER, then PASS only if the server asked for one
 * (3xx). Anything but a final 2xx is a refusal, and `what` names which refusal it
 * was — an anonymous login that was not accepted, or a GSI identity the server
 * authenticated but would not authorize.
 */
static int
ftp_user_pass(brix_ftp_sess *s, const char *user, const char *pass,
              const char *what, brix_status *st)
{
    if (brix_ftp_cmd(s, st, "USER %s", user) != 0) {
        return -1;
    }
    if (s->code >= 300 && s->code < 400) {
        if (brix_ftp_cmd(s, st, "PASS %s", pass) != 0) {
            return -1;
        }
    }
    if (s->code < 200 || s->code > 299) {
        brix_status_set(st, XRDC_EAUTH, 0, "gsiftp: %s: %d %s", what, s->code,
                        s->text);
        return -1;
    }
    return 0;
}


/* USER/PASS as the anonymous user (plain ftp:// only). */
static int
anon_login(brix_ftp_sess *s, brix_status *st)
{
    return ftp_user_pass(s, "anonymous", "brix@", "login refused", st);
}


/* Announce the identity the GSI context established (the gateway logs it and
 * some servers require a USER after 235). A refusal here is fatal. */
static int
gsi_user(brix_ftp_sess *s, brix_status *st)
{
    return ftp_user_pass(s, ":globus-mapping:", "dummy",
                         "authenticated but not authorized", st);
}


static int
gsi_login(brix_ftp_sess *s, const brix_opts *co, brix_status *st)
{
    /* The proxy path comes from $X509_USER_PROXY (xrdcp's --proxy sets it), so
     * one discovery rule serves every scheme. */
    const char *ca_dir   = (co != NULL) ? co->ca_dir : NULL;
    int         insecure = (co != NULL) ? co->insecure_tls : 0;

    if (brix_ftp_cmd(s, st, "AUTH GSSAPI") != 0) {
        return -1;
    }
    if (s->code != 334) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "gsiftp: server refused GSI authentication: %d %s",
                        s->code, s->text);
        return -1;
    }
    s->gss = brix_ftp_gss_create(NULL, ca_dir, insecure, st);
    if (s->gss == NULL) {
        return -1;
    }
    if (gsi_token_loop(s, st) != 0) {
        return -1;
    }
    return gsi_user(s, st);
}


int
brix_ftp_login(brix_ftp_sess *s, const brix_ftpurl *u, const brix_opts *co,
               brix_status *st)
{
    if (!u->gsi) {
        return anon_login(s, st);
    }
    return gsi_login(s, co, st);
}
