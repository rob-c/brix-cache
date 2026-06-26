/*
 * auth.c — authentication driver.
 *
 * WHAT: After kXR_login returns a "&P=<proto>,..." security list, parse it, pick
 *       a protocol we have credentials for (preference: gsi > ztn > unix, honoring
 *       an explicit --auth override), and drive the kXR_auth/kXR_authmore loop via
 *       the selected sec module.
 * WHY:  Turns the server's auth demand into a completed session, protocol-agnostic.
 * HOW:  Each kXR_auth carries the module's credtype + payload; the server replies
 *       kXR_authmore (feed the body back to module.more) or kXR_ok (done). Rounds
 *       are capped to defend against a server that never finishes.
 */
#include "sec/sec.h"
#include "protocol/sec_protocol.h"   /* shared "&P=" security-list parser */

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define XRDC_AUTH_MAX_ROUNDS 8

static int
send_auth(xrdc_conn *c, const char credtype[4], const uint8_t *payload,
          uint32_t plen, uint16_t *sid, xrdc_status *st)
{
    ClientAuthRequest req;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_auth);
    memcpy(req.credtype, credtype, 4);
    return xrdc_send(c, &req, payload, plen, sid, st);
}

/* Run one protocol's kXR_auth/authmore exchange to completion. 0 / -1. */
static int
run_module(xrdc_conn *c, const xrdc_sec_module *m, const char *parms,
           xrdc_status *st)
{
    uint8_t *payload = NULL;
    uint32_t plen = 0;
    int      round;

    if (m->first(c, parms, &payload, &plen, st) != 0) {
        return -1;
    }

    for (round = 0; round < XRDC_AUTH_MAX_ROUNDS; round++) {
        uint16_t sid, status;
        uint8_t *body = NULL;
        uint32_t blen = 0;
        int      rc;

        rc = send_auth(c, m->credtype, payload, plen, &sid, st);
        free(payload);
        payload = NULL;
        plen = 0;
        if (rc != 0) {
            return -1;
        }
        if (xrdc_recv(c, sid, &status, &body, &blen, st) != 0) {
            return -1;   /* kXR_error → st already set */
        }
        if (status == kXR_ok) {
            free(body);
            if (m->cleanup != NULL) {
                m->cleanup(c);
            }
            return 0;
        }
        if (status == kXR_authmore) {
            if (m->more == NULL) {
                free(body);
                xrdc_status_set(st, XRDC_EAUTH, 0,
                                "%s: server asked for more rounds (unsupported)",
                                m->name);
                return -1;
            }
            rc = m->more(c, body, blen, &payload, &plen, st);
            free(body);
            if (rc != 0) {
                return -1;
            }
            if (payload == NULL) {
                xrdc_status_set(st, XRDC_EAUTH, 0,
                                "%s: auth ended without server ok", m->name);
                return -1;
            }
            continue;
        }
        free(body);
        xrdc_status_set(st, XRDC_EAUTH, 0, "%s: unexpected auth status %u",
                        m->name, status);
        return -1;
    }

    free(payload);
    xrdc_status_set(st, XRDC_EAUTH, 0, "%s: too many auth rounds", m->name);
    return -1;
}

int
xrdc_authenticate(xrdc_conn *c, const char *seclist, const xrdc_opts *o,
                  xrdc_status *st)
{
    const xrdc_sec_module *mods[7];
    int                    nmods = 0;
    int                    i;
    int                    tried = 0;

    /* force_anon: complete the login but present NO credential. Used by the
     * remote-doctor auth-suite to test the SERVER's own enforcement (does it
     * reject unauthenticated operations?) independent of the client's creds. */
    if (o != NULL && o->force_anon) {
        return 0;
    }

    /* Preference order: gsi > ztn > krb5 > sss > unix > host > pwd.
     * (NULL skipped; each is tried only if the server advertised it.) */
    if (xrdc_sec_gsi() != NULL) {
        mods[nmods++] = xrdc_sec_gsi();
    }
    mods[nmods++] = xrdc_sec_token();
    mods[nmods++] = xrdc_sec_krb5();
    mods[nmods++] = xrdc_sec_sss();
    mods[nmods++] = xrdc_sec_unix();
    mods[nmods++] = xrdc_sec_host();
    mods[nmods++] = xrdc_sec_pwd();

    for (i = 0; i < nmods; i++) {
        const xrdc_sec_module *m = mods[i];
        char                   parms[256];

        if (m == NULL) {
            continue;
        }
        if (o != NULL && o->auth_force != NULL
            && strcmp(o->auth_force, m->name) != 0) {
            continue;
        }
        if (!xrootd_sec_proto_advertised(seclist, m->name, parms, sizeof(parms))) {
            continue;
        }
        if (m->have_creds != NULL && !m->have_creds(c)) {
            continue;
        }

        tried = 1;
        if (run_module(c, m, parms, st) == 0) {
            c->diag.chosen_auth = m->name;   /* §15 explain */
            return 0;
        }
        /*
         * A protocol we HAD credentials for failed.  Surface it on stderr:
         * otherwise the driver silently falls back (classically gsi → unix) and
         * the user sees only a confusing downstream authorization error from the
         * server (e.g. EOS "unauthorized identity used") instead of the real
         * cause (e.g. the GSI handshake the server rejected).  stderr keeps data
         * output (stdout) clean.
         */
        fprintf(stderr,
                "xrdc: warning: '%s' authentication failed (%s); "
                "falling back to the next offered protocol\n",
                m->name, st->msg[0] ? st->msg : "no detail");
    }

    if (!tried) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "no usable auth protocol for server list \"%s\"%s",
                        seclist,
                        (o != NULL && o->auth_force) ? " (with --auth filter)" : "");
    }
    return -1;
}

void
xrdc_auth_explain(xrdc_conn *c, const xrdc_opts *o, FILE *out)
{
    const xrdc_sec_module *mods[7];
    int                    nmods = 0, i, picked = 0;
    char                   parms[256];

    if (xrdc_sec_gsi() != NULL) {
        mods[nmods++] = xrdc_sec_gsi();
    }
    mods[nmods++] = xrdc_sec_token();
    mods[nmods++] = xrdc_sec_krb5();
    mods[nmods++] = xrdc_sec_sss();
    mods[nmods++] = xrdc_sec_unix();
    mods[nmods++] = xrdc_sec_host();
    mods[nmods++] = xrdc_sec_pwd();

    fprintf(out, "  sec list: %s\n",
            c->sec_list[0] ? c->sec_list : "(none — anonymous)");
    fprintf(out, "  authenticated with: %s\n",
            c->diag.chosen_auth ? c->diag.chosen_auth : "(none — anonymous login)");

    /* Re-derive the would-be choice read-only, so "why skipped" matches the real
     * driver's preference order (gsi > ztn > unix). */
    for (i = 0; i < nmods; i++) {
        const xrdc_sec_module *m = mods[i];
        const char            *why;
        if (m == NULL) {
            continue;
        }
        if (o != NULL && o->auth_force != NULL
            && strcmp(o->auth_force, m->name) != 0) {
            why = "skipped (--auth filter)";
        } else if (!xrootd_sec_proto_advertised(c->sec_list, m->name, parms, sizeof(parms))) {
            why = "not offered by server";
        } else if (m->have_creds != NULL && !m->have_creds(c)) {
            why = "offered, but no local credentials";
        } else if (!picked) {
            why = "offered + creds present → preferred";
            picked = 1;
        } else {
            why = "offered + creds present (lower preference)";
        }
        fprintf(out, "    %-6s %s\n", m->name, why);
    }
}
