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
#include "protocols/root/protocol/sec_protocol.h"   /* shared "&P=" security-list parser */
#include "protocols/root/protocol/codec/wire_codec.h" /* shared per-opcode wire-body codec */

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define XRDC_AUTH_MAX_ROUNDS 8

static int
send_auth(brix_conn *c, const char credtype[4], const uint8_t *payload,
          uint32_t plen, uint16_t *sid, brix_status *st)
{
    ClientAuthRequest req;
    brix_payload      pl = { payload, plen };

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_auth);
    {
        xrdw_auth_req_t b;
        memcpy(b.credtype, credtype, 4);
        xrdw_auth_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
    return brix_send(c, &req, &pl, sid, st);
}

/* Run one protocol's kXR_auth/authmore exchange to completion. 0 / -1. */
static int
run_module(brix_conn *c, const brix_sec_module *m, const char *parms,
           brix_status *st)
{
    uint8_t *payload = NULL;
    uint32_t plen = 0;
    int      round;

    if (m->first(c, parms, &payload, &plen, st) != 0) {
        return -1;
    }

    for (round = 0; round < XRDC_AUTH_MAX_ROUNDS; round++) {
        uint16_t      sid, status;
        uint8_t      *body = NULL;
        uint32_t      blen = 0;
        int           rc;
        brix_resp_out out = { &status, &body, &blen };

        rc = send_auth(c, m->credtype, payload, plen, &sid, st);
        free(payload);
        payload = NULL;
        plen = 0;
        if (rc != 0) {
            return -1;
        }
        if (brix_recv(c, sid, &out, st) != 0) {
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
                brix_status_set(st, XRDC_EAUTH, 0,
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
                brix_status_set(st, XRDC_EAUTH, 0,
                                "%s: auth ended without server ok", m->name);
                return -1;
            }
            continue;
        }
        free(body);
        brix_status_set(st, XRDC_EAUTH, 0, "%s: unexpected auth status %u",
                        m->name, status);
        return -1;
    }

    free(payload);
    brix_status_set(st, XRDC_EAUTH, 0, "%s: too many auth rounds", m->name);
    return -1;
}

/*
 * build_module_list — fill mods[] with every sec module, in preference order.
 *
 * WHAT: Populate the caller's fixed 7-slot array with the sec modules in the
 *       fixed preference order gsi > ztn > krb5 > sss > unix > host > pwd and
 *       return how many slots were written.
 * WHY:  Both the driver (brix_authenticate) and the read-only explainer
 *       (brix_auth_explain) must walk the SAME modules in the SAME order for
 *       "why skipped" to match the real choice; sharing one builder keeps them
 *       from drifting apart.
 * HOW:  gsi is only listed when its module is linked in (brix_sec_gsi may be
 *       NULL); the rest are appended unconditionally — a NULL slot there is
 *       filtered later at try-time, never here.
 */
static int
build_module_list(const brix_sec_module *mods[7])
{
    int nmods = 0;

    if (brix_sec_gsi() != NULL) {
        mods[nmods++] = brix_sec_gsi();
    }
    mods[nmods++] = brix_sec_token();
    mods[nmods++] = brix_sec_krb5();
    mods[nmods++] = brix_sec_sss();
    mods[nmods++] = brix_sec_unix();
    mods[nmods++] = brix_sec_host();
    mods[nmods++] = brix_sec_pwd();
    return nmods;
}

/*
 * module_candidate — decide whether one sec module is usable right now.
 *
 * WHAT: Return 1 (and fill parms with the server's advertised parameters for
 *       this protocol) when the module m should be driven, 0 when it must be
 *       skipped.
 * WHY:  Factors the four skip conditions of the try-loop out of the driver so
 *       the driver stays within complexity budget; the decision itself is
 *       unchanged and load-bearing — each branch guards a distinct reason a
 *       credential must NOT be presented.
 * HOW:  Skip a NULL slot; skip anything the --auth override filtered out; skip
 *       a protocol the server did not advertise (this call also fills parms as
 *       a side effect, so it must run for the surviving module); skip a module
 *       that reports no local credentials. Checks run in this exact order to
 *       preserve short-circuit behavior and the parms side effect.
 */
static int
module_candidate(brix_conn *c, const brix_sec_module *m, const brix_opts *o,
                 const char *seclist, char *parms, size_t parmslen)
{
    if (m == NULL) {
        return 0;
    }
    if (o != NULL && o->auth_force != NULL
        && strcmp(o->auth_force, m->name) != 0) {
        return 0;
    }
    if (!brix_sec_proto_advertised(seclist, m->name, parms, parmslen)) {
        return 0;
    }
    if (m->have_creds != NULL && !m->have_creds(c)) {
        return 0;
    }
    return 1;
}

/*
 * auth_warn_fallback — tell the user a credentialed protocol failed.
 *
 * WHAT: Emit a one-line stderr warning naming the protocol that failed and the
 *       reason captured in st, then let the caller fall back to the next module.
 * WHY:  A protocol we HAD credentials for failed. Without this, the driver
 *       silently falls back (classically gsi to unix) and the user sees only a
 *       confusing downstream authorization error from the server (e.g. EOS
 *       "unauthorized identity used") instead of the real cause (e.g. the GSI
 *       handshake the server rejected). stderr keeps data output (stdout) clean.
 * HOW:  Print m->name and st->msg, substituting "no detail" when st carries no
 *       message text.
 */
static void
auth_warn_fallback(const brix_sec_module *m, const brix_status *st)
{
    fprintf(stderr,
            "brix: warning: '%s' authentication failed (%s); "
            "falling back to the next offered protocol\n",
            m->name, st->msg[0] ? st->msg : "no detail");
}

int
brix_authenticate(brix_conn *c, const char *seclist, const brix_opts *o,
                  brix_status *st)
{
    const brix_sec_module *mods[7];
    int                    nmods;
    int                    i;
    int                    tried = 0;

    /* force_anon: complete the login but present NO credential. Used by the
     * remote-doctor auth-suite to test the SERVER's own enforcement (does it
     * reject unauthenticated operations?) independent of the client's creds. */
    if (o != NULL && o->force_anon) {
        return 0;
    }

    nmods = build_module_list(mods);

    for (i = 0; i < nmods; i++) {
        const brix_sec_module *m = mods[i];
        char                   parms[256];

        if (!module_candidate(c, m, o, seclist, parms, sizeof(parms))) {
            continue;
        }

        tried = 1;
        if (run_module(c, m, parms, st) == 0) {
            c->diag.chosen_auth = m->name;   /* §15 explain */
            return 0;
        }
        auth_warn_fallback(m, st);
    }

    if (!tried) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "no usable auth protocol for server list \"%s\"%s",
                        seclist,
                        (o != NULL && o->auth_force) ? " (with --auth filter)" : "");
    }
    return -1;
}

void
brix_auth_explain(brix_conn *c, const brix_opts *o, FILE *out)
{
    const brix_sec_module *mods[7];
    int                    nmods, i, picked = 0;
    char                   parms[256];

    nmods = build_module_list(mods);

    fprintf(out, "  sec list: %s\n",
            c->sec_list[0] ? c->sec_list : "(none — anonymous)");
    fprintf(out, "  authenticated with: %s\n",
            c->diag.chosen_auth ? c->diag.chosen_auth : "(none — anonymous login)");

    /* Re-derive the would-be choice read-only, so "why skipped" matches the real
     * driver's preference order (gsi > ztn > unix). */
    for (i = 0; i < nmods; i++) {
        const brix_sec_module *m = mods[i];
        const char            *why;
        if (m == NULL) {
            continue;
        }
        if (o != NULL && o->auth_force != NULL
            && strcmp(o->auth_force, m->name) != 0) {
            why = "skipped (--auth filter)";
        } else if (!brix_sec_proto_advertised(c->sec_list, m->name, parms, sizeof(parms))) {
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
