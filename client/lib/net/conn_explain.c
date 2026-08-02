/*
 * conn_explain.c - human-readable connection/role/TLS/credential summary (brix_explain_conn).
 * Phase-38 split of conn.c; behavior-identical.
 */
#include "brix.h"
#include "brix_auth.h"
#include "protocols/root/protocol/frame_hdr.h"
#include "core/compat/host_format.h"
#include "core/compat/crypto.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ---- Print the server-role summary line decoded from server_flags ----
 *
 * WHAT: writes the "Roles:" line (server / manager / proxy, or "(unknown)"
 *       when neither server nor manager bit is set) to out.
 *
 * WHY:  the role decode is one nameable concern; splitting it keeps
 *       brix_explain_conn a flat sequence and each decode under complexity cap.
 *
 * HOW:  1. test each role capability bit in the negotiated flags word; 2. emit
 *       its label or an empty string; 3. append "(unknown)" only when neither
 *       the server nor the manager bit is present.
 */
static void
explain_roles(unsigned f, FILE *out)
{
    fprintf(out, "Roles:    %s%s%s%s\n",
            (f & kXR_isServer)  ? "server "  : "",
            (f & kXR_isManager) ? "manager " : "",
            (f & kXR_attrProxy) ? "proxy "   : "",
            (f & (kXR_isServer | kXR_isManager)) ? "" : "(unknown)");
}

/* ---- Print the negotiated-capabilities summary line ----
 *
 * WHAT: writes the "Caps:" line (TLS availability + gotoTLS requirement,
 *       pgread/pgwrite support, POSC support) decoded from server_flags to out.
 *
 * WHY:  capability decode is a distinct concern from role decode; isolating it
 *       keeps the orchestrator flat and each helper independently reviewable.
 *
 * HOW:  1. map kXR_haveTLS to available/no and annotate with gotoTLS when the
 *       server mandates TLS; 2. map kXR_suppgrw and kXR_supposc to yes/no.
 */
static void
explain_caps(unsigned f, FILE *out)
{
    fprintf(out, "Caps:     TLS=%s%s pgread/pgwrite=%s POSC=%s\n",
            (f & kXR_haveTLS) ? "available" : "no",
            (f & kXR_gotoTLS) ? " (gotoTLS: required)" : "",
            (f & kXR_suppgrw) ? "yes" : "no",
            (f & kXR_supposc) ? "yes" : "no");
}

/* ---- Print the live TLS transport state, flagging a silent downgrade ----
 *
 * WHAT: writes the "TLS:" line — active with version/cipher when a session is
 *       up, or an explicit downgrade WARNING when the server advertised gotoTLS
 *       yet the transport is cleartext, or plain "inactive (cleartext)".
 *
 * WHY:  a gotoTLS→cleartext downgrade is a security-relevant condition operators
 *       must see; keeping the three-way decision in one helper preserves it
 *       verbatim while capping the orchestrator's complexity.
 *
 * HOW:  1. query brix_tls_info for the live cipher; 2. if active, print
 *       version/cipher (defaulting either to "?"); 3. else if the gotoTLS bit is
 *       set, print the downgrade warning; 4. else report plain cleartext.
 */
static void
explain_tls(brix_conn *c, unsigned f, FILE *out)
{
    const char *ver = NULL, *cipher = NULL;

    if (brix_tls_info(c, &ver, &cipher)) {
        fprintf(out, "TLS:      active — %s / %s\n",
                ver ? ver : "?", cipher ? cipher : "?");
    } else if (f & kXR_gotoTLS) {
        fprintf(out, "TLS:      INACTIVE — WARNING: server advertised gotoTLS but "
                "the session is cleartext (downgrade)\n");
    } else {
        fprintf(out, "TLS:      inactive (cleartext)\n");
    }
}

/* ---- Print any credentials discoverable in the process environment ----
 *
 * WHAT: writes a "Credentials (in environment):" block describing a discovered
 *       bearer token and/or an X509_USER_PROXY, when either is present; prints
 *       nothing when neither exists.
 *
 * WHY:  §15.2 — surfacing environment credentials even when they were NOT the
 *       chosen protocol lets operators see "you have a token but the server
 *       didn't offer ztn" and "your proxy is expired". Best-effort/read-only.
 *
 * HOW:  1. discover a token and read $X509_USER_PROXY; 2. if either is present,
 *       print the header; 3. explain the token (freeing the discovered copy);
 *       4. explain the proxy cert when the path is non-empty.
 */
static void
explain_env_credentials(FILE *out)
{
    char       *tok = brix_token_discover();
    const char *proxy = getenv("X509_USER_PROXY");

    if (tok != NULL || (proxy != NULL && proxy[0] != '\0')) {
        fprintf(out, "Credentials (in environment):\n");
        if (tok != NULL) {
            brix_token_explain(tok, out);
            free(tok);
        }
        if (proxy != NULL && proxy[0] != '\0') {
            brix_gsi_cert_explain(proxy, out);
        }
    }
}

/* ---- Print the 16-byte session id as lowercase hex on the "Session:" line ----
 *
 * WHAT: writes "Session:  " followed by the hex encoding of c->sessid to out.
 *
 * WHY:  the byte-loop encode is a separate concern from the flag/cap decodes;
 *       isolating it keeps the orchestrator a flat call sequence.
 *
 * HOW:  1. print the label; 2. walk every session-id byte emitting two hex
 *       digits; 3. terminate the line.
 */
static void
explain_session_id(brix_conn *c, FILE *out)
{
    int i;

    fprintf(out, "Session:  ");
    for (i = 0; i < (int) sizeof(c->sessid); i++) {
        fprintf(out, "%02x", c->sessid[i]);
    }
    fprintf(out, "\n");
}

/*
 * brix_explain_conn — narrate an established session: endpoint, server roles,
 * negotiated caps, signing, the auth choice, the TLS state, and the session id.
 *
 * WHAT: a read-only report over the conn fields conn.c/auth.c already populated.
 * WHY:  both `xrdfs explain` and `xrddiag check` want the same human-readable
 *       picture of what the handshake actually negotiated — single-source it here.
 * HOW:  decode server_flags into roles/caps, defer the per-module auth detail to
 *       brix_auth_explain, and call brix_tls_info for the live cipher (flagging a
 *       gotoTLS→cleartext downgrade as a warning).
 */
void
brix_explain_conn(brix_conn *c, const brix_opts *opts, FILE *out)
{
    unsigned f;

    if (c == NULL || out == NULL) {
        return;
    }
    f = (unsigned) c->server_flags;

    fprintf(out, "Endpoint: %s:%d\n", c->host, c->port);
    explain_roles(f, out);
    explain_caps(f, out);
    fprintf(out, "Signing:  sec_level=%d%s\n", c->sec_level,
            c->signing_active ? " (kXR_sigver active)" : "");

    fprintf(out, "Auth:\n");
    brix_auth_explain(c, opts != NULL ? opts : &c->opts, out);

    explain_tls(c, f, out);
    explain_env_credentials(out);
    explain_session_id(c, out);
}
