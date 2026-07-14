/*
 * credinfo.c — credential introspection for `explain` (§15.2).
 *
 * WHAT: Best-effort decoders that narrate the credentials a session is (or could
 *       be) using: a bearer token's claims, and a GSI proxy's subject / issuer /
 *       validity / VOMS FQANs / clock skew. Output is human diagnostic text.
 * WHY:  "Why did auth fail / why am I 'nobody'?" is usually a credential problem
 *       (expired token, wrong aud, near-expiry proxy, clock skew, missing VOMS).
 *       Surfacing the decoded credential turns a silent fallback into an obvious
 *       cause — exactly what the native client is positioned to show.
 * HOW:  JWT: base64url-decode the payload segment and scalar-scan iss/sub/aud/
 *       scope/exp (NO signature verify, NO jansson — a diagnostic, not a gate);
 *       flag EXPIRED against the local clock. GSI: reuse the OpenSSL X509 parse
 *       (as proxy.c) for subject/issuer/notAfter, walk the VOMS AC extension
 *       (OID 1.3.6.1.4.1.8005.100.100.5) for FQANs, and report notBefore skew.
 *
 * Every function is fail-soft: malformed input prints a one-line note and
 * returns; it must never crash `explain`. Clean-room: standard JWT/RFC + OpenSSL.
 */
#include "brix.h"
#include "auth/token/b64url.h"   /* shared base64url decode + JWS splitter (libxrdproto) */
#include "auth/token/scopes.h"   /* shared WLCG scope parser (libxrdproto) */
#include "core/compat/json_min.h" /* shared dependency-free JSON value extractor */
#include "cli/cli_hint.h"        /* brix_hint_doctor_referral(): spec WS-7 doctor hint */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* JWT (bearer token) claims                                           */

/* Decode a JWT's payload segment into out[outsz] as a NUL-terminated JSON string,
 * via the SHARED base64url decoder + JWS splitter (libxrdproto — the same code the
 * module's token path uses). Returns the decoded length (>=0), or -1 if the input
 * is not a JWT, the payload is too large, or it fails to decode. */
static ssize_t
decode_payload_json(const char *jwt, char *out, size_t outsz)
{
    xrdjwt_seg seg[3];
    ssize_t    n;

    if (outsz < 2 || xrdjwt_split(jwt, strlen(jwt), seg) != 0) {
        return -1;
    }
    n = b64url_decode(seg[1].p, seg[1].n, (uint8_t *) out, outsz - 1);
    if (n < 0) {
        return -1;
    }
    out[n] = '\0';
    return n;
}

/*
 * Copy the value of top-level claim `key` from `json` into out[outsz]; 1 if found.
 * Thin wrapper over the SHARED dependency-free extractor (libxrdproto) — the same
 * string-aware scanner is the single source of truth, so this no longer mis-parses
 * escaped quotes or matches a key buried inside another value.
 */
static int
json_str(const char *json, const char *key, char *out, size_t outsz)
{
    return brix_json_get_str(json, strlen(json), key, out, outsz);
}

void
brix_token_explain(const char *jwt, FILE *out)
{
    char json[8192];
    char buf[512];

    if (jwt == NULL || jwt[0] == '\0') {
        return;
    }
    if (decode_payload_json(jwt, json, sizeof(json)) < 0 || json[0] != '{') {
        fprintf(out, "    token:    (present, unparseable — not a JWT payload)\n");
        return;
    }
    fprintf(out, "    token:\n");
    if (json_str(json, "iss", buf, sizeof(buf)))   { fprintf(out, "      iss:   %s\n", buf); }
    if (json_str(json, "sub", buf, sizeof(buf)))   { fprintf(out, "      sub:   %s\n", buf); }
    if (json_str(json, "aud", buf, sizeof(buf)))   { fprintf(out, "      aud:   %s\n", buf); }
    if (json_str(json, "scope", buf, sizeof(buf))) { fprintf(out, "      scope: %s\n", buf); }
    if (json_str(json, "exp", buf, sizeof(buf))) {
        long expv = strtol(buf, NULL, 10);
        long now = (long) time(NULL);
        fprintf(out, "      exp:   %ld (%s)\n", expv,
                expv <= now ? "EXPIRED" : "valid");
    }
}

/*
 * Apply the JWT `exp` claim to *m (m->exp + m->expired).
 *
 * WHAT: if `json` carries a top-level `exp`, record its epoch value in m->exp and
 *       set m->expired when that instant is at/before the local clock. No-op when
 *       the claim is absent (m keeps its zeroed exp/expired).
 * WHY:  isolating the expiry classification keeps brix_token_meta_get a flat
 *       sequence of one-claim steps rather than one branchy procedure — the exp
 *       comparison is the single fact the doctor oracle needs to predict a deny.
 * HOW:  (1) extract `exp` with the shared JSON scanner; (2) strtol to epoch;
 *       (3) mark expired only for a positive exp that is <= now (guarding a
 *       missing/zero value from spuriously reading as expired).
 */
static void
token_meta_apply_exp(const char *json, brix_token_meta *m)
{
    char expbuf[32];

    if (json_str(json, "exp", expbuf, sizeof(expbuf))) {
        m->exp = strtol(expbuf, NULL, 10);
        m->expired = (m->exp > 0 && m->exp <= (long) time(NULL));
    }
}

/*
 * Set m->has_read / m->has_write from the SHARED parser's WLCG scope flags.
 *
 * WHAT: fold the `nsc` parsed WLCG scopes into a path-agnostic "any read-capable
 *       scope?" / "any write-capable scope?" pair on *m.
 * WHY:  the read/write reduction over the parser's exact permission flags is the
 *       authoritative branch — pulling it out keeps token_meta_apply_scope's
 *       parsed-vs-heuristic choice readable and this reduction independently
 *       testable against the server's grant semantics.
 * HOW:  walk each parsed scope; OR its `read` flag into m->has_read and its
 *       write/create/modify flags into m->has_write (any one implies writable).
 */
static void
token_scope_from_parsed(const brix_token_scope_t *sc, int nsc, brix_token_meta *m)
{
    int i;

    for (i = 0; i < nsc; i++) {
        if (sc[i].read) { m->has_read = 1; }
        if (sc[i].write || sc[i].create || sc[i].modify) { m->has_write = 1; }
    }
}

/*
 * Fail-soft keyword classification of an opaque (non-WLCG) scope string.
 *
 * WHAT: set m->has_read / m->has_write by substring-matching read / write /
 *       create / modify in a scope the WLCG parser yielded nothing for.
 * WHY:  an opaque or non-standard `scope` claim must still produce a best-effort
 *       answer rather than silently reading as no-access; isolating the legacy
 *       heuristic keeps it clearly the fallback path, not the primary one.
 * HOW:  substring-test `read` for has_read; treat any of write/create/modify as
 *       write-capable (deliberately generous — the server stays the real gate).
 */
static void
token_scope_from_heuristic(const char *scope, brix_token_meta *m)
{
    m->has_read  = (strstr(scope, "read") != NULL);
    m->has_write = (strstr(scope, "write") != NULL
                    || strstr(scope, "create") != NULL
                    || strstr(scope, "modify") != NULL);
}

/*
 * Apply the JWT `scope` claim to *m (has_scope + has_read/has_write).
 *
 * WHAT: if `json` carries a top-level `scope`, mark m->has_scope and derive the
 *       read/write capability, preferring the SHARED WLCG parser and falling back
 *       to the keyword heuristic only when the parser yields no scopes.
 * WHY:  centralising the parsed-vs-heuristic decision in one helper keeps the
 *       parser the single source of truth (matching the server's grant) with a
 *       clearly-secondary fallback, and flattens brix_token_meta_get.
 * HOW:  (1) extract `scope`; (2) set has_scope; (3) parse with
 *       brix_token_parse_scopes; (4) if it produced scopes, reduce them via
 *       token_scope_from_parsed, else classify the raw string via
 *       token_scope_from_heuristic.
 */
static void
token_meta_apply_scope(const char *json, brix_token_meta *m)
{
    char scope[1024];

    if (json_str(json, "scope", scope, sizeof(scope))) {
        brix_token_scope_t sc[16];
        int nsc = brix_token_parse_scopes(scope, sc, 16);
        m->has_scope = 1;
        if (nsc > 0) {
            /* Path-agnostic "any read/write-capable scope?" derived from the
             * shared parser's exact WLCG permission flags, matching the server. */
            token_scope_from_parsed(sc, nsc, m);
        } else {
            /* Fail-soft: an opaque/non-WLCG scope the parser yields nothing for
             * falls back to the legacy keyword heuristic (be generous on write). */
            token_scope_from_heuristic(scope, m);
        }
    }
}

/*
 * WHAT: fill *m with a bearer token's machine-readable facts (validity + WLCG
 *       read/write scope presence). m->valid=0 if the JWT can't be parsed.
 * WHY:  the remote-doctor auth-suite must know, programmatically, whether a token
 *       is expired or read-only so it can predict whether the server SHOULD allow
 *       or deny an operation — turning a guess into an oracle-backed assertion.
 * HOW:  base64url-decode the payload (shared decoder), scalar-scan exp (vs local
 *       clock), and classify the WLCG `scope` claim with the SHARED scope parser
 *       (brix_token_parse_scopes — the exact mapping the server enforces) so the
 *       oracle predicts the server's decision rather than approximating it. No
 *       signature verify — the server is the gate; this only predicts its answer.
 */
void
brix_token_meta_get(const char *jwt, brix_token_meta *m)
{
    char json[8192];

    if (m == NULL) {
        return;
    }
    memset(m, 0, sizeof(*m));
    if (jwt == NULL || jwt[0] == '\0') {
        return;
    }
    if (decode_payload_json(jwt, json, sizeof(json)) < 0 || json[0] != '{') {
        return;
    }
    m->valid = 1;
    token_meta_apply_exp(json, m);
    token_meta_apply_scope(json, m);
}

/* GSI proxy certificate                                              */

/* VOMS attribute-certificate extension OID. */
#define VOMS_AC_OID "1.3.6.1.4.1.8005.100.100.5"

/* Scan the DER bytes of the VOMS extension for FQAN-looking ASCII runs
 * ("/vo/...", "/vo/Role=..."), best-effort (full AC decode is out of scope). */
static void
voms_scan(const unsigned char *der, int len, FILE *out)
{
    int  i = 0, printed = 0;
    char run[256];

    while (i < len) {
        if (der[i] == '/') {
            int j = 0;
            while (i < len && j < (int) sizeof(run) - 1
                   && der[i] >= 0x20 && der[i] < 0x7f) {
                run[j++] = (char) der[i++];
            }
            run[j] = '\0';
            if (j >= 4 && (strstr(run, "Role=") != NULL || strchr(run + 1, '/') != NULL)) {
                fprintf(out, "      VOMS:  %s\n", run);
                printed = 1;
            }
        } else {
            i++;
        }
    }
    if (!printed) {
        fprintf(out, "      VOMS:  present (no FQAN decoded)\n");
    }
}

void
brix_gsi_cert_explain(const char *proxy_path, FILE *out)
{
    BIO  *bio;
    X509 *cert;
    char  subj[512], issuer[512];

    if (proxy_path == NULL || proxy_path[0] == '\0') {
        return;
    }
    bio = brix_credfile_bio(proxy_path, 1);
    if (bio == NULL) {
        return;
    }
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (cert == NULL) {
        fprintf(out, "    proxy:    (present at %s, unparseable PEM)\n", proxy_path);
        return;
    }

    X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof(subj));
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
    fprintf(out, "    proxy:\n");
    fprintf(out, "      subject: %s\n", subj);
    fprintf(out, "      issuer:  %s\n", issuer);

    /* validity + clock skew */
    {
        int              dn = 0, ds = 0, bn = 0, bs = 0;
        const ASN1_TIME *na = X509_get0_notAfter(cert);
        const ASN1_TIME *nb = X509_get0_notBefore(cert);
        if (ASN1_TIME_diff(&dn, &ds, NULL, na)) {
            if (dn < 0 || (dn == 0 && ds < 0)) {
                fprintf(out, "      expiry:  EXPIRED\n");
            } else {
                fprintf(out, "      expiry:  %dd %dh left\n", dn, ds / 3600);
            }
        }
        if (ASN1_TIME_diff(&bn, &bs, NULL, nb) && (bn > 0 || bs > 0)) {
            fprintf(out, "      skew:    notBefore is in the future "
                         "(local clock behind / cert not yet valid)\n");
        }
    }

    /* VOMS attribute certificate */
    {
        int loc = -1, n = X509_get_ext_count(cert), i;
        for (i = 0; i < n; i++) {
            X509_EXTENSION *ex = X509_get_ext(cert, i);
            ASN1_OBJECT    *obj = X509_EXTENSION_get_object(ex);
            char            oid[128];
            OBJ_obj2txt(oid, sizeof(oid), obj, 1);
            if (strcmp(oid, VOMS_AC_OID) == 0) {
                loc = i;
                break;
            }
        }
        if (loc < 0) {
            fprintf(out, "      VOMS:  none\n");
        } else {
            ASN1_OCTET_STRING *data =
                X509_EXTENSION_get_data(X509_get_ext(cert, loc));
            voms_scan(ASN1_STRING_get0_data(data), ASN1_STRING_length(data), out);
        }
    }
    X509_free(cert);
}

/* Phase 40 (c): client-side pre-flight / auth-failure diagnostics      */

/*
 * Diagnose the discoverable bearer token; return 1 for a likely-fatal problem.
 *
 * WHAT: discover a local bearer token (env / file / XDG / /tmp); if it parses,
 *       print — indented by `prefix` — a note for an EXPIRED token (returns 1), a
 *       read-only token on a `want_write` op (returns 1), or a near-expiry token
 *       (advisory only, returns 0). Returns 0 when no token, an unparseable token,
 *       or no likely-fatal problem.
 * WHY:  splitting the token arm out of brix_cred_diagnose keeps each credential
 *       kind's fail-fast logic self-contained and independently reviewable, and
 *       keeps the orchestrator a flat two-step sequence.
 * HOW:  (1) brix_token_discover; (2) brix_token_meta_get; (3) on a valid token,
 *       branch expired -> read-only-write -> near-expiry (first match wins,
 *       preserving the original else-if precedence); (4) free the token.
 */
static int
diagnose_token(int want_write, const char *prefix, FILE *out)
{
    char          *tok;
    int            problem = 0;
    brix_token_meta m;

    tok = brix_token_discover();
    if (tok == NULL) {
        return 0;
    }
    memset(&m, 0, sizeof(m));
    brix_token_meta_get(tok, &m);
    if (m.valid) {
        if (m.expired) {
            fprintf(out, "%sbearer token has EXPIRED (exp %ld, %ld s ago) — "
                         "obtain a fresh token and retry\n",
                    prefix, m.exp, (long) time(NULL) - m.exp);
            problem = 1;
        } else if (want_write && m.has_scope && !m.has_write) {
            fprintf(out, "%sbearer token grants READ scope only — this write "
                         "needs a storage.write / create / modify scope\n",
                    prefix);
            problem = 1;
        } else if (m.exp > 0) {
            long secs = m.exp - (long) time(NULL);
            if (secs >= 0 && secs < 300) {
                fprintf(out, "%sbearer token expires in %ld s — it may expire "
                             "mid-transfer\n", prefix, secs);
            }
        }
    }
    free(tok);
    return problem;
}

/*
 * Diagnose the default-path GSI proxy; return 1 for a likely-fatal problem.
 *
 * WHAT: if a readable GSI proxy exists at the default path and its remaining life
 *       is computable, print — indented by `prefix` — a note for an EXPIRED proxy
 *       (returns 1) or a near-expiry proxy (advisory only, returns 0). Returns 0
 *       when no proxy is present or its remaining life cannot be determined.
 * WHY:  mirrors diagnose_token so the proxy arm is self-contained; the two
 *       credential kinds stay decoupled and the orchestrator stays flat.
 * HOW:  (1) resolve the default proxy path; (2) require R_OK and a successful
 *       brix_proxy_remaining; (3) classify remaining <= 0 as expired (fatal) vs
 *       < 300 s as near-expiry (advisory).
 */
static int
diagnose_proxy(const char *prefix, FILE *out)
{
    char pxp[1024];
    long left = 0;

    brix_proxy_default_path(pxp, sizeof(pxp));
    if (access(pxp, R_OK) != 0 || brix_proxy_remaining(pxp, &left) != 0) {
        return 0;
    }
    if (left <= 0) {
        fprintf(out, "%sGSI proxy has EXPIRED (%s) — run 'xrdgsiproxy init'\n",
                prefix, pxp);
        return 1;
    }
    if (left < 300) {
        fprintf(out, "%sGSI proxy expires in %ld s (%s) — it may expire "
                     "mid-transfer\n", prefix, left, pxp);
    }
    return 0;
}

/*
 * WHAT: inspect whatever credential is present locally (a discoverable bearer
 *       token, then a GSI proxy at the default path) and print a specific,
 *       actionable hint to `out` when a likely auth problem is detectable WITHOUT
 *       contacting the server — an expired or near-expiry token/proxy, or (when
 *       want_write) a token that grants read scope only.  Returns 1 if a
 *       likely-fatal local problem was found, else 0.
 * WHY:  so the user sees the real cause instantly ("token expired 3m ago",
 *       "proxy expired — run xrdgsiproxy init", "token is read-only for a write")
 *       instead of digging after a bare "permission denied".  Pure local
 *       inspection: no network, no signature verification (it is a hint, not a
 *       gate — the server remains authoritative).
 */
int
brix_cred_diagnose(int want_write, const char *prefix, FILE *out)
{
    int problem = 0;

    if (out == NULL) {
        return 0;
    }
    if (prefix == NULL) {
        prefix = "";
    }

    /* Bearer token, if one is discoverable (env / file / XDG / /tmp). */
    problem |= diagnose_token(want_write, prefix, out);

    /* GSI proxy, if one is present at the default path. */
    problem |= diagnose_proxy(prefix, out);

    return problem;
}

/*
 * Print a credential hint at an app's error-reporting site, but only when the
 * status carries an auth/authz wire error — so an ordinary ENOENT/EIO failure
 * does not trigger credential noise.  Indented under the primary error line.
 * Also fires the doctor-referral hint (spec WS-7) so users know that
 * `xrddiag check <endpoint>` can walk through the auth handshake for them —
 * with the endpoint string when the caller has one (url_str, nullable).
 *
 * This _url variant is the canonical implementation; the historical
 * brix_cred_hint_for_status signature delegates with url_str=NULL so its
 * many existing call sites keep working unchanged.  brix_hint_doctor_referral
 * self-gates on the auth class (incl. the local XRDC_EAUTH sentinel, which is
 * broader than the wire-code gate used for the credential diagnosis) and
 * dedupes via brix_cli_hint_once("doctor").
 */
void
brix_cred_hint_for_status_url(const brix_status *st, int want_write, FILE *out,
                              const char *url_str)
{
    if (st == NULL || out == NULL) {
        return;
    }
    if (st->kxr == kXR_NotAuthorized || st->kxr == kXR_AuthFailed) {
        (void) brix_cred_diagnose(want_write, "  hint: ", out);
    }
    /* Spec WS-7: offer the xrddiag referral (self-gated on auth class). */
    brix_hint_doctor_referral(st, url_str);
}

void
brix_cred_hint_for_status(const brix_status *st, int want_write, FILE *out)
{
    brix_cred_hint_for_status_url(st, want_write, out, NULL);
}
