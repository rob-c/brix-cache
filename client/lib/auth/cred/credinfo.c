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
    char scope[1024];

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
    {
        char expbuf[32];
        if (json_str(json, "exp", expbuf, sizeof(expbuf))) {
            m->exp = strtol(expbuf, NULL, 10);
            m->expired = (m->exp > 0 && m->exp <= (long) time(NULL));
        }
    }
    if (json_str(json, "scope", scope, sizeof(scope))) {
        brix_token_scope_t sc[16];
        int nsc = brix_token_parse_scopes(scope, sc, 16);
        m->has_scope = 1;
        if (nsc > 0) {
            /* Path-agnostic "any read/write-capable scope?" derived from the
             * shared parser's exact WLCG permission flags (read vs
             * write/create/modify), matching what the server would grant. */
            int i;
            for (i = 0; i < nsc; i++) {
                if (sc[i].read) { m->has_read = 1; }
                if (sc[i].write || sc[i].create || sc[i].modify) { m->has_write = 1; }
            }
        } else {
            /* Fail-soft: an opaque/non-WLCG scope the parser yields nothing for
             * falls back to the legacy keyword heuristic (be generous on write). */
            m->has_read  = (strstr(scope, "read") != NULL);
            m->has_write = (strstr(scope, "write") != NULL
                            || strstr(scope, "create") != NULL
                            || strstr(scope, "modify") != NULL);
        }
    }
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
    int   problem = 0;
    char *tok;
    char  pxp[1024];
    long  left = 0;

    if (out == NULL) {
        return 0;
    }
    if (prefix == NULL) {
        prefix = "";
    }

    /* Bearer token, if one is discoverable (env / file / XDG / /tmp). */
    tok = brix_token_discover();
    if (tok != NULL) {
        brix_token_meta m;
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
    }

    /* GSI proxy, if one is present at the default path. */
    brix_proxy_default_path(pxp, sizeof(pxp));
    if (access(pxp, R_OK) == 0 && brix_proxy_remaining(pxp, &left) == 0) {
        if (left <= 0) {
            fprintf(out, "%sGSI proxy has EXPIRED (%s) — run 'xrdgsiproxy init'\n",
                    prefix, pxp);
            problem = 1;
        } else if (left < 300) {
            fprintf(out, "%sGSI proxy expires in %ld s (%s) — it may expire "
                         "mid-transfer\n", prefix, left, pxp);
        }
    }

    return problem;
}

/*
 * Print a credential hint at an app's error-reporting site, but only when the
 * status carries an auth/authz wire error — so an ordinary ENOENT/EIO failure
 * does not trigger credential noise.  Indented under the primary error line.
 * Also fires the doctor-referral hint (spec WS-7) so users know that
 * `xrddiag check <endpoint>` can walk through the auth handshake for them.
 */
void
brix_cred_hint_for_status(const brix_status *st, int want_write, FILE *out)
{
    if (st == NULL || out == NULL) {
        return;
    }
    if (st->kxr != kXR_NotAuthorized && st->kxr != kXR_AuthFailed) {
        return;
    }
    (void) brix_cred_diagnose(want_write, "  hint: ", out);
    /* Spec WS-7: after the credential hint, offer the xrddiag referral. */
    brix_hint_doctor_referral(st, NULL);
}
