/*
 * guard_classify.c — bad-actor request classification.
 *
 * WHAT: the classifier half of the guard core: signature-blocklist matching,
 *   namespace-grammar checks, and the pre-backend / post-response verdicts
 *   built on them.
 * WHY:  every adapter (ARC HTTP, XrdHttp/WebDAV, root:// relay) needs the same
 *   junk-vs-legitimate decision; keeping it pure C makes the decision
 *   testable without a server.
 * HOW:  pure functions over a caller-built guard_ruleset_t and a normalized
 *   guard_request_t — no allocation, no I/O, no globals.
 */
#include "guard.h"
#include <string.h>

/* ---- Test one signature pattern against a path ----
 *
 * WHAT: returns 1 if `path[0..len)` matches signature `s` (case-sensitive
 *   suffix, prefix, or substring per s->kind), else 0.
 *
 * WHY: the three pattern kinds cover the junk-scanner corpus (extension
 *   probes, well-known directory probes, embedded traversal/artifact tokens)
 *   without regex machinery in a pure-C core.
 *
 * HOW: 1. Reject empty or over-long patterns (can never match).
 *      2. SUFFIX: memcmp against the path tail.
 *      3. PREFIX: memcmp against the path head.
 *      4. SUBSTR: sliding-window memcmp across the path.
 */
static int
sig_hit(const guard_sig_t *s, const char *path, size_t len)
{
    if (s->pat_len == 0 || s->pat_len > len) {
        return 0;
    }
    switch (s->kind) {
    case GUARD_SIG_SUFFIX:
        return memcmp(path + len - s->pat_len, s->pat, s->pat_len) == 0;
    case GUARD_SIG_PREFIX:
        return memcmp(path, s->pat, s->pat_len) == 0;
    case GUARD_SIG_SUBSTR:
    default: {
        size_t window_start;
        for (window_start = 0; window_start + s->pat_len <= len;
             window_start++)
        {
            if (memcmp(path + window_start, s->pat, s->pat_len) == 0) {
                return 1;
            }
        }
        return 0;
    }
    }
}

/* ---- Match a path against the ruleset's signature blocklist ----
 *
 * WHAT: returns 1 if `path[0..len)` matches any configured signature, else 0.
 *
 * WHY: signatures are the highest-confidence bad-actor tell — a single hit on
 *   a grid data path (".php", "/wp-", "/.env") identifies a scanner, so this
 *   is the first check every adapter runs.
 *
 * HOW: 1. Linearly test each configured signature via sig_hit().
 *      2. First hit wins; order is irrelevant to the verdict.
 */
int
guard_signature_match(const guard_ruleset_t *rs, const char *path, size_t len)
{
    int sig_index;

    for (sig_index = 0; sig_index < rs->n_sigs; sig_index++) {
        if (sig_hit(&rs->sigs[sig_index], path, len)) {
            return 1;
        }
    }
    return 0;
}

/* ---- Check (op, path) against the namespace grammar ----
 *
 * WHAT: returns 1 if the op-class is permitted and the path starts with one
 *   of the configured namespace prefixes (or no prefixes are configured),
 *   else 0.
 *
 * WHY: each fronted service has a tiny legitimate namespace (ARC REST roots,
 *   an export root); anything outside it is scanner traffic even when no
 *   signature fires.
 *
 * HOW: 1. Reject ops the profile does not allow.
 *      2. With no prefixes configured, any path is in-grammar (op-only mode).
 *      3. Otherwise accept on the first prefix that heads the path.
 */
int
guard_grammar_ok(const guard_ruleset_t *rs, guard_op_class_t op,
    const char *path, size_t len)
{
    int prefix_index;

    if (!rs->op_allowed[op]) {
        return 0;
    }
    if (rs->n_prefixes == 0) {
        return 1;                       /* no prefixes configured = any path */
    }
    for (prefix_index = 0; prefix_index < rs->n_prefixes; prefix_index++) {
        if (len >= rs->prefix_len[prefix_index]
            && memcmp(path, rs->prefixes[prefix_index],
                      rs->prefix_len[prefix_index]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/* ---- Does buf open with an HTTP request line? ----
 *
 * WHAT: returns 1 if buf[0..len) begins with a recognized HTTP method token
 *   followed by a space (GET/POST/HEAD/PUT/OPTIONS/DELETE/CONNECT/TRACE/PATCH).
 *
 * WHY: a web scanner knocking on a root:// port opens with an HTTP request
 *   line; naming it in the audit tells the operator exactly what probed them.
 *
 * HOW: 1. Match each method's leading bytes plus the trailing space so a
 *         binary frame that merely starts with those letters is not misread.
 */
static int
is_http_line(const unsigned char *buf, size_t len)
{
    static const char *const verbs[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE ",
        "CONNECT ", "TRACE ", "PATCH "
    };
    size_t v;

    for (v = 0; v < sizeof(verbs) / sizeof(verbs[0]); v++) {
        size_t vlen = strlen(verbs[v]);
        if (len >= vlen && memcmp(buf, verbs[v], vlen) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ---- Wire-level handshake classifier ----
 *
 * WHAT: inspects the first bytes of a fresh connection on a root:// port and
 *   decides whether they are the kXR client handshake. Returns GUARD_WIRE_ROOT
 *   for a genuine (or still-incomplete-but-consistent) kXR opening, otherwise
 *   the best-effort identity of the non-root client (TLS/HTTP/SSH/empty/junk).
 *
 * WHY: the tap-based guard only sees DECODED kXR frames; a client that never
 *   speaks root — a TLS ClientHello, an HTTP scanner, an SSH bannergrab, raw
 *   junk — produces no frame and would otherwise sail through to the backend.
 *   This is the "who is knocking on the root port" classifier operators want.
 *
 * HOW: 1. A real kXR client opens with ClientInitHandShake: 12 zero bytes,
 *         then fourth == htonl(4) (bytes 12..15 == 00 00 00 04); fifth is left
 *         unchecked so odd-but-real clients still forward.
 *      2. Reject the instant an available leading byte breaks the zero-prefix;
 *         defer (*need_more) only while every byte seen stays consistent and
 *         the 20-byte signature is not yet complete.
 *      3. A non-root opening is identified for the audit line: TLS record
 *         (0x16 0x03), HTTP method line, "SSH-" banner, empty, else junk.
 */
guard_wire_t
guard_classify_handshake(const unsigned char *buf, size_t len, int *need_more)
{
    size_t lead, i;

    *need_more = 0;

    if (len == 0) {
        return GUARD_WIRE_EMPTY;
    }

    /* Step 1+2: is the opening consistent with the kXR zero-prefix? */
    lead = len < 12 ? len : 12;
    for (i = 0; i < lead; i++) {
        if (buf[i] != 0) {
            break;                      /* zero-prefix broken -> not root */
        }
    }
    if (i == lead) {                    /* every leading byte zero so far */
        if (len < 16) {
            *need_more = 1;             /* zero-prefix, fourth not yet in */
            return GUARD_WIRE_ROOT;
        }
        /* fourth is now present; fifth is deliberately unchecked, so the
         * 16-byte prefix is the whole verdict — final either way. */
        if (buf[12] == 0 && buf[13] == 0 && buf[14] == 0 && buf[15] == 4) {
            return GUARD_WIRE_ROOT;     /* genuine kXR ClientInitHandShake */
        }
        return GUARD_WIRE_JUNK;         /* 16+ zero-led bytes, fourth != 4 */
    }

    /* Step 3: name the non-root client for the operator. */
    if (buf[0] == 0x16 && len >= 2 && buf[1] == 0x03) {
        return GUARD_WIRE_TLS;          /* TLS handshake record, version 3.x */
    }
    if (is_http_line(buf, len)) {
        return GUARD_WIRE_HTTP;
    }
    if (len >= 4 && memcmp(buf, "SSH-", 4) == 0) {
        return GUARD_WIRE_SSH;
    }
    return GUARD_WIRE_JUNK;
}

/* ---- Pre-backend verdict: bounce or allow ----
 *
 * WHAT: classifies a request before it reaches the backend. Returns
 *   GUARD_BOUNCE with *why set to the firing signal (signature > grammar),
 *   or GUARD_ALLOW with *why = GUARD_R_NONE.
 *
 * WHY: bouncing junk pre-backend keeps scanner noise out of ARC/XRootD logs
 *   and off their worker threads, and gives fail2ban a single high-signal
 *   line to ban on.
 *
 * HOW: 1. Signature blocklist first — highest confidence, wins over grammar.
 *      2. Grammar check only when the ruleset enforces it (advisory mode
 *         still allows, adapters may log separately).
 *      3. Otherwise allow.
 */
guard_verdict_t
guard_classify_pre(const guard_ruleset_t *rs, const guard_request_t *req,
    guard_reason_t *why)
{
    if (guard_signature_match(rs, req->path, req->path_len)) {
        *why = GUARD_R_SIGNATURE;       /* signatures win over grammar */
        return GUARD_BOUNCE;
    }
    if (rs->enforce_grammar
        && !guard_grammar_ok(rs, req->op, req->path, req->path_len))
    {
        *why = GUARD_R_GRAMMAR;
        return GUARD_BOUNCE;
    }
    *why = GUARD_R_NONE;
    return GUARD_ALLOW;
}

/* ---- Post-response signal classification ----
 *
 * WHAT: maps a completed request's outcome to a loggable bad-actor reason
 *   (GUARD_R_NOTFOUND / GUARD_R_AUTHFAIL) when the ruleset flags that
 *   outcome, else GUARD_R_NONE. Never bounces — the response already went
 *   out.
 *
 * WHY: not-found storms and repeated auth failures are per-request weak
 *   signals that fail2ban aggregates into a ban via jail thresholds; the
 *   guard's job is only to emit one clean line each.
 *
 * HOW: 1. NOTFOUND outcome + flag_notfound -> GUARD_R_NOTFOUND.
 *      2. AUTHFAIL outcome + flag_authfail -> GUARD_R_AUTHFAIL.
 *      3. Everything else is not a signal.
 */
guard_reason_t
guard_classify_post(const guard_ruleset_t *rs, const guard_request_t *req)
{
    if (req->outcome == OUTCOME_NOTFOUND && rs->flag_notfound) {
        return GUARD_R_NOTFOUND;
    }
    if (req->outcome == OUTCOME_AUTHFAIL && rs->flag_authfail) {
        return GUARD_R_AUTHFAIL;
    }
    return GUARD_R_NONE;
}
