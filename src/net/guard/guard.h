#ifndef BRIX_GUARD_GUARD_H
#define BRIX_GUARD_GUARD_H

/*
 * guard.h — protocol-agnostic bad-actor classifier (pure C, no nginx).
 *
 * WHAT: normalizes any protocol request into guard_request_t, then classifies it
 *   for bad-actor signals (junk signatures, namespace-grammar violations,
 *   backend not-found storms, auth failures) and formats one audit line per
 *   flagged request for fail2ban to ban on.
 * WHY:  the bad-actor logic and the fail2ban contract are identical across ARC,
 *   XrdHttp/WebDAV, and root:// — write them once, feed from thin adapters.
 * HOW:  pure C — no nginx, no allocation, no OpenSSL — so it embeds in an nginx
 *   http module, in the stream relay, and unit-tests standalone. Mirrors
 *   src/net/tap/.
 */

#include <stddef.h>

typedef enum {
    GUARD_OP_READ, GUARD_OP_WRITE, GUARD_OP_LIST, GUARD_OP_DELETE,
    GUARD_OP_JOBCTL, GUARD_OP_STAGE, GUARD_OP_INFO, GUARD_OP_DELEG,
    GUARD_OP_HANDSHAKE, GUARD_OP_UNKNOWN
} guard_op_class_t;

typedef enum {
    OUTCOME_PENDING, OUTCOME_OK, OUTCOME_NOTFOUND,
    OUTCOME_AUTHFAIL, OUTCOME_ERROR
} guard_outcome_t;

typedef enum { GUARD_ALLOW, GUARD_BOUNCE } guard_verdict_t;

typedef enum {
    GUARD_R_NONE, GUARD_R_SIGNATURE, GUARD_R_GRAMMAR,
    GUARD_R_NOTFOUND, GUARD_R_AUTHFAIL, GUARD_R_NOTROOT,
    GUARD_R_PROXYABUSE,     /* forward-proxy abused to reach a non-allowlisted
                            * remote (open-proxy / SSRF probe) */
    GUARD_R_TAMPER          /* content failed CVMFS integrity verification —
                            * CAS hash or manifest/whitelist signature mismatch
                            * on a fill (tampered / MITM'd / corrupted origin) */
} guard_reason_t;

/* First-bytes wire-protocol guess for a connection opened on a root:// port.
 * GUARD_WIRE_ROOT = the fixed 20-byte kXR client handshake (or a zero-prefix
 * still consistent with one); every other value is a client NOT speaking root,
 * to be logged and dropped. Ordered most-to-least specific for the audit. */
typedef enum {
    GUARD_WIRE_ROOT,     /* kXR ClientInitHandShake (or its leading zero-prefix) */
    GUARD_WIRE_TLS,      /* TLS record: handshake / ClientHello */
    GUARD_WIRE_HTTP,     /* HTTP request line (web scanner) */
    GUARD_WIRE_SSH,      /* SSH client banner */
    GUARD_WIRE_EMPTY,    /* connected, sent nothing (bannergrab / idle probe) */
    GUARD_WIRE_JUNK      /* anything else — unrecognized binary/text */
} guard_wire_t;

typedef struct {
    const char       *ip;          /* remote addr, adapter-supplied, NUL-term */
    const char       *proto;       /* "arc" | "xrdhttp" | "root" */
    guard_op_class_t  op;
    const char       *path;        /* already sanitized at the adapter edge */
    size_t            path_len;
    int               cred_present; /* 1 = client cert verified OR bearer present */
    guard_outcome_t   outcome;      /* PENDING pre-backend; set post-response */
    int               status_code;  /* HTTP status or kXR_* status */
} guard_request_t;

/* Signature pattern kinds. */
typedef enum {
    GUARD_SIG_SUFFIX,   /* path ends with pat  (".php") */
    GUARD_SIG_PREFIX,   /* path starts with pat ("/wp-") */
    GUARD_SIG_SUBSTR    /* path contains pat   ("/../") */
} guard_sig_kind_t;

#define GUARD_MAX_SIGS      64
#define GUARD_MAX_PREFIXES  32

typedef struct { guard_sig_kind_t kind; const char *pat; size_t pat_len; }
    guard_sig_t;

typedef struct {
    /* signature blocklist */
    guard_sig_t sigs[GUARD_MAX_SIGS];
    int         n_sigs;
    /* namespace grammar */
    const char *prefixes[GUARD_MAX_PREFIXES];
    size_t      prefix_len[GUARD_MAX_PREFIXES];
    int         n_prefixes;
    int         op_allowed[GUARD_OP_UNKNOWN + 1]; /* 1 = op permitted */
    int         enforce_grammar;                  /* 0 = prefixes/ops advisory */
    /* outcome flag toggles */
    int         flag_notfound;
    int         flag_authfail;
} guard_ruleset_t;

/* ---- classification (guard_classify.c) ---- */

/* Pre-backend verdict: signatures + grammar only. Sets *why on BOUNCE. */
guard_verdict_t guard_classify_pre(const guard_ruleset_t *rs,
    const guard_request_t *req, guard_reason_t *why);

/* Post-response signal: maps req->outcome to a loggable reason, else NONE.
 * Never bounces (the response already went out). */
guard_reason_t guard_classify_post(const guard_ruleset_t *rs,
    const guard_request_t *req);

/* Return 1 if path matches any signature. */
int guard_signature_match(const guard_ruleset_t *rs,
    const char *path, size_t len);

/* Return 1 if (op,path) is within the configured grammar. */
int guard_grammar_ok(const guard_ruleset_t *rs, guard_op_class_t op,
    const char *path, size_t len);

/* Classify the FIRST bytes of a connection on a root:// port as speaking the
 * kXR handshake or not. Returns the wire guess; GUARD_WIRE_ROOT means the
 * bytes are (a prefix of) the 20-byte kXR ClientInitHandShake and must be
 * forwarded. *need_more is set to 1 only when buf is a zero-prefix shorter
 * than the full signature (verdict deferred until more bytes arrive), else 0.
 * Pure: no allocation, no I/O — buf need not be NUL-terminated. */
guard_wire_t guard_classify_handshake(const unsigned char *buf, size_t len,
    int *need_more);

/* ---- audit formatting (guard_audit.c) ---- */

/* Format one flagged request as a single key=value line (fail2ban-friendly)
 * into out[0..outsz). `ts` is a caller-supplied timestamp string (adapters own
 * the clock). Returns bytes written (excl. NUL), or 0 if it would not fit. */
size_t guard_audit_format(const guard_request_t *req, guard_reason_t reason,
    const char *ts, char *out, size_t outsz);

/* Reason -> stable lowercase token used in the audit line + fail2ban filter. */
const char *guard_reason_str(guard_reason_t r);

/* Op-class -> stable lowercase token. */
const char *guard_op_str(guard_op_class_t op);

/* Wire guess -> stable lowercase token used in the notroot audit line's path
 * field ("root", "tls-clienthello", "http-request", "ssh-banner", …). */
const char *guard_wire_str(guard_wire_t w);

/* ---- ruleset construction (guard_ruleset.c) ---- */

/* Zero a ruleset. */
void guard_ruleset_init(guard_ruleset_t *rs);

/* Append the built-in junk-scanner signature set (php/wp/.env/.git/…). */
void guard_ruleset_add_default_signatures(guard_ruleset_t *rs);

/* Add one signature (pat must outlive the ruleset). Returns 0 on overflow. */
int guard_ruleset_add_signature(guard_ruleset_t *rs, guard_sig_kind_t kind,
    const char *pat, size_t pat_len);

/* Add one valid namespace prefix. Returns 0 on overflow. */
int guard_ruleset_add_prefix(guard_ruleset_t *rs, const char *pfx, size_t len);

/* Load the built-in grammar defaults for a profile ("arc"|"xrdhttp"|"root").
 * Sets prefixes + op_allowed[]. Unknown profile leaves grammar permissive. */
void guard_ruleset_load_profile(guard_ruleset_t *rs, const char *profile);

#endif /* BRIX_GUARD_GUARD_H */
