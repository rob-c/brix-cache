/*
 * copy_cksum_verify.c - --cksum spec parse + local/remote/literal digest verify.
 * Phase-38 split of copy_remote.c; behavior-identical.
 */
#include "copy_internal.h"



/*
 * WHAT: A parsed --cksum spec: the resolved algorithm, its lowercase name (for
 *       kXR_Qcksum + messages), the optional mode suffix, and the silent flag.
 * WHY:  cksum_verify's spec grammar ("<type>[:source|:print|:<value>]") is parsed
 *       once up front; carrying the result (plus the caller's silent flag) in a
 *       small struct lets the digest and per-mode helpers take one argument
 *       instead of several loose values.
 * HOW:  `mode` points into the caller's `spec` (after the colon) or is NULL when
 *       no suffix was given; `name` is a NUL-terminated copy of the type token;
 *       `silent` suppresses the success prints.
 */
typedef struct {
    brix_cksum_algo algo;
    char            name[32];
    const char     *mode;
    int             silent;
} cksum_spec_t;


/*
 * WHAT: Parse `spec` into a resolved algorithm + mode (the "resolve-algo" step).
 *       Returns 0 on success; on a usage error sets `st` and returns -1.
 * WHY:  Splitting the grammar parse out of cksum_verify keeps the orchestrator a
 *       flat sequence (parse → digest → compare) with no nested branching.
 * HOW:  Split at the first ':' — the token before it is the algorithm name, the
 *       remainder (or NULL) is the mode. Reject an empty or over-long name, then
 *       resolve the name to an algo id via the shared parser.
 */
static int
cksum_parse_spec(const char *spec, cksum_spec_t *out, brix_status *st)
{
    const char *colon = strchr(spec, ':');
    size_t      alen  = colon ? (size_t) (colon - spec) : strlen(spec);

    if (alen == 0 || alen >= sizeof(out->name)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "bad --cksum type");
        return -1;
    }
    memcpy(out->name, spec, alen);
    out->name[alen] = '\0';
    out->mode = colon ? colon + 1 : NULL;

    if (brix_cksum_algo_parse(out->name, &out->algo) != 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "unsupported --cksum type \"%s\"", out->name);
        return -1;
    }
    return 0;
}


/*
 * WHAT: Compute `spec->algo` over the local file `local_path` into `hex` (the
 *       "compute-local" step). Returns 0 on success, -1 (st set) otherwise.
 * WHY:  The open/digest/close sequence is a single self-contained unit with one
 *       cleanup path; isolating it removes an fd lifetime from the orchestrator.
 * HOW:  open() the file read-only, run the shared fd digest, and close on every
 *       path (including the digest-failure path).
 */
static int
cksum_compute_local(const char *local_path, const cksum_spec_t *spec,
                    char *hex, size_t hexsz, brix_status *st)
{
    int lfd = open(local_path, O_RDONLY);

    if (lfd < 0) {
        brix_status_set(st, XRDC_EUSAGE, errno,
                        "open %s for checksum: %s", local_path, strerror(errno));
        return -1;
    }
    if (brix_cksum_fd(lfd, spec->algo, hex, hexsz, st) != 0) {
        close(lfd);
        return -1;
    }
    close(lfd);
    return 0;
}


/*
 * WHAT: :source / :end2end mode — fetch the server's digest for `remote_path` and
 *       compare it to `local_hex` (the "fetch-remote + compare" step).
 * WHY:  The server round-trip and the mismatch classification are one logical
 *       branch of cksum_verify; extracting it keeps the orchestrator's mode
 *       dispatch a flat ladder of single-line calls.
 * HOW:  Require a remote path, query kXR_Qcksum, then case-insensitively compare.
 *       A query/transport failure is UNVERIFIED (digest UNKNOWN); a definite
 *       inequality is a non-retryable MISMATCH (EINTEGRITY).
 */
static int
cksum_verify_source(brix_conn *c, const char *remote_path, const char *local_hex,
                    const cksum_spec_t *spec, brix_status *st)
{
    char server_hex[129];

    if (remote_path == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0, "--cksum:source has no remote");
        return XRDC_CK_UNVERIFIED;
    }
    /* §7.13: the sha family is LOCAL-only — the kXR_Qcksum plane speaks
     * adler32/crc32c/md5(/crc64), so a sha :source comparison could only ever
     * come back UNVERIFIED and silently pass.  Refuse loudly instead: the
     * literal form (--cksum sha256:<hex>) is the supported spelling. */
    if (spec->algo == XRDC_CK_SHA1 || spec->algo == XRDC_CK_SHA256
        || spec->algo == XRDC_CK_SHA512) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "--cksum %s:source is not available (the server "
                        "checksum plane has no sha support); give a literal "
                        "digest: --cksum %s:<hex>",
                        spec->name, spec->name);
        return XRDC_CK_MISMATCH;
    }
    if (brix_query_cksum(c, remote_path, spec->name,
                         server_hex, sizeof(server_hex), st) != 0) {
        return XRDC_CK_UNVERIFIED;   /* server digest UNKNOWN, not WRONG */
    }
    if (strcasecmp(local_hex, server_hex) != 0) {
        /* A checksum mismatch is a data-integrity failure, not a transient
         * framing fault — classify it non-retryable so no resilient loop
         * spins re-verifying the same bytes. */
        brix_status_set(st, XRDC_EINTEGRITY, 0,
                        "%s mismatch: local %s != server %s",
                        spec->name, local_hex, server_hex);
        return XRDC_CK_MISMATCH;
    }
    if (!spec->silent) {
        printf("%s %s OK (matches server)\n", spec->name, local_hex);
    }
    return XRDC_CK_OK;
}


/*
 * WHAT: :<value> mode — compare `local_hex` to the literal expected digest carried
 *       in `spec->mode` (the "compare-literal" step).
 * WHY:  The literal branch mirrors the :source branch but has no round-trip;
 *       splitting it keeps both compare paths at the same altitude.
 * HOW:  Case-insensitive compare; inequality is a non-retryable MISMATCH.
 */
static int
cksum_verify_literal(const char *local_hex, const cksum_spec_t *spec,
                     brix_status *st)
{
    if (strcasecmp(local_hex, spec->mode) != 0) {
        brix_status_set(st, XRDC_EINTEGRITY, 0,
                        "%s mismatch: got %s expected %s",
                        spec->name, local_hex, spec->mode);
        return XRDC_CK_MISMATCH;
    }
    if (!spec->silent) {
        printf("%s %s OK\n", spec->name, local_hex);
    }
    return XRDC_CK_OK;
}


/*
 * --cksum handling. `spec` is "<type>[:source|:print|:<value>]". Computes the
 * named checksum over the local file `local_path` (the bytes we actually moved)
 * and then, by mode:
 *   :source / :end2end → query the server (kXR_Qcksum) for `remote_path` on the
 *                        already-open connection `c` and require they match;
 *   :<value>           → require the local digest equals the given hex;
 *   :print / (none)    → print "<type> <digest>" (unless silent).
 * Returns XRDC_CK_OK (matched/printed), XRDC_CK_MISMATCH (digest known and WRONG
 * — caller drops the destination), or XRDC_CK_UNVERIFIED (query/transport/usage
 * error — the digest is UNKNOWN, so the caller keeps the file and only warns;
 * deleting a byte-perfect download because a control-plane query hiccupped would
 * be the inverse footgun).
 */
int
cksum_verify(brix_conn *c, const char *remote_path, const char *local_path,
             const char *spec, int silent, brix_status *st)
{
    cksum_spec_t parsed = { 0 };
    char         local_hex[129];

    if (cksum_parse_spec(spec, &parsed, st) != 0) {
        return XRDC_CK_UNVERIFIED;
    }
    parsed.silent = silent;

    if (local_path == NULL) {
        /* stdio endpoint — nothing on disk to digest; skip rather than lie. */
        if (!silent) {
            fprintf(stderr, "xrdcp: --cksum skipped for stdin/stdout\n");
        }
        return XRDC_CK_OK;
    }

    if (cksum_compute_local(local_path, &parsed,
                            local_hex, sizeof(local_hex), st) != 0) {
        return XRDC_CK_UNVERIFIED;
    }

    if (parsed.mode != NULL
        && (strcmp(parsed.mode, "source") == 0
            || strcmp(parsed.mode, "end2end") == 0)) {
        return cksum_verify_source(c, remote_path, local_hex, &parsed, st);
    }

    if (parsed.mode != NULL && strcmp(parsed.mode, "print") != 0) {
        return cksum_verify_literal(local_hex, &parsed, st);
    }

    /* print / no mode */
    if (!silent) {
        printf("%s %s\n", parsed.name, local_hex);
    }
    return XRDC_CK_OK;
}
