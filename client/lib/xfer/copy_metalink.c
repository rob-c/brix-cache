/*
 * copy_metalink.c — metalink virtual-redirector orchestration (phase-100).
 *
 * WHAT: Detects a metalink source in brix_copy, loads the document (local read
 *       or a bounded remote fetch through the normal copy engine), parses it
 *       via metalink.c, then runs the transfer against the ranked mirrors with
 *       ordered failover — handing the root-family mirror list to the
 *       extreme-copy engine when --sources asks for it.
 * WHY:  Upstream XrdCl treats .meta4/.metalink files as virtual redirectors;
 *       this file is that behavior for the BriX client, kept separate from the
 *       pure parser (metalink.c) and from the per-direction transfer bodies it
 *       reuses (copy_dispatch_one).
 * HOW:  copy_metalink_run = fetch -> parse -> per-mirror dispatch loop. Every
 *       inner dispatch runs with metalink_off forced on, so a mirror that
 *       itself names a .meta4 can never recurse.
 */
#include "copy_internal.h"
#include "metalink.h"


/* ---- Does this source string name a metalink we should resolve? ----
 *
 * WHAT: 1 when `src` has the metalink suffix and the options do not disable
 *       resolution (--no-metalink / inner-fetch guard). Pure.
 *
 * WHY: One predicate keeps brix_copy's routing branch a single call and makes
 *      the "resolution off" rule impossible to miss on new call sites.
 *
 * HOW: Option gate first (cheap), then the suffix check from metalink.c.
 */
int
copy_is_metalink_src(const char *src, const brix_copy_opts *o)
{
    if (o != NULL && o->metalink_off) {
        return 0;
    }
    return brix_metalink_is_name(src);
}


/* ---- Read a local metalink file into a fresh buffer, bounded ----
 *
 * WHAT: malloc-read `path` (at most XRDC_METALINK_MAX_BYTES) into buf/blen.
 *       0, or -1 with st set (open/oversize/short-read). Caller frees *buf.
 *
 * WHY: The local branch of the fetch; the size cap runs BEFORE the read so a
 *      huge file never lands in memory.
 *
 * HOW: open O_RDONLY+O_NOFOLLOW-less (a user-named local path may be a
 *      symlink; that is normal CLI behavior) -> fstat gate -> full read loop.
 */
static int
metalink_read_local(const char *path, char **buf, size_t *blen, brix_status *st)
{
    struct stat sb;
    int fd = open(path, O_RDONLY);
    char *data;
    size_t got = 0;

    if (fd < 0) {
        brix_status_set(st, XRDC_EUSAGE, errno, "open %s: %s",
                        path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)
        || sb.st_size <= 0 || sb.st_size > (off_t) XRDC_METALINK_MAX_BYTES) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "metalink %s: not a regular file within the %u-byte cap",
                        path, XRDC_METALINK_MAX_BYTES);
        close(fd);
        return -1;
    }
    data = (char *) malloc((size_t) sb.st_size + 1);
    if (data == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        close(fd);
        return -1;
    }
    while (got < (size_t) sb.st_size) {
        ssize_t n = read(fd, data + got, (size_t) sb.st_size - got);
        if (n <= 0) {
            brix_status_set(st, XRDC_EIO, errno, "read %s: %s",
                            path, n < 0 ? strerror(errno) : "short read");
            free(data);
            close(fd);
            return -1;
        }
        got += (size_t) n;
    }
    close(fd);
    data[got] = '\0';
    *buf = data;
    *blen = got;
    return 0;
}


/* ---- Fetch a REMOTE metalink through the normal copy engine ----
 *
 * WHAT: Pull `src` (root://, http(s)://, davs://, …) into a private mkstemp
 *       temp, read it bounded, unlink the temp. 0 / -1 (st set).
 *
 * WHY: Reusing copy_dispatch_one means every transport, auth scheme and
 *      resilience knob the client has works for the metalink document itself —
 *      no second fetch stack to maintain.
 *
 * HOW: 1. mkstemp under $TMPDIR (0600, private). 2. Inner dispatch with
 *         metalink_off=1 (no recursion), silent, force (the temp exists), and
 *         every transfer-decoration (cksum/progress/xcp/zip/recursive) zeroed.
 *         3. Bounded local read + unlink on every path.
 */
static int
metalink_fetch_remote(const char *src, const brix_copy_opts *o,
                      const brix_opts *co, char **buf, size_t *blen,
                      brix_status *st)
{
    const char *tmpdir = getenv("TMPDIR");
    char tmp[XRDC_PATH_MAX];
    int fd, rc;
    brix_copy_opts fetch;

    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    if ((size_t) snprintf(tmp, sizeof(tmp), "%s/xrdcp-mtln-XXXXXX",
                          tmpdir) >= sizeof(tmp)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "TMPDIR path too long");
        return -1;
    }
    fd = mkstemp(tmp);
    if (fd < 0) {
        brix_status_set(st, XRDC_EIO, errno, "mkstemp %s: %s",
                        tmp, strerror(errno));
        return -1;
    }
    close(fd);   /* the copy engine writes via its own temp+rename */

    fetch = *o;
    fetch.metalink_off  = 1;
    fetch.silent        = 1;
    fetch.force         = 1;
    fetch.cksum         = NULL;
    fetch.compress      = NULL;
    fetch.zip           = 0;
    fetch.zip_append    = 0;
    fetch.recursive     = 0;
    fetch.pgrw          = 0;
    fetch.parallel      = 0;
    fetch.sources       = 0;
    fetch.xcp_mirrors   = NULL;
    fetch.xcp_n_mirrors = 0;
    fetch.progress      = NULL;
    fetch.progress_arg  = NULL;
    fetch.remove_source = 0;
    fetch.dry_run       = 0;

    rc = copy_dispatch_one(src, tmp, &fetch, co, st);
    if (rc == 0) {
        rc = metalink_read_local(tmp, buf, blen, st);
    }
    unlink(tmp);
    return rc;
}


/* ---- Load the metalink document bytes from wherever `src` lives ----
 *
 * WHAT: Local paths read directly; anything with a scheme the copy engine
 *       knows fetches through it. 0 / -1 (st set); caller frees *buf.
 *
 * WHY: One seam for the two load paths keeps copy_metalink_run flat.
 *
 * HOW: Web URLs and root-family URLs go remote; a bare path or file:// (the
 *      LOCAL scheme) reads directly; stdio ("-") is rejected (a stream has no
 *      re-openable mirrors to fail over to anyway).
 */
static int
metalink_load(const char *src, const brix_copy_opts *o, const brix_opts *co,
              char **buf, size_t *blen, brix_status *st)
{
    brix_url u;
    brix_status parse_st;

    if (brix_is_web_url(src)) {
        return metalink_fetch_remote(src, o, co, buf, blen, st);
    }
    brix_status_clear(&parse_st);
    if (brix_url_parse(src, &u, &parse_st) == 0) {
        if (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS) {
            return metalink_fetch_remote(src, o, co, buf, blen, st);
        }
        if (u.scheme == XRDC_SCHEME_LOCAL) {
            return metalink_read_local(u.path, buf, blen, st);
        }
    }
    brix_status_set(st, XRDC_EUSAGE, 0,
                    "metalink source %s: unsupported scheme", src);
    return -1;
}


/* ---- May this failed mirror attempt fail over to the next mirror? ----
 *
 * WHAT: 1 to advance to the next mirror, 0 to stop with this verdict.
 *
 * WHY: Mirror failover exists for per-endpoint faults (dead host, missing
 *      replica, auth mismatch, corrupt copy). Verdicts that are identical for
 *      every mirror — usage errors (destination exists, bad flags), local
 *      disk failures, operator cancel — must surface immediately instead of
 *      being retried N times.
 *
 * HOW: Deny-list on the local verdict classes + the cooperative cancel flag;
 *      every transport/server/integrity class advances.
 */
static int
metalink_failover_ok(const brix_status *st)
{
    if (brix_copy_quit_requested()) {
        return 0;
    }
    if (st->kxr == XRDC_EUSAGE || st->kxr == XRDC_EIO) {
        return 0;
    }
    return 1;
}


/* ---- Is this mirror a root-family URL the block engine can dial? ----
 *
 * WHAT: 1 for root:// roots:// xroot:// xroots:// spellings. Pure.
 *
 * WHY: The extreme-copy engine speaks the root:// wire only; web mirrors stay
 *      in the serial failover loop.
 *
 * HOW: Prefix table, case-insensitive (mirror documents are hand-written).
 */
static int
metalink_url_is_root_family(const char *mirror_url)
{
    static const char *const roots[] = {
        "root://", "roots://", "xroot://", "xroots://",
    };
    size_t i;

    for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        if (strncasecmp(mirror_url, roots[i], strlen(roots[i])) == 0) {
            return 1;
        }
    }
    return 0;
}


/* ---- Run the transfer against the ranked mirrors with ordered failover ----
 *
 * WHAT: The virtual-redirector core: fetch + parse the metalink named by
 *       `src`, then dispatch dst against urls[0], urls[1], … until one
 *       succeeds. 0 / -1 (st = last mirror's verdict, or the parse failure).
 *
 * WHY: This IS the metalink feature: mirror failover for a one-shot copy, the
 *      document's digest inherited as an integrity gate, and the mirror list
 *      handed to the extreme-copy engine when --sources wants it.
 *
 * HOW: 1. Load + parse (buffer freed immediately after parse). 2. Build the
 *         per-attempt opts once: metalink_off (no recursion), the document
 *         digest as a literal --cksum when the user gave none, and the
 *         root-family mirror subset wired to xcp_mirrors for --sources. 3.
 *         Ordered loop over mirrors: success returns; a non-failover verdict
 *         stops; otherwise note the failure (unless -s) and advance.
 */
int
copy_metalink_run(const char *src, const char *dst, const brix_copy_opts *o,
                  const brix_opts *co, brix_status *st)
{
    brix_metalink  ml;
    char          *buf = NULL;
    size_t         blen = 0;
    brix_copy_opts attempt;
    char           cksum_spec[XRDC_METALINK_ALGO_MAX + XRDC_METALINK_HEX_MAX];
    const char    *root_mirrors[XRDC_METALINK_MAX_URLS];
    size_t         n_root = 0, i;
    int            rc = -1;

    if (metalink_load(src, o, co, &buf, &blen, st) != 0) {
        return -1;
    }
    rc = brix_metalink_parse(buf, blen, &ml, st);
    free(buf);
    if (rc != 0) {
        return -1;
    }

    attempt = *o;
    attempt.metalink_off = 1;

    /* Inherit the document digest as a literal integrity gate when the user
     * did not pick their own --cksum: a corrupt mirror then drops the download
     * exactly like a failed --cksum today (committed-but-bad file unlinked). */
    if (o->cksum == NULL && ml.hash_algo[0] != '\0') {
        snprintf(cksum_spec, sizeof(cksum_spec), "%s:%s",
                 ml.hash_algo, ml.hash_hex);
        attempt.cksum = cksum_spec;
    }

    /* The extreme-copy engine speaks the root:// wire only; hand it that
     * subset of the ranked mirrors (best-first order preserved). */
    for (i = 0; i < ml.n_urls; i++) {
        if (metalink_url_is_root_family(ml.urls[i].rank_url)) {
            root_mirrors[n_root++] = ml.urls[i].rank_url;
        }
    }
    attempt.xcp_mirrors   = (n_root > 0) ? root_mirrors : NULL;
    attempt.xcp_n_mirrors = n_root;

    for (i = 0; i < ml.n_urls; i++) {
        rc = copy_dispatch_one(ml.urls[i].rank_url, dst, &attempt, co, st);
        if (rc == 0) {
            return 0;
        }
        if (!metalink_failover_ok(st)) {
            return -1;
        }
        if (!o->silent && i + 1 < ml.n_urls) {
            fprintf(stderr, "xrdcp: metalink mirror %s failed (%s); "
                            "trying next mirror\n",
                    ml.urls[i].rank_url, st->msg);
        }
    }
    return rc;
}
