/*
 * copy_xcp_sources.c — replica-list policy for the extreme copy (phase-100).
 *
 * WHAT: Where the block-stealing engine's connections point: build the worker
 *       URL slots from, in preference order, the metalink mirror list, a
 *       kXR_locate on the control connection, then the single source
 *       duplicated up to the asked width. Also owns the block-size knob.
 * WHY:  Split from copy_xcp.c (600-line file gate): source discovery is
 *       policy, the engine is mechanism, and each reads standalone.
 * HOW:  copy_xcp.c calls xcp_build_sources() once during setup; everything
 *       here is single-threaded (workers have not spawned yet).
 */
#include "copy_internal.h"
#include "copy_xcp_internal.h"


/* ---- Effective block size ----
 *
 * WHAT: BRIX_XCP_BLOCK bytes when set (clamped to [64 KiB, 64 MiB]), else the
 *       shared 8 MiB copy chunk.
 *
 * WHY: Tests and tuning need block granularity without recompiling; the clamp
 *      keeps a hostile/typo value from degenerating the block table.
 *
 * HOW: getenv + strtoull + clamp.
 */
size_t
xcp_block_size(void)
{
    const char *env = getenv("BRIX_XCP_BLOCK");
    unsigned long long v;

    if (env == NULL || env[0] == '\0') {
        return XRDC_COPY_CHUNK;
    }
    v = strtoull(env, NULL, 10);
    if (v < XRDC_XCP_BLOCK_MIN) { v = XRDC_XCP_BLOCK_MIN; }
    if (v > XRDC_XCP_BLOCK_MAX) { v = XRDC_XCP_BLOCK_MAX; }
    return (size_t) v;
}


/* ---- Compose the canonical URL for a parsed root-family endpoint ----
 *
 * WHAT: "<scheme>://host:port/<abs-path>" (the double-slash spelling, since
 *       the path keeps its leading '/'). 0 / -1 when it does not fit.
 *
 * WHY: The locate fallback and the single-source duplication both need a
 *      dialable URL string for endpoints we only hold in parsed form.
 *
 * HOW: Scheme from u->scheme (TLS keeps roots://); IPv6 hosts re-bracket.
 */
static int
xcp_compose_url(const brix_url *u, char *out, size_t outsz)
{
    const char *scheme = (u->scheme == XRDC_SCHEME_ROOTS) ? "roots" : "root";
    int v6 = (strchr(u->host, ':') != NULL);

    return ((size_t) snprintf(out, outsz, "%s://%s%s%s:%d/%s",
                              scheme, v6 ? "[" : "", u->host, v6 ? "]" : "",
                              u->port, u->path) >= outsz) ? -1 : 0;
}


/* ---- Replica URLs from the metalink mirror list ----
 *
 * WHAT: Copy up to `want` root-family mirror URLs (already ranked best-first
 *       by the parser) into the worker slots. Returns the count.
 *
 * WHY: A metalink with N mirrors IS the replica list — no discovery needed.
 *
 * HOW: The resolver already filtered to root-family; bound-copy each.
 */
static size_t
xcp_sources_from_mirrors(const download_job_t *job, xcp_worker_t *w,
                         size_t want)
{
    const brix_copy_opts *o = job->o;
    size_t n = 0, i;

    for (i = 0; i < o->xcp_n_mirrors && n < want; i++) {
        const char *m = o->xcp_mirrors[i];
        if (m == NULL || strlen(m) >= sizeof(w[n].url)) {
            continue;
        }
        snprintf(w[n].url, sizeof(w[n].url), "%s", m);
        n++;
    }
    return n;
}


/* ---- Replica URLs from a kXR_locate on the control connection ----
 *
 * WHAT: Ask the (already connected) source endpoint where the file lives and
 *       turn each data-server token into a replica URL. Returns the count.
 *
 * WHY: Without a metalink, a clustered source (CMS manager) can still name
 *      multiple holders — upstream XCp does exactly this discovery.
 *
 * HOW: brix_locate → whitespace-split tokens shaped "S<r|w><host>:<port>"
 *      ('S'/'s' server entries; manager 'M'/'m' entries are skipped — dialing
 *      a manager would just re-locate). Bracketed IPv6 hosts pass through
 *      verbatim inside the composed URL.
 */
static size_t
xcp_sources_from_locate(const download_job_t *job, xcp_worker_t *w,
                        size_t want)
{
    char reply[4096], *cursor, *token, *save = NULL;
    const char *scheme =
        (job->su->scheme == XRDC_SCHEME_ROOTS) ? "roots" : "root";
    brix_status lst;
    size_t n = 0;

    brix_status_clear(&lst);
    if (brix_locate(job->c, job->su->path, reply, sizeof(reply), &lst) != 0) {
        return 0;   /* no locate support / error: caller falls back */
    }
    cursor = reply;
    while (n < want && (token = strtok_r(cursor, " \t\r\n", &save)) != NULL) {
        cursor = NULL;
        if ((token[0] != 'S' && token[0] != 's') || token[1] == '\0'
            || token[2] == '\0') {
            continue;
        }
        if ((size_t) snprintf(w[n].url, sizeof(w[n].url), "%s://%s/%s",
                              scheme, token + 2, job->su->path)
            >= sizeof(w[n].url)) {
            continue;
        }
        n++;
    }
    return n;
}


/* ---- Build the replica list for this transfer ----
 *
 * WHAT: Fill worker URL slots from, in preference order: metalink mirrors,
 *       locate discovery, then the single source duplicated up to `want`.
 *       Returns the worker count (0 only when even the source URL cannot be
 *       composed).
 *
 * WHY: One place owns the "where can these bytes come from" policy and its
 *      documented divergence: with only one known replica the source URL is
 *      duplicated, because parallel TCP streams to one host still help on
 *      high-latency links and it keeps --sources honest on single servers.
 *
 * HOW: Providers in order until >= 2 replicas exist; a single replica is
 *      duplicated to the asked width; >= 2 distinct replicas are used as-is.
 */
size_t
xcp_build_sources(const download_job_t *job, xcp_worker_t *w, size_t want)
{
    size_t n = xcp_sources_from_mirrors(job, w, want);

    if (n < 2) {
        n += xcp_sources_from_locate(job, w + n, want - n);
    }
    if (n == 0) {
        if (xcp_compose_url(job->su, w[0].url, sizeof(w[0].url)) != 0) {
            return 0;
        }
        n = 1;
    }
    if (n == 1) {   /* one known replica: duplicate it up to the asked width */
        while (n < want) {
            snprintf(w[n].url, sizeof(w[n].url), "%s", w[0].url);
            n++;
        }
    }
    return n;
}
