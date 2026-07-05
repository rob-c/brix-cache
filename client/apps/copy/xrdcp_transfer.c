/*
 * xrdcp_transfer.c - extracted concern
 * Phase-38 split of xrdcp.c; behavior-identical.
 */
#include "xrdcp_internal.h"


/* Relay a web->web copy through a private local temp file (download then upload).
 * Defined after copy_one_with_retry (which it calls for each leg). */

/* Copy one src->dst, retrying up to `retries` times with capped exponential backoff. */
int
copy_one_with_retry(const char *src, const char *dst, const brix_copy_opts *o,
                    const brix_opts *co, int retries, brix_status *st)
{
    int attempt = 0;
    /* web->web has no direct wire path — stage through a local temp. Each relay
     * leg is web<->local (never web->web), so it re-enters here on the normal
     * path with no recursion. */
    if (both_web(src, dst)) {
        return relay_web_to_web(src, dst, o, co, retries, st);
    }
    for (;;) {
        brix_status_clear(st);
        if (brix_copy(src, dst, o, co, st) == 0) {
            return 0;
        }
        if (attempt >= retries) {
            return -1;
        }
        {
            int backoff = 1 << (attempt < 5 ? attempt : 5);   /* 1,2,4,8,16,32 -> cap */
            unsigned half_ms, wait_ms;
            struct timespec ts;
            if (backoff > 30) { backoff = 30; }
            /* Phase 40 (a): "equal jitter" — wait half the backoff plus a random
             * slice of the other half, so many clients/jobs retrying in lockstep
             * spread their attempts instead of stampeding the server together. */
            half_ms = (unsigned) backoff * 500u;          /* backoff/2 in ms */
            wait_ms = half_ms + brix_jitter_ms(half_ms + 1u);
            if (!o->silent) {
                fprintf(stderr, "xrdcp: %s failed (%s); retry %d/%d in %.1fs\n",
                        src, st->msg, attempt + 1, retries, wait_ms / 1000.0);
            }
            ts.tv_sec  = wait_ms / 1000u;
            ts.tv_nsec = (long) (wait_ms % 1000u) * 1000000L;
            (void) nanosleep(&ts, NULL);
        }
        attempt++;
    }
}


/* Size of a regular file at `url` (root:// or local). 0 and *size set if it exists
 * as a regular file; -1 otherwise (missing, a directory, web, or error). */
int
entry_size(const char *url, const brix_opts *co, long long *size)
{
    brix_url    u;
    brix_status st;
    if (brix_is_web_url(url)) {
        return -1;   /* no cheap stat for web; --sync always copies web targets */
    }
    brix_status_clear(&st);
    if (brix_url_parse(url, &u, &st) != 0) {
        return -1;
    }
    if (u.scheme == XRDC_SCHEME_LOCAL) {
        struct stat sb;
        if (stat(u.path, &sb) != 0 || !S_ISREG(sb.st_mode)) { return -1; }
        *size = (long long) sb.st_size;
        return 0;
    }
    if (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS) {
        brix_conn     c;
        brix_statinfo si;
        int           ok;
        if (brix_connect(&c, &u, co, &st) != 0) { return -1; }
        ok = (brix_stat(&c, u.path, &si, &st) == 0 && !(si.flags & kXR_isDir));
        if (ok) { *size = (long long) si.size; }
        brix_close(&c);
        return ok ? 0 : -1;
    }
    return -1;
}


/* Transfer src -> dst. In --sync mode, skip when both ends exist with the same size.
 * Returns 0 (copied), 1 (skipped, up-to-date), or -1 (failed, st set). */
int
transfer_one(const char *src, const char *dst, const brix_copy_opts *o,
             const brix_opts *co, int retries, int sync_mode, brix_status *st)
{
    if (sync_mode) {
        long long ssz = 0, dsz = 0;
        if (entry_size(src, co, &ssz) == 0 && entry_size(dst, co, &dsz) == 0
            && ssz == dsz) {
            return 1;   /* up-to-date — skip */
        }
    }
    return (copy_one_with_retry(src, dst, o, co, retries, st) == 0) ? 0 : -1;
}


/* Relay a web->web copy (e.g. davs://a/f -> s3://b/k) by staging through a private
 * local temp file: download src into it, then upload it to dst. The wire has no
 * direct web->web op and brix_http_upload needs a seekable/sized body, so a temp
 * is the only correct path. The temp is created 0600 via mkstemp in $TMPDIR and
 * unlinked on every return. Note the download leg rewrites the temp via its own
 * temp+rename (which lands 0644), so we re-tighten it to 0600 before the upload
 * leg, keeping the staged bytes private during the (longer) upload window. Each
 * leg is web<->local, so cancellation is only as prompt as a single web transfer
 * (a timeout/EINTR boundary), not instantaneous. */
int
relay_web_to_web(const char *src, const char *dst, const brix_copy_opts *o,
                 const brix_opts *co, int retries, brix_status *st)
{
    const char    *tmpdir = getenv("TMPDIR");
    char           tmpl[XRDC_PATH_MAX];
    brix_copy_opts leg;
    int            fd, rc;

    if (tmpdir == NULL || tmpdir[0] == '\0') { tmpdir = "/tmp"; }
    if ((size_t) snprintf(tmpl, sizeof(tmpl), "%s/xrdcp-w2w-XXXXXX", tmpdir)
            >= sizeof(tmpl)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "web->web: temp path too long");
        return -1;
    }
    fd = mkstemp(tmpl);
    if (fd < 0) {
        brix_status_set(st, XRDC_ESOCK, errno,
                        "web->web: mkstemp in %s: %s", tmpdir, strerror(errno));
        return -1;
    }
    close(fd);   /* the download leg reopens by path */

    if (!o->silent) {
        fprintf(stderr, "xrdcp: %s -> %s (web->web via local temp)\n", src, dst);
    }
    /* Leg 1: download src -> our private temp. Force-overwrite the empty mkstemp
     * file (it is ours) and never recurse. */
    leg = *o;
    leg.force = 1;
    leg.recursive = 0;
    rc = copy_one_with_retry(src, tmpl, &leg, co, retries, st);
    if (rc == 0) {
        /* The download's temp+rename left the staged file group/other-readable;
         * re-tighten before the upload so the bytes aren't world-readable in a
         * shared /tmp for the whole upload. */
        (void) chmod(tmpl, S_IRUSR | S_IWUSR);
        /* Leg 2: upload temp -> dst, honouring the user's real force/posc/creds. */
        leg = *o;
        leg.recursive = 0;
        rc = copy_one_with_retry(tmpl, dst, &leg, co, retries, st);
    }
    (void) unlink(tmpl);
    return rc;
}


/* Copy one batch item into dstdir as dstdir/<basename>. Returns 0 (copied),
 * 1 (skipped), or -1 (failed, st set); the destination is written to dpath. */
int
batch_copy_one(const char *item, const char *dstdir, const brix_copy_opts *o,
               const brix_opts *co, int retries, int sync_mode, char *dpath,
               size_t dpsz, brix_status *st)
{
    char base[XRDC_NAME_MAX];
    path_basename(item, base, sizeof(base));
    if (base[0] == '\0') {
        brix_status_set(st, XRDC_EUSAGE, 0, "cannot derive a filename from %s", item);
        return -1;
    }
    if (join_dest(dstdir, base, dpath, dpsz) != 0) {
        brix_status_set(st, XRDC_EUSAGE, 0, "destination path too long for %s", item);
        return -1;
    }
    return transfer_one(item, dpath, o, co, retries, sync_mode, st);
}


/* Shared state for the parallel batch worker pool. Each brix_copy() is fully
 * independent (its own connection + fds), so workers only contend on this counter
 * block + stderr, guarded by one mutex. */

void *
batch_worker(void *arg)
{
    batch_ctx *b = (batch_ctx *) arg;
    for (;;) {
        size_t      idx;
        char        dpath[XRDC_PATH_MAX];
        brix_status st;
        int         rc;

        pthread_mutex_lock(&b->lock);
        idx = b->next++;
        pthread_mutex_unlock(&b->lock);
        if (idx >= b->n) {
            break;
        }
        brix_status_clear(&st);
        rc = batch_copy_one(b->items[idx], b->dst, b->o, b->co, b->retries,
                            b->sync_mode, dpath, sizeof(dpath), &st);
        pthread_mutex_lock(&b->lock);
        if (rc == 0) {
            b->ok++;
            if (!b->o->silent) {
                fprintf(stderr, "[%zu/%zu] %s -> %s\n", b->ok + b->skip + b->fail,
                        b->n, b->items[idx], dpath);
            }
        } else if (rc == 1) {
            b->skip++;
            if (!b->o->silent) {
                fprintf(stderr, "[%zu/%zu] %s (up-to-date)\n",
                        b->ok + b->skip + b->fail, b->n, b->items[idx]);
            }
        } else {
            b->fail++;
            fprintf(stderr, "xrdcp: %s: %s\n", b->items[idx], st.msg);
        }
        pthread_mutex_unlock(&b->lock);
    }
    return NULL;
}


/* Run the batch with `jobs` concurrent workers (jobs>=2). Fills ok/skip/fail counts. */
void
batch_parallel(char **items, size_t n, const char *dst, const brix_copy_opts *o,
               const brix_opts *co, int retries, int sync_mode, int jobs,
               size_t *ok, size_t *skip, size_t *fail)
{
    batch_ctx  b;
    pthread_t *th;
    int        j, spawned = 0;

    memset(&b, 0, sizeof(b));
    b.items = items; b.n = n; b.dst = dst; b.o = o; b.co = co; b.retries = retries;
    b.sync_mode = sync_mode;
    pthread_mutex_init(&b.lock, NULL);
    th = (pthread_t *) malloc((size_t) jobs * sizeof(pthread_t));
    if (th == NULL) {
        /* Fall back to single-threaded drain on allocation failure. */
        batch_worker(&b);
    } else {
        for (j = 0; j < jobs; j++) {
            if (pthread_create(&th[j], NULL, batch_worker, &b) == 0) {
                spawned++;
            }
        }
        if (spawned == 0) {
            batch_worker(&b);   /* no thread started — drain inline */
        }
        for (j = 0; j < spawned; j++) {
            pthread_join(th[j], NULL);
        }
        free(th);
    }
    pthread_mutex_destroy(&b.lock);
    *ok = b.ok;
    *skip = b.skip;
    *fail = b.fail;
}
