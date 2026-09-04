/* copy_web_relay.c - copy-engine retry and private web-to-web staging. */
#include "copy_internal.h"

static void
copy_retry_pause(const brix_copy_opts *opts, int attempt,
                 const char *src, const brix_status *status)
{
    int             backoff = 1 << (attempt < 5 ? attempt : 5);
    unsigned        half_ms;
    unsigned        wait_ms;
    struct timespec delay;

    if (backoff > 30) {
        backoff = 30;
    }
    half_ms = (unsigned) backoff * 500u;
    wait_ms = half_ms + brix_jitter_ms(half_ms + 1u);
    if (opts == NULL || !opts->silent) {
        fprintf(stderr, "xrdcp: %s failed (%s); retry %d/%d in %.1fs\n",
                src, status->msg, attempt + 1, opts->retry_count,
                wait_ms / 1000.0);
    }
    delay.tv_sec = wait_ms / 1000u;
    delay.tv_nsec = (long) (wait_ms % 1000u) * 1000000L;
    (void) nanosleep(&delay, NULL);
}


int
copy_web_leaf_retry(const char *src, const char *dst,
                    const brix_copy_opts *opts, const brix_opts *conn,
                    brix_status *status)
{
    int attempt;
    int retry_count = opts == NULL ? 0 : opts->retry_count;

    for (attempt = 0; ; attempt++) {
        brix_status_clear(status);
        if (copy_dispatch_one(src, dst, opts, conn, status) == 0) {
            return 0;
        }
        if (attempt >= retry_count || brix_copy_quit_requested()) {
            return -1;
        }
        copy_retry_pause(opts, attempt, src, status);
    }
}


static int
copy_web_relay_temp(char *path, size_t capacity, brix_status *status)
{
    const char *tmpdir = getenv("TMPDIR");
    int         fd;

    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    if ((size_t) snprintf(path, capacity, "%s/xrdcp-w2w-XXXXXX", tmpdir)
        >= capacity) {
        brix_status_set(status, XRDC_EUSAGE, 0,
                        "web->web: temp path too long");
        return -1;
    }
    fd = mkstemp(path);
    if (fd < 0) {
        brix_status_set(status, XRDC_ESOCK, errno,
                        "web->web: mkstemp in %s: %s", tmpdir,
                        strerror(errno));
        return -1;
    }
    close(fd);
    return 0;
}


int
copy_web_relay(const char *src, const char *dst,
               const brix_copy_opts *opts, const brix_opts *conn,
               brix_status *status)
{
    char           path[XRDC_PATH_MAX];
    brix_copy_opts leg;
    int            rc;

    if (copy_web_relay_temp(path, sizeof(path), status) != 0) {
        return -1;
    }
    if (opts == NULL) {
        memset(&leg, 0, sizeof(leg));
    } else {
        leg = *opts;
    }
    if (!leg.silent) {
        fprintf(stderr, "xrdcp: %s -> %s (web->web via local temp)\n",
                src, dst);
    }
    leg.force = 1;
    leg.recursive = 0;
    rc = copy_web_leaf_retry(src, path, &leg, conn, status);
    if (rc == 0) {
        (void) chmod(path, S_IRUSR | S_IWUSR);
        if (opts != NULL) {
            leg = *opts;
        }
        leg.recursive = 0;
        rc = copy_web_leaf_retry(path, dst, &leg, conn, status);
    }
    (void) unlink(path);
    return rc;
}
