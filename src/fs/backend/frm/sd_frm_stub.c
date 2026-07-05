/*
 * sd_frm_stub.c — the built-in "stub" MSS adapter: a local-directory tape
 * simulator (an online buffer dir + an offline "tape" dir, with residency,
 * recall, migrate and purge).  The default/fallback FRM back end and the one the
 * frm test suite drives.  Split out of sd_frm.c.  Also defines the two
 * filesystem helpers (frm_mkparents, stub_copyfile) the exec adapter reuses.
 */

#include "sd_frm_mss.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ===================== the built-in "stub" MSS adapter ===================== */

typedef struct {
    char       base[PATH_MAX];     /* the local "tape" directory */
    int        recall_delay_ms;    /* >0 simulates async MSS latency (SP5 park test) */
    ngx_log_t *log;
} stub_ctx_t;

/* The recall-in-flight marker for an async (delayed) stub recall:
 * <base>/.recalling/<key>. Its mtime records when the recall began; recall_poll
 * completes the copy once recall_delay_ms has elapsed. */
static int
stub_marker_path(const stub_ctx_t *c, const char *key, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/.recalling/%s", c->base,
                     (key[0] == '/') ? key + 1 : key);

    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

/* Build <base>[/.online]<key> into out. key carries a leading '/'. */
static int
stub_path(const stub_ctx_t *c, const char *key, int online, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s%s%s", c->base, online ? "/.online" : "",
                     (key[0] == '/') ? key : "/");
    if (n <= 0 || (size_t) n >= cap) {
        return -1;
    }
    if (key[0] != '/') {
        /* the snprintf above already added the separating '/' */
        n = snprintf(out, cap, "%s%s/%s", c->base, online ? "/.online" : "", key);
        return (n > 0 && (size_t) n < cap) ? 0 : -1;
    }
    n = snprintf(out, cap, "%s%s%s", c->base, online ? "/.online" : "", key);
    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

/* mkdir -p the parent directories of `path`. */
void
frm_mkparents(const char *path)
{
    char   tmp[PATH_MAX];
    size_t i;
    size_t n = strlen(path);

    if (n == 0 || n >= sizeof(tmp)) {
        return;
    }
    memcpy(tmp, path, n + 1);
    for (i = 1; i < n; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            (void) mkdir(tmp, 0755);     /* EEXIST ok */
            tmp[i] = '/';
        }
    }
}

/* Copy src -> dst (creating dst's parents), preserving mode. 0 / -1. */
int
stub_copyfile(const char *src, const char *dst, mode_t mode)
{
    char    buf[1u << 16];
    int     in;
    int     out;
    ssize_t r;

    in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0) {
        return -1;
    }
    frm_mkparents(dst);
    out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode ? mode : 0644);
    if (out < 0) {
        (void) close(in);
        return -1;
    }
    while ((r = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;

        while (off < r) {
            ssize_t w = write(out, buf + off, (size_t) (r - off));

            if (w < 0) {
                if (errno == EINTR) { continue; }
                (void) close(in);
                (void) close(out);
                return -1;
            }
            off += w;
        }
    }
    (void) close(in);
    if (close(out) != 0 || r < 0) {
        return -1;
    }
    return 0;
}

static int
stub_residency(void *mss, const char *key, off_t *size_out, time_t *mtime_out)
{
    stub_ctx_t *c = mss;
    char        path[PATH_MAX];
    struct stat sb;

    if (stub_path(c, key, 1 /* online */, path, sizeof(path)) == 0
        && stat(path, &sb) == 0)
    {
        if (size_out)  { *size_out = sb.st_size; }
        if (mtime_out) { *mtime_out = sb.st_mtime; }
        return BRIX_RESIDENCY_ONLINE;
    }
    if (stub_path(c, key, 0 /* tape */, path, sizeof(path)) == 0
        && stat(path, &sb) == 0)
    {
        if (size_out)  { *size_out = sb.st_size; }
        if (mtime_out) { *mtime_out = sb.st_mtime; }
        return BRIX_RESIDENCY_OFFLINE;
    }
    return BRIX_RESIDENCY_ABSENT;
}

static int
stub_recall_begin(void *mss, const char *key)
{
    stub_ctx_t *c = mss;
    char        tape[PATH_MAX];
    char        online[PATH_MAX];
    char        marker[PATH_MAX];
    struct stat sb;

    if (stub_path(c, key, 0, tape, sizeof(tape)) != 0
        || stub_path(c, key, 1, online, sizeof(online)) != 0
        || stat(tape, &sb) != 0)
    {
        return -1;
    }
    if (access(online, F_OK) == 0) {
        return 0;                        /* already online */
    }
    if (c->recall_delay_ms <= 0) {
        /* synchronous recall: a local copy tape -> online buffer (the default). */
        return stub_copyfile(tape, online, sb.st_mode & 0777);
    }
    /* Async: drop a recall marker (its mtime records the start). recall_poll
     * completes the copy once recall_delay_ms has elapsed - simulating MSS
     * latency so the cache tier parks the open (SP5 §9.2). Idempotent. */
    if (stub_marker_path(c, key, marker, sizeof(marker)) != 0) {
        return -1;
    }
    if (access(marker, F_OK) != 0) {
        int fd;

        frm_mkparents(marker);
        fd = open(marker, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
        if (fd >= 0) {
            (void) close(fd);
        }
    }
    return 0;                            /* recall in flight */
}

static int
stub_recall_poll(void *mss, const char *key)
{
    stub_ctx_t *c = mss;
    char        online[PATH_MAX];
    char        marker[PATH_MAX];
    char        tape[PATH_MAX];
    struct stat sb;

    if (stub_path(c, key, 1, online, sizeof(online)) != 0) {
        return -1;
    }
    if (access(online, F_OK) == 0) {
        return 1;                        /* online */
    }
    if (c->recall_delay_ms <= 0) {
        return 0;                        /* sync adapter: begin copies; not begun */
    }
    if (stub_marker_path(c, key, marker, sizeof(marker)) != 0
        || stat(marker, &sb) != 0)
    {
        return 0;                        /* no recall in flight */
    }
    if ((time(NULL) - sb.st_mtime) * 1000 < (time_t) c->recall_delay_ms) {
        return 0;                        /* still staging */
    }
    /* Delay elapsed: complete the recall (copy tape -> online), drop the marker. */
    if (stub_path(c, key, 0, tape, sizeof(tape)) != 0 || stat(tape, &sb) != 0) {
        return -1;
    }
    if (stub_copyfile(tape, online, sb.st_mode & 0777) != 0) {
        return -1;
    }
    (void) unlink(marker);
    return 1;
}

static int
stub_migrate(void *mss, const char *key)
{
    stub_ctx_t *c = mss;
    char        tape[PATH_MAX];
    char        online[PATH_MAX];
    struct stat sb;

    if (stub_path(c, key, 1, online, sizeof(online)) != 0
        || stub_path(c, key, 0, tape, sizeof(tape)) != 0
        || stat(online, &sb) != 0)
    {
        return -1;
    }
    return stub_copyfile(online, tape, sb.st_mode & 0777);
}

static int
stub_purge(void *mss, const char *key)
{
    stub_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (stub_path(c, key, 1, online, sizeof(online)) == 0) {
        (void) unlink(online);
    }
    return 0;
}

static int
stub_open_online(void *mss, const char *key)
{
    stub_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (stub_path(c, key, 1, online, sizeof(online)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return open(online, O_RDONLY | O_CLOEXEC);
}

static int
stub_create_online(void *mss, const char *key, mode_t mode)
{
    stub_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (stub_path(c, key, 1, online, sizeof(online)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    frm_mkparents(online);
    return open(online, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC,
                mode ? mode : 0644);
}

static void
stub_destroy(void *mss)
{
    free(mss);
}

const brix_mss_adapter_t brix_mss_stub_adapter = {
    .name          = "stub",
    .residency     = stub_residency,
    .recall_begin  = stub_recall_begin,
    .recall_poll   = stub_recall_poll,
    .migrate       = stub_migrate,
    .purge         = stub_purge,
    .open_online   = stub_open_online,
    .create_online = stub_create_online,
    .destroy       = stub_destroy,
};

/* ===================== stub adapter constructor ===================== */

/* brix_mss_stub_create — the local-directory stub simulator context. */
void *
brix_mss_stub_create(const char *location, ngx_log_t *log)
{
    stub_ctx_t *sc = calloc(1, sizeof(*sc));
    const char *d;

    if (sc == NULL) {
        return NULL;
    }
    ngx_cpystrn((u_char *) sc->base, (u_char *) location, sizeof(sc->base));
    sc->log = log;
    /* Test/dev knob: simulate MSS recall latency so the async park (202) path
     * is exercisable with the stub. 0 (default) = synchronous recall. */
    d = getenv("BRIX_FRM_STUB_RECALL_DELAY_MS");
    sc->recall_delay_ms = (d != NULL && d[0] != '\0')
        ? (int) ngx_atoi((u_char *) d, ngx_strlen(d)) : 0;
    if (sc->recall_delay_ms < 0) {
        sc->recall_delay_ms = 0;
    }
    return sc;
}
