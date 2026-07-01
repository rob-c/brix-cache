/*
 * sd_frm.c - the nearline (tape/MSS) backend FS driver (SP5). See header.
 *
 * The driver is a thin residency layer over a pluggable MSS adapter. A read of an
 * offline object RECALLS it into the MSS online buffer (synchronously in this
 * increment - the stub recall is a local copy), then serves from the buffer via a
 * real fd; a staged write lands in the online buffer and is MIGRATED to tape on
 * commit. The composing registry requires a cache tier in front (G8), so the
 * recall is in practice the cache miss-fill sourced from tape.
 *
 * The built-in "stub" MSS adapter simulates tape with two local directories under
 * a base: <base>/<key> is "on tape" (offline) and <base>/.online/<key> is the
 * online buffer. It is what the SP5 tests drive; a real MSS (exec stagecmd, HPSS,
 * CTA) is another adapter selected on the tape:// store-URL.
 */
#include "sd_frm.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

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
static void
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
static int
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
        return XROOTD_RESIDENCY_ONLINE;
    }
    if (stub_path(c, key, 0 /* tape */, path, sizeof(path)) == 0
        && stat(path, &sb) == 0)
    {
        if (size_out)  { *size_out = sb.st_size; }
        if (mtime_out) { *mtime_out = sb.st_mtime; }
        return XROOTD_RESIDENCY_OFFLINE;
    }
    return XROOTD_RESIDENCY_ABSENT;
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

static const xrootd_mss_adapter_t xrootd_mss_stub_adapter = {
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

/* ===================== the "exec" MSS adapter (real HSM) =====================
 * The classic FRM model: an operator-supplied stage command drives the real MSS
 * (HPSS, CTA, dCache, an Enstore wrapper, ...). The local online buffer lives at
 * <base>/.online/<key>; the recall/migrate/exists verbs shell out to:
 *     $XROOTD_FRM_STAGECMD <verb> <key> <online-path>
 * recall is expected to be ASYNC-SUBMIT (start the MSS recall and return promptly,
 * not block until online); the driver then parks the open and polls until the
 * online buffer appears. A `recall_poll` is the cheap local-buffer existence check,
 * so no per-poll fork. */

typedef struct {
    char       base[PATH_MAX];      /* local online-buffer root          */
    char       stagecmd[PATH_MAX];  /* $XROOTD_FRM_STAGECMD              */
    ngx_log_t *log;
} exec_ctx_t;

static int
exec_online_path(const exec_ctx_t *c, const char *key, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/.online/%s", c->base,
                     (key[0] == '/') ? key + 1 : key);

    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

/* Run "<stagecmd> <verb> <key> <online>"; returns the child's exit code (0 ok), or
 * -1 on spawn/wait failure. No shell - argv is passed directly (no injection). */
static int
exec_run(const exec_ctx_t *c, const char *verb, const char *key,
    const char *online)
{
    char  *argv[5];
    pid_t  pid;
    int    status;

    argv[0] = (char *) c->stagecmd;
    argv[1] = (char *) verb;
    argv[2] = (char *) key;
    argv[3] = (char *) online;
    argv[4] = NULL;

    if (posix_spawn(&pid, c->stagecmd, NULL, NULL, argv, environ) != 0) {
        return -1;
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int
exec_residency(void *mss, const char *key, off_t *size_out, time_t *mtime_out)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];
    struct stat sb;

    if (exec_online_path(c, key, online, sizeof(online)) == 0
        && stat(online, &sb) == 0)
    {
        if (size_out)  { *size_out = sb.st_size; }
        if (mtime_out) { *mtime_out = sb.st_mtime; }
        return XROOTD_RESIDENCY_ONLINE;
    }
    /* Ask the MSS: exit 0 = on tape (offline), non-zero = absent. The size is
     * unknown until recalled; the cache fill restats the online buffer. */
    if (exec_run(c, "exists", key, "") == 0) {
        if (size_out)  { *size_out = 0; }
        if (mtime_out) { *mtime_out = time(NULL); }
        return XROOTD_RESIDENCY_OFFLINE;
    }
    return XROOTD_RESIDENCY_ABSENT;
}

static int
exec_recall_begin(void *mss, const char *key)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) != 0) {
        return -1;
    }
    if (access(online, F_OK) == 0) {
        return 0;                            /* already online */
    }
    frm_mkparents(online);                   /* the cmd writes the online buffer */
    return (exec_run(c, "recall", key, online) == 0) ? 0 : -1;
}

static int
exec_recall_poll(void *mss, const char *key)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) != 0) {
        return -1;
    }
    return (access(online, F_OK) == 0) ? 1 : 0;
}

static int
exec_migrate(void *mss, const char *key)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) != 0) {
        return -1;
    }
    return (exec_run(c, "migrate", key, online) == 0) ? 0 : -1;
}

static int
exec_purge(void *mss, const char *key)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) == 0) {
        (void) unlink(online);
    }
    return 0;
}

static int
exec_open_online(void *mss, const char *key)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return open(online, O_RDONLY | O_CLOEXEC);
}

static int
exec_create_online(void *mss, const char *key, mode_t mode)
{
    exec_ctx_t *c = mss;
    char        online[PATH_MAX];

    if (exec_online_path(c, key, online, sizeof(online)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    frm_mkparents(online);
    return open(online, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC,
                mode ? mode : 0644);
}

static void
exec_destroy(void *mss)
{
    free(mss);
}

static const xrootd_mss_adapter_t xrootd_mss_exec_adapter = {
    .name          = "exec",
    .residency     = exec_residency,
    .recall_begin  = exec_recall_begin,
    .recall_poll   = exec_recall_poll,
    .migrate       = exec_migrate,
    .purge         = exec_purge,
    .open_online   = exec_open_online,
    .create_online = exec_create_online,
    .destroy       = exec_destroy,
};

/* ===================== the sd_frm driver ===================== */

typedef struct {
    const xrootd_mss_adapter_t *mss;
    void                       *mss_ctx;
    ngx_log_t                  *log;
} sd_frm_state;

typedef struct {
    sd_frm_state *fst;
    int           fd;
    char          key[1024];
} sd_frm_staged_state;

#define SD_FRM_ST(inst)  ((sd_frm_state *) (inst)->state)

/* Bounded synchronous recall: ensure `key` is online in the MSS buffer. Returns 0
 * (online), or -1 (errno: ENOENT absent, EAGAIN still in-flight, EIO error). A
 * genuinely slow MSS would return EAGAIN and the cache tier would park the open on
 * the stage_engine waiter (the deferred async path); the stub completes at once. */
static int
frm_ensure_online(sd_frm_state *st, const char *key)
{
    off_t  sz = 0;
    time_t mt = 0;
    int    res = st->mss->residency(st->mss_ctx, key, &sz, &mt);

    if (res == XROOTD_RESIDENCY_ONLINE) {
        return 0;
    }
    if (res == XROOTD_RESIDENCY_ABSENT) {
        errno = ENOENT;
        return -1;
    }
    if (st->mss->recall_begin(st->mss_ctx, key) != 0) {
        errno = EIO;
        return -1;
    }
    /* One poll: a synchronous adapter (begin copied) is online now; an async MSS is
     * still staging, so return EAGAIN and let the HTTP plane answer 202 (the open
     * "parks" via client retry, §9.2). A later retry re-polls and completes. */
    {
        int p = st->mss->recall_poll(st->mss_ctx, key);

        if (p == 1) {
            return 0;
        }
        if (p < 0) {
            errno = EIO;
            return -1;
        }
    }
    errno = EAGAIN;
    return -1;
}

static xrootd_sd_obj_t *
sd_frm_open(xrootd_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_frm_state    *st = SD_FRM_ST(inst);
    xrootd_sd_obj_t *o;
    int              fd;

    (void) mode;
    if ((sd_flags & XROOTD_SD_O_WRITE) != 0) {
        /* writes go through the staged path (migrate); a direct write-open is not
         * supported on a nearline backend. */
        if (err_out) { *err_out = EROFS; }
        return NULL;
    }
    if (frm_ensure_online(st, path) != 0) {
        if (err_out) { *err_out = errno; }
        return NULL;
    }
    fd = st->mss->open_online(st->mss_ctx, path);
    if (fd < 0) {
        if (err_out) { *err_out = errno ? errno : EIO; }
        return NULL;
    }
    o = calloc(1, sizeof(*o));
    if (o == NULL) {
        (void) close(fd);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    o->driver     = inst->driver;
    o->inst       = inst;
    o->fd         = fd;
    o->heap_shell = 1;
    {
        struct stat sb;
        if (fstat(fd, &sb) == 0) {
            o->snap.size   = sb.st_size;
            o->snap.mtime  = sb.st_mtime;
            o->snap.mode   = sb.st_mode;
            o->snap.is_reg = 1;
        }
    }
    return o;
}

static ngx_int_t
sd_frm_close(xrootd_sd_obj_t *obj)
{
    if (obj == NULL) {
        return NGX_OK;
    }
    if (obj->fd >= 0) {
        (void) close(obj->fd);
        obj->fd = -1;
    }
    if (obj->heap_shell) {
        free(obj);
    }
    return NGX_OK;
}

static ssize_t
sd_frm_pread(xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    return pread(obj->fd, buf, len, off);
}

static ngx_int_t
sd_frm_fstat(xrootd_sd_obj_t *obj, xrootd_sd_stat_t *out)
{
    struct stat sb;

    if (fstat(obj->fd, &sb) != 0) {
        return NGX_ERROR;
    }
    ngx_memzero(out, sizeof(*out));
    out->size   = sb.st_size;
    out->mtime  = sb.st_mtime;
    out->ctime  = sb.st_ctime;
    out->mode   = sb.st_mode;
    out->ino    = sb.st_ino;
    out->is_reg = 1;
    return NGX_OK;
}

static ngx_int_t
sd_frm_stat(xrootd_sd_instance_t *inst, const char *path, xrootd_sd_stat_t *out)
{
    sd_frm_state *st = SD_FRM_ST(inst);
    off_t         sz = 0;
    time_t        mt = 0;
    int           res = st->mss->residency(st->mss_ctx, path, &sz, &mt);

    if (res == XROOTD_RESIDENCY_ABSENT) {
        return NGX_ERROR;            /* ENOENT - errno set by the caller's mapping */
    }
    ngx_memzero(out, sizeof(*out));
    out->size   = sz;
    out->mtime  = mt;
    out->mode   = S_IFREG | 0644;
    out->is_reg = 1;
    return NGX_OK;
}

/* Residency (the VFS residency seam, phase-64 §9) — classify `key` via the MSS
 * adapter WITHOUT initiating a recall, mapping the adapter's residency model onto
 * the SD residency enum the protocol handlers consume. ABSENT ⇒ LOST (errno ENOENT
 * so the seam can surface a missing object); ONLINE/NEARLINE/OFFLINE pass through. */
static ngx_int_t
sd_frm_residency(xrootd_sd_instance_t *inst, const char *key,
                 xrootd_sd_residency_t *out)
{
    sd_frm_state *st = SD_FRM_ST(inst);
    off_t         sz = 0;
    time_t        mt = 0;
    int           res = st->mss->residency(st->mss_ctx, key, &sz, &mt);

    switch (res) {
    case XROOTD_RESIDENCY_ONLINE:   *out = XROOTD_SD_RES_ONLINE;   break;
    case XROOTD_RESIDENCY_NEARLINE: *out = XROOTD_SD_RES_NEARLINE; break;
    case XROOTD_RESIDENCY_OFFLINE:  *out = XROOTD_SD_RES_OFFLINE;  break;
    default:                        errno = ENOENT; return NGX_ERROR;  /* ABSENT */
    }
    return NGX_OK;
}

static ngx_int_t
sd_frm_recall(xrootd_sd_instance_t *inst, const char *key, char reqid_out[40])
{
    sd_frm_state *st = SD_FRM_ST(inst);

    if (reqid_out != NULL) {
        reqid_out[0] = '\0';         /* synchronous recall: no parking handle */
    }
    if (frm_ensure_online(st, key) == 0) {
        return NGX_OK;               /* online now - the cache tier does a normal fill */
    }
    return (errno == EAGAIN) ? NGX_AGAIN : NGX_ERROR;
}

/* ---- migrate via the staged-write path (online buffer -> tape on commit) ---- */

static xrootd_sd_staged_t *
sd_frm_staged_open(xrootd_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_frm_state        *st = SD_FRM_ST(inst);
    sd_frm_staged_state *ss;
    xrootd_sd_staged_t  *h;
    int                  fd;

    fd = st->mss->create_online(st->mss_ctx, final_path, mode);
    if (fd < 0) {
        if (err_out) { *err_out = errno ? errno : EIO; }
        return NULL;
    }
    ss = calloc(1, sizeof(*ss));
    h  = calloc(1, sizeof(*h));
    if (ss == NULL || h == NULL) {
        (void) close(fd);
        free(ss);
        free(h);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    ss->fst = st;
    ss->fd  = fd;
    ngx_cpystrn((u_char *) ss->key, (u_char *) final_path, sizeof(ss->key));
    h->inst  = inst;
    h->state = ss;
    return h;
}

static ssize_t
sd_frm_staged_write(xrootd_sd_staged_t *st, const void *buf, size_t len, off_t off)
{
    sd_frm_staged_state *ss = st->state;

    return pwrite(ss->fd, buf, len, off);
}

static ngx_int_t
sd_frm_staged_commit(xrootd_sd_staged_t *st, int noreplace)
{
    sd_frm_staged_state *ss = st->state;
    int                  rc;

    (void) noreplace;
    if (ss->fd >= 0) {
        (void) close(ss->fd);
        ss->fd = -1;
    }
    /* Publish: migrate the online-buffer object to tape. */
    rc = ss->fst->mss->migrate(ss->fst->mss_ctx, ss->key);
    free(ss);
    free(st);
    return (rc == 0) ? NGX_OK : NGX_ERROR;
}

static void
sd_frm_staged_abort(xrootd_sd_staged_t *st)
{
    sd_frm_staged_state *ss = st->state;

    if (ss->fd >= 0) {
        (void) close(ss->fd);
        ss->fd = -1;
    }
    (void) ss->fst->mss->purge(ss->fst->mss_ctx, ss->key);
    free(ss);
    free(st);
}

static const xrootd_sd_driver_t xrootd_sd_frm_driver = {
    .name = "frm",
    .caps = XROOTD_SD_CAP_NEARLINE | XROOTD_SD_CAP_RANGE_READ
          | XROOTD_SD_CAP_RANDOM_WRITE | XROOTD_SD_CAP_FD,
    .open          = sd_frm_open,
    .close         = sd_frm_close,
    .pread         = sd_frm_pread,
    .fstat         = sd_frm_fstat,
    .stat          = sd_frm_stat,
    .recall        = sd_frm_recall,
    .residency     = sd_frm_residency,
    .staged_open   = sd_frm_staged_open,
    .staged_write  = sd_frm_staged_write,
    .staged_commit = sd_frm_staged_commit,
    .staged_abort  = sd_frm_staged_abort,
};

xrootd_sd_instance_t *
xrootd_sd_frm_create(const char *adapter, const char *location, ngx_log_t *log)
{
    xrootd_sd_instance_t *inst;
    sd_frm_state         *st;
    stub_ctx_t           *sc;

    if (location == NULL || location[0] == '\0') {
        errno = EINVAL;
        return NULL;
    }
    inst = calloc(1, sizeof(*inst));
    st   = calloc(1, sizeof(*st));
    if (inst == NULL || st == NULL) {
        free(inst);
        free(st);
        errno = ENOMEM;
        return NULL;
    }
    st->log = log;

    /* "exec" drives a real HSM via $XROOTD_FRM_STAGECMD (the classic FRM model). */
    if (adapter != NULL && ngx_strcmp(adapter, "exec") == 0) {
        const char *cmd = getenv("XROOTD_FRM_STAGECMD");

        if (cmd == NULL || cmd[0] == '\0') {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "xrootd frm: the \"exec\" MSS adapter needs $XROOTD_FRM_STAGECMD "
                "(the stage command); falling back to the built-in stub");
        } else {
            exec_ctx_t *ec = calloc(1, sizeof(*ec));

            if (ec == NULL) {
                free(inst);
                free(st);
                errno = ENOMEM;
                return NULL;
            }
            ngx_cpystrn((u_char *) ec->base, (u_char *) location, sizeof(ec->base));
            ngx_cpystrn((u_char *) ec->stagecmd, (u_char *) cmd,
                        sizeof(ec->stagecmd));
            ec->log     = log;
            st->mss     = &xrootd_mss_exec_adapter;
            st->mss_ctx = ec;
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd frm: exec MSS adapter (stagecmd=%s, online buffer=%s)",
                cmd, location);
        }
    }

    /* Default / fallback: the built-in local-dir stub simulator. */
    if (st->mss == NULL) {
        const char *d;

        if (adapter != NULL && adapter[0] != '\0'
            && ngx_strcmp(adapter, "stub") != 0
            && ngx_strcmp(adapter, "exec") != 0)
        {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "xrootd frm: MSS adapter \"%s\" is not yet implemented "
                "(phase-64 SP5: hpss/cta); using the built-in stub", adapter);
        }
        sc = calloc(1, sizeof(*sc));
        if (sc == NULL) {
            free(inst);
            free(st);
            errno = ENOMEM;
            return NULL;
        }
        ngx_cpystrn((u_char *) sc->base, (u_char *) location, sizeof(sc->base));
        sc->log = log;
        /* Test/dev knob: simulate MSS recall latency so the async park (202) path
         * is exercisable with the stub. 0 (default) = synchronous recall. */
        d = getenv("XROOTD_FRM_STUB_RECALL_DELAY_MS");
        sc->recall_delay_ms = (d != NULL && d[0] != '\0')
            ? (int) ngx_atoi((u_char *) d, ngx_strlen(d)) : 0;
        if (sc->recall_delay_ms < 0) {
            sc->recall_delay_ms = 0;
        }
        st->mss     = &xrootd_mss_stub_adapter;
        st->mss_ctx = sc;
    }

    inst->driver = &xrootd_sd_frm_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = st;
    return inst;
}

void
xrootd_sd_frm_destroy(xrootd_sd_instance_t *inst)
{
    sd_frm_state *st;

    if (inst == NULL) {
        return;
    }
    st = inst->state;
    if (st != NULL) {
        if (st->mss != NULL && st->mss->destroy != NULL) {
            st->mss->destroy(st->mss_ctx);
        }
        free(st);
    }
    free(inst);
}
