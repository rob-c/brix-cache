/*
 * userns_broker_test.c — end-to-end test of the phase-40 impersonation broker
 * inside an UNPRIVILEGED user namespace (no real root required).
 *
 * WHAT: Drives the real privileged broker (src/auth/impersonate/broker.c) + worker
 *   client (client.c) + identity mapper (idmap.c) through the actual AF_UNIX wire
 *   protocol — including SCM_RIGHTS fd passing — and asserts the security
 *   properties that justify the whole design:
 *     - created files are owned by the MAPPED user (not the worker),
 *     - the mapped user's kernel DAC is ENFORCED (the broker dropped
 *       CAP_DAC_OVERRIDE), so a user without permission is denied at open,
 *     - supplementary-group membership is honoured (setgroups),
 *     - RESOLVE_BENEATH confinement still blocks "../" + symlink escapes,
 *     - unmapped / reserved-uid / below-min_uid principals are DENIED,
 *     - squash-to-default works,
 *     - interleaved identities never leak credentials (no setfsuid bleed),
 *     - rename/link/unlink/chmod/truncate behave under impersonation.
 *
 * WHY a user namespace: the assertions require files owned by *several distinct
 *   uids* and the broker switching between them — normally root-only.  An
 *   unprivileged user namespace with a subuid RANGE map (newuidmap) makes the
 *   test process in-ns root over a private range of uids, so the broker can
 *   genuinely setfsuid() to mapped users with zero real privilege.  This is why
 *   the test lives in a SEPARATE sub-folder: it needs userns + newuidmap +
 *   /etc/subuid, which the main pytest suite does not.
 *
 * HOW: parent fork()s a child that unshare(CLONE_NEWUSER|CLONE_NEWNS)es and
 *   pauses; the parent runs newuidmap/newgidmap against it (inside-0 -> caller,
 *   inside-1.. -> subuid range) then releases it.  The child becomes in-ns root,
 *   makes its mounts private, bind-mounts a fake /etc/passwd + /etc/group (so
 *   getpwnam resolves the test principals to in-ns uids with NO nss_wrapper),
 *   builds an export tree, forks the broker, and runs the client assertions.
 *   Missing userns/newuidmap/subuid -> prints "SKIP: ..." and exits 0.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "impersonate.h"
#include "impersonate_proto.h"

/* In-ns test uids/gids (well inside the subuid range). */
#define UID_ALICE 1001
#define GID_ALICE 1001
#define UID_BOB   1002
#define GID_BOB   1002
#define GID_SHARED 1500

#define SKIP_CODE 42

/* ------------------------------------------------------------------ */
/* nginx symbol shims (so we can link the three .o without libngxcore) */
/* ------------------------------------------------------------------ */

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
                   const char *fmt, ...)
{
    /* Surface broker/idmap diagnostics to stderr to aid failure triage. */
    va_list ap;
    (void) log;
    if (level > 5 /* > NGX_LOG_NOTICE-ish */) {
        return;
    }
    fprintf(stderr, "[ngx] ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (err) {
        fprintf(stderr, " (errno=%d %s)", err, strerror(err));
    }
    fputc('\n', stderr);
}

u_char *
ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }
    while (--n) {
        *dst = *src;
        if (*dst == '\0') {
            return dst;
        }
        dst++;
        src++;
    }
    *dst = '\0';
    return dst;
}

/* ------------------------------------------------------------------ */
/* Assertion bookkeeping                                               */
/* ------------------------------------------------------------------ */

static int g_pass, g_fail;

#define OKAY(cond, msg)                                                        \
    do {                                                                       \
        if (cond) {                                                            \
            g_pass++;                                                          \
            fprintf(stderr, "PASS: %s\n", (msg));                             \
        } else {                                                               \
            g_fail++;                                                          \
            fprintf(stderr, "FAIL: %s (errno=%d %s)\n", (msg), errno,         \
                    strerror(errno));                                          \
        }                                                                      \
    } while (0)

/* ------------------------------------------------------------------ */
/* Small process / fs helpers                                          */
/* ------------------------------------------------------------------ */

/* Run argv[0] to completion; returns its exit status, or -1 if it couldn't run. */
static int
run_cmd(char *const argv[])
{
    pid_t pid = fork();
    int   st;

    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    if (waitpid(pid, &st, 0) < 0) {
        return -1;
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Map the paused child: inside-0 -> caller uid, inside-1.. -> subuid range. */
static int
apply_maps(pid_t child)
{
    char pidbuf[32], ru[32], rg[32];
    int  rc;

    snprintf(pidbuf, sizeof(pidbuf), "%d", (int) child);
    snprintf(ru, sizeof(ru), "%u", (unsigned) getuid());
    snprintf(rg, sizeof(rg), "%u", (unsigned) getgid());

    {
        char *uargv[] = { "newuidmap", pidbuf, "0", ru, "1",
                          "1", "100000", "65536", NULL };
        rc = run_cmd(uargv);
        if (rc != 0) {
            return -1;
        }
    }
    {
        char *gargv[] = { "newgidmap", pidbuf, "0", rg, "1",
                          "1", "100000", "65536", NULL };
        rc = run_cmd(gargv);
        if (rc != 0) {
            return -1;
        }
    }
    return 0;
}

/* Write a whole string to a new file (in-ns root). Returns 0/-1. */
static int
write_file(const char *path, const char *data, mode_t mode)
{
    int     fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    ssize_t n;

    if (fd < 0) {
        return -1;
    }
    n = write(fd, data, strlen(data));
    close(fd);
    return (n == (ssize_t) strlen(data)) ? 0 : -1;
}

/* mkdir + chown + chmod a path under the export tree. */
static int
make_dir(const char *path, uid_t uid, gid_t gid, mode_t mode)
{
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    if (chown(path, uid, gid) != 0) {
        return -1;
    }
    return chmod(path, mode);
}

/* Create + bind a 0600 AF_UNIX listening socket at `path`. Returns lfd or -1. */
static int
make_listen(const char *path)
{
    struct sockaddr_un addr;
    int                lfd;

    lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) {
        return -1;
    }
    unlink(path);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (bind(lfd, (struct sockaddr *) &addr, sizeof(addr)) != 0
        || listen(lfd, 16) != 0)
    {
        close(lfd);
        return -1;
    }
    chmod(path, 0600);
    return lfd;
}

/*
 * Fork a broker serving `rootfd` on `sockpath`.  default_user: squash account
 * (NULL/"" => deny on miss).  broker_uid/gid: drop the broker to this non-root
 * service account keeping CAP_SETUID/SETGID ((uid_t)-1 => stay in-ns root).
 * worker_uid: an extra forbidden-target uid ((uid_t)-1 => none).  Returns pid/-1.
 */
static pid_t
spawn_broker_ex(const char *sockpath, int rootfd, const char *default_user,
                uid_t broker_uid, gid_t broker_gid, uid_t worker_uid)
{
    int   lfd = make_listen(sockpath);
    pid_t pid;

    if (lfd < 0) {
        return -1;
    }
    /* Set the broker-user globals BEFORE fork so the broker inherits them. */
    brix_imp_broker_user_uid = broker_uid;
    brix_imp_broker_user_gid = broker_gid;

    pid = fork();
    if (pid < 0) {
        close(lfd);
        return -1;
    }
    if (pid == 0) {
        brix_idmap_conf_t c;
        memset(&c, 0, sizeof(c));
        c.min_uid    = 1000;
        c.cache_ttl  = 600;
        c.worker_uid = worker_uid;       /* forbid the worker uid as a target */
        if (default_user && default_user[0]) {
            c.default_user.data = (u_char *) default_user;
            c.default_user.len  = strlen(default_user);
        }
        brix_idmap_init(&c, NULL);
        /* broker_run drops caps (+ optional non-root drop) then serves. */
        _exit(brix_imp_broker_run(lfd, rootfd, NULL, NULL) == 0 ? 0 : 1);
    }
    close(lfd);
    /* Give the broker a moment to drop caps + reach accept(). */
    usleep(100 * 1000);
    return pid;
}

/* Default broker: in-ns root, deny-on-miss, no extra forbidden worker uid. */
static pid_t
spawn_broker(const char *sockpath, int rootfd, const char *default_user)
{
    return spawn_broker_ex(sockpath, rootfd, default_user,
                           (uid_t) -1, (gid_t) -1, (uid_t) -1);
}

/* stat a path under exportdir; returns 0 + fills st, or -1. */
static int
stat_under(const char *exportdir, const char *rel, struct stat *st)
{
    char p[4096];
    snprintf(p, sizeof(p), "%s/%s", exportdir, rel);
    return lstat(p, st);
}

/* ------------------------------------------------------------------ */
/* The actual assertions (run as in-ns root, broker(s) forked)         */
/* ------------------------------------------------------------------ */

static void
run_ownership_and_dac(const char *exportdir, const char *sock)
{
    struct stat st;
    int         fd;

    if (brix_imp_client_connect(sock, NULL) != NGX_OK) {
        OKAY(0, "client connects to deny-broker");
        return;
    }
    OKAY(1, "client connects to deny-broker");

    /* (B) OPEN O_CREAT as alice -> file owned by alice:alice. */
    brix_imp_set_principal("alice");
    fd = brix_imp_open("/alice/newfile", O_WRONLY | O_CREAT, 0644);
    OKAY(fd >= 0, "alice OPEN(O_CREAT) /alice/newfile succeeds");
    if (fd >= 0) {
        OKAY(write(fd, "hello", 5) == 5, "write to broker-returned fd works");
        close(fd);
    }
    OKAY(stat_under(exportdir, "alice/newfile", &st) == 0
             && st.st_uid == UID_ALICE && st.st_gid == GID_ALICE,
         "created file owned by mapped user alice (uid 1001:1001)");

    /* (C) STAT as alice reports alice ownership. */
    {
        struct stat bs;
        memset(&bs, 0, sizeof(bs));
        brix_imp_set_principal("alice");
        OKAY(brix_imp_stat("/alice/newfile", &bs, 0) == 0
                 && bs.st_uid == UID_ALICE && bs.st_size == 5,
             "broker STAT returns alice owner + size");
    }

    /* (D) MKDIR as alice. */
    brix_imp_set_principal("alice");
    OKAY(brix_imp_mkdir("/alice/adir", 0755) == 0, "alice MKDIR /alice/adir");
    OKAY(stat_under(exportdir, "alice/adir", &st) == 0
             && st.st_uid == UID_ALICE && S_ISDIR(st.st_mode),
         "mkdir owned by alice");

    /* (E) DAC ENFORCED: alice cannot write into bob's 0700 dir. */
    brix_imp_set_principal("alice");
    errno = 0;
    fd = brix_imp_open("/bobonly/x", O_WRONLY | O_CREAT, 0644);
    OKAY(fd < 0 && errno == EACCES,
         "alice DENIED in bob's 0700 dir (DAC enforced => broker dropped "
         "CAP_DAC_OVERRIDE)");
    if (fd >= 0) { close(fd); }

    /* ...but bob (the owner) CAN. */
    brix_imp_set_principal("bob");
    fd = brix_imp_open("/bobonly/x", O_WRONLY | O_CREAT, 0644);
    OKAY(fd >= 0, "bob ALLOWED in his own 0700 dir");
    if (fd >= 0) {
        close(fd);
        OKAY(stat_under(exportdir, "bobonly/x", &st) == 0
                 && st.st_uid == UID_BOB,
             "bob's file owned by bob (uid 1002)");
    }

    /* (I) supplementary group: alice is in 'shared'(1500); the dir is 0070. */
    brix_imp_set_principal("alice");
    fd = brix_imp_open("/shared/viagroup", O_WRONLY | O_CREAT, 0644);
    OKAY(fd >= 0, "alice ALLOWED in group-only dir via supplementary group");
    if (fd >= 0) { close(fd); }
    /* bob is NOT in 'shared' and others=---  => denied. */
    brix_imp_set_principal("bob");
    errno = 0;
    fd = brix_imp_open("/shared/nope", O_WRONLY | O_CREAT, 0644);
    OKAY(fd < 0 && errno == EACCES,
         "bob DENIED in group-only dir (not a member of 'shared')");
    if (fd >= 0) { close(fd); }

    /* (F) confinement: "../" and symlink escapes are blocked by the broker. */
    brix_imp_set_principal("alice");
    errno = 0;
    fd = brix_imp_open("/../../../../etc/passwd", O_RDONLY, 0);
    OKAY(fd < 0, "broker blocks ../ traversal escape");
    if (fd >= 0) { close(fd); }
    errno = 0;
    fd = brix_imp_open("/esc/passwd", O_RDONLY, 0);   /* /esc -> /etc symlink */
    OKAY(fd < 0, "broker blocks symlink escape (RESOLVE_BENEATH)");
    if (fd >= 0) { close(fd); }

    /* (G) unmapped principal => DENY (no passwd entry). */
    brix_imp_set_principal("mallory");
    errno = 0;
    fd = brix_imp_open("/alice/x", O_WRONLY | O_CREAT, 0644);
    OKAY(fd < 0 && errno == EACCES, "unmapped principal 'mallory' DENIED");
    if (fd >= 0) { close(fd); }

    /* (H) reserved/below-floor uids => DENY. */
    brix_imp_set_principal("rootish");        /* uid 0 in fake passwd */
    errno = 0;
    fd = brix_imp_open("/alice/x", O_WRONLY | O_CREAT, 0644);
    OKAY(fd < 0 && errno == EACCES, "uid-0 principal 'rootish' DENIED");
    if (fd >= 0) { close(fd); }
    brix_imp_set_principal("sys100");         /* uid 100 < min_uid 1000 */
    errno = 0;
    fd = brix_imp_open("/alice/x", O_WRONLY | O_CREAT, 0644);
    OKAY(fd < 0 && errno == EACCES, "below-min_uid principal 'sys100' DENIED");
    if (fd >= 0) { close(fd); }

    /* (L) rename / link / truncate / chmod / unlink under alice's own dir. */
    brix_imp_set_principal("alice");
    OKAY(brix_imp_rename("/alice/newfile", "/alice/renamed") == 0,
         "alice RENAME within own dir");
    OKAY(brix_imp_truncate("/alice/renamed", 2) == 0, "alice TRUNCATE");
    OKAY(stat_under(exportdir, "alice/renamed", &st) == 0 && st.st_size == 2,
         "truncate took effect (size==2)");
    OKAY(brix_imp_chmod("/alice/renamed", 0600) == 0, "alice CHMOD");
    OKAY(brix_imp_link("/alice/renamed", "/alice/hardlink") == 0,
         "alice LINK within own dir");
    OKAY(brix_imp_unlink("/alice/hardlink", 0) == 0, "alice UNLINK");
    OKAY(brix_imp_unlink("/alice/adir", 1) == 0, "alice RMDIR");
}

/* (K) concurrency: two interleaved identities never cross creds. */
static void
run_concurrency(const char *exportdir, const char *sock)
{
    const int ROUNDS = 60;
    pid_t     a, b;
    int       sta, stb, i, ok = 1;

    a = fork();
    if (a == 0) {
        brix_imp_client_connect(sock, NULL);
        brix_imp_set_principal("alice");
        for (i = 0; i < ROUNDS; i++) {
            char p[64];
            int  fd;
            snprintf(p, sizeof(p), "/alice/c_a_%d", i);
            fd = brix_imp_open(p, O_WRONLY | O_CREAT, 0644);
            if (fd >= 0) { close(fd); }
        }
        _exit(0);
    }
    b = fork();
    if (b == 0) {
        brix_imp_client_connect(sock, NULL);
        brix_imp_set_principal("bob");
        for (i = 0; i < ROUNDS; i++) {
            char p[64];
            int  fd;
            snprintf(p, sizeof(p), "/bob/c_b_%d", i);
            fd = brix_imp_open(p, O_WRONLY | O_CREAT, 0644);
            if (fd >= 0) { close(fd); }
        }
        _exit(0);
    }
    waitpid(a, &sta, 0);
    waitpid(b, &stb, 0);

    for (i = 0; i < ROUNDS; i++) {
        char        rel[64];
        struct stat st;
        snprintf(rel, sizeof(rel), "alice/c_a_%d", i);
        if (stat_under(exportdir, rel, &st) != 0 || st.st_uid != UID_ALICE) {
            ok = 0;
        }
        snprintf(rel, sizeof(rel), "bob/c_b_%d", i);
        if (stat_under(exportdir, rel, &st) != 0 || st.st_uid != UID_BOB) {
            ok = 0;
        }
    }
    OKAY(ok, "interleaved alice/bob: every file owned by the correct uid "
             "(no setfsuid credential leak)");
}

/*
 * Reserved-id floor (the "impossible to drop to uid/gid < 1000" guarantee).
 * A principal whose mapped PRIMARY GID is reserved, or who is a member of a
 * reserved SUPPLEMENTARY group, must be denied — and no file created — at BOTH
 * the mapping layer (clean deny) and the broker's setfsuid edge.  The broker must
 * stay alive (graceful deny, not a crash) for these normal denials.
 */
static void
run_reserved_id_floor(const char *exportdir, const char *sock)
{
    struct stat st;
    int         fd;

    if (brix_imp_client_connect(sock, NULL) != NGX_OK) {
        OKAY(0, "client connects for reserved-id floor checks");
        return;
    }

    /* primary gid 50 (< 1000) -> GRACEFUL deny (EACCES, not a broker death), no file. */
    brix_imp_set_principal("lowgid");
    errno = 0;
    fd = brix_imp_open("/pub/lowgid_file", O_WRONLY | O_CREAT, 0644);
    OKAY(fd < 0 && errno == EACCES, "reserved PRIMARY gid (50) -> denied (EACCES)");
    if (fd >= 0) { close(fd); }
    OKAY(stat_under(exportdir, "pub/lowgid_file", &st) != 0,
         "reserved PRIMARY gid -> NO file created");

    /* member of wheel (gid 10) -> GRACEFUL deny (EACCES), no file. */
    brix_imp_set_principal("sysmember");
    errno = 0;
    fd = brix_imp_open("/pub/sysmember_file", O_WRONLY | O_CREAT, 0644);
    OKAY(fd < 0 && errno == EACCES,
         "reserved SUPPLEMENTARY group (wheel/10) -> denied (EACCES)");
    if (fd >= 0) { close(fd); }
    OKAY(stat_under(exportdir, "pub/sysmember_file", &st) != 0,
         "reserved SUPPLEMENTARY group -> NO file created");

    /* The broker must still be alive (these are graceful denials): a legit alice
     * op right after must still succeed. */
    brix_imp_set_principal("alice");
    fd = brix_imp_open("/alice/after_floor_checks", O_WRONLY | O_CREAT, 0644);
    OKAY(fd >= 0, "broker still serving after reserved-id denials (not crashed)");
    if (fd >= 0) {
        close(fd);
        OKAY(stat_under(exportdir, "alice/after_floor_checks", &st) == 0
                 && st.st_uid == UID_ALICE,
             "post-denial alice op owned by alice");
    }
}

/*
 * Deny-lists: a forbidden TARGET account (high uid, e.g. nobody) and a member of
 * a forbidden privileged GROUP whose gid is >= the floor (docker, gid 1500) — both
 * denied even though their numeric ids pass the floor.  A control user still works.
 */
static void
run_deny_lists(const char *exportdir, const char *sock)
{
    struct stat st;
    int         fd;

    if (brix_imp_client_connect(sock, NULL) != NGX_OK) {
        OKAY(0, "client connects for deny-list checks");
        return;
    }

    /* forbidden user 'nobody' (uid 65534 >= floor, but on the forbidden_users list). */
    brix_imp_set_principal("nobody");
    errno = 0;
    fd = brix_imp_open("/pub/nobody_file", O_WRONLY | O_CREAT, 0644);
    OKAY(fd < 0 && errno == EACCES,
         "forbidden target account 'nobody' (uid>=floor) -> denied");
    if (fd >= 0) { close(fd); }
    OKAY(stat_under(exportdir, "pub/nobody_file", &st) != 0,
         "forbidden account -> NO file created");

    /* member of privileged group 'docker' (gid 1500 >= floor) -> denied by NAME. */
    brix_imp_set_principal("dockerite");
    errno = 0;
    fd = brix_imp_open("/pub/docker_file", O_WRONLY | O_CREAT, 0644);
    OKAY(fd < 0 && errno == EACCES,
         "member of high-gid privileged group 'docker' (1500) -> denied by name");
    if (fd >= 0) { close(fd); }

    /*
     * >32-group fail-CLOSED: 'manygroups' is in a forbidden group ('sudo', gid
     * 1700) that sits PAST the 32-slot getgrouplist cap — it MUST still be denied
     * (the deny-list must not fail open on group-list truncation).
     */
    brix_imp_set_principal("manygroups");
    errno = 0;
    fd = brix_imp_open("/pub/many_file", O_WRONLY | O_CREAT, 0644);
    OKAY(fd < 0 && errno == EACCES,
         "user in a forbidden group PAST the 32-group cap -> still denied "
         "(deny-list fails closed on truncation)");
    if (fd >= 0) { close(fd); }

    /* ...but a heavy-group user with NO forbidden group is NOT over-denied. */
    brix_imp_set_principal("manyok");
    fd = brix_imp_open("/pub/manyok_file", O_WRONLY | O_CREAT, 0644);
    OKAY(fd >= 0, "user with >32 groups but none forbidden -> still allowed "
                  "(no over-deny)");
    if (fd >= 0) { close(fd); }

    /* control: alice (no forbidden id) still works. */
    brix_imp_set_principal("alice");
    fd = brix_imp_open("/alice/after_denylist", O_WRONLY | O_CREAT, 0644);
    OKAY(fd >= 0, "control user still allowed after deny-list checks");
    if (fd >= 0) { close(fd); }
}

/* A broker that forbids the worker uid (=bob here): bob is refused, alice works. */
static void
run_worker_forbid(const char *exportdir, const char *sock)
{
    int fd;

    (void) exportdir;
    if (brix_imp_client_connect(sock, NULL) != NGX_OK) {
        OKAY(0, "client connects to worker-forbid broker");
        return;
    }
    brix_imp_set_principal("bob");          /* bob's uid == the forbidden worker uid */
    errno = 0;
    fd = brix_imp_open("/bob/wf", O_WRONLY | O_CREAT, 0644);
    OKAY(fd < 0 && errno == EACCES,
         "worker uid is a forbidden impersonation target -> denied");
    if (fd >= 0) { close(fd); }
    brix_imp_set_principal("alice");
    fd = brix_imp_open("/alice/wf", O_WRONLY | O_CREAT, 0644);
    OKAY(fd >= 0, "non-worker user still allowed on worker-forbid broker");
    if (fd >= 0) { close(fd); }
}

/*
 * Non-root broker: the broker drops its base uid to a non-root service account
 * (990) keeping only CAP_SETUID/SETGID, and STILL impersonates correctly — proving
 * the PR_SET_KEEPCAPS + setresuid + re-raise path works and nothing needs root.
 */
static void
run_broker_nonroot(const char *exportdir, const char *sock)
{
    struct stat st;
    int         fd;

    if (brix_imp_client_connect(sock, NULL) != NGX_OK) {
        OKAY(0, "client connects to non-root broker");
        return;
    }
    brix_imp_set_principal("alice");
    fd = brix_imp_open("/alice/nonroot", O_WRONLY | O_CREAT, 0644);
    OKAY(fd >= 0, "non-root broker (svc uid 990) still impersonates");
    if (fd >= 0) {
        close(fd);
        OKAY(stat_under(exportdir, "alice/nonroot", &st) == 0
                 && st.st_uid == UID_ALICE,
             "non-root broker: created file still owned by mapped user alice");
    }
}

/*
 * POSIX-extension ops (kXR_setattr/symlink/readlink) routed through the broker:
 * they must run as the mapped user (so a symlink is owned by them, chgrp/utimens
 * succeed on their own files, and DAC is enforced on another user's file).
 */
static void
run_posix_ext_ops(const char *exportdir, const char *sock)
{
    struct stat st;
    int         fd;

    if (brix_imp_client_connect(sock, NULL) != NGX_OK) {
        OKAY(0, "client connects for ext-ops");
        return;
    }

    brix_imp_set_principal("alice");
    fd = brix_imp_open("/alice/extfile", O_WRONLY | O_CREAT, 0644);
    OKAY(fd >= 0, "alice creates a file for ext-ops");
    if (fd >= 0) { close(fd); }

    /* SETATTR: chgrp to 'shared' (alice is a member) + set mtime — as alice. */
    {
        struct timespec ts[2];
        ts[0].tv_sec = 1000000; ts[0].tv_nsec = 0;
        ts[1].tv_sec = 2000000; ts[1].tv_nsec = 0;
        OKAY(brix_imp_setattr("/alice/extfile", 1, ts, 1,
                                (uid_t) -1, (gid_t) GID_SHARED) == 0,
             "alice SETATTR (chgrp shared + set times) as the mapped user");
        OKAY(stat_under(exportdir, "alice/extfile", &st) == 0
                 && st.st_gid == GID_SHARED && st.st_mtime == 2000000,
             "SETATTR took effect (gid=shared, mtime set)");
    }

    /* SYMLINK: created as alice, owned by alice. */
    OKAY(brix_imp_symlink("the-target-path", "/alice/slink") == 0,
         "alice SYMLINK /alice/slink");
    OKAY(stat_under(exportdir, "alice/slink", &st) == 0
             && S_ISLNK(st.st_mode) && st.st_uid == UID_ALICE,
         "symlink created and owned by mapped user alice");

    /* READLINK: read the target back through the broker (trailing payload). */
    {
        char    buf[256];
        ssize_t n = brix_imp_readlink("/alice/slink", buf, sizeof(buf));
        OKAY(n == (ssize_t) ngx_strlen("the-target-path")
                 && memcmp(buf, "the-target-path", (size_t) (n > 0 ? n : 0)) == 0,
             "READLINK returns the symlink target");
    }

    /* DAC: alice SETATTR on a file inside bob's 0700 dir -> denied. */
    {
        struct timespec ts[2];
        ts[0].tv_sec = 1; ts[0].tv_nsec = 0;
        ts[1].tv_sec = 1; ts[1].tv_nsec = 0;
        errno = 0;
        OKAY(brix_imp_setattr("/bobonly/x", 1, ts, 0,
                                (uid_t) -1, (gid_t) -1) != 0,
             "alice SETATTR inside bob's 0700 dir -> denied (DAC enforced)");
    }
}

/* (J) squash: a second broker with default_user=alice squashes unmapped. */
static void
run_squash(const char *exportdir, const char *sock)
{
    struct stat st;
    int         fd;

    if (brix_imp_client_connect(sock, NULL) != NGX_OK) {
        OKAY(0, "client connects to squash-broker");
        return;
    }
    brix_imp_set_principal("mallory");          /* unmapped -> squash to alice */
    fd = brix_imp_open("/alice/squashed", O_WRONLY | O_CREAT, 0644);
    OKAY(fd >= 0, "squash: unmapped principal allowed via default_user");
    if (fd >= 0) {
        close(fd);
        OKAY(stat_under(exportdir, "alice/squashed", &st) == 0
                 && st.st_uid == UID_ALICE,
             "squash: file owned by the default (alice) account");
    }
}

/* ------------------------------------------------------------------ */
/* Namespace setup + test orchestration (runs as in-ns root)           */
/* ------------------------------------------------------------------ */

static const char *FAKE_PASSWD =
    "root:x:0:0:root:/:/bin/sh\n"
    "alice:x:1001:1001:alice:/home/alice:/bin/sh\n"
    "bob:x:1002:1002:bob:/home/bob:/bin/sh\n"
    "sys100:x:100:100:sys:/:/bin/sh\n"
    "rootish:x:0:0:rootish:/:/bin/sh\n"
    /* uid ok (>=1000) but PRIMARY gid is reserved (<1000): must be denied. */
    "lowgid:x:1005:50:lowgid:/:/bin/sh\n"
    /* uid+gid ok but a SUPPLEMENTARY group is reserved (wheel, gid 10). */
    "sysmember:x:1006:1006:sysmember:/:/bin/sh\n"
    /* uid+gid ok and ALL ids >= floor, but member of 'docker' (gid 1500) — a
     * privileged group denied BY NAME even though its gid is >= the floor. */
    "dockerite:x:1007:1007:dockerite:/:/bin/sh\n"
    /* members of >32 groups: 'manygroups' has a forbidden group (sudo) PAST the
     * 32-slot getgrouplist cap; 'manyok' has many groups but none forbidden. */
    "manygroups:x:1008:1008:manygroups:/:/bin/sh\n"
    "manyok:x:1009:1009:manyok:/:/bin/sh\n"
    "nobody:x:65534:65534:nobody:/:/bin/sh\n";

static const char *FAKE_GROUP =
    "root:x:0:\n"
    "alice:x:1001:\n"
    "bob:x:1002:\n"
    "shared:x:1500:alice\n"
    "lowgidgrp:x:50:\n"
    "wheel:x:10:sysmember\n"
    /* a privileged group with a HIGH gid (>= floor, distinct from shared=1500):
     * only the name deny-list catches it, not the numeric floor. */
    "docker:x:1600:dockerite\n"
    "nogroup:x:65534:\n";

static int
in_ns_main(void)
{
    char  tmpl[] = "/tmp/imp_userns_XXXXXX";
    char *base;
    char  path[4096], exportdir[4096], sock1[4096], sock2[4096];
    char  passwd_path[4096], group_path[4096];
    int   rootfd;
    pid_t broker1, broker2;

    /* Become a clean in-ns root (real uid already maps to inside-0). */
    if (setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0) {
        fprintf(stderr, "SKIP: could not assume in-ns root: %s\n",
                strerror(errno));
        return SKIP_CODE;
    }
    {
        gid_t z = 0;
        setgroups(1, &z);
    }

    /* Private mounts so our bind-mounts are local to this namespace. */
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        fprintf(stderr, "SKIP: MS_PRIVATE remount failed: %s\n", strerror(errno));
        return SKIP_CODE;
    }

    base = mkdtemp(tmpl);
    if (base == NULL) {
        fprintf(stderr, "SKIP: mkdtemp failed: %s\n", strerror(errno));
        return SKIP_CODE;
    }
    snprintf(exportdir, sizeof(exportdir), "%s/export", base);
    snprintf(sock1, sizeof(sock1), "%s/deny.sock", base);
    snprintf(sock2, sizeof(sock2), "%s/squash.sock", base);
    snprintf(passwd_path, sizeof(passwd_path), "%s/passwd", base);
    snprintf(group_path, sizeof(group_path), "%s/group", base);

    /*
     * Build the group file = base entries + 40 filler groups (gid 2000..2039,
     * members manygroups+manyok) + a forbidden group 'sudo' (gid 1700, member
     * manygroups) appended LAST.  getgrouplist returns groups in file order, so
     * for 'manygroups' sudo lands well past the 32-slot cap — exercising the
     * fail-CLOSED full-set re-resolve.  'manyok' has 40 groups but none forbidden.
     */
    {
        char  grp[8192];
        size_t n = 0;
        int    fi;
        n += (size_t) snprintf(grp + n, sizeof(grp) - n, "%s", FAKE_GROUP);
        for (fi = 0; fi < 40; fi++) {
            n += (size_t) snprintf(grp + n, sizeof(grp) - n,
                                   "fill%d:x:%d:manygroups,manyok\n", fi, 2000 + fi);
        }
        n += (size_t) snprintf(grp + n, sizeof(grp) - n, "sudo:x:1700:manygroups\n");
        if (write_file(passwd_path, FAKE_PASSWD, 0644) != 0
            || write_file(group_path, grp, 0644) != 0)
        {
            fprintf(stderr, "SKIP: cannot write fake passwd/group\n");
            return SKIP_CODE;
        }
    }
    if (mount(passwd_path, "/etc/passwd", NULL, MS_BIND, NULL) != 0
        || mount(group_path, "/etc/group", NULL, MS_BIND, NULL) != 0)
    {
        fprintf(stderr, "SKIP: bind-mount of /etc/passwd|group failed: %s\n",
                strerror(errno));
        return SKIP_CODE;
    }

    /* Sanity: the bound passwd must resolve our principals to in-ns uids. */
    {
        struct passwd *pa = getpwnam("alice");
        if (pa == NULL || pa->pw_uid != UID_ALICE) {
            fprintf(stderr, "SKIP: getpwnam(alice) did not resolve via "
                            "bound /etc/passwd (nsswitch?)\n");
            return SKIP_CODE;
        }
    }

    /* Export tree + DAC fixtures. */
    if (make_dir(exportdir, 0, 0, 0755) != 0) {
        fprintf(stderr, "SKIP: export root setup failed: %s\n", strerror(errno));
        return SKIP_CODE;
    }
    snprintf(path, sizeof(path), "%s/alice", exportdir);
    make_dir(path, UID_ALICE, GID_ALICE, 0755);
    snprintf(path, sizeof(path), "%s/bob", exportdir);
    make_dir(path, UID_BOB, GID_BOB, 0755);
    snprintf(path, sizeof(path), "%s/bobonly", exportdir);
    make_dir(path, UID_BOB, GID_BOB, 0700);
    snprintf(path, sizeof(path), "%s/shared", exportdir);
    make_dir(path, 0, GID_SHARED, 0070);
    /* World-writable dir: a create here would SUCCEED if the reserved-id guard
     * were absent, so "no file created" proves the guard (not a perm error). */
    snprintf(path, sizeof(path), "%s/pub", exportdir);
    make_dir(path, 0, 0, 0777);
    snprintf(path, sizeof(path), "%s/esc", exportdir);
    if (symlink("/etc", path) != 0 && errno != EEXIST) {
        fprintf(stderr, "note: could not create esc symlink: %s\n",
                strerror(errno));
    }

    rootfd = open(exportdir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) {
        fprintf(stderr, "SKIP: cannot open export rootfd: %s\n", strerror(errno));
        return SKIP_CODE;
    }

    /* Broker #1: deny-on-miss.  Run ownership/DAC/confinement/deny + concurrency. */
    broker1 = spawn_broker(sock1, rootfd, NULL);
    if (broker1 < 0) {
        fprintf(stderr, "SKIP: could not spawn deny-broker\n");
        return SKIP_CODE;
    }
    run_ownership_and_dac(exportdir, sock1);
    run_reserved_id_floor(exportdir, sock1);
    run_deny_lists(exportdir, sock1);
    run_posix_ext_ops(exportdir, sock1);
    run_concurrency(exportdir, sock1);

    /* Broker #2: squash-to-alice. */
    broker2 = spawn_broker(sock2, rootfd, "alice");
    if (broker2 >= 0) {
        run_squash(exportdir, sock2);
    } else {
        OKAY(0, "spawn squash-broker");
    }

    /* Broker #3: forbids the worker uid (= bob, 1002). */
    {
        char  sock3[4096];
        pid_t broker3;
        snprintf(sock3, sizeof(sock3), "%s/wforbid.sock", base);
        broker3 = spawn_broker_ex(sock3, rootfd, NULL,
                                  (uid_t) -1, (gid_t) -1, (uid_t) UID_BOB);
        if (broker3 >= 0) {
            run_worker_forbid(exportdir, sock3);
            kill(broker3, SIGKILL);
            waitpid(broker3, NULL, 0);
        } else {
            OKAY(0, "spawn worker-forbid broker");
        }
    }

    /* Broker #4: drops to a non-root service account (uid/gid 990). */
    {
        char  sock4[4096];
        pid_t broker4;
        snprintf(sock4, sizeof(sock4), "%s/nonroot.sock", base);
        broker4 = spawn_broker_ex(sock4, rootfd, NULL,
                                  (uid_t) 990, (gid_t) 990, (uid_t) -1);
        if (broker4 >= 0) {
            run_broker_nonroot(exportdir, sock4);
            kill(broker4, SIGKILL);
            waitpid(broker4, NULL, 0);
        } else {
            OKAY(0, "spawn non-root broker");
        }
    }

    /* Tear down brokers. */
    kill(broker1, SIGKILL);
    waitpid(broker1, NULL, 0);
    if (broker2 >= 0) {
        kill(broker2, SIGKILL);
        waitpid(broker2, NULL, 0);
    }

    fprintf(stderr, "\n%d passed, %d failed\n", g_pass, g_fail);
    if (g_fail == 0) {
        fprintf(stderr, "ALL PASSED\n");
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Outer orchestration: unshare + map + release                        */
/* ------------------------------------------------------------------ */

int
main(void)
{
    int   ready[2], go[2];
    pid_t child;
    char  b;
    int   st;

    if (pipe(ready) != 0 || pipe(go) != 0) {
        fprintf(stderr, "SKIP: pipe failed\n");
        return 0;
    }

    child = fork();
    if (child < 0) {
        fprintf(stderr, "SKIP: fork failed\n");
        return 0;
    }

    if (child == 0) {
        close(ready[0]);
        close(go[1]);
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
            _exit(SKIP_CODE);            /* unprivileged userns unavailable */
        }
        if (write(ready[1], "R", 1) != 1) {
            _exit(SKIP_CODE);
        }
        if (read(go[0], &b, 1) != 1) {
            _exit(SKIP_CODE);            /* parent gave up (map failed) */
        }
        _exit(in_ns_main());
    }

    /* Parent: wait for the child to unshare, then install its id maps. */
    close(ready[1]);
    close(go[0]);
    if (read(ready[0], &b, 1) != 1) {
        waitpid(child, &st, 0);
        printf("SKIP: user namespace unavailable on this host\n");
        return 0;
    }
    if (apply_maps(child) != 0) {
        kill(child, SIGKILL);
        waitpid(child, &st, 0);
        printf("SKIP: newuidmap/newgidmap unavailable or /etc/subuid not "
               "configured for this user\n");
        return 0;
    }
    if (write(go[1], "G", 1) != 1) {
        kill(child, SIGKILL);
        waitpid(child, &st, 0);
        printf("SKIP: could not release child\n");
        return 0;
    }

    if (waitpid(child, &st, 0) < 0 || !WIFEXITED(st)) {
        printf("FAIL: test child did not exit cleanly\n");
        return 1;
    }
    if (WEXITSTATUS(st) == SKIP_CODE) {
        printf("SKIP: in-namespace prerequisites unmet (see stderr)\n");
        return 0;
    }
    if (WEXITSTATUS(st) == 0) {
        printf("ALL PASSED\n");
        return 0;
    }
    printf("FAILED\n");
    return 1;
}
