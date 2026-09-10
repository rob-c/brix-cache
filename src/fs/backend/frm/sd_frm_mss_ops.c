/*
 * sd_frm_mss_ops.c — the online-buffer vtable ops shared by every real-HSM MSS
 * adapter (exec + lib), implemented once against frm_mss_head_t.
 *
 * Moved verbatim out of sd_frm_stub.c on 2026-09-05 (phase-115 W3.2) when that
 * file reached the 600-line cap (coding-standards §1); the stub adapter keeps
 * its own local-directory ops there. Adds the W3.2 `on_tape` probe the purge
 * engine asks before releasing an online copy.
 */

#include "sd_frm_mss.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ============ shared online-buffer vtable ops (exec + lib adapters) ============
 *
 * WHAT: The whole brix_mss_adapter_t surface except destroy, implemented once
 *       against the frm_mss_head_t every real-HSM adapter context starts with.
 * WHY:  The exec and lib adapters were line-for-line clones that differed only
 *       in HOW an MSS verb runs (posix_spawn of the stage command vs a dlsym'd
 *       in-process call). That one difference is now the head's `invoke`
 *       callback; everything else — resolve <base>/.online/<key>, the local
 *       stat/access/open/unlink discipline, mkparents before a recall — is
 *       stated once here so the two transports cannot drift.
 * HOW:  Each op resolves the online path, does its local-buffer work, and
 *       calls the MSS only through head->invoke(verb, key, online).
 */

int
frm_online_path(const char *base, const char *key, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/.online/%s", base,
                     (key[0] == '/') ? key + 1 : key);

    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

int
frm_mss_residency(void *mss, const char *key, off_t *size_out, time_t *mtime_out)
{
    frm_mss_head_t *h = mss;
    char            online[PATH_MAX];
    struct stat     sb;

    if (frm_online_path(h->base, key, online, sizeof(online)) == 0
        && stat(online, &sb) == 0)
    {
        if (size_out)  { *size_out = sb.st_size; }
        if (mtime_out) { *mtime_out = sb.st_mtime; }
        return BRIX_RESIDENCY_ONLINE;
    }
    /* Ask the MSS: 0 = on tape (offline), non-zero = absent. The size is
     * unknown until recalled; the cache fill restats the online buffer. */
    if (h->invoke(mss, "exists", key, "") == 0) {
        if (size_out)  { *size_out = 0; }
        if (mtime_out) { *mtime_out = time(NULL); }
        return BRIX_RESIDENCY_OFFLINE;
    }
    return BRIX_RESIDENCY_ABSENT;
}

/* The six path-resolving ops share one body: resolve <base>/.online/<key>,
 * then do the op's local-buffer work + MSS invoke. A resolve failure is
 * ENAMETOOLONG/-1 for every op except purge, which stays best-effort (it still
 * offers the MSS-side drop and reports success, matching the old adapters). */
typedef enum {
    MSS_OP_RECALL_BEGIN,
    MSS_OP_RECALL_POLL,
    MSS_OP_MIGRATE,
    MSS_OP_PURGE,
    MSS_OP_OPEN,
    MSS_OP_CREATE,
} mss_op_t;

/* One MSS verb, with a DETERMINISTIC errno on failure (2.0, 2026-09-09).
 *
 * The invoke contract is "0 or non-zero" -- a stage command that exits 1 sets
 * no errno at all, and the runner it goes through may leave one of its own
 * behind (the reparented agent's waitpid loses the race with nginx's SIGCHLD
 * handler and leaves ECHILD; an internal open leaves ENOENT). Callers up the
 * stack DO read errno: brix_sd_frm_seal's caller maps it through
 * stage_seal_drop_reason(), where a stale ENOENT means "the marker was
 * withdrawn" and DROPS a journaled archive record that should have been
 * retried and finally dead-lettered. A verb that fails without a reason of its
 * own therefore reports EIO: an MSS-side error, retryable, never a drop. */
static int
mss_invoke_verb(frm_mss_head_t *h, void *mss, const char *verb,
    const char *key, const char *online)
{
    errno = 0;
    if (h->invoke(mss, verb, key, online) == 0) {
        return 0;
    }
    if (errno == 0) {
        errno = EIO;
    }
    return -1;
}

static int
mss_online_op(void *mss, const char *key, mss_op_t op, mode_t mode)
{
    frm_mss_head_t *h = mss;
    char            online[PATH_MAX];

    if (frm_online_path(h->base, key, online, sizeof(online)) != 0) {
        if (op == MSS_OP_PURGE) {
            (void) h->invoke(mss, "purge", key, "");
            return 0;
        }
        errno = ENAMETOOLONG;
        return -1;
    }

    switch (op) {
    case MSS_OP_RECALL_BEGIN:
        if (access(online, F_OK) == 0) {
            return 0;                        /* already online */
        }
        frm_mkparents(online);               /* the MSS writes the online buffer */
        return mss_invoke_verb(h, mss, "recall", key, online);
    case MSS_OP_RECALL_POLL:
        return (access(online, F_OK) == 0) ? 1 : 0;
    case MSS_OP_MIGRATE:
        return mss_invoke_verb(h, mss, "migrate", key, online);
    case MSS_OP_PURGE:
        (void) unlink(online);
        (void) h->invoke(mss, "purge", key, "");   /* best-effort MSS-side drop */
        return 0;
    case MSS_OP_OPEN:
        return open(online, O_RDONLY | O_CLOEXEC);
    case MSS_OP_CREATE:
        frm_mkparents(online);
        return open(online, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC,
                    mode ? mode : 0644);
    }
    return -1;
}

int
frm_mss_recall_begin(void *mss, const char *key)
{
    return mss_online_op(mss, key, MSS_OP_RECALL_BEGIN, 0);
}

int
frm_mss_recall_poll(void *mss, const char *key)
{
    return mss_online_op(mss, key, MSS_OP_RECALL_POLL, 0);
}

int
frm_mss_migrate(void *mss, const char *key)
{
    return mss_online_op(mss, key, MSS_OP_MIGRATE, 0);
}

int
frm_mss_purge(void *mss, const char *key)
{
    return mss_online_op(mss, key, MSS_OP_PURGE, 0);
}

int
frm_mss_open_online(void *mss, const char *key)
{
    return mss_online_op(mss, key, MSS_OP_OPEN, 0);
}

int
frm_mss_create_online(void *mss, const char *key, mode_t mode)
{
    return mss_online_op(mss, key, MSS_OP_CREATE, mode);
}

/* Phase-107 C3, shared-head form (exec/lib adapters): the only LOCAL artifact
 * of a publish is the online-buffer copy — flush its parent's entry. Tape-side
 * durability belongs to the real MSS behind `invoke`. */
int
frm_mss_sync_publish(void *mss, const char *key)
{
    frm_mss_head_t *h = mss;
    char             online[PATH_MAX];

    if (frm_online_path(h->base, key, online, sizeof(online)) != 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return frm_dirsync_parent(online);
}

/* Phase-115 W3.2: 1 iff the MSS holds a durable copy of `key` (the `exists`
 * verb answers 0), 0 when it does not. The online buffer is deliberately NOT
 * consulted — this is the "safe to release the buffer copy" question, and an
 * ONLINE object whose migrate never completed must answer 0. */
int
frm_mss_on_tape(void *mss, const char *key)
{
    frm_mss_head_t *h = mss;

    return (h->invoke(mss, "exists", key, "") == 0) ? 1 : 0;
}
