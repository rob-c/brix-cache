/*
 * sd_frm_arc_seal.c — the dataset archiver's write side (2.0 F3 backup queue)
 *
 * WHAT: arc_migrate / arc_create_online / arc_seal — the adapter slots that
 *       turn a completion-marker commit into an archive seal — and the
 *       PENDING state between them.
 *
 * WHY:  the OssArc backup queue (parity audit §3.5, readiness axis (e) F3).
 *       Sealing composes every member into one archive and ships it; on a
 *       real tape tier that is minutes of work. Before F3 the marker's commit
 *       ran the whole seal inline on the client's close, so the client hung
 *       for the duration and a crash mid-seal left an unsealed dataset that
 *       nothing would ever revisit. Now migrate(marker) only ANSWERS
 *       BRIX_MSS_MIGRATE_DEFERRED and the frm driver (sd_frm_staged.c) hands
 *       the seal to the durable stage engine (kind archive), which drives
 *       arc_seal() off the event loop, retries a transient failure on the
 *       brix_frm_fail_backoff sweep, replays it after a restart and
 *       dead-letters it at brix_frm_fail_retries.
 *
 * HOW:  a dataset is PENDING from the moment its marker enters the online
 *       buffer (create_online accepted it) until the sidecar index exists
 *       (arc_sealed). Members freeze at the marker's acceptance, not at the
 *       seal: create_online refuses a member of a pending or sealed dataset
 *       EPERM and a second marker EEXIST, so nothing slips in between the
 *       marker and the archive. arc_seal(marker) composes (arc_compose,
 *       sd_frm_arc_store.c); an already-sealed dataset answers 0 (an
 *       idempotent replay), a non-marker key EINVAL, a marker whose online
 *       copy is gone ENOENT (withdrawn by the operator: nothing to seal).
 */

#include "sd_frm_arc_internal.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

/* Is the online copy of `key` present in the buffer? */
static int
arc_online(const arc_ctx_t *c, const char *key)
{
    char path[PATH_MAX];

    return frm_online_path(c->base, key, path, sizeof(path)) == 0
           && access(path, F_OK) == 0;
}

int
arc_pending(const arc_ctx_t *c, const char *ds)
{
    char marker[BRIX_ZIP_NAME_MAX + sizeof(BRIX_ARC_MARKER) + 1];

    if (arc_sealed(c, ds)) {
        return 0;
    }
    if (snprintf(marker, sizeof(marker), "%s/%s", ds, BRIX_ARC_MARKER)
        >= (int) sizeof(marker))
    {
        return 0;
    }
    return arc_online(c, marker);
}

int
arc_migrate(void *mss, const char *key)
{
    arc_ctx_t *c = mss;
    arc_key_t  k;

    switch (arc_classify(c, key, &k)) {
    case ARC_KEY_RESERVED:
        errno = EINVAL;
        return -1;
    case ARC_KEY_MEMBER:
        return 0;                       /* deferred to the completion marker */
    case ARC_KEY_MARKER:
        return BRIX_MSS_MIGRATE_DEFERRED; /* the driver queues arc_seal()   */
    default:
        return c->inner->migrate(c->ictx, key);
    }
}

int
arc_create_online(void *mss, const char *key, mode_t mode)
{
    arc_ctx_t *c = mss;
    arc_key_t  k;

    switch (arc_classify(c, key, &k)) {
    case ARC_KEY_RESERVED:
        errno = EINVAL;
        return -1;
    case ARC_KEY_MEMBER:
        if (arc_sealed(c, k.ds) || arc_pending(c, k.ds)) {
            errno = EPERM;              /* a sealed or sealing dataset is immutable */
            return -1;
        }
        break;
    case ARC_KEY_MARKER:
        if (arc_sealed(c, k.ds) || arc_pending(c, k.ds)) {
            errno = EEXIST;
            return -1;
        }
        break;
    default:
        break;
    }
    return c->inner->create_online(c->ictx, key, mode);
}

int
arc_seal(void *mss, const char *key)
{
    arc_ctx_t *c = mss;
    arc_key_t  k;

    if (arc_classify(c, key, &k) != ARC_KEY_MARKER) {
        errno = EINVAL;
        return -1;
    }
    if (arc_sealed(c, k.ds)) {
        return 0;                       /* replayed after the seal landed */
    }
    if (!arc_online(c, key)) {
        errno = ENOENT;                 /* marker withdrawn: nothing to seal */
        return -1;
    }
    return arc_compose(c, &k);
}
