#ifndef BRIX_FS_BACKEND_CACHE_SD_CACHE_FOLLOW_H
#define BRIX_FS_BACKEND_CACHE_SD_CACHE_FOLLOW_H

/*
 * sd_cache_follow.h — serve-while-filling for the whole-file fill (audit §4.5).
 *
 * A reader that arrives while another reader's whole-file fill is still pumping
 * FOLLOWS that fill: it reads the staged (uncommitted) bytes up to the fill
 * frontier and is told to retry past it, instead of blocking until the fill
 * commits. Driver-private to the cache decorator; not part of sd_cache.h.
 */

#include "sd_cache_internal.h"   /* sd_cache_inst_state */

/* Publish the in-flight marker for `key`, naming the staged temp file the
 * frontier lives in. Best-effort and silent: a store with no local root, or a
 * staged plane with no physical path, simply publishes nothing and readers keep
 * today's wait-for-commit behaviour. Called by the fill spine once the staged
 * object exists, before the first byte is pumped. */
void sd_cache_follow_publish(sd_cache_inst_state *st, const char *key,
    const char *staged_path, off_t declared_size);

/* Arm serve-while-filling for `key` on the staged object `staged`, resolving its
 * physical path through the driver. Declines silently — leaving readers with
 * today's wait-for-commit behaviour — when the knob is off, when the staged
 * plane has no physical path (a remote store), or, SECURITY, when the fill runs
 * under any verify mode: a verifying fill's staged bytes are PROVISIONAL and
 * cache_fill_verify may still reject them as a digest mismatch or a broken
 * signature chain, by which time a follower would already have served them.
 * Only an unverified fill (BRIX_CACHE_VERIFY_OFF) is followable.
 *
 * `declared_size` is the source's size for the object. It is published because
 * the staged file's own st_size is NOT the final length: the phase-107 C5
 * admission reserve uses fallocate(FALLOC_FL_KEEP_SIZE), which claims blocks
 * without moving st_size, so st_size tracks the FRONTIER. A follower that
 * reported it would tell the client the object is short. 0 = unknown. */
void sd_cache_follow_arm(sd_cache_inst_state *st, const char *key,
    brix_sd_staged_t *staged, off_t declared_size);


/* Withdraw the marker for `key`. `aborted` != 0 means the fill FAILED: the
 * staged file is unlinked first so a follower's fstat sees st_nlink == 0 and
 * fails the read closed (EIO) rather than reporting the short staged file as a
 * clean EOF. Called AFTER a successful commit (the rename already happened) and
 * on every abort path. Best-effort and silent. */
void sd_cache_follow_withdraw(sd_cache_inst_state *st, const char *key,
    int aborted);

/* Open a follower on the in-flight fill of `key`. Returns a read object whose
 * pread serves staged bytes below the frontier, EAGAIN at it and EIO/ETIMEDOUT
 * when the fill dies, or NULL with *err_out = ENOENT when no fill is in flight
 * (the caller then runs its own fill). NULL whenever the policy knob is off,
 * and — SECURITY, independently of the publisher — whenever the export runs
 * under any verify mode: arm() never publishes there, so a marker seen under a
 * verify policy is stale or planted, and following it would stream bytes no
 * digest ever checked to a client whose export demands verification. */
brix_sd_obj_t *sd_cache_follow_open(sd_cache_inst_state *st, const char *key,
    int *err_out);

#endif /* BRIX_FS_BACKEND_CACHE_SD_CACHE_FOLLOW_H */
