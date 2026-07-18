/*
 * pblock_snap.h — F6 snapshots / instant fixture reset for the pblock driver.
 *
 * WHAT: A named point-in-time copy of the whole catalog namespace (the `objects`
 *       and `xattrs` rows), with every referenced blob's refcount held up so the
 *       block store is shared, not copied. Take is O(metadata); restore swaps the
 *       live namespace back to a snapshot's rows; drop releases a snapshot's held
 *       references. The block bytes are shared through the F10 `blobs` refcount
 *       table — so snapshots BUILD ON F10 (the `snap=1` opt auto-arms refcounted
 *       blobs; without them a delete between take and restore would physically
 *       remove blocks a snapshot still needs).
 *
 * WHY:  Millisecond fixture reset. A populated export can be snapshotted, mutated
 *       destructively by a test, and restored byte-identical in one metadata
 *       transaction — no fixture re-upload. Clone-from-snapshot gives per-test
 *       isolated exports over one shared block store.
 *
 * HOW:  Single-table design (`snapshots` + `snap_objects` + `snap_xattrs`, the
 *       snapshot name a bound column, never an interpolated identifier) so a name
 *       can never inject SQL; the name is additionally validated to a strict
 *       charset. Take/restore/drop run inside BEGIN IMMEDIATE and recompute every
 *       blob's refcount from (live objects + all snapshot copies) so the F10
 *       release path stays exact. Restore refuses (EBUSY) while any regular-file
 *       handle is open on the export (st->open_files), and clears the nscache
 *       (it replaces the whole namespace). Control is driven through a reserved
 *       namespace on the export root — `mkdir /.pblock/snap/<name>` takes,
 *       `mkdir /.pblock/restore/<name>` restores, `rmdir /.pblock/snap/<name>`
 *       drops — intercepted in the driver's mkdir/unlink before any real catalog
 *       work, so it needs no wire-protocol change. Reached only through the inner
 *       (service) mkdir/unlink paths, so snapshot control is service-only.
 *       ngx-free (libc + sqlite3); BRIX_HAVE_SQLITE-gated like the rest of pblock.
 *
 * Requires: pblock_store.h (pblock_state_t) before inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_SNAP_H
#define BRIX_FS_BACKEND_PBLOCK_SNAP_H

#include "pblock_store.h"

/* Create the snapshot tables (idempotent). 0, or -1/errno. */
int pblock_snap_init(pblock_state_t *st);

/* 1 iff `name` is a legal snapshot name ([A-Za-z0-9_.-], 1..64, not . or ..). */
int pblock_snap_valid_name(const char *name);

/* Take a snapshot named `name` of the current namespace. 0, or -1 with errno
 * EINVAL (bad name) / EEXIST (name taken) / EIO. */
int pblock_snap_take(pblock_state_t *st, const char *name);

/* Restore the namespace to snapshot `name`. 0, or -1 with errno EINVAL /
 * ENOENT (no such snapshot) / EBUSY (a file handle is open) / EIO. */
int pblock_snap_restore(pblock_state_t *st, const char *name);

/* Drop snapshot `name`, releasing its held blob references. 0, or -1 with errno
 * EINVAL / ENOENT / EIO. */
int pblock_snap_drop(pblock_state_t *st, const char *name);

/* ---- reserved-namespace control dispatch -------------------------------- *
 * The driver's mkdir/unlink call these when the gate is armed and the path is
 * under the reserved control prefix, before any real namespace work. */

/* 1 iff `path` is under the reserved control prefix ("/.pblock/"). */
int pblock_snap_ctl_path(const char *path);

/* mkdir on a reserved control path: /.pblock/snap/<name> takes, .../restore/…
 * restores. 0, or -1/errno (EINVAL for an unrecognised control path). */
int pblock_snap_ctl_mkdir(pblock_state_t *st, const char *path);

/* rmdir on a reserved control path: /.pblock/snap/<name> drops. 0, or -1/errno. */
int pblock_snap_ctl_rmdir(pblock_state_t *st, const char *path);

#endif /* BRIX_FS_BACKEND_PBLOCK_SNAP_H */
