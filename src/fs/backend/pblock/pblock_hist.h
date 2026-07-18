/*
 * pblock_hist.h — Phase-83 F11: versioning + trash/undelete for the pblock driver.
 *
 * WHAT: Two lifecycle safety-nets built on the F10 refcounted-blob foundation:
 *         versions — with `versions=N`, an overwrite-publish over an existing
 *                    file moves the prior object into `versions(path, gen, …)`
 *                    (its blob held, not freed), trimmed to the newest N
 *                    generations; the old content survives exactly in gen-N.
 *         trash    — with `trash=1`, an unlink moves the object into
 *                    `trash(trash_id, path, deleted_at, …)` (blob held) instead
 *                    of freeing it; `pblock-fsck --gc` purges rows past the TTL,
 *                    and undelete pops the most-recent entry back into the
 *                    namespace.
 *
 * WHY:  Gives lifecycle-tooling tests a real undelete/version-listing surface and
 *       makes destructive-op tests self-auditing: after an overwrite the previous
 *       bytes are exactly in gen-1, and after a delete the object is exactly in
 *       the trash — a standing oracle no other feature provides.
 *
 * HOW:  Every held blob uses the F10 explicit refcount arithmetic: push bumps the
 *       blob (so the caller's subsequent release only decrements — a copy-on-write
 *       transfer of the reference from the live object to the version/trash row),
 *       trim/undelete release it symmetrically. Bump-before-any-release keeps the
 *       refcount >= 1 across the transfer, so blocks are never removed mid-move. A
 *       failed push returns -1 and the caller falls back to the plain release
 *       (the file is simply overwritten/deleted, no history) — fail-open, never a
 *       lost user op. Both features therefore auto-arm F10 refs. Paths are only
 *       ever bound column values (never interpolated), so a hostile name can
 *       neither inject nor traverse. ngx-free (libc + sqlite3); BRIX_HAVE_SQLITE-
 *       gated.
 *
 * Requires: pblock_store.h (pblock_state_t), sd_pblock_catalog.h (pblock_meta)
 *           before inclusion.
 */
#ifndef BRIX_FS_BACKEND_PBLOCK_HIST_H
#define BRIX_FS_BACKEND_PBLOCK_HIST_H

/* Ensure the versions + trash tables (+ their indexes) exist. 0 or -1/errno. */
int pblock_hist_init(pblock_state_t *st);

/* Save `meta` (the about-to-be-overwritten object at `path`) as a new version
 * generation, holding its blob, then trim to the newest st->versions
 * generations (releasing each trimmed blob). No-op success for a directory (no
 * blob). 0 or -1/errno; on failure nothing is held and the caller proceeds with
 * a plain overwrite. */
int pblock_hist_version_push(pblock_state_t *st, const char *path,
    const pblock_meta *meta);

/* Move `meta` (the about-to-be-unlinked object at `path`) into the trash,
 * holding its blob. No-op success for a directory. 0 or -1/errno; on failure
 * nothing is held and the caller proceeds with a plain unlink. */
int pblock_hist_trash_push(pblock_state_t *st, const char *path,
    const pblock_meta *meta);

/* Undelete: pop the most-recently-deleted trash entry for `path` back into the
 * namespace (transferring the held blob reference to the restored object row).
 * NGX_ERROR/ENOENT when the trash holds no entry for `path`, or EEXIST when a
 * live object already occupies `path`. 0 or -1/errno. */
int pblock_hist_undelete(pblock_state_t *st, const char *path);

/* Reserved-namespace control dispatch. mkdir /.pblock/undelete/<path> undeletes
 * <path> (leading slash implied). Reached only through the inner (service)
 * mkdir path, so history control is service-only — like F6 snapshots. */
int pblock_hist_ctl_mkdir_match(const char *path);
int pblock_hist_ctl_mkdir(pblock_state_t *st, const char *path);

#endif /* BRIX_FS_BACKEND_PBLOCK_HIST_H */
