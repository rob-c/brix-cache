/*
 * overlay_internal.h - private split contract for overlay.c and overlay_copyup.c.
 * Not a public API: include only from lib/fs/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XRDC_OVERLAY_INTERNAL_H
#define XRDC_OVERLAY_INTERNAL_H

#include "fs/overlay.h"

#define OV_NAME_MAX 256   /* one path component incl. NUL (shared: overlay.c + overlay_copyup.c) */

/* overlay.c helpers shared with overlay_copyup.c (Phase-38 split) */
int ov_walk_parent_mk(const brix_overlay *ov, const char *rel,
                      char *leaf, size_t leafcap, int mk,
                      mode_t (*mode_fn)(void *ud, const char *rel_dir),
                      void *ud);
int ov_open_dir(const brix_overlay *ov, const char *rel_dir);

#endif /* XRDC_OVERLAY_INTERNAL_H */
