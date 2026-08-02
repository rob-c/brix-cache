/*
 * cktree_internal.h - private split contract shared by xrdcktree.c and xrdckcheck.c.
 * Not a public API: include only from apps/cksum/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_CKTREE_INTERNAL_H
#define BRIX_CKTREE_INTERNAL_H

#include <stddef.h>

/* Max hex digest length + NUL (SHA-512 = 128 hex + NUL, rounded). */
#define TREE_HEX_MAX  129

/* Helpers defined in xrdcktree.c, reused by the ckcheck tool (xrdckcheck.c). */
int ckt_is_root_url(const char *s);
int ckt_path_join(const char *dir, const char *name, char *out, size_t outsz);

#endif /* BRIX_CKTREE_INTERNAL_H */
