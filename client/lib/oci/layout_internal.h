/*
 * layout_internal.h - private split contract for layout.c / layout_index.c.
 * Not a public API: include only from client/lib/oci/.
 */
#ifndef BRIX_OCI_LAYOUT_INTERNAL_H
#define BRIX_OCI_LAYOUT_INTERNAL_H

#include "oci/layout.h"

#define LAY_INDEX_CAP (8u << 20)    /* 8 MiB ceiling on index.json */

/* layout.c */
/* Whole-file read (<= cap); *out malloc'd + NUL-terminated. 0 / -1 (errno; EFBIG over cap). */
int layx_read_file(const char *path, size_t cap, char **out, size_t *outlen);
/* Staged write of dir/name (temp + fsync + rename). Result code. */
int layx_write_atomic(const char *dir, const char *name, const void *body, size_t len, char *err, size_t errlen);

#endif /* BRIX_OCI_LAYOUT_INTERNAL_H */
