/*
 * sd_fs_id.c — the census-backed backend-id lookups.
 *
 * WHAT: Implements brix_fs_id_name() / brix_fs_id_from_name(), the
 *       name<->brix_fs_id_t mapping generated from the central filesystem
 *       declaration (core/types/fs_list.h).
 * WHY:  The per-backend SHM byte counters index by a bounded enum; attribution
 *       sites hold a driver NAME (obj->driver->name / sd_backend_name), so one
 *       shared, generated map keeps the label set closed (INVARIANT #8) and
 *       adding a filesystem in fs_list.h extends it for free.
 * HOW:  An X-macro-expanded names[] array parallel to the enum. Kept ngx-free
 *       and free of driver externs so it links standalone (unit test) and adds
 *       zero coupling; the <=13-entry strcmp scan runs once per COMPLETED I/O
 *       op, which is noise against the syscall it accounts.
 */
#include <string.h>

#include "core/types/fs_list.h"

static const char *const brix_fs_id_names[] = {
#define BRIX_FS_ROW_NAME(ID, sym, name, kind) name,
    BRIX_FS_DRIVER_LIST(BRIX_FS_ROW_NAME)
#undef BRIX_FS_ROW_NAME
};

/* The census label for id ("posix", "pblock", ...); "?" when out of range. */
const char *
brix_fs_id_name(int id)
{
    if (id < 0 || id >= BRIX_FS_ID_COUNT) {
        return "?";
    }
    return brix_fs_id_names[id];
}

/* Exact-match name -> id over the census; -1 for NULL or unknown names. */
int
brix_fs_id_from_name(const char *name)
{
    int id;

    if (name == NULL || name[0] == '\0') {
        return -1;
    }
    for (id = 0; id < BRIX_FS_ID_COUNT; id++) {
        if (strcmp(brix_fs_id_names[id], name) == 0) {
            return id;
        }
    }
    return -1;
}
