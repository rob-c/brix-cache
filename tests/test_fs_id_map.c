/*
 * test_fs_id_map.c — standalone unit test for the fs_list.h backend-id surface
 * (brix_fs_id_from_name / brix_fs_id_name).
 *
 * Build+run (no nginx tree needed — sd_fs_id.c is ngx-free):
 *   gcc -I src -o /tmp/test_fs_id_map tests/test_fs_id_map.c src/fs/backend/sd_fs_id.c && /tmp/test_fs_id_map
 */
#include <stdio.h>
#include <string.h>

#include "core/types/fs_list.h"

static int failures = 0;

static void
check(int cond, const char *what)
{
    if (cond) {
        printf("  ok   %s\n", what);
    } else {
        printf("  FAIL %s\n", what);
        failures++;
    }
}

int
main(void)
{
    int  id;
    char label[64];

    /* Roundtrip every census row: name -> id -> name. */
    for (id = 0; id < BRIX_FS_ID_COUNT; id++) {
        const char *name = brix_fs_id_name(id);

        snprintf(label, sizeof(label), "row %d roundtrip (%s)", id, name);
        check(name != NULL && name[0] != '\0'
              && brix_fs_id_from_name(name) == id, label);
    }

    /* Known anchors present in every build. */
    check(brix_fs_id_from_name("posix") >= 0, "posix registered");
    check(brix_fs_id_from_name("cache") >= 0, "cache decorator registered");
    check(brix_fs_id_from_name("xroot") >= 0, "xroot origin registered");

    /* Negatives: unknown / NULL / out-of-range id. */
    check(brix_fs_id_from_name("nosuchfs") == -1, "unknown name -> -1");
    check(brix_fs_id_from_name(NULL) == -1, "NULL name -> -1");
    check(strcmp(brix_fs_id_name(-1), "?") == 0, "id -1 -> \"?\"");
    check(strcmp(brix_fs_id_name(BRIX_FS_ID_COUNT), "?") == 0,
          "id COUNT -> \"?\"");

    printf(failures == 0 ? "ALL PASS\n" : "%d FAILURES\n", failures);
    return failures == 0 ? 0 : 1;
}
