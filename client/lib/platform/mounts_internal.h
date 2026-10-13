#ifndef BRIX_CLIENT_PLATFORM_MOUNTS_INTERNAL_H
#define BRIX_CLIENT_PLATFORM_MOUNTS_INTERNAL_H

#include "platform/platform.h"

int brix_plat_mountinfo_walk(const char *table_path, brix_plat_mount_cb cb,
    void *arg);

#endif
