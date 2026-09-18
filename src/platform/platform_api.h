/*
 * src/platform/platform_api.h - Platform Abstraction Layer Public API
 *
 * This header defines the complete PAL API. Source code should ONLY include
 * this header - NEVER platform-specific headers or preprocessor blocks.
 * It contains no host conditional: platform.h selected the host directory
 * from -DBRIX_PLATFORM_HOST, and each API family pulls its host counterpart
 * through one computed #include.
 *
 * Supported Platforms:
 *   - Linux (x86_64, arm64)
 *   - macOS/Darwin (x86_64, arm64/Apple Silicon)
 *   - Windows (x86_64, arm64) [planned]
 *
 * Usage Example:
 *   #include "platform/platform_api.h"
 *
 *   int fd = brix_plat_anon_fd("temp-file", NULL);
 *   ssize_t n = brix_plat_getxattr(path, "user.key", buf, sizeof(buf));
 *   uint64_t be_val = brix_plat_htobe64(host_val);
 */

#pragma once
#ifndef BRIX_PLATFORM_API_H
#define BRIX_PLATFORM_API_H

#include "platform.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

/* Keep the public include stable; each child owns one API family. */
#include "platform_api_info.h"
#include "platform_api_file.h"
#include "platform_api_event.h"
#include "platform_api_security.h"
#include "platform_api_xattr.h"
#include "platform_api_process.h"
#include "platform_api_posix.h"
#include "platform_api_endian.h"
#include "platform_api_lifecycle.h"

/* Host-only extensions: Apple Silicon (darwin/host_api.h), Win32
 * (windows/host_api.h); Linux answers with an empty header. */
#include BRIX_PLAT_HOST_HEADER(host_api.h)

#endif /* BRIX_PLATFORM_API_H */
