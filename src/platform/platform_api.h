/*
 * src/platform/platform_api.h - Platform Abstraction Layer Public API
 *
 * This header defines the complete PAL API. Source code should ONLY include
 * this header - NEVER platform-specific headers or preprocessor blocks.
 *
 * All platform detection and implementation logic lives in platform-specific subdirectories.
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

/* Platform-specific headers for byte-order operations */
#if BRIX_PLATFORM_LINUX
#include <endian.h>
#elif BRIX_PLATFORM_DARWIN
#include <libkern/OSByteOrder.h>
#elif BRIX_PLATFORM_WINDOWS
/* Windows byte order handled via intrinsics in inline functions below */
#include <windows.h>
#include <stdlib.h>
#endif

/* Keep the public include stable; each child owns one API family. */
#include "platform_api_info.h"
#include "platform_api_file.h"
#include "platform_api_event.h"
#include "platform_api_security.h"
#include "platform_api_xattr.h"
#include "platform_api_process.h"
#include "platform_api_endian.h"
#include "platform_api_lifecycle.h"
#include "platform_api_apple.h"
#include "platform_api_windows.h"

#endif /* BRIX_PLATFORM_API_H */
