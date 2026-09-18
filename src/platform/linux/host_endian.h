/* src/platform/linux/host_endian.h - native byte-order operations (glibc <endian.h>). */
#ifndef BRIX_PLATFORM_LINUX_HOST_ENDIAN_H
#define BRIX_PLATFORM_LINUX_HOST_ENDIAN_H

#include <endian.h>

#define BRIX_PLAT_NATIVE_HTOBE64 htobe64
#define BRIX_PLAT_NATIVE_BE64TOH be64toh
#define BRIX_PLAT_NATIVE_HTOBE32 htobe32
#define BRIX_PLAT_NATIVE_BE32TOH be32toh
#define BRIX_PLAT_NATIVE_HTOBE16 htobe16
#define BRIX_PLAT_NATIVE_BE16TOH be16toh

#endif /* BRIX_PLATFORM_LINUX_HOST_ENDIAN_H */
