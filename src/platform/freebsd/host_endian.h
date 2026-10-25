/* FreeBSD's native byte-order API; included through the PAL umbrella. */
#pragma once
#include <sys/endian.h>
#define BRIX_PLAT_NATIVE_HTOBE64 htobe64
#define BRIX_PLAT_NATIVE_BE64TOH be64toh
#define BRIX_PLAT_NATIVE_HTOBE32 htobe32
#define BRIX_PLAT_NATIVE_BE32TOH be32toh
#define BRIX_PLAT_NATIVE_HTOBE16 htobe16
#define BRIX_PLAT_NATIVE_BE16TOH be16toh
