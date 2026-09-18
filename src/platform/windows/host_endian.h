/* src/platform/windows/host_endian.h - native byte-order operations (MSVC intrinsics). */
#ifndef BRIX_PLATFORM_WINDOWS_HOST_ENDIAN_H
#define BRIX_PLATFORM_WINDOWS_HOST_ENDIAN_H

#include <stdlib.h>

#define BRIX_PLAT_NATIVE_HTOBE64 _byteswap_uint64
#define BRIX_PLAT_NATIVE_BE64TOH _byteswap_uint64
#define BRIX_PLAT_NATIVE_HTOBE32 _byteswap_ulong
#define BRIX_PLAT_NATIVE_BE32TOH _byteswap_ulong
#define BRIX_PLAT_NATIVE_HTOBE16 _byteswap_ushort
#define BRIX_PLAT_NATIVE_BE16TOH _byteswap_ushort

#endif /* BRIX_PLATFORM_WINDOWS_HOST_ENDIAN_H */
