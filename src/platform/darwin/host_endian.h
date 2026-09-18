/* src/platform/darwin/host_endian.h - native byte-order operations (OSByteOrder),
 * and the <endian.h> names the tree is written against, which Darwin lacks. */
#ifndef BRIX_PLATFORM_DARWIN_HOST_ENDIAN_H
#define BRIX_PLATFORM_DARWIN_HOST_ENDIAN_H

#include <libkern/OSByteOrder.h>

#define BRIX_PLAT_NATIVE_HTOBE64 OSSwapHostToBigInt64
#define BRIX_PLAT_NATIVE_BE64TOH OSSwapBigToHostInt64
#define BRIX_PLAT_NATIVE_HTOBE32 OSSwapHostToBigInt32
#define BRIX_PLAT_NATIVE_BE32TOH OSSwapBigToHostInt32
#define BRIX_PLAT_NATIVE_HTOBE16 OSSwapHostToBigInt16
#define BRIX_PLAT_NATIVE_BE16TOH OSSwapBigToHostInt16

#ifndef htobe16
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#endif

#endif /* BRIX_PLATFORM_DARWIN_HOST_ENDIAN_H */
