/*
 * crc32_ieee.c — CRC-32/IEEE (see crc32_ieee.h).
 *
 * The reflected, table-free CRC-32 (poly 0xedb88320, init/xorout 0xffffffff) used
 * by the XRootD SSS credential blob. Shared by the module's SSS verify and the
 * native client's SSS mint. ngx-free; no dependencies.
 */
#include "crc32_ieee.h"

uint32_t
brix_crc32_ieee(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xffffffffu;

    while (len--) {
        int i;
        crc ^= *buf++;
        for (i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t) -(int32_t) (crc & 1));
        }
    }
    return crc ^ 0xffffffffu;
}
