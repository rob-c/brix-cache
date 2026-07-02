/*
 * crc32_ieee.h — CRC-32/IEEE (the SSS credential-blob CRC).
 *
 * WHAT: reflected CRC-32, poly 0xedb88320, init/xorout 0xffffffff — the integrity
 *       checksum carried in the XRootD SSS shared-secret credential blob.
 * WHY:  the module (SSS verify) and the native client (SSS mint) each hand-rolled
 *       this identical routine; one shared kernel keeps them in step.
 * HOW:  bit-by-bit reflected CRC over caller bytes; no tables, no ngx, no alloc.
 *
 * NOTE: this is CRC-32/IEEE (zlib's crc32), DISTINCT from CRC-32C/Castagnoli in
 *       crc32c.h — different polynomial, NOT interchangeable.
 */
#ifndef XROOTD_COMPAT_CRC32_IEEE_H
#define XROOTD_COMPAT_CRC32_IEEE_H

#include <stddef.h>
#include <stdint.h>

uint32_t xrootd_crc32_ieee(const uint8_t *buf, size_t len);

#endif /* XROOTD_COMPAT_CRC32_IEEE_H */
