/*
 * checksum_core.h — pure (ngx-free) whole-file checksum compute kernels.
 *
 * WHAT: Stream a file descriptor and produce a 32-bit checksum (Adler-32/CRC-32/
 *       CRC-32c) or a cryptographic digest (MD5/SHA-1/SHA-256). No nginx, no
 *       logging — the caller maps its own algorithm enum to the kind codes here
 *       and handles errors/logging at the edge.
 * WHY:  Both the nginx module (src/compat/checksum.c) and the native client
 *       (client/lib/checksum.c) need identical fd→checksum compute; this is the
 *       single source they share via libxrdproto (build-in-place), like crc32c
 *       and gsi_core.
 * HOW:  pread(2) the whole file in 64 KiB chunks; zlib for adler32/crc32,
 *       libxrdproto's xrootd_crc32c_extend for crc32c, OpenSSL EVP for digests.
 *
 * The kind codes match xrootd_checksum_alg_t's ordinals so the module passes its
 * enum value directly; the client maps its own (smaller) enum onto them.
 */
#ifndef XROOTD_CHECKSUM_CORE_H
#define XROOTD_CHECKSUM_CORE_H

#include <stdint.h>

#define XROOTD_CK_ADLER32   0
#define XROOTD_CK_CRC32     1
#define XROOTD_CK_CRC32C    2
#define XROOTD_CK_MD5       3
#define XROOTD_CK_SHA1      4
#define XROOTD_CK_SHA256    5
#define XROOTD_CK_CRC64     6   /* CRC-64/XZ   */
#define XROOTD_CK_CRC64NVME 7   /* CRC-64/NVME */

/* Whole-file (pread from offset 0) 32-bit checksum for ADLER32/CRC32/CRC32C into
 * *out. Returns 0 / -1 (errno set on a read failure). */
int xrootd_cksum_u32_fd(int kind, int fd, uint32_t *out);

/* Whole-file (pread from offset 0) 64-bit checksum for CRC64/CRC64NVME into *out.
 * Returns 0 / -1 (errno set on a read failure; -1 also for an unknown kind). */
int xrootd_cksum_u64_fd(int kind, int fd, uint64_t *out);

/* Whole-file digest for MD5/SHA1/SHA256 into out[<=EVP_MAX_MD_SIZE], length in
 * *outlen. Returns 0 / -1 (errno set on a read failure). */
int xrootd_cksum_digest_fd(int kind, int fd, unsigned char *out,
                           unsigned int *outlen);

#endif /* XROOTD_CHECKSUM_CORE_H */
