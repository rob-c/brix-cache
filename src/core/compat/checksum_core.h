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
 *       libxrdproto's brix_crc32c_extend for crc32c, OpenSSL EVP for digests.
 *
 * The kind codes match brix_checksum_alg_t's ordinals so the module passes its
 * enum value directly; the client maps its own (smaller) enum onto them.
 */
#ifndef BRIX_CHECKSUM_CORE_H
#define BRIX_CHECKSUM_CORE_H

#include <stdint.h>

#include "fs/backend/sd.h"   /* brix_sd_obj_t — driver-routed whole-object read */

#define BRIX_CK_ADLER32   0
#define BRIX_CK_CRC32     1
#define BRIX_CK_CRC32C    2
#define BRIX_CK_MD5       3
#define BRIX_CK_SHA1      4
#define BRIX_CK_SHA256    5
#define BRIX_CK_CRC64     6   /* CRC-64/XZ   */
#define BRIX_CK_CRC64NVME 7   /* CRC-64/NVME */
#define BRIX_CK_ZCRC32    8   /* zlib CRC-32 — XRootD "zcrc32" (same algorithm
                                 * as CRC32/ISO-HDLC; a distinct registered name) */

/* Whole-OBJECT (driver pread from offset 0) checksums — the canonical entry for
 * a backend-bound handle (block-striped/object store): every byte is read
 * through obj->driver, so a multi-block file is summed in full (not just block
 * 0). obj->driver must be non-NULL. The _fd wrappers below POSIX-wrap a bare fd
 * onto this same kernel for the default export. Return 0 / -1. */
int brix_cksum_u32_obj(int kind, brix_sd_obj_t *obj, uint32_t *out);
int brix_cksum_u64_obj(int kind, brix_sd_obj_t *obj, uint64_t *out);
int brix_cksum_digest_obj(int kind, brix_sd_obj_t *obj, unsigned char *out,
                            unsigned int *outlen);

/* Whole-file (pread from offset 0) 32-bit checksum for ADLER32/CRC32/CRC32C into
 * *out. Returns 0 / -1 (errno set on a read failure). */
int brix_cksum_u32_fd(int kind, int fd, uint32_t *out);

/* Whole-file (pread from offset 0) 64-bit checksum for CRC64/CRC64NVME into *out.
 * Returns 0 / -1 (errno set on a read failure; -1 also for an unknown kind). */
int brix_cksum_u64_fd(int kind, int fd, uint64_t *out);

/* Whole-file digest for MD5/SHA1/SHA256 into out[<=EVP_MAX_MD_SIZE], length in
 * *outlen. Returns 0 / -1 (errno set on a read failure). */
int brix_cksum_digest_fd(int kind, int fd, unsigned char *out,
                           unsigned int *outlen);

#endif /* BRIX_CHECKSUM_CORE_H */
