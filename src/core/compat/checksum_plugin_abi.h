/*
 * brix checksum plugin ABI (site-facing).
 *
 * A site that needs a checksum algorithm the seven built-ins (adler32, crc32,
 * crc32c, crc64, crc64nvme, md5, sha1, sha256, sha512) do not cover compiles a
 * shared object against THIS header only and registers it with
 *
 *     brix_checksum_plugin <name> /abs/path/plugin.so [parms];
 *
 * The object exports one data symbol, `brix_cks_plugin`, of type
 * brix_cks_plugin_t. The server dlopen()s it at config time (RTLD_NOW|RTLD_LOCAL),
 * validates every field, runs an empty-input self-test and refuses the config
 * on any mismatch — a broken plugin never reaches a worker.
 *
 * Streaming contract (one state per computation, never shared):
 *   init(state, parms)        -> 0 on success; `parms` is the directive's third
 *                                argument or "" when absent.
 *   update(state, buf, n)     -> 0 on success; called in file order with the
 *                                bytes of the object, n may be 0.
 *   final(state, digest)      -> 0 on success; writes exactly digest_len bytes.
 *
 * The host hex-encodes `digest` itself (lowercase, 2*digest_len characters),
 * so a plugin never touches the wire; every protocol (kXR_query cks, WebDAV
 * Want-Digest, Qconfig chksum) sees the plugin under the registered name.
 *
 * The header is plain C99 with no server dependencies on purpose: a plugin
 * must build outside the nginx tree.
 */

#ifndef BRIX_CHECKSUM_PLUGIN_ABI_H
#define BRIX_CHECKSUM_PLUGIN_ABI_H

#include <stddef.h>

/* Bump when the struct layout or calling contract changes; the host refuses
 * any other value at load time. */
#define BRIX_CKS_PLUGIN_ABI          1

/* Exported data symbol the host looks up with dlsym(). */
#define BRIX_CKS_PLUGIN_SYMBOL       "brix_cks_plugin"

/* Registered name: 1..15 ASCII letters/digits, compared case-insensitively. */
#define BRIX_CKS_PLUGIN_NAME_MAX     15

/* Digest length bound == EVP_MAX_MD_SIZE (the host static-asserts that). */
#define BRIX_CKS_PLUGIN_DIGEST_MAX   64

/* Per-computation state bound; the host keeps it on the calling stack. */
#define BRIX_CKS_PLUGIN_STATE_MAX    4096

/* Registered plugins per server process. */
#define BRIX_CKS_PLUGINS_MAX         8

typedef struct {
    unsigned      abi;          /* BRIX_CKS_PLUGIN_ABI */
    const char   *name;         /* must match the directive's <name> */
    size_t        digest_len;   /* 1..BRIX_CKS_PLUGIN_DIGEST_MAX */
    size_t        state_size;   /* 1..BRIX_CKS_PLUGIN_STATE_MAX */
    int         (*init)(void *state, const char *parms);
    int         (*update)(void *state, const unsigned char *buf, size_t n);
    int         (*final)(void *state, unsigned char *digest);
} brix_cks_plugin_t;

#endif /* BRIX_CHECKSUM_PLUGIN_ABI_H */
