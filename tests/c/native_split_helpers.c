/* Runtime contracts for pure helpers extracted from oversized native modules. */
#include "protocols/root/read/open_internal.h"
#include "protocols/root/fattr/storage_keys.h"
#include "platform/platform_api.h"
#include "core/compat/crypto.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

/* WHAT: Supply bounded open payload bytes. WHY: Exercise real opaque parsing.
 * HOW: 1. Zero request state. 2. Attach the caller-owned string and length. */
static void request(brix_ctx_t *ctx, const char *payload)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->recv.payload = (u_char *) payload;
    ctx->recv.cur_dlen = (uint32_t) strlen(payload);
}

/* WHAT: Check accepted options and keys. WHY: Refactoring must retain outputs.
 * HOW: 1. Parse real CGI hints. 2. Check direct and deterministic wrapped keys. */
static void success(void)
{
    brix_ctx_t ctx;
    brix_sd_open_hints_t hints;
    char key[512], again[512];
    int wrapped;

    request(&ctx, "/file?oss.asize=8192&pfc.blocksize=4096&pfc.prefetch=3");
    assert(brix_open_declared_asize(&ctx) == 8192);
    hints = brix_open_cache_hints(&ctx, 0);
    assert(hints.block_size == 4096 && hints.prefetch_set == 1);
    assert(hints.prefetch_blocks == 3);
    assert(!brix_open_options_conflict(kXR_open_wrto | kXR_open_apnd));
    assert(fattr_storage_key("ordinary", 8, key, sizeof(key), &wrapped) == 0);
    assert(!wrapped && strcmp(key, "user.U.ordinary") == 0);
    assert(fattr_storage_hashed_key("ordinary", 8, key, sizeof(key)) == 0);
    assert(fattr_storage_hashed_key("ordinary", 8, again, sizeof(again)) == 0);
    assert(strcmp(key, again) == 0);
    assert(fattr_storage_chunk_count(2049) == 2);
}

/* WHAT: Check typed failures. WHY: Error codes and absent values are contracts.
 * HOW: 1. Probe malformed/absent CGI. 2. Check invalid names and short buffers. */
static void error(void)
{
    brix_ctx_t ctx;
    char key[512];
    int wrapped;

    request(&ctx, "/file?oss.asize=not-a-number");
    assert(brix_open_declared_asize(&ctx) == 0);
    request(&ctx, "/file");
    assert(brix_open_declared_asize(&ctx) == 0);
    assert(fattr_storage_key(NULL, 0, key, sizeof(key), &wrapped) == -1);
    assert(errno == EINVAL);
    assert(fattr_storage_key("normal", 6, key, 2, &wrapped) == -1);
    assert(errno == ENAMETOOLONG);
}

/* WHAT: Check adversarial boundaries. WHY: Names/hints cannot widen authority.
 * HOW: 1. Reject conflicting modes. 2. Suppress write hints. 3. Wrap reserved names. */
static void negative(void)
{
    brix_ctx_t ctx;
    brix_sd_open_hints_t hints;
    char key[512], chunk[512];
    uint8_t digest[32] = { 0 };
    int wrapped;

    assert(brix_open_options_conflict(kXR_open_read | kXR_open_wrto));
    assert(brix_open_options_conflict(UINT16_MAX));
    request(&ctx, "/file?pfc.blocksize=4096&pfc.prefetch=3");
    hints = brix_open_cache_hints(&ctx, 1);
    assert(hints.block_size == 0 && hints.prefetch_set == 0);
    assert(hints.prefetch_blocks == 0);
    assert(fattr_storage_key("$brix$forged", 12, key, sizeof(key), &wrapped) == 0);
    assert(wrapped && strncmp(key, FATTR_STORED_PREFIX, FATTR_STORED_PREFIX_LEN) == 0);
    assert(fattr_storage_chunk_key(chunk, sizeof(chunk), key, digest,
                                  FATTR_CHUNK_MAX) == -1);
    assert(errno == EINVAL);
}

/* WHAT: Run one isolated contract group. WHY: Preserve separate outcome evidence.
 * HOW: 1. Initialize real crypto. 2. Dispatch the named case. 3. Clean up. */
int main(int argc, char **argv)
{
    assert(argc == 2 && brix_crypto_init());
    if (strcmp(argv[1], "success") == 0) {
        success();
    } else if (strcmp(argv[1], "error") == 0) {
        error();
    } else {
        assert(strcmp(argv[1], "negative") == 0);
        negative();
    }
    brix_crypto_cleanup();
    return 0;
}
