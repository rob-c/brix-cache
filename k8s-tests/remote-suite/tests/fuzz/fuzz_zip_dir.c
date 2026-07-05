/*
 * fuzz_zip_dir.c — libFuzzer target for the server ZIP central-directory walk.
 *
 * WHAT: Wraps fuzz bytes in a memfd and exercises brix_zip_find_member (the
 *       server's ZIP member locator) plus brix_zip_extract_full (the one-shot
 *       inflate path) under ASan + UBSan.
 *
 * WHY:  The central-directory parser consumes attacker-supplied byte offsets and
 *       sizes (cd_size, comp_size, lhdr_off, ZIP64 overrides). These fields drove
 *       the Phase-B safe_size.h allocation hardening; this target ensures that
 *       hardening holds against arbitrary hostile archives.
 *
 * HOW:  Unity build — zip_kernel.c, sd_posix.c (XRDPROTO_NO_NGX), and zip_dir.c
 *       are #included directly so the ngx-shim macros below apply to every TU
 *       without touching any source file or requiring -include flags. The build
 *       command is a single clang line with -lz.
 *
 *       On BRIX_ZIP_OK the fuzzer also calls brix_zip_extract_full so the
 *       zlib inflate path is reachable. The output buffer is capped at 1 MiB to
 *       keep per-input allocation bounded.
 *
 * Build:
 *   cd tests/fuzz
 *   clang -O1 -g -fsanitize=fuzzer,address,undefined \
 *       fuzz_zip_dir.c -lz -o fuzz_zip_dir
 *   mkdir -p corpus_zip_dir
 *   ./fuzz_zip_dir -runs=200000 -max_total_time=120 corpus_zip_dir/
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* ---- minimal nginx shims --------------------------------------------------
 * Must appear before any #include that indirectly pulls in sd.h or safe_size.h:
 *   XRDPROTO_NO_NGX        → sd.h emits typedef stubs for ngx_int_t / ngx_pool_t
 *                            / ngx_log_t / NGX_OK / NGX_ERROR / ngx_memzero, and
 *                            the nginx-coupled lifecycle sections of sd_posix.c
 *                            are compiled out.
 *   BRIX_SAFE_SIZE_STANDALONE → safe_size.h skips <ngx_config.h>/<ngx_core.h>.
 *   ngx_palloc / _pcalloc / _alloc → cover the safe_size.h static inline
 *                            functions that the compiler parses but zip_dir.c
 *                            never calls (brix_palloc_array and friends). */
#define XRDPROTO_NO_NGX              1
#define BRIX_SAFE_SIZE_STANDALONE  1
#define ngx_palloc(pool, n)          malloc(n)
#define ngx_pcalloc(pool, n)         calloc(1, (n))
#define ngx_alloc(n, log)            malloc(n)
#define ngx_free(p)                  free(p)

/* ---- unity build: pull in the TUs under test -----------------------------
 * Relative paths resolve from each included file's own directory (GCC/Clang
 * standard behaviour), so zip_dir.c's "../fs/backend/sd.h" and
 * sd_posix.c's "../sd.h" find the right files without any -I flag. */
#include "../../src/protocols/root/zip/zip_kernel.c"           /* pure-C kernel, no nginx    */
#include "../../src/fs/backend/posix/sd_posix.c" /* POSIX vtable (ngx-free parts) */
#include "../../src/protocols/root/zip/zip_dir.c"              /* TU under test              */

/* Public header (already pulled in by zip_dir.c, but named here for clarity). */
#include "../../src/protocols/root/zip/zip_dir.h"

/* ---- fuzzer entry point -------------------------------------------------- */

/*
 * LLVMFuzzerTestOneInput — drive the ZIP central-directory walk with hostile
 * input: write fuzz bytes to a memfd, call brix_zip_find_member, and on a
 * successful find drive brix_zip_extract_full to reach the inflate path.
 *
 * The member name is fixed at "any.dat"; the directory walk (not the name
 * match) is what we are exercising. A cd_max of 1 MiB matches a realistic
 * operator cap and keeps fuzzer-injected cd_size values bounded.
 */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    brix_zip_member_t m;
    int                 fd;
    int                 rc;

    if (size == 0) {
        return 0;
    }

    fd = memfd_create("zipfuzz", 0);
    if (fd < 0) {
        return 0;
    }
    if (write(fd, data, size) != (ssize_t) size) {
        close(fd);
        return 0;
    }

    memset(&m, 0, sizeof(m));
    rc = brix_zip_find_member(fd, (off_t) size, "any.dat", 1u << 20, &m);

    if (rc == BRIX_ZIP_OK && m.uncomp_size > 0
        && m.uncomp_size <= (size_t)(1u << 20))
    {
        /* Exercise the extraction path (stored + deflate inflate) up to 1 MiB.
         * This also validates that comp_size / data_off are internally consistent
         * (pread_full will short-read or -1 on any inconsistency, returning -1). */
        unsigned char *buf = malloc(m.uncomp_size);
        if (buf != NULL) {
            (void) brix_zip_extract_full(fd, &m, buf, m.uncomp_size);
            free(buf);
        }
    }

    close(fd);
    return 0;
}
