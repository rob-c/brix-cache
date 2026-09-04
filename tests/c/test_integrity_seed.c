/*
 * test_integrity_seed.c — brix_integrity_seed_fd: recording a digest that is
 * already proven, so the first checksum request on the file does not re-read it.
 *
 * WHAT: Exercises the seed producer against the real xattr cache layer in
 *       integrity_info.c and the reader that consults it (brix_integrity_get_fd
 *       with no_compute=1, which DECLINES on a miss — so "the cache answered"
 *       and "the file was read" are distinguishable outcomes rather than the
 *       same hex string arriving by two routes).
 *
 * WHY:  The seed exists for one reason: a cache fill has just verified a digest
 *       over the bytes it committed, and without recording it the next
 *       kXR_Qcksum / Want-Digest reads the whole cached file back to re-derive
 *       the same value. The properties that make that safe are all testable
 *       locally: the value must survive canonicalisation of the algorithm name,
 *       must be refused rather than truncated when malformed, and must go stale
 *       the instant the bytes it describes change.
 *
 * HOW:  Real temp files on the test filesystem. The VFS xattr seam is stubbed to
 *       the bare fgetxattr/fsetxattr syscalls (the real seam only adds metrics
 *       observation, and linking it would drag the metrics closure in), and the
 *       §8.2 record fallback is stubbed to an in-test counter so its use is
 *       observable and the xmeta carrier is not linked. Both stubs are of OUR
 *       thin wrappers, never of an nginx function (ngx_log_error_core aside —
 *       ngx_log.o is not in this link at all).
 *
 *       The checksum COMPUTE kernels below the algorithm parser are stubbed to
 *       abort(). That is not a convenience: the property this whole change
 *       exists for is "the digest is answered WITHOUT reading the object", and
 *       an aborting kernel is the only way to assert it that cannot be satisfied
 *       by a coincidentally-equal hex string.
 *
 * Tests:
 *   1 success — a seeded digest is served from cache without reading the file,
 *               through an algorithm-name spelling the reader canonicalises.
 *   2 error   — bad fd / unknown algorithm / empty and non-hex values are all
 *               refused, and none of them leave anything behind.
 *   3 secneg  — an over-long value is refused WHOLE (no truncated digest is
 *               stored), a seed never mutates the file it describes, and a
 *               seeded value stops being served the moment the bytes change.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "core/compat/integrity_info.h"
#include "core/compat/integrity_info_internal.h"

/* ---- stubs: the VFS xattr seam (metrics-free) ----------------------------- */

ssize_t
brix_vfs_fgetxattr(const void *ctx, int fd, const char *name, void *val,
    size_t cap)
{
    (void) ctx;
    return fgetxattr(fd, name, val, cap);
}

ngx_int_t
brix_vfs_fsetxattr(const void *ctx, int fd, const char *name, const void *val,
    size_t len, int flags)
{
    (void) ctx;
    return (fsetxattr(fd, name, val, len, flags) != 0) ? NGX_ERROR : NGX_OK;
}

ngx_int_t
brix_vfs_fremovexattr(const void *ctx, int fd, const char *name)
{
    (void) ctx;
    return (fremovexattr(fd, name) != 0) ? NGX_ERROR : NGX_OK;
}

/* Phase-105 carried-policy twins: same passthrough, honoring the one property
 * the carried forms exist for — a READ_ONLY policy refuses with EROFS before
 * the syscall (integrity_info.c hands its stored endpoint posture here). */
ngx_int_t
brix_vfs_fsetxattr_carried(brix_vfs_mutation_policy_t policy, brix_proto_t proto,
    int fd, const char *name, const void *value, size_t len, int flags)
{
    (void) proto;
    if (policy != BRIX_VFS_MUTATION_ALLOWED) { errno = EROFS; return NGX_ERROR; }
    return (fsetxattr(fd, name, value, len, flags) != 0) ? NGX_ERROR : NGX_OK;
}

ngx_int_t
brix_vfs_fremovexattr_carried(brix_vfs_mutation_policy_t policy,
    brix_proto_t proto, int fd, const char *name)
{
    (void) proto;
    if (policy != BRIX_VFS_MUTATION_ALLOWED) { errno = EROFS; return NGX_ERROR; }
    return (fremovexattr(fd, name) != 0) ? NGX_ERROR : NGX_OK;
}

ngx_int_t
brix_vfs_removexattr(const void *ctx, const char *root, const char *path,
    const char *name)
{
    (void) ctx; (void) root; (void) path; (void) name;
    return NGX_OK;
}

void
brix_vfs_ctx_init(void *ctx, void *conf, const char *root, size_t rootlen)
{
    (void) ctx; (void) conf; (void) root; (void) rootlen;
}

void
brix_vfs_ctx_bind_no_authz_rules(void *ctx)
{
    (void) ctx;
}

/* ---- stubs: the compute kernels, which this test must never reach ---------- */

#define NEVER_COMPUTE(fn)                                                     \
    do {                                                                      \
        fprintf(stderr, "FAIL: " fn " ran - the file was READ when the "      \
                        "seeded digest should have answered\n");              \
        abort();                                                              \
    } while (0)

ngx_int_t brix_cksum_digest_fd(int a, int b, const void *c, void *d, void *e)
{ (void) a; (void) b; (void) c; (void) d; (void) e;
  NEVER_COMPUTE("brix_cksum_digest_fd"); }

ngx_int_t brix_cksum_digest_obj(int a, void *b, const void *c, void *d, void *e)
{ (void) a; (void) b; (void) c; (void) d; (void) e;
  NEVER_COMPUTE("brix_cksum_digest_obj"); }

ngx_int_t brix_cksum_u32_fd(int a, int b, const void *c, void *d)
{ (void) a; (void) b; (void) c; (void) d;
  NEVER_COMPUTE("brix_cksum_u32_fd"); }

ngx_int_t brix_cksum_u32_obj(int a, void *b, const void *c, void *d)
{ (void) a; (void) b; (void) c; (void) d;
  NEVER_COMPUTE("brix_cksum_u32_obj"); }

ngx_int_t brix_cksum_u64_fd(int a, int b, const void *c, void *d)
{ (void) a; (void) b; (void) c; (void) d;
  NEVER_COMPUTE("brix_cksum_u64_fd"); }

ngx_int_t brix_cksum_u64_obj(int a, void *b, const void *c, void *d)
{ (void) a; (void) b; (void) c; (void) d;
  NEVER_COMPUTE("brix_cksum_u64_obj"); }

/* ---- stubs: the logging / formatting seam --------------------------------- */

volatile ngx_cycle_t *ngx_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

size_t
brix_hex_encode(char *dst, size_t dstcap, const unsigned char *src, size_t n)
{
    (void) dst; (void) dstcap; (void) src; (void) n;
    return 0;
}

const char *
brix_sanitize_log_string(const char *in, char *buf, size_t cap)
{
    (void) in;
    if (cap > 0) { buf[0] = '\0'; }
    return buf;
}

/* ---- stubs: the §8.2 record fallback -------------------------------------- */

static int g_record_writes;

int
integrity_record_read(const char *path, const char *algo,
    brix_integrity_info_t *out)
{
    (void) path; (void) algo; (void) out;
    return 0;
}

void
integrity_record_write(const char *path, const char *algo, const char *hexval)
{
    (void) path; (void) algo; (void) hexval;
    g_record_writes++;
}

/* ---- fixtures ------------------------------------------------------------- */

#define SHA256_HEX_UPPER \
    "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
#define SHA256_HEX_LOWER \
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
#define CRC64_HEX "0123456789abcdef"

static char g_path[256];

/* Create a fresh temp file holding `body`; returns an open O_RDWR fd. */
static int
make_file(const char *body)
{
    int fd;

    snprintf(g_path, sizeof(g_path), "/tmp/brix-seed-XXXXXX");
    fd = mkstemp(g_path);
    assert(fd >= 0);
    assert(write(fd, body, strlen(body)) == (ssize_t) strlen(body));
    return fd;
}

/* Ask the cache layer ONLY: no_compute makes a miss return NGX_DECLINED instead
 * of silently reading the file, which is what lets a test tell the two apart. */
static ngx_int_t
lookup_cached(int fd, const char *alg, brix_integrity_info_t *out)
{
    brix_integrity_opts_t o;

    ngx_memzero(&o, sizeof(o));
    o.allow_xattr_cache = 1;
    o.no_compute        = 1;
    return brix_integrity_get_fd(NULL, fd, NULL, g_path, alg, &o, out);
}

/* 1 iff this filesystem accepted a user xattr on `fd` — the whole xattr layer is
 * untestable (and the module falls back to §8.2) when it did not. */
static int
xattr_supported(int fd)
{
    return fsetxattr(fd, "user.brix.probe", "1", 1, 0) == 0;
}

/* ---- test 1: the success path -------------------------------------------- */

static void
test_seed_is_served_without_reading(void)
{
    brix_integrity_info_t info;
    int                     fd = make_file("hello world\n");

    if (!xattr_supported(fd)) {
        printf("  SKIP 1: filesystem has no user xattrs\n");
        close(fd); unlink(g_path);
        return;
    }

    /* Nothing seeded yet: the cache-only reader must DECLINE, not invent. */
    assert(lookup_cached(fd, "sha256", &info) == NGX_DECLINED);

    /* Seed in upper case, under an upper-case algorithm name. */
    assert(brix_integrity_seed_fd(fd, g_path, "SHA256", SHA256_HEX_UPPER)
           == NGX_OK);

    /* ...and look it up canonically: one key, either spelling, lowercase value. */
    ngx_memzero(&info, sizeof(info));
    assert(lookup_cached(fd, "sha256", &info) == NGX_OK);
    assert(info.from_cache == 1);
    assert(strcmp(info.hex, SHA256_HEX_LOWER) == 0);
    assert(strcmp(info.alg_name, "sha256") == 0);

    /* The same for an ALIASED name: a fill that reports "crc64xz" and a client
     * that asks for "crc64" must meet on one cache key, or the seed silently
     * buys nothing for exactly the algorithm whose name has two spellings. */
    assert(brix_integrity_seed_fd(fd, g_path, "crc64xz", CRC64_HEX) == NGX_OK);
    ngx_memzero(&info, sizeof(info));
    assert(lookup_cached(fd, "crc64", &info) == NGX_OK);
    assert(strcmp(info.hex, CRC64_HEX) == 0);
    assert(strcmp(info.alg_name, "crc64") == 0);

    /* A different algorithm is a miss, not the seeded value under a new label. */
    ngx_memzero(&info, sizeof(info));
    assert(lookup_cached(fd, "md5", &info) == NGX_DECLINED);

    close(fd);
    unlink(g_path);
    printf("  ok   1: seeded digest served from cache, name canonicalised (case + alias), value lowercased\n");
}

/* ---- test 2: the error path ----------------------------------------------- */

static void
test_bad_input_is_refused(void)
{
    brix_integrity_info_t info;
    int                     fd = make_file("hello world\n");

    if (!xattr_supported(fd)) {
        printf("  SKIP 2: filesystem has no user xattrs\n");
        close(fd); unlink(g_path);
        return;
    }

    /* No fd to hang it on. */
    assert(brix_integrity_seed_fd(-1, g_path, "sha256", SHA256_HEX_LOWER)
           == NGX_ERROR);
    /* An algorithm this build cannot compute must not get a cache key either —
     * a value nobody can ever re-derive is a value nobody can ever check. */
    assert(brix_integrity_seed_fd(fd, g_path, "notanalgorithm",
                                    SHA256_HEX_LOWER) == NGX_ERROR);
    /* A punctuated spelling the parser refuses outright ("sha-256"): it must not
     * become an xattr key of its own, or a lookup for "sha256" misses forever. */
    assert(brix_integrity_seed_fd(fd, g_path, "sha-256", SHA256_HEX_LOWER)
           == NGX_ERROR);
    assert(brix_integrity_seed_fd(fd, g_path, NULL, SHA256_HEX_LOWER)
           == NGX_ERROR);
    /* Empty, NULL and non-hex values. */
    assert(brix_integrity_seed_fd(fd, g_path, "sha256", "") == NGX_ERROR);
    assert(brix_integrity_seed_fd(fd, g_path, "sha256", NULL) == NGX_ERROR);
    assert(brix_integrity_seed_fd(fd, g_path, "sha256", "dead beef")
           == NGX_ERROR);
    assert(brix_integrity_seed_fd(fd, g_path, "sha256", "deadbeeg")
           == NGX_ERROR);

    /* None of the above wrote anything: the reader still declines. */
    ngx_memzero(&info, sizeof(info));
    assert(lookup_cached(fd, "sha256", &info) == NGX_DECLINED);

    close(fd);
    unlink(g_path);
    printf("  ok   2: bad fd / unknown algorithm / empty / non-hex all refused, nothing stored\n");
}

/* ---- test 3: the security negatives --------------------------------------- */

static void
test_never_truncates_mutates_or_outlives(void)
{
    brix_integrity_info_t info;
    char                    toolong[600];
    struct stat             before, after;
    int                     fd = make_file("hello world\n");

    if (!xattr_supported(fd)) {
        printf("  SKIP 3: filesystem has no user xattrs\n");
        close(fd); unlink(g_path);
        return;
    }

    /* (a) An over-long value is refused WHOLE. The failure mode this pins is a
     *     validate-and-copy loop that leaves a valid PREFIX behind: a 64-hex
     *     head of a 512-hex value is a perfectly well-formed sha256 digest of
     *     nothing, and every later reader would serve it as authoritative. */
    memset(toolong, 'a', sizeof(toolong) - 1);
    toolong[sizeof(toolong) - 1] = '\0';
    assert(brix_integrity_seed_fd(fd, g_path, "sha256", toolong) == NGX_ERROR);
    ngx_memzero(&info, sizeof(info));
    assert(lookup_cached(fd, "sha256", &info) == NGX_DECLINED);

    /* (b) Seeding is metadata-only: it must not touch size or content. */
    assert(fstat(fd, &before) == 0);
    assert(brix_integrity_seed_fd(fd, g_path, "sha256", SHA256_HEX_LOWER)
           == NGX_OK);
    assert(fstat(fd, &after) == 0);
    assert(after.st_size == before.st_size);
    {
        char buf[32];
        assert(pread(fd, buf, 11, 0) == 11);
        assert(memcmp(buf, "hello world", 11) == 0);
    }
    ngx_memzero(&info, sizeof(info));
    assert(lookup_cached(fd, "sha256", &info) == NGX_OK);

    /* (c) A seeded digest describes the bytes it was seeded over and nothing
     *     else. Append one byte and the cache MUST stop answering — otherwise a
     *     rewritten cache entry would keep serving the old file's checksum. */
    assert(write(fd, "!", 1) == 1);
    ngx_memzero(&info, sizeof(info));
    assert(lookup_cached(fd, "sha256", &info) == NGX_DECLINED);

    close(fd);
    unlink(g_path);
    printf("  ok   3: over-long refused whole, file untouched, stale after a write\n");
}

/* ---- test 4: the record fallback ------------------------------------------ */

static void
test_record_fallback_on_no_xattr(void)
{
    int fd;

    /* An fd that cannot carry a user xattr at all: fsetxattr on a pipe fails
     * with the same class of errno an xattr-less filesystem returns, which is
     * exactly the condition the §8.2 record fallback exists for. */
    int pipefd[2];

    assert(pipe(pipefd) == 0);
    fd = pipefd[0];
    g_record_writes = 0;

    /* Validation still runs first — a refused value never reaches either layer. */
    assert(brix_integrity_seed_fd(fd, "/nonexistent/path", "sha256", "zz")
           == NGX_ERROR);
    assert(g_record_writes == 0);

    if (xattr_supported(fd)) {
        /* Not the condition this leg is about; skip rather than assert on it. */
        printf("  SKIP 4: this platform accepts xattrs on a pipe\n");
    } else {
        /* An accepted value on an xattr-incapable target falls through to §8.2
         * exactly once — a seed must not be silently dropped on the exports the
         * fallback exists for. */
        assert(brix_integrity_seed_fd(fd, "/nonexistent/path", "sha256",
                                        SHA256_HEX_LOWER) == NGX_OK);
        assert(g_record_writes == 1);
        printf("  ok   4: refused value reaches neither layer; accepted value falls back to the §8.2 record\n");
    }
    close(pipefd[0]);
    close(pipefd[1]);
}

int
main(void)
{
    test_seed_is_served_without_reading();
    test_bad_input_is_refused();
    test_never_truncates_mutates_or_outlives();
    test_record_fallback_on_no_xattr();
    printf("test_integrity_seed: ALL PASS\n");
    return 0;
}
