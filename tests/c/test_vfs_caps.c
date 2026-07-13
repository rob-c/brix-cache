/* test_vfs_caps.c — phase-71 capability-uniformity unit test.
 *
 * WHAT: Exercises the two accessors the VFS now uses to make backend-neutral
 *       decisions — brix_sd_supports() (capability bitmap) and the new
 *       brix_sd_cred_accept() (delegation-kind mask) — against synthetic driver
 *       structs standing in for read-only / writable / bearer-only / proxy-only
 *       backends. This is the storage-neutral half of phase-71: proves the gates
 *       the VFS wrappers call (CAP_DIRS_WRITE, CAP_XATTR_WRITE, CAP_TRUNCATE,
 *       cred_accept) return the right verdict per declared caps, with no backend
 *       identity anywhere.
 *
 * WHY:  The VFS op guards (mkdir/rename → CAP_DIRS_WRITE, set/removexattr →
 *       CAP_XATTR_WRITE, truncate → CAP_TRUNCATE, deleg → cred_accept) are only
 *       as correct as these accessors; a regression here silently re-opens the
 *       identity-branch hole the guard forbids.
 */
#include <stdio.h>
#include "fs/backend/sd.h"

/* sd_registry.o (which carries the accessors under test) references these driver
 * struct symbols in its static registration table. We link only sd_registry.o,
 * so provide minimal stub definitions to satisfy the linker; the accessors under
 * test operate only on the synthetic drivers below, never on these. */
const brix_sd_driver_t brix_sd_posix_driver;
const brix_sd_driver_t brix_sd_block_driver;
const brix_sd_driver_t brix_sd_pblock_driver;

/* sd_registry's instance-create path (unreached by this test) pulls these two
 * nginx pool symbols; stub them so the object links standalone. */
ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log)
    { (void) size; (void) log; return NULL; }
void *ngx_pcalloc(ngx_pool_t *pool, size_t size)
    { (void) pool; (void) size; return NULL; }

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else         { printf("ok  : %s\n", msg); } } while (0)

int
main(void)
{
    /* A read-only catalog backend: lists dirs + reads xattrs, but cannot mutate
     * either, cannot truncate, and consumes no delegated credential. */
    static const brix_sd_driver_t ro = {
        .name = "ro", .cred_accept = BRIX_SD_CRED_NONE,
        .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_DIRS | BRIX_SD_CAP_XATTR,
    };
    /* A fully writable local backend + a bearer-only remote + a proxy-only remote. */
    static const brix_sd_driver_t rw = {
        .name = "rw",
        .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_RANDOM_WRITE
              | BRIX_SD_CAP_TRUNCATE | BRIX_SD_CAP_DIRS | BRIX_SD_CAP_DIRS_WRITE
              | BRIX_SD_CAP_XATTR | BRIX_SD_CAP_XATTR_WRITE,
    };
    static const brix_sd_driver_t bearer_only = {
        .name = "bearer", .cred_accept = BRIX_SD_CRED_BEARER,
        .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_MEMFILE,
    };
    static const brix_sd_driver_t proxy_only = {
        .name = "proxy", .cred_accept = BRIX_SD_CRED_PROXY_PEM,
        .caps = BRIX_SD_CAP_RANGE_READ | BRIX_SD_CAP_MEMFILE,
    };

    brix_sd_instance_t i_ro = { .driver = &ro };
    brix_sd_instance_t i_rw = { .driver = &rw };
    brix_sd_instance_t i_be = { .driver = &bearer_only };
    brix_sd_instance_t i_px = { .driver = &proxy_only };

    /* catalog mutation (mkdir/rename) — CAP_DIRS_WRITE */
    CHECK(brix_sd_supports(&i_rw, BRIX_SD_CAP_DIRS_WRITE) == NGX_OK,
          "rw backend supports CAP_DIRS_WRITE (mkdir/rename allowed)");
    CHECK(brix_sd_supports(&i_ro, BRIX_SD_CAP_DIRS_WRITE) != NGX_OK,
          "ro backend lacks CAP_DIRS_WRITE (mkdir/rename -> EPERM)");
    CHECK(brix_sd_supports(&i_ro, BRIX_SD_CAP_DIRS) == NGX_OK,
          "ro backend still supports CAP_DIRS (listing allowed)");

    /* xattr write (set/removexattr) — CAP_XATTR_WRITE, reads use CAP_XATTR */
    CHECK(brix_sd_supports(&i_rw, BRIX_SD_CAP_XATTR_WRITE) == NGX_OK,
          "rw backend supports CAP_XATTR_WRITE (set/remove allowed)");
    CHECK(brix_sd_supports(&i_ro, BRIX_SD_CAP_XATTR_WRITE) != NGX_OK,
          "ro backend lacks CAP_XATTR_WRITE (set/remove -> ENOTSUP)");
    CHECK(brix_sd_supports(&i_ro, BRIX_SD_CAP_XATTR) == NGX_OK,
          "ro backend still supports CAP_XATTR (get/list allowed)");

    /* truncate — CAP_TRUNCATE */
    CHECK(brix_sd_supports(&i_rw, BRIX_SD_CAP_TRUNCATE) == NGX_OK,
          "rw backend supports CAP_TRUNCATE");
    CHECK(brix_sd_supports(&i_ro, BRIX_SD_CAP_TRUNCATE) != NGX_OK,
          "ro backend lacks CAP_TRUNCATE (resize -> ENOTSUP)");

    /* delegation-kind accept mask — brix_sd_cred_accept */
    CHECK((brix_sd_cred_accept(&i_be) & BRIX_SD_CRED_BEARER) != 0,
          "bearer-only backend accepts a bearer");
    CHECK((brix_sd_cred_accept(&i_be) & BRIX_SD_CRED_PROXY_PEM) == 0,
          "bearer-only backend REJECTS a proxy_pem (deny before origin)");
    CHECK((brix_sd_cred_accept(&i_px) & BRIX_SD_CRED_PROXY_PEM) != 0,
          "proxy-only backend accepts a proxy_pem");
    CHECK((brix_sd_cred_accept(&i_px) & BRIX_SD_CRED_BEARER) == 0,
          "proxy-only backend REJECTS a bearer (deny before origin)");
    CHECK(brix_sd_cred_accept(&i_ro) == 0,
          "no-delegation backend rejects both kinds");

    /* NULL-safety (the accessors must tolerate a NULL instance) */
    CHECK(brix_sd_cred_accept(NULL) == 0, "cred_accept(NULL) == 0");
    CHECK(brix_sd_supports(NULL, BRIX_SD_CAP_DIRS_WRITE) != NGX_OK,
          "supports(NULL, ...) != NGX_OK");

    printf(fails ? "\n%d FAILED\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
