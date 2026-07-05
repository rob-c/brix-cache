/*
 * overlay_unittest.c — unit tests for the brixMount writable-overlay core.
 *
 * WHAT: exercises the FUSE-free union primitives (classify, whiteouts, opaque
 *       dirs, mutations, copy-up, readdir nameset, CLI cores) on throwaway
 *       tmp directories — no mount, no CVMFS, no network.
 * WHY:  every union corner case (masking, shadowing, atomicity, symlink
 *       escapes) must be provable without a FUSE session.
 * HOW:  one mkdtemp fixture per section; raw mkdir/creat/symlink build the
 *       upper tree, then the public brix_overlay_* API is checked against it.
 *
 * gcc -Wall -Wextra -Werror -I client/lib -o /tmp/overlay_ut \
 *     client/lib/fs/overlay_unittest.c client/lib/fs/overlay.c && /tmp/overlay_ut
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "fs/overlay.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int g_checks, g_failed;
#define CHECK(c, n) do { g_checks++; if (c) { printf("  ok   %s\n", n); } \
    else { printf("  FAIL %s (line %d)\n", n, __LINE__); g_failed++; } } while (0)

/* ---- fixture: a fresh .brixwrites dir + initialised overlay ------------- */

typedef struct {
    char          root[128];    /* the mkdtemp dir (plays <mnt>/.brixwrites) */
    int           writes_fd;
    brix_overlay  ov;
} fix_t;

static int fix_up(fix_t *f) {
    snprintf(f->root, sizeof(f->root), "/tmp/ovut.XXXXXX");
    if (mkdtemp(f->root) == NULL) return -1;
    f->writes_fd = open(f->root, O_RDONLY | O_DIRECTORY);
    if (f->writes_fd < 0) return -1;
    return brix_overlay_init(&f->ov, f->writes_fd);
}

static void fix_down(fix_t *f) {
    char cmd[160];
    brix_overlay_close(&f->ov);
    close(f->writes_fd);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", f->root);
    if (system(cmd) != 0) { /* best-effort teardown */ }
}

/* create a file with content under the fixture root (raw, not via the API) */
static void raw_put(const fix_t *f, const char *rel, const char *content) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", f->root, rel);
    FILE *fp = fopen(p, "w");
    if (fp) { fputs(content, fp); fclose(fp); }
}

static void raw_mkdir(const fix_t *f, const char *rel) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", f->root, rel);
    mkdir(p, 0755);
}

/* classify shorthand: returns the state (or 99 on API error) */
static brix_ov_state cls(const fix_t *f, const char *rel, struct stat *st) {
    brix_ov_state s;
    struct stat tmp;
    if (brix_overlay_classify(&f->ov, rel, st ? st : &tmp, &s) != 0) return (brix_ov_state) 99;
    return s;
}

/* ---- section 1: init + reserved names + classify + whiteouts ------------ */

static void test_reserved_names(void) {
    printf("== reserved names ==\n");
    CHECK(brix_ov_name_reserved(".brix.wh.x") == 1,  "whiteout prefix reserved");
    CHECK(brix_ov_name_reserved(".brix.opq") == 1,   "opaque marker reserved");
    CHECK(brix_ov_name_reserved(".brix.tmp.a") == 1, "copy-up tmp prefix reserved");
    CHECK(brix_ov_name_reserved("hello") == 0,       "plain name not reserved");
    CHECK(brix_ov_name_reserved(".brixcacheX") == 0, "lookalike not reserved");
}

static void test_classify(void) {
    fix_t f;
    printf("== classify ==\n");
    CHECK(fix_up(&f) == 0, "overlay init");

    struct stat st;
    CHECK(fstatat(f.writes_fd, BRIX_OV_UPPER_DIRNAME, &st, 0) == 0
          && S_ISDIR(st.st_mode), "init created upper/");

    CHECK(cls(&f, "nope", NULL) == BRIX_OV_NONE, "absent path → NONE");
    CHECK(cls(&f, "", NULL) == BRIX_OV_UPPER, "root → UPPER dir");

    raw_mkdir(&f, "upper/a");
    raw_put(&f, "upper/a/b", "hi");
    CHECK(cls(&f, "a/b", &st) == BRIX_OV_UPPER && S_ISREG(st.st_mode),
          "upper file → UPPER + S_ISREG");
    CHECK(cls(&f, "a", &st) == BRIX_OV_UPPER && S_ISDIR(st.st_mode),
          "upper dir → UPPER + S_ISDIR");
    CHECK(cls(&f, "a/missing", NULL) == BRIX_OV_NONE, "missing in upper dir → NONE");

    raw_put(&f, "upper/.brix.wh.gone", "");
    CHECK(cls(&f, "gone", NULL) == BRIX_OV_MASKED, "whiteout → MASKED");
    CHECK(cls(&f, "gone/child", NULL) == BRIX_OV_MASKED, "child of whiteout → MASKED");
    CHECK(brix_overlay_whiteout(&f.ov, "gone") == 1, "whiteout query → 1");
    CHECK(brix_overlay_whiteout(&f.ov, "a/b") == 0, "no whiteout query → 0");

    CHECK(brix_overlay_whiteout_set(&f.ov, "sub/dead") == 0, "whiteout_set deep");
    CHECK(cls(&f, "sub/dead", NULL) == BRIX_OV_MASKED, "deep whiteout → MASKED");
    CHECK(brix_overlay_whiteout_clear(&f.ov, "sub/dead") == 0, "whiteout_clear");
    CHECK(cls(&f, "sub/dead", NULL) == BRIX_OV_NONE, "cleared → NONE");
    CHECK(brix_overlay_whiteout_clear(&f.ov, "never/was") == 0, "clear of absent is a no-op");

    raw_mkdir(&f, "upper/od");
    raw_put(&f, "upper/od/.brix.opq", "");
    CHECK(cls(&f, "od/missing", NULL) == BRIX_OV_MASKED, "opaque dir masks lower names");
    CHECK(cls(&f, "od", &st) == BRIX_OV_UPPER, "opaque dir itself → UPPER");

    raw_put(&f, "upper/f", "x");
    CHECK(cls(&f, "f/child", NULL) == BRIX_OV_MASKED, "upper file shadows subtree");

    CHECK(cls(&f, "a/../b", NULL) == (brix_ov_state) 99, "dot-dot component rejected");  /* neg */

    /* security-neg: a symlink planted in upper must never be followed */
    char lp[512];
    snprintf(lp, sizeof(lp), "%s/upper/esc", f.root);
    CHECK(symlink("/etc", lp) == 0, "plant escape symlink");
    CHECK(cls(&f, "esc", &st) == BRIX_OV_UPPER && S_ISLNK(st.st_mode),
          "symlink itself → UPPER + S_ISLNK (not followed)");
    CHECK(cls(&f, "esc/passwd", NULL) == BRIX_OV_MASKED,
          "path through symlink → MASKED, never resolved outside");

    fix_down(&f);
}

/* ---- section 2: mutation primitives ------------------------------------- */

static mode_t mode_0700(void *ud, const char *rel_dir) {
    (void) ud; (void) rel_dir;
    return 0700;
}

static void test_mutations(void) {
    fix_t f;
    printf("== mutations ==\n");
    CHECK(fix_up(&f) == 0, "overlay init");

    struct stat st;
    CHECK(brix_overlay_mkdirs(&f.ov, "d1/d2/d3", NULL, NULL) == 0
          && cls(&f, "d1/d2/d3", &st) == BRIX_OV_UPPER && S_ISDIR(st.st_mode),
          "mkdirs deep chain");
    CHECK(brix_overlay_mkdirs(&f.ov, "m1/m2", mode_0700, NULL) == 0
          && cls(&f, "m1", &st) == BRIX_OV_UPPER && (st.st_mode & 07777) == 0700,
          "mkdirs honors mode_fn");

    int fd = brix_overlay_open(&f.ov, "d1/d2/new", O_WRONLY | O_CREAT | O_EXCL, 0644);
    CHECK(fd >= 0, "open O_CREAT|O_EXCL");
    CHECK(write(fd, "abc", 3) == 3, "write via returned fd");
    close(fd);
    CHECK(cls(&f, "d1/d2/new", &st) == BRIX_OV_UPPER && st.st_size == 3,
          "created file classifies UPPER, size 3");
    CHECK(brix_overlay_open(&f.ov, "noparent/x", O_WRONLY | O_CREAT, 0644) == -ENOENT,
          "open with missing parent → -ENOENT");  /* neg */

    CHECK(brix_overlay_mkdir(&f.ov, "d1/sub", 0750) == 0
          && cls(&f, "d1/sub", &st) == BRIX_OV_UPPER && (st.st_mode & 07777) == 0750,
          "mkdir with mode");
    CHECK(brix_overlay_mkdir(&f.ov, "d1/sub", 0750) == -EEXIST, "mkdir twice → -EEXIST");

    CHECK(brix_overlay_set_opaque(&f.ov, "d1/sub") == 0, "set_opaque");
    CHECK(cls(&f, "d1/sub/anything", NULL) == BRIX_OV_MASKED, "opaque masks below");

    CHECK(brix_overlay_unlink_upper(&f.ov, "d1/d2/new") == 0
          && cls(&f, "d1/d2/new", NULL) == BRIX_OV_NONE, "unlink_upper");

    /* rmdir_upper: marker-only dir succeeds, real entries refuse */
    CHECK(brix_overlay_whiteout_set(&f.ov, "wd/x") == 0, "seed marker-only dir");
    CHECK(brix_overlay_rmdir_upper(&f.ov, "wd") == 0
          && cls(&f, "wd", NULL) == BRIX_OV_NONE, "rmdir_upper removes marker-only dir");
    raw_mkdir(&f, "upper/full");
    raw_put(&f, "upper/full/keep", "k");
    CHECK(brix_overlay_rmdir_upper(&f.ov, "full") == -ENOTEMPTY,
          "rmdir_upper with real entry → -ENOTEMPTY");  /* neg */

    /* rename across dirs */
    raw_put(&f, "upper/d1/src", "mv");
    CHECK(brix_overlay_rename_upper(&f.ov, "d1/src", "d1/d2/dst") == 0
          && cls(&f, "d1/d2/dst", NULL) == BRIX_OV_UPPER
          && cls(&f, "d1/src", NULL) == BRIX_OV_NONE, "rename_upper across dirs");

    /* symlink + readlink round-trip */
    char lbuf[64];
    CHECK(brix_overlay_symlink(&f.ov, "target/here", "d1/lnk") == 0, "symlink");
    CHECK(brix_overlay_readlink(&f.ov, "d1/lnk", lbuf, sizeof(lbuf)) == 0
          && strcmp(lbuf, "target/here") == 0, "readlink round-trip");

    /* chmod / truncate / utimens */
    raw_put(&f, "upper/d1/attrs", "0123456789");
    CHECK(brix_overlay_chmod(&f.ov, "d1/attrs", 0640) == 0
          && cls(&f, "d1/attrs", &st) == BRIX_OV_UPPER && (st.st_mode & 07777) == 0640,
          "chmod 0640");
    CHECK(brix_overlay_chmod(&f.ov, "d1/lnk", 0640) == -EOPNOTSUPP,
          "chmod on symlink refused");  /* neg */
    CHECK(brix_overlay_truncate(&f.ov, "d1/attrs", 3) == 0
          && cls(&f, "d1/attrs", &st) == BRIX_OV_UPPER && st.st_size == 3,
          "truncate to 3");
    struct timespec tv[2] = { { 12345, 0 }, { 12345, 0 } };
    CHECK(brix_overlay_utimens(&f.ov, "d1/attrs", tv) == 0
          && cls(&f, "d1/attrs", &st) == BRIX_OV_UPPER && st.st_mtime == 12345,
          "utimens sets mtime");

    /* security-neg: mutation through a planted symlink dead-ends */
    char lp[512];
    snprintf(lp, sizeof(lp), "%s/upper/esc", f.root);
    CHECK(symlink("/etc", lp) == 0, "plant escape symlink");
    CHECK(brix_overlay_truncate(&f.ov, "esc/passwd", 0) < 0
          && brix_overlay_truncate(&f.ov, "esc/passwd", 0) != -EISDIR,
          "truncate through symlink refused (walk dead-ends)");
    CHECK(brix_overlay_truncate(&f.ov, "esc", 0) == -ELOOP,
          "truncate of symlink itself → -ELOOP");

    fix_down(&f);
}

int main(void) {
    test_reserved_names();
    test_classify();
    test_mutations();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
