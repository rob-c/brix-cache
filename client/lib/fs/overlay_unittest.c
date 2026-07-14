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

/* ---- mkdirs + create + mkdir + opaque + unlink ----
 *
 * WHAT: asserts the directory-creating and file-creating mutation primitives —
 *       brix_overlay_mkdirs (default + mode_fn), brix_overlay_open (O_CREAT and
 *       missing-parent -ENOENT), brix_overlay_mkdir (mode + -EEXIST on repeat),
 *       set_opaque masking, and unlink_upper. Populates the fixture upper tree
 *       (under d1/d2 and m1) that later mutation groups depend on.
 * WHY:  split out of test_mutations so each named mutation family stays under
 *       the per-function complexity cap while every assertion and its ordering
 *       are preserved exactly.
 * HOW:  (1) mkdirs a deep chain, then one honoring the mode callback; (2) open
 *       O_CREAT|O_EXCL, write, close, and re-classify the new file; (3) reject a
 *       missing-parent create; (4) mkdir with an explicit mode, then twice;
 *       (5) set_opaque and confirm it masks below; (6) unlink_upper the created
 *       file back to NONE.
 */
static void test_mut_mkdirs_create(fix_t *f) {
    struct stat st;
    CHECK(brix_overlay_mkdirs(&f->ov, "d1/d2/d3", NULL, NULL) == 0
          && cls(f, "d1/d2/d3", &st) == BRIX_OV_UPPER && S_ISDIR(st.st_mode),
          "mkdirs deep chain");
    CHECK(brix_overlay_mkdirs(&f->ov, "m1/m2", mode_0700, NULL) == 0
          && cls(f, "m1", &st) == BRIX_OV_UPPER && (st.st_mode & 07777) == 0700,
          "mkdirs honors mode_fn");

    int fd = brix_overlay_open(&f->ov, "d1/d2/new", O_WRONLY | O_CREAT | O_EXCL, 0644);
    CHECK(fd >= 0, "open O_CREAT|O_EXCL");
    CHECK(write(fd, "abc", 3) == 3, "write via returned fd");
    close(fd);
    CHECK(cls(f, "d1/d2/new", &st) == BRIX_OV_UPPER && st.st_size == 3,
          "created file classifies UPPER, size 3");
    CHECK(brix_overlay_open(&f->ov, "noparent/x", O_WRONLY | O_CREAT, 0644) == -ENOENT,
          "open with missing parent → -ENOENT");  /* neg */

    CHECK(brix_overlay_mkdir(&f->ov, "d1/sub", 0750) == 0
          && cls(f, "d1/sub", &st) == BRIX_OV_UPPER && (st.st_mode & 07777) == 0750,
          "mkdir with mode");
    CHECK(brix_overlay_mkdir(&f->ov, "d1/sub", 0750) == -EEXIST, "mkdir twice → -EEXIST");

    CHECK(brix_overlay_set_opaque(&f->ov, "d1/sub") == 0, "set_opaque");
    CHECK(cls(f, "d1/sub/anything", NULL) == BRIX_OV_MASKED, "opaque masks below");

    CHECK(brix_overlay_unlink_upper(&f->ov, "d1/d2/new") == 0
          && cls(f, "d1/d2/new", NULL) == BRIX_OV_NONE, "unlink_upper");
}

/* ---- rmdir_upper: marker-only vs real-entry ----
 *
 * WHAT: asserts brix_overlay_rmdir_upper removes a dir holding only overlay
 *       markers (a seeded whiteout) yet refuses one with a real child, returning
 *       -ENOTEMPTY.
 * WHY:  rmdir must treat overlay bookkeeping entries as absent while protecting
 *       user data — the marker-only-succeeds / real-entry-refuses split is the
 *       load-bearing corner case.
 * HOW:  (1) seed a whiteout under wd/, rmdir it, confirm NONE; (2) raw-build a
 *       dir with a real file and confirm rmdir_upper returns -ENOTEMPTY.
 */
static void test_mut_rmdir(fix_t *f) {
    CHECK(brix_overlay_whiteout_set(&f->ov, "wd/x") == 0, "seed marker-only dir");
    CHECK(brix_overlay_rmdir_upper(&f->ov, "wd") == 0
          && cls(f, "wd", NULL) == BRIX_OV_NONE, "rmdir_upper removes marker-only dir");
    raw_mkdir(f, "upper/full");
    raw_put(f, "upper/full/keep", "k");
    CHECK(brix_overlay_rmdir_upper(&f->ov, "full") == -ENOTEMPTY,
          "rmdir_upper with real entry → -ENOTEMPTY");  /* neg */
}

/* ---- rename + symlink + readlink ----
 *
 * WHAT: asserts brix_overlay_rename_upper moves a file across dirs (source →
 *       NONE, dest → UPPER) and that symlink/readlink round-trip the target
 *       string unchanged.
 * WHY:  rename and symlink are the remaining namespace-shaping mutations; kept
 *       together as one small, nameable group.
 * HOW:  (1) raw-seed d1/src, rename to d1/d2/dst, check both endpoints;
 *       (2) create a symlink, read it back, and strcmp the target.
 */
static void test_mut_rename_symlink(fix_t *f) {
    raw_put(f, "upper/d1/src", "mv");
    CHECK(brix_overlay_rename_upper(&f->ov, "d1/src", "d1/d2/dst") == 0
          && cls(f, "d1/d2/dst", NULL) == BRIX_OV_UPPER
          && cls(f, "d1/src", NULL) == BRIX_OV_NONE, "rename_upper across dirs");

    char lbuf[64];
    CHECK(brix_overlay_symlink(&f->ov, "target/here", "d1/lnk") == 0, "symlink");
    CHECK(brix_overlay_readlink(&f->ov, "d1/lnk", lbuf, sizeof(lbuf)) == 0
          && strcmp(lbuf, "target/here") == 0, "readlink round-trip");
}

/* ---- chmod / truncate / utimens ----
 *
 * WHAT: asserts the attribute-mutating primitives — chmod (0640 applied, symlink
 *       refused with -EOPNOTSUPP), truncate (size 3), and utimens (mtime 12345)
 *       — each re-classifying the target as UPPER after the change.
 * WHY:  attribute mutations must land on the upper copy and reject a symlink
 *       target; grouped so the metadata-mutation family is independently
 *       reviewable. Depends on d1/lnk seeded by the rename+symlink group.
 * HOW:  (1) raw-seed d1/attrs; (2) chmod it 0640 and re-stat; (3) chmod the
 *       symlink and expect -EOPNOTSUPP; (4) truncate to 3 and re-stat;
 *       (5) utimens and confirm mtime.
 */
static void test_mut_attrs(fix_t *f) {
    struct stat st;
    raw_put(f, "upper/d1/attrs", "0123456789");
    CHECK(brix_overlay_chmod(&f->ov, "d1/attrs", 0640) == 0
          && cls(f, "d1/attrs", &st) == BRIX_OV_UPPER && (st.st_mode & 07777) == 0640,
          "chmod 0640");
    CHECK(brix_overlay_chmod(&f->ov, "d1/lnk", 0640) == -EOPNOTSUPP,
          "chmod on symlink refused");  /* neg */
    CHECK(brix_overlay_truncate(&f->ov, "d1/attrs", 3) == 0
          && cls(f, "d1/attrs", &st) == BRIX_OV_UPPER && st.st_size == 3,
          "truncate to 3");
    struct timespec tv[2] = { { 12345, 0 }, { 12345, 0 } };
    CHECK(brix_overlay_utimens(&f->ov, "d1/attrs", tv) == 0
          && cls(f, "d1/attrs", &st) == BRIX_OV_UPPER && st.st_mtime == 12345,
          "utimens sets mtime");
}

/* ---- security-neg: mutation through a planted symlink ----
 *
 * WHAT: asserts a symlink planted in upper is never followed by mutations —
 *       truncate through it fails (and not as -EISDIR, proving the walk
 *       dead-ended rather than resolving), and truncate of the symlink itself
 *       returns -ELOOP.
 * WHY:  the core symlink-escape invariant — the confined walk must not resolve
 *       outside the overlay root — must hold for the mutation path too.
 * HOW:  (1) plant an /etc symlink at upper/esc; (2) truncate esc/passwd and
 *       assert it fails but not with -EISDIR; (3) truncate esc and expect -ELOOP.
 */
static void test_mut_symlink_escape(fix_t *f) {
    char lp[512];
    snprintf(lp, sizeof(lp), "%s/upper/esc", f->root);
    CHECK(symlink("/etc", lp) == 0, "plant escape symlink");
    CHECK(brix_overlay_truncate(&f->ov, "esc/passwd", 0) < 0
          && brix_overlay_truncate(&f->ov, "esc/passwd", 0) != -EISDIR,
          "truncate through symlink refused (walk dead-ends)");
    CHECK(brix_overlay_truncate(&f->ov, "esc", 0) == -ELOOP,
          "truncate of symlink itself → -ELOOP");
}

/* ---- section 2 driver: mutation primitives ----
 *
 * WHAT: runs the mutation-primitive test groups in order against one fixture.
 * WHY:  each group is a small single-purpose helper; this driver only owns the
 *       fixture lifecycle and the fixed execution order the groups depend on
 *       (create → rmdir → rename/symlink → attrs → symlink-escape).
 * HOW:  (1) fix_up; (2) call each test_mut_* group in dependency order;
 *       (3) fix_down.
 */
static void test_mutations(void) {
    fix_t f;
    printf("== mutations ==\n");
    CHECK(fix_up(&f) == 0, "overlay init");

    test_mut_mkdirs_create(&f);
    test_mut_rmdir(&f);
    test_mut_rename_symlink(&f);
    test_mut_attrs(&f);
    test_mut_symlink_escape(&f);

    fix_down(&f);
}

/* ---- section 3: copy-up -------------------------------------------------- */

#define CU_SIZE (3u * 1024u * 1024u)   /* 3 MiB → exercises the chunk loop */

typedef struct { int fail_at_mib; } cu_src_t;

/* mock lower reader: byte i = (i * 7) & 0xff; optional -EIO at a boundary */
static int cu_read(void *ud, const char *rel, uint64_t off, size_t len,
                   unsigned char *buf, size_t *outlen) {
    cu_src_t *s = ud;
    (void) rel;
    if (s->fail_at_mib >= 0 && off >= (uint64_t) s->fail_at_mib * 1024 * 1024)
        return -EIO;
    if (off >= CU_SIZE) { *outlen = 0; return 0; }
    size_t n = len;
    if (off + n > CU_SIZE) n = CU_SIZE - off;
    for (size_t i = 0; i < n; i++) buf[i] = (unsigned char) (((off + i) * 7) & 0xff);
    *outlen = n;
    return 0;
}

/* any ".brix.tmp.*" residue under upper/<dir>? */
static int cu_tmp_residue(const fix_t *f) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "find '%s/upper' -name '.brix.tmp.*' | grep -q .", f->root);
    return system(cmd) == 0;
}

static void test_copyup(void) {
    fix_t f;
    printf("== copy-up ==\n");
    CHECK(fix_up(&f) == 0, "overlay init");

    struct stat lower = { 0 };
    lower.st_size  = CU_SIZE;
    lower.st_mode  = S_IFREG | 0664;
    lower.st_mtime = 424242;

    cu_src_t ok_src = { .fail_at_mib = -1 };
    CHECK(brix_overlay_copyup(&f.ov, "sw/pkg/big.bin", &lower, cu_read, &ok_src) == 0,
          "copyup succeeds");
    struct stat st;
    CHECK(cls(&f, "sw/pkg/big.bin", &st) == BRIX_OV_UPPER
          && (uint64_t) st.st_size == CU_SIZE, "target UPPER with full size");
    CHECK((st.st_mode & 07777) == 0664, "lower mode preserved");
    CHECK(st.st_mtime == 424242, "lower mtime preserved");
    CHECK(!cu_tmp_residue(&f), "no tmp residue after success");

    int fd = brix_overlay_open(&f.ov, "sw/pkg/big.bin", O_RDONLY, 0);
    unsigned char b[3];
    CHECK(fd >= 0 && pread(fd, b, 3, 2u * 1024u * 1024u + 1u) == 3 /* vfs-seam-allow: unit-test spot-check on local overlay fixture file, not export data */
          && b[0] == (unsigned char) (((2u * 1024u * 1024u + 1u) * 7) & 0xff),
          "byte spot-check past 2 MiB");
    if (fd >= 0) close(fd);

    /* copy-up over an existing whiteout clears it */
    CHECK(brix_overlay_whiteout_set(&f.ov, "sw/pkg/back") == 0, "seed whiteout");
    CHECK(brix_overlay_copyup(&f.ov, "sw/pkg/back", &lower, cu_read, &ok_src) == 0
          && brix_overlay_whiteout(&f.ov, "sw/pkg/back") == 0,
          "copyup clears whiteout");

    /* error-neg: reader failing mid-stream leaves nothing behind */
    cu_src_t bad_src = { .fail_at_mib = 1 };
    CHECK(brix_overlay_copyup(&f.ov, "sw/pkg/torn.bin", &lower, cu_read, &bad_src) == -EIO,
          "mid-stream -EIO propagates");
    CHECK(cls(&f, "sw/pkg/torn.bin", NULL) == BRIX_OV_NONE, "no torn target");
    CHECK(!cu_tmp_residue(&f), "no tmp residue after failure");

    fix_down(&f);
}

/* ---- section 4: readdir nameset ------------------------------------------ */

static void test_nameset(void) {
    fix_t f;
    printf("== readdir nameset ==\n");
    CHECK(fix_up(&f) == 0, "overlay init");

    raw_mkdir(&f, "upper/d");
    raw_put(&f, "upper/d/a", "1");
    raw_mkdir(&f, "upper/d/sub");
    raw_put(&f, "upper/d/.brix.wh.gone", "");
    raw_put(&f, "upper/d/.brix.opq", "");
    raw_put(&f, "upper/d/.brix.tmp.x", "");

    brix_ov_nameset set;
    int opaque = -1;
    CHECK(brix_overlay_read_upper(&f.ov, "d", &set, &opaque) == 0, "read_upper");
    CHECK(set.count == 3, "3 entries (a, sub, gone) — tmp/opq stripped");
    CHECK(opaque == 1, "opaque detected");
    CHECK(brix_ov_nameset_flag(&set, "a") == 'u', "a flagged upper");
    CHECK(brix_ov_nameset_flag(&set, "sub") == 'u', "sub flagged upper");
    CHECK(brix_ov_nameset_flag(&set, "gone") == 'w', "gone flagged whiteout");
    CHECK(brix_ov_nameset_flag(&set, "other") == 0, "absent name → 0");

    size_t uppers = 0, whs = 0;
    for (size_t i = 0; i < set.count; i++) {
        char fl = 0;
        const char *nm = brix_ov_nameset_at(&set, i, &fl);
        if (nm != NULL && fl == 'u') uppers++;
        if (nm != NULL && fl == 'w') whs++;
    }
    CHECK(uppers == 2 && whs == 1, "iteration sees 2 upper + 1 whiteout");
    CHECK(brix_ov_nameset_at(&set, 3, NULL) == NULL, "out-of-range → NULL");
    brix_ov_nameset_free(&set);

    brix_ov_nameset empty;
    opaque = -1;
    CHECK(brix_overlay_read_upper(&f.ov, "noexist", &empty, &opaque) == 0
          && empty.count == 0 && opaque == 0, "missing upper dir → empty set");
    brix_ov_nameset_free(&empty);

    fix_down(&f);
}

/* ---- section 5: CLI cores (--overlay-list / --overlay-reset) ------------- */

/* The CLI operates on <mountdir>/.brixwrites — build a fake mountdir whose
 * .brixwrites is the fixture root (raw-dir mode, i.e. unmounted). */
static void test_cli(void) {
    printf("== CLI list/reset ==\n");

    char mnt[128];
    snprintf(mnt, sizeof(mnt), "/tmp/ovcli.XXXXXX");
    CHECK(mkdtemp(mnt) != NULL, "mountdir fixture");
    char wr[256];
    snprintf(wr, sizeof(wr), "%s/" BRIX_OV_DIRNAME "/" BRIX_OV_UPPER_DIRNAME "/sub", mnt);
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s' && echo n > '%s/../n.txt' && echo m > '%s/m.txt' "
             "&& touch '%s/../.brix.wh.del' '%s/.brix.opq'", wr, wr, wr, wr, wr);
    CHECK(system(cmd) == 0, "seed upper tree");

    char  *lbuf = NULL;
    size_t llen = 0;
    FILE  *ls = open_memstream(&lbuf, &llen);
    CHECK(brix_overlay_cli_list(mnt, ls) == 0, "list rc 0");
    fclose(ls);
    CHECK(lbuf != NULL && strstr(lbuf, "upper n.txt\n") != NULL, "lists upper n.txt");
    CHECK(lbuf != NULL && strstr(lbuf, "dir sub\n") != NULL, "lists dir sub");
    CHECK(lbuf != NULL && strstr(lbuf, "upper sub/m.txt\n") != NULL, "lists nested file");
    CHECK(lbuf != NULL && strstr(lbuf, "deleted del\n") != NULL, "lists whiteout as deleted");
    CHECK(lbuf != NULL && strstr(lbuf, ".brix.opq") == NULL, "opaque marker not listed");
    free(lbuf);

    CHECK(brix_overlay_cli_reset(mnt) == 0, "reset rc 0");
    char up[256];
    snprintf(up, sizeof(up), "%s/" BRIX_OV_DIRNAME "/" BRIX_OV_UPPER_DIRNAME, mnt);
    struct stat st;
    CHECK(lstat(up, &st) == 0 && S_ISDIR(st.st_mode), "upper/ still present");
    snprintf(cmd, sizeof(cmd), "find '%s' -mindepth 1 | grep -q .", up);
    CHECK(system(cmd) != 0, "upper/ emptied");

    /* error-neg: a dir with no .brixwrites is refused untouched */
    char plain[128];
    snprintf(plain, sizeof(plain), "/tmp/ovplain.XXXXXX");
    CHECK(mkdtemp(plain) != NULL, "plain dir fixture");
    snprintf(cmd, sizeof(cmd), "touch '%s/keep'", plain);
    CHECK(system(cmd) == 0, "seed plain dir");
    FILE *devnull = fopen("/dev/null", "w");
    CHECK(brix_overlay_cli_list(plain, devnull) == 2, "list on non-overlay dir → 2");
    CHECK(brix_overlay_cli_reset(plain) == 2, "reset on non-overlay dir → 2");
    fclose(devnull);
    snprintf(cmd, sizeof(cmd), "test -f '%s/keep'", plain);
    CHECK(system(cmd) == 0, "plain dir untouched");

    snprintf(cmd, sizeof(cmd), "rm -rf '%s' '%s'", mnt, plain);
    if (system(cmd) != 0) { /* best-effort teardown */ }
}

int main(void) {
    test_reserved_names();
    test_classify();
    test_mutations();
    test_copyup();
    test_nameset();
    test_cli();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
