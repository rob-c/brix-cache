/*
 * sd_pblock_catalog_unittest.c — standalone unit test for the pblock SQLite
 * metadata catalog (sd_pblock_catalog.c). Pure libc + sqlite3, no nginx and no
 * running server: builds a throwaway catalog under a temp directory and drives
 * the public API directly.
 *
 * Build & run:
 *   cc -Wall -Wextra -I. sd_pblock_catalog_unittest.c sd_pblock_catalog.c \
 *      -lsqlite3 -o /tmp/pb_cat_ut && /tmp/pb_cat_ut
 */
#include "sd_pblock_catalog.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: ", __func__, __LINE__);              \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static pblock_meta
file_meta(const char *blob_id, int64_t size)
{
    pblock_meta m;

    memset(&m, 0, sizeof(m));
    m.is_dir = 0;
    snprintf(m.blob_id, sizeof(m.blob_id), "%s", blob_id);
    m.size       = size;
    m.block_size = 1 << 20;   /* 1 MiB */
    m.mtime = 1000;
    m.ctime = 1000;
    m.mode  = S_IFREG | 0644;
    return m;
}

static pblock_meta
dir_meta(void)
{
    pblock_meta m;

    memset(&m, 0, sizeof(m));
    m.is_dir = 1;
    m.mode   = S_IFDIR | 0755;
    m.mtime  = 1000;
    m.ctime  = 1000;
    return m;
}

/* put -> lookup round-trips every field; absent paths report not-found. */
static void
test_put_lookup(pblock_catalog *cat)
{
    pblock_meta in = file_meta("0123456789abcdef0123456789abcdef", 4242);
    pblock_meta out;

    CHECK(pblock_catalog_put(cat, "/a.txt", &in) == 0, "put failed: %s",
          strerror(errno));
    CHECK(pblock_catalog_lookup(cat, "/a.txt", &out) == 0, "lookup miss");
    CHECK(out.is_dir == 0, "is_dir wrong");
    CHECK(out.size == 4242, "size %lld", (long long) out.size);
    CHECK(out.block_size == (1 << 20), "block_size %lld",
          (long long) out.block_size);
    CHECK(strcmp(out.blob_id, in.blob_id) == 0, "blob_id %s", out.blob_id);
    CHECK((out.mode & 0777) == 0644, "mode %o", out.mode);

    CHECK(pblock_catalog_lookup(cat, "/nope.txt", &out) == 1, "ghost found");
}

/* touch updates only size+mtime and only for existing rows. */
static void
test_parent_gate(pblock_catalog *cat)
{
    /* phase-68 orphan fix: every create requires its immediate parent to
     * exist and be a directory — an orphan row (reachable by key, invisible
     * to every listing) must be impossible. */
    pblock_meta in, out;

    memset(&in, 0, sizeof(in));
    in.mode = S_IFREG | 0644;

    errno = 0;
    CHECK(pblock_catalog_put(cat, "/ghostdir/file", &in) != 0
          && errno == ENOENT, "orphan put allowed (errno %d)", errno);
    CHECK(pblock_catalog_create(cat, "/ghostdir/sub/leaf", &in) != 0
          && errno == ENOENT, "orphan create allowed (errno %d)", errno);
    CHECK(pblock_catalog_lookup(cat, "/ghostdir/file", &out) == 1,
          "orphan row landed anyway");

    /* parent present but NOT a directory -> ENOTDIR */
    CHECK(pblock_catalog_put(cat, "/plainfile", &in) == 0, "seed file");
    errno = 0;
    CHECK(pblock_catalog_put(cat, "/plainfile/child", &in) != 0
          && errno == ENOTDIR, "file-as-parent allowed (errno %d)", errno);

    /* the chain in order works, and rename into a missing parent fails */
    memset(&in, 0, sizeof(in));
    in.is_dir = 1;
    in.mode = S_IFDIR | 0755;
    CHECK(pblock_catalog_put(cat, "/ghostdir", &in) == 0, "mkdir parent");
    memset(&in, 0, sizeof(in));
    in.mode = S_IFREG | 0644;
    CHECK(pblock_catalog_put(cat, "/ghostdir/file", &in) == 0,
          "put after mkdir");
    errno = 0;
    CHECK(pblock_catalog_rename(cat, "/ghostdir/file", "/nowhere/f") != 0
          && errno == ENOENT, "rename into missing parent allowed");
    CHECK(pblock_catalog_remove(cat, "/ghostdir/file") == 0, "cleanup file");
    CHECK(pblock_catalog_remove(cat, "/ghostdir") == 0, "cleanup dir");
    CHECK(pblock_catalog_remove(cat, "/plainfile") == 0, "cleanup plain");
}

static void
test_touch(pblock_catalog *cat)
{
    pblock_meta in = file_meta("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0);
    pblock_meta out;

    CHECK(pblock_catalog_put(cat, "/grow", &in) == 0, "put failed");
    CHECK(pblock_catalog_touch(cat, "/grow", 9000, 1234) == 0, "touch failed");
    CHECK(pblock_catalog_lookup(cat, "/grow", &out) == 0, "lookup miss");
    CHECK(out.size == 9000, "size not updated: %lld", (long long) out.size);
    CHECK(out.mtime == 1234, "mtime not updated: %lld", (long long) out.mtime);

    errno = 0;
    CHECK(pblock_catalog_touch(cat, "/absent", 1, 1) == -1 && errno == ENOENT,
          "touch on absent row should ENOENT");
}

/* child_count reflects direct children; remove drops the row. */
static void
test_children_and_remove(pblock_catalog *cat)
{
    pblock_meta d = dir_meta();
    pblock_meta f = file_meta("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1);

    CHECK(pblock_catalog_put(cat, "/d", &d) == 0, "mkdir row");
    CHECK(pblock_catalog_child_count(cat, "/d") == 0, "new dir not empty");
    CHECK(pblock_catalog_put(cat, "/d/x", &f) == 0, "child x");
    CHECK(pblock_catalog_put(cat, "/d/y", &f) == 0, "child y");
    CHECK(pblock_catalog_child_count(cat, "/d") == 2, "child count != 2");

    CHECK(pblock_catalog_remove(cat, "/d/x") == 0, "remove x");
    CHECK(pblock_catalog_child_count(cat, "/d") == 1, "child count != 1");
    CHECK(pblock_catalog_lookup(cat, "/d/x", NULL) == 1, "x still present");
}

/* directory rename reparents every descendant. */
static void
test_rename_subtree(pblock_catalog *cat)
{
    pblock_meta d = dir_meta();
    pblock_meta f = file_meta("cccccccccccccccccccccccccccccccc", 7);

    CHECK(pblock_catalog_put(cat, "/src", &d) == 0, "mkdir src");
    CHECK(pblock_catalog_put(cat, "/src/deep", &d) == 0, "mkdir deep");
    CHECK(pblock_catalog_put(cat, "/src/deep/file", &f) == 0, "deep file");

    CHECK(pblock_catalog_rename(cat, "/src", "/dst") == 0, "rename failed: %s",
          strerror(errno));
    CHECK(pblock_catalog_lookup(cat, "/src", NULL) == 1, "src survived");
    CHECK(pblock_catalog_lookup(cat, "/dst", NULL) == 0, "dst missing");
    CHECK(pblock_catalog_lookup(cat, "/dst/deep/file", NULL) == 0,
          "descendant not reparented");
    CHECK(pblock_catalog_lookup(cat, "/src/deep/file", NULL) == 1,
          "old descendant survived");
}

/* opendir enumerates direct children only (basenames). */
static void
test_opendir(pblock_catalog *cat)
{
    pblock_meta d = dir_meta();
    pblock_meta f = file_meta("dddddddddddddddddddddddddddddddd", 1);
    pblock_catalog_iter *it;
    char  name[256];
    int   seen_a = 0, seen_b = 0, n = 0, rc;

    CHECK(pblock_catalog_put(cat, "/list", &d) == 0, "mkdir list");
    CHECK(pblock_catalog_put(cat, "/list/a", &f) == 0, "a");
    CHECK(pblock_catalog_put(cat, "/list/b", &f) == 0, "b");
    /* "/list/b" is a FILE: since the phase-68 parent gate this insert must
     * fail ENOTDIR outright (it used to land as an orphan row that readdir
     * could never reach — the listing-shape CHECKs below still hold). */
    errno = 0;
    CHECK(pblock_catalog_put(cat, "/list/b/nested", &f) != 0
          && errno == ENOTDIR, "nested under a file allowed (errno %d)",
          errno);

    it = pblock_catalog_opendir(cat, "/list");
    CHECK(it != NULL, "opendir failed");
    while ((rc = pblock_catalog_readdir(it, name, sizeof(name))) == 0) {
        if (strcmp(name, "a") == 0) { seen_a = 1; }
        if (strcmp(name, "b") == 0) { seen_b = 1; }
        CHECK(strchr(name, '/') == NULL, "readdir returned a path: %s", name);
        n++;
    }
    CHECK(rc == 1, "readdir ended with error %d", rc);
    pblock_catalog_closedir(it);
    CHECK(seen_a && seen_b, "missing children a=%d b=%d", seen_a, seen_b);
    CHECK(n == 2, "expected 2 direct children, got %d", n);
}

/* xattr set/get/list/remove round-trips. */
static void
test_xattr(pblock_catalog *cat)
{
    pblock_meta f = file_meta("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", 1);
    char    buf[128];
    ssize_t n;

    CHECK(pblock_catalog_put(cat, "/xf", &f) == 0, "put xf");
    CHECK(pblock_catalog_setxattr(cat, "/xf", "user.k", "val", 3, 0) == 0,
          "setxattr");
    n = pblock_catalog_getxattr(cat, "/xf", "user.k", buf, sizeof(buf));
    CHECK(n == 3 && memcmp(buf, "val", 3) == 0, "getxattr n=%zd", n);

    n = pblock_catalog_listxattr(cat, "/xf", buf, sizeof(buf));
    CHECK(n == (ssize_t) sizeof("user.k"), "listxattr n=%zd", n);
    CHECK(memcmp(buf, "user.k", sizeof("user.k")) == 0, "listxattr name");

    CHECK(pblock_catalog_removexattr(cat, "/xf", "user.k") == 0, "removexattr");
    errno = 0;
    n = pblock_catalog_getxattr(cat, "/xf", "user.k", buf, sizeof(buf));
    CHECK(n == -1 && errno == ENODATA, "get after remove n=%zd errno=%d", n,
          errno);
}

/* the identity registry assigns stable ids >= PBLOCK_ID_BASE, never renumbers,
 * keeps user/group namespaces separate, and rejects empty names. */
static void
test_id_map(pblock_catalog *cat)
{
    int64_t alice1 = 0, alice2 = 0, bob = 0, atlas = 0, alice_grp = 0;

    CHECK(pblock_catalog_id_map(cat, PBLOCK_ID_USER, "alice", &alice1) == 0,
          "map alice: %s", strerror(errno));
    CHECK(alice1 >= PBLOCK_ID_BASE, "alice id below base: %lld",
          (long long) alice1);
    CHECK(pblock_catalog_id_map(cat, PBLOCK_ID_USER, "alice", &alice2) == 0
          && alice2 == alice1, "alice id not stable: %lld vs %lld",
          (long long) alice1, (long long) alice2);

    CHECK(pblock_catalog_id_map(cat, PBLOCK_ID_USER, "bob", &bob) == 0
          && bob != alice1, "bob id collides with alice");
    CHECK(pblock_catalog_id_map(cat, PBLOCK_ID_GROUP, "atlas", &atlas) == 0
          && atlas != alice1 && atlas != bob, "atlas gid collides");
    /* the same NAME in the group namespace is a separate identity */
    CHECK(pblock_catalog_id_map(cat, PBLOCK_ID_GROUP, "alice", &alice_grp) == 0
          && alice_grp != alice1, "group 'alice' shares the user id");

    errno = 0;
    CHECK(pblock_catalog_id_map(cat, PBLOCK_ID_USER, "", &bob) == -1
          && errno == EINVAL, "empty name accepted (errno %d)", errno);
}

/* setattr's owner column honors set_owner + the -1 keep sentinels. */
static void
test_setattr_owner(pblock_catalog *cat)
{
    pblock_meta f = file_meta("ffffffffffffffffffffffffffffffff", 1);
    pblock_meta out;

    f.uid = 10001;
    f.gid = 10002;
    CHECK(pblock_catalog_put(cat, "/owned", &f) == 0, "put owned");
    CHECK(pblock_catalog_lookup(cat, "/owned", &out) == 0
          && out.uid == 10001 && out.gid == 10002,
          "put owner not stored: %u/%u", out.uid, out.gid);

    /* chgrp only: uid=-1 keeps the owner */
    CHECK(pblock_catalog_setattr(cat, "/owned", 0, 0, 1, -1, 10007,
                                 0, 0, 2000) == 0, "chgrp failed");
    CHECK(pblock_catalog_lookup(cat, "/owned", &out) == 0
          && out.uid == 10001 && out.gid == 10007,
          "chgrp result %u/%u", out.uid, out.gid);
    CHECK(out.ctime == 2000, "ctime not bumped: %lld", (long long) out.ctime);

    /* set_owner=0 must not touch the columns even with ids present */
    CHECK(pblock_catalog_setattr(cat, "/owned", 1, 0600, 0, 10099, 10099,
                                 0, 0, 2001) == 0, "chmod failed");
    CHECK(pblock_catalog_lookup(cat, "/owned", &out) == 0
          && out.uid == 10001 && out.gid == 10007 && (out.mode & 0777) == 0600,
          "chmod leaked ownership: %u/%u mode %o", out.uid, out.gid, out.mode);

    errno = 0;
    CHECK(pblock_catalog_setattr(cat, "/no-such", 0, 0, 1, 1, 1, 0, 0, 1) == -1
          && errno == ENOENT, "setattr on absent row (errno %d)", errno);
}

/* setxattr honours XATTR_CREATE / XATTR_REPLACE and the path-existence gate. */
static void
test_xattr_flags(pblock_catalog *cat)
{
    pblock_meta f = file_meta("99999999999999999999999999999999", 1);
    char        buf[32];
    ssize_t     n;

    CHECK(pblock_catalog_put(cat, "/xflags", &f) == 0, "put xflags");

    errno = 0;
    CHECK(pblock_catalog_setxattr(cat, "/xflags", "user.a", "v", 1,
                                  XATTR_CREATE | XATTR_REPLACE) == -1
          && errno == EINVAL, "both flags accepted (errno %d)", errno);

    errno = 0;
    CHECK(pblock_catalog_setxattr(cat, "/xflags", "user.a", "v", 1,
                                  XATTR_REPLACE) == -1 && errno == ENODATA,
          "REPLACE created (errno %d)", errno);

    CHECK(pblock_catalog_setxattr(cat, "/xflags", "user.a", "v1", 2,
                                  XATTR_CREATE) == 0, "CREATE new failed");
    errno = 0;
    CHECK(pblock_catalog_setxattr(cat, "/xflags", "user.a", "v2", 2,
                                  XATTR_CREATE) == -1 && errno == EEXIST,
          "CREATE overwrote (errno %d)", errno);

    CHECK(pblock_catalog_setxattr(cat, "/xflags", "user.a", "v3", 2,
                                  XATTR_REPLACE) == 0, "REPLACE failed");
    n = pblock_catalog_getxattr(cat, "/xflags", "user.a", buf, sizeof(buf));
    CHECK(n == 2 && memcmp(buf, "v3", 2) == 0, "REPLACE value n=%zd", n);

    /* every xattr op on an absent path is ENOENT, not silent success */
    errno = 0;
    CHECK(pblock_catalog_setxattr(cat, "/xghost", "user.a", "v", 1, 0) == -1
          && errno == ENOENT, "set on ghost path (errno %d)", errno);
    errno = 0;
    CHECK(pblock_catalog_getxattr(cat, "/xghost", "user.a", buf,
                                  sizeof(buf)) == -1 && errno == ENOENT,
          "get on ghost path (errno %d)", errno);
    errno = 0;
    CHECK(pblock_catalog_listxattr(cat, "/xghost", buf, sizeof(buf)) == -1
          && errno == ENOENT, "list on ghost path (errno %d)", errno);
    errno = 0;
    CHECK(pblock_catalog_removexattr(cat, "/xghost", "user.a") == -1
          && errno == ENOENT, "remove on ghost path (errno %d)", errno);
}

/* parent_lookup surfaces the parent row (and the right errnos). */
static void
test_parent_lookup(pblock_catalog *cat)
{
    pblock_meta d = dir_meta();
    pblock_meta f = file_meta("88888888888888888888888888888888", 1);
    pblock_meta out;

    d.uid = 10042;
    d.mode = S_IFDIR | 0770;
    CHECK(pblock_catalog_put(cat, "/pdir", &d) == 0, "mkdir pdir");
    CHECK(pblock_catalog_put(cat, "/pdir/leaf", &f) == 0, "leaf");

    CHECK(pblock_catalog_parent_lookup(cat, "/pdir/leaf", &out) == 0
          && out.is_dir && out.uid == 10042 && (out.mode & 0777) == 0770,
          "parent row wrong: uid %u mode %o", out.uid, out.mode);

    errno = 0;
    CHECK(pblock_catalog_parent_lookup(cat, "/", &out) == -1
          && errno == EINVAL, "root parent (errno %d)", errno);
    errno = 0;
    CHECK(pblock_catalog_parent_lookup(cat, "/ghost/leaf", &out) == -1
          && errno == ENOENT, "ghost parent (errno %d)", errno);
    errno = 0;
    CHECK(pblock_catalog_parent_lookup(cat, "/pdir/leaf/below", &out) == -1
          && errno == ENOTDIR, "file parent (errno %d)", errno);
}

int
main(void)
{
    char  dir[]  = "/tmp/pb_cat_ut.XXXXXX";
    char  db[512];
    pblock_catalog *cat;

    CHECK(mkdtemp(dir) != NULL, "mkdtemp failed");
    snprintf(db, sizeof(db), "%s/catalog.db", dir);

    cat = pblock_catalog_open(db, 2000);
    CHECK(cat != NULL, "catalog_open failed: %s", strerror(errno));
    if (cat == NULL) {
        return 1;
    }

    test_put_lookup(cat);
    test_parent_gate(cat);
    test_touch(cat);
    test_children_and_remove(cat);
    test_rename_subtree(cat);
    test_opendir(cat);
    test_xattr(cat);
    test_id_map(cat);
    test_setattr_owner(cat);
    test_xattr_flags(cat);
    test_parent_lookup(cat);

    pblock_catalog_close(cat);
    unlink(db);
    rmdir(dir);

    if (failures == 0) {
        printf("sd_pblock_catalog_unittest: ALL PASS\n");
        return 0;
    }
    fprintf(stderr, "sd_pblock_catalog_unittest: %d FAILURE(S)\n", failures);
    return 1;
}
