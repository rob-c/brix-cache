/*
 * sd_pblock_unittest_ident.c — identity-enforcement (*_cred slots) slice of the
 * pblock driver unit test (split from sd_pblock_unittest.c). The per-leg helpers
 * stay file-local; test_identity() is the group entry point driven by main().
 * Shared harness + open_block_export() come via sd_pblock_unittest_internal.h.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* nftw(3) + FTW_PHYS for the on-disk block scan */
#endif

#include "fs/backend/sd.h"
#include "sd_pblock_catalog.h"
#include "sd_pblock_unittest_internal.h"

#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- identity enforcement (the *_cred slots) ------------------------------- *
 * alice + carol share VO "atlas"; bob is VO "cms"; a zeroed principal is the
 * service (bypasses every check). Ownership is catalog-internal synthetic ids,
 * so all assertions compare ids read back via stat — never fixed numbers. */

static const brix_sd_cred_t CRED_ALICE = { .principal = "alice",
                                           .vos = "atlas" };
static const brix_sd_cred_t CRED_BOB   = { .principal = "bob",
                                           .vos = "cms" };
static const brix_sd_cred_t CRED_CAROL = { .principal = "carol",
                                           .vos = "atlas" };

/* cred_write_file — open_cred-create `path` as `who` with `mode`, write a few
 * bytes, close. 0 or -1/errno. */
static int
cred_write_file(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *who)
{
    int              err = 0;
    brix_sd_obj_t *o;
    ssize_t          n;

    o = D->open_cred(inst, path,
                     BRIX_SD_O_WRITE | BRIX_SD_O_READ | BRIX_SD_O_CREATE,
                     mode, who, &err);
    if (o == NULL) {
        errno = err;
        return -1;
    }
    n = D->pwrite(o, "data", 4, 0);
    pb_close(o);
    return n == 4 ? 0 : -1;
}

/* creation records the requester as owner; mode bits gate other users by
 * class (owner / VO-group / other); the service bypasses everything. */
static void
test_ident_ownership(brix_sd_instance_t *inst)
{
    brix_sd_stat_t  st;
    brix_sd_obj_t  *o;
    int             err = 0;

    /* 0640: owner rw, VO-group r, other none */
    CHECK(cred_write_file(inst, "/a.dat", 0640, &CRED_ALICE) == 0,
          "alice create: %s", strerror(errno));
    CHECK(D->stat(inst, "/a.dat", &st) == NGX_OK, "stat a.dat");
    CHECK(st.uid >= PBLOCK_ID_BASE && st.gid >= PBLOCK_ID_BASE,
          "synthetic owner not recorded: %u/%u",
          (unsigned) st.uid, (unsigned) st.gid);

    /* same user re-opens rw (owner class) */
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_WRITE | BRIX_SD_O_READ, 0,
                     &CRED_ALICE, &err);
    CHECK(o != NULL, "owner reopen rw: %s", strerror(err));
    if (o != NULL) { pb_close(o); }

    /* carol shares VO atlas: group class grants read, denies write */
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_READ, 0, &CRED_CAROL, &err);
    CHECK(o != NULL, "same-VO read: %s", strerror(err));
    if (o != NULL) { pb_close(o); }
    err = 0;
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_WRITE, 0, &CRED_CAROL, &err);
    CHECK(o == NULL && err == EACCES, "same-VO write allowed (err %d)", err);

    /* bob (VO cms) is other class: no bits at all — neither read nor write */
    err = 0;
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_READ, 0, &CRED_BOB, &err);
    CHECK(o == NULL && err == EACCES, "foreign-VO read allowed (err %d)", err);
    err = 0;
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_WRITE, 0, &CRED_BOB, &err);
    CHECK(o == NULL && err == EACCES, "foreign-VO write allowed (err %d)",
          err);

    /* the service (NULL cred) bypasses the gate entirely */
    o = D->open_cred(inst, "/a.dat", BRIX_SD_O_WRITE | BRIX_SD_O_READ, 0,
                     NULL, &err);
    CHECK(o != NULL, "service bypass: %s", strerror(err));
    if (o != NULL) { pb_close(o); }

    /* a group-WRITABLE file (0660) really is shared within the VO: carol may
     * write to alice's file and read alice's bytes back — bob still may not */
    CHECK(cred_write_file(inst, "/shared.dat", 0660, &CRED_ALICE) == 0,
          "alice create shared: %s", strerror(errno));
    o = D->open_cred(inst, "/shared.dat", BRIX_SD_O_WRITE | BRIX_SD_O_READ,
                     0, &CRED_CAROL, &err);
    CHECK(o != NULL, "same-VO group write: %s", strerror(err));
    if (o != NULL) {
        char buf[8];

        CHECK(D->pread(o, buf, 4, 0) == 4 && memcmp(buf, "data", 4) == 0,
              "same-VO read of alice's bytes");
        CHECK(D->pwrite(o, "EDIT", 4, 0) == 4, "same-VO pwrite");
        pb_close(o);
    }
    err = 0;
    o = D->open_cred(inst, "/shared.dat", BRIX_SD_O_WRITE, 0, &CRED_BOB,
                     &err);
    CHECK(o == NULL && err == EACCES,
          "foreign-VO write on group file allowed (err %d)", err);
}

/* per-VO shared directories: group-writable dir admits VO members and no one
 * else, for mkdir, staged publish and opendir alike. */
static void
test_ident_vo_dir(brix_sd_instance_t *inst)
{
    brix_sd_staged_t *sh;
    brix_sd_stat_t    st, sub;
    brix_sd_dir_t    *dir;
    int               err = 0;

    /* alice's VO-shared dir: 0770 — atlas members rwx, others nothing */
    CHECK(D->mkdir_cred(inst, "/atlas", 0770, &CRED_ALICE) == NGX_OK,
          "mkdir /atlas: %s", strerror(errno));
    CHECK(D->stat(inst, "/atlas", &st) == NGX_OK
          && st.uid >= PBLOCK_ID_BASE, "dir owner missing");

    CHECK(D->mkdir_cred(inst, "/atlas/carol", 0770, &CRED_CAROL) == NGX_OK,
          "same-VO mkdir: %s", strerror(errno));
    CHECK(D->stat(inst, "/atlas/carol", &sub) == NGX_OK
          && sub.uid != st.uid, "subdir not owned by carol");

    errno = 0;
    CHECK(D->mkdir_cred(inst, "/atlas/bob", 0770, &CRED_BOB) == NGX_ERROR
          && errno == EACCES, "foreign-VO mkdir allowed (errno %d)", errno);

    /* staged publish obeys the same parent gate and records the requester */
    err = 0;
    sh = D->staged_open_cred(inst, "/atlas/stage.dat", 0640, &CRED_BOB, &err);
    CHECK(sh == NULL && err == EACCES, "foreign-VO staged (err %d)", err);
    sh = D->staged_open_cred(inst, "/atlas/stage.dat", 0640, &CRED_CAROL,
                             &err);
    CHECK(sh != NULL, "same-VO staged: %s", strerror(err));
    if (sh != NULL) {
        CHECK(D->staged_write(sh, "zz", 2, 0) == 2, "staged write");
        CHECK(D->staged_commit(sh, 0) == NGX_OK, "staged commit");
        CHECK(D->stat(inst, "/atlas/stage.dat", &st) == NGX_OK
              && st.uid == sub.uid, "staged row not owned by carol");
    }

    /* listing = reading the directory */
    errno = 0;
    dir = D->opendir_cred(inst, "/atlas", &err, &CRED_BOB);
    CHECK(dir == NULL && err == EACCES, "foreign-VO opendir (err %d)", err);
    dir = D->opendir_cred(inst, "/atlas", &err, &CRED_CAROL);
    CHECK(dir != NULL, "same-VO opendir: %s", strerror(err));
    if (dir != NULL) { D->closedir(dir); }
}

/* directory traverse: the parent's X bit gates every access to entries inside
 * it — a world-readable file in a 0770 group dir stays invisible to
 * non-members (runs after test_ident_vo_dir; reuses its /atlas dir). */
static void
test_ident_traverse(brix_sd_instance_t *inst)
{
    brix_sd_obj_t *o;
    char           v[8];
    int            err = 0;

    /* 0644 would grant bob other-read — but /atlas (0770) must block him */
    CHECK(cred_write_file(inst, "/atlas/pub.dat", 0644, &CRED_ALICE) == 0,
          "alice create in /atlas: %s", strerror(errno));

    o = D->open_cred(inst, "/atlas/pub.dat", BRIX_SD_O_READ, 0, &CRED_CAROL,
                     &err);
    CHECK(o != NULL, "same-VO traverse+read: %s", strerror(err));
    if (o != NULL) { pb_close(o); }

    err = 0;
    o = D->open_cred(inst, "/atlas/pub.dat", BRIX_SD_O_READ, 0, &CRED_BOB,
                     &err);
    CHECK(o == NULL && err == EACCES,
          "no-traverse read allowed (err %d)", err);
    err = 0;
    o = D->open_cred(inst, "/atlas/new.dat",
                     BRIX_SD_O_WRITE | BRIX_SD_O_CREATE, 0644, &CRED_BOB,
                     &err);
    CHECK(o == NULL && err == EACCES,
          "no-traverse create allowed (err %d)", err);
    errno = 0;
    CHECK(D->getxattr_cred(inst, "/atlas/pub.dat", "user.k", v, sizeof(v),
                           &CRED_BOB) < 0 && errno == EACCES,
          "no-traverse getxattr allowed (errno %d)", errno);
    errno = 0;
    CHECK(D->unlink_cred(inst, "/atlas/pub.dat", 0, &CRED_BOB) == NGX_ERROR
          && errno == EACCES,
          "no-traverse unlink allowed (errno %d)", errno);

    /* the service still bypasses traverse like every other gate */
    o = D->open_cred(inst, "/atlas/pub.dat", BRIX_SD_O_READ, 0, NULL, &err);
    CHECK(o != NULL, "service traverse bypass: %s", strerror(err));
    if (o != NULL) { pb_close(o); }
}

/* chmod/chown policy: owner-only chmod; no giving files away; chgrp only into
 * a VO the owner belongs to. */
static void
test_ident_setattr(brix_sd_instance_t *inst)
{
    brix_sd_setattr_t attr;
    brix_sd_stat_t    st, bobst;

    CHECK(cred_write_file(inst, "/chown.me", 0640, &CRED_ALICE) == 0,
          "seed chown.me");
    CHECK(cred_write_file(inst, "/bob.dat", 0640, &CRED_BOB) == 0,
          "seed bob.dat");
    CHECK(D->stat(inst, "/chown.me", &st) == NGX_OK, "stat chown.me");
    CHECK(D->stat(inst, "/bob.dat", &bobst) == NGX_OK, "stat bob.dat");

    /* chmod: owner yes, non-owner EPERM */
    memset(&attr, 0, sizeof(attr));
    attr.set_mode = 1;
    attr.mode = 0664;
    CHECK(D->setattr_cred(inst, "/chown.me", &attr, &CRED_ALICE) == NGX_OK,
          "owner chmod: %s", strerror(errno));
    errno = 0;
    CHECK(D->setattr_cred(inst, "/chown.me", &attr, &CRED_BOB) == NGX_ERROR
          && errno == EPERM, "non-owner chmod allowed (errno %d)", errno);

    /* chown to another uid is service-only */
    memset(&attr, 0, sizeof(attr));
    attr.set_owner = 1;
    attr.uid = (uid_t) bobst.uid;
    attr.gid = (gid_t) -1;
    errno = 0;
    CHECK(D->setattr_cred(inst, "/chown.me", &attr, &CRED_ALICE) == NGX_ERROR
          && errno == EPERM, "give-away chown allowed (errno %d)", errno);
    CHECK(D->setattr_cred(inst, "/chown.me", &attr, NULL) == NGX_OK,
          "service chown: %s", strerror(errno));
    CHECK(D->stat(inst, "/chown.me", &st) == NGX_OK && st.uid == bobst.uid,
          "service chown not applied");

    /* chgrp: owner may move into own VO, not a foreign one */
    memset(&attr, 0, sizeof(attr));
    attr.set_owner = 1;
    attr.uid = (uid_t) -1;
    attr.gid = (gid_t) bobst.gid;            /* cms — bob's VO */
    CHECK(D->setattr_cred(inst, "/bob.dat", &attr, &CRED_BOB) == NGX_OK,
          "chgrp into own VO: %s", strerror(errno));
    CHECK(D->stat(inst, "/atlas", &st) == NGX_OK, "stat /atlas");
    attr.gid = (gid_t) st.gid;               /* atlas — NOT bob's VO */
    errno = 0;
    CHECK(D->setattr_cred(inst, "/bob.dat", &attr, &CRED_BOB) == NGX_ERROR
          && errno == EPERM, "chgrp into foreign VO allowed (errno %d)",
          errno);
}

/* xattr mode gates (R to read, W to write) and the sticky top level: users
 * cannot delete or rename each other's root entries, owners can. */
static void
test_ident_xattr_sticky(brix_sd_instance_t *inst)
{
    char    buf[16];
    ssize_t n;
    int     alice_err = 0;

    /* /a.dat is alice's, 0640 (VO atlas may read) */
    CHECK(D->setxattr_cred(inst, "/a.dat", "user.t", "1", 1, 0,
                           &CRED_ALICE) == NGX_OK,
          "owner setxattr: %s", strerror(errno));
    n = D->getxattr_cred(inst, "/a.dat", "user.t", buf, sizeof(buf),
                         &CRED_CAROL);
    CHECK(n == 1 && buf[0] == '1', "same-VO getxattr n=%zd", n);
    errno = 0;
    CHECK(D->setxattr_cred(inst, "/a.dat", "user.t", "2", 1, 0,
                           &CRED_CAROL) == NGX_ERROR && errno == EACCES,
          "read-only VO member setxattr allowed (errno %d)", errno);
    errno = 0;
    n = D->listxattr_cred(inst, "/a.dat", buf, sizeof(buf), &CRED_BOB);
    CHECK(n == -1 && errno == EACCES, "foreign-VO listxattr n=%zd", n);
    errno = 0;
    CHECK(D->removexattr_cred(inst, "/a.dat", "user.t",
                              &CRED_BOB) == NGX_ERROR && errno == EACCES,
          "foreign-VO removexattr allowed (errno %d)", errno);

    /* the denials are symmetric: alice cannot write to or delete bob's file
     * either (/bob.dat is 0640, gid cms — alice is other class) */
    errno = 0;
    CHECK(D->open_cred(inst, "/bob.dat", BRIX_SD_O_WRITE, 0, &CRED_ALICE,
                       &alice_err) == NULL && alice_err == EACCES,
          "alice write on bob's file allowed (err %d)", alice_err);
    errno = 0;
    CHECK(D->unlink_cred(inst, "/bob.dat", 0, &CRED_ALICE) == NGX_ERROR
          && errno == EPERM, "alice unlink of bob's file allowed (errno %d)",
          errno);

    /* sticky synthetic root: only the owner removes/renames a root entry */
    errno = 0;
    CHECK(D->unlink_cred(inst, "/a.dat", 0, &CRED_BOB) == NGX_ERROR
          && errno == EPERM, "cross-user root unlink allowed (errno %d)",
          errno);
    errno = 0;
    CHECK(D->rename_cred(inst, "/a.dat", "/stolen.dat", 0,
                         &CRED_BOB) == NGX_ERROR && errno == EPERM,
          "cross-user root rename allowed (errno %d)", errno);
    CHECK(D->rename_cred(inst, "/a.dat", "/a2.dat", 0,
                         &CRED_ALICE) == NGX_OK,
          "owner root rename: %s", strerror(errno));
    CHECK(D->unlink_cred(inst, "/a2.dat", 0, &CRED_ALICE) == NGX_OK,
          "owner root unlink: %s", strerror(errno));

    /* server_copy: source readability is enforced */
    errno = 0;
    CHECK(D->server_copy_cred(inst, "/bob.dat", "/copy.dat", NULL,
                              &CRED_CAROL) == NGX_ERROR && errno == EACCES,
          "unreadable-source copy allowed (errno %d)", errno);
    CHECK(D->server_copy_cred(inst, "/bob.dat", "/copy.dat", NULL,
                              &CRED_BOB) == NGX_OK,
          "owner copy: %s", strerror(errno));
}

/* fresh export so the sticky synthetic root + registry start empty. */
void
test_identity(void)
{
    char                 root[] = "/tmp/pb_id.XXXXXX";
    brix_sd_instance_t inst;

    CHECK(mkdtemp(root) != NULL, "mkdtemp");
    CHECK(open_block_export(&inst, root, 0) == 0, "init identity export");
    CHECK((D->cred_accept & BRIX_SD_CRED_IDENTITY) != 0,
          "driver does not advertise IDENTITY");

    test_ident_ownership(&inst);
    test_ident_vo_dir(&inst);
    test_ident_traverse(&inst);
    test_ident_setattr(&inst);
    test_ident_xattr_sticky(&inst);

    D->cleanup(&inst);
}
