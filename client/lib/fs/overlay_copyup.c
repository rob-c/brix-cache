/*
 * overlay_copyup.c - copy-up streaming, upper-dir enumeration, and the overlay CLI (list/reset).
 * Phase-38 split of overlay.c; behavior-identical.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE                 /* asprintf (parent overlay.c self-guards it too) */
#endif
#include "fs/overlay.h"
#include "overlay_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

/* ---- copy-up ------------------------------------------------------------- */

#define OV_COPYUP_CHUNK (1024u * 1024u)

/* Stream `size` lower bytes of `rel` into fd via the injected reader. A short
 * read before `size` is a lower-layer lie → -EIO. */
static int ov_copyup_stream(int fd, const char *rel, uint64_t size,
                            brix_ov_read_fn read_lower, void *ud) {
    unsigned char *buf = malloc(OV_COPYUP_CHUNK);
    if (buf == NULL) return -ENOMEM;

    uint64_t off = 0;
    int      rc  = 0;
    while (rc == 0 && off < size) {
        size_t want = size - off > OV_COPYUP_CHUNK ? OV_COPYUP_CHUNK
                                                   : (size_t) (size - off);
        size_t got  = 0;
        rc = read_lower(ud, rel, off, want, buf, &got);
        if (rc == 0 && got == 0) rc = -EIO;         /* premature EOF */
        for (size_t done = 0; rc == 0 && done < got; ) {
            ssize_t w = pwrite(fd, buf + done, got - done, (off_t) (off + done)); /* vfs-seam-allow: copy-up write to upper writable overlay layer, not export data */
            if (w < 0) rc = -errno;
            else done += (size_t) w;
        }
        off += got;
    }
    free(buf);
    return rc;
}

int brix_overlay_copyup(const brix_overlay *ov, const char *rel,
                        const struct stat *lower_st,
                        brix_ov_read_fn read_lower, void *ud) {
    char leaf[OV_NAME_MAX], tmp[OV_NAME_MAX + sizeof(BRIX_OV_TMP_PREFIX)];
    int  parent = ov_walk_parent_mk(ov, rel, leaf, sizeof(leaf), 1, NULL, NULL);
    if (parent < 0) return parent;

    snprintf(tmp, sizeof(tmp), BRIX_OV_TMP_PREFIX "%s", leaf);
    int fd = openat(parent, tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                    lower_st->st_mode & 07777);
    if (fd < 0) { int e = errno; close(parent); return -e; }

    /* the openat mode is umask-filtered — restate the exact lower bits */
    int rc = fchmod(fd, lower_st->st_mode & 07777) != 0 ? -errno : 0;
    if (rc == 0)
        rc = ov_copyup_stream(fd, rel, (uint64_t) lower_st->st_size, read_lower, ud);
    if (rc == 0) {
        struct timespec tv[2] = { { lower_st->st_mtime, 0 }, { lower_st->st_mtime, 0 } };
        if (futimens(fd, tv) != 0) rc = -errno;
    }
    close(fd);

    if (rc == 0 && renameat(parent, tmp, parent, leaf) != 0) rc = -errno;
    if (rc != 0) unlinkat(parent, tmp, 0);          /* leave no torn trace */
    close(parent);

    return rc == 0 ? brix_overlay_whiteout_clear(ov, rel) : rc;
}

/* ---- merged-readdir support ---------------------------------------------- */

static int ov_nameset_add(brix_ov_nameset *s, char flag, const char *name) {
    size_t need = strlen(name) + 2;              /* flag + name + NUL */
    if (s->used + need > s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 512;
        while (ncap < s->used + need) ncap *= 2;
        char *nb = realloc(s->buf, ncap);
        if (nb == NULL) return -ENOMEM;
        s->buf = nb;
        s->cap = ncap;
    }
    s->buf[s->used] = flag;
    memcpy(s->buf + s->used + 1, name, need - 1);
    s->used += need;
    s->count++;
    return 0;
}

int brix_overlay_read_upper(const brix_overlay *ov, const char *rel,
                            brix_ov_nameset *set, int *opaque) {
    memset(set, 0, sizeof(*set));
    *opaque = 0;

    int dir = ov_open_dir(ov, rel);
    if (dir == -ENOENT || dir == -ENOTDIR) return 0;   /* nothing in upper */
    if (dir < 0) return dir;

    DIR *d = fdopendir(dir);                     /* owns dir from here */
    if (d == NULL) { int e = errno; close(dir); return -e; }

    int            rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        if (strcmp(n, ".") == 0 || strcmp(n, "..") == 0) continue;
        if (strcmp(n, BRIX_OV_OPQ_NAME) == 0) { *opaque = 1; continue; }
        if (strncmp(n, BRIX_OV_TMP_PREFIX, sizeof(BRIX_OV_TMP_PREFIX) - 1) == 0) continue;
        if (strncmp(n, BRIX_OV_WH_PREFIX, sizeof(BRIX_OV_WH_PREFIX) - 1) == 0)
            rc = ov_nameset_add(set, 'w', n + sizeof(BRIX_OV_WH_PREFIX) - 1);
        else
            rc = ov_nameset_add(set, 'u', n);
    }
    closedir(d);
    if (rc != 0) brix_ov_nameset_free(set);
    return rc;
}

char brix_ov_nameset_flag(const brix_ov_nameset *s, const char *name) {
    for (size_t off = 0; off < s->used; ) {
        char        fl = s->buf[off];
        const char *nm = s->buf + off + 1;
        if (strcmp(nm, name) == 0) return fl;
        off += strlen(nm) + 2;
    }
    return 0;
}

const char *brix_ov_nameset_at(const brix_ov_nameset *s, size_t i, char *flag) {
    size_t idx = 0;
    for (size_t off = 0; off < s->used; idx++) {
        const char *nm = s->buf + off + 1;
        if (idx == i) {
            if (flag != NULL) *flag = s->buf[off];
            return nm;
        }
        off += strlen(nm) + 2;
    }
    return NULL;
}

void brix_ov_nameset_free(brix_ov_nameset *s) {
    free(s->buf);
    memset(s, 0, sizeof(*s));
}

/* ---- CLI cores (--overlay-list / --overlay-reset) ------------------------ */

/* Wrong-mountpoint guard: <mountdir>/.brixwrites/upper must be a directory.
 * On success *upper_out (asprintf'd, caller frees) holds its path. */
static int ov_cli_guard(const char *mountdir, char **upper_out) {
    if (asprintf(upper_out, "%s/" BRIX_OV_DIRNAME "/" BRIX_OV_UPPER_DIRNAME,
                 mountdir) < 0)
        return 1;
    struct stat st;
    if (lstat(*upper_out, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    fprintf(stderr, "brixMount: no " BRIX_OV_DIRNAME
            " overlay under %s (not a cvmfs-rw mountpoint?)\n", mountdir);
    free(*upper_out);
    *upper_out = NULL;
    return 2;
}

/* Change kind for an upper file: the live mount answers the user.overlay
 * magic xattr ("new"/"modified"); unmounted raw trees have none → "upper". */
static void ov_cli_kind(const char *mountdir, const char *rel,
                        char *kind, size_t cap) {
    char   *p = NULL;
    ssize_t n = -1;
    if (asprintf(&p, "%s/%s", mountdir, rel) >= 0) {
        n = lgetxattr(p, "user.overlay", kind, cap - 1);
        free(p);
    }
    if (n > 0) kind[n] = '\0';
    else       snprintf(kind, cap, "upper");
}

/* Forward decl: ov_cli_list_dir and ov_cli_list_entry recurse into each other
 * (a subdirectory entry descends via ov_cli_list_dir). */
static int ov_cli_list_entry(const char *mountdir, const char *upper_root,
                             const char *rel, const char *dirp,
                             const char *name, FILE *out);

static int ov_cli_list_dir(const char *mountdir, const char *upper_root,
                           const char *rel, FILE *out) {
    char *dirp = NULL;
    if (asprintf(&dirp, "%s%s%s", upper_root, rel[0] ? "/" : "", rel) < 0) return 1;
    DIR *d = opendir(dirp);
    if (d == NULL) { free(dirp); return 1; }

    int            rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        rc = ov_cli_list_entry(mountdir, upper_root, rel, dirp, e->d_name, out);
    }
    closedir(d);
    free(dirp);
    return rc;
}

/* ---- Emit one upper-tree entry during --overlay-list ----
 *
 * WHAT: Classifies dirent `name` in the upper directory `dirp` (union path
 *       `rel`): "." "..", the opaque marker and tmp files are skipped; a
 *       whiteout prints a "deleted" line; a subdirectory prints "dir" and
 *       recurses; any other entry prints its change kind. Returns 0, or 1 on
 *       an allocation failure (which stops the enclosing scan).
 *
 * WHY:  Splitting the per-entry decision ladder out of ov_cli_list_dir keeps
 *       each function small and single-purpose while preserving the exact
 *       skip/whiteout/recurse ordering the listing relies on.
 *
 * HOW:  1. Return early for reserved/skipped names.
 *       2. Print and return for a whiteout marker.
 *       3. Build the child union path and absolute path; on OOM free and fail.
 *       4. Recurse into a subdirectory, else print the file's change kind.
 */
static int ov_cli_list_entry(const char *mountdir, const char *upper_root,
                             const char *rel, const char *dirp,
                             const char *name, FILE *out) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return 0;
    if (strcmp(name, BRIX_OV_OPQ_NAME) == 0) return 0;
    if (strncmp(name, BRIX_OV_TMP_PREFIX, sizeof(BRIX_OV_TMP_PREFIX) - 1) == 0) return 0;

    if (strncmp(name, BRIX_OV_WH_PREFIX, sizeof(BRIX_OV_WH_PREFIX) - 1) == 0) {
        fprintf(out, "deleted %s%s%s\n", rel, rel[0] ? "/" : "",
                name + sizeof(BRIX_OV_WH_PREFIX) - 1);
        return 0;
    }

    char *crel = NULL, *full = NULL;
    if (asprintf(&crel, "%s%s%s", rel, rel[0] ? "/" : "", name) < 0
        || asprintf(&full, "%s/%s", dirp, name) < 0) {
        free(crel);
        return 1;
    }

    int         rc = 0;
    struct stat st;
    if (lstat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
        fprintf(out, "dir %s\n", crel);
        rc = ov_cli_list_dir(mountdir, upper_root, crel, out);
    } else {
        char kind[64];
        ov_cli_kind(mountdir, crel, kind, sizeof(kind));
        fprintf(out, "%s %s\n", kind, crel);
    }
    free(crel);
    free(full);
    return rc;
}

int brix_overlay_cli_list(const char *mountdir, FILE *out) {
    char *upper = NULL;
    int   rc    = ov_cli_guard(mountdir, &upper);
    if (rc != 0) return rc;
    rc = ov_cli_list_dir(mountdir, upper, "", out);
    free(upper);
    return rc;
}

/* Recursively delete everything inside dirfd (never following symlinks). */
static int ov_cli_reset_contents(int dirfd) {
    int lfd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (lfd < 0) return 1;
    DIR *d = fdopendir(lfd);                     /* owns lfd */
    if (d == NULL) { close(lfd); return 1; }

    int            rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        if (strcmp(n, ".") == 0 || strcmp(n, "..") == 0) continue;
        struct stat st;
        if (fstatat(dirfd, n, &st, AT_SYMLINK_NOFOLLOW) != 0) { rc = 1; break; }
        if (S_ISDIR(st.st_mode)) {
            int sub = openat(dirfd, n, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (sub < 0) { rc = 1; break; }
            rc = ov_cli_reset_contents(sub);
            close(sub);
            if (rc == 0 && unlinkat(dirfd, n, AT_REMOVEDIR) != 0) rc = 1;
        } else if (unlinkat(dirfd, n, 0) != 0) {
            rc = 1;
        }
    }
    closedir(d);
    return rc;
}

int brix_overlay_cli_reset(const char *mountdir) {
    char *upper = NULL;
    int   rc    = ov_cli_guard(mountdir, &upper);
    if (rc != 0) return rc;

    int fd = open(upper, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(upper);
    if (fd < 0) return 1;
    rc = ov_cli_reset_contents(fd);
    close(fd);
    return rc;
}
