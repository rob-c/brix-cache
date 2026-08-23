/* cas_store.c — content-addressed local POSIX object store. See cas_store.h.
 * With `s->pack` set (brix_cas_init_packed*) every op dispatches to the
 * log-structured packed backend (cas_pack.c) behind the same contract. */
#include "cache/cas_store.h"
#include "cache/cas_pack.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

/* base fd for the *at family: the preserved dirfd, or AT_FDCWD (absolute paths). */
static int cas_base(const brix_cas_store_t *s) { return s->dirfd >= 0 ? s->dirfd : AT_FDCWD; }

/* "<root>/<2>/<rest>" (dir mode) or "<2>/<rest>" (dirfd mode). */
static int cas_obj_rel(const brix_cas_store_t *s, const char *key, char *buf, size_t n) {
    if (key == NULL || strlen(key) < 3) return -1;
    int w = s->dirfd >= 0
        ? snprintf(buf, n, "%c%c/%s", key[0], key[1], key + 2)
        : snprintf(buf, n, "%s/%c%c/%s", s->root, key[0], key[1], key + 2);
    return (w < 0 || (size_t) w >= n) ? -1 : w;
}

/* the "<2>" fan-out dir. */
static int cas_dir_rel(const brix_cas_store_t *s, const char *key, char *buf, size_t n) {
    int w = s->dirfd >= 0
        ? snprintf(buf, n, "%c%c", key[0], key[1])
        : snprintf(buf, n, "%s/%c%c", s->root, key[0], key[1]);
    return (w < 0 || (size_t) w >= n) ? -1 : w;
}

static int mkdirat_ok(int base, const char *path) {
    if (mkdirat(base, path, 0755) == 0) return 0;
    return errno == EEXIST ? 0 : -1;
}

int brix_cas_init(brix_cas_store_t *s, const char *root, long quota_bytes) {
    if (root == NULL || strlen(root) >= sizeof(s->root)) { errno = EINVAL; return -1; }
    memset(s, 0, sizeof(*s));
    s->dirfd = -1;
    strcpy(s->root, root);
    s->quota_bytes = quota_bytes;
    if (mkdirat_ok(AT_FDCWD, root) != 0) return -1;
    s->cur_bytes = brix_cas_size(s);
    return 0;
}

int brix_cas_init_at(brix_cas_store_t *s, int dirfd, long quota_bytes) {
    if (dirfd < 0) { errno = EINVAL; return -1; }
    memset(s, 0, sizeof(*s));
    s->dirfd = dirfd;
    s->quota_bytes = quota_bytes;
    s->cur_bytes = brix_cas_size(s);
    return 0;
}

int brix_cas_init_packed(brix_cas_store_t *s, const char *root, long quota_bytes,
                         long seg_bytes, int tiering) {
    if (root == NULL || strlen(root) >= sizeof(s->root)) { errno = EINVAL; return -1; }
    memset(s, 0, sizeof(*s));
    s->dirfd = -1;
    strcpy(s->root, root);
    s->quota_bytes = quota_bytes;
    return brix_cas_pack_open(&s->pack, root, -1, quota_bytes, seg_bytes, tiering);
}

int brix_cas_init_packed_at(brix_cas_store_t *s, int dirfd, long quota_bytes,
                            long seg_bytes, int tiering) {
    if (dirfd < 0) { errno = EINVAL; return -1; }
    memset(s, 0, sizeof(*s));
    s->dirfd = dirfd;
    s->quota_bytes = quota_bytes;
    return brix_cas_pack_open(&s->pack, NULL, dirfd, quota_bytes, seg_bytes, tiering);
}

void brix_cas_destroy(brix_cas_store_t *s) {
    brix_cas_pack_close(s->pack);
    s->pack = NULL;
}

int brix_cas_path(const brix_cas_store_t *s, const char *key, char *buf, size_t buflen) {
    if (s->pack != NULL) { errno = EOPNOTSUPP; return -1; }   /* no per-object path */
    return cas_obj_rel(s, key, buf, buflen);
}

int brix_cas_has(const brix_cas_store_t *s, const char *key) {
    char rel[640];
    struct stat st;
    if (s->pack != NULL) return brix_cas_pack_has(s->pack, key);
    if (cas_obj_rel(s, key, rel, sizeof(rel)) < 0) return 0;
    return fstatat(cas_base(s), rel, &st, 0) == 0 && S_ISREG(st.st_mode);
}

int brix_cas_open(const brix_cas_store_t *s, const char *key) {
    char rel[640];
    if (s->pack != NULL) return brix_cas_pack_get_fd(s->pack, key);
    if (cas_obj_rel(s, key, rel, sizeof(rel)) < 0) { errno = EINVAL; return -1; }
    return openat(cas_base(s), rel, O_RDONLY);
}

/*
 * WHAT: Create a collision-resistant temporary object in one fan-out directory.
 * WHY:  CAS publication needs an exclusive sibling file before atomic rename.
 * HOW:  Try sixteen pid/random names, retry only collisions, and return its fd.
 */
static int cas_temp_open(int base, const char *dir, char *tmp, size_t tmp_len) {
    int attempt;

    for (attempt = 0; attempt < 16; attempt++) {
        int fd;

        snprintf(tmp, tmp_len, "%s/.tmp.%d.%x", dir, (int) getpid(),
                 (unsigned) (rand() ^ (attempt << 8)));
        fd = openat(base, tmp, O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd >= 0 || errno != EEXIST)
            return fd;
    }
    return -1;
}

/*
 * WHAT: Write and durably close one temporary CAS object.
 * WHY:  Short writes, interruptions, fsync, and close errors share one contract.
 * HOW:  Complete the byte loop, optionally fsync, close, and preserve failure.
 */
static int cas_temp_write(int fd, const void *data, size_t len, int no_fsync) {
    const char *bytes = data;
    size_t      offset = 0;
    int         rc = 0;

    while (offset < len) {
        ssize_t written = write(fd, bytes + offset, len - offset);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            rc = -1;
            break;
        }
        offset += (size_t) written;
    }
    if (rc == 0 && !no_fsync && fsync(fd) != 0)
        rc = -1;
    if (close(fd) != 0)
        rc = -1;
    return rc;
}

/*
 * WHAT: Rename a completed temporary object into its immutable CAS name.
 * WHY:  A concurrent successful writer is equivalent to our own publication.
 * HOW:  Rename, remove a failed temp, and accept an already-present target.
 */
static int cas_temp_publish(brix_cas_store_t *s, const char *key,
                            int base, const char *tmp, const char *obj) {
    int saved_errno;

    if (renameat(base, tmp, base, obj) == 0)
        return 0;
    saved_errno = errno;
    unlinkat(base, tmp, 0);
    if (brix_cas_has(s, key))
        return 1;
    errno = saved_errno;
    return -1;
}

int brix_cas_put(brix_cas_store_t *s, const char *key, const void *data, size_t len) {
    char obj[640];
    char dir[640];
    char tmp[680];
    int  base;
    int  fd;
    int  published;

    if (s->pack != NULL)
        return brix_cas_pack_put(s->pack, key, data, len);
    if (cas_obj_rel(s, key, obj, sizeof(obj)) < 0
        || cas_dir_rel(s, key, dir, sizeof(dir)) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (brix_cas_has(s, key))
        return 0;
    base = cas_base(s);
    if (mkdirat_ok(base, dir) != 0)
        return -1;
    fd = cas_temp_open(base, dir, tmp, sizeof(tmp));
    if (fd < 0)
        return -1;
    if (cas_temp_write(fd, data, len, s->no_fsync) != 0) {
        unlinkat(base, tmp, 0);
        return -1;
    }
    published = cas_temp_publish(s, key, base, tmp, obj);
    if (published < 0)
        return -1;
    if (published > 0)
        return 0;
    s->cur_bytes += (long) len;
    brix_cas_enforce_quota(s);
    return 0;
}

int brix_cas_del(brix_cas_store_t *s, const char *key) {
    char rel[640];
    struct stat st;
    if (s->pack != NULL) return brix_cas_pack_del(s->pack, key);
    if (cas_obj_rel(s, key, rel, sizeof(rel)) < 0) { errno = EINVAL; return -1; }
    int base = cas_base(s);
    if (fstatat(base, rel, &st, 0) != 0 || !S_ISREG(st.st_mode)) return -1;
    if (unlinkat(base, rel, 0) != 0) return -1;
    s->cur_bytes -= (long) st.st_size;
    if (s->cur_bytes < 0) s->cur_bytes = 0;
    return 0;
}

/* ---- fd-based tree walk (uniform across modes) -------------------------- */

typedef void (*cas_walk_fn)(int subdir_fd, const char *fname, const struct stat *st, void *ud);

/* Open the store's top directory for reading (caller closes the returned fd). */
static int cas_open_top(const brix_cas_store_t *s) {
    return s->dirfd >= 0
        ? openat(s->dirfd, ".", O_RDONLY | O_DIRECTORY)
        : open(s->root, O_RDONLY | O_DIRECTORY);
}

static int cas_walk(const brix_cas_store_t *s, cas_walk_fn fn, void *ud) {
    int top_fd = cas_open_top(s);
    if (top_fd < 0) return -1;
    DIR *top = fdopendir(top_fd);
    if (top == NULL) { close(top_fd); return -1; }

    struct dirent *de;
    while ((de = readdir(top)) != NULL) {
        if (de->d_name[0] == '.') continue;
        int sub_fd = openat(top_fd, de->d_name, O_RDONLY | O_DIRECTORY);
        if (sub_fd < 0) continue;
        DIR *sub = fdopendir(sub_fd);
        if (sub == NULL) { close(sub_fd); continue; }
        struct dirent *fe;
        while ((fe = readdir(sub)) != NULL) {
            if (fe->d_name[0] == '.') continue;
            struct stat st;
            if (fstatat(sub_fd, fe->d_name, &st, 0) == 0 && S_ISREG(st.st_mode))
                fn(sub_fd, fe->d_name, &st, ud);
        }
        closedir(sub);
    }
    closedir(top);
    return 0;
}

static void sum_cb(int sfd, const char *fn, const struct stat *st, void *ud) {
    (void) sfd; (void) fn;
    *(long *) ud += (long) st->st_size;
}

long brix_cas_size(const brix_cas_store_t *s) {
    long total = 0;
    if (s->pack != NULL) return brix_cas_pack_size(s->pack);
    if (cas_walk(s, sum_cb, &total) != 0) return -1;
    return total;
}

/* ---- LRU reap ----------------------------------------------------------- */

typedef struct { int sub_fd; char name[256]; long size; time_t atime; } cas_ent_t;
typedef struct { cas_ent_t *v; size_t n, cap; long total; int oom; } cas_list_t;

static int by_atime(const void *a, const void *b) {
    const cas_ent_t *x = a, *y = b;
    return (x->atime < y->atime) ? -1 : (x->atime > y->atime) ? 1 : 0;
}

/*
 * WHAT: Append one walked object to an LRU-reap snapshot.
 * WHY:  The existing fd walk already handles both path and supplied-dirfd stores.
 * HOW:  Grow the vector, duplicate its directory fd, and accumulate byte size.
 */
static void reap_collect_cb(int sub_fd, const char *name,
                            const struct stat *st, void *ud) {
    cas_list_t *list = ud;
    cas_ent_t  *entry;

    if (list->oom)
        return;
    if (list->n == list->cap) {
        size_t     capacity = list->cap ? list->cap * 2 : 256;
        cas_ent_t *entries = realloc(list->v, capacity * sizeof(*entries));

        if (entries == NULL) {
            list->oom = 1;
            return;
        }
        list->v = entries;
        list->cap = capacity;
    }
    entry = &list->v[list->n];
    entry->sub_fd = dup(sub_fd);
    if (entry->sub_fd < 0) {
        list->oom = 1;
        return;
    }
    list->n++;
    snprintf(entry->name, sizeof(entry->name), "%s", name);
    entry->size = (long) st->st_size;
    entry->atime = st->st_atime;
    list->total += entry->size;
}

/*
 * WHAT: Close and release a partially or fully collected reap snapshot.
 * WHY:  Duplicated directory descriptors must survive the walk but never leak.
 * HOW:  Close every recorded fd, free the vector, and clear its bookkeeping.
 */
static void reap_list_free(cas_list_t *list) {
    size_t i;

    for (i = 0; i < list->n; i++)
        close(list->v[i].sub_fd);
    free(list->v);
    memset(list, 0, sizeof(*list));
}

/*
 * WHAT: Remove oldest snapshot entries until the requested byte target is met.
 * WHY:  Reap policy should be separate from filesystem discovery and cleanup.
 * HOW:  Sort by access time, unlink while over target, and close each held fd.
 */
static int reap_oldest(cas_list_t *list, long target_bytes, long *remaining) {
    long   total = list->total;
    int    removed = 0;
    size_t i;

    qsort(list->v, list->n, sizeof(list->v[0]), by_atime);
    for (i = 0; i < list->n; i++) {
        if (total > target_bytes &&
            unlinkat(list->v[i].sub_fd, list->v[i].name, 0) == 0) {
            total -= list->v[i].size;
            removed++;
        }
        close(list->v[i].sub_fd);
        list->v[i].sub_fd = -1;
    }
    *remaining = total;
    return removed;
}

int brix_cas_reap(brix_cas_store_t *s, long target_bytes) {
    cas_list_t list = {0};
    long       total;
    int        removed;

    if (s->pack != NULL)
        return brix_cas_pack_reap(s->pack, target_bytes);
    if (cas_walk(s, reap_collect_cb, &list) != 0 || list.oom) {
        reap_list_free(&list);
        return -1;
    }
    removed = reap_oldest(&list, target_bytes, &total);
    free(list.v);
    s->cur_bytes = total;
    return removed;
}

int brix_cas_enforce_quota(brix_cas_store_t *s) {
    if (s->pack != NULL) return brix_cas_pack_enforce_quota(s->pack);
    if (s->quota_bytes <= 0 || s->cur_bytes <= s->quota_bytes) return 0;
    long low = (s->quota_bytes * 3) / 4;         /* reap to 75% */
    int r = brix_cas_reap(s, low);
    return r < 0 ? 0 : r;
}
