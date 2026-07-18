/* cas_store.c — content-addressed local POSIX object store. See cas_store.h. */
#include "cache/cas_store.h"

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

int brix_cas_path(const brix_cas_store_t *s, const char *key, char *buf, size_t buflen) {
    return cas_obj_rel(s, key, buf, buflen);
}

int brix_cas_has(const brix_cas_store_t *s, const char *key) {
    char rel[640];
    struct stat st;
    if (cas_obj_rel(s, key, rel, sizeof(rel)) < 0) return 0;
    return fstatat(cas_base(s), rel, &st, 0) == 0 && S_ISREG(st.st_mode);
}

int brix_cas_open(const brix_cas_store_t *s, const char *key) {
    char rel[640];
    if (cas_obj_rel(s, key, rel, sizeof(rel)) < 0) { errno = EINVAL; return -1; }
    return openat(cas_base(s), rel, O_RDONLY);
}

int brix_cas_put(brix_cas_store_t *s, const char *key, const void *data, size_t len) {
    char obj[640], dir[640];
    if (cas_obj_rel(s, key, obj, sizeof(obj)) < 0
        || cas_dir_rel(s, key, dir, sizeof(dir)) < 0) { errno = EINVAL; return -1; }
    if (brix_cas_has(s, key)) return 0;                 /* immutable: present */

    int base = cas_base(s);
    if (mkdirat_ok(base, dir) != 0) return -1;

    /* atomic put: O_EXCL temp in the fan-out dir + fsync + renameat. */
    char tmp[680];
    int  fd = -1;
    for (int attempt = 0; attempt < 16 && fd < 0; attempt++) {
        snprintf(tmp, sizeof(tmp), "%s/.tmp.%d.%x", dir, (int) getpid(),
                 (unsigned) (rand() ^ (attempt << 8)));
        fd = openat(base, tmp, O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd < 0 && errno != EEXIST) return -1;
    }
    if (fd < 0) return -1;

    const char *p = data; size_t off = 0; int rc = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; rc = -1; break; }
        off += (size_t) w;
    }
    if (rc == 0 && fsync(fd) != 0) rc = -1;
    if (close(fd) != 0) rc = -1;
    if (rc != 0) { unlinkat(base, tmp, 0); return -1; }

    if (renameat(base, tmp, base, obj) != 0) {
        int e = errno;
        unlinkat(base, tmp, 0);
        if (brix_cas_has(s, key)) return 0;             /* racing writer won */
        errno = e; return -1;
    }
    s->cur_bytes += (long) len;
    brix_cas_enforce_quota(s);
    return 0;
}

int brix_cas_del(brix_cas_store_t *s, const char *key) {
    char rel[640];
    struct stat st;
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
    if (cas_walk(s, sum_cb, &total) != 0) return -1;
    return total;
}

/* ---- LRU reap ----------------------------------------------------------- */

typedef struct { int sub_fd; char name[256]; long size; time_t atime; } cas_ent_t;
typedef struct { cas_ent_t *v; size_t n, cap; long total; } cas_list_t;

static int by_atime(const void *a, const void *b) {
    const cas_ent_t *x = a, *y = b;
    return (x->atime < y->atime) ? -1 : (x->atime > y->atime) ? 1 : 0;
}

int brix_cas_reap(brix_cas_store_t *s, long target_bytes) {
    /* Snapshot every object (dup'ing each fan-out dir fd so it stays unlinkable
     * after the walk closes it), sort by atime, then evict oldest-first until at
     * or below target_bytes. */
    cas_list_t l; memset(&l, 0, sizeof(l));

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
            if (fstatat(sub_fd, fe->d_name, &st, 0) != 0 || !S_ISREG(st.st_mode)) continue;
            if (l.n == l.cap) {
                size_t nc = l.cap ? l.cap * 2 : 256;
                cas_ent_t *nv = realloc(l.v, nc * sizeof(*nv));
                if (nv == NULL) break;
                l.v = nv; l.cap = nc;
            }
            cas_ent_t *e = &l.v[l.n++];
            e->sub_fd = dup(sub_fd);       /* keep openable after sub closes */
            snprintf(e->name, sizeof(e->name), "%s", fe->d_name);
            e->size = (long) st.st_size;
            e->atime = st.st_atime;
            l.total += e->size;
        }
        closedir(sub);
    }
    closedir(top);

    qsort(l.v, l.n, sizeof(l.v[0]), by_atime);   /* oldest first */

    int  removed = 0;
    long total   = l.total;
    for (size_t i = 0; i < l.n; i++) {
        if (total > target_bytes
            && unlinkat(l.v[i].sub_fd, l.v[i].name, 0) == 0) {
            total -= l.v[i].size; removed++;
        }
        close(l.v[i].sub_fd);
    }
    free(l.v);
    s->cur_bytes = total;
    return removed;
}

int brix_cas_enforce_quota(brix_cas_store_t *s) {
    if (s->quota_bytes <= 0 || s->cur_bytes <= s->quota_bytes) return 0;
    long low = (s->quota_bytes * 3) / 4;         /* reap to 75% */
    int r = brix_cas_reap(s, low);
    return r < 0 ? 0 : r;
}
