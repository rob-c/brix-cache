/* Execute checksum CLI objects with finite remote replies and I/O faults.
 * Local hashing, manifest validation, and cache metadata decoding stay real. */
#include "brix.h"
#include "brix_ops.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fault(const char *name)
{
    const char *value = getenv("BRIX_CHECKSUM_FAULT");
    return value != NULL && strcmp(value, name) == 0;
}

static unsigned advance(const char *key)
{
    const char *value = getenv(key);
    unsigned n = value ? (unsigned) atoi(value) : 0;
    char next[32];
    snprintf(next, sizeof(next), "%u", n + 1);
    assert(setenv(key, next, 1) == 0);
    return n;
}

int __wrap_brix_connect(brix_conn *c, const brix_url *url,
                       const brix_opts *options, brix_status *st)
{
    (void) options;
    assert(strcmp(url->host, "fixture.invalid") == 0);
    if (fault("connect")) {
        brix_status_set(st, XRDC_ESOCK, ECONNREFUSED, "fixture connect refused");
        return -1;
    }
    memset(c, 0, sizeof(*c));
    advance("BRIX_CHECKSUM_CONNECTIONS");
    return 0;
}

void __wrap_brix_close(brix_conn *c)
{
    (void) c;
    advance("BRIX_CHECKSUM_CLOSES");
}

int __wrap_brix_query_cksum(brix_conn *c, const char *path, const char *algorithm,
                           char *hex, size_t capacity, brix_status *st)
{
    const char *value = getenv("BRIX_CHECKSUM_DIGEST");
    (void) c;
    fprintf(stderr, "QUERY %s %s\n", algorithm, path);
    if (fault("query") || fault("query-empty")) {
        brix_status_set(st, kXR_NotAuthorized, EACCES,
                       fault("query-empty") ? "" : "fixture query denied");
        return -1;
    }
    assert(value != NULL && strlen(value) < capacity);
    snprintf(hex, capacity, "%s", value);
    return 0;
}

int __wrap_brix_tree_walk(brix_conn *c, const char *path, brix_walk_fn visit,
                         void *data, brix_status *st)
{
    brix_dirent entry = {0};
    char base[4096], child[4096];
    size_t length = strlen(path);
    const char *custom = getenv("BRIX_CHECKSUM_WALK_PATH");
    (void) c;
    if (fault("walk")) {
        brix_status_set(st, kXR_IOError, EIO, "fixture walk failure");
        return -1;
    }
    while (length > 0 && path[length - 1] == '/') { length--; }
    assert(length < sizeof(base));
    memcpy(base, path, length); base[length] = '\0';
    assert(snprintf(child, sizeof(child), "%s/sub", base) < (int) sizeof(child));
    entry.have_stat = 1; entry.st.flags = kXR_isDir;
    assert(visit(child, &entry, 1, data) == 0);
    entry.have_stat = 0; entry.st.flags = 0;
    assert(snprintf(child, sizeof(child), "%s/sub/file", base) < (int) sizeof(child));
    assert(visit(custom ? custom : child, &entry, 2, data) == 0);
    return 0;
}

int __real_brix_cksum_fd(int, brix_cksum_algo, char *, size_t, brix_status *);
int __wrap_brix_cksum_fd(int fd, brix_cksum_algo algorithm, char *hex,
                        size_t capacity, brix_status *st)
{
    assert(fcntl(fd, F_GETFD) >= 0);
    if (fault("checksum") || fault("checksum-empty")) {
        brix_status_set(st, XRDC_EIO, EIO, fault("checksum-empty") ? "" : "fixture hash failure");
        return -1;
    }
    return __real_brix_cksum_fd(fd, algorithm, hex, capacity, st);
}

int __real_open(const char *, int, ...);
int __wrap_open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags); mode = (mode_t) va_arg(ap, int); va_end(ap);
    }
    if (fault("open")) { errno = EACCES; return -1; }
    return __real_open(path, flags, mode);
}

int __real_fseek(FILE *, long, int);
long __real_ftell(FILE *);
size_t __real_fread(void *, size_t, size_t, FILE *);
void *__real_malloc(size_t);
int __wrap_fseek(FILE *stream, long offset, int origin)
{
    if (fault("seek")) { errno = ESPIPE; return -1; }
    return __real_fseek(stream, offset, origin);
}
long __wrap_ftell(FILE *stream)
{
    if (fault("tell")) { errno = EIO; return -1; }
    return __real_ftell(stream);
}
size_t __wrap_fread(void *data, size_t size, size_t count, FILE *stream)
{
    if (fault("short-read")) { return 0; }
    return __real_fread(data, size, count, stream);
}
void *__wrap_malloc(size_t size)
{
    if (fault("allocation")) { return NULL; }
    return __real_malloc(size);
}

/* WHAT: Count live descriptors. WHY: Check error cleanup. HOW: Linux fixture. */
static unsigned descriptor_count(void)
{
    unsigned count = 0;
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    assert(directory != NULL);
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] != '.') { count++; }
    }
    closedir(directory);
    return count;
}

int brix_xrdcktree_main(int, char **);
int brix_xrdckcheck_main(int, char **);
int brix_xrdcinfo_main(int, char **);
int main(int argc, char **argv)
{
    unsigned before = descriptor_count();
    int result;
    assert(argc >= 2);
    if (strcmp(argv[1], "tree") == 0) { result = brix_xrdcktree_main(argc - 1, argv + 1); }
    else if (strcmp(argv[1], "check") == 0) { result = brix_xrdckcheck_main(argc - 1, argv + 1); }
    else { assert(strcmp(argv[1], "info") == 0); result = brix_xrdcinfo_main(argc - 1, argv + 1); }
    assert(unsetenv("BRIX_CHECKSUM_FAULT") == 0);
    assert(descriptor_count() == before);
    assert(advance("BRIX_CHECKSUM_CONNECTIONS") == advance("BRIX_CHECKSUM_CLOSES"));
    return result;
}
