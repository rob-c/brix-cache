/* Compare actual digest results over finite root, HTTP and TLS providers. */
#include "apps/diag/diag_internal.h"
#include <assert.h>

typedef struct { const char *mode; int connections, closes, temporary, removed; char paths[3][128]; } fixture;
static fixture *state(void)
{ const char *value = getenv("BRIX_COMPARE_STATE"); return value ? (fixture *)(uintptr_t)strtoull(value, NULL, 16) : NULL; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }
static int refuse(brix_status *st)
{ brix_status_set(st, XRDC_ESOCK, ECONNRESET, "finite transport failure"); return -1; }
int __wrap_brix_connect(brix_conn *c, const brix_url *url, const brix_opts *options, brix_status *st)
{
    (void)options; assert(strstr(url->host, "fixture")); int index = ++state()->connections;
    if ((mode("connect-a") && index == 1) || (mode("connect-b") && index == 2)) { return refuse(st); }
    memset(c, 0, sizeof(*c)); c->io.fd = index; return 0;
}
void __wrap_brix_close(brix_conn *c) { assert(c->io.fd > 0); state()->closes++; c->io.fd = -1; }
int __wrap_brix_stat(brix_conn *c, const char *path, brix_statinfo *out, brix_status *st)
{
    assert(path[0] == '/' && c->io.fd > 0); memset(out, 0, sizeof(*out)); out->size = 9;
    if (mode("stat")) { return refuse(st); }
    if (!strncmp(state()->mode, "dir", 3)) { out->flags = kXR_isDir; }
    if (mode("size") && c->io.fd == 2) { out->size++; } return 0;
}
int __wrap_brix_dirlist(brix_conn *c, const char *path, int stat, brix_dirent **entries, size_t *count, brix_status *status)
{
    assert(path[0] == '/' && !stat);
    if (mode("dir-error")) { return refuse(status); }
    *count = mode("dir-count") && c->io.fd == 2 ? 1 : 2;
    *entries = calloc(*count, sizeof(**entries)); assert(*entries);
    for (size_t i = 0; i < *count; i++) { snprintf((*entries)[i].name, sizeof((*entries)[i].name), "%s",
        (c->io.fd == 1 ? i : 1 - i) ? "b" : "a"); }
    if (mode("dir-name") && c->io.fd == 2) { strcpy((*entries)[0].name, "other"); } return 0;
}
int __wrap_download_to_fd(brix_conn *c, const char *path, int fd, int64_t *bytes, brix_status *st)
{
    assert(path[0] == '/' && c->io.fd > 0);
    if (mode("read")) { return refuse(st); }
    const char *text = mode("mismatch") && c->io.fd == 2 ? "different" : "samebytes";
    *bytes = (int64_t)strlen(text); assert(write(fd, text, (size_t)*bytes) == *bytes); return 0;
}
int __wrap_brix_http_get(const char *host, int port, const char *path, int timeout, int *status,
    char *out, size_t capacity, size_t *length, brix_status *st)
{
    assert(!strcmp(host, "fixture.invalid") && port == 8080 && path[0] == '/' && timeout == 5000 && capacity >= 9);
    if (mode("http")) { return refuse(st); }
    *status = mode("http-status") ? 403 : 200;
    const char *text = mode("mismatch") ? "different" : "samebytes";
    *length = strlen(text); memcpy(out, text, *length); return 0;
}
int __wrap_brix_http_download(const char *host, int port, int tls, const char *path, const char *headers,
    int verify, const char *ca, const char *cert, int fd, int timeout, int *status, long long *length, brix_status *st)
{
    assert(!strcmp(host, "fixture.invalid") && port == 8443 && tls && path[0] == '/' && !headers && verify && !ca && !cert && timeout == 5000);
    if (mode("tls")) { return refuse(st); }
    *status = mode("tls-status") ? 503 : 200; *length = 9;
    assert(write(fd, "samebytes", 9) == 9); return 0;
}
int __real_mkstemp(char *);
int __wrap_mkstemp(char *name)
{
    fixture *f = state(); int index = ++f->temporary;
    if ((mode("temp-root") && index == 1) || (mode("temp-dav") && index == 2) || (mode("temp-tls") && index == 3)) { errno = EMFILE; return -1; }
    int fd = __real_mkstemp(name); assert(fd >= 0 && index <= 3);
    snprintf(f->paths[index - 1], sizeof(f->paths[0]), "%s", name); return fd;
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size)
{ return state() && mode("allocation") && size == (1u << 20) ? NULL : __real_malloc(size); }
int main(int argc, char **argv)
{
    assert(argc == 5); fixture f = {.mode=argv[1]}; char pointer[40];
    snprintf(pointer, sizeof(pointer), "%lx", (unsigned long)(uintptr_t)&f);
    assert(setenv("BRIX_COMPARE_STATE", pointer, 1) == 0);
    diag_args args = {.url=argv[3], .ref_url=!strcmp(argv[4], "-") ? NULL : argv[4], .verify_tls=1};
    if (!strcmp(argv[2], "http")) { args.davs="fixture.invalid:8080"; args.davs_tls="fixture.invalid:8443"; }
    g_fails = 0; int rc = do_compare(&args);
    for (int i = 0; i < 3; i++) { if (f.paths[i][0]) { assert(access(f.paths[i], F_OK) == -1 && errno == ENOENT); } }
    fprintf(stderr, "RESULT %d %d %d %d\n", rc, g_fails, f.connections, f.closes);
    unsetenv("BRIX_COMPARE_STATE"); return 0;
}
