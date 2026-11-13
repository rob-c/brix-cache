/* Finite remote-doctor failures keep findings honest and clean up owned work.
 * The real probe and report implementations run; only network operations are
 * replaced. Every ownership transition is emitted for an independent oracle. */
#include "apps/diag/diag_internal.h"
#include <assert.h>

static int mode(const char *name) { return !strcmp(getenv("BRIX_DOCTOR_FAULT"), name); }
static int failure(brix_status *st)
{ brix_status_set(st, atoi(getenv("BRIX_DOCTOR_ERROR")), 0, "fixture-private-data-must-not-leak"); return -1; }
static void event(const char *name) { printf("event=%s\n", name); }
int __wrap_brix_stat(brix_conn *c, const char *path, brix_statinfo *out, brix_status *st)
{
    assert(c && path); event("stat");
    if (mode("stat") || mode("anon-denied") || mode("anon-open")) { return failure(st); }
    memset(out, 0, sizeof(*out)); out->flags = mode("offline") ? kXR_offline : 0; return 0;
}
int __wrap_brix_dirlist(brix_conn *c, const char *path, int flags, brix_dirent **out,
    size_t *count, brix_status *st)
{
    assert(c && !strcmp(path, "/") && flags == 0); event("list");
    if (mode("list")) { return failure(st); }
    *count = mode("empty") ? 0 : 2; *out = calloc(2, sizeof(**out)); assert(*out);
    strcpy((*out)[0].name, ".hidden"); strcpy((*out)[1].name, mode("hidden") ? ".private" : "visible"); return 0;
}
int __wrap_brix_file_open_read(brix_conn *c, const char *path, brix_file *f, brix_status *st)
{
    assert(c && path); event("open-read");
    if (mode("open-read") || mode("anon-denied")) { return failure(st); }
    memset(f, 0, sizeof(*f)); f->fhandle[0] = 1; return 0;
}
int __wrap_brix_file_open_write(brix_conn *c, const char *path, int force, int posc,
    brix_file *f, brix_status *st)
{
    assert(c && strstr(path, "/.xrddiag-dx-") == path && force == 1 && posc == 0); event("open-write");
    if (mode("open-write")) { return failure(st); }
    memset(f, 0, sizeof(*f)); f->fhandle[0] = 2; return 0;
}
ssize_t __wrap_brix_file_read(brix_conn *c, brix_file *f, int64_t offset,
    void *out, size_t cap, brix_status *st)
{
    assert(c && f->fhandle[0] == 1 && offset == 0); event("read");
    if (mode("read")) { return failure(st); }
    const char *payload = "xrddiag-remote-doctor-write-probe\n"; size_t n = strlen(payload); assert(cap >= n);
    memcpy(out, payload, n); if (mode("corrupt")) { ((char *) out)[0] ^= 1; }
    return mode("short") ? (ssize_t) n - 1 : (ssize_t) n;
}
int __wrap_brix_file_write(brix_conn *c, brix_file *f, int64_t offset,
    const void *data, size_t size, brix_status *st)
{
    assert(c && f->fhandle[0] == 2 && offset == 0);
    const char *payload = "xrddiag-remote-doctor-write-probe\n";
    assert(size == strlen(payload) && !memcmp(data, payload, size)); event("write");
    return mode("write") ? failure(st) : 0;
}
int __wrap_brix_file_close(brix_conn *c, brix_file *f, brix_status *st)
{
    assert(c && f); event(f->fhandle[0] == 2 ? "close-write" : "close-read");
    return f->fhandle[0] == 2 && mode("close-write") ? failure(st) : 0;
}
int __wrap_brix_mkdir(brix_conn *c, const char *path, int permissions, int parents, brix_status *st)
{
    assert(c && strstr(path, "/.xrddiag-") == path && permissions == 0700 && !parents); event("mkdir");
    return mode("mkdir") ? failure(st) : 0;
}
int __wrap_brix_rm(brix_conn *c, const char *path, brix_status *st)
{ assert(c && path && st); event("rm"); return 0; }
int __wrap_brix_rmdir(brix_conn *c, const char *path, brix_status *st)
{ assert(c && path); event("rmdir"); return mode("cleanup") ? failure(st) : 0; }
int __wrap_brix_prepare(brix_conn *c, const char *const *paths, int count, int flags,
    int priority, int port, char *out, size_t capacity, brix_status *st)
{
    assert(c && count == 1 && !strcmp(paths[0], "/object"));
    assert(!flags && !priority && !port && out && capacity); event("prepare");
    return mode("prepare") ? failure(st) : 0;
}
int __wrap_dx_connect_as(const diag_args *args, const brix_url *url, const dx_cred_sel *selection,
    brix_conn *c, brix_status *st)
{
    assert(args && url && selection); event("connect");
    assert(selection->force_anon || (selection->auth_force && !strcmp(selection->auth_force, "ztn")
        && selection->token_override && !strcmp(selection->token_override, "fixture-token")));
    if (mode("connect")) { return failure(st); }
    memset(c, 0, sizeof(*c)); if (!mode("anonymous")) { strcpy(c->sec_list, "&P=ztn"); } return 0;
}
void __wrap_brix_close(brix_conn *c) { assert(c); event("close-session"); }
int __wrap_brix_query_cksum(brix_conn *c, const char *path, const char *algorithm,
    char *out, size_t cap, brix_status *st)
{
    assert(c && !strcmp(path, "/object") && !strcmp(algorithm, "adler32")); event("query-checksum");
    if (mode("query")) { return failure(st); }
    snprintf(out, cap, "%s", getenv("BRIX_DOCTOR_CHECKSUM")); return 0;
}
int __wrap_download_to_fd(brix_conn *c, const char *path, int fd, int64_t *got, brix_status *st)
{
    assert(c && !strcmp(path, "/object")); event("download");
    if (mode("download")) { return failure(st); }
    assert(write(fd, "abc", 3) == 3); *got = 3; return 0;
}

static void invoke_probe(const char *name, brix_conn *c, doctor_ep *e)
{
    if (!strcmp(name, "namespace")) { dx_probe_namespace(c, e); return; }
    if (!strcmp(name, "read")) { dx_probe_read(c, "/object", e); return; }
    if (!strcmp(name, "write")) { dx_probe_write(c, e); return; }
    if (!strcmp(name, "stage")) { dx_probe_stage(c, "/object", e); return; }
    if (!strcmp(name, "checksum")) { dx_probe_checksum(c, "/object", e); return; }
    if (!strcmp(name, "auth")) {
        if (!mode("anonymous")) { strcpy(c->sec_list, "&P=ztn"); }
        if (mode("authenticated")) { c->diag.chosen_auth = "ztn"; }
        dx_probe_auth(c, e); return;
    }
    diag_args args = {0}; brix_url url = {0};
    if (!strcmp(name, "anon")) { char offered[32]; dx_authz_anon(&args, &url, "/object", 1, offered, sizeof(offered), e); return; }
    if (!strcmp(name, "forged")) { dx_authz_forged(&args, &url, "authz-forged", "fixture-token", e); return; }
    if (!strcmp(name, "expired")) { dx_authz_expired(&args, &url, "fixture-token", e); return; }
    assert(!strcmp(name, "scope")); dx_authz_scope(&args, &url, "fixture-token", e);
}
int main(int argc, char **argv)
{
    assert(argc == 2); doctor_ep endpoint = {0}; brix_conn connection = {0};
    invoke_probe(argv[1], &connection, &endpoint);
    printf("status=%d\noffline=%d\nfindings=%d\n", endpoint.status, endpoint.offline_seen, endpoint.ndx);
    for (int i = 0; i < endpoint.ndx; i++) {
        dx_finding *f = &endpoint.dx[i];
        printf("finding=%s|%d|%d|%s\n", f->probe, f->verdict, f->kxr, f->cause);
        assert(!strstr(f->cause, "fixture-private-data"));
    }
    return 0;
}
