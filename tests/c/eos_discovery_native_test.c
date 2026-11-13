/* EOS manager discovery preserves bounded enumeration and identity-gated fallback. */
#include "apps/diag/diag_internal.h"
#include <assert.h>

/* WHAT: Select one finite scenario. WHY: Isolate faults. HOW: Read process input. */
static int mode(const char *s) { return !strcmp(getenv("BRIX_EOS_MODE"), s); }
/* WHAT: Count ownership transitions. WHY: Detect leaked protocol handles.
 * HOW: Increment a caller-owned environment counter without a production hook. */
static int count(const char *name)
{
    const char *old = getenv(name); int n = old ? atoi(old) : 0;
    char value[32]; snprintf(value, sizeof(value), "%d", n + 1);
    assert(setenv(name, value, 1) == 0); return n + 1;
}
/* WHAT: Fail one allocation family. WHY: Verify cleanup on OOM.
 * HOW: Refuse realloc only in the selected finite process. */
void *__real_realloc(void *, size_t);
void *__wrap_realloc(void *p, size_t n)
{
    if (mode("allocation-error")) { errno = ENOMEM; return NULL; }
    return __real_realloc(p, n);
}
/* WHAT: Establish a finite manager connection. WHY: Keep discovery network-free.
 * HOW: Check its real parsed authority and optionally reject the connection. */
int __wrap_brix_connect(brix_conn *c, const brix_url *u, const brix_opts *opts, brix_status *st)
{
    assert(!strcmp(u->host, "origin.invalid") && opts && st);
    count("BRIX_EOS_CONNECTIONS"); memset(c, 0, sizeof(*c));
    return mode("connect-error") ? -1 : 0;
}
/* WHAT: Record manager release. WHY: Discovery must close every session.
 * HOW: Mark closure independently of the endpoint result. */
void __wrap_brix_close(brix_conn *c) { assert(c); count("BRIX_EOS_CLOSED"); }
/* WHAT: Open one finite EOS proc reply. WHY: Pin user/admin command selection.
 * HOW: Check flags, record the command kind, and refuse selected identities. */
int __wrap_brix_file_open_opaque(brix_conn *c, const char *path, const char *opaque,
    int write, int force, int posc, brix_file *f, brix_status *st)
{
    assert(c && !write && !force && !posc);
    int admin = !strcmp(path, "/proc/admin/");
    assert(admin || !strcmp(path, "/proc/user/"));
    assert(!strcmp(opaque, admin ? "mgm.cmd=fs&mgm.subcmd=ls&mgm.outformat=m" : "mgm.cmd=version"));
    count("BRIX_EOS_OPEN_ATTEMPTS");
    if (mode("open-error") || (admin && (mode("admin-denied") || mode("sample-empty")))) {
        brix_status_set(st, kXR_NotAuthorized, 0, "identity denied"); return -1;
    }
    memset(f, 0, sizeof(*f)); f->fhandle[0] = (uint8_t) admin;
    count("BRIX_EOS_OPENED"); return 0;
}
/* WHAT: Read one command envelope. WHY: Exercise real grow-read and parser paths.
 * HOW: Slice the selected finite reply by offset, or inject a read fault. */
ssize_t __wrap_brix_file_read(brix_conn *c, brix_file *f, int64_t offset,
    void *out, size_t cap, brix_status *st)
{
    assert(c && offset >= 0);
    if (mode("read-error")) { brix_status_set(st, XRDC_ESOCK, EIO, "read failed"); return -1; }
    if (mode("large-body")) {
        size_t length = 200000, off = (size_t) offset;
        if (off >= length) { return 0; }
        size_t n = length - off; if (n > cap) { n = cap; }
        memset(out, 'x', n); return (ssize_t) n;
    }
    const char *body = f->fhandle[0] ? getenv("BRIX_EOS_ADMIN") : getenv("BRIX_EOS_VERSION");
    size_t length = strlen(body), off = (size_t) offset;
    if (off >= length) { return 0; }
    size_t n = length - off; if (n > cap) { n = cap; }
    memcpy(out, body + off, n); return (ssize_t) n;
}
/* WHAT: Release a proc handle. WHY: Error paths must release it exactly once.
 * HOW: Record each independent close. */
int __wrap_brix_file_close(brix_conn *c, brix_file *f, brix_status *st)
{
    assert(c && f && st); count("BRIX_EOS_FILE_CLOSED"); return 0;
}
/* WHAT: Return a finite unprivileged replica sample. WHY: Verify safe fallback.
 * HOW: Require the exact user path and retain the caller's endpoint capacity. */
int __wrap_doctor_eos_discover_fileinfo(brix_conn *c, const char *root,
    doctor_ep *arr, int cap, int start, int *n, brix_status *st)
{
    assert(c && st && !strcmp(root, "/sample") && start == 1);
    count("BRIX_EOS_SAMPLED");
    if (mode("sample-empty")) { return 0; }
    int added = cap - start < 2 ? cap - start : 2;
    for (int i = 0; i < added; i++) { arr[start + i].eos.kind = DOC_EOS_FST; }
    *n = start + added; return added;
}
/* WHAT: Verify all acquired resources were released. WHY: Error status is insufficient.
 * HOW: Compare independent open and close counts after the public call returns. */
static void cleanup(void)
{
    const char *a = getenv("BRIX_EOS_OPENED"), *b = getenv("BRIX_EOS_FILE_CLOSED");
    assert((a ? atoi(a) : 0) == (b ? atoi(b) : 0));
    if (getenv("BRIX_EOS_CONNECTIONS")) {
        assert((getenv("BRIX_EOS_CLOSED") != NULL) == !mode("connect-error"));
    }
}
/* WHAT: Run discovery or a proc read. WHY: Verify bounded topology and exact bytes.
 * HOW: Invoke real algorithms, then emit facts for independent Python assertions. */
int main(int argc, char **argv)
{
    assert(argc == 3);
    if (!strcmp(argv[1], "proc")) {
        brix_conn c = {0}; brix_status st; brix_status_clear(&st); char *out = NULL;
        int rc = doctor_eos_proc(&c, "/proc/user/", "mgm.cmd=version", &out, &st);
        printf("%d %zu\n", rc, out ? strlen(out) : 0); free(out); cleanup(); return 0;
    }
    doctor_ep arr[4] = {0}; diag_args a = {0}; int n = 2, cap = atoi(argv[2]);
    a.map = !mode("disabled"); a.urls[0] = mode("bad-url") ? "file:///sample" : "root://origin.invalid//sample";
    a.probe_timeout_ms = mode("custom-timeout") ? 1234 : 0;
    int trunc = doctor_eos_map(&a, arr, cap, &n);
    printf("truncated=%d count=%d fst=%d gated=%d sampled=%d\n", trunc, n,
        arr[0].eos.fst_count, arr[0].eos.gated, arr[0].eos.sampled);
    fputs("{\"endpoint\":1", stdout); doctor_eos_emit_json(&arr[0], stdout); puts("}");
    cleanup(); return 0;
}
