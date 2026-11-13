/* Clock probes retain protocol selection, skew sign and cleanup on refusal. */
#include "apps/diag/xrd_internal.h"
#include <assert.h>

/* WHAT: Match the selected fault. WHY: Keep cases independent. HOW: Read process-owned input. */
static int mode(const char *value) { return !strcmp(getenv("BRIX_CLOCK_MODE"), value); }
/* WHAT: Record an ownership transition. WHY: Detect missing cleanup. HOW: Set a private marker. */
static void mark(const char *name) { assert(setenv(name, "yes", 1) == 0); }
/* WHAT: Return a selected transport failure. WHY: Pin error propagation. HOW: Write a bounded diagnostic. */
static int refuse(brix_status *status, const char *step)
{
    if (!mode(step)) { return 0; }
    snprintf(status->msg, sizeof(status->msg), "fixture-%s", step); return -1;
}

/* WHAT: Supply a fixed clock sample. WHY: Skew boundaries need exact time. HOW: Return a known epoch. */
int __wrap_clock_gettime(clockid_t id, struct timespec *out)
{
    assert(id == CLOCK_REALTIME || id == CLOCK_MONOTONIC);
    out->tv_sec = 1700000000; out->tv_nsec = 0; return 0;
}
/* WHAT: Supply the root probe clock. WHY: Align its interval with HTTP. HOW: Return the same fixed epoch. */
time_t __wrap_time(time_t *out)
{
    if (out) { *out = 1700000000; } return 1700000000;
}

/* WHAT: Supply one HTTP response. WHY: Keep date parsing real. HOW: Check the request and return selected headers. */
int __wrap_brix_http_req(const char *host, int port, int tls, const char *method,
    const char *path, const char *headers, const void *body, size_t length,
    int timeout, int verify, const char *ca, const char *cert,
    brix_http_resp *out, brix_status *status)
{
    assert(!strcmp(host, "origin.invalid") && port > 0);
    assert(tls == 0 || tls == 1); assert(!strcmp(method, "HEAD"));
    assert(!strcmp(path, "/") || !strcmp(path, "/data"));
    assert(!headers && !body && length == 0 && timeout == 5000 && verify == 0);
    assert(!ca && !cert); mark("BRIX_CLOCK_HTTP");
    if (refuse(status, "http-error")) { return -1; }
    memset(out, 0, sizeof(*out)); out->status = 200;
    if (!mode("missing-date")) {
        const char *date = mode("bad-date") ? "hostile" : getenv("BRIX_CLOCK_DATE");
        snprintf(out->headers, sizeof(out->headers), "HTTP/1.1 200 OK\r\nDate: %s\r\n\r\n", date);
    }
    return 0;
}

/* WHAT: Supply the connection result. WHY: Keep probes finite. HOW: Validate the parsed endpoint and inject refusal. */
int __wrap_brix_connect(brix_conn *c, const brix_url *u, const brix_opts *o, brix_status *s)
{
    (void) c; assert(!strcmp(u->host, "origin.invalid") && o);
    mark("BRIX_CLOCK_CONNECT"); return refuse(s, "connect-error");
}
/* WHAT: Record connection release. WHY: prove failed probes do not retain sessions. HOW: set a private marker. */
void __wrap_brix_close(brix_conn *c) { assert(c); mark("BRIX_CLOCK_CLOSE"); }
/* WHAT: Model a temporary remote create. WHY: verify its safe name and flags. HOW: record ownership or reject. */
int __wrap_brix_file_open_write(brix_conn *c, const char *path, int force, int posc,
    brix_file *f, brix_status *s)
{
    assert(c && f && !strncmp(path, "/.xrd_clockskew_", 15) && force && !posc);
    mark("BRIX_CLOCK_OPEN"); return refuse(s, "open-error");
}
/* WHAT: Record file-handle release. WHY: detect leaked handles. HOW: assert valid inputs and mark close. */
int __wrap_brix_file_close(brix_conn *c, brix_file *f, brix_status *s)
{
    assert(c && f && s); mark("BRIX_CLOCK_FILE_CLOSE"); return 0;
}
/* WHAT: Supply remote modification time. WHY: pin skew sign and stat failure. HOW: return the chosen offset. */
int __wrap_brix_stat(brix_conn *c, const char *path, brix_statinfo *out, brix_status *s)
{
    assert(c && !strncmp(path, "/.xrd_clockskew_", 15));
    if (refuse(s, "stat-error")) { return -1; }
    memset(out, 0, sizeof(*out)); out->mtime = 1700000000 + atol(getenv("BRIX_CLOCK_OFFSET"));
    return 0;
}
/* WHAT: Record remote temp removal. WHY: prevent abandoned probe files. HOW: validate the exact probe prefix. */
int __wrap_brix_rm(brix_conn *c, const char *path, brix_status *s)
{
    assert(c && s && !strncmp(path, "/.xrd_clockskew_", 15));
    mark("BRIX_CLOCK_REMOVE"); return 0;
}

/* WHAT: Check final ownership. WHY: Status alone misses leaks. HOW: Compare each marker with the acquired resources. */
static void cleanup_contract(void)
{
    if (!getenv("BRIX_CLOCK_CONNECT")) { return; }
    assert((getenv("BRIX_CLOCK_CLOSE") != NULL) == !mode("connect-error"));
    int created = !mode("connect-error") && !mode("open-error");
    assert((getenv("BRIX_CLOCK_FILE_CLOSE") != NULL) == created);
    assert((getenv("BRIX_CLOCK_REMOVE") != NULL) == created);
}

/* WHAT: Run one probe contract. WHY: Isolate every failure. HOW: Dispatch parsing or the real CLI and check cleanup. */
int main(int argc, char **argv)
{
    assert(argc >= 3);
    if (!strcmp(argv[1], "date")) {
        time_t value = 0; int rc = xrd_parse_http_date(argv[2], &value);
        printf("%d %ld\n", rc, (long) value); return 0;
    }
    if (!strcmp(argv[1], "epoch")) {
        char buf[64]; xrd_fmt_epoch(atol(argv[2]), buf, sizeof(buf)); puts(buf); return 0;
    }
    char *args[] = {"xrd", "clockskew", argv[2], NULL};
    int result = xrd_clockskew(mode("missing-endpoint") ? 2 : 3, args);
    cleanup_contract(); return result;
}
