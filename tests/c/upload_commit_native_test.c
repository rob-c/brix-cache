/* Real upload/pump and VFS lifetimes with fault-controlled remote operations. */
#include "xfer/copy_internal.h"
#include <assert.h>

static int mode(const char *name) { return strcmp(getenv("BRIX_UPLOAD_MODE"), name) == 0; }
static unsigned count(const char *name) {
    const char *value = getenv(name);
    return value ? (unsigned) strtoul(value, NULL, 10) : 0;
}
static unsigned bump(const char *name) {
    unsigned value = count(name) + 1;
    char text[32];
    snprintf(text, sizeof(text), "%u", value);
    assert(setenv(name, text, 1) == 0);
    return value;
}
static int fail(brix_status *st, int code) {
    brix_status_set(st, code, 0, "injected remote failure"); return -1;
}
uint64_t __wrap_brix_mono_ns(void) { return (uint64_t) bump("UPLOAD_CLOCK") * 1000000; }
void __wrap_brix_backoff_sleep_fast(unsigned attempt) { assert(attempt < 50); }
int __wrap_brix_copy_quit_requested(void) { return mode("cancel"); }

int __wrap_brix_connect_resilient(brix_conn *c, const brix_url *url,
    const brix_opts *opts, brix_status *st) {
    (void) opts;
    assert(strcmp(url->path, "/target") == 0);
    bump("UPLOAD_CONNECTS");
    memset(c, 0, sizeof(*c)); c->io.fd = -1;
    if (mode("connect")) { return fail(st, kXR_NotAuthorized); }
    return 0;
}
void __wrap_brix_close(brix_conn *c) { assert(c->io.fd == -1); bump("UPLOAD_DISCONNECTS"); }

static int open_write(brix_file *file, int force, int posc, brix_status *st) {
    unsigned n = bump("UPLOAD_OPENS");
    assert(force == (1 | XRDC_OPEN_COERCE) && posc == 1);
    if (mode("open-auth")) { return fail(st, kXR_NotAuthorized); }
    if (mode("open-retry") && n == 1) { return fail(st, XRDC_ESOCK); }
    memset(file, 0, sizeof(*file)); file->fhandle[0] = 19;
    file->write_codec = mode("compressed") ? 1 : 0;
    return 0;
}
int __wrap_brix_file_open_write(brix_conn *c, const char *path, int force,
    int posc, brix_file *file, brix_status *st) {
    (void) c; assert(strcmp(path, "/target") == 0);
    return open_write(file, force, posc, st);
}
int __wrap_brix_file_open_opaque(brix_conn *c, const char *path, const char *opaque,
    int write, int force, int posc, brix_file *file, brix_status *st) {
    assert(write == 1 && strcmp(opaque, "xrootd.compress=zstd") == 0);
    bump("UPLOAD_OPAQUE");
    return __wrap_brix_file_open_write(c, path, force, posc, file, st);
}
void __wrap_csctx_reopen_home(brix_conn *c, brix_status *st) {
    (void) c; brix_status_clear(st); bump("UPLOAD_RECONNECTS");
}
int __wrap_brix_streams_open(brix_streamset *ss, brix_conn *c, int streams,
    brix_status *st) {
    (void) c; (void) st; assert(streams == 3); ss->n = 2;
    bump("UPLOAD_STREAMS"); return 0;
}
void __wrap_brix_streams_close(brix_streamset *ss) {
    assert(ss->n == (mode("compressed") ? 0 : 2)); bump("UPLOAD_STREAM_CLOSES");
}

int __wrap_pump_sink_remote(void *context, const uint8_t *buf, int64_t off,
    size_t size, brix_status *st) {
    pump_remote_t *sink = context;
    const char *payload = "upload contents\n";
    assert(off >= 0 && off + (int64_t) size <= (int64_t) strlen(payload));
    assert(memcmp(buf, payload + off, size) == 0);
    assert(sink->resilient && sink->posc && sink->max_stall_ms == 20);
    assert((sink->ss == NULL) == (mode("compressed") || mode("paged")));
    bump("UPLOAD_WRITES");
    if (mode("pump")) { return fail(st, kXR_NotAuthorized); }
    return 0;
}
int __wrap_brix_file_close(brix_conn *c, brix_file *file, brix_status *st) {
    (void) c; assert(file->fhandle[0] == 19);
    unsigned n = bump("UPLOAD_COMMITS");
    if (strncmp(getenv("BRIX_UPLOAD_MODE"), "close-", 6) == 0
        || mode("cancel")) {
        if (mode("close-retry") && n == 2) { brix_status_clear(st); return 0; }
        return fail(st, XRDC_ESOCK);
    }
    return 0;
}
int __wrap_pump_sink_reopen(pump_remote_t *sink, brix_status *st) {
    assert(strcmp(sink->path, "/target") == 0 && sink->posc);
    bump("UPLOAD_REOPENS");
    if (mode("close-retry")) { return 0; }
    return fail(st, kXR_NotFound);
}
int __wrap_brix_stat(brix_conn *c, const char *path, brix_statinfo *stat,
    brix_status *st) {
    (void) c; assert(strcmp(path, "/target") == 0);
    bump("UPLOAD_STATS");
    if (mode("close-stat-error")) { return fail(st, kXR_NotAuthorized); }
    if (mode("close-transient")) { return fail(st, XRDC_ESOCK); }
    memset(stat, 0, sizeof(*stat));
    stat->size = mode("close-wrong-size") ? 4 : 16;
    return 0;
}
int __wrap_cksum_verify(brix_conn *c, const char *remote, const char *local,
    const char *algorithm, int silent, brix_status *st) {
    (void) c; (void) silent;
    assert(strcmp(remote, "/target") == 0 && strcmp(algorithm, "adler32") == 0);
    assert((local == NULL) == mode("stdin"));
    bump("UPLOAD_CHECKSUMS");
    if (mode("mismatch")) { fail(st, kXR_ChkSumErr); return XRDC_CK_MISMATCH; }
    if (strncmp(getenv("BRIX_UPLOAD_MODE"), "unverified", 10) == 0) {
        fail(st, XRDC_ESOCK); return XRDC_CK_UNVERIFIED;
    }
    return XRDC_CK_OK;
}
int __real_brix_vfs_fstat(brix_vfs_file *, brix_vfs_stat *, brix_status *);
int __wrap_brix_vfs_fstat(brix_vfs_file *file, brix_vfs_stat *stat, brix_status *st) {
    if (mode("unknown-size")) { return fail(st, XRDC_ESOCK); }
    return __real_brix_vfs_fstat(file, stat, st);
}

int main(int argc, char **argv) {
    brix_url source = {0}, destination = {0};
    brix_copy_opts options = {0};
    brix_opts connection = {0};
    brix_status status;
    assert(argc == 5);
    assert(setenv("BRIX_UPLOAD_MODE", argv[2], 1) == 0);
    assert(brix_url_parse(argv[1], &source, &status) == 0);
    assert(brix_url_parse("root://origin.test/target", &destination, &status) == 0);
    options.force = options.coerce = options.posc = 1;
    options.streams = 3; options.max_stall_ms = 20;
    options.silent = atoi(argv[4]);
    options.pgrw = mode("paged");
    options.cksum = "adler32";
    options.verify_strict = mode("unverified-strict") || mode("stdin-strict");
    options.compress = mode("compressed") ? "zstd" : NULL;
    brix_status_clear(&status);
    int rc = copy_upload(&source, &destination, &options, &connection, &status);
    printf("RESULT rc=%d status=%d\n", rc, status.kxr);
    const char *names[] = {"UPLOAD_CONNECTS", "UPLOAD_DISCONNECTS", "UPLOAD_OPENS",
        "UPLOAD_RECONNECTS", "UPLOAD_STREAMS", "UPLOAD_STREAM_CLOSES", "UPLOAD_WRITES",
        "UPLOAD_COMMITS", "UPLOAD_REOPENS", "UPLOAD_STATS", "UPLOAD_CHECKSUMS", "UPLOAD_OPAQUE"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        printf("%s=%u\n", names[i], count(names[i]));
    }
    fflush(stdout);
    assert(rc == atoi(argv[3]));
    return 0;
}
