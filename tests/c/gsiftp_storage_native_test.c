/* Real GridFTP storage operations with an observed, finite origin boundary. */
#include "fs/backend/gsiftp/sd_gsiftp_internal.h"
#include "native_alloc_fail.h"
#include <stdarg.h>
#include <dirent.h>
#include <openssl/rand.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    const char *action, *mode, *size_text;
    unsigned opened, closed, commands, retrieved, stored, published, deleted;
    unsigned writes, reads;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return state() && !strcmp(state()->mode, name); }

int __wrap_gftp_session_open(gftp_session_t *session, const gftp_session_cfg_t *cfg)
{
    assert(!strcmp(cfg->host, "origin.invalid") && cfg->port == 2811);
    assert(cfg->proxy_path && !strcmp(cfg->proxy_path, "/private/proxy"));
    memset(session, 0, sizeof(*session));
    if (mode("session")) {
        strcpy(session->error, "finite connection failure"); errno = ECONNREFUSED; return -1;
    }
    state()->opened++; return 0;
}
void __wrap_gftp_session_close(gftp_session_t *session)
{ (void) session; state()->closed++; }

/* WHAT: Emulate the origin command boundary, not the storage implementation.
 * WHY: Size parsing, directory fallback and cleanup must handle hostile replies.
 * HOW: Record commands and return explicit FTP reply classes or transport errors. */
int __wrap_gftp_command(gftp_session_t *session, const char *format, ...)
{
    char command[4096]; va_list args; va_start(args, format);
    vsnprintf(command, sizeof(command), format, args); va_end(args);
    state()->commands++;
    if (!strncmp(command, "DELE ", 5)) { state()->deleted++; }
    if (mode("command")) { errno = EIO; strcpy(session->error, "finite command failure"); return -1; }
    session->code = 250;
    if (!strncmp(command, "SIZE ", 5)) {
        if (mode("absent")) { errno = ENOENT; return -1; }
        session->code = mode("directory") ? 550 : 213;
        snprintf(session->text, sizeof(session->text), "%s", state()->size_text);
    } else if (!strncmp(command, "MDTM ", 5)) {
        session->code = mode("no-mtime") ? 500 : 213;
        strcpy(session->text, mode("bad-mtime") ? "oops" : " 20260102030405 ");
    } else if (mode("reply-missing")) { session->code = 550; }
    else if (mode("reply-bad")) { session->code = 500; }
    return 0;
}
int __wrap_gftp_expect(gftp_session_t *session, int low, int high, const char *format, ...)
{
    (void) session;
    char command[4096]; va_list args; va_start(args, format);
    vsnprintf(command, sizeof(command), format, args); va_end(args);
    assert(high == low + 99);
    if (!strncmp(command, "RNFR ", 5)) {
        assert(low == 300);
        if (mode("rename-from")) { errno = EACCES; return -1; }
    } else {
        assert(!strncmp(command, "RNTO /base/", 11) && low == 200);
        if (mode("rename-to")) { errno = EACCES; return -1; }
        state()->published++;
    }
    return 0;
}
int __wrap_gftp_slurp(gftp_session_t *session, const char *command, char **out, size_t *length)
{
    (void) session; assert(!strncmp(command, "MLSD /base/", 11));
    if (mode("listing")) { errno = EIO; return -1; }
    const char *text = "\r\nbad\nType=cdir; .\r\nType=pdir; ..\r\nType=file;size=7; item\r\nType=dir; subdir\n";
    *out = strdup(text); assert(*out); *length = strlen(text); return 0;
}

int __wrap_gftp_retrieve(gftp_session_t *session, const char *path, off_t offset,
    size_t limit, gftp_sink_fn sink, void *context, size_t *received)
{
    (void) session; assert(!strcmp(path, "/base/file") && offset >= 0);
    state()->retrieved++;
    if (mode("retrieve")) { errno = EIO; return -1; }
    size_t length = 7 - (size_t) offset; if (length > limit) { length = limit; }
    if (mode("short") && length) { length--; }
    off_t where = mode("negative-block") ? -1 : mode("outside-block") ? (off_t) limit + 1 : 0;
    if (sink(context, where, (const uint8_t *) "payload" + offset, length) != 0) { return -1; }
    *received = length; return 0;
}
int __wrap_gftp_store(gftp_session_t *session, const char *path, gftp_source_fn source, void *context)
{
    (void) session; assert(strstr(path, ".brix-tmp-")); state()->stored++;
    if (mode("store")) { errno = EIO; return -1; }
    uint8_t bytes[16]; size_t used = 0; ssize_t n;
    while ((n = source(context, bytes + used, 2)) > 0) { used += (size_t) n; assert(used <= 7); }
    if (n < 0) { return -1; }
    assert(used == 7 && !memcmp(bytes, "payload", 7)); return 0;
}
FILE *__real_tmpfile64(void);
FILE *__wrap_tmpfile64(void)
{ if (mode("scratch")) { errno = ENOSPC; return NULL; } return __real_tmpfile64(); }
int __real_RAND_bytes(unsigned char *, int);
int __wrap_RAND_bytes(unsigned char *data, int length)
{ return mode("random") ? 0 : __real_RAND_bytes(data, length); }
ssize_t __real_pwrite64(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite64(int fd, const void *data, size_t length, off_t offset)
{
    state()->writes++;
    if (mode("write-eintr") && state()->writes == 1) { errno = EINTR; return -1; }
    if (mode("write-zero")) { return 0; }
    if (mode("write-error")) { errno = ENOSPC; return -1; }
    return __real_pwrite64(fd, data, mode("write-short") && length > 1 ? 1 : length, offset);
}
ssize_t __real_pread64(int, void *, size_t, off_t);
ssize_t __wrap_pread64(int fd, void *data, size_t length, off_t offset)
{
    state()->reads++;
    if (mode("read-eintr") && state()->reads == 1) { errno = EINTR; return -1; }
    if (mode("read-error")) { errno = EIO; return -1; }
    return __real_pread64(fd, data, length, offset);
}

static long stat_object(brix_sd_instance_t *inst, const char *path, brix_sd_cred_t *cred)
{
    brix_sd_stat_t result;
    long rc = sd_gsiftp_stat_cred(inst, path, &result, cred);
    if (!rc) {
        if (mode("directory")) { assert(result.is_dir && S_ISDIR(result.mode)); }
        else {
            assert(result.is_reg && result.size == strtoll(state()->size_text, NULL, 10));
            assert(result.mtime == (mode("bad-mtime") || mode("no-mtime") ? 0 : 1767323045));
        }
    }
    return rc;
}

/* WHAT: Exercise object reads with the real positioned sink and vector copier.
 * WHY: A malicious MODE E offset cannot overwrite a caller's read buffer.
 * HOW: Guarded byte arrays, finite origin blocks and immutable metadata checks. */
static long read_object(brix_sd_instance_t *inst, const char *path, brix_sd_cred_t *cred)
{
    int error = 0, flags = mode("write-flag") ? BRIX_SD_O_WRITE : BRIX_SD_O_READ;
    brix_sd_obj_t *obj = sd_gsiftp_open_cred(inst, path, flags, 0, cred, &error);
    if (!obj) { assert(error == errno); return -1; }
    brix_sd_stat_t snapshot; assert(sd_gsiftp_fstat(obj, &snapshot) == NGX_OK && snapshot.size == 7);
    if (mode("buffer")) { native_alloc_arm("malloc", 0); }
    unsigned char data[16]; memset(data, '!', sizeof(data));
    struct iovec parts[2] = {{data + 1, 3}, {data + 4, 8}};
    if (mode("overflow")) { parts[0].iov_len = SIZE_MAX; }
    if (mode("empty")) { parts[0].iov_len = 0; parts[1].iov_len = 0; }
    off_t offset = mode("negative") ? -1 : mode("eof") ? 7 : 0;
    long rc = sd_gsiftp_preadv(obj, parts, 2, offset); int saved = errno;
    native_alloc_disarm();
    if (rc > 0) { assert(rc <= 7 && !memcmp(data + 1, "payload", (size_t) rc)); }
    assert(data[0] == '!' && data[12] == '!');
    sd_gsiftp_close(obj); free(obj); errno = saved; return rc;
}
static long staged(brix_sd_instance_t *inst, const char *path, brix_sd_cred_t *cred)
{
    int error = 0;
    brix_sd_staged_t *handle = sd_gsiftp_staged_open_cred(inst, path, 0600, 7, cred, &error);
    if (!handle) { assert(error == errno); return -1; }
    long rc = sd_gsiftp_staged_write(handle, "payload", 7, mode("negative") ? -1 : 0);
    brix_sd_precond_t pre = {.kind = mode("exists") || mode("absent") ? BRIX_SD_PRECOND_ABSENT :
        mode("etag") ? BRIX_SD_PRECOND_MATCH_ETAG : BRIX_SD_PRECOND_NONE};
    if (rc == 7) { rc = sd_gsiftp_staged_commit(handle, &pre); }
    int saved = errno;
    if (rc != NGX_OK) { sd_gsiftp_staged_abort(handle); }
    errno = saved; return rc;
}
static long directory(brix_sd_instance_t *inst, const char *path, brix_sd_cred_t *cred)
{
    int error = 0; brix_sd_dir_t *dir = sd_gsiftp_opendir_cred(inst, path, &error, cred);
    if (!dir) { return -1; }
    brix_sd_dirent_t entry;
    assert(sd_gsiftp_readdir(dir, &entry) == NGX_OK && !strcmp(entry.name, "item") && entry.d_type == DT_REG);
    assert(sd_gsiftp_readdir(dir, &entry) == NGX_OK && !strcmp(entry.name, "subdir") && entry.d_type == DT_DIR);
    assert(sd_gsiftp_readdir(dir, &entry) == NGX_DONE);
    return sd_gsiftp_closedir(dir);
}
static long operation(brix_sd_instance_t *inst, const char *path, brix_sd_cred_t *cred)
{
    const char *action = state()->action;
    if (!strcmp(action, "stat")) { return stat_object(inst, path, cred); }
    if (!strcmp(action, "read")) { return read_object(inst, path, cred); }
    if (!strcmp(action, "stage")) { return staged(inst, path, cred); }
    if (!strcmp(action, "dir")) { return directory(inst, path, cred); }
    if (!strcmp(action, "mkdir")) { return sd_gsiftp_mkdir_cred(inst, path, 0700, cred); }
    if (!strcmp(action, "unlink")) { return sd_gsiftp_unlink_cred(inst, path, 0, cred); }
    if (!strcmp(action, "rmdir")) { return sd_gsiftp_unlink_cred(inst, path, 1, cred); }
    if (!strcmp(action, "rename")) { return sd_gsiftp_rename_cred(inst, path, "/dest", mode("exists"), cred); }
    off_t count = -1;
    long rc = sd_gsiftp_server_copy_cred(inst, path, mode("same") ? path : "/dest", &count, cred);
    assert(count == (rc == NGX_OK ? 7 : -1)); return rc;
}
int main(int argc, char **argv)
{
    assert(argc == 6); fixture f = {0}; f.action = argv[1]; f.mode = argv[2]; f.size_text = argv[4];
    f.cycle.log = &f.log; ngx_cycle = &f.cycle; ngx_time_init(); assert(ngx_strerror_init() == NGX_OK);
    brix_sd_gsiftp_cfg_t config = {.host = "origin.invalid", .port = 2811, .base_path = "/base"};
    brix_sd_instance_t *inst = brix_sd_gsiftp_create(&config, &f.log); assert(inst);
    brix_sd_cred_t cred = {.x509_proxy = "/private/proxy"};
    if (mode("denied")) { cred.x509_proxy = NULL; cred.fallback_deny = 1; }
    if (mode("allocation")) { native_alloc_arm("calloc", (unsigned) atoi(argv[5])); }
    long rc = operation(inst, argv[3], &cred); int saved = errno;
    native_alloc_disarm();
    assert(f.opened == f.closed);
    printf("rc=%ld\nerrno=%d\nopened=%u\nretrieved=%u\nstored=%u\npublished=%u\ndeleted=%u\n",
        rc, saved, f.opened, f.retrieved, f.stored, f.published, f.deleted);
    brix_sd_gsiftp_destroy(inst); ngx_cycle = NULL; return 0;
}
