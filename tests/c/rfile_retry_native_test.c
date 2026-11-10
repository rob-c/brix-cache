/* Real resilient handle retry orchestration; only remote operations are scripted. */
#include "brix.h"
#include "_brix_net_ext.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    brix_conn connection;
    const char *mode;
    int paged, calls, reconnects, opens;
    size_t last_read;
} retry_fixture_t;

/* WHAT: Model cancellation owned by the caller. WHY: No remote work may follow initial cancel.
 * HOW: Read an isolated process flag through the public cancellation callback. */
static int canceled(void) { return getenv("BRIX_RFILE_CANCEL") != NULL; }

/* WHAT: Choose one remote outcome. WHY: Retry policy must distinguish transport from auth errors.
 * HOW: Fail once for retry cases, fail definitively for refusal cases, otherwise succeed. */
static int outcome(retry_fixture_t *fixture, brix_file *file, brix_status *status)
{
    fixture->calls++;
    assert(file->fhandle[0] == (fixture->opens ? 0x20 : 0x10));
    if (!strcmp(fixture->mode, "success")) { return 0; }
    if ((!strcmp(fixture->mode, "retry") || !strcmp(fixture->mode, "floor")) && fixture->calls == 2) {
        return 0;
    }
    if (!strcmp(fixture->mode, "deadline")) { usleep(5000); }
    int code = !strcmp(fixture->mode, "auth-error") ? kXR_NotAuthorized : XRDC_ESOCK;
    brix_status_set(status, code, ECONNRESET, "scripted remote refusal");
    return -1;
}

/* WHAT: Preserve read coordinates and record adaptive capacity.
 * WHY: Reopened reads must use the same offset and a bounded byte count.
 * HOW: Return a short real payload only after the selected attempt succeeds. */
static ssize_t read_once(brix_conn *connection, brix_file *file, int64_t offset,
                          void *buffer, size_t length, brix_status *status, int paged)
{
    retry_fixture_t *fixture = (retry_fixture_t *)connection;
    assert(fixture->paged == paged && offset == 123 && length >= 7);
    fixture->last_read = length;
    if (outcome(fixture, file, status)) { return -1; }
    memcpy(buffer, "payload", 7); return 7;
}
ssize_t __wrap_brix_file_read(brix_conn *c, brix_file *f, int64_t o, void *p, size_t n, brix_status *s) {
    return read_once(c, f, o, p, n, s, 0);
}
ssize_t __wrap_brix_file_pgread(brix_conn *c, brix_file *f, int64_t o, void *p, size_t n, brix_status *s) {
    return read_once(c, f, o, p, n, s, 1);
}

/* WHAT: Preserve writes across retries. WHY: No retry may shrink or change the replayed bytes.
 * HOW: Assert the original payload and offset before returning the scripted outcome. */
static int write_once(brix_conn *connection, brix_file *file, int64_t offset,
                       const void *buffer, size_t length, brix_status *status, int paged)
{
    retry_fixture_t *fixture = (retry_fixture_t *)connection;
    assert(fixture->paged == paged && offset == 123 && length == 7);
    assert(!memcmp(buffer, "payload", 7)); return outcome(fixture, file, status);
}
int __wrap_brix_file_write(brix_conn *c, brix_file *f, int64_t o, const void *p, size_t n, brix_status *s) {
    return write_once(c, f, o, p, n, s, 0);
}
int __wrap_brix_file_pgwrite(brix_conn *c, brix_file *f, int64_t o, const void *p, size_t n, brix_status *s) {
    return write_once(c, f, o, p, n, s, 1);
}

/* WHAT: Return handle-based metadata after the selected retry.
 * WHY: Stat must follow the refreshed handle rather than resolving a path again.
 * HOW: Require the current handle identity through the common outcome check. */
int __wrap_brix_file_stat(brix_conn *c, brix_file *f, brix_statinfo *out, brix_status *status)
{
    int rc = outcome((retry_fixture_t *)c, f, status);
    if (rc == 0) { out->size = 1234; } return rc;
}

/* WHAT: Observe home reconnection without opening sockets.
 * WHY: The runner must reopen exactly once after a retryable failure.
 * HOW: Validate endpoint identity and count on the connection-owned fixture. */
int __wrap_brix_reconnect(brix_conn *c, const char *host, int port, brix_status *status)
{
    (void)status; retry_fixture_t *fixture = (retry_fixture_t *)c;
    assert(!strcmp(host, "home.test") && port == 1094); fixture->reconnects++; return 0;
}
void __wrap_brix_backoff_sleep_fast(unsigned attempt) { assert(attempt == 0); }

/* WHAT: Refresh a handle without truncating its destination.
 * WHY: Retrying a write must reopen in-place and retain POSC.
 * HOW: Use distinct read/update entry points and publish a changed handle identity. */
static int reopened(brix_conn *c, const char *path, brix_file *file)
{
    retry_fixture_t *fixture = (retry_fixture_t *)c;
    assert(!strcmp(path, "/data")); fixture->opens++; file->fhandle[0] = 0x20; return 0;
}
int __wrap_brix_file_open_read(brix_conn *c, const char *path, brix_file *file, brix_status *status) {
    (void)status; return reopened(c, path, file);
}
int __wrap_brix_file_open_update(brix_conn *c, const char *path, int posc,
                                 brix_file *file, brix_status *status) {
    (void)status; assert(posc == 1); return reopened(c, path, file);
}

/* WHAT: Check one public operation and the runner's recovery disposition.
 * WHY: Success, cancellation, hard errors and disabled/deadline retries differ.
 * HOW: Inspect returned bytes/metadata, wire-call counts, and unchanged write sizing. */
static void check(retry_fixture_t *fixture, brix_rfile *file, const char *operation)
{
    brix_status status = {0}; brix_statinfo info = {0}; char buffer[7] = {0}; ssize_t rc;
    int reading = strstr(operation, "read") != NULL;
    if (reading) { rc = brix_rfile_pread(file, 123, buffer, 1048576, &status); }
    else if (!strcmp(operation, "stat")) { rc = brix_rfile_stat(file, &info, &status); }
    else { rc = brix_rfile_pwrite(file, 123, "payload", 7, &status); }
    int retry = !strcmp(fixture->mode, "retry") || !strcmp(fixture->mode, "floor");
    int success = retry || !strcmp(fixture->mode, "success");
    assert(rc == (success ? (reading ? 7 : 0) : -1));
    assert(fixture->reconnects == retry && fixture->opens == retry);
    int is_canceled = !strcmp(fixture->mode, "cancel");
    assert(fixture->calls == (is_canceled ? 0 : 1 + retry));
    if (is_canceled) { assert(status.sys_errno == ECANCELED); }
    if (success && reading) { assert(!memcmp(buffer, "payload", 7)); }
    if (success && !strcmp(operation, "stat")) { assert(info.size == 1234); }
}

/* WHAT: Bind one finite case. WHY: No production state or real endpoint is shared.
 * HOW: Initialize a public handle directly and run its real operation wrapper. */
int main(int argc, char **argv)
{
    assert(argc == 3); retry_fixture_t fixture = {0}; brix_rfile file = {0};
    fixture.mode = argv[2]; fixture.paged = !strncmp(argv[1], "pg", 2);
    strcpy(fixture.connection.home_host, "home.test"); fixture.connection.home_port = 1094;
    file.c = &fixture.connection; file.pgrw = fixture.paged; file.cancel = canceled;
    file.writable = strstr(argv[1], "write") != NULL; file.posc = 1;
    file.max_stall_ms = 1000; file.cur_chunk = 1048576; strcpy(file.path, "/data");
    file.f.fhandle[0] = 0x10;
    if (!strcmp(argv[2], "disabled")) { file.max_stall_ms = 0; }
    if (!strcmp(argv[2], "deadline")) { file.max_stall_ms = 1; }
    if (!strcmp(argv[2], "floor")) { file.cur_chunk = 262144; }
    if (!strcmp(argv[2], "cancel")) { assert(setenv("BRIX_RFILE_CANCEL", "1", 1) == 0); }
    check(&fixture, &file, argv[1]);
    if (!strcmp(argv[2], "retry") && strstr(argv[1], "read")) { assert(fixture.last_read == 524288); }
    if (!strcmp(argv[2], "floor") && strstr(argv[1], "read")) { assert(fixture.last_read == 262144); }
    if (file.writable) { assert(file.cur_chunk == 1048576); }
    return 0;
}

