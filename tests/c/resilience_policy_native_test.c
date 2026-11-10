/* Retry classes govern replay, independent of the operation's transport. */
#include "brix.h"
#include "posix/fuse_ops.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    brix_conn connection;
    const char *mode;
    unsigned operations, reconnects, checkins;
    int benign_errno;
} policy_fixture;

uint64_t
__wrap_brix_mono_ns(void)
{
    char *clock = getenv("BRIX_POLICY_CLOCK");
    unsigned long tick = strtoul(clock, NULL, 10) + 1;
    snprintf(clock, 32, "%031lu", tick);
    return (uint64_t) tick * 1000000;
}

void __wrap_brix_backoff_sleep_fast(unsigned attempt) { assert(attempt < 20); }

static int
outcome(policy_fixture *f, brix_status *st)
{
    f->operations++;
    if (strcmp(f->mode, "success") == 0) { brix_status_clear(st); return 0; }
    if ((strcmp(f->mode, "retry") == 0 || strcmp(f->mode, "reconnect-retry") == 0)
        && f->operations == 2) { brix_status_clear(st); return 0; }
    if ((strncmp(f->mode, "normalize", 9) == 0 && f->operations > 1)
        || strcmp(f->mode, "first-benign") == 0) {
        int code = strcmp(f->mode, "normalize-missing") == 0 ? kXR_NotFound : kXR_ItExists;
        brix_status_set(st, code, 0, "already applied"); return -1;
    }
    if (strcmp(f->mode, "auth") == 0
        || (strcmp(f->mode, "late-auth") == 0 && f->operations > 1)) {
        brix_status_set(st, kXR_NotAuthorized, 0, "auth refused"); return -1;
    }
    brix_status_set(st, XRDC_ESOCK,
                   strcmp(f->mode, "refused") == 0 ? ECONNREFUSED : ECONNRESET,
                   "scripted transport failure");
    return -1;
}

int
__wrap_brix_connect(brix_conn *c, const brix_url *u, const brix_opts *o, brix_status *st)
{
    (void) o;
    assert(strcmp(u->host, "origin.test") == 0 && u->port == 1094);
    return outcome((policy_fixture *) c, st);
}

int
__wrap_brix_reconnect(brix_conn *c, const char *host, int port, brix_status *st)
{
    policy_fixture *f = (policy_fixture *) c;
    assert(strcmp(host, "origin.test") == 0 && port == 1094);
    f->reconnects++;
    if (strcmp(f->mode, "reconnect-auth") == 0) {
        brix_status_set(st, kXR_NotAuthorized, 0, "reconnect denied"); return -1;
    }
    if (strcmp(f->mode, "reconnect-retry") == 0 && f->reconnects == 1) {
        brix_status_set(st, XRDC_ESOCK, ECONNRESET, "reconnect lost"); return -1;
    }
    return 0;
}

int
__wrap_brix_roundtrip(brix_conn *c, void *header, const brix_payload *payload,
                     brix_resp_out *out, brix_status *st)
{
    (void) out;
    assert(((unsigned char *) header)[0] == 0x35);
    assert(payload->len == 7 && memcmp(payload->data, "payload", 7) == 0);
    return outcome((policy_fixture *) c, st);
}

static int
stateless(brix_conn *c, void *argument, brix_status *st)
{
    assert(strcmp(argument, "payload") == 0);
    return outcome((policy_fixture *) c, st);
}

brix_conn *
__wrap_brix_pool_checkout(brix_pool *pool, brix_status *st)
{
    (void) st;
    policy_fixture *f = (policy_fixture *) pool;
    f->reconnects++;
    return &f->connection;
}

void
__wrap_brix_pool_checkin(brix_pool *pool, brix_conn *c, int healthy)
{
    policy_fixture *f = (policy_fixture *) pool;
    assert(c == &f->connection);
    assert(healthy == (strcmp(f->mode, "success") == 0 || f->operations > 1
                       || strcmp(f->mode, "first-benign") == 0
                       || strcmp(f->mode, "auth") == 0));
    f->checkins++;
}

static int
open_file(brix_conn *c, const char *path, brix_file *file, brix_status *st)
{
    assert(strcmp(path, "/data") == 0);
    int rc = outcome((policy_fixture *) c, st);
    if (rc == 0) { file->fhandle[0] = 0x23; }
    return rc;
}

int __wrap_brix_file_open_read(brix_conn *c, const char *path, brix_file *f, brix_status *st) {
    return open_file(c, path, f, st);
}
int __wrap_brix_file_open_opaque(brix_conn *c, const char *path, const char *opaque,
    int write, int force, int posc, brix_file *f, brix_status *st) {
    assert(strcmp(opaque, "key=value") == 0 && !write && !force && !posc);
    return open_file(c, path, f, st);
}
int __wrap_brix_file_open_write(brix_conn *c, const char *path, int force, int posc,
    brix_file *f, brix_status *st) {
    assert(force == 1 && posc == 1);
    return open_file(c, path, f, st);
}

static int
file_operation(policy_fixture *f, const char *name, brix_status *st)
{
    brix_rfile file;
    int rc;
    if (strcmp(name, "write") == 0) {
        rc = brix_rfile_open_write(&f->connection, "/data", 1, 1, 1, 0, &file, st);
        assert(file.writable && file.posc);
    } else {
        const char *opaque = strcmp(name, "opaque") == 0 ? "key=value" : NULL;
        rc = brix_rfile_open_read(&f->connection, "/data", opaque, 1, 0, &file, st);
        assert(!file.writable);
    }
    assert(file.pgrw && file.cur_chunk == 4 * 1024 * 1024);
    if (rc == 0) { assert(file.f.fhandle[0] == 0x23); }
    return rc;
}

static int
operation(policy_fixture *f, const char *name, brix_op_class kind, brix_status *st)
{
    brix_url url = {0};
    unsigned char header[24] = {0x35};
    uint16_t status = 0;
    uint8_t *body = NULL;
    uint32_t length = 0;
    if (strcmp(name, "fuse") == 0) {
        int rc = brix_fuse_run((brix_pool *) f, 1, 0, f->benign_errno,
                               stateless, "payload", st);
        assert(f->checkins == f->operations && f->reconnects == f->checkins);
        return rc;
    }
    if (strcmp(name, "connect") == 0) {
        strcpy(url.host, "origin.test"); url.port = 1094;
        return brix_connect_resilient(&f->connection, &url, &f->connection.opts, st);
    }
    if (strcmp(name, "roundtrip") == 0) {
        return brix_roundtrip_resilient(&f->connection, header, "payload", 7,
                                       kind, f->benign_errno, &status, &body, &length, st);
    }
    if (strcmp(name, "operation") == 0) {
        return brix_with_resilience(&f->connection, brix_resilient_window_ms(&f->connection),
                                   kind, f->benign_errno, stateless, "payload", st);
    }
    return file_operation(f, name, st);
}

int
main(int argc, char **argv)
{
    policy_fixture f = {0};
    brix_status st;
    int rc;
    assert(argc == 8);
    f.mode = argv[2];
    f.benign_errno = EEXIST;
    if (strcmp(f.mode, "normalize-missing") == 0) { f.benign_errno = ENOENT; }
    if (strcmp(f.mode, "normalize-zero") == 0) { f.benign_errno = 0; }
    if (strcmp(f.mode, "normalize-negative") == 0) { f.benign_errno = -EEXIST; }
    if (strcmp(f.mode, "normalize-mismatch") == 0) { f.benign_errno = ENOENT; }
    strcpy(f.connection.host, "origin.test"); f.connection.port = 1094;
    if (atoi(argv[7])) {
        strcpy(f.connection.home_host, "origin.test"); f.connection.home_port = 1094;
        strcpy(f.connection.host, "redirected.test"); f.connection.port = 9999;
    }
    assert(setenv("BRIX_POLICY_CLOCK", "0000000000000000000000000000000", 1) == 0);
    assert(setenv("XRDC_MAX_STALL_MS", argv[4], 1) == 0);
    brix_status_clear(&st);
    rc = operation(&f, argv[1], (brix_op_class) atoi(argv[3]), &st);
    printf("RESULT %d status=%d calls=%u reconnects=%u\n", rc, st.kxr, f.operations, f.reconnects);
    fflush(stdout);
    assert(rc == atoi(argv[5]));
    assert(f.operations == (unsigned) atoi(argv[6]));
    if (strcmp(f.mode, "normalize") == 0 && rc == 0) { assert(st.kxr == 0); }
    return 0;
}
