"""Sanitized real inode-registry ownership, independent of mount availability."""
from pathlib import Path
import subprocess

import pytest

from csource_scan import function_body
from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def inode_registry_binary(native_compile):
    """Compile the production registry, not an imitation of its algorithm."""
    root = Path(__file__).resolve().parents[1]
    return native_compile(
        "fuse-inode-registry", (root / "tests/c/fuse_inode_registry_test.c").read_text(),
        sources=["client/apps/fs/xrootdfs_nodes.c"],
        extra=["-DXRDPROTO_NO_NGX", "-fsanitize=address,undefined",
               "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"],
        include_dirs=[root / "client/lib", root / "client/apps/fs"],
    )


@pytest.mark.parametrize("case", ["links", "lifetime", "rename", "limits", "replacement",
                                 "collision"])
def test_inode_registry_contract(inode_registry_binary, case):
    """Hard links, unlinked opens, rename, capacity and replacement stay distinct."""
    result = subprocess.run([str(inode_registry_binary), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope="module")
def inode_request_binary(native_compile):
    """Exercise exact request helpers without manufacturing a libfuse session."""
    root = Path(__file__).resolve().parents[1]
    source = (root / "client/apps/fs/xrootdfs_session.c").read_text()
    definitions = [
        ("xfs_req_uid", "uid_t xfs_req_uid(fuse_req_t req)"),
        ("xfs_req_path", "int xfs_req_path(xfs_session *session, fuse_ino_t ino, char *out)"),
        ("xfs_req_child", "int xfs_req_child(xfs_session *session, fuse_ino_t parent, "
                          "const char *name, char *out)"),
    ]
    driver = (root / "tests/c/fuse_inode_request_test.c").read_text()
    bodies = "\n".join(signature + function_body(source, name)
                       for name, signature in definitions)
    lookup = (root / "client/apps/fs/xrootdfs_lookup.c").read_text()
    bodies += ("\nstatic afh *xfs_ll_caller_handle(fuse_req_t req, xfs_node *node)"
               + function_body(lookup, "xfs_ll_caller_handle"))
    return native_compile(
        "fuse-inode-request", driver + "\n" + bodies,
        sources=["client/apps/fs/xrootdfs_nodes.c"],
        extra=["-DXRDPROTO_NO_NGX", "-fsanitize=address,undefined",
               "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"],
        include_dirs=[root / "client/lib", root / "client/apps/fs"],
    )


@pytest.mark.parametrize("case", ["caller", "paths", "boundaries", "handle-caller"])
def test_inode_request_contract(inode_request_binary, case):
    """Kernel uid zero/non-owner, stale nodes, traversal and long export bases."""
    result = subprocess.run([str(inode_request_binary), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope="module")
def handle_stat_binary(native_compile):
    """Inject only the transport edge; compile the real encoder and decoder."""
    root = Path(__file__).resolve().parents[1]
    aio = (root / "client/lib/core/aio/aio_mfile.c").read_text()
    metadata = (root / "client/lib/protocols/root/ops_meta.c").read_text()
    code = r'''
#include "brix.h"
#include "core/aio/aio.h"
#include "protocols/root/protocol/stat_line.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
struct brix_mfile { brix_aconn *ac; int max_stall_ms; };
static int mfile_stat_once(brix_mfile *, const uint8_t *, brix_statinfo *, brix_status *);
/* WHAT: Inject stat transport results. WHY: Exercise real malformed reply arms.
 * HOW: 1. Check handle-only framing. 2. Return controlled bytes or transport error. */
int brix_aio_call_ex(brix_aconn *ac, const void *header, const void *payload,
                    uint32_t plen, const brix_aio_opts *opts, uint16_t *status,
                    uint8_t **body, uint32_t *length, brix_status *st)
{
    const char *variant = (const char *) ac;
    const ClientRequestHdr *request = header;
    assert(ntohs(request->requestid) == kXR_stat && !payload && plen == 0);
    assert(opts->retry_safe == 0 && opts->max_retries == 0);
    xrdw_stat_req_t fields;
    assert(xrdw_stat_req_unpack(request->body, &fields) == XRDW_OK);
    assert(fields.fhandle[0] == 0x13 && fields.fhandle[3] == 0x37);
    if (strcmp(variant, "transport") == 0) {
        brix_status_set(st, XRDC_ESOCK, EIO, "controlled transport error");
        return -1;
    }
    const char *text = strcmp(variant, "syntax") == 0 ? "bad" : "38 12345 0 1700000000";
    *length = (uint32_t) strlen(text);
    if (strcmp(variant, "empty") == 0) { *length = 0; }
    if (strcmp(variant, "oversize") == 0) { *length = 1024; }
    *body = calloc((size_t) *length + 1, 1);
    assert(*body);
    if (*length && *length < 1024) { memcpy(*body, text, *length); }
    *status = kXR_ok;
    return 0;
}
/* WHAT: Exercise one handle-stat result. WHY: Refusals must not become metadata.
 * HOW: 1. Set the injected peer. 2. Call production body. 3. Check exact outcome. */
int main(int argc, char **argv)
{
    assert(argc == 2);
    brix_mfile file = {.ac = (brix_aconn *) argv[1], .max_stall_ms = 1000};
    const uint8_t handle[4] = {0x13, 0, 0, 0x37};
    brix_statinfo info;
    brix_status status;
    brix_status_clear(&status);
    int rc = mfile_stat_once(&file, handle, &info, &status);
    if (strcmp(argv[1], "success") == 0) {
        assert(rc == 0 && info.id == 38 && info.size == 12345);
    } else if (strcmp(argv[1], "transport") == 0) {
        assert(rc == -1 && status.kxr == XRDC_ESOCK && status.sys_errno == EIO);
    } else {
        assert(rc == -1 && status.kxr == XRDC_EPROTO);
    }
    return 0;
}
'''
    code += ("\nint brix_statinfo_parse(const char *s, brix_statinfo *out)"
             + function_body(metadata, "brix_statinfo_parse"))
    code += ("\nstatic int mfile_stat_once(brix_mfile *mf, const uint8_t fh[4], "
             "brix_statinfo *out, brix_status *st)" + function_body(aio, "mfile_stat_once"))
    return native_compile(
        "fuse-handle-stat", code, sources=["client/lib/core/types/status.c"],
        extra=["-DXRDPROTO_NO_NGX", "-fsanitize=address,undefined",
               "-fno-sanitize-recover=all", str(root / "shared/xrdproto/libxrdproto.a")],
        include_dirs=[root / "client/lib"],
    )


@pytest.mark.parametrize("case", ["success", "empty", "oversize", "syntax", "transport"])
def test_handle_stat_reply_contract(handle_stat_binary, case):
    """The real handle request rejects invalid lengths, syntax and transport errors."""
    result = subprocess.run([str(handle_stat_binary), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope="module")
def fuse_short_read_binary(native_compile):
    """Compile actual FUSE read bodies, injecting only buffer/transport edges."""
    root = Path(__file__).resolve().parents[1]
    source = (root / "client/apps/fs/xrootdfs_io.c").read_text()
    code = r'''
#include "brix.h"
#include "core/aio/aio.h"
#include "fs/iobuf.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
struct brix_mfile {
    ssize_t received;
    int64_t size;
    int read_calls, stat_calls, stat_error;
};
typedef struct { brix_mfile *mf; pthread_mutex_t lock; brix_iobuf io; } afh;
struct fuse_file_info { uint64_t fh; };
static ssize_t afh_check_short_read(afh *, ssize_t, off_t, size_t, brix_status *);
int xfs_read(const char *, char *, size_t, off_t, struct fuse_file_info *);
/* WHAT: Inject the buffered read edge. WHY: Never copy production EOF logic.
 * HOW: 1. Count calls. 2. Fill bounded bytes or preserve a backend error. */
ssize_t brix_iobuf_read(brix_iobuf *io, off_t off, char *out, size_t size, brix_status *status)
{
    (void) off;
    brix_mfile *state = io->be;
    state->read_calls++;
    if (state->received < 0) {
        brix_status_set(status, XRDC_ESOCK, ECONNRESET, "injected read failure");
        return -1;
    }
    assert((size_t) state->received <= size);
    memset(out, 'x', (size_t) state->received);
    return state->received;
}
/* WHAT: Inject metadata for the exact handle. WHY: No pathname authority loan.
 * HOW: 1. Count calls. 2. Preserve metadata failure or return current size. */
int brix_mfile_stat(brix_mfile *file, brix_statinfo *info, brix_status *status)
{
    file->stat_calls++;
    if (file->stat_error) {
        brix_status_set(status, XRDC_EAUTH, EACCES, "injected handle denial");
        return -1;
    }
    memset(info, 0, sizeof(*info));
    info->size = file->size;
    return 0;
}
/* WHAT: Expose the errno produced by the real read. WHY: Preserve refusals.
 * HOW: 1. Require a meaningful error. 2. Return its negative errno. */
int xfs_err(const brix_status *status)
{
    assert(status->sys_errno != 0);
    return -status->sys_errno;
}
/* WHAT: Exercise one actual read contract. WHY: Catch silent kernel zero fill.
 * HOW: 1. Select immutable inputs. 2. Read with an owned mutex/handle.
 *      3. Check exact count/error, metadata calls and untouched buffer tails. */
int main(int argc, char **argv)
{
    assert(argc == 2);
    struct read_case { const char *name; ssize_t received; int64_t size;
        off_t offset; size_t wanted; int result, stats, reads, flags; };
    const struct read_case cases[] = {
        {"full", 8, 8, 0, 8, 8, 0, 1, 0},
        {"eof", 3, 5, 2, 8, 3, 1, 1, 0},
        {"empty", 0, 0, 0, 8, 0, 1, 1, 0},
        {"beyond", 0, 5, 9, 8, 0, 1, 1, 0},
        {"truncated", 0, 1, 2, 8, 0, 1, 1, 0},
        {"zero-request", 0, 8, 0, 0, 0, 0, 1, 0},
        {"premature-empty", 0, 8, 2, 8, -EIO, 1, 1, 0},
        {"premature-partial", 3, 8, 2, 8, -EIO, 1, 1, 0},
        {"invalid-size", 0, -1, 2, 8, -EIO, 1, 1, 0},
        {"large-offset", 0, INT64_MAX, INT64_MAX - 2, 8, -EIO, 1, 1, 0},
        {"stat-denied", 0, 8, 2, 8, -EACCES, 1, 1, 1},
        {"read-error", -1, 8, 2, 8, -ECONNRESET, 0, 1, 0},
        {"invalid-handle", 0, 8, 0, 8, -EBADF, 0, 0, 2},
        {"negative-offset", 0, 8, -1, 8, -EINVAL, 0, 0, 0},
        {"oversized-request", 0, 8, 0, (size_t) INT32_MAX + 1, -EINVAL, 0, 0, 0},
        {"web-handle", 3, 8, 2, 8, 3, 0, 1, 4},
    };
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        const struct read_case *item = &cases[index];
        if (strcmp(argv[1], item->name) != 0) { continue; }
        brix_mfile state = {.received = item->received, .size = item->size,
                            .stat_error = item->flags == 1};
        afh handle = {.mf = item->flags == 4 ? NULL : &state};
        handle.io.be = &state;
        assert(pthread_mutex_init(&handle.lock, NULL) == 0);
        struct fuse_file_info file = {.fh = item->flags == 2 ? 0 : (uint64_t) (uintptr_t) &handle};
        char buffer[9];
        memset(buffer, 's', sizeof(buffer));
        assert(xfs_read(NULL, buffer, item->wanted, item->offset, &file) == item->result);
        assert(state.read_calls == item->reads && state.stat_calls == item->stats);
        assert(buffer[8] == 's');
        assert(pthread_mutex_destroy(&handle.lock) == 0);
        return 0;
    }
    assert(0);
}
'''
    for name, signature in (
            ("afh_check_short_read", "static ssize_t afh_check_short_read(afh *handle, ssize_t received, "
             "off_t offset, size_t requested, brix_status *status)"),
            ("xfs_read", "int xfs_read(const char *path, char *buf, size_t size, off_t offset, "
             "struct fuse_file_info *fi)")):
        code += "\n" + signature + function_body(source, name)
    return native_compile("fuse-short-read", code,
        sources=["client/lib/core/types/status.c"],
        extra=["-DXRDPROTO_NO_NGX", "-fsanitize=address,undefined",
               "-fno-sanitize-recover=all", str(root / "shared/xrdproto/libxrdproto.a"), "-pthread"],
        include_dirs=[root / "client/lib"])


@pytest.mark.parametrize("case", ["full", "eof", "empty", "beyond", "truncated", "zero-request",
    "premature-empty", "premature-partial", "invalid-size", "large-offset", "stat-denied",
    "read-error", "invalid-handle", "negative-offset", "oversized-request", "web-handle"])
def test_fuse_short_read_contract(fuse_short_read_binary, case):
    """Valid EOF works; malformed peers and denied metadata cannot synthesize bytes."""
    result = subprocess.run([str(fuse_short_read_binary), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
