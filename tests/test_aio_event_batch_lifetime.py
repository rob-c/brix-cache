"""Readiness pointers must be consumed before queued CLOSE commands free them."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_platform_linux_native import native_compile
from lib_py.nginx_build import selected_native_dependency


@pytest.fixture(scope="module")
def batch_driver(native_compile):
    """Compile the real loop and command dispatcher, replacing only I/O edges."""
    root = Path(__file__).resolve().parents[1]
    includes, libraries = (selected_native_dependency('epoll-shim')
                           if sys.platform.startswith('freebsd') else ([], []))
    return native_compile("aio-event-batch", _DRIVER,
                          ["client/lib/core/aio/aio.c"],
                          ["-DXRDPROTO_NO_NGX",
                           "-ffunction-sections", "-fdata-sections",
                           "-Wl,--gc-sections", "-pthread", *includes, *libraries],
                          include_dirs=[root / "client/lib"])


@pytest.mark.parametrize("case", ["active", "close", "duplicate"])
def test_ready_batch_keeps_connection_alive_until_commands_run(batch_driver, case):
    """Normal I/O, concurrent close and duplicate readiness retain valid storage."""
    result = subprocess.run([str(batch_driver), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


_DRIVER = r'''
#include "core/aio/aio_internal.h"
#include <assert.h>

typedef struct {
    brix_loop loop;
    brix_aconn connection;
    int destroyed;
    int delivered;
    int event_count;
} batch_fixture;

/* WHAT: Supply a ready batch while CLOSE is already queued.
 * WHY: This is the interleaving captured in the Ubuntu24 crash core.
 * HOW: 1. Tag every event with the same live connection. 2. Return its count. */
int io_engine_wait(brix_loop *loop, struct epoll_event *events, int max, int timeout)
{
    batch_fixture *fixture = (batch_fixture *) loop;
    (void) timeout;
    assert(fixture->event_count <= max);
    for (int index = 0; index < fixture->event_count; ++index) {
        events[index].data.ptr = &fixture->connection;
        events[index].events = EPOLLIN;
    }
    return fixture->event_count;
}

/* WHAT: Verify dispatch never observes logically destroyed connection storage.
 * WHY: Keeping storage mapped makes the old order fail deterministically.
 * HOW: 1. Check the lifetime boundary. 2. Count the delivered event. */
void aconn_handle_io(brix_aconn *connection, uint32_t events)
{
    batch_fixture *fixture = (batch_fixture *) connection->loop;
    assert(fixture->destroyed == 0);
    assert(events == EPOLLIN);
    ++fixture->delivered;
    if (fixture->delivered == fixture->event_count) {
        cmd *stop = calloc(1, sizeof(*stop));
        assert(stop != NULL);
        stop->type = CMD_STOP;
        if (fixture->loop.cq_tail != NULL) {
            fixture->loop.cq_tail->next = stop;
        } else {
            fixture->loop.cq_head = stop;
        }
        fixture->loop.cq_tail = stop;
    }
}

/* WHAT: Record destruction and unlink the fixture without releasing its shell.
 * WHY: The real command dispatcher must own the lifetime transition.
 * HOW: 1. Require one destruction. 2. Unlink the connection. */
void aconn_destroy(brix_aconn *connection)
{
    batch_fixture *fixture = (batch_fixture *) connection->loop;
    assert(fixture->destroyed++ == 0);
    fixture->loop.aconns = NULL;
}

/* WHAT: Reject an unexpected ADD edge.
 * WHY: This fixture starts with an attached connection.
 * HOW: 1. Abort if an ADD command is dispatched. */
int io_engine_arm(brix_loop *loop, brix_aconn *connection, int want)
{
    (void) loop; (void) connection; (void) want;
    abort();
}

/* WHAT: Reject an unexpected SUBMIT edge.
 * WHY: The regression concerns already-collected readiness and CLOSE.
 * HOW: 1. Abort if the fixture dispatches a submission. */
void aconn_submit_cmd(brix_aconn *connection, cmd *command)
{
    (void) connection; (void) command;
    abort();
}

/* WHAT: Leave reconnect state unchanged.
 * WHY: No transport operation runs in this loop-ordering unit.
 * HOW: 1. Ignore the live connection. */
void aconn_poll_reconnect(brix_aconn *connection) { (void) connection; }

/* WHAT: Leave heartbeat state unchanged.
 * WHY: No timer activity is required to reproduce the close race.
 * HOW: 1. Ignore the live connection. */
void aconn_maybe_ping(brix_aconn *connection) { (void) connection; }

/* WHAT: Provide a bounded next wait interval.
 * WHY: Keep timer policy outside this lifetime regression.
 * HOW: 1. Return one millisecond. */
int loop_process_timeouts(brix_loop *loop) { (void) loop; return 1; }

/* WHAT: Execute one native ready/control batch.
 * WHY: Exercise success, a pending close and repeated pointers without timing.
 * HOW: 1. Queue CLOSE/STOP. 2. Run the real loop. 3. Check ordering and cleanup. */
int main(int argc, char **argv)
{
    assert(argc == 2);
    batch_fixture fixture = {0};
    fixture.connection.loop = &fixture.loop;
    fixture.loop.aconns = &fixture.connection;
    fixture.event_count = strcmp(argv[1], "duplicate") == 0 ? 2 : 1;
    assert(pthread_mutex_init(&fixture.loop.cq_lock, NULL) == 0);
    if (strcmp(argv[1], "active") != 0) {
        assert(strcmp(argv[1], "close") == 0 || strcmp(argv[1], "duplicate") == 0);
        cmd *close = calloc(1, sizeof(*close));
        assert(close != NULL);
        close->type = CMD_CLOSE_ACONN;
        close->ac = &fixture.connection;
        fixture.loop.cq_head = fixture.loop.cq_tail = close;
    }
    loop_thread(&fixture.loop);
    assert(fixture.delivered == fixture.event_count);
    assert(fixture.destroyed == 1);
    assert(fixture.loop.cq_head == NULL && fixture.loop.cq_tail == NULL);
    assert(pthread_mutex_destroy(&fixture.loop.cq_lock) == 0);
    return 0;
}
'''
