/* Real disk-ring API, with allocation/submit failures restricted to this process. */
#include "core/aio/uring.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* WHAT: Consume a single explicitly armed fault.
 * WHY: Later cleanup and coverage output must retain normal allocation semantics.
 * HOW: Read and clear one process-local environment setting on an exact match. */
static int fault(const char *name)
{
    const char *mode = getenv("BRIX_DISK_RING_FAULT");
    if (mode == NULL || strcmp(mode, name)) { return 0; }
    assert(unsetenv("BRIX_DISK_RING_FAULT") == 0); errno = ENOMEM;
    return 1;
}

void *__real_calloc(size_t, size_t);
void *__real_malloc(size_t);
int __real_posix_memalign(void **, size_t, size_t);
int __real_io_uring_queue_init(unsigned, struct io_uring *, unsigned);
int __real_io_uring_submit(struct io_uring *);

/* WHAT: Fail the ring object or slot-array allocation.
 * WHY: Both ownership stages must be independently cleanable.
 * HOW: Distinguish the one-object allocation from the multi-slot array. */
void *__wrap_calloc(size_t count, size_t size)
{
    if (fault(count == 1 ? "calloc" : "slots")) { return NULL; }
    return __real_calloc(count, size);
}

/* WHAT: Fail one slab allocation. WHY: Buffered storage must handle OOM.
 * HOW: Consume the selected fault before calling the real allocator. */
void *__wrap_malloc(size_t size)
{
    return fault("malloc") ? NULL : __real_malloc(size);
}

/* WHAT: Fail aligned storage. WHY: Direct-I/O setup must restore the caller's fd.
 * HOW: Return the allocator's documented error without publishing a pointer. */
int __wrap_posix_memalign(void **out, size_t alignment, size_t size)
{
    return fault("aligned") ? ENOMEM : __real_posix_memalign(out, alignment, size);
}

/* WHAT: Refuse ring setup after resources were allocated.
 * WHY: A kernel setup failure must unwind the complete allocation set.
 * HOW: Fail only the armed create call, leaving runtime probing real. */
int __wrap_io_uring_queue_init(unsigned depth, struct io_uring *ring, unsigned flags)
{
    return fault("queue") ? -ENOMEM : __real_io_uring_queue_init(depth, ring, flags);
}

/* WHAT: Refuse one submission. WHY: Unsubmitted buffers must never stay in flight.
 * HOW: Inject a negative liburing return before the real syscall boundary. */
int __wrap_io_uring_submit(struct io_uring *ring)
{
    return fault("submit") ? -ENOMEM : __real_io_uring_submit(ring);
}

/* WHAT: Check sequential writes, random read resets, EOF and undersized output.
 * WHY: Readahead ordering and write-behind ownership must preserve every byte.
 * HOW: Write more operations than the ring depth, then compare several read slices. */
static void roundtrip(int fd, const char *mode)
{
    brix_status status = {0};
    int flags = fcntl(fd, F_GETFL);
    int direct = !strcmp(mode, "direct");
    unsigned depth = !strcmp(mode, "depth-low") ? 0 : 2;
    if (!strcmp(mode, "depth-high")) { depth = 300; }
    brix_disk_ring *ring = brix_disk_ring_create(fd, depth, 4096, direct, &status);
    assert(ring != NULL);
    assert(brix_disk_ring_bufsz(ring) == 4096);
    unsigned char bytes[16389], readback[4097];
    for (size_t i = 0; i < sizeof(bytes); ++i) { bytes[i] = (i * 37 + 11) % 251; }
    for (size_t offset = 0; offset < sizeof(bytes); offset += 4096) {
        size_t size = sizeof(bytes) - offset;
        if (size > 4096) { size = 4096; }
        assert(brix_disk_ring_pwrite(ring, offset, bytes + offset, size, &status) == 0);
    }
    assert(brix_disk_ring_flush(ring, &status) == 0);
    brix_disk_ring_destroy(ring);
    assert(fcntl(fd, F_GETFL) == flags);
    ring = brix_disk_ring_create(fd, 2, 4096, 0, &status);
    assert(ring != NULL);
    const off_t offsets[] = {0, 4096, 3, 16000, 16389, 0};
    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
        size_t size = sizeof(bytes) - offsets[i];
        if (size > 4096) { size = 4096; }
        assert(brix_disk_ring_pread(ring, offsets[i], readback, 4096, &status)
               == (ssize_t)size);
        assert(!memcmp(readback, bytes + offsets[i], size));
    }
    assert(brix_disk_ring_pread(ring, 5, readback, 3, &status) == 3);
    assert(!memcmp(readback, bytes + 5, 3));
    assert(brix_disk_ring_pread(ring, 8, readback, 3, &status) == 3);
    assert(!memcmp(readback, bytes + 8, 3));
    brix_disk_ring_destroy(ring);
}

/* WHAT: Surface kernel read/write errors and retain sticky failed-write status.
 * WHY: Submission success cannot hide a failed completion or permit later success.
 * HOW: Bind a ring to an invalid fd and force completion via read or flush. */
static void io_error(const char *mode)
{
    brix_status status = {0};
    brix_disk_ring *ring = brix_disk_ring_create(-1, 2, 4096, 0, &status);
    assert(ring != NULL);
    unsigned char bytes[4] = {0};
    if (!strcmp(mode, "read-error")) {
        assert(brix_disk_ring_pread(ring, 0, bytes, sizeof(bytes), &status) == -1);
    } else {
        assert(brix_disk_ring_pwrite(ring, 0, bytes, sizeof(bytes), &status) == 0);
        assert(brix_disk_ring_flush(ring, &status) == -1);
        assert(brix_disk_ring_pwrite(ring, 0, bytes, sizeof(bytes), &status) == -1);
    }
    assert(status.sys_errno == EBADF);
    brix_disk_ring_destroy(ring);
}

/* WHAT: Exercise setup unwind and submission failure without hidden fallback.
 * WHY: Failed operations must return an error while leaving the owned fd usable.
 * HOW: Arm one failure after runtime probing, then inspect status and fd flags. */
static void allocation_error(int fd, const char *mode)
{
    brix_status status = {0};
    int flags = fcntl(fd, F_GETFL);
    assert(setenv("BRIX_DISK_RING_FAULT", mode, 1) == 0);
    brix_disk_ring *ring = brix_disk_ring_create(fd, 2, 4096,
                                                !strcmp(mode, "aligned"), &status);
    if (!strcmp(mode, "submit")) {
        assert(ring != NULL);
        unsigned char byte = 0;
        assert(brix_disk_ring_pwrite(ring, 0, &byte, 1, &status) == -1);
        brix_disk_ring_destroy(ring);
    } else { assert(ring == NULL); }
    assert(status.kxr != 0 && fcntl(fd, F_GETFL) == flags);
    assert(getenv("BRIX_DISK_RING_FAULT") == NULL);
}

/* WHAT: Execute one disk-ring contract against the real kernel.
 * WHY: Unsupported hosts must report an explicit skip rather than fake I/O.
 * HOW: Probe before fault injection; open a private file and dispatch the case. */
int main(int argc, char **argv)
{
    assert(argc == 3);
    if (!brix_uring_available()) { return 77; }
    assert(brix_uring_available());
    brix_disk_ring_destroy(NULL); assert(brix_disk_ring_bufsz(NULL) == 0);
    int fd = open(argv[2], O_RDWR | O_CREAT | O_EXCL, 0600); assert(fd >= 0);
    if (strstr(argv[1], "error")) { io_error(argv[1]); }
    else if (!strncmp(argv[1], "depth-", 6) || !strcmp(argv[1], "roundtrip")
             || !strcmp(argv[1], "direct") || !strcmp(argv[1], "short-read")) {
        roundtrip(fd, argv[1]);
    } else { allocation_error(fd, argv[1]); }
    close(fd);
    return 0;
}
