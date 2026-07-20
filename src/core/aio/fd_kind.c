/*
 * fd_kind.c — classify what a file descriptor refers to RIGHT NOW.
 *
 * WHAT: brix_fd_kind(fd) returns a stable label ("regular"/"socket"/"fifo"/
 * "dir"/"other"), or "stale" when fstat fails (the fd is closed or already
 * recycled away).
 * WHY: the fast-lane watch item — rare kXR_IOError reads whose strerror is
 * ESPIPE ("Illegal seek") or EBADF — pattern-matches an fd closed and recycled
 * under an in-flight read. Probing the fd at failure time turns the next
 * occurrence into a diagnosis instead of another mystery.
 * HOW: pure fstat classification; no data I/O, safe on any fd, no nginx
 * dependencies (this file is deliberately freestanding so the C regression
 * harness links it directly).
 */

#include <sys/stat.h>

const char *
brix_fd_kind(int fd)
{
    struct stat st;

    if (fstat(fd, &st) != 0) {  /* vfs-seam-allow: error-path fd forensics, no data I/O */
        return "stale";
    }
    if (S_ISREG(st.st_mode)) {
        return "regular";
    }
    if (S_ISSOCK(st.st_mode)) {
        return "socket";
    }
    if (S_ISFIFO(st.st_mode)) {
        return "fifo";
    }
    if (S_ISDIR(st.st_mode)) {
        return "dir";
    }
    return "other";
}
