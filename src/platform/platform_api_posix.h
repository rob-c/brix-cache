/*
 * src/platform/platform_api_posix.h - the POSIX surface the PAL guarantees on every host
 *
 * WHAT: The Linux/glibc spellings the tree is written against (byte-order
 *       names, Linux-shaped xattr calls, O_PATH, SOCK_CLOEXEC, RESOLVE_*,
 *       PR_*, CAP_*, ...) plus brix_plat_* entry points for the operations
 *       whose Darwin form is not a one-line alias (openat2, renameat2, wake
 *       descriptors, peer credentials, birth time, block-device size, ...).
 *       Reached ONLY through platform/platform_api.h.
 * WHY:  Phase 119 left ~80 `#if defined(__APPLE__)` sites, each a private port
 *       of one call that no PAL fixture exercised. tools/ci/check_platform_leak.py
 *       now rejects any OS-detection macro or OS-private header outside the
 *       PAL owners (src/platform/, client/lib/platform/, shared/cvmfs/platform/),
 *       so every such branch lives here or in a host adapter beneath it.
 * HOW:  This header is host-free: the names are guaranteed by the host's
 *       host_posix.h (linux/: the real glibc headers; darwin/: adapters and
 *       constants, e.g. Linux-shaped xattr calls with ENOATTR -> ENODATA;
 *       windows/: ssize_t and the openat2 ABI), pulled by one computed
 *       #include below. Where the semantics differ (not just the spelling)
 *       the tree calls a brix_plat_* function whose body lives under
 *       src/platform/<host>/; the Linux body is the plain syscall.
 */

#pragma once
#ifndef BRIX_PLATFORM_API_POSIX_H
#define BRIX_PLATFORM_API_POSIX_H

#include "platform.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <spawn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>

/* The host's part of this surface: headers, name aliases, constants. */
#include BRIX_PLAT_HOST_HEADER(host_posix.h)

/* ==========================================================================
 * PATHS - confinement primitives beneath brix_open_beneath / the VFS.
 * ========================================================================== */

/**
 * openat2(2): open `rel` beneath rootfd under `resolve` (RESOLVE_* flags).
 * Linux issues the syscall (ENOSYS on a pre-5.6 kernel); Darwin walks the
 * path component by component on an fd stack and gives the same verdicts
 * (EXDEV / ELOOP). O_CLOEXEC is always added; `mode` applies with O_CREAT.
 * @return fd, or -1 with errno
 */
int brix_plat_openat2(int rootfd, const char *rel, int flags, mode_t mode,
    uint64_t resolve);

/** 1 when brix_plat_openat2 works on this host at run time, else 0. */
int brix_plat_openat2_available(void);

/**
 * Confined stat: the metadata of `rel` beneath rootfd under `resolve`,
 * without handing back a descriptor (Linux: O_PATH + fstat; Darwin: the walk
 * ends in fstatat). `nofollow` reports a trailing symlink as itself.
 * @return 0, or -1 with errno
 */
int brix_plat_stat_resolve(int rootfd, const char *rel, int nofollow,
    uint64_t resolve, struct stat *st);

#define BRIX_RENAME_NOREPLACE  1  /**< fail with EEXIST if the target exists */
#define BRIX_RENAME_EXCHANGE   2  /**< atomically swap the two names */

/**
 * renameat2(2) with one BRIX_RENAME_* flag. Linux: the syscall; Darwin:
 * renameatx_np(RENAME_EXCL / RENAME_SWAP). A kernel or filesystem without
 * the flag answers ENOTSUP so the caller can choose its degraded path.
 * @return 0, or -1 with errno
 */
int brix_plat_renameat2(int sfd, const char *sbase, int dfd, const char *dbase,
    unsigned int flags);

/**
 * unlinkat(2) with Linux errno semantics: unlinking a directory without
 * AT_REMOVEDIR answers EISDIR on every host (Darwin's kernel says EPERM,
 * which callers would misreport as an authorization failure).
 * @return 0, or -1 with errno
 */
int brix_plat_unlinkat(int dirfd, const char *name, int flags);

/**
 * fstatat(2) plus the birth time (Linux statx STATX_BTIME; Darwin
 * st_birthtimespec). *btime is 0 when the filesystem does not record one.
 * @return 0, or -1 with errno
 */
int brix_plat_fstatat_btime(int dirfd, const char *name, int flags,
    struct stat *st, time_t *btime);

/* ==========================================================================
 * STORAGE - fd-level operations whose Linux form is not portable.
 * ========================================================================== */

/** Capacity of a block device (BLKGETSIZE64 / DKIOCGETBLOCK*). */
int brix_plat_blockdev_size(int fd, uint64_t *bytes);

/** Seal an anonymous fd against growth, shrink and writes (F_ADD_SEALS);
 *  a no-op on a host without sealing. */
int brix_plat_fd_seal(int fd);

/**
 * Reserve `size` bytes without changing st_size (fallocate KEEP_SIZE),
 * releasing the beyond-EOF part of a refused range on ENOSPC/EDQUOT.
 * EOPNOTSUPP where the host cannot reserve.
 * @return 0, or -1 with errno
 */
int brix_plat_reserve(int fd, off_t size);

/** preadv2(2); a host without it uses preadv and ignores `flags`. */
ssize_t brix_plat_preadv2(int fd, const struct iovec *iov, int iovcnt,
    off_t off, int flags);

/**
 * pwrite that honours an O_APPEND handle: Linux pwrite(2) already lands at
 * EOF on such an fd, BSD hosts honour the offset, so with `append` set the
 * write goes through write(2) there.
 */
ssize_t brix_plat_pwrite_at(int fd, const void *buf, size_t len, off_t off,
    int append);

/* ==========================================================================
 * DESCRIPTORS & EVENTS
 * ========================================================================== */

/**
 * A wake descriptor pair: Linux eventfd (rfd == wfd), Darwin a pipe.
 * `flags` are BRIX_EVENTFD_CLOEXEC | BRIX_EVENTFD_NONBLOCK.
 * @return 0, or -1 with errno
 */
int brix_plat_wakefd_open(int *rfd, int *wfd, int flags);

/** Post one wake-up (an 8-byte counter increment). */
int brix_plat_wakefd_signal(int wfd);

/** Consume every pending wake-up; 0 when drained, -1 with errno otherwise. */
int brix_plat_wakefd_drain(int rfd);

/** Close both ends (once when they are the same fd). */
void brix_plat_wakefd_close(int rfd, int wfd);

/** accept4(2) with SOCK_CLOEXEC when `cloexec`; Darwin: accept + fcntl. */
int brix_plat_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
    int cloexec);

/**
 * The peer's credentials on a connected AF_UNIX socket (SO_PEERCRED /
 * LOCAL_PEERCRED + LOCAL_PEERPID). Any out-pointer may be NULL.
 * @return 0, or -1 with errno
 */
int brix_plat_peer_cred(int fd, uid_t *uid, gid_t *gid, pid_t *pid);

/** Close every descriptor >= lowfd (close_range, /proc/self/fd, or a loop). */
int brix_plat_close_from(int lowfd);

/**
 * A new O_RDONLY|O_CLOEXEC descriptor on the same file as `fd` (which may be
 * write-only and, on Linux, unlinked), positioned at offset 0.
 * Linux re-opens /proc/self/fd/<fd>; Darwin has no such alias for a write-only
 * descriptor (/dev/fd refuses a mode the original lacks), so it re-opens the
 * F_GETPATH name and checks the inode still matches, falling back to dup(2)
 * when the original is itself readable. Fails EACCES when neither works.
 * @return the descriptor, or -1 with errno
 */
int brix_plat_fd_reopen_readonly(int fd);

/** posix_spawn file action closing every descriptor >= lowfd in the child. */
/* Linux queues one closefrom file action; Darwin instead sets
 * POSIX_SPAWN_CLOEXEC_DEFAULT on `attr` (every descriptor not dup2()'d by a
 * file action is closed in the child), because a queued close of one of the
 * process's guarded descriptors makes posix_spawn fail with EBADF there.
 * `attr` must be initialised and passed to posix_spawn(). */
int brix_plat_spawn_closefrom(posix_spawn_file_actions_t *fa,
                              posix_spawnattr_t *attr, int lowfd);

/* ==========================================================================
 * IDENTITY & PRIVILEGE
 * ========================================================================== */

int brix_plat_setresuid(uid_t ruid, uid_t euid, uid_t suid);
int brix_plat_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
int brix_plat_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
int brix_plat_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);

/** getgrouplist(3) with gid_t groups on every host (Darwin takes int *). */
int brix_plat_getgrouplist(const char *user, gid_t base, gid_t *groups,
    int *ngroups);

/**
 * prctl(2) with one argument. Darwin has no prctl: the call succeeds and
 * does nothing, exactly the pre-PAL behaviour; the Darwin security adapter
 * (src/platform/darwin/README.md) records that no-new-privs is not enforced.
 */
int brix_plat_prctl(int option, unsigned long arg);

/** capget(2) / capset(2); ENOSYS on a host without capabilities. */
int brix_plat_capget(struct __user_cap_header_struct *hdr,
    struct __user_cap_data_struct *data);
int brix_plat_capset(struct __user_cap_header_struct *hdr,
    struct __user_cap_data_struct *data);

/** secure_getenv(3): NULL in a set-user-ID image (Darwin: issetugid(2)). */
const char *brix_plat_secure_getenv(const char *name);

/** crypt(3) from the host libc (<crypt.h> on glibc, <unistd.h> on Darwin). */
char *brix_plat_crypt(const char *key, const char *setting);

/* ==========================================================================
 * PROCESS & HOST IDENTITY
 * ========================================================================== */

/**
 * The running executable's absolute, symlink-free path (Linux: the
 * /proc/self/exe link; Darwin: _NSGetExecutablePath + realpath).
 * @return 0, or -1 with errno (ENAMETOOLONG when `cap` is too small)
 */
int brix_plat_self_exe(char *buf, size_t cap);

/**
 * The kernel's per-boot identifier, NUL-terminated with no trailing newline
 * (Linux: /proc/sys/kernel/random/boot_id; Darwin: kern.bootsessionuuid).
 * @return 0, or -1 with errno
 */
/**
 * Wait up to `timeout_ms` for `pid` to exit, WITHOUT reaping it.
 * Linux polls a pidfd; Darwin arms kqueue's EVFILT_PROC/NOTE_EXIT.  A host
 * that can do neither answers 0 ("exited"), which degrades to the unbounded
 * wait the caller would otherwise have done.
 * @return 1 when the deadline expired first, 0 when the process exited
 */
int brix_plat_wait_pid_timeout(pid_t pid, unsigned timeout_ms);

int brix_plat_boot_id(char *buf, size_t cap);

#endif /* BRIX_PLATFORM_API_POSIX_H */
