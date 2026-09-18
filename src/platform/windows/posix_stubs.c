/*
 * src/platform/windows/posix_stubs.c - Windows stubs for the POSIX PAL surface
 *
 * WHAT: ENOSYS / ENOTSUP bodies for every platform_api_posix.h entry point.
 * WHY:  The Windows adapter is development-grade; keeping the symbol set
 *       complete lets the module link while each operation reports that it
 *       is unavailable instead of silently doing something else.
 * HOW:  One stub per prototype, no policy.
 */

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include "win32_compat.h"
#include "../platform_api.h"
#include <errno.h>

static int stub_enosys(void) { errno = ENOSYS; return -1; }

int brix_plat_openat2(int rootfd, const char *rel, int flags, mode_t mode,
    uint64_t resolve)
{ (void) rootfd; (void) rel; (void) flags; (void) mode; (void) resolve; return stub_enosys(); }
int brix_plat_openat2_available(void) { return 0; }
int brix_plat_stat_resolve(int rootfd, const char *rel, int nofollow,
    uint64_t resolve, struct stat *st)
{ (void) rootfd; (void) rel; (void) nofollow; (void) resolve; (void) st; return stub_enosys(); }
int brix_plat_renameat2(int sfd, const char *s, int dfd, const char *d,
    unsigned int flags)
{ (void) sfd; (void) s; (void) dfd; (void) d; (void) flags; errno = ENOTSUP; return -1; }
int brix_plat_wait_pid_timeout(pid_t pid, unsigned timeout_ms)
{ (void) pid; (void) timeout_ms; return 0; }
int brix_plat_unlinkat(int dirfd, const char *name, int flags)
{ (void) dirfd; (void) name; (void) flags; return stub_enosys(); }
int brix_plat_fstatat_btime(int dirfd, const char *name, int flags,
    struct stat *st, time_t *btime)
{ (void) dirfd; (void) name; (void) flags; (void) st; *btime = 0; return stub_enosys(); }
int brix_plat_blockdev_size(int fd, uint64_t *bytes)
{ (void) fd; *bytes = 0; return stub_enosys(); }
int brix_plat_fd_seal(int fd) { (void) fd; return 0; }
int brix_plat_fd_reopen_readonly(int fd) { (void) fd; return stub_enosys(); }
int brix_plat_reserve(int fd, off_t size)
{ (void) fd; (void) size; errno = EOPNOTSUPP; return -1; }
ssize_t brix_plat_preadv2(int fd, const struct iovec *iov, int iovcnt,
    off_t off, int flags)
{ (void) fd; (void) iov; (void) iovcnt; (void) off; (void) flags; return stub_enosys(); }
ssize_t brix_plat_pwrite_at(int fd, const void *buf, size_t len, off_t off,
    int append)
{ (void) fd; (void) buf; (void) len; (void) off; (void) append; return stub_enosys(); }
int brix_plat_wakefd_open(int *rfd, int *wfd, int flags)
{ (void) flags; *rfd = -1; *wfd = -1; return stub_enosys(); }
int brix_plat_wakefd_signal(int wfd) { (void) wfd; return stub_enosys(); }
int brix_plat_wakefd_drain(int rfd) { (void) rfd; return stub_enosys(); }
void brix_plat_wakefd_close(int rfd, int wfd) { (void) rfd; (void) wfd; }
int brix_plat_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
    int cloexec)
{ (void) sockfd; (void) addr; (void) addrlen; (void) cloexec; return stub_enosys(); }
int brix_plat_peer_cred(int fd, uid_t *uid, gid_t *gid, pid_t *pid)
{ (void) fd; (void) uid; (void) gid; (void) pid; return stub_enosys(); }
int brix_plat_close_from(int lowfd) { (void) lowfd; return 0; }
int brix_plat_spawn_closefrom(posix_spawn_file_actions_t *fa, posix_spawnattr_t *attr, int lowfd)
{
    (void) attr; (void) fa; (void) lowfd; return ENOSYS; }
int brix_plat_setresuid(uid_t r, uid_t e, uid_t s) { (void) r; (void) e; (void) s; return stub_enosys(); }
int brix_plat_setresgid(gid_t r, gid_t e, gid_t s) { (void) r; (void) e; (void) s; return stub_enosys(); }
int brix_plat_getresuid(uid_t *r, uid_t *e, uid_t *s) { (void) r; (void) e; (void) s; return stub_enosys(); }
int brix_plat_getresgid(gid_t *r, gid_t *e, gid_t *s) { (void) r; (void) e; (void) s; return stub_enosys(); }
int brix_plat_getgrouplist(const char *user, gid_t base, gid_t *groups, int *ngroups)
{ (void) user; (void) base; (void) groups; *ngroups = 0; return stub_enosys(); }
int brix_plat_prctl(int option, unsigned long arg) { (void) option; (void) arg; return 0; }
int brix_plat_capget(struct __user_cap_header_struct *h, struct __user_cap_data_struct *d)
{ (void) h; (void) d; return stub_enosys(); }
int brix_plat_capset(struct __user_cap_header_struct *h, struct __user_cap_data_struct *d)
{ (void) h; (void) d; return stub_enosys(); }
const char *brix_plat_secure_getenv(const char *name) { return getenv(name); }
char *brix_plat_crypt(const char *key, const char *setting)
{ (void) key; (void) setting; errno = ENOSYS; return NULL; }

#endif /* BRIX_PLATFORM_WINDOWS */
