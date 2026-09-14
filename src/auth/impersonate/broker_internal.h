/*
 * broker_internal.h - private split contract for broker.c and its Phase-38 siblings.
 * Not a public API: include only from src/impersonate/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_BROKER_INTERNAL_H
#define BRIX_BROKER_INTERNAL_H

#include "core/types/tunables.h"
#include "impersonate.h"
#include "impersonate_proto.h"
#include "impersonate_state.h"
#include "core/compat/log_diag.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* macOS lacks sys/fsuid.h - provide stubs for setfsuid/setfsgid */
#if defined(__APPLE__) && defined(__MACH__)
/* macOS doesn't have filesystem UID/GID - use real UID/GID as fallback */
static inline int setfsuid(uid_t uid) {
    /* On macOS, seteuid affects both real and effective for the process */
    return seteuid(uid);
}
static inline int setfsgid(gid_t gid) {
    return setegid(gid);
}
#else
#include <sys/fsuid.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
/* macOS lacks linux/openat2.h - provide compatibility stubs */
#if defined(__APPLE__) && defined(__MACH__)
#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH 0x8
#endif
#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT 0x10
#endif
#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV 0x01
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS 0x02
#endif
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS 0x04
#endif
#ifndef SYS_openat2
#define SYS_openat2 -1
#endif
#else
#include <linux/openat2.h>
#endif

/* macOS lacks linux/capability.h - stub out capability syscalls */
#if defined(__APPLE__) && defined(__MACH__)
#ifndef SYS_capset
#define SYS_capset -1
#endif
#ifndef SYS_capget
#define SYS_capget -1
#endif
#else
#include <linux/capability.h>
#endif
/* macOS lacks sys/prctl.h - provide stubs */
#if defined(__APPLE__) && defined(__MACH__)
/* prctl is Linux-specific; on macOS, skip these operations */
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif
static inline int prctl(int option, ...) {
    (void)option;
    /* On macOS, skip prctl operations - return success for NO_NEW_PRIVS */
    return 0;
}
#else
#include <sys/prctl.h>
#endif
#define IMP_BROKER_MAXCONN  BRIX_IMP_BROKER_MAXCONN
#define IMP_REFUSE_PRIV  (-2)

/* Globals encapsulated in brix_imp_state_t - use accessor functions */
/* Legacy externs removed - use brix_imp_get_*() accessors instead */
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1u << 1)
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1u << 0)
#endif


/* broker.c */
int imp_peer_allowed(int conn_fd);

/* broker_creds.c */
int imp_capset_setuid_setgid(int with_effective, ngx_log_t *log);
int imp_drop_to_service_user(ngx_log_t *log);
int imp_become(const brix_idmap_creds_t *cr);
void imp_restore(void);
const char * imp_rel(const char *path);

/*
 * imp_op_ctx_t — one privileged fs-op invocation, bundled.  WHAT: the full
 * argument set of a broker fs op plus the once-computed root-relative path,
 * so imp_do_op() and every per-op helper take a single explicit parameter.
 * WHY: explicit data flow with no globals while keeping each imp_op_<name>()
 * under the complexity gate.  HOW: the caller (imp_serve_one) fills every
 * field except `rel`, which imp_do_op() derives from req->path.
 */
typedef struct {
    int              rootfd;       /* export-root O_PATH fd (confinement anchor) */
    const imp_req_t *req;          /* decoded request frame */
    imp_rep_t       *rep;          /* reply frame being built */
    int             *out_fd;       /* OPEN: fd handed back via SCM_RIGHTS */
    char            *data_out;     /* trailing reply payload buffer */
    size_t           data_max;     /* capacity of data_out */
    const char      *data_in;      /* SETXATTR inbound value payload */
    size_t           data_in_len;  /* byte count of data_in */
    const char      *rel;          /* imp_rel(req->path): root-relative path */
} imp_op_ctx_t;

/* broker_ops.c */
int imp_openat2(int rootfd, const char *rel, uint32_t flags, uint32_t mode);
int imp_open_parent(int rootfd, const char *rel, char *scratch, const char **base);
void imp_fill_stat(imp_stat_t *o, const struct stat *s);
int imp_xattr_open(int rootfd, const char *rel);
int imp_xattr_name_ok(const char *name);
size_t imp_xattr_filter_user(char *list, size_t len);
int imp_do_rename(int sfd, const char *sbase, int dfd, const char *dbase, int noreplace);
int imp_do_exchange(int sfd, const char *sbase, int dfd, const char *dbase);
int imp_do_op(imp_op_ctx_t *c);

/* broker.c */
int imp_read_full(int fd, void *buf, size_t n);
int imp_send_reply(int conn_fd, const imp_rep_t *rep, int fd, const void *data, size_t data_len);
int imp_serve_one(int conn_fd, int rootfd, ngx_log_t *log);

#endif /* BRIX_BROKER_INTERNAL_H */
