#ifndef XROOTD_IMPERSONATE_PROTO_H
#define XROOTD_IMPERSONATE_PROTO_H

/*
 * impersonate_proto.h — worker <-> broker wire protocol (phase 40).
 *
 * WHAT: The fixed-size request/reply frames the unprivileged worker exchanges
 *   with the privileged root broker over an AF_UNIX socket.  The worker sends a
 *   request naming the authenticated principal + a root-relative path + the op;
 *   the broker maps the principal to UNIX creds, performs the op under those
 *   creds with RESOLVE_BENEATH confinement, and replies — passing an open file
 *   descriptor back via SCM_RIGHTS for OPEN.
 *
 * WHY: A fixed-size frame (like the FRM stage-agent protocol) keeps framing
 *   trivial and bounded — no parser, no partial-frame state machine beyond a
 *   read-full loop.  Paths are root-relative (the broker holds the authoritative
 *   rootfd), so the worker can never name an absolute path or escape the export.
 *
 * HOW: One frame type each way.  `imp_req_t` carries op + flags + mode + length
 *   + bounded principal/path/path2 buffers.  `imp_rep_t` carries a status
 *   (0 = ok, negative = -errno, positive = an IMP_STATUS_*), reply flags, and a
 *   portable stat subset.  Both are POD; the broker and the worker are the same
 *   architecture (a local socket), so no byte-swapping.
 */

#include <stdint.h>

#define IMP_PROTO_VERSION   1

/* Bounds (paths are root-relative; principal is a DN/sub/sss-user). */
#define IMP_PRINC_MAX       512
#define IMP_PATH_MAX        4096

/* Request operations. */
enum {
    IMP_OP_PING     = 0,   /* liveness / version handshake */
    IMP_OP_OPEN     = 1,   /* openat2 -> returns an fd via SCM_RIGHTS */
    IMP_OP_STAT     = 2,   /* fstatat (follow symlinks) -> imp_stat_t */
    IMP_OP_LSTAT    = 3,   /* fstatat (AT_SYMLINK_NOFOLLOW) -> imp_stat_t */
    IMP_OP_MKDIR    = 4,   /* mkdirat */
    IMP_OP_UNLINK   = 5,   /* unlinkat (file) */
    IMP_OP_RMDIR    = 6,   /* unlinkat (AT_REMOVEDIR) */
    IMP_OP_RENAME   = 7,   /* renameat (path -> path2) */
    IMP_OP_LINK     = 8,   /* linkat (path -> path2) */
    IMP_OP_CHMOD    = 9,   /* fchmodat */
    IMP_OP_CHOWN    = 10,  /* fchownat (gid only; uid kept) */
    IMP_OP_TRUNCATE = 11,  /* open+ftruncate to `length` */
    IMP_OP_SETATTR  = 12,  /* utimensat (+ optional fchownat) — POSIX kXR_setattr */
    IMP_OP_SYMLINK  = 13,  /* symlinkat (path=link, path2=target) */
    IMP_OP_READLINK = 14   /* readlinkat -> target via trailing reply payload */
};

/* SETATTR (imp_req_t.attr_flags): which attributes to apply. */
#define IMP_ATTR_TIMES  0x1   /* apply atime/mtime from the req timespecs */
#define IMP_ATTR_OWNER  0x2   /* apply set_uid/set_gid (each (uint32_t)-1 = keep) */

/* Reply status (in imp_rep_t.status). 0 = success.  Negative = -errno from the
 * impersonated syscall (e.g. -EACCES = DAC denied the mapped user). */
#define IMP_STATUS_OK            0
#define IMP_STATUS_DENY          1   /* principal has no permitted UNIX mapping */
#define IMP_STATUS_BADREQ        2   /* malformed request (bounds/NUL/version) */
#define IMP_STATUS_INTERNAL      3   /* broker-side failure (setfsuid etc.) */
#define IMP_STATUS_PRIV_REFUSED  4   /* reserved-id (uid/gid < floor) refused at
                                      * the syscall edge — broker is terminating */

/* imp_rep_t.rep_flags */
#define IMP_REP_HAS_FD       0x1 /* an fd follows via SCM_RIGHTS */
#define IMP_REP_HAS_STAT     0x2 /* st is valid */
#define IMP_REP_HAS_DATA     0x4 /* data_len trailing bytes follow (READLINK) */

/* Portable stat subset (architecture-stable layout for the local socket). */
typedef struct {
    uint64_t ino;
    uint64_t dev;
    uint64_t size;
    uint64_t blocks;
    int64_t  mtime;        /* seconds since epoch */
    int64_t  ctime;
    int64_t  atime;
    uint32_t mode;         /* st_mode (type + perms) */
    uint32_t uid;
    uint32_t gid;
    uint32_t nlink;
    uint32_t blksize;
} imp_stat_t;

/* Fixed-size request frame (~8.7 KiB). */
typedef struct {
    uint32_t version;                 /* IMP_PROTO_VERSION */
    uint32_t op;                      /* IMP_OP_* */
    uint32_t open_flags;              /* OPEN: O_* flags */
    uint32_t mode;                    /* OPEN(create)/MKDIR/CHMOD: mode bits */
    int64_t  length;                  /* TRUNCATE: new size */
    /* SETATTR payload (utimensat + fchownat). */
    int64_t  atime_sec;               /* access time seconds (UTIME_OMIT/NOW ok) */
    int64_t  atime_nsec;              /* access time nanoseconds */
    int64_t  mtime_sec;               /* modify time seconds */
    int64_t  mtime_nsec;              /* modify time nanoseconds */
    uint32_t set_uid;                 /* SETATTR owner; (uint32_t)-1 = unchanged */
    uint32_t set_gid;                 /* SETATTR group; (uint32_t)-1 = unchanged */
    uint32_t attr_flags;              /* IMP_ATTR_TIMES | IMP_ATTR_OWNER */
    uint32_t reserved;                /* keep 8-byte alignment / future use */
    char     principal[IMP_PRINC_MAX];/* NUL-terminated DN / sub / sss-user */
    char     path[IMP_PATH_MAX];      /* root-relative path (SYMLINK: the link) */
    char     path2[IMP_PATH_MAX];     /* RENAME/LINK dest; SYMLINK: verbatim target */
} imp_req_t;

/* Fixed-size reply frame.  For READLINK, `data_len` bytes (the link target) follow
 * the frame in the same message and IMP_REP_HAS_DATA is set. */
typedef struct {
    int32_t    status;                /* 0 ok; -errno; or IMP_STATUS_* (>0) */
    uint32_t   rep_flags;             /* IMP_REP_HAS_FD | _STAT | _DATA */
    imp_stat_t st;                    /* valid when IMP_REP_HAS_STAT */
    uint32_t   data_len;              /* trailing payload bytes (READLINK target) */
} imp_rep_t;

#endif /* XROOTD_IMPERSONATE_PROTO_H */
