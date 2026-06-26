/*
 * broker.c — the privileged root I/O broker (phase 40).
 *
 * WHAT: A long-lived root process that performs namespace/open syscalls on behalf
 *   of unprivileged nginx workers, impersonating the mapped local UNIX user for
 *   each request (setgroups + setfsgid + setfsuid), under RESOLVE_BENEATH
 *   confinement against its own export rootfd, and returns the resulting fd to
 *   the worker via SCM_RIGHTS.
 *
 * WHY: It is the only privileged component; workers hold no capabilities.  It
 *   drops every capability except CAP_SETUID/CAP_SETGID up front — crucially
 *   CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH/CAP_FOWNER/CAP_CHOWN, whose presence
 *   would let a root broker bypass the impersonated user's DAC and make
 *   impersonation meaningless.  The mapping policy (never uid 0 / below min_uid)
 *   plus the rootfd confinement bound a compromised worker to acting as a
 *   mapped, non-system user inside the export.
 *
 * HOW: A single-threaded poll() loop over the listening socket + one persistent
 *   connection per worker.  Per request: validate -> xrootd_idmap_resolve ->
 *   impersonate -> do the confined op -> restore creds -> reply.  Single-threaded
 *   is deliberate: setfsuid is per-thread, so serializing eliminates any chance
 *   of a credential leak between requests; each op is a fast syscall.
 */

#include "impersonate.h"
#include "impersonate_proto.h"
#include "../compat/log_diag.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fsuid.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <linux/openat2.h>
#include <linux/capability.h>
#include <sys/prctl.h>

#define IMP_BROKER_MAXCONN  1024

/*
 * imp_become() return codes.  0 = became the user; -1 = a transient failure
 * (setgroups/setfsuid did not take) → deny this op, keep serving; IMP_REFUSE_PRIV
 * = a RESERVED id (uid/gid/supp < XROOTD_IMP_HARD_MIN_ID) reached the syscall edge
 * → NO credential change was performed, and the broker must abort (see
 * imp_serve_one) so a privileged file op can never run.
 */
#define IMP_REFUSE_PRIV  (-2)

/*
 * Peer-uid gate: when non-zero, the broker only accepts connections whose
 * SO_PEERCRED uid is this value (the unprivileged worker uid) or 0 (root/test).
 * 0 = accept any (the default; used by the in-namespace test where both ends are
 * in-ns root).  The lifecycle layer sets it to the nginx worker uid before fork.
 */
uid_t xrootd_imp_broker_allow_uid = 0;

/* Verify the connected peer's credentials against the allow-uid gate. */
static int
imp_peer_allowed(int conn_fd)
{
    struct ucred cred;
    socklen_t    len = sizeof(cred);

    if (xrootd_imp_broker_allow_uid == 0) {
        return 1;                        /* gate disabled */
    }
    if (getsockopt(conn_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        return 0;                        /* cannot verify -> refuse */
    }
    return cred.uid == xrootd_imp_broker_allow_uid || cred.uid == 0;
}

/* Broker base credentials, captured at startup; restored after each op. */
static uid_t  imp_base_uid;
static gid_t  imp_base_gid;
static gid_t  imp_base_groups[XROOTD_IDMAP_MAXGROUPS];
static int    imp_base_ngroups;

/* The broker's OWN real uid, captured at startup.  The broker structurally
 * refuses to impersonate to its own uid (config-independent), so it can never be
 * coerced into acting as the privileged service/root account it runs as. */
static uid_t  imp_self_uid;

/*
 * Non-root broker identity (hyper-hardening).  When set to a real uid/gid (not
 * (uid_t)-1), the broker drops its REAL uid/gid to this dedicated service account
 * while KEEPING only CAP_SETUID/CAP_SETGID — so nothing runs as root after the
 * master-side rootfd open; the broker's base/idle identity is unprivileged and
 * it holds exactly the two capabilities impersonation needs.  Set by the
 * lifecycle layer (from xrootd_impersonation_broker_user) before broker_run; the
 * forked broker inherits them.  (uid_t)-1 => stay as the current uid.
 */
uid_t xrootd_imp_broker_user_uid = (uid_t) -1;
gid_t xrootd_imp_broker_user_gid = (gid_t) -1;

/* Set effective=permitted={SETUID,SETGID} (inheritable empty).  Returns 0/-1. */
static int
imp_capset_setuid_setgid(int with_effective, ngx_log_t *log)
{
    struct __user_cap_header_struct  hdr;
    struct __user_cap_data_struct    data[2];

    ngx_memzero(&hdr, sizeof(hdr));
    ngx_memzero(data, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid     = 0;
    data[0].permitted   = (1u << CAP_SETUID) | (1u << CAP_SETGID);
    data[0].effective   = with_effective ? data[0].permitted : 0;
    data[0].inheritable = 0;
    if (syscall(SYS_capset, &hdr, data) != 0) {
        if (log) ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                               "impersonate broker: capset failed");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Capability minimisation                                             */
/* ------------------------------------------------------------------ */

/*
 * Drop the broker's real uid/gid to the configured non-root service account while
 * retaining only CAP_SETUID/CAP_SETGID.  Must be called while still root and AFTER
 * the bounding set + permitted caps have been reduced to the two we keep.  Uses
 * PR_SET_KEEPCAPS so the permitted set survives the uid transition, then re-raises
 * the effective set.  No-op (returns 0) when no broker user is configured or we
 * are not root.  Returns -1 on a hard failure (fail closed).
 */
static int
imp_drop_to_service_user(ngx_log_t *log)
{
    uid_t svc_uid = xrootd_imp_broker_user_uid;
    gid_t svc_gid = xrootd_imp_broker_user_gid;
    gid_t one[1];

    if (svc_uid == (uid_t) -1 || getuid() != 0) {
        return 0;                        /* no drop requested, or not root */
    }
    if (svc_uid == 0) {
        if (log) XROOTD_DIAG_EMERG(log, 0,
            "impersonate broker: service user resolves to root (uid 0)",
            "the broker must run as an unprivileged account so it cannot be "
            "abused to act as root",
            "set xrootd_impersonation_broker_user to a dedicated non-root "
            "account");
        return -1;
    }
    if (svc_gid == (gid_t) -1) {
        svc_gid = (gid_t) svc_uid;
    }

    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
        if (log) ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                               "impersonate broker: PR_SET_KEEPCAPS failed");
        return -1;
    }
    one[0] = svc_gid;
    if (syscall(SYS_setgroups, (size_t) 1, one) != 0
        || setresgid(svc_gid, svc_gid, svc_gid) != 0
        || setresuid(svc_uid, svc_uid, svc_uid) != 0)
    {
        if (log) XROOTD_DIAG_EMERG(log, ngx_errno,
            "impersonate broker: cannot drop to service uid %d",
            "the service account is invalid, or the container/host blocks the "
            "setresuid/setgroups transition",
            "verify the broker account exists and that the master runs with "
            "the privileges to switch to it; the OS reason is appended below",
            (int) svc_uid);
        return -1;
    }
    (void) prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);

    /* Effective caps were cleared by the uid transition; re-raise the two we kept
     * (permitted retained them via KEEPCAPS). */
    if (imp_capset_setuid_setgid(1, log) != 0) {
        return -1;
    }
    /*
     * Verify the real, effective AND saved uids/gids all became the service id, so
     * setresuid cannot be undone by a plain setuid()/setgid().  NOTE: we do NOT
     * probe "can't regain root" — the broker MUST keep CAP_SETUID for setfsuid, and
     * CAP_SETUID inherently lets a process setuid(0).  So the non-root base reduces
     * incidental-root exposure (idle state, NSS, path bugs run as the service uid)
     * but does NOT contain a code-execution exploit, which is root-equivalent via
     * CAP_SETUID regardless of the base uid.  This is documented.
     */
    {
        uid_t ru, eu, su;
        gid_t rg, eg, sg;
        if (getresuid(&ru, &eu, &su) != 0 || getresgid(&rg, &eg, &sg) != 0
            || ru != svc_uid || eu != svc_uid || su != svc_uid
            || rg != svc_gid || eg != svc_gid || sg != svc_gid)
        {
            if (log) ngx_log_error(NGX_LOG_EMERG, log, 0,
                                   "impersonate broker: service-uid drop did not "
                                   "stick (r/e/s mismatch)");
            return -1;
        }
    }
    if (log) ngx_log_error(NGX_LOG_NOTICE, log, 0,
                           "impersonate broker: running as non-root service uid %d "
                           "with only CAP_SETUID+CAP_SETGID", (int) svc_uid);
    return 0;
}

int
xrootd_imp_broker_drop_caps(ngx_log_t *log)
{
    int cap;

    /* No new privileges (defence in depth: no setuid-binary escalation). */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        if (log) ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                               "impersonate broker: PR_SET_NO_NEW_PRIVS failed");
        return -1;
    }

    /* Clear the bounding set of everything but SETUID/SETGID so the dropped caps
     * can never be re-acquired (even via a future exec).  Done while root, which
     * holds CAP_SETPCAP. */
    for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (cap == CAP_SETUID || cap == CAP_SETGID) {
            continue;
        }
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && ngx_errno != EINVAL) {
            /* EINVAL = unknown cap on this kernel; ignore. Other errors fail. */
            if (log) ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                                   "impersonate broker: CAPBSET_DROP(%d) failed",
                                   cap);
            return -1;
        }
    }

    /* Reduce permitted + effective to {SETUID, SETGID}. */
    if (imp_capset_setuid_setgid(1, log) != 0) {
        return -1;
    }

    /* Hyper-harden: drop to the non-root service account (keeping the two caps),
     * so the broker's base identity is unprivileged and nothing runs as root after
     * this point.  No-op when no broker user is configured. */
    if (imp_drop_to_service_user(log) != 0) {
        return -1;
    }

    if (log) ngx_log_error(NGX_LOG_NOTICE, log, 0,
                           "impersonate broker: dropped to CAP_SETUID+CAP_SETGID "
                           "(DAC now enforced for the impersonated user)");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Impersonation (per request)                                         */
/* ------------------------------------------------------------------ */

/*
 * Become the mapped user for the duration of one op.  Returns 0 on success, -1 on
 * a transient failure, or IMP_REFUSE_PRIV if the target identity is reserved.
 *
 * HARD GUARD (non-bypassable, the whole point of this function): BEFORE touching
 * any credential syscall, refuse outright if the target uid, primary gid, or ANY
 * supplementary gid is 0 or below XROOTD_IMP_HARD_MIN_ID.  The mapping layer
 * already rejects such principals, so reaching here with a reserved id is a
 * should-be-impossible invariant breach — we perform NO setgroups/setfsgid/
 * setfsuid and signal the caller to abort.  This makes a privileged file op
 * impossible in the code path even if the mapping layer were bypassed.
 *
 * Order: setgroups/setfsgid first, fsuid LAST; each set is read back (setfsuid(-1)
 * returns the current fsuid without changing it) because a failed setfsuid
 * silently keeps the old fsuid, which would be a privilege leak.  Finally the
 * REALIZED fsuid/fsgid are re-checked against the hard floor — belt and suspenders
 * against any kernel/edge anomaly.
 */
static int
imp_become(const xrootd_idmap_creds_t *cr)
{
    uid_t got_uid;
    gid_t got_gid;

    if (xrootd_imp_creds_privileged(cr, XROOTD_IMP_HARD_MIN_ID, NULL, NULL)) {
        return IMP_REFUSE_PRIV;          /* reserved id — touch NO syscall */
    }

    /*
     * Config-independent confused-deputy guard: never impersonate to the broker's
     * OWN uid (the privileged service/root account it runs as) nor to the nginx
     * worker uid (the SO_PEERCRED-gated peer).  Even if the mapping layer's
     * deny-lists were misconfigured, the broker cannot be coerced into acting as
     * the gateway's own service identity.
     */
    if (cr->uid == imp_self_uid
        || (xrootd_imp_broker_allow_uid != 0
            && cr->uid == xrootd_imp_broker_allow_uid))
    {
        return IMP_REFUSE_PRIV;
    }

    if (syscall(SYS_setgroups, (size_t) cr->ngroups, cr->groups) != 0) {
        return -1;
    }
    (void) setfsgid(cr->gid);
    if ((gid_t) setfsgid((gid_t) -1) != cr->gid) {
        return -1;
    }
    (void) setfsuid(cr->uid);
    if ((uid_t) setfsuid((uid_t) -1) != cr->uid) {
        return -1;                       /* fsuid did not take — refuse the op */
    }

    /* Re-verify the realized fs-credentials are non-reserved before any file op. */
    got_uid = (uid_t) setfsuid((uid_t) -1);
    got_gid = (gid_t) setfsgid((gid_t) -1);
    if (got_uid == 0 || got_uid < (uid_t) XROOTD_IMP_HARD_MIN_ID
        || got_gid == 0 || got_gid < (gid_t) XROOTD_IMP_HARD_MIN_ID)
    {
        return IMP_REFUSE_PRIV;          /* realized fsuid/fsgid is reserved */
    }
    return 0;
}

/* Restore the broker's own credentials (reverse order: fsuid, fsgid, groups). */
static void
imp_restore(void)
{
    (void) setfsuid(imp_base_uid);
    (void) setfsgid(imp_base_gid);
    (void) syscall(SYS_setgroups, (size_t) imp_base_ngroups, imp_base_groups);
}

/* ------------------------------------------------------------------ */
/* Confined filesystem ops (mirror src/path/beneath.c, broker-side)    */
/* ------------------------------------------------------------------ */

/* Strip a leading '/' so the path is relative to rootfd; "" / "/" -> ".". */
static const char *
imp_rel(const char *path)
{
    while (*path == '/') {
        path++;
    }
    return *path ? path : ".";
}

/* openat2(rootfd, rel, RESOLVE_BENEATH).  Returns fd or -errno. */
static int
imp_openat2(int rootfd, const char *rel, uint32_t flags, uint32_t mode)
{
    struct open_how how;
    long            fd;

    ngx_memzero(&how, sizeof(how));
    how.flags   = flags | O_CLOEXEC;
    /*
     * openat2() is stricter than open()/openat(): it rejects (EINVAL) any
     * how.mode bit outside 07777.  Callers legitimately pass a full struct
     * stat st_mode (e.g. staged_file copying a source's permissions during a
     * WebDAV/S3 COPY), which carries the S_IFMT type bits.  Mask to the
     * permission bits, exactly as the worker-local do_openat2() in
     * src/path/beneath.c does, so a struct-stat mode is accepted instead of
     * failing the whole impersonated COPY with EINVAL.
     */
    how.mode    = (flags & O_CREAT) ? (mode & 07777) : 0;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;

    fd = syscall(SYS_openat2, rootfd, rel, &how, sizeof(how));
    return (fd < 0) ? -errno : (int) fd;
}

/*
 * Open the PARENT directory of `rel` beneath rootfd (O_PATH|O_DIRECTORY) and
 * point *base at the final path component.  Returns the parent fd or -errno;
 * rejects a trailing "." / ".." / empty base.  `scratch` (>= IMP_PATH_MAX) holds
 * the mutated copy that *base points into.
 */
static int
imp_open_parent(int rootfd, const char *rel, char *scratch, const char **base)
{
    char *slash;
    int   pfd;

    if (ngx_strlen(rel) >= IMP_PATH_MAX) {
        return -ENAMETOOLONG;
    }
    ngx_memcpy(scratch, rel, ngx_strlen(rel) + 1);

    slash = strrchr(scratch, '/');
    if (slash == NULL) {
        *base = scratch;                 /* parent is rootfd itself */
        pfd = imp_openat2(rootfd, ".", O_PATH | O_DIRECTORY, 0);
    } else {
        *slash = '\0';
        *base = slash + 1;
        pfd = imp_openat2(rootfd, imp_rel(scratch), O_PATH | O_DIRECTORY, 0);
    }

    if ((*base)[0] == '\0'
        || ngx_strcmp(*base, ".") == 0 || ngx_strcmp(*base, "..") == 0)
    {
        if (pfd >= 0) { close(pfd); }
        return -EINVAL;
    }
    return pfd;                          /* fd or -errno from imp_openat2 */
}

/* Fill a portable imp_stat_t from a struct stat. */
static void
imp_fill_stat(imp_stat_t *o, const struct stat *s)
{
    o->ino     = (uint64_t) s->st_ino;
    o->dev     = (uint64_t) s->st_dev;
    o->size    = (uint64_t) s->st_size;
    o->blocks  = (uint64_t) s->st_blocks;
    o->mtime   = (int64_t)  s->st_mtime;
    o->ctime   = (int64_t)  s->st_ctime;
    o->atime   = (int64_t)  s->st_atime;
    o->mode    = (uint32_t) s->st_mode;
    o->uid     = (uint32_t) s->st_uid;
    o->gid     = (uint32_t) s->st_gid;
    o->nlink   = (uint32_t) s->st_nlink;
    o->blksize = (uint32_t) s->st_blksize;
}

/* ------------------------------------------------------------------ */
/* Per-op dispatch (already impersonated)                              */
/* ------------------------------------------------------------------ */

/*
 * imp_xattr_open — open the xattr target file beneath rootfd as the (already
 * impersonated) mapped user for an f*xattr op.  O_RDONLY|O_NONBLOCK is enough:
 * f{get,set,remove,list}xattr check inode permission against the caller's
 * (impersonated) creds at the call, independent of the fd's open mode, while the
 * RESOLVE_BENEATH open both confines the path and enforces the mapped user's DAC
 * to even reach the file.  O_NONBLOCK avoids blocking on a FIFO.  Returns fd or
 * -errno.  (Rare write-only files — mode 0200 — cannot be opened O_RDONLY; such
 * a SETXATTR fails EACCES, an acceptable corner the path-based fallback avoided.)
 */
static int
imp_xattr_open(int rootfd, const char *rel)
{
    return imp_openat2(rootfd, rel, O_RDONLY | O_NONBLOCK, 0);
}

/*
 * imp_xattr_name_ok — the broker only services the `user.` xattr namespace (all
 * the module's xattr users live there: locks, dead properties, checksum cache).
 * Refusing every other namespace is defence-in-depth: it denies any attempt to
 * drive the broker into setting security.* / system.* / trusted.* attributes,
 * independent of what the (unprivileged) mapped user's own creds would allow.
 */
static int
imp_xattr_name_ok(const char *name)
{
    return ngx_strncmp(name, "user.", 5) == 0;
}

/*
 * imp_xattr_filter_user — restrict a flistxattr(2) result (NUL-separated attribute
 * names, total `len` bytes including terminators) to the `user.` namespace,
 * repacking the kept names densely in place and returning the new length.  Without
 * this the broker would hand the worker the NAMES of every attribute on the file,
 * including system.* / security.* / trusted.* set by root — an information leak
 * (the worker cannot read their VALUES, but it learns they exist).  Matches the
 * same user.-only policy the per-name ops enforce via imp_xattr_name_ok().
 */
static size_t
imp_xattr_filter_user(char *list, size_t len)
{
    size_t in = 0, out = 0;

    while (in < len) {
        size_t entry = 0;
        while (in + entry < len && list[in + entry] != '\0') {
            entry++;
        }
        if (in + entry >= len) {
            break;                       /* no NUL terminator: malformed tail */
        }
        entry++;                         /* include the NUL */
        if (imp_xattr_name_ok(list + in)) {
            if (out != in) {
                ngx_memmove(list + out, list + in, entry);
            }
            out += entry;
        }
        in += entry;
    }
    return out;
}

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1u << 0)
#endif

/*
 * renameat, optionally with RENAME_NOREPLACE (atomic create-if-absent).  When
 * `noreplace` is set and the kernel/filesystem lacks RENAME_NOREPLACE
 * (ENOSYS/EINVAL) it falls back to a plain renameat so behaviour degrades to the
 * legacy last-writer-wins rather than spuriously failing; on a modern kernel
 * (>=3.15) the exclusive path is taken and a pre-existing dst yields EEXIST.
 * Returns 0 on success, -1 with errno set.
 */
static int
imp_do_rename(int sfd, const char *sbase, int dfd, const char *dbase,
              int noreplace)
{
    if (!noreplace) {
        return renameat(sfd, sbase, dfd, dbase);
    }
    if (syscall(SYS_renameat2, sfd, sbase, dfd, dbase,
                (unsigned int) RENAME_NOREPLACE) == 0) {
        return 0;
    }
    if (errno == ENOSYS || errno == EINVAL) {
        return renameat(sfd, sbase, dfd, dbase);
    }
    return -1;
}

/*
 * Perform the requested op while impersonated.  Returns 0 and may set *out_fd
 * (>=0, ownership transferred to the caller) and/or rep->st; or returns -errno.
 * `data_out` (size `data_max`) receives a trailing reply payload for READLINK /
 * GETXATTR / LISTXATTR; rep->data_len + IMP_REP_HAS_DATA are set in that case.
 * `data_in` (size `data_in_len`) is the inbound payload for SETXATTR (the value).
 */
static int
imp_do_op(int rootfd, const imp_req_t *req, imp_rep_t *rep, int *out_fd,
          char *data_out, size_t data_max,
          const char *data_in, size_t data_in_len)
{
    const char *rel  = imp_rel(req->path);
    const char *rel2;
    char        scratch[IMP_PATH_MAX], scratch2[IMP_PATH_MAX];
    const char *base, *base2;
    int         pfd, pfd2, fd, rc;
    struct stat st;

    /*
     * Last-line guard, at the file-op execution point itself: the effective
     * fs-credentials MUST be non-reserved here (imp_become guarantees it).  Read
     * them back one more time and refuse the op rather than ever run a file
     * operation as uid/gid 0 or < the hard floor.  Cheap (two syscalls), and it
     * closes the window completely — no file op runs under a reserved identity.
     */
    if ((uid_t) setfsuid((uid_t) -1) < (uid_t) XROOTD_IMP_HARD_MIN_ID
        || (gid_t) setfsgid((gid_t) -1) < (gid_t) XROOTD_IMP_HARD_MIN_ID)
    {
        return -EPERM;
    }

    switch (req->op) {

    case IMP_OP_OPEN: {
        int fl;

        /*
         * Force O_NONBLOCK for the open(2) itself.  WHY: a FIFO opened O_RDONLY
         * blocks until a writer arrives, and a device node can block in its
         * open method — either would wedge this single broker process, denying
         * service to *every* worker/tenant (a cross-tenant DoS) since one bad
         * path in the export hangs the whole impersonation channel.  With
         * O_NONBLOCK the open returns immediately for every file type, then we
         * inspect what we actually got and only hand back regular files and
         * directories — the only types the gateway data plane ever serves.
         */
        fd = imp_openat2(rootfd, rel, req->open_flags | O_NONBLOCK, req->mode);
        if (fd < 0) {
            return fd;
        }
        if (fstat(fd, &st) != 0) {
            rc = -errno;
            close(fd);
            return rc;
        }
        /*
         * Reject FIFOs, sockets, and character/block devices: the gateway only
         * reads/writes regular files and enumerates directories.  Handing the
         * worker a device or pipe fd would both leak a non-file capability and
         * (for the data plane's blocking pread/pwrite/sendfile) reintroduce the
         * very stall we just avoided.  Fail closed with EOPNOTSUPP.
         */
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
            close(fd);
            return -EOPNOTSUPP;
        }
        /*
         * Restore blocking semantics for the returned fd: O_NONBLOCK was only
         * needed to survive the open(2); the worker's data plane expects a
         * blocking regular-file/dir fd (it has no EAGAIN retry path).  On a
         * regular file/dir O_NONBLOCK is otherwise a no-op, so clearing it is
         * always safe.
         */
        fl = fcntl(fd, F_GETFL);
        if (fl != -1) {
            (void) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        }
        *out_fd = fd;
        rep->rep_flags |= IMP_REP_HAS_FD;
        return 0;
    }

    case IMP_OP_STAT:
    case IMP_OP_LSTAT:
        fd = imp_openat2(rootfd, rel,
                         O_PATH | (req->op == IMP_OP_LSTAT ? O_NOFOLLOW : 0), 0);
        if (fd < 0) {
            return fd;
        }
        rc = fstatat(fd, "", &st, AT_EMPTY_PATH) == 0 ? 0 : -errno;
        close(fd);
        if (rc != 0) {
            return rc;
        }
        imp_fill_stat(&rep->st, &st);
        rep->rep_flags |= IMP_REP_HAS_STAT;
        return 0;

    case IMP_OP_TRUNCATE:
        fd = imp_openat2(rootfd, rel, O_WRONLY, 0);
        if (fd < 0) {
            return fd;
        }
        rc = ftruncate(fd, (off_t) req->length) == 0 ? 0 : -errno;
        close(fd);
        return rc;

    case IMP_OP_MKDIR:
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = mkdirat(pfd, base, req->mode) == 0 ? 0 : -errno;
        close(pfd);
        return rc;

    case IMP_OP_UNLINK:
    case IMP_OP_RMDIR:
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = unlinkat(pfd, base, req->op == IMP_OP_RMDIR ? AT_REMOVEDIR : 0) == 0
                 ? 0 : -errno;
        close(pfd);
        return rc;

    case IMP_OP_CHMOD:
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = fchmodat(pfd, base, req->mode, 0) == 0 ? 0 : -errno;
        close(pfd);
        return rc;

    case IMP_OP_CHOWN:
        /* gid only (uid is fixed by ownership); the mapped user must own it. */
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = fchownat(pfd, base, (uid_t) -1, (gid_t) req->mode,
                      AT_SYMLINK_NOFOLLOW) == 0 ? 0 : -errno;
        close(pfd);
        return rc;

    case IMP_OP_RENAME:
    case IMP_OP_RENAME_NOREPLACE:
    case IMP_OP_LINK:
        rel2 = imp_rel(req->path2);
        pfd  = imp_open_parent(rootfd, rel,  scratch,  &base);
        if (pfd < 0) {
            return pfd;
        }
        pfd2 = imp_open_parent(rootfd, rel2, scratch2, &base2);
        if (pfd2 < 0) {
            close(pfd);
            return pfd2;
        }
        if (req->op == IMP_OP_LINK) {
            rc = linkat(pfd, base, pfd2, base2, 0) == 0 ? 0 : -errno;
        } else {
            rc = imp_do_rename(pfd, base, pfd2, base2,
                               req->op == IMP_OP_RENAME_NOREPLACE) == 0
                 ? 0 : -errno;
        }
        close(pfd);
        close(pfd2);
        return rc;

    case IMP_OP_SETATTR:
        /* utimensat (+ optional fchownat) on the final component, NOFOLLOW.  As
         * the mapped user: chgrp/utimens on a file they own succeeds; a chown to
         * a different owner correctly fails (the broker holds no CAP_CHOWN). */
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = 0;
        if (req->attr_flags & IMP_ATTR_TIMES) {
            struct timespec ts[2];
            ts[0].tv_sec  = (time_t) req->atime_sec;
            ts[0].tv_nsec = (long)   req->atime_nsec;
            ts[1].tv_sec  = (time_t) req->mtime_sec;
            ts[1].tv_nsec = (long)   req->mtime_nsec;
            if (utimensat(pfd, base, ts, AT_SYMLINK_NOFOLLOW) != 0) {
                rc = -errno;
            }
        }
        if (rc == 0 && (req->attr_flags & IMP_ATTR_OWNER)) {
            uid_t u = (req->set_uid == (uint32_t) -1) ? (uid_t) -1
                                                      : (uid_t) req->set_uid;
            gid_t g = (req->set_gid == (uint32_t) -1) ? (gid_t) -1
                                                      : (gid_t) req->set_gid;
            if (fchownat(pfd, base, u, g, AT_SYMLINK_NOFOLLOW) != 0) {
                rc = -errno;
            }
        }
        close(pfd);
        return rc;

    case IMP_OP_SYMLINK:
        /* path = link location (root-relative); path2 = verbatim target string.
         * Only the link site is confined; a target pointing outside the root just
         * cannot be followed later (the confined open re-applies RESOLVE_BENEATH). */
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = symlinkat(req->path2, pfd, base) == 0 ? 0 : -errno;
        close(pfd);
        return rc;

    case IMP_OP_READLINK: {
        ssize_t n;
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        n = readlinkat(pfd, base, data_out, data_max);
        close(pfd);
        if (n < 0) {
            return -errno;
        }
        rep->data_len   = (uint32_t) n;     /* link target -> trailing payload */
        rep->rep_flags |= IMP_REP_HAS_DATA;
        return 0;
    }

    case IMP_OP_GETXATTR:
    case IMP_OP_LISTXATTR: {
        ssize_t n;
        if (req->op == IMP_OP_GETXATTR && !imp_xattr_name_ok(req->path2)) {
            return -EPERM;
        }
        fd = imp_xattr_open(rootfd, rel);
        if (fd < 0) {
            return fd;
        }
        if (req->op == IMP_OP_GETXATTR) {
            n = fgetxattr(fd, req->path2, data_out, data_max);
        } else {
            n = flistxattr(fd, data_out, data_max);
        }
        close(fd);
        if (n < 0) {
            return -errno;                  /* ENODATA / ERANGE / EACCES ... */
        }
        if (req->op == IMP_OP_LISTXATTR) {
            /* Withhold non-user.* attribute NAMES from the worker (the per-name
             * GET/SET/REMOVE ops are already user.-only). */
            n = (ssize_t) imp_xattr_filter_user(data_out, (size_t) n);
        }
        rep->data_len   = (uint32_t) n;     /* value / name list -> reply payload */
        rep->rep_flags |= IMP_REP_HAS_DATA;
        return 0;
    }

    case IMP_OP_SETXATTR:
        if (!imp_xattr_name_ok(req->path2)) {
            return -EPERM;
        }
        fd = imp_xattr_open(rootfd, rel);
        if (fd < 0) {
            return fd;
        }
        rc = fsetxattr(fd, req->path2, data_in, data_in_len,
                       (int) req->mode) == 0 ? 0 : -errno;
        close(fd);
        return rc;

    case IMP_OP_REMOVEXATTR:
        if (!imp_xattr_name_ok(req->path2)) {
            return -EPERM;
        }
        fd = imp_xattr_open(rootfd, rel);
        if (fd < 0) {
            return fd;
        }
        rc = fremovexattr(fd, req->path2) == 0 ? 0 : -errno;
        close(fd);
        return rc;

    default:
        return -ENOSYS;
    }
}

/* ------------------------------------------------------------------ */
/* Wire IO                                                             */
/* ------------------------------------------------------------------ */

/* Read exactly n bytes; returns 1 ok, 0 EOF, -1 error. */
static int
imp_read_full(int fd, void *buf, size_t n)
{
    u_char *p = buf;
    size_t  got = 0;

    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r == 0) { return 0; }
        if (r < 0) {
            if (errno == EINTR) { continue; }
            return -1;
        }
        got += (size_t) r;
    }
    return 1;
}

/*
 * Send the reply frame, optionally with `data_len` trailing bytes (READLINK
 * target) in the same message, and attaching `fd` via SCM_RIGHTS when fd >= 0.
 */
static int
imp_send_reply(int conn_fd, const imp_rep_t *rep, int fd,
               const void *data, size_t data_len)
{
    struct msghdr   msg;
    struct iovec    iov[2];
    union {
        struct cmsghdr align;
        char           buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    ssize_t n;

    ngx_memzero(&msg, sizeof(msg));
    iov[0].iov_base = (void *) rep;
    iov[0].iov_len  = sizeof(*rep);
    msg.msg_iov     = iov;
    msg.msg_iovlen  = 1;
    if (data_len > 0) {
        iov[1].iov_base = (void *) data;
        iov[1].iov_len  = data_len;
        msg.msg_iovlen  = 2;
    }

    if (fd >= 0) {
        struct cmsghdr *c;
        ngx_memzero(&cmsgbuf, sizeof(cmsgbuf));
        msg.msg_control    = cmsgbuf.buf;
        msg.msg_controllen = sizeof(cmsgbuf.buf);
        c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type  = SCM_RIGHTS;
        c->cmsg_len   = CMSG_LEN(sizeof(int));
        ngx_memcpy(CMSG_DATA(c), &fd, sizeof(int));
    }

    do {
        n = sendmsg(conn_fd, &msg, MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);

    return (n == (ssize_t) (sizeof(*rep) + data_len)) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Connection servicing                                                */
/* ------------------------------------------------------------------ */

/* Serve one request on conn_fd.  Returns 1 to keep the connection, 0 to close. */
static int
imp_serve_one(int conn_fd, int rootfd, ngx_log_t *log)
{
    /*
     * Outbound (READLINK/GETXATTR/LISTXATTR) and inbound (SETXATTR value)
     * trailing-payload scratch.  `static` rather than stack: the broker serve
     * loop is strictly single-threaded and non-reentrant, so two 64 KiB frames
     * on the stack per request would be wasteful; each request fully overwrites
     * the bytes it sends (only rep.data_len of data_buf is ever transmitted), so
     * nothing stale leaks across requests.
     */
    static char          data_buf[IMP_XATTR_MAX]; /* outbound reply payload */
    static char          data_in[IMP_XATTR_MAX];  /* inbound SETXATTR value */
    imp_req_t            req;
    imp_rep_t            rep;
    xrootd_idmap_creds_t creds;
    size_t               in_len = 0;
    int                  rc, fd = -1;

    rc = imp_read_full(conn_fd, &req, sizeof(req));
    if (rc <= 0) {
        return 0;                        /* EOF or error -> drop the connection */
    }

    ngx_memzero(&rep, sizeof(rep));

    /* Validate the frame: version, NUL-termination, op range. */
    req.principal[IMP_PRINC_MAX - 1] = '\0';
    req.path[IMP_PATH_MAX - 1]       = '\0';
    req.path2[IMP_PATH_MAX - 1]      = '\0';
    if (req.version != IMP_PROTO_VERSION) {
        rep.status = IMP_STATUS_BADREQ;
        return imp_send_reply(conn_fd, &rep, -1, NULL, 0) == 0 ? 1 : 0;
    }

    /*
     * SETXATTR carries an inbound value payload after the fixed frame.  It MUST
     * be drained from the SOCK_STREAM before any deny/early-return path, or the
     * leftover bytes would be mis-read as the next request frame (desync).  An
     * over-large declared length is rejected and the connection dropped (we
     * cannot trust the stream position).  Only SETXATTR consumes inbound data;
     * every other op leaves req_data_len == 0.
     */
    if (req.op == IMP_OP_SETXATTR) {
        if (req.req_data_len > IMP_XATTR_MAX) {
            rep.status = IMP_STATUS_BADREQ;
            (void) imp_send_reply(conn_fd, &rep, -1, NULL, 0);
            return 0;                    /* close: stream position untrustworthy */
        }
        in_len = req.req_data_len;
        if (in_len > 0 && imp_read_full(conn_fd, data_in, in_len) <= 0) {
            return 0;                    /* EOF/error mid-payload -> drop */
        }
    }

    if (req.op == IMP_OP_PING) {
        rep.status = IMP_STATUS_OK;
        return imp_send_reply(conn_fd, &rep, -1, NULL, 0) == 0 ? 1 : 0;
    }

    /* Map the principal -> UNIX creds.  Anything that is not a concrete OK/SQUASH
     * mapping (deny uid 0 / below floor, or a hard resolver error) fails closed —
     * the broker must never impersonate on an uncertain mapping. */
    rc = xrootd_idmap_resolve(NULL, req.principal, &creds, log);
    if (rc != XROOTD_IDMAP_OK && rc != XROOTD_IDMAP_SQUASH) {
        rep.status = IMP_STATUS_DENY;
        return imp_send_reply(conn_fd, &rep, -1, NULL, 0) == 0 ? 1 : 0;
    }

    /* Impersonate -> op -> restore (always restore, even on error). */
    rc = imp_become(&creds);
    if (rc == IMP_REFUSE_PRIV) {
        /*
         * CRITICAL, should-be-impossible: a reserved uid/gid reached the setfsuid
         * edge despite the mapping-layer floor.  NO credential change was made.
         * Refuse, return an explicit error to the worker, log loudly, and
         * TERMINATE the privileged broker (fail-closed + fail-loud) so a
         * privileged file op can never be executed.  Workers then fail closed on
         * every subsequent impersonated op.  This is not reachable in correct
         * operation (idmap denies reserved ids first); reaching it means an
         * upstream guard was bypassed, which we treat as fatal.
         */
        rep.status = IMP_STATUS_PRIV_REFUSED;
        (void) imp_send_reply(conn_fd, &rep, -1, NULL, 0);
        if (log) ngx_log_error(NGX_LOG_CRIT, log, 0,
                               "impersonate broker: FATAL — refused RESERVED "
                               "credential at the setfsuid edge (uid=%d gid=%d, "
                               "floor=%d); terminating broker to guarantee no "
                               "privileged file op runs",
                               (int) creds.uid, (int) creds.gid,
                               XROOTD_IMP_HARD_MIN_ID);
        /* Also emit to stderr: this is fatal and log may be NULL (tests, or a
         * mis-set error_log), and the reason must never be silently swallowed. */
        fprintf(stderr, "impersonate broker: FATAL — refused RESERVED credential "
                "(uid=%d gid=%d floor=%d); terminating\n",
                (int) creds.uid, (int) creds.gid, XROOTD_IMP_HARD_MIN_ID);
        _exit(EXIT_FAILURE);
    }
    if (rc != 0) {
        imp_restore();
        rep.status = -EPERM;
        if (log) ngx_log_error(NGX_LOG_ERR, log, 0,
                               "impersonate broker: could not become uid=%d",
                               (int) creds.uid);
        return imp_send_reply(conn_fd, &rep, -1, NULL, 0) == 0 ? 1 : 0;
    }
    rc = imp_do_op(rootfd, &req, &rep, &fd, data_buf, sizeof(data_buf),
                   data_in, in_len);
    imp_restore();

    rep.status = rc;                     /* 0 or -errno */

    rc = imp_send_reply(conn_fd, &rep, fd, data_buf, rep.data_len);
    if (fd >= 0) {
        close(fd);                       /* the kernel duped it into the worker */
    }
    return rc == 0 ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Main loop                                                           */
/* ------------------------------------------------------------------ */

int
xrootd_imp_broker_run(int listen_fd, int rootfd,
                      const volatile sig_atomic_t *stop, ngx_log_t *log)
{
    struct pollfd pfds[IMP_BROKER_MAXCONN + 1];
    nfds_t        nfds = 1;
    int           ng;

    /*
     * Drop privileges FIRST (cap minimisation + optional drop to a non-root
     * service account), THEN capture the base credentials — so the base/idle
     * identity the broker restores to between ops, and imp_self_uid (the
     * never-impersonate-to-self guard), reflect the final, minimal identity.
     */
    if (xrootd_imp_broker_drop_caps(log) != 0) {
        return -1;                       /* fail closed: DAC would not be enforced */
    }

    imp_base_uid = geteuid();
    imp_base_gid = getegid();
    imp_self_uid = getuid();
    ng = getgroups(XROOTD_IDMAP_MAXGROUPS, imp_base_groups);
    imp_base_ngroups = (ng > 0) ? ng : 0;

    pfds[0].fd     = listen_fd;
    pfds[0].events = POLLIN;

    for ( ;; ) {
        nfds_t i;
        int    n;

        if (stop != NULL && *stop) {
            return 0;
        }
        n = poll(pfds, nfds, 1000);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            return -1;
        }
        if (n == 0) {
            continue;
        }

        /* New worker connection. */
        if (pfds[0].revents & POLLIN) {
            int c = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
            if (c >= 0) {
                if (!imp_peer_allowed(c)) {
                    if (log) ngx_log_error(NGX_LOG_ERR, log, 0,
                                           "impersonate broker: rejected peer "
                                           "(SO_PEERCRED uid mismatch)");
                    close(c);
                } else if (nfds <= IMP_BROKER_MAXCONN) {
                    pfds[nfds].fd      = c;
                    pfds[nfds].events  = POLLIN;
                    pfds[nfds].revents = 0;  /* MUST clear: the swap-remove
                                              * compaction below may move this
                                              * freshly-accepted slot into an
                                              * active index and re-examine it in
                                              * this same pass; a stale POLLHUP
                                              * left in the slot would otherwise
                                              * close the brand-new connection. */
                    nfds++;
                } else {
                    close(c);            /* at capacity */
                }
            }
        }

        /* Serve / reap worker connections (compact the array in place). */
        for (i = 1; i < nfds; ) {
            short re = pfds[i].revents;
            int   keep = 1;

            if (re & (POLLERR | POLLHUP | POLLNVAL)) {
                keep = 0;
            } else if (re & POLLIN) {
                keep = imp_serve_one(pfds[i].fd, rootfd, log);
            }

            if (!keep) {
                close(pfds[i].fd);
                pfds[i] = pfds[nfds - 1];   /* swap-remove */
                nfds--;
            } else {
                i++;
            }
        }
    }
}
