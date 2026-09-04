/*
 * cred_stage.h — one private staging area for short-lived credential material.
 *
 * Several subsystems must hand a live secret (an OAuth2 subject/bearer token, a
 * delegated X.509 proxy PEM) to a fork/exec'd helper that reads it from a FILE
 * path rather than a fd — curl -d @file, the GSI blocking client, etc.  Writing
 * that file into world-traversable /tmp opens a co-tenant race (CWE-377): during
 * the brief window the file exists a shell on the same host / mount namespace can
 * open() the inode by name and read the secret.
 *
 * This module is the SINGLE place that decides where such files live and enforces
 * the directory's safety.  Every credential stager routes through it instead of
 * open-coding an mkstemp("/tmp/...").  The staging dir is a per-uid 0700 tmpfs
 * directory (/dev/shm/brix-creds.<euid>); a 0700 parent owned by the worker uid
 * removes the co-tenant open() entirely, and tmpfs keeps nothing on disk or in
 * backups.  There is deliberately NO /tmp fallback: if a private directory cannot
 * be guaranteed, callers fail closed rather than stage a secret insecurely.
 *
 * Pure libc (no nginx headers) so the path/permission logic is unit-testable
 * standalone — see tests/c/test_cred_stage.c.
 */

#ifndef BRIX_COMPAT_CRED_STAGE_H
#define BRIX_COMPAT_CRED_STAGE_H

#include <stddef.h>

/*
 * brix_cred_stage_dir — resolve (creating if absent) the process's private
 * credential staging directory and copy its NUL-terminated path into out.
 *
 * The directory is created 0700 and REQUIRED to be a real directory owned by the
 * effective uid with no group/other access bits; any deviation (foreign owner, a
 * loosened mode, a symlink swap, tmpfs absent) is treated as unsafe.
 *
 * Returns 0 on success; -1 with errno set when a private directory cannot be
 * guaranteed (EPERM if a pre-existing path fails the owner/mode check).  Callers
 * MUST fail closed on -1 — never fall back to a world-traversable location.
 */
int brix_cred_stage_dir(char *out, size_t outsz);

/*
 * brix_cred_stage_write — atomically stage len bytes into a fresh 0600 file under
 * the private staging directory and return its path in path_out.
 *
 * The file name begins with prefix (e.g. "tpc_token_body_") followed by mkstemp's
 * unique suffix.  On any failure no file is left behind and -1 is returned with
 * errno set.  The caller owns `bytes`; this function does not retain or scrub them
 * (the caller cleanses its own buffer) and remains responsible for unlink()ing the
 * returned path once the helper subprocess has consumed it.
 *
 * Returns 0 on success, -1 with errno set on failure.
 */
int brix_cred_stage_write(const char *prefix, const void *bytes, size_t len,
                          char *path_out, size_t path_outsz);

/*
 * ---- The shared credential-write verb (phase-108 C11) ----
 *
 * One engine for EVERY file this server creates whose content is a live
 * secret.  Before it, four sites hand-rolled the same dance with divergent
 * invariants (deleg_capture wrote a forwarded TGT into getenv("TMPDIR")||
 * "/tmp" — the exact CWE-377 this module exists to prevent).  The engine owns
 * the invariant table once: O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC
 * create at 0600 (+ defensive fchmod), a directory that is 0700/euid-owned/
 * (mode & 0077)==0 re-checked on every call for BOTH arms, EINTR-safe
 * full-length write, close() checked as a write error, unlink on every
 * failure branch.
 *
 * Forward-declared so this header stays nginx-free (ngx_log_t is a typedef of
 * struct ngx_log_s); the pure engine and the standalone unit never touch it.
 */
struct ngx_log_s;

/* The lifetime arm is stated by the CALLER, never inferred (no statfs probe:
 * a probe would turn a mount change into a silent durability change). */
typedef enum {
    BRIX_CRED_ARM_VOLATILE = 0,   /* per-uid tmpfs staging dir; consumed and
                                   * unlinked by the caller; NEVER fsynced —
                                   * the §3.3 tmpfs carve-out, weaker on
                                   * purpose: durability of a secret that must
                                   * not survive reboot is an anti-goal */
    BRIX_CRED_ARM_PERSISTENT,     /* caller-named dir + final name; fsync data,
                                   * publish by rename, fsync parent dir */
    BRIX_CRED_ARM_COUNT
} brix_cred_arm_t;

/* What the bytes ARE — audit vocabulary (and a future TTL-reaper key), never
 * mechanics: both arms treat every kind identically on the wire to disk. */
typedef enum {
    BRIX_CRED_KIND_BEARER = 0,    /* OAuth2 bearer/subject token */
    BRIX_CRED_KIND_PROXY,         /* delegated X.509 proxy PEM */
    BRIX_CRED_KIND_CCACHE,        /* krb5 credential cache */
    BRIX_CRED_KIND_KEYTAB,        /* krb5 keytab */
    BRIX_CRED_KIND_COUNT
} brix_cred_kind_t;

typedef struct {
    struct ngx_log_s  *log;       /* audit sink; unused by the pure engine */
    brix_cred_arm_t    arm;
    brix_cred_kind_t   kind;
    const char        *dir;       /* PERSISTENT: destination directory */
    const char        *name;      /* PERSISTENT: final basename (no '/') */
    const char        *prefix;    /* VOLATILE: staged-name prefix (no '/') */
} brix_cred_write_req_t;

/*
 * brix_cred_write_engine — the pure-libc mechanics of both arms.
 *
 * VOLATILE: stages under brix_cred_stage_dir() as "<prefix><random>"; the
 * temp file IS the product (path_out) and no rename or fsync happens.
 * PERSISTENT: creates "<dir>/.<name>.<random>", fsyncs the data, publishes it
 * as "<dir>/<name>" by rename, then fsyncs the parent directory; path_out is
 * the final path.  len == 0 is valid on both arms (an empty 0600 file — the
 * krb5 ccache pre-creation shape).
 *
 * Returns 0, or -1 with errno: EINVAL (request shape — missing/'/'-bearing
 * name or prefix, out-of-range arm/kind, NULL bytes with len > 0), EPERM (the
 * directory safety check failed — fail closed, never a fallback location),
 * ENAMETOOLONG, or the failing syscall's errno (write/fsync/close/rename all
 * checked).  On failure before publish the temp file is always unlinked; a
 * PERSISTENT parent-fsync failure after rename reports -1 but does NOT unlink
 * the published file (the rename may have replaced a live credential —
 * destroying it would be worse than the lost durability barrier).
 *
 * Pure libc; unit-tested standalone in tests/c/test_cred_stage.c.
 */
int brix_cred_write_engine(const brix_cred_write_req_t *req,
                           const void *bytes, size_t len,
                           char *path_out, size_t path_outsz);

/*
 * brix_cred_write — the domain-gated, audited form (src/core/compat/
 * cred_write.c, nginx-aware).  Validates the request shape, claims the
 * CREDENTIAL storage domain through the typed policy seam
 * (brix_vfs_domain_claim — an EXPORT claim can never be laundered through
 * it: EROFS), runs the engine, and emits exactly one structured audit line:
 * arm/kind/dir/outcome only — never the bytes, never a secret-bearing path
 * component.  Same return contract as the engine, plus EROFS/EINVAL from the
 * domain claim.  Returns 0 on success, -1 with errno set.
 */
int brix_cred_write(const brix_cred_write_req_t *req,
                    const void *bytes, size_t len,
                    char *path_out, size_t path_outsz);

#endif /* BRIX_COMPAT_CRED_STAGE_H */
