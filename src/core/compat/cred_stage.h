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

#endif /* BRIX_COMPAT_CRED_STAGE_H */
