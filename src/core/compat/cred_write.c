/*
 * cred_write.c — the domain-gated, audited credential-write verb (phase-108
 * C11).
 *
 * WHAT: Implements brix_cred_write(): the form every credential
 *       materialization site calls. It claims the CREDENTIAL storage domain
 *       through the typed policy seam, runs the pure engine in cred_stage.c,
 *       and emits exactly one structured audit line per materialization.
 *
 * WHY:  The engine must stay pure libc (it links into the standalone unit and
 *       both nginx modules), but the domain claim and the audit line are
 *       nginx-territory — so the gated form lives here, a deliberate,
 *       recorded deviation from the phase-108 §9.4 ledger's letter (which
 *       named only cred_stage.c) in service of the ledger's intent: one
 *       engine, one gate, one audit shape. An EXPORT-domain claim can never
 *       be laundered through this path — brix_vfs_domain_claim routes it to
 *       the phase-105 kernel fail-closed and the answer is EROFS.
 *
 * HOW:  Shape-check, claim the domain (books the
 *       vfs_domain_mutation_total{credential,credential} sample), run the
 *       engine, audit. The audit line carries arm/kind/dir/outcome ONLY —
 *       never the bytes, never a secret-bearing path component (a
 *       credential's basename can encode a subject identity; the directory
 *       cannot).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "core/compat/cred_stage.h"
#include "fs/vfs/vfs_policy_domain.h"

static const char *brix_cred_arm_names[BRIX_CRED_ARM_COUNT] = {
    "volatile", "persistent",
};

static const char *brix_cred_kind_names[BRIX_CRED_KIND_COUNT] = {
    "bearer", "proxy", "ccache", "keytab",
};

/* The §6.3 audit line — the ONE place it is emitted. `dir` is the
 * operator-configured destination (persistent) or the fixed per-uid staging
 * dir (volatile); neither embeds a subject. */
static void
cred_write_audit(ngx_log_t *log, const brix_cred_write_req_t *req,
                 const char *dir, const char *outcome, int err)
{
    ngx_uint_t level;

    if (log == NULL) {
        return;
    }

    level = (err == 0) ? NGX_LOG_NOTICE : NGX_LOG_ERR;

    ngx_log_error(level, log, err,
                  "brix: cred: arm=%s kind=%s dir=\"%s\" outcome=%s",
                  brix_cred_arm_names[req->arm],
                  brix_cred_kind_names[req->kind],
                  dir != NULL ? dir : "",
                  outcome);
}

int
brix_cred_write(const brix_cred_write_req_t *req, const void *bytes,
                size_t len, char *path_out, size_t path_outsz)
{
    int   saved;
    char  stage_dir[64];
    const char *dir;

    /* Shape first, so the name tables and audit line below can index the
     * enums safely; the engine re-checks the rest of the shape itself. */
    if (req == NULL
        || (unsigned) req->arm >= BRIX_CRED_ARM_COUNT
        || (unsigned) req->kind >= BRIX_CRED_KIND_COUNT)
    {
        errno = EINVAL;
        return -1;
    }

    if (req->arm == BRIX_CRED_ARM_PERSISTENT) {
        dir = req->dir;
    } else if (brix_cred_stage_dir(stage_dir, sizeof(stage_dir)) == 0) {
        dir = stage_dir;
    } else {
        dir = NULL;                     /* staging dir unsafe/unavailable —
                                         * the engine will refuse below */
    }

    if (brix_vfs_domain_claim((ngx_log_t *) req->log,
                              BRIX_VFS_DOMAIN_CREDENTIAL,
                              BRIX_VFS_MUTATE_CREDENTIAL)
        != NGX_OK)
    {
        saved = errno;
        cred_write_audit((ngx_log_t *) req->log, req, dir, "denied", saved);
        errno = saved;
        return -1;
    }

    if (brix_cred_write_engine(req, bytes, len, path_out, path_outsz) != 0) {
        saved = errno;
        cred_write_audit((ngx_log_t *) req->log, req, dir, "err", saved);
        errno = saved;
        return -1;
    }

    cred_write_audit((ngx_log_t *) req->log, req, dir, "ok", 0);
    return 0;
}
