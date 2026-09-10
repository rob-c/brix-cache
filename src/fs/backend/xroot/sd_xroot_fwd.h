#ifndef BRIX_SD_XROOT_FWD_H
#define BRIX_SD_XROOT_FWD_H

/*
 * sd_xroot_fwd.h — forwarding root:// proxy driver (XrdPss forwarding mode).
 *
 * WHAT: A storage backend whose ORIGIN is named by the CLIENT, per open: a
 *       `brix_storage_backend forward://root[,roots] permit=<host|.suffix>...`
 *       export serves `/root://host[:port]//path` by dialling `host` with the
 *       export's service credential and forwarding the operation.  It is the
 *       one-to-many sibling of sd_xroot: every op parses the key
 *       (sd_xroot_fwd_key.h), checks the protocol list and the permit
 *       allowlist, then relays to a per-host sd_xroot child instance.
 * WHY:  Upstream XCache/XrdPss forwarding mode (`pss.origin =` absent,
 *       `pss.permit`) is what lets one proxy front a whole federation without
 *       an origin per export — 2.0 F5, release-2.0-readiness.md axis (e).
 *       The client names the host, so the driver is a network-egress surface:
 *       the permit list is mandatory (an empty list forwards to nothing) and
 *       the protocol list is closed (root / roots only — never http, never a
 *       local path).
 * HOW:  Children are created lazily under a mutex (metadata ops run on the
 *       thread pool) from the template credentials the registry stamped, keyed
 *       by host:port:tls, capped at SD_XROOT_FWD_MAX_CHILDREN.  Objects, dirs
 *       and staged handles belong to the child (obj->inst / obj->driver are the
 *       child's), so the VFS talks to sd_xroot directly for byte I/O; the
 *       object-keyed slots here exist for the seams that dispatch through the
 *       export's instance (ctx->sd->driver->staged_write, ->close, ...) and
 *       relay to the object's own driver.  The permit verdict shares
 *       brix_tpc_host_pattern_match with the TPC egress guard so a forwarded
 *       open and a TPC pull agree on what ".example.org" means.
 */

#include "sd_xroot.h"

/* Everything a registry-built forwarding instance needs.  `origin` is the
 * TEMPLATE every child is created from — its credential / CA / resolver /
 * verify_pages / nearline fields are copied onto the instance; its host, port
 * and tls are IGNORED (the client supplies them per key).  `permit` is the
 * space-separated host allowlist (exact host or ".suffix"; required, and an
 * empty list permits nothing).  The two flags are the protocol list. */
typedef struct {
    brix_sd_xroot_origin_cfg_t  origin;
    const char                   *permit;
    unsigned                      allow_root:1;
    unsigned                      allow_roots:1;
} brix_sd_xroot_fwd_cfg_t;

/* Build a forwarding instance.  Returns a malloc-owned instance whose ->driver
 * is the "xroot-fwd" driver, or NULL with errno (EINVAL: empty permit list or
 * no protocol allowed).  Destroy with brix_sd_xroot_fwd_destroy. */
brix_sd_instance_t *brix_sd_xroot_fwd_create(
    const brix_sd_xroot_fwd_cfg_t *cfg, ngx_log_t *log);

/* Free a forwarding instance and every child it created. NULL-safe. */
void brix_sd_xroot_fwd_destroy(brix_sd_instance_t *inst);

/* The admission verdict for a client-named key, WITHOUT parsing a host into
 * existence: 0 when the key is admitted -- or when `inst` is not a forwarding
 * export, so there is nothing to admit -- ENOTSUP for a scheme outside the
 * protocol list, EACCES for a host the permit list refuses, and the key
 * parser's own errno (ENOENT / EINVAL / ENAMETOOLONG) for a key that names no
 * origin at all.
 *
 * The read-open existence probe reports EVERY driver-stat failure as a miss
 * (the no-existence-oracle rule), which would turn both refusals into
 * kXR_NotFound and hide the reason from the client.  The protocol layer calls
 * this before the probe so the real verdict is reported: the origin is the
 * client's own words, so naming it back leaks nothing about the namespace.
 * No child is created and no host is dialled. */
int brix_sd_xroot_fwd_admit_key(brix_sd_instance_t *inst, const char *key);

/* Does `inst` serve root:// origins — the plain "xroot" driver OR this
 * forwarding one?  The cache fill's xroot-specific seams (fill from the
 * registered backend, kXR_Qcksum checksum-on-fill) apply to both: a forwarded
 * object IS an sd_xroot object. */
int brix_sd_xroot_serves(const brix_sd_instance_t *inst);

#endif /* BRIX_SD_XROOT_FWD_H */
