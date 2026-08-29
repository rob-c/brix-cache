/* ---------------------------------------------------------------------------
 * ident.h — single source of truth for the server's reported identity.
 *
 * WHAT: Product name and version strings the server advertises to clients
 *       and monitoring consumers (kXR_query Qconfig "version", kXR_query
 *       stats XML, XrdHttp statistics, SRR storageservice, /healthz,
 *       Pelican director registration).
 *
 * WHY:  Every externally visible identity string must come from here so a
 *       rebrand or version bump is a one-line change; scattered literals
 *       drift out of sync.
 *
 * HOW:  Compile-time string macros only — sites either concatenate them
 *       into format literals or pass them as %s arguments.  Wire *protocol*
 *       versions (kXR_PROTOCOLVERSION, statistics schema ids) are NOT
 *       identity and stay where the protocol defines them.
 * ------------------------------------------------------------------------- */

#ifndef BRIX_CORE_IDENT_H
#define BRIX_CORE_IDENT_H

/* Product name reported wherever the server names itself. */
#define BRIX_SERVER_NAME          "BriX-Cache"

/* Version, bare and with the "v" prefix XRootD clients expect from
 * Qconfig "version" (they parse it for digits — keep digits present).
 *
 * THIS LINE IS THE RELEASE. Everything else derives from it: the RPM version
 * (packaging/rpm/build-rpm{,-container}.sh sed this macro out), the spec's
 * literal fallback, the CHANGELOG's top entry, and the git tag. Bumping it
 * alone is not a release — follow docs/09-developer-guide/release-process.md;
 * tools/ci/check_version_sync.py fails the build if the derived copies drift. */
#define BRIX_SERVER_VERSION_BARE  "1.5.0"
#define BRIX_SERVER_VERSION       "v" BRIX_SERVER_VERSION_BARE

#endif /* BRIX_CORE_IDENT_H */
