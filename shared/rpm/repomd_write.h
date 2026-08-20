/* repomd_write.h — repodata emission for `brixrpm createrepo` (phase-104
 * D12.3).
 *
 * WHAT: render per-package primary/filelists/other XML fragments from a
 *       parsed rpmhdr package, accumulate them, and emit
 *       repodata/{<sha256>-primary.xml.gz, <sha256>-filelists.xml.gz,
 *       <sha256>-other.xml.gz, repomd.xml} — checksum-named data files,
 *       repomd.xml staged and renamed LAST (the .cvmfspublished swap
 *       discipline), so a reader never sees a repomd that names files that
 *       are not yet in place.
 * WHY:  clean-room createrepo — no createrepo_c linkage. The oracle is the
 *       Appendix-X Python generator (byte-parity on the decompressed XML)
 *       plus a stock EL9 dnf depsolving and installing from the output.
 * HOW:  fragments are first-class so the CLI's `--update` memo can cache
 *       them per package and skip re-parsing unchanged RPMs: render() for a
 *       fresh package, add_fragments() for a cache hit, one finish().
 */
#ifndef BRIX_RPM_REPOMD_WRITE_H
#define BRIX_RPM_REPOMD_WRITE_H

#include <stddef.h>
#include <stdint.h>

#include "rpm/rpmhdr.h"

typedef struct brix_repomd_s brix_repomd_t;

/* Start an emission run for <repo_dir> (repodata/ created on finish). */
brix_repomd_t *brix_repomd_begin(const char *repo_dir, char *err,
                                 size_t errlen);

/* Render one package's three fragments (malloc'd, NUL-terminated; caller
 * frees). href is the location relative to the repo root; mtime is the
 * package file's mtime. File entries whose joined path fails
 * brix_rpm_path_sane() are dropped from the XML and counted into *skipped
 * (may be NULL) — metadata may not traverse. 0 ok / -1 + err. */
int brix_repomd_render(brix_rpm_pkg_t *p, const char *href, int64_t mtime,
                       char **primary, char **filelists, char **other,
                       uint32_t *skipped, char *err, size_t errlen);

/* render + append in one step (the no-cache path). */
int brix_repomd_add(brix_repomd_t *w, brix_rpm_pkg_t *p, const char *href,
                    int64_t mtime, uint32_t *skipped, char *err,
                    size_t errlen);

/* Append pre-rendered fragments (the `--update` cache-hit path). */
int brix_repomd_add_fragments(brix_repomd_t *w, const char *primary,
                              const char *filelists, const char *other,
                              char *err, size_t errlen);

/* Gzip + checksum-name + stage/rename the three documents, then write
 * repomd.xml last. Consumes the writer on success. 0 ok / -1 + err (the
 * writer stays live for abort). */
int brix_repomd_finish(brix_repomd_t *w, char *err, size_t errlen);

/* Drop an unfinished run (nothing on disk is touched before finish). */
void brix_repomd_abort(brix_repomd_t *w);

#endif /* BRIX_RPM_REPOMD_WRITE_H */
