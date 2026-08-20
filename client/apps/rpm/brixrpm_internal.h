/*
 * brixrpm_internal.h - split contract for the brixrpm personality
 * (brixrpm.c front-end / brixrpm_createrepo.c repo builder). Not a
 * public API.
 */
#ifndef BRIXRPM_INTERNAL_H
#define BRIXRPM_INTERNAL_H

#include "rpm/rpmhdr.h"
#include "rpm/repomd_write.h"

/* createrepo options, parsed once in brixrpm_main. Hrefs are always
 * emitted relative to the repo root; --baseurl-relative names that
 * default explicitly (accepted for createrepo_c muscle memory). */
typedef struct {
    const char *dir;        /* repo root to scan */
    int         update;     /* --update: reuse the .brixrpm-cache memo */
    int         strict;     /* --strict: unparsable .rpm is fatal, not a skip */
    int         paranoid;   /* --paranoid: memo hits are re-hashed, not trusted
                             * on (size, mtime) — see brixrpm_createrepo.c */
} brixrpm_cr_opts_t;

/* brixrpm_createrepo.c: scan <dir> for *.rpm, emit repodata/. Returns the
 * process exit code (0 ok · 1 failed). */
int brixrpm_createrepo(const brixrpm_cr_opts_t *o);

#endif /* BRIXRPM_INTERNAL_H */
