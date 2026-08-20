/*
 * brixoci_internal.h - split contract for the brixoci personality
 * (brixoci.c front-end / brixoci_copy.c pump). Not a public API.
 */
#ifndef BRIXOCI_INTERNAL_H
#define BRIXOCI_INTERNAL_H

#include "oci/ref.h"
#include "oci/reg_client.h"
#include "oci/layout.h"

/* Malformed command line discovered below the arg parser (bad ref, bad
 * oci: spec). Distinct from the registry result codes so main can map it
 * onto exit 2 instead of 6. */
#define BRIXOCI_EUSAGE (-100)

/* `gc --grace` default: the window in which an unreferenced blob is assumed
 * to belong to a push whose manifest has not landed yet. An hour is far past
 * the gap between an upload sealing and its manifest PUT, and far short of
 * "the operator will notice the space is still gone". */
#define BRIXOCI_GC_GRACE 3600

/* The common flags, parsed once in brixoci_main. */
typedef struct {
    const char *token_file;   /* --token-file: static bearer */
    const char *cert;         /* --cert / --key: mutual TLS */
    const char *key;
    const char *platform;     /* --platform os/arch[/variant] */
    const char *tag;          /* convert --tag: destination-layout ref */
    const char *to_dir;       /* pull --to */
    const char *from_dir;     /* push --from */
    long        grace;        /* gc --grace, seconds */
    int         insecure;     /* --insecure: plain http + no verify */
    int         raw;          /* inspect --raw */
    int         dry_run;      /* gc --dry-run: report, remove nothing */
    int         json;         /* gc --json: machine-readable counters */
    int         estargz;      /* convert --estargz: the only encoding */
} brixoci_opts_t;

/* One transfer endpoint: a registry ref or an `oci:DIR` image layout. */
typedef struct {
    int               is_layout;
    brix_oci_ref_t    ref;        /* registry endpoints only */
    brix_oci_reg_t    reg;
    char              name[256];  /* effective repository name */
    brix_oci_layout_t lay;        /* layout endpoints only */
} brixoci_end_t;

/* brixoci.c: open an endpoint from its spec text, applying the auth
 * material from `o` (+ the combined client PEM path, may be "") to
 * registry endpoints. create=1 initializes a missing layout. */
int brixoci_end_open(brixoci_end_t *e, const char *spec, int create,
                     const brixoci_opts_t *o, const char *client_pem,
                     char *err, size_t errlen);

/* brixoci_copy.c: the one pump behind pull/push/copy — source manifest,
 * every referenced blob, then the manifest binding. digest_out (may be
 * NULL) receives the copied manifest's "<alg>:<hex>". */
int brixoci_copy_run(brixoci_end_t *src, brixoci_end_t *dst,
                     const brixoci_opts_t *o, char *digest_out, size_t dlen,
                     char *err, size_t errlen);

/* brixoci_copy.c seams the converter shares with the pump, so both refuse
 * the same inputs and bind under the same tag conventions:
 *   src_manifest  — resolve the source manifest (registry or layout);
 *   is_index      — an image index, by media type OR by carrying a
 *                   "manifests" array (a registry that mislabels one must
 *                   still be refused, not walked as if it had layers);
 *   xfer_tags     — which tag selects the source and which one the result
 *                   is bound under;
 *   fd_pump       — sequential fd → fd copy;
 *   put_manifest  — bind a manifest body at the destination.
 */
int brixoci_src_manifest(brixoci_end_t *s, const char *seltag,
                         const brixoci_opts_t *o, brix_oci_desc_t *m,
                         char *err, size_t errlen);
int brixoci_is_index(const brix_oci_desc_t *m);
void brixoci_xfer_tags(const brixoci_end_t *src, const brixoci_end_t *dst,
                       const char **seltag, const char **bindtag);
int brixoci_fd_pump(int in_fd, int out_fd, char *err, size_t errlen);
int brixoci_put_manifest(brixoci_end_t *d, const char *bindtag,
                         const brix_oci_desc_t *m, char *digest_out,
                         size_t dlen, char *err, size_t errlen);

/* brixoci_convert.c: re-encode every layer of one image into eStargz and
 * bind the rewritten manifest at the destination. Conversion changes both
 * the layer digests and their diff_ids, so the config's rootfs.diff_ids and
 * the manifest descriptors are rebuilt from what the writer reports. */
int brixoci_convert_run(brixoci_end_t *src, brixoci_end_t *dst,
                        const brixoci_opts_t *o, char *digest_out,
                        size_t dlen, char *err, size_t errlen);

/* brixoci_gc.c: mark-and-sweep one on-disk registry store root (pos[0]),
 * reclaiming the blobs, layer marks and referrer descriptors that the
 * request handlers deliberately leave behind. */
int brixoci_gc_run(const brixoci_opts_t *o, const char **pos, int npos,
                   char *err, size_t errlen);

#endif /* BRIXOCI_INTERNAL_H */
