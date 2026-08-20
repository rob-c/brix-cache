/* brixcvmfs_ingest_diffid.c — `ingest image --verify-diffids` (phase-104 D8.e).
 *
 * WHAT: compare the diff_ids captured while flattening an image's layers
 *       against the rootfs.diff_ids the image *config* declares.
 * WHY:  the manifest names compressed blobs and ingest verifies those on
 *       fetch — that is the transport identity. The config names the
 *       UNCOMPRESSED layer hashes, and nothing else in the pipeline reads
 *       them, so a registry whose manifest and config disagree about which
 *       bytes the image is made of is visible only here. Off by default: the
 *       check costs no second inflate (tar_digest.c rides the flattener's
 *       own decompression) but it does mean the config must be trusted, so
 *       it stays a typed decision by the operator.
 * HOW:  tool surface (G14), libc + the shared digest/JSON grammars. Fails
 *       closed: an unreadable, oversized or malformed config is a refusal,
 *       never a pass.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "brixcvmfs_ingest_internal.h"
#include "core/compat/json_iter.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ING_CONFIG_MAX (1u << 20)      /* an image config is kilobytes */

/* Whole small file into a fresh buffer. 0 / -1 (absent, empty, oversized or
 * short read — every one of them fails the verification closed). */
static int diffid_slurp(const char *path, char **out, size_t *outlen) {
    struct stat sb;
    char       *buf;
    ssize_t     got;
    int         fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        return -1;
    if (fstat(fd, &sb) != 0 || sb.st_size <= 0
        || sb.st_size > (off_t) ING_CONFIG_MAX
        || (buf = malloc((size_t) sb.st_size)) == NULL) {
        close(fd);
        return -1;
    }
    got = read(fd, buf, (size_t) sb.st_size);
    close(fd);
    if (got != (ssize_t) sb.st_size) {
        free(buf);
        return -1;
    }
    *out    = buf;
    *outlen = (size_t) got;
    return 0;
}

/* One `"sha256:…"` element of rootfs.diff_ids against layer i's captured
 * hash. The element arrives as a raw span, quotes included. */
static int diffid_cmp(const ing_diffid_t *hex, int n, int i,
                      const char *el, size_t en) {
    brix_oci_digest_t d;
    char              detail[224];

    if (i >= n)
        return bci_fail(ING_FAIL, "image config declares more diff_ids than"
                        " the manifest has layers", NULL);
    if (en < 2 || el[0] != '"'
        || brix_oci_digest_parse(el + 1, en - 2, &d) != 0)
        return bci_fail(ING_FAIL, "malformed diff_id in image config", NULL);
    if (strcmp(d.hex, hex[i]) == 0)
        return ING_OK;
    snprintf(detail, sizeof(detail),
             "layer %d: config says sha256:%s, the layer bytes hash to"
             " sha256:%s", i, d.hex, hex[i]);
    return bci_fail(ING_FAIL, "diff_id mismatch", detail);
}

int bci_diffids_verify(const char *config_path, const ing_diffid_t *hex,
                       int n) {
    char       *body;
    const char *rootfs, *arr, *el;
    size_t      len, rn, an, en, cur = 0;
    int         i = 0, st = 0, rc = ING_OK;

    if (diffid_slurp(config_path, &body, &len) != 0)
        return bci_fail(ING_FAIL, "cannot read config sidecar", config_path);
    if (brix_json_get_raw(body, len, "rootfs", &rootfs, &rn) != 1
        || brix_json_get_raw(rootfs, rn, "diff_ids", &arr, &an) != 1) {
        free(body);
        return bci_fail(ING_FAIL, "image config has no rootfs.diff_ids", NULL);
    }
    while (rc == ING_OK
           && (st = brix_json_arr_next(arr, an, &cur, &el, &en)) == 1)
        rc = diffid_cmp(hex, n, i++, el, en);
    free(body);
    if (rc != ING_OK)
        return rc;
    if (st < 0)
        return bci_fail(ING_FAIL, "malformed rootfs.diff_ids array", NULL);
    if (i != n)
        return bci_fail(ING_FAIL, "image config declares fewer diff_ids than"
                        " the manifest has layers", NULL);
    printf("verified %d diff_id%s against the image config\n",
           i, i == 1 ? "" : "s");
    return ING_OK;
}
