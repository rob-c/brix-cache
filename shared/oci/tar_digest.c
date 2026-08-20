/* tar_digest.c — diff-id capture over the tar reader (phase-104 D8.e).
 *
 * WHAT: the brix_tar_digest_* half of tar.h — a streaming sha256 of the
 *       *decompressed* layer stream, which is what an OCI image config
 *       calls a rootfs diff_id.
 * WHY:  a layer blob's own digest is the transport identity (verified on
 *       fetch); the diff_id is the identity the image *config* signs. They
 *       are different hashes of different bytes, so a registry that serves a
 *       manifest whose layers do not match its config is only visible from
 *       here. `ingest image --verify-diffids` is that check, and it costs no
 *       second inflate because the flattener is decompressing anyway.
 * HOW:  the hash rides brix_tar_src(), so every decompressed byte the reader
 *       produces is covered however it was consumed (header, body, skip).
 *       Finishing drains what the entry walk never reads — the padding past
 *       the end-of-archive marker, which the producer hashed into the
 *       diff_id — and only then finalizes.
 */
#include "oci/tar_internal.h"

#include <string.h>

int brix_tar_digest_enable(brix_tar_t *t) {
    if (t->dig_on)
        return 0;
    if (brix_oci_sha256_init(&t->dig) != 0)
        return brix_tar_fail(t, "diff-id: sha256 init failed");
    t->dig_on = 1;
    return 0;
}

int brix_tar_digest_finish(brix_tar_t *t, char *hex, size_t hexlen) {
    brix_oci_digest_t d;

    if (!t->dig_on)
        return brix_tar_fail(t, "diff-id: capture was never enabled");
    if (hexlen < BRIX_OCI_SHA256_HEXLEN + 1)
        return brix_tar_fail(t, "diff-id: output buffer too small");

    for (;;) {                       /* the tail the entry walk never reads */
        int got = brix_tar_src(t, t->body, sizeof(t->body));

        if (got < 0) {
            brix_oci_sha256_abort(&t->dig);
            t->dig_on = 0;
            return -1;               /* t->err is the source's own message */
        }
        if (got == 0)
            break;
    }

    t->dig_on = 0;
    if (brix_oci_sha256_final(&t->dig, &d) != 0)
        return brix_tar_fail(t, "diff-id: sha256 final failed");
    memcpy(hex, d.hex, BRIX_OCI_SHA256_HEXLEN + 1);
    return 0;
}
