/* mediatypes.h — the OCI/Docker media-type string table (phase-104 §0.7.3).
 *
 * WHAT: every registry media-type string the tools branch on, named once.
 * WHY:  the mirror round-trips Content-Type byte-exact and never branches on
 *       it; the TOOLS (brixoci pull, brixcvmfs ingest) must branch — index vs
 *       manifest, gzip vs zstd layer — and a typo'd string literal at a call
 *       site is an invisible bug. This header is the only place the strings
 *       appear (grep-enforceable), shared by client tools and the server's
 *       Accept-header builder alike.
 * HOW:  plain #defines so they concatenate into Accept lines at compile time.
 */
#ifndef BRIX_OCI_MEDIATYPES_H
#define BRIX_OCI_MEDIATYPES_H

/* OCI image-spec types. */
#define OCI_MT_MANIFEST      "application/vnd.oci.image.manifest.v1+json"
#define OCI_MT_INDEX         "application/vnd.oci.image.index.v1+json"
#define OCI_MT_CONFIG        "application/vnd.oci.image.config.v1+json"
#define OCI_MT_LAYER_TAR     "application/vnd.oci.image.layer.v1.tar"
#define OCI_MT_LAYER_GZ      "application/vnd.oci.image.layer.v1.tar+gzip"
#define OCI_MT_LAYER_ZSTD    "application/vnd.oci.image.layer.v1.tar+zstd"

/* Docker Registry V2 legacy types (DockerHub still serves these). */
#define D2_MT_MANIFEST       "application/vnd.docker.distribution.manifest.v2+json"
#define D2_MT_LIST           "application/vnd.docker.distribution.manifest.list.v2+json"
#define D2_MT_CONFIG         "application/vnd.docker.container.image.v1+json"
#define D2_MT_LAYER_GZ       "application/vnd.docker.image.rootfs.diff.tar.gzip"
#define D2_MT_LAYER_FOREIGN  "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"

/* The Accept value a manifest request sends: every manifest-class type we can
 * consume, most-preferred first (what podman sends, W-1 observed six lines;
 * one joined header is wire-equivalent per RFC 9110 §5.2). */
#define OCI_ACCEPT_MANIFEST \
    OCI_MT_INDEX ", " OCI_MT_MANIFEST ", " D2_MT_LIST ", " D2_MT_MANIFEST

#endif /* BRIX_OCI_MEDIATYPES_H */
