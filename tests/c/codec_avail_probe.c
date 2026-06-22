/*
 * codec_avail_probe.c — print "<name> <0|1>" availability for every codec.
 *
 * Used by the phase-42 build matrix (tests/test_compression_build_matrix.py) to
 * verify per-codec graceful degradation: the probe is compiled once per matrix
 * cell with a different subset of -DXROOTD_HAVE_* flags + linked libs, and the
 * test asserts the codec dropped from that cell reports available=0 while the
 * codecs kept in the cell report available=1 (codecs are independent — dropping
 * one never disables another, and the table never has a hole).
 */
#include "codec_core.h"

#include <stdio.h>
#include <stddef.h>

int
main(void)
{
    const struct { xrootd_codec_id_t id; const char *name; } codecs[] = {
        { XROOTD_CODEC_GZIP,   "gzip"   },
        { XROOTD_CODEC_ZSTD,   "zstd"   },
        { XROOTD_CODEC_XZ,     "xz"     },
        { XROOTD_CODEC_BROTLI, "brotli" },
        { XROOTD_CODEC_BZIP2,  "bzip2"  },
        { XROOTD_CODEC_LZ4,    "lz4"    },
    };
    size_t i;

    for (i = 0; i < sizeof(codecs) / sizeof(codecs[0]); i++) {
        /* a descriptor MUST always exist (dense table, no holes) even when the
         * codec's lib is absent — print availability for the matrix to check. */
        const xrootd_codec_desc_t *d = xrootd_codec_by_id(codecs[i].id);
        printf("%s %d\n", codecs[i].name,
               (d != NULL && xrootd_codec_available(codecs[i].id)) ? 1 : 0);
    }
    return 0;
}
