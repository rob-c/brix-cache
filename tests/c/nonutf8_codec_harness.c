/*
 * nonutf8_codec_harness.c — data-driven driver for the pure byte-input kernels
 * every non-UTF8 user input flows through before auth or storage sees it:
 *
 *   - brix_http_urldecode / brix_http_urlencode (src/core/compat/uri.c) — THE
 *     percent-codec shared by WebDAV path/query, S3 SigV4 canonicalisation and
 *     key parsing, and XrdHttp path handling. Byte-transparent: %FF -> 0xFF.
 *   - brix_opaque_illegal_byte (src/protocols/root/path/opaque_validate.c) — the
 *     one gate that rejects non-ASCII/control/metacharacter bytes in the XRootD
 *     CGI opaque string (the everything-after-'?' of a wire path).
 *
 * The harness links the REAL production objects (no reimplementation) and speaks
 * a tiny line protocol on stdin so a Python suite can parametrise thousands of
 * byte vectors against it. All I/O is hex so any byte — NUL, CR/LF, 0x80-0xFF —
 * travels on one line unambiguously.
 *
 * Input line grammar (fields single-space separated; "." == empty byte string):
 *   d <flags:int> <dstsz:int> <hexin>   decode  -> "<rc> <outlen> <hexout>"
 *   e <safe|-> <dstsz:int> <hexin>      encode  -> "<rc> <outlen> <hexout>"
 *   r <flags:int> <dstsz:int> <hexin>   encode-then-decode round trip (same out)
 *   o <hexin>                           opaque byte gate -> "<rc> <badbyte|-1>"
 *   s <hexin>                           opaque schema gate -> "<rc> <keylen> <keyhex>"
 *   n <hexin>                           internal-name gate -> "<rc>" (1 hidden / 0 visible)
 *
 * For d/r, <rc> is a BRIX_URLDECODE_* code; on OK the output is the decoded C
 * string (strlen view — an embedded decoded NUL truncates it, which is exactly
 * what the C-string callers downstream see). For e, <rc> is the encoder's return
 * (byte count, or -1 on overflow). For o, <rc> is 1 (illegal byte found, decimal
 * value in field 2) or 0 (all bytes permitted, field 2 == -1). For s, <rc> is a
 * BRIX_OPAQUE_SCHEMA_* verdict and the trailing hex is the offending key the gate
 * copied out ("." when empty) — that echoed key is logged/named downstream, so its
 * byte-transparency on a non-UTF8 key is itself part of "handled correctly".
 *
 * Pure libc + the real kernels; no nginx runtime, no sockets, no live server.
 * Compiled and run by tests/cmdscripts/nonutf8_codec.py (see tests/test_nonutf8_input.py).
 */

#include "core/compat/uri.h"
#include "core/compat/hex.h"
#include "protocols/root/path/opaque_validate.h"
#include "fs/path/reserved_names.h"      /* header-only static-inline gate */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IN_CAP   (64 * 1024)
#define DST_CAP  (256 * 1024)

/* Decode one hex token into out[]; returns byte count, or -1 on malformed hex.
 * "." denotes the empty byte string. */
static long
unhex(const char *tok, unsigned char *out, size_t out_cap)
{
    size_t n, m, i;

    if (tok == NULL) {
        return -1;
    }
    if (strcmp(tok, ".") == 0) {
        return 0;
    }

    n = strlen(tok);
    if (n % 2 != 0) {
        return -1;
    }
    m = n / 2;
    if (m > out_cap) {
        return -1;
    }

    for (i = 0; i < m; i++) {
        int hi = brix_hex_from_char((unsigned char) tok[2 * i]);
        int lo = brix_hex_from_char((unsigned char) tok[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (unsigned char) ((hi << 4) | lo);
    }
    return (long) m;
}

/* Emit "<rc> <len> <hexout>" — hexout is "." for the empty output. */
static void
emit(int rc, const unsigned char *buf, long len)
{
    char *h;

    if (len <= 0) {
        printf("%d 0 .\n", rc);
        return;
    }
    h = malloc((size_t) len * 2 + 1);
    if (h == NULL) {
        printf("%d 0 .\n", rc);        /* OOM: degrade to empty, never crash */
        return;
    }
    brix_hex_encode(buf, (size_t) len, h);
    printf("%d %ld %s\n", rc, len, h);
    free(h);
}

static void
do_decode(unsigned flags, size_t dst_sz, const char *hexin,
    unsigned char *in, char *dst)
{
    long inlen = unhex(hexin, in, IN_CAP);
    int  rc;

    if (inlen < 0) {
        printf("ERR badhex\n");
        return;
    }
    if (dst_sz > DST_CAP) {
        dst_sz = DST_CAP;
    }
    rc = brix_http_urldecode(in, (size_t) inlen, dst, dst_sz, flags);
    if (rc == BRIX_URLDECODE_OK) {
        emit(rc, (const unsigned char *) dst, (long) strlen(dst));
    } else {
        emit(rc, NULL, 0);
    }
}

static void
do_encode(const char *safe, size_t dst_sz, const char *hexin,
    unsigned char *in, char *dst)
{
    long    inlen = unhex(hexin, in, IN_CAP);
    ssize_t rc;

    if (inlen < 0) {
        printf("ERR badhex\n");
        return;
    }
    if (dst_sz > DST_CAP) {
        dst_sz = DST_CAP;
    }
    rc = brix_http_urlencode(in, (size_t) inlen, dst, dst_sz,
        (strcmp(safe, "-") == 0) ? NULL : safe);
    if (rc >= 0) {
        emit((int) rc, (const unsigned char *) dst, (long) rc);
    } else {
        emit(-1, NULL, 0);
    }
}

static void
do_roundtrip(unsigned flags, size_t dst_sz, const char *hexin,
    unsigned char *in, char *dst)
{
    long    inlen = unhex(hexin, in, IN_CAP);
    char   *mid;
    ssize_t enc;
    int     rc;

    if (inlen < 0) {
        printf("ERR badhex\n");
        return;
    }
    mid = malloc((size_t) inlen * 3 + 1);      /* worst case %XX expansion + NUL */
    if (mid == NULL) {
        printf("ERR oom\n");
        return;
    }
    enc = brix_http_urlencode(in, (size_t) inlen, mid,
        (size_t) inlen * 3 + 1, NULL);
    if (enc < 0) {
        free(mid);
        printf("ERR encfail\n");
        return;
    }
    if (dst_sz > DST_CAP) {
        dst_sz = DST_CAP;
    }
    rc = brix_http_urldecode((const unsigned char *) mid, (size_t) enc,
        dst, dst_sz, flags);
    if (rc == BRIX_URLDECODE_OK) {
        emit(rc, (const unsigned char *) dst, (long) strlen(dst));
    } else {
        emit(rc, NULL, 0);
    }
    free(mid);
}

static void
do_opaque(const char *hexin, unsigned char *in)
{
    long          inlen = unhex(hexin, in, IN_CAP - 1);
    unsigned char bad = 0;
    int           rc;

    if (inlen < 0) {
        printf("ERR badhex\n");
        return;
    }
    in[inlen] = '\0';                          /* NUL-terminate for the C-string API */
    rc = brix_opaque_illegal_byte((const char *) in, &bad);
    if (rc) {
        printf("1 %u\n", (unsigned) bad);
    } else {
        printf("0 -1\n");
    }
}

/* Tier-2 schema gate: emit "<verdict> <offending-key-hex|.>". The key the gate
 * copies out is what a rejection log/message names, so we round-trip it as hex
 * to prove a non-UTF8 key survives byte-for-byte (no truncation, no mojibake). */
#define KEYBUF_CAP 256
static void
do_schema(const char *hexin, unsigned char *in)
{
    long inlen = unhex(hexin, in, IN_CAP - 1);
    char keybuf[KEYBUF_CAP];
    int  rc;

    if (inlen < 0) {
        printf("ERR badhex\n");
        return;
    }
    in[inlen] = '\0';                          /* NUL-terminate for the C-string API */
    keybuf[0] = '\0';
    rc = brix_opaque_schema_check((const char *) in, keybuf, sizeof keybuf);
    emit(rc, (const unsigned char *) keybuf, (long) strlen(keybuf));
}

/* Internal-name (invisible sidecar/temp) gate on the NUL-terminated basename:
 * emit just the verdict (1 = hidden/NotFound, 0 = client-visible). A non-UTF8
 * basename must be classified byte-exactly — a high-byte stem ending in a
 * reserved suffix must still be hidden, and no lone byte may be misclassified. */
static void
do_internal_name(const char *hexin, unsigned char *in)
{
    long inlen = unhex(hexin, in, IN_CAP - 1);

    if (inlen < 0) {
        printf("ERR badhex\n");
        return;
    }
    in[inlen] = '\0';                          /* NUL-terminate for the C-string API */
    printf("%d\n", brix_is_internal_name((const char *) in));
}

int
main(void)
{
    char          *line = NULL;
    size_t         cap = 0;
    ssize_t        len;
    unsigned char *in  = malloc(IN_CAP);
    char          *dst = malloc(DST_CAP);

    if (in == NULL || dst == NULL) {
        fprintf(stderr, "harness: OOM\n");
        return 2;
    }

    while ((len = getline(&line, &cap, stdin)) != -1) {
        char *op, *a, *b, *c;

        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        if (line[0] == '\0' || line[0] == '#') {
            continue;                          /* blank / comment: no output line */
        }

        op = strtok(line, " ");
        if (op == NULL) {
            printf("ERR empty\n");
            continue;
        }

        if (strcmp(op, "d") == 0 || strcmp(op, "r") == 0) {
            a = strtok(NULL, " ");             /* flags */
            b = strtok(NULL, " ");             /* dstsz */
            c = strtok(NULL, " ");             /* hexin */
            if (a == NULL || b == NULL || c == NULL) {
                printf("ERR args\n");
                continue;
            }
            if (op[0] == 'd') {
                do_decode((unsigned) strtoul(a, NULL, 10),
                    (size_t) strtoul(b, NULL, 10), c, in, dst);
            } else {
                do_roundtrip((unsigned) strtoul(a, NULL, 10),
                    (size_t) strtoul(b, NULL, 10), c, in, dst);
            }
        } else if (strcmp(op, "e") == 0) {
            a = strtok(NULL, " ");             /* safe | - */
            b = strtok(NULL, " ");             /* dstsz */
            c = strtok(NULL, " ");             /* hexin */
            if (a == NULL || b == NULL || c == NULL) {
                printf("ERR args\n");
                continue;
            }
            do_encode(a, (size_t) strtoul(b, NULL, 10), c, in, dst);
        } else if (strcmp(op, "o") == 0) {
            a = strtok(NULL, " ");             /* hexin */
            if (a == NULL) {
                printf("ERR args\n");
                continue;
            }
            do_opaque(a, in);
        } else if (strcmp(op, "s") == 0) {
            a = strtok(NULL, " ");             /* hexin */
            if (a == NULL) {
                printf("ERR args\n");
                continue;
            }
            do_schema(a, in);
        } else if (strcmp(op, "n") == 0) {
            a = strtok(NULL, " ");             /* hexin */
            if (a == NULL) {
                printf("ERR args\n");
                continue;
            }
            do_internal_name(a, in);
        } else {
            printf("ERR op\n");
        }
    }

    free(line);
    free(in);
    free(dst);
    return 0;
}
