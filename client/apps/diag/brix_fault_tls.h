/*
 * brix_fault_tls.h — pure TLS record-layer surgery for brix-fault-proxy.
 *
 * A TLS/DTLS stream on the wire is a sequence of records, each a 5-byte header
 * ([content-type][version-major][version-minor][length-hi][length-lo]) followed
 * by `length` payload bytes.  An on-path adversary who cannot decrypt the record
 * bodies can still attack the RECORD LAYER: re-fragment records to stress a
 * peer's reassembly, lie about a record's declared length (stall the parser),
 * relabel a record's content-type (present application-data as handshake), flip a
 * ciphertext byte so the MAC check fails, drop records of a chosen type, forge a
 * plaintext alert record, or downgrade the record-layer version.
 *
 * These are the record-framing bugs a hardened TLS client/server must survive.
 * Everything here is a PURE function over caller buffers — no globals, no I/O —
 * so the relay snapshots its (locked) config and calls in from the hot path, and
 * unit tests exercise the record math directly.  Operates per read-buffer
 * (best-effort across a record split by TCP segmentation, like the length-mangle
 * lever): a record header straddling two reads is passed through untouched.
 */
#ifndef BRIX_FAULT_TLS_H
#define BRIX_FAULT_TLS_H

#include <stddef.h>

/* Per-direction TLS record-surgery config.  Sentinel -1 (or 0 for frag/inflate/
 * flip) disables an op; fp_tls_cfg_init() installs those defaults. */
typedef struct {
    int frag_max;       /* >0: re-fragment each record to <= this payload size   */
    int set_type;       /* >=0: overwrite every record's content-type byte        */
    int set_ver_major;  /* >=0: overwrite the record version high byte             */
    int set_ver_minor;  /* >=0: overwrite the record version low byte              */
    int inflate_len;    /* !=0: add this to each record's declared length field    */
    int flip_payload;   /* 1: XOR-flip the first payload byte of each record       */
    int drop_type;      /* >=0: drop records whose content-type equals this        */
    int alert_level;    /* >=0: prepend ONE forged alert record (consumed once)    */
    int alert_desc;     /* alert description byte for the forged alert             */
} fp_tls_cfg;

/* Tallies accumulated by fp_tls_rewrite() (added, not reset). */
typedef struct {
    unsigned long records;     /* records seen */
    unsigned long fragmented;  /* fragments emitted by re-fragmentation */
    unsigned long flipped;     /* records whose payload byte was flipped */
    unsigned long dropped;     /* records dropped by drop-type */
    unsigned long alerts;      /* forged alert records emitted */
    unsigned long retyped;     /* records whose content-type was rewritten */
} fp_tls_stats;

/* Install the "all off" defaults (sentinels) into *c. */
void fp_tls_cfg_init(fp_tls_cfg *c);

/* True if any op in *c is active. */
int fp_tls_active(const fp_tls_cfg *c);

/* Rewrite the TLS record stream in `in[0..n)` into `out` (capacity `outcap`),
 * applying *c.  A one-shot forged alert (alert_level>=0) is emitted first and
 * then cleared IN *c (so pass a mutable snapshot).  Returns the produced length;
 * never writes past `outcap`.  Tallies land in *st. */
size_t fp_tls_rewrite(const unsigned char *in, size_t n,
                      unsigned char *out, size_t outcap,
                      fp_tls_cfg *c, fp_tls_stats *st);

#endif /* BRIX_FAULT_TLS_H */
