#ifndef BRIX_SSI_CTA_PB_WIRE_H
#define BRIX_SSI_CTA_PB_WIRE_H

/*
 * pb_wire.h — minimal protobuf wire-format primitives (no external library).
 *
 * WHAT: bounds-checked readers and appenders for the protobuf binary encoding —
 *       varints, tags (field<<3 | wiretype), length-delimited fields, and a
 *       field skipper for unknown fields.
 * WHY:  the CTA SSI messages are protobuf; we decode/encode exactly the fields we
 *       use without pulling in protobuf-c or generated code. Pure C, standalone-
 *       testable.
 * HOW:  every reader takes a {p, end} cursor and fails (returns -1) rather than
 *       reading past end — the input is untrusted. Writers append into a
 *       caller-sized buffer and fail on overflow.
 */

#include <stddef.h>
#include <stdint.h>

/* protobuf wire types */
#define PB_WT_VARINT 0
#define PB_WT_I64    1
#define PB_WT_LEN    2
#define PB_WT_I32    5

typedef struct {
    const unsigned char *p;
    const unsigned char *end;
} pb_reader;

typedef struct {
    unsigned char *p;
    size_t         len;   /* bytes written so far */
    size_t         cap;   /* capacity of p */
} pb_writer;

/* Readers — return 0 on success, -1 on malformed/overrun. */
int pb_read_varint(pb_reader *r, uint64_t *out);
int pb_read_tag(pb_reader *r, uint32_t *field, int *wiretype);
int pb_read_len_delim(pb_reader *r, const unsigned char **data, size_t *len);
int pb_skip_field(pb_reader *r, int wiretype);

/* Writers — return 0 on success, -1 on buffer overflow. */
int pb_write_varint(pb_writer *w, uint64_t v);
int pb_write_tag(pb_writer *w, uint32_t field, int wiretype);
int pb_write_len_delim(pb_writer *w, uint32_t field,
                       const unsigned char *data, size_t len);
int pb_write_string(pb_writer *w, uint32_t field, const char *s);
int pb_write_varint_field(pb_writer *w, uint32_t field, uint64_t v);

#endif /* BRIX_SSI_CTA_PB_WIRE_H */
