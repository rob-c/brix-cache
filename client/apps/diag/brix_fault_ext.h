/*
 * brix_fault_ext.h — pure, root-free stream-mutation + spoofing helpers that
 * extend brix-fault-proxy into a full on-path MITM for wild-internet hardening.
 *
 * These are the byte-surgery and forgery primitives an adversary between a public
 * client and a public service can apply WITHOUT touching the kernel: deleting or
 * duplicating individual bytes (framing desync / length-mismatch bugs), rewriting
 * a substring on the wire (mangle a Content-Length, flip a status line, poison a
 * checksum, inject a header), splicing bytes in (request smuggling / protocol
 * confusion), and prepending a forged PROXY-protocol header to make a service
 * trust an attacker-chosen source IP.
 *
 * Everything here is a PURE function over caller-owned buffers — no globals, no
 * sockets, no locks — so the relay can snapshot its (locked) config and call in
 * from the hot path, and the unit tests can exercise the byte math directly.
 */
#ifndef BRIX_FAULT_EXT_H
#define BRIX_FAULT_EXT_H

#include <stddef.h>

/* A snapshot of the payload-level mutation config for one direction. Byte
 * pointers are borrowed (the caller owns the storage for the call's duration).
 * A zero-length field disables that mutation. */
typedef struct {
    const unsigned char *find;      size_t find_len;    /* replace: needle */
    const unsigned char *repl;      size_t repl_len;    /* replace: replacement */
    const unsigned char *inject;    size_t inject_len;  /* one-shot prefix splice */
    int                  drop_ppm;    /* per-byte delete probability (ppm) */
    int                  repeat_ppm;  /* per-byte duplicate probability (ppm) */
} fp_ext_mut;

/* Event tallies accumulated by fp_ext_mutate() for the status oracle. */
typedef struct {
    unsigned long dropped;    /* bytes deleted */
    unsigned long repeated;   /* bytes duplicated */
    unsigned long injected;   /* bytes spliced in */
    unsigned long replaced;   /* substring matches rewritten */
} fp_ext_stats;

/* True if `m` has any active mutation (so the caller can skip the copy). */
int fp_ext_mut_active(const fp_ext_mut *m);

/* Transform `in[0..n)` into `out` (capacity `outcap`), applying — in order — the
 * one-shot inject prefix, then per byte: a non-overlapping `find`->`repl` rewrite,
 * else a probabilistic delete, else emit-and-maybe-duplicate.  `seed` is the
 * caller's private rand_r() state.  Never writes past `outcap` (a full buffer just
 * truncates the mutated output, which is itself a valid fault).  Returns the
 * produced length.  Tallies land in *st (added, not reset). */
size_t fp_ext_mutate(const unsigned char *in, size_t n,
                     unsigned char *out, size_t outcap,
                     const fp_ext_mut *m, unsigned *seed, fp_ext_stats *st);

/* Decode a control-plane payload token into raw bytes.  "hex:deadbeef" decodes
 * hex; "str:foo\r\n" (or a bare token) is taken literally with C escapes
 * \r \n \t \0 \xNN \\ honoured.  Returns the byte length, or -1 on a malformed
 * token.  Writes at most `cap` bytes. */
int fp_ext_parse_payload(const char *tok, unsigned char *out, size_t cap);

/* Build a PROXY-protocol v1 (human-readable) header for TCP4/TCP6 into `out`.
 * `src`/`dst` are "ip:port"; if `dst` is NULL the proxy's own endpoint is assumed
 * by the caller and should be passed in.  Returns the header length or -1. */
int fp_ext_proxy_v1(char *out, size_t cap, const char *src, const char *dst);

/* Build a PROXY-protocol v2 (binary) header.  Same argument contract; returns the
 * total header length or -1 (e.g. mixed/invalid families). */
int fp_ext_proxy_v2(unsigned char *out, size_t cap, const char *src, const char *dst);

#endif /* BRIX_FAULT_EXT_H */
