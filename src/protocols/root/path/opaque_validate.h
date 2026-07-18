#ifndef BRIX_OPAQUE_VALIDATE_H
#define BRIX_OPAQUE_VALIDATE_H

#include <stddef.h>

/*
 * opaque_validate.h — ABI for the two-tier XRootD CGI opaque gate
 * (hyper-hardening-plan §D-2). Pure C, no nginx/libc-string deps: safe to
 * include from the wire edge and from a standalone unit test alike.
 *
 * Tier 1 — byte-hygiene (always on): brix_opaque_illegal_byte() rejects a
 *          control / non-ASCII / shell-metacharacter byte before any handler
 *          parses, logs, or forwards the string. Zero false positives — a
 *          conforming client percent-encodes anything outside the set.
 *
 * Tier 2 — schema (opt-in via brix_opaque_strict): brix_opaque_schema_check()
 *          parses the key=value pairs and enforces (a) a positive-integer type
 *          on the keys brix assigns a type to (oss.asize) and (b) a recognized-
 *          namespace vocabulary, rejecting a key in no known namespace. OFF by
 *          default — stock XRootD leaves both unenforced, so enabling it is an
 *          operator's deliberate posture choice and cannot regress parity.
 */

/*
 * Tier 1. Returns 1 (and, if bad != NULL, the offending byte) when opaque[]
 * carries a byte outside the set a well-formed opaque needs; else 0 (including
 * the NULL / empty string).
 */
int brix_opaque_illegal_byte(const char *opaque, unsigned char *bad);

/* Tier-2 verdicts. */
#define BRIX_OPAQUE_SCHEMA_OK           0  /* every key recognized, typed values conform */
#define BRIX_OPAQUE_SCHEMA_BAD_TYPE     1  /* a typed key carried a non-conforming value */
#define BRIX_OPAQUE_SCHEMA_UNKNOWN_KEY  2  /* a key outside every recognized namespace */

/*
 * Tier 2. Walk the '&'-separated key=value pairs of a NUL-terminated opaque and
 * return the first schema violation, or BRIX_OPAQUE_SCHEMA_OK when every key is
 * recognized and every typed value conforms (NULL / empty opaque is OK).
 *
 * On a violation the offending key is copied (truncated, always NUL-terminated)
 * into keybuf[0..keybuf_len) when keybuf != NULL, so the caller can name it in
 * the rejection. keybuf is left as an empty string on OK.
 */
int brix_opaque_schema_check(const char *opaque, char *keybuf, size_t keybuf_len);

#endif /* BRIX_OPAQUE_VALIDATE_H */
