/* name.h — OCI repository-name + tag grammar (phase-104 §0.7.2).
 *
 * WHAT: validate registry repository names ("library/alpine") and tag
 *       strings ("v1.2-rc1") against the Distribution-spec grammar.
 * WHY:  names and tags become cache-key material and store path components;
 *       one strict validator shared by the server classifier and the client
 *       tools means nothing traversal-shaped ever survives into a path. The
 *       enforced properties (§0.7.2) each carry a classifier unit test: no
 *       empty components, no leading/trailing separator runs, no "..", byte
 *       caps checked before any use.
 * HOW:  hand-rolled state walks over the byte grammar — no regex, no alloc,
 *       classify.c's discipline.
 *
 *   name      ::= component ("/" component)*        ; <= 255 bytes total
 *   component ::= [a-z0-9]+ (("." | "_" | "__" | "-"+) [a-z0-9]+)*
 *   tag       ::= [a-zA-Z0-9_] [a-zA-Z0-9._-]{0,127}
 */
#ifndef BRIX_OCI_NAME_H
#define BRIX_OCI_NAME_H

#include <stddef.h>

#define BRIX_OCI_NAME_MAX 255
#define BRIX_OCI_TAG_MAX  128

/* 0 = valid repository name, -1 = invalid. */
int brix_oci_name_valid(const char *s, size_t n);

/* 0 = valid tag, -1 = invalid. */
int brix_oci_tag_valid(const char *s, size_t n);

/* Slash-separated component count of a VALID name (callers validate first);
 * the DockerHub "library/" normalization keys off count == 1. */
int brix_oci_name_components(const char *s, size_t n);

#endif /* BRIX_OCI_NAME_H */
