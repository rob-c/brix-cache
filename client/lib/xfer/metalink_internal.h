/*
 * metalink_internal.h — private split contract of the metalink parser.
 *
 * WHAT: One concept: the bounded XML lexing primitives the two phase-100
 *       metalink TUs exchange — metalink_lex.c owns tag/attribute/text
 *       extraction and entity decoding; metalink.c owns the document semantics
 *       (ranking, digest folding, file-scope collection, the public API).
 * WHY:  metalink.c alone crossed the 600-line file gate, and the two layers are
 *       genuinely separable: the lexer knows nothing about mirrors or digests,
 *       and the semantics layer never touches a byte offset. Splitting on that
 *       line keeps each TU one concept (coding-standards §1) and gives the
 *       hostile-input lexing rules their own doc surface.
 * HOW:  Both TUs include this after copy_internal.h. Every routine here is
 *       bounded by an explicit `end`/`gt` pointer and never allocates — the
 *       parser's purity contract holds across the split.
 *
 * Requires: copy_internal.h before inclusion. Not a public API: include only
 * from client/lib/xfer/.
 */
#pragma once

/* Case-insensitive bounded substring search over [p,end); NULL when absent. */
const char *ml_find_ci(const char *p, const char *end, const char *needle);

/* Next `<name` in [p,end) with a real name boundary, so "<url" never matches
 * "<urlfoo". Returns the '<', or NULL. attrs_out/gt_out (may be NULL) receive
 * the attribute-window start and the tag's '>'. */
const char *ml_tag_open(const char *p, const char *end, const char *name,
                        const char **attrs_out, const char **gt_out);

/* `name="value"` inside the attribute window [attrs,gt), entity-decoded into
 * out[outsz]. Returns 0 when found and it fits, -1 otherwise. */
int ml_attr(const char *attrs, const char *gt, const char *name,
            char *out, size_t outsz);

/* Element text between the opening tag's `gt` and `</name`, whitespace-trimmed
 * and entity-decoded into out[outsz]. Returns 0, or -1 (no close tag / no fit). */
int ml_elem_text(const char *gt, const char *end, const char *name,
                 char *out, size_t outsz);
