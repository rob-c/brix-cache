/*
 * xrdcp_parse_internal.h — private split contract of the xrdcp CLI parser.
 *
 * WHAT: One concept: the option groups xrdcp_parse.c's fan-out reaches in a
 *       sibling TU. Today that is the transport-posture family.
 * WHY:  xrdcp_parse.c crossed the 600-line file gate. The transport options are
 *       the natural first tenant of a sibling TU: they form a closed family
 *       expressed as a descriptor table (coding-standards §8.6) and, unlike the
 *       manifest / filter / credential groups, they write only to the copy
 *       options — so the contract needs no access to the parser's private CLI
 *       scratch state.
 * HOW:  Both TUs include this after xrdcp_internal.h (which supplies
 *       brix_copy_opts). Return convention matches the rest of the fan-out:
 *       1 = consumed, 0 = not mine, 50 = usage error (already reported).
 *
 * Requires: xrdcp_internal.h before inclusion. Not a public API: include only
 * from client/apps/copy/.
 */
#pragma once

/* Consume one transport-posture option at argv[*i], advancing *i past any
 * value it takes. Returns 1 when consumed, 0 when the argument belongs to
 * another group, 50 on a bad value (message + usage already printed). */
int xrdcp_parse_transport_option(brix_copy_opts *o, int argc, char **argv,
                                 size_t *i);

/* Post-argv validation + finalization (xrdcp_parse_validate.c): flag-matrix
 * checks, destination/source-list assembly, journal + resilience posture.
 * Returns 0 on success, 50 on usage error, 51 on OOM — exactly the codes
 * parse_and_validate_args propagates. */
int xrdcp_validate_and_finalize_args(xrdcp_opts_t *o, xrdcp_lists_t *l,
                                     const char *prog);
