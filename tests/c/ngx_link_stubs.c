/* ngx_link_stubs.c — the two nginx globals a unit test inherits when it links
 * one of nginx's OWN objects.
 *
 * NOT a test: it defines no main and is compiled INTO the sd_remote runners
 * alongside their test file (see _sd_remote_objs in
 * tests/cmdscripts/c_regression_units_part2.py).
 *
 * WHY it exists: nginx's string kernel (ngx_string.o) and its allocator closure
 * (ngx_palloc.o, ngx_alloc.o) reference `ngx_cycle` and `ngx_log_error_core`,
 * which live in objects a unit test has no business linking (the whole cycle,
 * the log machinery, the event loop). Every unit that needs a real
 * ngx_decode_base64 therefore needs these two definitions — and the rule is that
 * such a unit must never stub an ngx_string.c FUNCTION, only these globals.
 *
 * WHY shared: the sd_remote closure grew nginx's string kernel the day the
 * driver table gained the checksum-offload slot (digest_header.c decodes base64),
 * so five existing units needed them at once. Five copies of the same block is
 * how a duplication gate earns its keep; one file is the answer.
 *
 * Instances under test are built with log=NULL, so nothing ever calls the log
 * hook — it exists to satisfy the linker, and doing nothing is the correct body.
 */

#include <ngx_config.h>
#include <ngx_core.h>

volatile ngx_cycle_t *ngx_cycle = NULL;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}
