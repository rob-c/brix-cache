/* Real connected sockets and UDP collectors exercise short-lived flow reports. */
#include "core/ngx_brix_module.h"
#include "observability/pmark/pmark.h"
#include <assert.h>

/* WHAT: Report one inherited connection to an inherited collector address.
 * WHY: Transfer direction and lifecycle must survive the short-lived path.
 * HOW: Use real endpoint queries and datagrams, with explicit invalid inputs. */
int main(int argc, char **argv)
{
    assert(argc == 6);
    ngx_cycle_t cycle = {0}; ngx_log_t log = {0}; ngx_cycle = &cycle;
    cycle.log = &log; cycle.hostname = (ngx_str_t) ngx_string("fixture");
    ngx_time_init();
    brix_pmark_conf_t conf = {0}; conf.firefly = 1;
    brix_pmark_dest_t dest = {0}; dest.len = sizeof(dest.ss);
    int collector = atoi(argv[3]);
    assert(getsockname(collector, (struct sockaddr *) &dest.ss, &dest.len) == 0);
    dest.family = dest.ss.ss_family;
    ngx_array_t destinations = {0};
    destinations.elts = &dest; destinations.nelts = 1; conf.dest_sa = &destinations;
    int fd = atoi(argv[2]); const char *mode = argv[1];
    if (!strcmp(mode, "disabled")) { conf.firefly = 0; }
    if (!strcmp(mode, "negative-fd")) { fd = -1; }
    if (!strcmp(mode, "bad-family")) { dest.family = AF_UNSPEC; }
    if (!strcmp(mode, "bad-address")) { dest.len = 0; }
    if (!strcmp(mode, "no-collector")) { conf.dest_sa = NULL; }
    const char *app = !strcmp(argv[5], "<null>") ? NULL : argv[5];
    brix_pmark_firefly_oneshot(!strcmp(mode, "null-conf") ? NULL : &conf,
                              fd, 17, 3, atoi(argv[4]), app, &log);
    return 0;
}
