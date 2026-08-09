#ifndef BRIX_CMS_ALTDS_H
#define BRIX_CMS_ALTDS_H

/*
 * cms/altds.h — §2.12 alternate (foreign) data server (stock cms.altds).
 *
 * Contract: with brix_cms_altds <port> configured, the CMS login advertises
 * that port as this node's data port (dPort) — clients selected here are
 * redirected to the co-located foreign data server (e.g. a stock xrootd on
 * the same host; the manager records the CONNECTION's peer address as the
 * data host, so only the port is advertisable — same-host by construction).
 *
 * With the `monitor` option, brix_cms_altds_start() (cms_start.c, worker 0)
 * arms a periodic nonblocking TCP probe of 127.0.0.1:<port>; a probe failure
 * sends kYR_status(suspend) on every logged-in manager link and a recovery
 * sends kYR_status(resume) — the mesh stops selecting a node whose foreign
 * DS died, exactly like stock altds monitoring.
 *
 * Requires: cms_internal.h types (include after it).
 */

void brix_cms_altds_start(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *conf);

#endif /* BRIX_CMS_ALTDS_H */
