#include "ngx_xrootd_module.h"
#include "proxy/proxy.h"
#include "proxy/proxy_internal.h"
#include "impersonate/lifecycle.h"

extern ngx_command_t ngx_stream_xrootd_commands[];

/* Module definition — XRootD stream module (native protocol, root:// endpoints)
 * WHAT: Declares the static module descriptor and context for nginx's XRootD stream subsystem. This file defines how nginx discovers the XRootD module at startup: the module context struct (ngx_stream_module_t) contains lifecycle callbacks from preconfiguration through postconfiguration to per-server config creation/merging; the module descriptor (ngx_module_t) references this context plus the directive table (ngx_stream_xrootd_commands) and identifies NGX_STREAM_MODULE as the subsystem owner. The combined core + cache/proxy directives come from module.c — this file only declares the external reference.
 *
 * WHY: nginx requires a static module descriptor to discover custom modules at startup. Without this declaration, nginx cannot parse XRootD-specific config directives (xrootd_enable, xrootd_server, etc.) or invoke the stream handler lifecycle hooks. The module context deliberately omits main-conf callbacks because each stream server manages its own configuration independently — no global aggregation is needed for native XRootD protocol operation. Thread safety: static declarations are immutable after nginx startup; all runtime operations occur via per-server ctx objects created in create_srv_conf. */


static ngx_stream_module_t ngx_stream_xrootd_module_ctx = {
    /* No global parser rewrites are needed before nginx reads stream blocks. */
    NULL,                                 /* preconfiguration  */
    /* Final validation and resource setup once all stream servers are parsed. */
    ngx_stream_xrootd_postconfiguration,  /* postconfiguration */
    /* This module keeps no stream-wide main configuration object. */
    NULL,                                 /* create main conf  */
  /* Therefore there is also nothing to normalize/validate at main-conf level. */
    NULL,                                 /* init main conf    */
    /* Per-server config object allocation and parent/child merging hooks. */
    ngx_stream_xrootd_create_srv_conf,    /* create srv conf   */
    ngx_stream_xrootd_merge_srv_conf,     /* merge srv conf    */
};


ngx_module_t ngx_stream_xrootd_module = {
  NGX_MODULE_V1,
  &ngx_stream_xrootd_module_ctx,
  ngx_stream_xrootd_commands,
  NGX_STREAM_MODULE,
  /* init_master: none.  init_module (master, once per load): spawn the phase-40
   * identity broker when xrootd_impersonation=map; a no-op otherwise. */
    NULL,                                   /* init master        */
    xrootd_imp_init_module,                 /* init module        */
    ngx_stream_xrootd_init_process,         /* init process       */
    NULL, NULL, xrootd_exit_process, NULL,
    NGX_MODULE_V1_PADDING
};
