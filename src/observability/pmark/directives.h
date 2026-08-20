/*
 * directives.h — shared SciTags packet-marking directive entries.
 *
 * The root:// and WebDAV command tables use different nginx scopes and
 * configuration types, but the directive grammar is identical.  Keep the
 * entry list in one X-macro so the two command tables cannot drift.
 */
#ifndef BRIX_PMARK_DIRECTIVES_H
#define BRIX_PMARK_DIRECTIVES_H

#define BRIX_PMARK_DIRECTIVES(conf_scope, conf_offset, conf_type) \
    { ngx_string("brix_pmark"), \
      conf_scope | NGX_CONF_FLAG, ngx_conf_set_flag_slot, \
      conf_offset, \
      offsetof(conf_type, common.pmark.enable), NULL }, \
    { ngx_string("brix_pmark_firefly"), \
      conf_scope | NGX_CONF_FLAG, ngx_conf_set_flag_slot, \
      conf_offset, \
      offsetof(conf_type, common.pmark.firefly), NULL }, \
    { ngx_string("brix_pmark_flowlabel"), \
      conf_scope | NGX_CONF_FLAG, ngx_conf_set_flag_slot, \
      conf_offset, \
      offsetof(conf_type, common.pmark.flowlabel), NULL }, \
    { ngx_string("brix_pmark_scitag_cgi"), \
      conf_scope | NGX_CONF_FLAG, ngx_conf_set_flag_slot, \
      conf_offset, \
      offsetof(conf_type, common.pmark.scitag_cgi), NULL }, \
    { ngx_string("brix_pmark_firefly_origin"), \
      conf_scope | NGX_CONF_FLAG, ngx_conf_set_flag_slot, \
      conf_offset, \
      offsetof(conf_type, common.pmark.firefly_origin), NULL }, \
    { ngx_string("brix_pmark_http_plain"), \
      conf_scope | NGX_CONF_FLAG, ngx_conf_set_flag_slot, \
      conf_offset, \
      offsetof(conf_type, common.pmark.http_plain), NULL }, \
    { ngx_string("brix_pmark_echo"), \
      conf_scope | NGX_CONF_TAKE1, ngx_conf_set_msec_slot, \
      conf_offset, \
      offsetof(conf_type, common.pmark.echo), NULL }, \
    { ngx_string("brix_pmark_appname"), \
      conf_scope | NGX_CONF_TAKE1, ngx_conf_set_str_slot, \
      conf_offset, \
      offsetof(conf_type, common.pmark.appname), NULL }, \
    { ngx_string("brix_pmark_defsfile"), \
      conf_scope | NGX_CONF_TAKE1, ngx_conf_set_str_slot, \
      conf_offset, \
      offsetof(conf_type, common.pmark.defsfile), NULL }, \
    { ngx_string("brix_pmark_domain"), \
      conf_scope | NGX_CONF_TAKE1, brix_pmark_set_domain, \
      conf_offset, 0, NULL }, \
    { ngx_string("brix_pmark_firefly_dest"), \
      conf_scope | NGX_CONF_TAKE1, brix_pmark_set_firefly_dest, \
      conf_offset, 0, NULL }, \
    { ngx_string("brix_pmark_map_experiment"), \
      conf_scope | NGX_CONF_TAKE23, brix_pmark_set_map_experiment, \
      conf_offset, 0, NULL }, \
    { ngx_string("brix_pmark_map_activity"), \
      conf_scope | NGX_CONF_TAKE3 | NGX_CONF_TAKE4, \
      brix_pmark_set_map_activity, \
      conf_offset, 0, NULL },

#endif /* BRIX_PMARK_DIRECTIVES_H */
