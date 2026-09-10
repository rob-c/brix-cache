/*
 * directives_cms_fsxeq.h — the CMS forwarded-namespace-op external program
 * (stock `cms.fsxeq`), split out of directives_cms.h so neither header outgrows
 * the 600-line contract.  #included into ngx_stream_brix_commands[] in module.c
 * (the compiler concatenates; setters from module_enums.h stay visible).
 * Not a standalone TU.
 */
#pragma once
    /* §2.19 (cms.fsxeq): run an operator program IN PLACE OF the built-in
     * POSIX leg for one or more forwarded namespace ops.  Stock grammar:
     *
     *   brix_cms_fsxeq <op>... <program> [<arg>...]
     *
     * where <op> is one or more of chmod mkdir mkpath mv rm rmdir trunc.  The
     * op's own arguments are APPENDED to the configured command line (stock
     * XrdOucProg::Run semantics: mode/size first where the op has one, then the
     * physical path, then the second path for mv).  The op name is NOT
     * injected — an operator who points several ops at one program
     * disambiguates by baking a literal argument into the directive line.
     *
     * Repeatable; one op may name exactly one program (a second line naming an
     * already-claimed op is a parse error, not a silent override).  The program
     * must be an absolute path and must not be group- or world-writable — both
     * are refused at `nginx -t` by the shared brix_frm_check_program(). */
    { ngx_string("brix_cms_fsxeq"),
      NGX_STREAM_SRV_CONF | NGX_CONF_2MORE,
      brix_conf_set_cms_fsxeq,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* The wall-clock deadline for one fsxeq program run.  A program that has
     * not exited by then has its whole process group SIGKILLed and the op
     * fails closed with kYR_error — the worker never blocks on it (the run
     * happens on a thread-pool task, never on the event loop). Default 10s. */
    { ngx_string("brix_cms_fsxeq_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cms.fsxeq_timeout),
      NULL },
