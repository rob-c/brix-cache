/*
 * directives_pmark.h — SciTags packet-marking directives (brix_pmark, firefly, activity map — src/observability/pmark)
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * setters/enum tables from module_enums.h stay visible). Not a standalone TU.
 */
#pragma once
#include "observability/pmark/directives.h"

    /* SciTags packet marking (src/pmark/) — see phase-34 doc */
    BRIX_PMARK_DIRECTIVES(NGX_STREAM_SRV_CONF, NGX_STREAM_SRV_CONF_OFFSET,
                          ngx_stream_brix_srv_conf_t)
