#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <stddef.h>
#include "../ngx_xrootd_module.h"

size_t xrootd_chain_pending_bytes(ngx_chain_t *cl) {
    size_t total = 0;
    for (; cl != NULL; cl = cl->next) {
        if (cl->buf) {
            total += ngx_buf_size(cl->buf);
        }
    }
    return total;
}
