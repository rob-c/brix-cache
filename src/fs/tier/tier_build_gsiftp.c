/* Build a tier-composed outbound GridFTP origin. */

#include "tier.h"
#include "fs/backend/gsiftp/sd_gsiftp.h"
#include "core/compat/cstr.h"

brix_sd_instance_t *
brix_tier_build_gsiftp(const brix_tier_cfg_t *tier, ngx_log_t *log)
{
    char proxy[1024] = "";
    char ca_dir[1024] = "";

    if (tier->credential != NULL) {
        if (tier->credential->x509_proxy.len != 0) {
            (void) brix_str_cbuf(proxy, sizeof(proxy),
                                  &tier->credential->x509_proxy);
        } else if (tier->credential->x509_cert.len != 0) {
            (void) brix_str_cbuf(proxy, sizeof(proxy),
                                  &tier->credential->x509_cert);
        }
        if (tier->credential->ca_dir.len != 0) {
            (void) brix_str_cbuf(ca_dir, sizeof(ca_dir),
                                  &tier->credential->ca_dir);
        }
    }
    {
        brix_sd_gsiftp_cfg_t cfg = {
            .host = tier->host,
            .port = tier->port,
            .base_path = tier->path[0] != '\0' ? tier->path : "/",
            .require_gsi = tier->tls,
            .x509_proxy = proxy[0] != '\0' ? proxy : NULL,
            .ca_dir = ca_dir[0] != '\0' ? ca_dir : NULL,
            .timeout_ms = 30000,
        };

        return brix_sd_gsiftp_create(&cfg, log);
    }
}
