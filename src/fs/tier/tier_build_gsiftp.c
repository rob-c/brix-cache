/* Build a tier-composed outbound GridFTP origin. */

#include "tier.h"
#include "core/types/tunables.h"  /* BRIX_GSIFTP_TIMEOUT_DEFAULT_MS */
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
            .timeout_ms = BRIX_GSIFTP_TIMEOUT_DEFAULT_MS,
            .dns = tier->dns,
            /* phase-115 W5.1: the store line's data-channel policy, carried as
             * a typed request the session negotiates once and never relaxes. */
            .mode = tier->ftp_mode_e ? GFTP_DMODE_E : GFTP_DMODE_S,
            .prot = tier->ftp_prot_p ? GFTP_DPROT_P : GFTP_DPROT_C,
            /* phase-115 W5.3: a CEILING, not a demand — an origin that
             * will not stripe still serves the bytes over one link. */
            .streams = tier->ftp_streams,
        };

        return brix_sd_gsiftp_create(&cfg, log);
    }
}
