#ifndef BRIX_SD_GSIFTP_H
#define BRIX_SD_GSIFTP_H

/* Outbound ftp:// / gsiftp:// origin storage driver. */

#include "fs/backend/sd.h"
#include "gftp_client.h"

struct brix_dns_policy_s;   /* net/dns/dns.h */

typedef struct {
    const char *host;
    int         port;
    const char *base_path;
    int         require_gsi;
    const char *x509_proxy;
    const char *ca_dir;
    int         timeout_ms;
    const struct brix_dns_policy_s *dns;   /* phase-116: origin resolver policy */
    gftp_dmode_t mode;                     /* phase-115 W5.1: MODE S | MODE E  */
    gftp_dprot_t prot;                     /* phase-115 W5.1: PROT C | PROT P  */
    unsigned     streams;                  /* phase-115 W5.3: SPAS ceiling, 0/1 */
} brix_sd_gsiftp_cfg_t;

brix_sd_instance_t *brix_sd_gsiftp_create(
    const brix_sd_gsiftp_cfg_t *cfg, ngx_log_t *log);
void brix_sd_gsiftp_destroy(brix_sd_instance_t *inst);

#endif /* BRIX_SD_GSIFTP_H */
