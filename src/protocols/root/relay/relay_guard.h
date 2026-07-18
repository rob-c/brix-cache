#ifndef NGX_BRIX_RELAY_GUARD_H
#define NGX_BRIX_RELAY_GUARD_H

/*
 * relay_guard.h — bad-actor guard sink for the transparent stream relay.
 *
 * WHAT: per-relay guard state plus the tap sink that classifies each decoded
 *   root:// frame (requests pre-verdict, responses post-signal) and asks the
 *   relay to drop the connection on a BOUNCE.
 * WHY:  the relay is a credential-preserving MITM in front of a real XRootD
 *   server; the guard gives it the same junk-bounce + fail2ban audit contract
 *   the HTTP guard module gives ARC/XrdHttp (see src/net/guard/).
 * HOW:  registered as an additional sink on the relay's tap; enforcement is a
 *   drop flag the relay pump checks after every tap feed (a stream has no
 *   "403" — the bounce is connection teardown).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "net/tap/tap.h"
#include "net/guard/guard.h"

typedef struct {
    guard_ruleset_t  rules;      /* built once at relay start ("root" profile) */
    int              enable;
    int              drop;       /* set by the sink -> the pump tears down */
    int              hs_seen;    /* first-bytes wire check reached a verdict */
    unsigned char    hs_buf[20]; /* accumulated opening bytes (kXR sig is 20) */
    unsigned char    hs_len;     /* bytes buffered so far (fragmentation-safe) */
    char             ip[64];     /* NUL-terminated client address for audit */
    ngx_log_t       *log;        /* relay's stable log (no session appender) */
} brix_relay_guard_t;

/* Build the ruleset (default signatures + "root" profile) and record the
 * client address; a disabled guard leaves the sink a no-op. */
void brix_relay_guard_init(brix_relay_guard_t *g, int enable,
    const ngx_str_t *client_addr, ngx_log_t *log);

/* Tap sink (brix_tap_sink_fn): ctx is the brix_relay_guard_t. */
void brix_relay_guard_sink(void *ctx, const brix_tap_frame_t *f,
    brix_tap_dir_t dir, const uint8_t *payload, size_t payload_len);

/* First-bytes wire check: inspect the opening client->upstream bytes for the
 * kXR handshake signature BEFORE they are forwarded. A client not speaking
 * root sets the drop flag and emits one signal=notroot audit line. Runs at
 * most once per relay (guarded by g->hs_seen); a no-op when disabled. */
void brix_relay_guard_handshake(brix_relay_guard_t *g,
    const unsigned char *buf, size_t len);

/* 1 when a classified frame demanded the connection be dropped. */
int brix_relay_guard_should_drop(const brix_relay_guard_t *g);

#endif /* NGX_BRIX_RELAY_GUARD_H */
