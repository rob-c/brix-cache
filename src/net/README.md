# net — clustering, proxying, shadowing, and connection defense

Everything that makes one brix node talk to *other servers* — CMS cluster
membership, manager-mode redirection, upstream proxying — or defend and
observe its own traffic: rate limiting, the observation tap, mirroring,
and the bad-actor guard.

| Dir | What |
|---|---|
| [cms/](cms/) | CMS protocol client: manager heartbeat, registration, kYR messaging |
| [manager/](manager/) | manager-mode registry + client redirection |
| [upstream/](upstream/) | upstream XRootD session handling for proxy mode (redirect/wait/waitresp) |
| [proxy/](proxy/) | terminating reverse proxy with tap integration (`brix_tap_proxy*`) |
| [ratelimit/](ratelimit/) | SHM token-bucket rate limiting (per-key in-flight/open-file gauges) |
| [tap/](tap/) | ngx-free wire observation tap: decode + sink fan-out |
| [mirror/](mirror/) | request mirroring |
| [guard/](guard/) | bad-actor detection core (pure C, protocol-fed) |
| [httpguard/](httpguard/) | the HTTP-side guard module (+ fail2ban integration in `deploy/fail2ban/`) |

**Gotcha:** rate-limit gauges are reset on reload adoption
(`zone_reset_gauges`) because SIGKILLed workers leak in-flight counts —
don't "simplify" that away.
