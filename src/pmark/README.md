# pmark — SciTags packet marking

Network flow tagging for nginx-xrootd, compatible with XRootD's `pmark` directive
family and the [SciTags](https://www.scitags.org) initiative (WLCG / ESnet / GÉANT).
Each data flow is labelled with an `(experiment, activity)` pair so R&E network
operators can account for and engineer traffic per-VO / per-activity.

Design doc: [`docs/refactor/phase-34-packet-marking-scitags.md`](../../docs/refactor/phase-34-packet-marking-scitags.md).

## Overview

A flow-id is a 16-bit value `(experiment << 6) | activity` (10-bit experiment
1–1023, 6-bit activity 1–63). Two SciTags techniques are implemented, both
**fail-open** (a misconfiguration, an unreachable collector, or a kernel that
refuses a label degrades to "not marked" and never blocks/slows/fails a transfer):

1. **Firefly UDP** (`firefly.c`) — out-of-band RFC5424-syslog-wrapped JSON
   flow-lifecycle documents (`start` / `ongoing` / `end`) sent to a collector
   (default UDP port 10514). Byte-for-byte compatible with XRootD's
   `XrdNetPMarkFF` so existing `flowd` collectors and dashboards just work.
2. **IPv6 Flow Label** (`flowlabel.c`) — in-band stamping of the 20-bit IPv6
   flow label via `setsockopt(IPV6_FLOWLABEL_MGR)` + `IPV6_FLOWINFO_SEND`. This
   completes the path XRootD only stubbed (`// { TODO??? }`). No-op on IPv4 /
   IPv4-mapped, and self-disables (one-time probe) where the host kernel forbids
   setting a specific label (sysctls / `CAP_NET_ADMIN`).

## Files

| File | Responsibility |
|---|---|
| `pmark.h` | Public types (`xrootd_pmark_conf_t`, `xrootd_pmark_flow_t`, runtime), flow-id encode/decode/validate inlines, and the whole API. |
| `config.c` | Directive setters + per-server config init/merge (defaults: opt-in off; firefly + flowlabel + scitag-cgi on; domain remote; port 10514). |
| `scitag.c` | Defensive `scitag.flow=<N>` parser (out-of-range / malformed rejected, never coerced; client bytes never reach the firefly JSON). |
| `defsfile.c` | Parse the scitags experiment/activity registry JSON (jansson) → name↔id maps. |
| `mapping.c` | First-use runtime resolution (defsfile + rules + collector addrs) and `getCodes` priority: scitag → path-glob → VO → default; activity user → role → default → 1. |
| `firefly.c` | Per-worker UDP sender, datagram assembly, `flow_begin` / `flow_end` / `flow_echo`, and the HTTP per-request `http_mark` + pool-cleanup helpers. |
| `sockstats.c` | TCP_INFO byte/rtt (read by stable kernel-ABI offset — glibc's struct is a subset), the firefly µs-UTC timestamp, and the `ip:port` + address-family formatter. |
| `flowlabel.c` | IPv6 flow-label encode + apply + one-time capability probe (Linux-only; no-op stubs elsewhere). |

## Configuration

Per-server / per-location directives (live in the shared `common` config preamble,
so the same set works in the stream `server {}`, WebDAV, and S3 location blocks).
See doc §4 for the full list and the XRootD `pmark` equivalence table. Common case:

```nginx
xrootd_pmark            on;
xrootd_pmark_firefly_dest flowd.example.org:10514;
xrootd_pmark_defsfile   /etc/xrootd/scitags.json;
xrootd_pmark_map_experiment vo atlas atlas;
xrootd_pmark_map_experiment default        dteam;
xrootd_pmark_map_activity   atlas default   default;
# xrootd_pmark_flowlabel on;   # default on (IPv6 only)
# xrootd_pmark_http_plain on;  # also mark plain WebDAV/S3 GET/PUT (default: TPC only)
```

## Control & data flow

A flow is begun once per transfer at the protocol's open/handler site and ended at
teardown (firefly `end` reads the final TCP_INFO before the fd closes):

- **root://** (stream): begun in [`../read/open_request.c`](../read/README.md) on
  the first local data open; ended in [`../connection/disconnect.c`](../connection/README.md).
  Handle stored on `xrootd_ctx_t.pmark_flow`.
- **WebDAV / S3** (HTTP): begun in [`../webdav/dispatch.c`](../webdav/README.md) /
  [`../s3/handler.c`](../s3/README.md) post-auth; ended via an `ngx_pool_cleanup`.
  TPC (COPY) always marked; plain GET/PUT only with `xrootd_pmark_http_plain`.

## Invariants, security & gotchas

- **Fail-open, always.** Marking never returns an error to the data plane; UDP and
  `setsockopt` failures are dropped/counted, not surfaced.
- **SciTags is accounting only** — a client-supplied `scitag.flow` (or any tag)
  must never widen authorization. It does not touch auth/ACL.
- Untrusted `scitag.flow` is range-checked (`scitag.c`); out-of-range/malformed is
  ignored, and only parsed integers + numeric IPs are ever emitted (no client
  bytes in the firefly JSON).
- The flow-label **bit layout** is the WLCG SciTags spec
  (`draft-cc-v6ops-wlcg-flow-label-marking`): activity at bits 2–7, community
  (experiment) at bits 9–17 **in reversed bit order**, 5 random entropy bits at
  0,1,8,18,19. It is pinned in the single `xrootd_pmark_flowlabel_encode()` (+ the
  entropy OR in `flowlabel.c`). A CMS client's `scitag.flow=206` (exp 3, act 14)
  therefore appears on the wire as flow label `196664` — the value cms-sw/cmssw
  `c2797da` reads back. Match this layout to the deployed spec version before
  declaring interop.
- TCP_INFO byte fields are read by fixed kernel-ABI offset because glibc's
  `<netinet/tcp.h>` `struct tcp_info` omits them and `<linux/tcp.h>` conflicts with
  it; rtt is always available, byte counts where the kernel provides them.

## See also

- [`../../docs/refactor/phase-34-packet-marking-scitags.md`](../../docs/refactor/phase-34-packet-marking-scitags.md) — full design + XRootD ground truth.
- [`../config/shared_conf.h`](../config/README.md) — where the pmark config is embedded.
