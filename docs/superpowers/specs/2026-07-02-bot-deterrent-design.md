# Bot-deterrent flag (`xrootd_bot_deterrent`) — design

**Date:** 2026-07-02
**Status:** approved

## Problem

Public HTTP(S) endpoints (WebDAV, S3, cvmfs, SRR, metrics) attract search-engine
crawlers and ad-network verifiers. There is currently no way to tell them to go
away: `/robots.txt` and `/ads.txt` 404 through the normal pipeline, and nothing
emits an anti-indexing header. Operators want a single boolean flag that turns a
bot-deterrent surface on, HTTP(S)-plane only — `root://` must never be affected.

## Decision

One new flag on the existing HTTP guard module (`src/net/httpguard/`,
`ngx_http_xrootd_guard_module`):

```
xrootd_bot_deterrent on | off;        # default off
```

- `NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG`,
  `ngx_conf_set_flag_slot`, merged main→srv→loc with default 0 — same shape as
  `xrootd_guard`.
- Independent of `xrootd_guard`: works with classification off.
- Hosting it in an http-plane module satisfies "only on when serving http(s)
  traffic" by construction and gives every HTTP protocol one shared flag with
  zero per-protocol wiring.

Approaches rejected: a per-protocol flag in `ngx_http_xrootd_shared_conf_t`
(three directives + three dispatcher call sites + per-protocol pre-auth
plumbing for the same behaviour) and a documented config snippet (not a module
boolean, no header, copy-paste per deployment).

## Behaviour

### Well-known files (new `src/net/httpguard/bot_deterrent.c`)

A **PREACCESS-phase** handler — it must run before every auth/access handler
because crawlers are anonymous and would otherwise bounce off GSI/token/SigV4
auth with a 401. When the flag is on it intercepts exact-match `GET`/`HEAD` on:

| Path | Body | Meaning |
|---|---|---|
| `/robots.txt` | `User-agent: *`␊`Disallow: /`␊ | crawlers: nothing here is crawlable |
| `/ads.txt` | `placeholder.example.com, placeholder, DIRECT, placeholder`␊ | IAB "no authorized ad sellers" record |
| `/app-ads.txt` | same placeholder record | ditto for app ad verifiers |

Responses are static in-memory strings: `200`, `Content-Type: text/plain`,
`Content-Length` set, `Cache-Control: max-age=86400` (bots shouldn't re-poll
aggressively). `HEAD` sends headers only. The handler serves the response and
finalizes the request from the phase handler (discard body → send header →
output filter → finalize, returning `NGX_DONE` to the phase engine).

Everything else declines to the normal pipeline:

- flag off (default): immediate decline, zero cost;
- any other method on those paths (e.g. `PUT /robots.txt`): declines, so the
  protocol's auth/write gates still apply;
- non-root paths (`/sub/robots.txt`): untouched — exact match on `r->uri` only.

Documented side effect: with the flag on, a real `robots.txt`/`ads.txt` in the
export root is shadowed at these exact URIs.

### Noindex header

A header filter (chained via `ngx_http_next_header_filter` in the module's
postconfiguration) appends `X-Robots-Tag: noindex, nofollow` to every
main-request response — all methods, all statuses, error pages included — in
scopes where the flag is on. This covers what robots.txt cannot: it stops
indexing of URLs search engines already know.

### Interaction with the guard

The file handler runs at PREACCESS; guard classification runs at ACCESS. A
polite crawler fetching `/robots.txt` therefore gets the file and never reaches
the guard/fail2ban pipeline — well-behaved bots are not banned for asking.

## Build

`bot_deterrent.c` is added to the module source list in the repo-root
`./config` → requires one `./configure` + `make` (per BUILD GOVERNANCE).

## Testing (`tests/test_bot_deterrent.py`)

1. **Success:** flag on → `GET /robots.txt` returns the disallow-all body and
   `GET /ads.txt`/`/app-ads.txt` the placeholder record on WebDAV, S3 and cvmfs
   ports; `HEAD` returns headers only; a normal data `GET` on a flagged
   location carries `X-Robots-Tag: noindex, nofollow`.
2. **Error/off:** default-off endpoint → `/robots.txt` 404s through the normal
   pipeline and responses carry no `X-Robots-Tag`.
3. **Security-negative:** flag on → anonymous `GET /robots.txt` succeeds on an
   auth-required endpoint (pre-auth by design), but `PUT /robots.txt` is still
   rejected by auth/write gates, and `GET /sub/robots.txt` is not intercepted.

## Docs

`src/net/httpguard/README.md` gains the directive + behaviour; guard_http.h
doc block updated with the new directive line.
