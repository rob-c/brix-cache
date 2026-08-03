# xrd1 Cache + Origin End-to-End Demo (2026-07-23)

*Demo / runbook record — brought up 2026-07-23 on `xrd1.edi.scotgrid.ac.uk`.*

## Context

On 2026-07-23 the full stack was brought up on `xrd1.edi.scotgrid.ac.uk` for a
load-test demo: a **brix front** (`/etc/nginx/nginx.conf`) sitting in front of an
**official XRootD / CMSD origin**. The load-test driver was
`/root/brix-loadtest/brix_loadtest.py` with a dashboard on port `8088`.

The read path worked end-to-end (cache miss → fill from origin → hits). Two live
bugs (write staged-commit, 443 VOMS) and a client-tool limitation (`xrdcp` over
https) are recorded below. Host-specific paths/ports here are **(historical)** —
they document the demo host, not repo defaults; the brix directives and code
components they exercise all still exist in-tree (verified below).

## The stack + ports

Backend port remap was done to match the brix forward targets. The origin config
lives in `/etc/xrootd/xrootd-brix{,-mgr,-http}.cfg` (backups `*.bak-20260723`).
Both `xrootd@%i` and `cmsd@%i` share `xrootd-%i.cfg`, differentiated inside the
config by `if exec xrootd|cmsd`. **(historical — demo-host layout)**

- **`xrootd@brix`** — data server on `11094` (`root://`) + https on `10443`;
  `cmsd@brix` runs as a server.
- **`xrootd@brix-mgr`** — a **second data server** on `11095` (`roots://`, TLS).
  This was originally a redirector, but that caused *"Redirect limit reached"*,
  so it was made a plain data server. `cmsd@brix-mgr` = cluster manager on
  **`11213`** (`all.manager :11213`).
- **`xrootd@brix-http`** — cleartext http on `10080`.
- Origin store `/data/xrootd` (export `"/"`), authdb `/etc/xrootd/authdb-brix`
  (`g /lhcb / a` + `u brixsvc / a`).

Dashboard: `http://xrd1…:8088/brix/login`, password `brix-watch-2026`.

## What worked

- Reads through brix on `root://1094` and `roots://1095` end-to-end: cache
  miss → fill from origin → subsequent hits; round-2 reads roughly **2x faster**.
- The request guard bounces scanner paths (`wp-login.php`, `.env` → `444`).
- See [Default Gateway Write Staging](default-gateway-write-staging.md) for the
  write-staging tier that the write path (below) exercises.

## Gotchas

### brix origin proxy expires

The `brix_credential origin` fallback proxy at
`/etc/grid-security/brix/proxy.pem` had **EXPIRED** (Jul 9), so every origin
read/write failed with `Secgsi ... Proxy: certificate expired (kXR 3030)`.

Renewal (host DN gridmaps to `brixsvc`):

```sh
sudo -u nginx \
  X509_USER_CERT=/etc/grid-security/brix/hostcert.pem \
  X509_USER_KEY=/etc/grid-security/brix/hostkey.pem \
  voms-proxy-init -valid 168:00 -out …
# then install 0600, nginx-owned, and reload nginx
```

See [pblock Privilege-Drop Hardening](pblock-privilege-drop-hardening.md). The
`brix_credential` directive is implemented in
`src/core/config/credential_block.c` and consumed by
`src/core/config/runtime_server_backend.c`.

### brix_cms_manager must NOT point at the official origin cmsd — SUPERSEDED

At demo time, every nginx worker's CMS client subscribed as host `xrd1`,
colliding with the real `cmsd@brix`; the manager logged `server…already logged
in` + resets, producing `CMS write handler: send_load failed`. The workaround
was to **remove** `brix_cms_manager` from both stream servers (`brix_cms_manager`
is for a brix *leaf* registering with a brix *manager*; direct caching uses
`brix_storage_backend` directly).

**This gotcha is now superseded.** The per-worker SID collision is fixed in-code
by the CMS auto-role / worker-0 connection-gate work — see
[CMS Auto-Role, Sub-Manager Supervision, and the Worker-0 Connection Gate](cms-auto-role-submanager.md)
(landed 2026-07-23, validated live on `xrd1`). `brix_cms_manager` is defined in
`src/net/cms/config.c` / `src/net/cms/connect.c`.

## Known live bugs

### LIVE BUG 1 — writes through brix fail (staged-commit ENOENT)

Writes fail with `[3007] staged commit failed (destination)`.
`brix_commit_staged` (`src/core/compat/staged_file_commit.c`) hits **ENOENT**
publishing the staged `.part`. Deterministic and **pre-existing** (orphaned
`.part` files in `/data/brix/export` from Jul 8). The origin never sees the
write. Workaround: the demo seeds files to the origin directly
(`root://11094`, the working write path) then moves them via brix downloads.

### LIVE BUG 2 — 443 reads return 403 authfail (VOMS)

The brix 443 front's VOMS / `brix_webdav_require_vo lhcb` gate rejects even a
valid lhcb proxy (`curl` sends only the proxy leaf; `davix` / `xrdfs-https`
also `403`). Front TLS + guard are fine; the VOMS proxy-chain passthrough
validation needs work. `brix_webdav_require_vo` is implemented in
`src/protocols/webdav/access.c` / `module_directives.c`.

## Client-tool limitation — xrdcp over https

`xrdcp v5.9.6-1.el9`'s URL classifier (`libXrdAppUtils`) rejects `https://`
(*"file protocol is not supported"*) even with the plugin loaded — `xrdfs` /
`curl` over https work. Fixing the plugin soname
(`/etc/xrootd/client.plugins.d/xrdcl-http-plugin.conf`: `lib =
libXrdClHttp-5.so`) and setting `XRD_PLUGINCONFDIR` did **not** help; `xrdcp`
still won't copy https. So the demo script seeds/reads over `root` / `roots`
only.
