# Clustering, redirection, TPC, proxy, and traffic mirroring

> Part of the [XRootD vs BriX-Cache comparison set](./README.md).

This document compares official XRootD against the `nginx-xrootd` module on the
five subsystems that turn a single data server into a federated storage service:

1. **CMS clustering** — the `cmsd` control-plane mesh (manager / server roles).
2. **Redirection & locate** — how a redirector answers `kXR_locate`/`kXR_open`
   with a `kXR_redirect`, including loop avoidance.
3. **Native `root://` third-party copy (TPC)** — destination-pull transfers
   coordinated with a rendezvous key.
4. **Proxy mode** — forwarding `root://` to a backend storage cluster.
5. **Traffic mirroring** — replaying live requests to a shadow backend (an
   BriX-Cache extension with no official equivalent).

Every claim below is grounded in source. Official paths are under
`/tmp/brix-src/src/`; module paths are repo-relative under `src/`. Where wire
interoperability has not been validated end-to-end against a running daemon, the
text says so explicitly ("not verified").

This page is consistent with, and does not contradict, the cluster/proxy/TPC
section of [`../../source-verified-xrootd-comparison.md`](../../source-verified-xrootd-comparison.md).

## Scope

In scope: the control plane and redirection/transfer-coordination machinery for
multi-node deployments — CMS membership, locate/redirect, native TPC key
rendezvous, transparent `root://` proxying, and write/read shadow replay. Both
the `root://` (stream) plane and the relevant HTTP integration points are
covered.

Out of scope here (covered in sibling comparison pages): the HTTP/WebDAV
**HTTP-TPC** `COPY` transport (`src/protocols/webdav/tpc*.c` vs
`/tmp/brix-src/src/XrdHttpTpc/`); the data-plane I/O opcodes; auth plugins; and
UDP monitoring (an explicit module non-goal). Erasure-coded redirects
(`kXR_ecRedir`) are defined but never set on the module side and require an EC
backend, so they are not analysed.

## In official XRootD

Clustering in XRootD is the job of a **separate daemon, `cmsd`** (Cluster
Management Service daemon), which runs alongside `xrootd` on every node and forms
a tree of managers and servers. The two daemons share a config file but listen
on different ports; the `xrootd` data server consults its local `cmsd` (through
`XrdCmsFinder`) to resolve where a file lives.

Key official source areas:

- **Roles & config:** `XrdCms/XrdCmsRole.hh` (the `RoleID` enum:
  `MetaManager, Manager, Supervisor, Server, ProxyManager, ProxySuper,
  ProxyServer, PeerManager, Peer`), parsed from the `role`/`all.role` directive
  in `XrdCms/XrdCmsConfig.cc` (`xrole()`), which sets `isManager`, `isServer`,
  `isMeta`, `isProxy`, `isPeer`, `isSolo`. Manager addresses come from
  `all.manager` (`ManList`/`NanList`/`SanList` in `XrdCmsConfig.hh`).
- **The CMS wire protocol (YProtocol):** `XProtocol/YProtocol.hh` defines the
  8-byte `CmsRRHdr` (`streamid u32`, `rrCode u8`, `modifier u8`, `datalen u16`)
  and the `CmsReqCode` enum (`kYR_login=0, kYR_locate=2, kYR_select=10,
  kYR_avail=12, kYR_gone=14, kYR_have=15, kYR_load=16, kYR_ping=17, kYR_pong=18,
  kYR_space=19, kYR_state=20, kYR_status=22, kYR_try=24, kYR_xauth=27, ...`) and
  the `CmsRspCode` enum (`kYR_data, kYR_error, kYR_redirect, kYR_wait,
  kYR_waitresp, kYR_yauth`).
- **Login & auth:** `XrdCms/XrdCmsLogin.cc/.hh` (`Admit()` server-side,
  `Login()` client-side); SSS auth via the `kYR_xauth` exchange in
  `XrdCms/XrdCmsSecurity.cc`; payload field vectors in `XrdCms/XrdCmsParser.cc`;
  the `XrdOucPup` pack/unpack encoding in `XrdOuc/XrdOucPup.cc/.hh`.
- **Selection & redirection:** `XrdCms/XrdCmsCluster.cc` (`Select`/`Locate`),
  `XrdCms/XrdCmsNode.cc` (`do_Locate`, `do_State`, `do_Have`, `do_Status`,
  `do_Ping`, `do_Load`), `XrdCms/XrdCmsCache.cc` (file→server cache). The
  redirect to the *client* is formed in `XrdXrootd` —
  `XrdXrootd/XrdXrootdXeq.cc` (`do_Locate`) and `XrdXrootdProtocol.cc`
  (`Response.Send(kXR_redirect, port, host)`) — via `XrdCms/XrdCmsFinder.cc`.
- **Proxy storage:** `XrdPss/` — a storage backend (`XrdOss`) plugin that uses
  the `XrdCl`/`XrdPosix` client to fetch from an origin, configured with
  `pss.origin`/`pss.persona` (`XrdPss/XrdPssConfig.cc`).
- **Native TPC:** `XrdOfs/XrdOfsTPC*.cc` (the in-process key registry and
  coordinator), with CGI helpers in `XrdOuc/XrdOucTPC.cc` and config via
  `ofs.tpc` (`XrdOfs/XrdOfsConfig.cc` `xtpc()`).
- **Other cluster machinery:** `XrdCmsManTree.cc`/`XrdCmsManList.cc` (manager
  hierarchy), `XrdCmsBlackList.cc` (host blacklist), `XrdCmsClustID.cc` (cluster
  IDs / alternate-server masks), `XrdCmsMeter.cc` (load/space metering).

There is **no traffic-mirroring/shadow-replay** subsystem in the reviewed
official source.

## In BriX-Cache

The module folds all of this into the single nginx process model. Five
subsystems map to the five topics:

- **`src/net/cms/`** — speaks the CMS wire protocol in both directions. A
  *heartbeat client* (`connect.c`, `recv.c`, `send.c`, `wire.c`, `space.c`,
  `frame_io.c`) registers this node *up* to a parent manager; a *manager-side
  server* (`server_*.c`, the separate `ngx_stream_brix_cms_srv_module`)
  accepts CMS connections *down* from data nodes and records them.
- **`src/net/manager/`** — the redirector control plane: a SHM server registry
  (`registry.c`), a redirect-collapse cache (`redir_cache.c`), a pending-locate
  correlation table (`pending.c`), and active health checks (`health_check.c`).
  Plus a config-time static `manager_map` route table (`src/core/config/manager_map.c`).
- **`src/tpc/`** — native destination-pull TPC over `root://`, including a SHM
  cross-worker rendezvous-key registry (`key_registry.c`) and a hand-rolled
  outbound GSI/`ztn` exchange (`gsi_outbound_*.c`, `tpc_token.c`).
- **`src/net/proxy/` + `src/net/upstream/`** — two different outbound modes. `proxy/` is
  a *transparent frame relay* (`brix_proxy`) that forwards every post-login
  opcode to a backend. `upstream/` is a narrower *redirector-resolution client*
  (`brix_upstream`) that asks a backend to resolve `locate`/`open`/`stat` and
  forwards the answer.
- **`src/net/mirror/`** — fire-and-forget shadow replay of reads, metadata
  mutations, and (gated) writes to one or more shadow backends.

Everything runs on nginx's single-threaded stream event loop, except the
blocking native-TPC pull (a detached thread-pool task) and one `statvfs` in
`src/net/cms/space.c`.

## CMS clustering

### Roles and topologies

| Concept | Official XRootD | BriX-Cache |
|---|---|---|
| Daemon model | Separate `cmsd` per node, sharing config with `xrootd` | In-process; both halves are nginx stream modules |
| Role set | 9 roles (`XrdCmsRole.hh`): meta-manager, manager, supervisor, server, proxy-manager/super/server, peer-manager, peer | Effective roles: **data server** (default), **manager/redirector** (`brix_manager_mode on`), **sub-manager** (manager_mode + CMS client up to a meta), **supervisor flag** (`brix_supervisor`, sets `kXR_attrSuper`) |
| Role directive | `all.role manager` / `all.role server` / `all.role meta manager` (`XrdCmsConfig.cc xrole()`) | `brix_manager_mode on;` (redirector) + `brix_cms_server on;` (accept registrations); a leaf data node sets `brix_cms_manager host:port` to register upward |
| Manager address | `all.manager <host>:<cmsport>` (`ManList`) | leaf: `brix_cms_manager <host>:<port>`; meta tier: a sub-manager runs both `brix_cms_server` and `brix_cms_manager` (memory: multi-tier mesh "D" validated) |
| Membership store | `XrdCmsCluster` node table + `XrdCmsClustID` masks | SHM server registry `src/net/manager/registry.c` (`brix_srv_entry_t`: host/port/paths/free_mb/util_pct), spinlock-guarded, shared across workers |

The module does not reproduce the full nine-role taxonomy. It implements the
practically important subset: leaf server, redirector/manager, and sub-manager
in a meta tree. Proxy-manager / peer roles are not implemented as CMS roles
(proxying is handled by `src/net/proxy/`, a different mechanism).

### The CMS login / Pup handshake

Both sides use the same 8-byte `CmsRRHdr` and the same `XrdOucPup` payload
encoding. The module re-implements the encoding in `src/net/cms/wire.c`:

- Scalars carry a Pup type tag — `0x80` for short (`[0x80][2B BE]`), `0xa0` for
  int (`[0xa0][4B BE]`) — matching `XrdOucPup`.
- **Strings are tagless, length-prefixed** `[u16 BE len][bytes + trailing NUL]`,
  where `len` counts the NUL; empty/NULL packs as a bare `00 00`. The parser
  distinguishes a string from a scalar by the absence of the `0x80` bit in the
  first length byte (`src/net/cms/wire.c`, README "put_string semantics").

The login payload is the official `CmsLoginData` field order
(`XrdCms/XrdCmsParser.cc` logArgs / `YProtocol.hh`): ten scalars
(`Version, Mode, HoldTime, tSpace, fSpace, mSpace, fsNum, fsUtil, dPort, sPort`)
followed (after the Pup `Fence`) by four strings (`SID, Paths, ifList, envCGI`).
The module's `src/net/cms/send.c::_send_login` emits exactly this, with `Mode`
set to `kYR_server (0x08)`, space figures from `src/net/cms/space.c` (`statvfs`),
`dPort` taken from `brix_listen_port`, and `Paths` formatted as
`"<w|r> <ns-path>\n"` per export.

> Interop history (memory: *CMS real-protocol wire spec*): the module's original
> login was rejected by a real `cmsd` ("invalid login data") because it emitted
> bogus reserved shorts and tagged the `Paths` string as a Pup short instead of a
> tagless string, and omitted `SID/ifList/envCGI`. That was fixed; a real `cmsd`
> now registers the nginx node as `server.<pid>@host:dport` and `xrdfs locate`
> redirects to it with byte-exact `xrdcp`. The `CMS_ST_*` status and
> `CMS_LOGIN_MODE_*` constants were also corrected
> (`kYR_manager=0x2`, not `0x10` which is proxy).

### SSS cluster auth (`kYR_xauth`)

Official: registration auth is a separate `kYR_xauth (27)` handshake *before* the
login frame is parsed — `XrdCmsLogin::Admit` calls `XrdCmsSecurity` to
getToken / Authenticate, and only then parses the login. It is opt-in (skipped
unless `sec.protocol` is configured).

Module: `src/net/cms/server_auth.c` implements the same gate. On the manager side,
when `brix_cms_server_sss_keytab` is set, `kYR_login` does **not** register the
node; the manager sends its SSS parms (`&P=sss`) via
`brix_cms_srv_send_xauth`, waits for the `kYR_xauth` credential, and registers
only after `brix_cms_srv_verify_xauth` succeeds (`server_recv.c`
`cms_srv_complete_login`). The credential is the same `XrdSecProtocolsss`
`"sss\0"` blob the repo already parses for `kXR_auth`, so verification is reused.

Two more registration controls (the redirect-poisoning trust boundary, since any
peer reaching the CMS port could otherwise self-report arbitrary
`host:port:paths`):

- **CIDR allowlist** `brix_cms_server_allow <cidr>...` — accept-time gate in
  `server_handler.c` (`brix_cms_srv_check_peer`); with no list it fails *open*
  but warns once.
- **Host-character validation** in `src/net/manager/registry.c`
  (`brix_srv_register` rejects any host failing `brix_net_host_chars_valid`,
  `registry.c:209`) — a single store choke point protecting every redirect-emit
  path.

> Interop maturity (not fully verified): the **negative** SSS path is validated
> live — an unauthenticated real `cmsd` node is refused registration and
> `xrdfs locate` returns "file not found". The **positive** real-`cmsd`→nginx SSS
> path is blocked by an upstream `cmsd` packaging issue (its
> `XrdCmsSecurity::Configure` receives a null ConfigFN), so a real `cmsd` never
> presents an SSS cred in the test harness. Treat cmsd-SSS positive interop as
> requiring a site-specific working `cmsd` SSS config.

### On-demand selection (`kYR_state` → `kYR_have`)

A real manager does **not** redirect purely on registered export paths — it
verifies per file. Official flow (`XrdCmsNode.cc`,
`XrdCmsCluster.cc`):

1. client → mgr: `kYR_locate`/`kYR_select` (Ident, Opts, Path).
2. mgr → each server: `kYR_state (20)` with modifier `kYR_raw (0x20)`, payload =
   raw NUL-terminated path (not Pup-encoded).
3. server checks local FS; if present → `kYR_have (15)` (modifier
   `raw|Online`) back up.
4. mgr caches (`Cache.AddFile`) and → client: `CmsResponse kYR_redirect`
   (`Val = htonl(port)` + host).

Module: `src/net/cms/recv.c` answers `kYR_state` with `kYR_have` only when it can
serve the path. Critically, **the existence probe is kernel-confined**: a data
node uses `brix_stat_beneath` against the persistent export rootfd
(`recv.c:268`, `RESOLVE_BENEATH`), never a raw `stat`, so a malicious manager
cannot probe arbitrary paths and a symlink under the export root cannot leak
files outside it. In manager mode the `kYR_state` handler instead consults
`brix_srv_select` over the registry, so a real meta-manager's on-demand query
resolves down through the nginx sub-manager to its leaf (memory: multi-tier "D").
After login the client sends `kYR_status` (`Resume|noStage`) to become selectable
(`connect.c:119`) — a real `cmsd` keeps an un-status'd node suspended.

### Heartbeat, keepalive, load/space

| Frame | Official (`XrdCmsNode.cc`) | BriX-Cache |
|---|---|---|
| `kYR_ping (17)` / `kYR_pong (18)` | `do_Ping`/`do_Pong`, header-only | client: `recv.c` ping→`_send_pong`; manager: `server_recv.c` ping timer, `_send_ping` |
| `kYR_load (16)` | `do_Load`: 6-byte load array (cpu/net/xeq/mem/pag/dsk) + disk free, via `XrdCmsMeter` | `send.c::_send_load` periodic heartbeat (`theLoad` as `[2B 6][6 bytes]` blob + disk free) |
| `kYR_space (19)` / `kYR_avail (12)` | `do_Space` query → server `kYR_avail` | client: `recv.c` space→`_send_avail`; capacity from `space.c` |
| Heartbeat interval | `cms.*` timers; managers default `cms.delay startup ~90s` | `brix_cms_interval` (client), `brix_cms_server_interval` (manager ping) |

> Operational gotcha (memory): a real manager defaults to ~90s `cms.delay
> startup` before redirecting, so the first locate against a fresh real manager
> can hang unless `cms.delay startup 5 servers 1 lookup 2` is set. This is a
> `cmsd` behaviour, not a module defect.

### Resilience controls (module extensions)

The manager-side CMS server adds operational guards not present as discrete
`cmsd` knobs (`src/net/cms/server_recv.c`, `server_module.c`):

- **Frames-per-wakeup cap** `NGX_BRIX_CMS_MAX_FRAMES_PER_WAKEUP`
  (`recv.c:415`, `server_recv.c:555`): bounds how many CMS frames one event
  drains before yielding, counting `cms_frame_yields_total` — prevents a chatty
  peer from monopolising the event loop.
- **Per-IP and total connection caps** `brix_cms_server_max_connections` and
  `brix_cms_server_max_connections_per_ip` (with `cms_cap_rejections_total`).
- **Login / read / send / idle timeouts**, TCP keepalive and `TCP_USER_TIMEOUT`
  (`brix_cms_server_login_timeout`, `_idle_timeout`, `_tcp_keepalive`,
  `_tcp_user_timeout`; client-side `brix_cms_read_timeout`, `_send_timeout`,
  `_locate_timeout`, `_arm_read_deadline`).
- On disconnect the manager **blacklists** the node for 30s and unregisters it
  (`brix_cms_srv_close`).

## Redirection & locate

### How a client gets a redirect

Official: the data server's `XrdXrootd` layer translates a client
`kXR_locate`/`kXR_open` into a CMS query through `XrdCmsFinderRMT::Locate()`
(`XrdCmsFinder.cc`), mapping client flags (`SFS_O_CREAT` → `kYR_select|kYR_create`,
`SFS_O_LOCATE` → `kYR_locate`, plus IPv4/IPv6 return-format flags). The cluster
answers with a server list; `XrdXrootdProtocol.cc` sends
`Response.Send(kXR_redirect, port, host)`.

Module (manager mode): the read-path handlers `src/protocols/root/read/open_request.c` (open),
`src/protocols/root/read/locate.c` (locate), `src/protocols/root/read/stat.c` (stat), and
`src/protocols/root/dirlist/handler.c` resolve a target locally and emit `kXR_redirect`. The
resolution order (`open_request.c`, `locate.c`):

1. **`tried/triedrc` exhaustion check** (`brix_manager_tried_exhausted`) — if
   the client's `tried=`/`triedrc=` CGI shows it has already visited every
   candidate, answer `kXR_NotFound` once instead of looping.
2. **Redirect-collapse cache lookup** (`brix_redir_cache_lookup`).
3. On a miss, **registry selection** (`brix_srv_select`): longest-prefix path
   match over colon-delimited export tokens (`srv_path_matches`), then policy —
   **lowest `util_pct` for reads, highest `free_mb` for writes**, skipping
   `in_use==0` and blacklisted slots. On success the result is cached
   (`brix_redir_cache_insert`) and a redirect emitted.
4. **Locate returns the full set** via `brix_srv_locate_all` (lateral
   redirect), not just one target.
5. When resolution must be delegated upward to a parent CMS manager, the client
   session is parked (`brix_pending_insert`, state `XRD_ST_WAITING_CMS`) and a
   `kYR_locate` is forwarded via `src/net/cms/send.c`; the manager's
   `kYR_select`/`kYR_try` reply arrives on `src/net/cms/recv.c`, which wakes the
   suspended client (`cms_wake_pending_session`) and emits `kXR_redirect`.

Manager-mode bug history (memory: *manager-mode write bugs*): `kXR_stat` and
`kXR_dirlist` originally fell through to the local FS instead of redirecting, and
the write gate (`!allow_write` → `kXR_fsReadOnly`) fired *before* the redirect;
both fixed so all open handlers skip local serving when `conf->manager_mode`.

### Loop avoidance

Official XRootD uses the `tried=`/`triedrc=` CGI the client accumulates across
redirects so a manager won't keep sending it to a node that failed. The module
honours the same protocol in `brix_manager_tried_exhausted` /
`brix_srv_select` (registry README: "`tried/triedrc` retry-exhaustion logic"),
returning `kXR_NotFound` once all candidates are exhausted rather than risking a
redirect loop. The module also implements **redirect collapse**: when
`brix_collapse_redir on` is configured it advertises `kXR_collapseRedir` and
memoises `path → (host,port)` in the SHM redirect cache (`redir_cache.c`,
`brix_collapse_redir_ttl` TTL) so a busy manager answers repeat opens from
memory. This is a module-specific operational optimisation; the cache is an
FNV-1a-hashed bounded-probe open-addressing table that evicts soonest-to-expire.

### Static routing (`manager_map`) and virtual redirector

Beyond dynamic CMS membership, the module offers a **config-time static route
table**: `brix_manager_map <prefix> <host>:<port>` (`src/core/config/manager_map.c`,
consulted in `src/protocols/root/read/locate.c:150` via `brix_find_manager_map`). This routes
`open/stat/dirlist/locate/checksum` for a path prefix straight to a fixed
backend without any CMS handshake — useful for deterministic federation where the
topology is known. `brix_virtual_redirector on` advertises `kXR_attrVirtRdr`
and auto-detects static-map deployment. These two are **nginx extensions**;
official XRootD's redirector is always backed by a live `cmsd` mesh (clients
understand `kXR_attrVirtRdr` but the server-side static map is module-specific).

### Confirming with the data server (`src/net/upstream/`)

A subtle but important divergence: the module can optionally **confirm** a chosen
server before redirecting. When `brix_upstream host:port` is set and a local
lookup misses, `src/net/upstream/` opens an outbound XRootD client to the backend,
completes the bootstrap (handshake → protocol → optional TLS → login → optional
`ztn` token auth), serializes the saved `kXR_locate`/`kXR_open`/`kXR_stat`, and
forwards whatever the backend answers (redirect/ok/error/`kXR_wait`/
`kXR_waitresp`) verbatim with the client's streamid rewritten in. Only those
three opcodes are serialized outbound — exactly the redirector-resolution set.
This is closest in spirit to how an official data server consults its `cmsd`,
but here the gateway speaks `root://` directly to the backend rather than CMS.

## Native root:// TPC

### The official model

Native TPC in XRootD is a **per-data-server, in-process** rendezvous, not a
cross-process service (`XrdOfs/XrdOfsTPC*.cc`). The client opens the **destination**
with `tpc.key` + `tpc.src` (+ `tpc.org`, `tpc.lfn`, `tpc.cks`, `tpc.str`, ...)
CGI; the destination pulls from the **source**, which had been primed (or is
primed on demand) with a matching `tpc.key`. The CGI helpers live in
`XrdOuc/XrdOucTPC.cc` (`cgiC2Dst` / `cgiD2Src`). The authorization queue
(`XrdOfsTPCAuth.cc`) is a single mutex-protected linked list (`authQ`/`authMutex`)
scoped to one data-server process, with TTL expiry (`RunTTL`); `Match()`
(`XrdOfsTPCInfo.cc`) compares Key+Org+Lfn+Dst. Config is `ofs.tpc`
(`XrdOfsConfig.cc xtpc()`): `pgm`, `ttl <default>[ <max>]`, `xfr`, `streams`,
`allow {dn|group|host|vo}`, `require {all|client|dest}`, `restrict <path>`,
`autorm`, `fcreds <auth> =<envar>` / `fcpath` (delegated-credential forwarding),
`redirect`. The actual byte movement is typically done by an external program
(`ofs.tpc pgm`, e.g. an `xrdcp` wrapper) or the built-in client.

### The module model

`src/tpc/` implements the **destination-side pull** for `root://`. A client
issues a write-mode `kXR_open` whose opaque query carries
`tpc.src=root://origin//path` (+ `tpc.key`, `tpc.org`, `tpc.lfn`,
`tpc.token_mode`); this gateway becomes the destination, opens a *fresh outbound
XRootD client connection* to the source, streams the file in, writes it to the
confined local export, and only then completes. The client never touches the
bytes.

Two material differences from official:

1. **Cross-process SHM key registry (zero-copy rendezvous).** Where official
   uses an in-process mutex-protected list per data server, the module's source
   side registers rendezvous keys in a **shared-memory table**
   (`src/tpc/engine/key_registry.c`: `BRIX_TPC_KEY_SLOTS` = 256, `BRIX_TPC_KEY_TTL_MS`
   default, runtime override `brix_tpc_key_ttl`), guarded by an
   `ngx_shmtx_sh_t` spinlock so any nginx **worker** can validate/consume a key
   the destination presents on reconnect with `tpc.org`+`tpc.key`. Keys are
   **single-use** — `brix_tpc_key_consume` removes the key on a successful
   match (replay protection); `_validate` only checks presence. This is the "SHM
   key registry, cross-process, zero-copy" architecture invariant.

2. **Two-phase arm/flush keyed off `kXR_sync`.** Phase one (`kXR_open`,
   `launch.c::brix_tpc_prepare_pull`) runs the SSRF preflight, creates the
   confined destination file, generates/echoes the key, and returns a handle
   immediately. Phase two is driven by `kXR_sync` (`src/protocols/root/write/sync.c`): the
   **first** sync arms the transfer (`ctx->tpc_armed`), the **second** fires it
   (`launch.c::brix_tpc_start_pull`), posting the blocking pull to the nginx
   thread pool. This matches `xrdcp`/`gfal` TPC semantics and lets the client
   control when staging-to-final commit happens.

The blocking fetch runs in a detached `ngx_thread_task`
(`thread.c → connect.c → bootstrap.c/gsi_outbound_*/tpc_token.c → source.c`);
only the completion callback (`done.c`) runs back on the event loop to frame the
deferred response. Off-loop code uses `malloc`/`free` and raw socket syscalls —
never `ngx_palloc` (not thread-safe there).

### The native client (libxrdc) dialect

`client/lib/copy_remote.c::copy_tpc` (the `xrdcp --tpc` path of the native
client) emits the **stock XrdOucTPC CGI dialect** in the stock XrdCl control
order: best-effort source stat (size + post-redirect endpoint), destination
open with `tpc.key` + `tpc.src=<host:port>` + `tpc.lfn=</path>` +
`tpc.dlg`/`tpc.spr`/`tpc.tpr`/`tpc.dlgon=0` + `oss.asize` + `tpc.stage=copy`,
first `kXR_sync` (rendezvous/arm), source open with `tpc.key` +
`tpc.dst=<dest-host>` + `tpc.stage=copy`, second `kXR_sync` (trigger + await).
Both destinations accept this: a stock `XrdOfsTPC` parses it natively, and the
module normalizes bare-host `tpc.src` + `tpc.lfn` in `src/tpc/engine/parse.c`. The
legacy full-URL form (`tpc.src=root://host:port/path`, source-first order) was
nginx-only — a stock destination rejects it with "Invalid address (source)" and
a stock source fails `Match()` on the full-URL `tpc.dst` — and is no longer
emitted. `tpc.token_mode` remains an nginx extension (unknown `tpc.*` keys are
ignored by both sides). Regression matrix (all four server combinations plus a
clean-failure guard): `tests/test_root_tpc.py::TestNativeClientRootTPC`.
Delegation (`tpc.dlgon=1`, TPC-lite `tpc.scgi`) is NOT implemented in the
native client.

### Outbound source auth (GSI / `ztn` / delegated tokens)

A strong module capability is reaching real grid origins (dCache/EOS) for the
pull. `gsi_outbound_finish.c` selects the auth method from the source's login
`&P=` parameter block: prefer WLCG JWT (`ztn`) when a token is available, fall
back to **hand-rolled GSI** (`gsi_outbound_certreq.c` + `gsi_outbound_exchange.c`:
Diffie-Hellman key exchange, derive shared secret, encrypt and send the cert
chain `kXGC_cert`, optional server-cert verification against the configured CA
store with `X509_V_FLAG_ALLOW_PROXY_CERTS`). `gsi_outbound_dh_helpers.c` handles
the `cipher_alg`/`md_alg` buckets — cipher selection from `kXRS_cipher_alg`,
hex-pubkey → `BIGNUM`, peer `EVP_PKEY` assembly. `tpc_token.c` fetches delegated
OAuth2/OIDC tokens (`oidc-agent` mode or RFC 8693 token-exchange via `curl`),
configured by `brix_tpc_outbound_token_endpoint` / `_client_id` / `_client_secret`
/ `_scope` / `_bearer_file`.

Official GSI uses GSSAPI/`XrdSecgsi`; the module re-implements the GSI DH exchange
directly against OpenSSL. Interop with grid origins is the explicit design target
(memory: GSI xcache vs real EOS), but multi-hop / TLS-upgrade edge cases are
flagged as needing per-site verification.

### TPC controls

| Concern | Official `ofs.tpc` | BriX-Cache |
|---|---|---|
| Enable / key TTL | `ofs.tpc ttl <d>[ <m>]` | `brix_tpc_keys on`, `brix_tpc_key_ttl` |
| Concurrency | `ofs.tpc xfr`, `streams` | `brix_tpc_transfers`, `brix_tpc_max_transfer_secs`, `brix_tpc_transfer_max_age` |
| Source restriction | `ofs.tpc allow {dn\|group\|host\|vo}`, `restrict <path>` | SSRF policy `brix_tpc_allow_local` / `brix_tpc_allow_private` (two-stage: event-thread preflight + per-resolved-address recheck at connect, closing the resolve/connect TOCTOU) |
| Credential delegation | `ofs.tpc fcreds <auth> =<envar>`, `fcpath` | `brix_tpc_outbound_*` (OIDC/token-exchange + bearer file); GSI cert via `gsi_store` |
| Confinement | OSS namespace | mandatory `brix_open_beneath(conf->rootfd, ...)` (`RESOLVE_BENEATH`); `launch.c` strips `root_canon` to pass the logical path |

The module does **not** implement an external-program transfer model
(`ofs.tpc pgm`); it always pulls in-process via its own XRootD client.

## Proxy mode

There are two distinct things called "proxy" here, and they differ from official
XrdPss.

### Official XrdPss

`XrdPss` is a **storage backend (OSS) plugin**, not a wire-level frame relay. The
`xrootd` server is configured with PSS as its OSS layer (`ofs.osslib` →
`libXrdPss`); PSS implements the POSIX-like `XrdOss` interface by calling the
`XrdCl`/`XrdPosix` client to fetch from an origin (`XrdPss/XrdPss.cc` calls
`XrdPosixXrootd::Stat/Opendir/...`). Origin and identity are configured with
`pss.origin =[<prot>,...] <host>:<port>` and `pss.persona client|server`
(`XrdPss/XrdPssConfig.cc` `xorig()`/`xpers()`); per-request identity/credential
forwarding is built in `XrdPss/XrdPssUrlInfo.cc` (e.g. `pss.tid=<tident>`, SSS
persona). Because it is an OSS plugin, every server operation (read, write, stat,
dirlist) flows through the XrdCl client to origin — it is a *re-client*, not a
byte forwarder.

### Module `src/net/proxy/` (transparent frame relay)

`brix_proxy on` makes the node a **transparent reverse proxy** at the wire
level. After local auth + TLS termination, `src/protocols/root/handshake/dispatch.c` calls
`brix_proxy_dispatch()` for every post-login opcode (once
`conf->proxy_enable && ctx->logged_in`), *before* any local read/write handler —
so no local path is ever resolved. The proxy drives an independent event-loop
state machine on the upstream socket: async TCP connect → optional TLS → XRootD
bootstrap (handshake + `kXR_protocol` + `kXR_login` + optional `kXR_auth`) →
IDLE → FORWARDING, while the client read loop is parked in `XRD_ST_PROXY`. It
forwards opcodes verbatim and translates file handles and stream IDs end-to-end.

This is **architecturally different from XrdPss**: PSS re-issues high-level OSS
operations through a client library; the module relays the raw XRootD frames.
The module approach is a true protocol bridge — the backend sees the proxy's
login, the client sees one endpoint.

Capabilities (`src/net/proxy/`, memory: proxy enhancements / phase 2-3):

- **Upstream credentialing** `brix_proxy_auth anonymous|forward|sss|sss:<keyname>`
  and per-endpoint overrides on `brix_proxy_upstream host[:port] [auth]`:
  anonymous; forward the client's WLCG bearer as a `ztn` credential; SSS keys
  (global or per-upstream, via `brix_sss_build_proxy_credential`); or a
  file-token bridge. Pool reuse is **credential-scoped** (index + auth type +
  bearer-token MD5), so a forwarded-token session never reuses another user's
  backend connection.
- **Upstream TLS** `brix_proxy_upstream_tls on` with `_tls_ca` / `_tls_name`
  (SNI + optional cert verify).
- **`kXR_bind` secondary proxying with lazy-open** — a bound secondary
  `read`/`pgread`/`readv` whose handle has no upstream mapping triggers a
  synthetic `kXR_open` first; `kXR_readv` collects all unresolved handles and
  opens them one at a time before dispatching.
- **Transparency features the client never sees:** `kXR_wait` is absorbed and the
  request silently retried via a timer (capped); `kXR_redirect` is followed
  in-process (up to 3 hops); `kXR_attn` is relayed with its own streamid;
  zero-copy `splice()` for plaintext reads (declined when either side is TLS);
  the `kXR_status` two-phase pgread/pgwrite framing is preserved.
- **Idle-only reconnect recovery** (`brix_proxy_reconnect_attempts`): a drop
  while IDLE with no open handle re-bootstraps transparently; a drop mid-transfer
  is a hard `kXR_IOError`.
- **Path rewriting** `brix_proxy_path_rewrite /strip /add`, multi-upstream
  round-robin over healthy endpoints, a worker-local idle-connection pool
  (`brix_proxy_pool`), `kXR_endsess` forwarding, and JSON audit logging of file
  and path-mutation ops (`brix_proxy_audit_log`).

> Critical fix (memory: *proxy retry leak postmortem*): a proxy whose upstream
> *permanently* rejected the forwarded credential previously spun forever in the
> upstream read handler's `for(;;)` loop (95% CPU, RSS to >20GB) because the loop
> keyed liveness off `proxy->state` while `brix_proxy_abort` signalled teardown
> via `ctx->proxy = NULL`. The fix is one teardown guard at the top of the loop in
> `src/net/proxy/events_read.c` — `if (ctx->proxy != proxy) return;` — keying off the
> same signal abort sets, catching abort from any branch. A
> `BRIX_PROXY_MAX_CONN_FAILS=8` per-connection cap is kept as defence-in-depth.

### Module WebDAV proxy and `src/net/upstream/`

For completeness, one more outbound path exists (see also the HTTP comparison
page): `src/net/upstream/` (described under [Redirection](#confirming-with-the-data-server-srcupstream))
is the narrow redirector-confirmation client, **not** a transparent proxy.
The dedicated WebDAV reverse-proxy (`brix_webdav_proxy`, `src/protocols/webdav/proxy.c`)
was removed after the relay path to stock XrdHttp backends proved unstable — those
directives are no longer available.

## Traffic mirroring (nginx-forward)

This is an **BriX-Cache extension with no official equivalent** — there is no
shadow-replay subsystem in the reviewed XRootD source. It exists for migration
validation: stand up a new backend behind a production gateway and prove it
answers identically against real traffic before cutover.

`src/net/mirror/` replays a sampled copy of live requests to up to 4 shadow backends
*after* the primary has already answered, compares the shadow status against the
primary's, and counts divergence. The client never sees the shadow response and
is never delayed. Three surfaces share one config block (`brix_mirror_conf_t`)
and one set of low-cardinality counters:

- **HTTP/WebDAV** (`http_mirror.c`): a PRECONTENT-phase handler fires one
  `NGX_HTTP_SUBREQUEST_BACKGROUND` per shadow, proxied with credentials stripped;
  a LOG-phase handler stamps the primary status for comparison.
- **Stream reads & metadata mutations** (`stream_mirror.c`): a self-contained
  async XRootD client opens a fresh shadow session, replays the *saved request
  frame* (streamid rewritten to `0x0002` as a loop guard), reads one response,
  and discards it. Only side-effect-free frames are replayed — locate/dirlist/
  query, path-based stat/statx, and **read-only** opens; handle-based reads are
  skipped because the primary's file handle is meaningless on the shadow's
  separate session (this is what lets the mirror sit in front of a real
  `xrootd` without spurious divergence).
- **Stream data writes ("W3", `stream_wmirror.c`)**: the stateful
  `open(write) → write → close` sequence is buffered per file and, on close,
  replayed to an **isolated** shadow as `open(create) → write → close`.

Safety model (load-bearing): mirroring is **off by default**; writes are
**double-gated** — a write op mirrors only when it is both listed
(`brix_mirror_opcodes`/`_methods`) **and** `brix_mirror_writes on`. The
shadow **MUST be an isolated namespace** (separate server/root); replaying writes
to a shadow that shares the primary's backing store would corrupt data. Stream
and write replays own a pool created from `ngx_cycle->pool` (never the client
pool/log, which may free first — that would be a use-after-free). Benign
differences — a shadow returning `kXR_Unsupported`, or demanding
`kXR_gotoTLS`/`kXR_authmore` — are treated as alive-but-different and not counted
as divergence. Configured by `brix_mirror_url` (HTTP) /
`brix_stream_mirror_url` (stream), `brix_mirror_sample`,
`brix_mirror_writes`, `brix_mirror_opcodes` / `_exclude_opcodes` /
`_methods`, `brix_mirror_strip_auth`, `brix_mirror_token`,
`brix_mirror_log_diverge`, `brix_mirror_timeout`.

## Admin deployment (both sides)

### Redirector + data servers, official XRootD

Run **both** `cmsd` and `xrootd` on each node from one config, scoping ports per
program (memory: known-good `cmsd` cfg idiom):

```
# Manager node (redirector):
all.role manager
all.manager <self-host>:<cmsport>
xrd.port <dataport>
if exec cmsd
  xrd.port <cmsport>
fi
cms.delay startup 5 servers 1 lookup 2   # else first locate can hang ~90s

# Data server node:
all.role server
all.manager <mgr-host>:<mgrcmsport>
xrd.port <dataport>
if exec cmsd
  xrd.port <cmsport>
fi
ofs.tpc ttl 7 15        # enable native TPC on data servers
```

Clients then `xrdcp root://<mgr-host>:<dataport>//path /local` and get redirected
to a data server. PSS proxying is a separate `ofs.osslib libXrdPss` +
`pss.origin` deployment.

### Redirector + data servers, BriX-Cache

```nginx
# Redirector / manager (serves no files):
stream {
    server {
        listen 1094;
        brix_root on;
        brix_manager_mode on;        # redirect, do not serve locally
        brix_cms_server on;          # accept CMS registrations from data nodes
        brix_cms_server_allow 10.0.0.0/8;          # CIDR trust gate
        # brix_cms_server_sss_keytab /etc/brix/cms.keytab;  # fail-closed SSS
        brix_registry_slots 256;
        brix_collapse_redir on;      # advertise kXR_collapseRedir + cache
        # static route alternative to live CMS membership:
        # brix_manager_map /atlas/ ds1.example.org:1094;
        # brix_virtual_redirector on;
    }
}
```

```nginx
# Data server (registers up to the manager):
stream {
    server {
        listen 1095;
        brix_root on;
        brix_export /data/export;
        brix_listen_port 1095;       # advertised in the CMS login (must match)
        brix_cms_manager mgr.example.org:1094;
        brix_tpc_keys on;            # enable native destination-pull TPC
        brix_tpc_allow_private off;  # SSRF policy for the outbound pull
        # brix_tpc_outbound_bearer_file /etc/brix/tpc.token;  # source auth
    }
}
```

A **sub-manager** in a meta tree sets both `brix_cms_server on` (to leaves
below) and `brix_cms_manager <meta>:<port>` (up to the meta). A redirector
needs **no** `brix_export` (memory: validation skips it in manager mode; data
servers on non-default ports **must** set `brix_listen_port`).

Transparent proxy and mirror are separate `server {}` modes:

```nginx
# Transparent root:// proxy in front of a backend cluster:
server {
    listen 1196;
    brix_root on;
    brix_proxy on;
    brix_proxy_upstream backend.example.org:1094 forward;  # forward client ztn
    brix_proxy_upstream_tls on;
    brix_proxy_auth forward;
    brix_proxy_pool on;
}

# Shadow a new backend for migration validation (isolated namespace!):
server {
    listen 1094;
    brix_root on;
    brix_export /data/export;
    brix_stream_mirror_url newbackend.example.org:1094;
    brix_mirror_sample 10;            # 10% of traffic
    # brix_mirror_writes on;          # ONLY with an isolated shadow store
}
```

## Parity, divergences, and extensions

| Capability | Official XRootD | BriX-Cache | Status |
|---|---|---|---|
| Cluster daemon model | Separate `cmsd` per node (`XrdCms/`) | In-process stream modules (`src/net/cms/`) | Different architecture, comparable function |
| Role taxonomy | 9 roles (`XrdCmsRole.hh`) | server / manager / sub-manager / supervisor-flag | Partial — practical subset |
| CMS login + Pup encoding | `XrdCmsLogin.cc`, `XrdOucPup.cc` | `src/net/cms/send.c`, `wire.c` (real format, fixed) | Parity — validated nginx→real-`cmsd` |
| `kYR_xauth` SSS cluster auth | `XrdCmsSecurity.cc`, opt-in | `src/net/cms/server_auth.c`, fail-closed when keytab set | Parity (negative path live; positive real-`cmsd` blocked by upstream packaging — not verified) |
| On-demand select (`kYR_state`→`kYR_have`) | `XrdCmsNode.cc`/`Cluster.cc` | `src/net/cms/recv.c` (kernel-confined probe) | Parity + stronger confinement |
| Ping/pong, load/space heartbeat | `XrdCmsNode.cc`, `XrdCmsMeter.cc` | `src/net/cms/send.c`/`recv.c`, `space.c` | Parity |
| CMS resilience caps (frames/wakeup, per-IP, timeouts) | Not discrete `cmsd` knobs | `src/net/cms/server_*` directives + metrics | nginx+ |
| Client redirect (`kXR_redirect`) | `XrdXrootd` + `XrdCmsFinder` | `src/protocols/root/read/open_request.c`/`locate.c`/`stat.c` | Parity |
| `tried/triedrc` loop avoidance | Client CGI honoured by manager | `brix_manager_tried_exhausted`/`brix_srv_select` | Parity |
| Redirect collapse cache | Client/server mechanics | SHM `redir_cache.c` + `kXR_collapseRedir` | nginx+ |
| Static `manager_map` routing | n/a (always live `cmsd`) | `src/core/config/manager_map.c` | nginx+ |
| Virtual redirector | Clients understand `kXR_attrVirtRdr` | `brix_virtual_redirector` static-map mode | nginx+ |
| Redirector-confirm outbound client | `cmsd` mesh | `src/net/upstream/` (locate/open/stat only) | Different mechanism |
| Native TPC key rendezvous | In-process mutex list (`XrdOfsTPCAuth.cc`) | **Cross-process SHM** registry (`key_registry.c`) | Parity + cross-worker, zero-copy |
| TPC arm/flush handshake | Built-in/`pgm` driven | Two-phase via `kXR_sync` (`launch.c`/`sync.c`) | Parity |
| TPC outbound source auth | `XrdSecgsi` + `fcreds` | hand-rolled GSI DH + `ztn` + OIDC/RFC8693 (`gsi_outbound_*`, `tpc_token.c`) | Parity (multi-hop/TLS edges not verified) |
| External-program TPC (`ofs.tpc pgm`) | Yes | No (always in-process pull) | Missing (by design) |
| Proxy storage model | XrdPss OSS re-client (`XrdPss/`) | Transparent wire frame relay (`src/net/proxy/`) | Different architecture |
| Proxy upstream TLS / auth bridge / pool | XrdPss persona + XrdCl | `brix_proxy_*` (ztn/SSS/file, TLS, credential-scoped pool) | nginx+ for wire-relay form |
| Proxy `kXR_wait`/`kXR_redirect`/`kXR_bind` transparency | Client/server async | absorbed/followed/lazy-open in `src/net/proxy/` | Parity / nginx+ |
| Proxy async `kXR_attn` full relay | Yes | `kXR_waitresp` forwarded; complete unsolicited `kXR_attn` path not fully verified | Partial (not verified) |
| Traffic mirroring / shadow replay | None found | `src/net/mirror/` (HTTP + stream reads + gated writes) | nginx+ (extension) |

## Source references

Official XRootD (`/tmp/brix-src/src/`):

- CMS roles/config: `XrdCms/XrdCmsRole.hh`, `XrdCms/XrdCmsConfig.cc` (`xrole`),
  `XrdCms/XrdCmsConfig.hh` (`ManList`/`NanList`/`SanList`).
- CMS wire/login: `XProtocol/YProtocol.hh` (`CmsRRHdr`, `CmsLoginData`,
  `CmsReqCode`/`CmsRspCode`, status flags), `XrdCms/XrdCmsLogin.cc/.hh`,
  `XrdCms/XrdCmsParser.cc`, `XrdCms/XrdCmsSecurity.cc`, `XrdOuc/XrdOucPup.cc/.hh`.
- CMS selection/redirect: `XrdCms/XrdCmsCluster.cc`, `XrdCms/XrdCmsNode.cc`
  (`do_Locate`/`do_State`/`do_Have`/`do_Status`/`do_Ping`/`do_Load`),
  `XrdCms/XrdCmsCache.cc`, `XrdCms/XrdCmsFinder.cc`,
  `XrdXrootd/XrdXrootdXeq.cc` (`do_Locate`), `XrdXrootd/XrdXrootdProtocol.cc`.
- CMS hierarchy/meter/blacklist: `XrdCms/XrdCmsManTree.cc`,
  `XrdCms/XrdCmsManList.cc`, `XrdCms/XrdCmsMeter.cc`,
  `XrdCms/XrdCmsBlackList.cc`, `XrdCms/XrdCmsClustID.cc`.
- Proxy: `XrdPss/XrdPss.cc`, `XrdPss/XrdPssConfig.cc` (`xorig`/`xpers`),
  `XrdPss/XrdPssUrlInfo.cc`.
- Native TPC: `XrdOfs/XrdOfsTPC.cc`, `XrdOfsTPCAuth.cc`, `XrdOfsTPCInfo.cc`,
  `XrdOfsTPCConfig.hh`, `XrdOfsTPCJob.cc`, `XrdOfsTPCProg.cc`,
  `XrdOuc/XrdOucTPC.cc`, `XrdOfs/XrdOfsConfig.cc` (`xtpc`).

BriX-Cache (repo-relative `src/`):

- CMS: `src/net/cms/` — `connect.c`, `recv.c`, `send.c`, `wire.c`, `space.c`,
  `frame_io.c`, `cms_internal.h`; manager half `server_handler.c`,
  `server_recv.c`, `server_send.c`, `server_auth.c`, `server_module.c`,
  `server.h`; and [`src/net/cms/README.md`](../../../../src/net/cms/README.md).
- Redirector control plane: `src/net/manager/` — `registry.c`/`.h`,
  `redir_cache.c`/`.h`, `pending.c`/`.h`, `health_check.c`/`.h`;
  static routes `src/core/config/manager_map.c`; read-path
  `src/protocols/root/read/locate.c`, `src/protocols/root/read/open_request.c`, `src/protocols/root/read/stat.c`,
  `src/protocols/root/dirlist/handler.c`; and [`src/net/manager/README.md`](../../../../src/net/manager/README.md).
- Redirector-confirm client: `src/net/upstream/` — `start.c`, `bootstrap.c`,
  `request.c`, `response.c`, `tls.c`, `auth.c`, `events.c`, `lifecycle.c`,
  `directives.c`; and [`src/net/upstream/README.md`](../../../../src/net/upstream/README.md).
- Native TPC: `src/tpc/` — `parse.c`, `launch.c`, `thread.c`, `connect.c`,
  `bootstrap.c`, `source.c`, `io.c`, `done.c`, `key_registry.c`/`.h`,
  `gsi_outbound_*.c`, `tpc_token.c`, `tpc_internal.h`, `common/`; arm/flush
  trigger `src/protocols/root/write/sync.c`; and [`src/tpc/README.md`](../../../../src/tpc/README.md).
- Proxy: `src/net/proxy/` — `forward_relay_dispatch.c`, `connect_upstream.c`,
  `connect_lifecycle.c`, `events_read.c` (teardown-guard leak fix),
  `events_write.c`, `events_bootstrap.c`, `events_splice.c`,
  `forward_request.c`, `forward_relay*.c`, `pool.c`, `directives.c`,
  `proxy_internal.h`; WebDAV counterpart `src/protocols/webdav/proxy.c`; and
  [`src/net/proxy/README.md`](../../../../src/net/proxy/README.md).
- Mirroring: `src/net/mirror/` — `mirror.h`, `http_mirror.c`, `stream_mirror.c`,
  `stream_wmirror.c`; and [`src/net/mirror/README.md`](../../../../src/net/mirror/README.md).
- Cross-cutting context: [`../../source-verified-xrootd-comparison.md`](../../source-verified-xrootd-comparison.md)
  (Cluster, Redirector, Proxy, and TPC section).
