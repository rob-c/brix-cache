# Read-Only Public `root://` Gateway

A public, anonymous `root://` endpoint that fronts an XRootD server and cannot
be written to — by anyone, through any opcode. This page gives the config, then
the opcode-by-opcode evidence that the guarantee actually holds, then the
things that are *not* covered by it.

The verification for everything on this page is executed, not asserted:
`tests/test_cmd_root_readonly_gateway.py` — rig and probe table in
`tests/cmdscripts/root_readonly_gateway.py`, the exhaustive sweeps in
`tests/cmdscripts/root_readonly_gateway_deep.py`. One run starts six instances
(the XRootD origin, this gateway, a `read_only`+`allow_write` gateway, a
writable control, a substreams-off gateway and a `brix_read_only_public`
gateway) and fires ~360 checks at them.

Every expectation on this page is *derived from the C*, not copied from it: the
opcode list is parsed out of `opcodes.h`, the routing classification out of the
four `dispatch_*.c` tables, and the write-implying open flags out of
`BRIX_OPEN_WRITE_BITS`. A new opcode, a new route or a new write flag therefore
enters the sweep the moment it is defined, and an unswept one fails the test.

---

## 1. The configuration

```nginx
# nginx.conf — public read-only root:// gateway in front of an XRootD origin
events { worker_connections 1024; }

stream {
    server {
        listen 1094;

        brix_root on;

        # Local scratch root. With a storage backend configured the namespace
        # is served from the origin; this directory is the server's own working
        # area (checkpoint recovery lock, staged temporaries).
        brix_export /var/lib/brix/export;

        # Anonymous: every client logs in without a credential.
        brix_auth none;

        # THE SWITCH. Forces allow_write off at config-merge time, so every
        # write gate in the protocol refuses before the VFS is reached and
        # before any token scope is consulted.
        brix_read_only on;

        # Stricter variant — see §6. Implies brix_read_only AND additionally
        # refuses the kXR_query infotypes that describe the SERVER (statistics,
        # space, config values). Use it instead of brix_read_only when the
        # listener faces the open internet.
        # brix_read_only_public on;

        # Where the bytes actually live.
        brix_storage_backend root://internal-xrootd.example.org:1094;

        # Hot cache tier (optional but recommended: it keeps repeat reads off
        # the origin). Written by the SERVER, never by a client — see §4.
        brix_cache_store posix:/var/cache/brix;
    }
}
```

The matching XRootD origin needs nothing special — it is an ordinary server;
the gateway speaks `root://` to it as a client:

```
xrd.port 1094
all.export /
oss.localroot /srv/data
all.adminpath /var/spool/xrootd
all.pidpath   /var/spool/xrootd
```

On startup the gateway states its posture in the error log:

```
brix: root:// endpoint ready — export "/var/lib/brix/export" (read-only), auth: none (anonymous)
```

Validate before serving: `nginx -t`.

---

## 2. Why the whole surface is covered

`brix_read_only on` is not a per-operation flag. `brix_shared_apply_read_only()`
(`src/core/config/shared_conf.h`) forces `common.allow_write = 0` during the
config merge, and the stream plane applies it in
`src/core/config/runtime_server.c`. Two consequences matter:

* **It overrides `brix_allow_write on`.** If both are present, read-only wins
  and the merge logs a `NOTICE` saying so. An operator cannot re-open the
  surface by accident, and neither can a config include ordering change.
* **It is checked before token scope** (INVARIANT 3). A WLCG token carrying a
  `storage.modify` scope cannot bypass it, because `allow_write` is consulted
  first.

Every mutating opcode then funnels through one of four choke points:

| Choke point | Source | Covers |
|---|---|---|
| `brix_dispatch_require_write()` | `src/protocols/root/handshake/policy.c` | every row of the write-gated route table in `dispatch_write.c` |
| `brix_open_mode_guard()` | `src/protocols/root/read/open_request.c` | `kXR_open` in any write mode |
| fattr write-subcode gate | `src/protocols/root/fattr/dispatch.c` | `kXR_fattrSet`, `kXR_fattrDel` |
| `brix_validate_write_handle()` | `src/protocols/root/connection/fd_table.c` | `kXR_clone` (derived: no writable handle can exist) |

`kXR_open` and `kXR_fattr` sit in the *read* dispatch table — they are
auth-gated, not write-gated — which is exactly why they carry their own gates.
`kXR_prepare` with `kXR_wmode` is refused in `src/protocols/root/query/prepare.c`;
a TPC **destination** open (a pull *into* this server) is refused in
`src/protocols/root/read/open_tpc.c`.

---

## 3. The verified refusal matrix

Live results against the config in §1, with a stock `xrootd` origin behind it.
The identical set is produced with `brix_read_only on` alone and with
`brix_allow_write on; brix_read_only on;` together.

| Opcode / form | Result |
|---|---|
| `kXR_open` create-new (`updt\|new`) | `kXR_fsReadOnly` (3025) |
| `kXR_open` truncate (`updt\|delete`) | `kXR_fsReadOnly` |
| `kXR_open` update (`updt`) | `kXR_fsReadOnly` |
| `kXR_open` append (`apnd`) | `kXR_fsReadOnly` |
| `kXR_open` write-to (`wrto`) | `kXR_fsReadOnly` |
| `kXR_open` `mkpath\|new` | `kXR_fsReadOnly` |
| `kXR_open` `posc\|new` | `kXR_fsReadOnly` |
| `kXR_open` TPC destination (`tpc.src=`+`tpc.key=`) | `kXR_fsReadOnly` |
| `kXR_mkdir` | `kXR_fsReadOnly` |
| `kXR_rm` | `kXR_fsReadOnly` |
| `kXR_rmdir` | `kXR_fsReadOnly` |
| `kXR_mv` | `kXR_fsReadOnly` |
| `kXR_chmod` | `kXR_fsReadOnly` |
| `kXR_truncate` (by path) | `kXR_fsReadOnly` |
| `kXR_write` | `kXR_fsReadOnly` |
| `kXR_pgwrite` | `kXR_fsReadOnly` |
| `kXR_writev` | `kXR_fsReadOnly` |
| `kXR_sync` | `kXR_fsReadOnly` |
| `kXR_chkpoint` | `kXR_fsReadOnly` |
| `kXR_fattr` set | `kXR_fsReadOnly` ("fattr: server is read-only") |
| `kXR_fattr` del | `kXR_fsReadOnly` ("fattr: server is read-only") |
| `kXR_setattr` (vendor ext) | `kXR_fsReadOnly` |
| `kXR_symlink` (vendor ext) | `kXR_fsReadOnly` |
| `kXR_link` (vendor ext) | `kXR_fsReadOnly` |
| `kXR_prepare` with `kXR_wmode` | `kXR_fsReadOnly` |
| `kXR_clone` onto an open READ handle | `kXR_NotAuthorized` (3010), "file not open for writing" |

The write-gated set is not a hand-written list: the test parses the
`brix_wr_routes[]` table out of `dispatch_write.c` and fails if any row is not
probed. A new mutating opcode added to the dispatcher therefore breaks this
test rather than silently widening the public surface.

What still works, unchanged:

| Operation | Result |
|---|---|
| `kXR_open` read | `kXR_ok` |
| `kXR_read` / `kXR_readv` / `kXR_pgread` | origin bytes |
| `kXR_stat` | `kXR_ok` |
| `kXR_dirlist` | `kXR_ok` |
| `kXR_fattr` get / list | `kXR_ok` |
| `kXR_prepare` without `kXR_wmode` | not refused as read-only |

`xrdcp`/`xrdfs` against the gateway behave exactly as against the origin for
every read operation. Note that the `flags` field of a `kXR_stat` reply is
derived from POSIX mode bits against the server's effective uid
(`brix_stat_flags_from_stat`), **not** from `brix_read_only` — a client cannot
infer the posture from it and must take the `kXR_fsReadOnly` refusal as the
authority.

### 3.1 The exhaustive sweeps

The matrix above is the hand-considered set. Because "the *whole* surface is
read-only" is a claim about everything that is *not* on a hand-written list,
the same run also sweeps the spaces exhaustively:

| Sweep | Extent | Result |
|---|---|---|
| Whole opcode space | all **37** request ids in `opcodes.h`, standard and vendor | every write-routed id → `kXR_fsReadOnly`; the one id routed by no dispatch table (`kXR_gpfile`, 3005) → `kXR_InvalidRequest` (3006) "Invalid request code" |
| `kXR_open` option word | **73** words: every one of the 16 single bits, every combination of the write-implying bits, each also `\|kXR_open_read` | every word intersecting `BRIX_OPEN_WRITE_BITS` (= `0x822a`: `delete\|new\|updt\|apnd\|wrto`) → `kXR_fsReadOnly`; no read-only word misrefused |
| `kXR_query` infotypes | all **13**, including `kXR_Qopaquf`/`kXR_Qopaqug` (the FSctl escape hatches) and `kXR_Qckscan` | all answered, nothing mutated — but see §5.1; under `brix_read_only_public` the five server-scoped ones are refused instead (§6) |
| Path spellings | 10 shapes: traversal, deep traversal, doubled separators, trailing slash, dot segment, opaque suffix, embedded NUL, relative, `/`, empty | none accepted |
| Before authentication | all 25 mutating probes sent pre-`kXR_login`, and one sent pre-handshake | pre-login → `kXR_NotAuthorized` (3010); pre-handshake → nothing executed |
| Bound secondary stream | `kXR_bind`, then the one opcode `policy.c` lets a bound stream carry | bound `kXR_write` → `kXR_fsReadOnly`; every other opcode from a bound stream → `kXR_NotAuthorized` first |
| Signing envelope | `kXR_sigver`-prefixed `kXR_mkdir` | `kXR_fsReadOnly` — the envelope does not smuggle the covered request past the gate |
| Session opcodes | `kXR_set` (appid, clttl, `cms.space`) and a second `kXR_login` on a live session | accepted/answered, then the *same* mutation is still `kXR_fsReadOnly` |
| Concurrency | all 25 probes across 8 threads simultaneously | every one `kXR_fsReadOnly`; no interleaving lifts the gate |
| Reload | `SIGHUP`, then re-probe | posture persists — a reload for an unrelated reason cannot silently open the gateway |

**The assertion is about bytes, not about error codes.** Every family above is
bracketed by a SHA-256 content digest of the origin tree *and* of the gateway's
own export directory, so a request that answered with an error while still
rewriting a file in place — or materialising a new one — is caught. Only the
server's own artefacts (the checkpoint-recovery lock) are exempted, by name.

---

## 4. What read-only does NOT mean

Four honest caveats. None is a hole in the protocol guarantee, but all of them
matter when you write the deployment ticket. (A fifth used to be listed here —
`brix_manager_mode` — and it *was* a genuine bypass; it is now refused at config
time instead. See below.)

**The cache tier is still written — by the server.** With
`brix_cache_store posix:…` configured, a read miss populates the cache
directory. `brix_read_only` makes the *protocol surface* read-only; it does not
make the server's own storage immutable. The client never chooses what lands
there and cannot address it.

**A read-only gateway can still act as a TPC *source*.** A TPC destination
elsewhere can pull bytes *out* of this gateway; that is egress, not mutation,
and it is governed separately by `brix_tpc_source_guard` /
`brix_tpc_source_allow`. Set those according to your egress policy. TPC
*destination* opens (pulls *in*) are refused — see the matrix above.

**Secondary data channels are enabled by default, and are still read-only.**
`brix_data_substreams` merges to *on*, so this gateway does accept a `kXR_bind`
secondary connection. That matters because a bound stream is the one route by
which a bare `kXR_write` reaches the dispatcher without an `open` on the same
connection — `policy.c` admits `kXR_write`, and only `kXR_write`, from a bound
stream. It is still refused with `kXR_fsReadOnly`; every other opcode from a
bound stream is refused with `kXR_NotAuthorized` before the write gate is even
reached. Setting `brix_data_substreams off;` makes `kXR_bind` itself answer
`kXR_Unsupported` — a reasonable narrowing for a public listener, but it is not
what makes the gateway read-only.

**`kXR_set` is reachable and is a pure log sink.** It is login-gated but not
write-gated (`dispatch_session.c`), so an anonymous client can send it. The
handler (`src/protocols/root/query/set.c`) only logs the modifier — it cannot
move `allow_write`, cannot change the export, and a mutation on the same
connection immediately afterwards is still refused. Verified for `appid`,
`clttl` and a `cms.space` payload.

One scoping quirk worth knowing: `kXR_prepare`'s path scan runs against the
local export rather than the storage backend, so a stage hint for a
backend-only path answers "file not found". That is pre-existing behaviour of
`prepare`, unrelated to the read-only gate.

### 4.1 `brix_manager_mode` + `brix_read_only` is a fatal config error

In manager mode `manager_redirect_mutation()` (`dispatch_write.c`) redirects
`mkdir`, `rm`, `rmdir`, `mv`, `chmod` and `truncate` to a data node *before* the
local write gate runs — by design, because a manager holds no data. The
consequence was measurable: with both directives set, a `kXR_mkdir` answered
`kXR_FSError` (3005) *"no data server available for path"*, **not**
`kXR_fsReadOnly`. The only thing standing between the client and a write was
that no data node happened to be available.

An operator who writes `brix_read_only on` believes they have a read-only
endpoint. On a manager they did not have one. So the pair is no longer merely
documented as dangerous — it is **refused**, at config-merge time, by
`brix_merge_srv_readonly_role_check()` in
`src/core/config/server_conf_merge_cluster.c`:

```
$ nginx -t
nginx: [emerg] brix_manager_mode and brix_read_only are mutually exclusive: a
manager redirects mkdir/rm/rmdir/mv/chmod/truncate to a data node BEFORE the
local read-only gate runs, so the endpoint would not be read-only. Put the
manager and the read-only gateway in separate server {} blocks
nginx: configuration file /etc/nginx/nginx.conf test failed
```

`nginx -t` fails and the master never starts, so the configuration cannot reach
production silently. The same applies to `brix_read_only_public`, which implies
`brix_read_only` — the message then says so explicitly. A manager **without**
either directive is unaffected and still parses normally.

A manager and a public read-only gateway are different roles. Put them in
different `server {}` blocks (or on different hosts); a manager that should not
be written to is constrained with authorization, not with `brix_read_only`.

---

## 5. Hardening the public listener

### 5.1 Read-only is not the same as non-disclosing

The guarantee on this page is about *mutation*. It says nothing about what a
public client can *learn*, and the `kXR_query` sweep makes that concrete — all
of the following are answered to an anonymous client on the config in §1:

| Infotype | Discloses |
|---|---|
| `kXR_QStats` (1) | server version, program name, hostname, listening port, live link counters |
| `kXR_Qxattr` (4) | `oss.*` metadata for any readable path (type, size, mtime, cgroup) |
| `kXR_Qspace` (5) | total / free / used bytes and quota of the filesystem holding the export |
| `kXR_Qconfig` (7) | configuration values by name — including `version` (which build) and `role` (cluster position) |
| `kXR_Qcksum` (3) | checksums of readable files |

If the deployment ticket says "public read-only", decide separately whether it
also says "public introspection". `kXR_QStats` in particular identifies the
build you are running. **`brix_read_only_public` (§6) is the switch that closes
this surface**; the config in §1 leaves it open.

### 5.2 Exposure controls

For a genuinely public endpoint pair the read-only switch with the usual
exposure controls:

```nginx
stream {
    # stream-level: the shared-memory zone the two limits below key into.
    brix_rate_limit_zone zone=pub:10m;

    server {
        listen 1094;
        brix_root on;
        brix_export /var/lib/brix/export;
        brix_auth none;
        brix_read_only on;
        brix_storage_backend root://internal-xrootd.example.org:1094;
        brix_cache_store posix:/var/cache/brix;

        # Advertise + require TLS for the data path where the deployment
        # warrants it. brix_tls on REQUIRES both certificate directives.
        brix_tls on;
        brix_certificate     /etc/brix/tls/gateway.crt;
        brix_certificate_key /etc/brix/tls/gateway.key;
        # brix_tls_require session data;

        # Bound the blast radius of anonymous clients.
        brix_rate_limit_rule   zone=pub key=ip rate=200r/s burst=400;
        brix_concurrency_limit zone=pub key=ip limit=32;
    }
}
```

Note `brix_rate_limit_rule` (the per-principal shaping rule) rather than the
older `brix_rate_limit`, which keys into a `brix_kv_zone` instead.

`brix_auth none` authenticates nobody, so `brix_min_sec_level intense` is
incompatible with it by design (it requires a non-anonymous identity). If you
need an authenticated read-only endpoint, keep `brix_read_only on` and switch
`brix_auth` — the read-only guarantee is orthogonal to the auth method.

---

## 6. `brix_read_only_public` — read-only *and* non-disclosing

`brix_read_only` answers the mutation question. `brix_read_only_public` answers
the disclosure one as well:

```nginx
events { worker_connections 1024; }

stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /var/lib/brix/export;
        brix_auth none;

        # Implies brix_read_only — you do not need both, and setting only this
        # one is the safer spelling because the two cannot then drift apart.
        brix_read_only_public on;

        brix_storage_backend root://internal-xrootd.example.org:1094;
        brix_cache_store posix:/var/cache/brix;
    }
}
```

At startup the implication is announced, not silent:

```
brix: read_only_public on - implies read_only; the export is read-only and server-introspection queries are refused
```

### 6.1 What it refuses

The `kXR_query` infotypes that describe the **server** rather than a path the
client is already allowed to read. The gate runs in `brix_handle_query()`
*before* routing, so no handler gets to answer partially.

| Infotype | Refused | Why |
|---|---|---|
| `kXR_QStats` (1) | ✅ | server version, program name, hostname, port, live link counters |
| `kXR_Qspace` (5) | ✅ | total / free / used bytes and quota of the backing filesystem |
| `kXR_Qvisa` (8) | ✅ | issues a visa/token against the server |
| `kXR_QFSinfo` (10) | ✅ | filesystem-level information |

All four answer `kXR_NotAuthorized` (3010) *"server introspection is disabled on
this public read-only endpoint"*, and the refusal is logged at `info` with the
peer address.

`kXR_Qconfig` (7) is **filtered per key** rather than refused — see §6.3, which
is the part to read if you care about transfer performance.

### 6.2 What it does *not* touch

Everything a client needs in order to browse and stream data:

| Surface | Still works |
|---|---|
| `kXR_dirlist`, `kXR_stat`, `kXR_open` (read), `kXR_read`/`kXR_readv` | ✅ listing and streaming are the point of the endpoint |
| `kXR_Qconfig` (7) | ✅ filtered per key, not refused — capability and limits answer, deployment identity does not (§6.3) |
| `kXR_Qcksum` (3) | ✅ `xrdcp` verifies transfers with it |
| `kXR_Qxattr` (4) | ✅ per-path `oss.*` metadata — scoped to a path the client can already read |
| `kXR_QPrep` (2), `kXR_Qckscan` (6), `kXR_QFinfo` (9) | ✅ path-scoped, unchanged |
| `kXR_Qopaque*` (16/32/64) | unchanged — already refused, `kXR_Unsupported` |

The test fires **every** infotype at a plain `read_only` gateway and at a
`read_only_public` one and compares: the only permitted difference is that the
four above flip from answered to refused. A build that over-refused (breaking
`xrdcp`) or under-refused (leaking server state) fails it.

### 6.3 `kXR_Qconfig`: deployment identity withheld, protocol capability kept

Refusing `kXR_Qconfig` outright is the obvious reading of "no config values",
and it is the wrong one — because the keys clients actually ask for are not site
configuration at all. They are the **protocol's own limits and capability
list**, and a client that cannot read them does not get a more secure endpoint,
it gets a slower one:

* `readv_ior_max` — bytes per vector-read element
* `readv_iov_max` — elements per `kXR_readv` request
* `pio_max`, `bind_max`, `fattr` — parallel-I/O, bound-stream and xattr limits
* `chksum` — the checksum list `xrdcp` negotiates transfer verification with
* `readv`, `tpc`, `tpcdlg`, `cmpread`, `cmpwrite`, `xrdfs.ext` — capability flags

XrdCl parses `readv_ior_max`/`readv_iov_max` with `atoi()` on a bare integer
line. A refusal is not distinguishable from a missing value, so the client
**silently falls back to conservative built-in defaults** and issues many more,
much smaller vector reads — against the one endpoint whose entire purpose is
streaming bulk data. Withholding those numbers hides nothing an anonymous client
could not establish by trying a large `readv` and seeing what comes back.

So the filter is per key, in the descriptor table in
`src/protocols/root/query/config.c`. Every row carries a `public_safe` column:

| Key | Under `brix_read_only_public` |
|---|---|
| `chksum`, `readv`, `readv_ior_max`, `readv_iov_max`, `pio_max`, `bind_max`, `fattr`, `tpc`, `tpcdlg`, `cmpread`, `cmpwrite`, `xrdfs.ext`, `brix.substreams` | answered, byte-identically to a plain `read_only` gateway |
| `version` — which build is running | **withheld** |
| `role` — this node's place in a cluster | **withheld** |

A withheld key is answered exactly like an **unknown** key: the reference
`do_Qconf` default branch echoes the key name back, so `version` returns
`version` and `role` returns `role`. On the wire a restricted key is
indistinguishable from one this build never supported — no error to fingerprint,
no value to harvest, and the client takes a code path it already has.

**The column defaults to withheld.** A key added to that table later is
invisible to a public client until someone deliberately marks it safe, so the
disclosure decision cannot be forgotten.

The test fires every key in the table at both postures: capability keys must
match byte for byte, withheld keys must echo *and* their real value must appear
nowhere in the public answer, and a real four-element `kXR_readv` sized from the
advertised limits must be served by the public gateway.

### 6.4 It is still read-only

`brix_read_only_public` reaches the write gates through the implication applied
in `brix_shared_apply_read_only()`, so the mutation battery is fired at an
instance configured with **only** this directive — no explicit
`brix_read_only`. Every probe in §3 is refused with `kXR_fsReadOnly`, and the
digest brackets show nothing on disk moved. The implication is proven on the
wire, not assumed from the config.

The directive is registered on the `root://` stream plane only: the restricted
surface is `kXR_query`, which has no HTTP equivalent.

---

## See also

* [Configuration Reference](config-reference.md) — `brix_read_only`,
  `brix_read_only_public`, `brix_allow_write`, `brix_storage_backend`,
  `brix_cache_store`
* [Deployment Modes](../02-concepts/deployment-modes.md) — gateway vs. cache vs.
  manager roles
* [Production Deployment](production-deployment.md)
* [TLS Configuration](tls-config.md)
