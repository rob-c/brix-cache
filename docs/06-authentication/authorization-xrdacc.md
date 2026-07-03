# XrdAcc-compatible authorization (`brix_authdb_format xrdacc`)

The module ships **two** authorization-database engines, selected per server by
`brix_authdb_format`:

| Format | Engine | Use when |
|---|---|---|
| `native` (default) | `src/auth/authz/authdb.c` — `u/g/p/a` records, 6 privilege bits, single longest-prefix rule, root:// only | existing deployments; simple per-DN/VO/host-CIDR ACLs |
| `xrdacc` | `src/auth/authz/acc/` — a faithful re-implementation of XRootD's **XrdAcc** | dropping in a stock XRootD `authdb`; full XrdAcc grammar + semantics |

`native` is unchanged and remains the default, so existing configs are unaffected.

> For the bigger picture — how an X.509/VOMS/VO or token/SSS identity becomes a
> local UNIX **user/group** (incl. OS `getpwnam`/`getgrouplist` resolution,
> created-file ownership, and how to force/override a mapping) — see
> [**identity-mapping.md**](identity-mapping.md).

## Enabling the XrdAcc engine

```nginx
server {
    listen 1094;
    xrootd on;
    brix_root /export;
    brix_auth token;                 # or gsi / none (anon `u *` rules)
    brix_authdb_format xrdacc;        # <-- select the XrdAcc engine
    brix_authdb /etc/brix/authdb;   # a stock XRootD authdb file
    brix_authdb_audit all;            # none | deny | grant | all
    brix_authdb_refresh 60;           # hot-reload on mtime change (s); 0 = off
}
```

OS/NIS group resolution tunables (XrdAcc `acc.*` equivalents):

```nginx
brix_acc_gidlifetime 43200;          # Unix-group cache TTL (s)
brix_acc_pgo;                        # resolve the primary Unix group only
brix_acc_nisdomain example.org;      # NIS domain for netgroup lookups
brix_acc_gidretran "65534 100";      # gids to skip (ambiguous shared gid->name)
```

Host matching and legacy authdb encoding (off by default):

```nginx
brix_acc_resolve_hosts on;           # reverse-DNS the peer so `h <host>` rules match
brix_acc_spacechar +;                # substitute `+`->space in authdb identity names
brix_acc_encoding on;                # URI-decode authdb path tokens (%20 -> space)
```

`brix_acc_resolve_hosts` does one blocking reverse lookup per connection
(cached); with it **off** (the default) `h`/`.domain` rules see only the peer IP
and never match a hostname, exactly as XrdAcc behaves until a host rule is
present. All of these directives are also valid in an `http` location (WebDAV/S3).

## authdb grammar

Identical to XRootD's `authdb`. Each record is one logical line
(`\`-continuation, `#` comments):

```
<idtype> <name> [<path|template> <privs>]...
```

| idtype | matches |
|---|---|
| `u <name>` / `u *` / `u =` | a user, all users (default), any authenticated user (fungible) |
| `g <name>` | a group (the credential's groups **and** the user's OS gidlist) |
| `o <name>` | an organization / VO |
| `r <name>` | a role (parsed from the VOMS `Role=` FQAN field or token) |
| `h <name>` / `h .domain` | a host, or a domain suffix |
| `n <name>` | a NIS netgroup (`innetgr`) |
| `= <id> <sel> <val>...` | a compound identity (AND of `u`/`g`/`h`/`o`/`r` selectors) |
| `x <id>` / `s <id>` | an **exclusive** (first-match-wins) / **inclusive** rule on a `=` id |
| `t <name>` | a reusable path template (referenced by name) |

**Privilege letters** (`XrdAccPrivs`): `a`=all, `d`=delete, `i`=insert,
`k`=lock, `l`=lookup, `n`=rename, `r`=read, `w`=write, and a single `-`
introduces **negative** (explicitly denied) privileges. The effective grant is
`(positive & ~negative)`.

> **Note:** unlike the `native` engine, `r` does **not** imply `l`. A stat needs
> `l` (lookup); a directory listing and a read need `r`. `a` means *all*
> privileges here (in `native`, `a` is the append/record-type letter).

Path templates substitute the connecting user's name at `@=`, e.g. a per-user
home: `u = /home/@=/ rwi`.

### Example

```
# everyone may list+read /public
u * /public rl
# per-user home directories (fungible)
u = /home/@=/ rwi
# the cms VO may read /cms; production role may also write
o cms /cms rl
r production /cms rw
# alice has everything under /data, but never delete /data/archive
u alice /data/archive ra-d  /data a
# a compound, exclusive rule: only cms-VO carol, and only on /devarea
= dev u carol o cms
x dev /devarea rwid
```

## Semantics (faithful to XrdAcc)

- **Additive accumulation.** Privileges are OR-ed across *every* matching
  identity (default → host/domain → netgroup → fungible → user → group → org →
  role → inclusive rules), then `positive & ~negative` is applied.
- **First-match within a list.** Within one identity's capability list the first
  path-prefix match wins, so order specific paths before general ones.
- **Exclusive rules short-circuit.** If an `x` rule applies, it is the *only*
  rule consulted — even the `u *` default is skipped.
- **Operation → privilege.** Each request maps to an XrdAcc operation
  (stat→lookup, read/readdir→read, mkdir→insert, rm→delete, chmod→chmod) and is
  granted only if the accumulated privileges satisfy it.
- **Create vs update.** A write open that *creates* a file (`kXR_new` / O_CREAT;
  WebDAV PUT to a new path; S3 PUT) is `AOP_Create` and needs **insert + read +
  write** (`rwi`); opening an *existing* file for write (truncate / append) is
  `AOP_Update` and needs only **read + write** (`rw`) — faithful to `XrdOfs`,
  which keys Create off O_CREAT alone. `mv` needs `n`(rename) on the source and
  `i`(insert) on the destination.
- **Staging.** `kXR_prepare`/QPrep (stage) and the WLCG Tape REST API use
  `AOP_Stage` (privilege `0x180`, granted only by `a`), routed through the same
  engine — not the native authdb.
- **Fail-closed.** No matching rule, or a failed authdb load, denies.
- **Hot reload.** `brix_authdb_refresh` re-reads the file on mtime change and
  atomically swaps the per-worker tables — no restart, no `reload`. Supported on
  **both** the stream (root://) and HTTP (WebDAV/S3) tiers; the HTTP timer is
  armed lazily on the first request in each worker.
- **Result cache.** When `brix_auth_cache` is configured the verdict is cached
  under a key that includes the operation and peer host (plus path, DN, VO and
  token scope), so a cached *update* grant is never replayed for a *create*, and
  a `h`-rule verdict is never shared across peers. Group membership — the one
  remaining input — is bounded by the `gidlifetime` TTL.
- **Audit.** `brix_authdb_audit` logs `grant`/`deny`/both as
  `xrootd authz: <id>@<host> grant|deny <op> "<path>"` (fields sanitised).

## Protocol coverage

The `xrdacc` engine authorizes **all three protocols** through one decision
engine:

| Protocol | Operation → XrdAcc op | Identity |
|---|---|---|
| **root://** (stream) | open-rd→read, open-wr→update, stat→stat, dirlist→readdir, mkdir→insert, rm→delete, mv→rename, chmod→chmod | DN / token subject + FQAN VO/role/group |
| **WebDAV** (davs://) | GET/HEAD→read, PUT→create, DELETE→delete, MKCOL→mkdir, MOVE→rename, COPY→read, PROPFIND→readdir, PROPPATCH/LOCK→update | cert DN / bearer-token subject |
| **S3** | GET→read, HEAD→stat, PUT/POST→create, DELETE→delete | SigV4 access key |

Set `brix_authdb_format xrdacc;` + `brix_authdb <path>;` in the `stream`
server block (root://) and/or the `http` location (WebDAV/S3). For HTTP the
tables are built lazily per worker on first request, and the refresh timer is
armed at that point; the stream tier builds and arms at worker start. Every
`brix_authdb_*` / `brix_acc_*` directive is valid in both tiers; the HTTP
forms are registered once (by the WebDAV module) and configure both the WebDAV
and S3 loc-confs from a single shared `brix_acc_http_t` block.

## Implementation

`src/auth/authz/acc/` (see its `README.md`): `privs.c` (privilege algebra), `authfile.c` +
`tables.c` + `capability.c` (grammar → tables, incl. spacechar/encoding),
`entity.c` + `access.c` (the decision engine), `groups.c` (OS/NIS resolution +
gidretran), `resolve.c` (reverse-DNS for `h` rules), `config.c` (build + hot
reload for stream and HTTP), `audit.c`. The operation precision (create vs
update, stage), the bypass-site routing (TPC dest-open, prepare) and the
operation/host-keyed result cache live in `src/auth/authz/auth_gate.c`. Ported from
`/tmp/brix-src/src/XrdAcc/` with numeric privilege values kept identical so a
stock authdb decides the same. Tests: `tests/test_acc.py` (engine + protocols),
`tests/test_acc_residual.py` (create/update, stage, host-resolve, HTTP reload,
encoding, result-cache).
