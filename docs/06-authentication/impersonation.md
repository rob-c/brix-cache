# Per-request UNIX impersonation (phase 40)

> **Status:** optional, **off by default**. Enabling `map` mode is a deliberate
> security-posture change — the nginx **master must run as root** so it can spawn
> a small privileged identity broker. Most sites do **not** need this; the
> default single-worker-uid model ([identity-mapping.md](identity-mapping.md))
> remains the recommended posture. Use impersonation only when you genuinely need
> on-disk per-user ownership / quota / kernel DAC per identity.

## What it does

By default every filesystem operation runs as the single UNIX user the nginx
worker runs as, and created files are owned by that worker. With impersonation
enabled, the gateway runs each **open / metadata** operation as the **local UNIX
account the authenticated identity maps to** — so:

- created files and directories are **owned by the mapped user:group**, and
- the **kernel's DAC for that user is enforced** at `open()` (a user without
  permission is denied even if the authdb granted access).

The data plane (`read`/`write`/`sendfile`) is unchanged: it runs on the
already-open fd as the worker, because Linux checks DAC at open time and an open
fd is a capability. Only the open + namespace + metadata ops are impersonated.

## How it works (architecture)

Workers stay **fully unprivileged**. A small **root broker** does the privileged
work:

```
 root master                              root broker (double-forked → init)
  init_module: spawn broker  ───────────▶  drop caps to {SETUID,SETGID};
  create 0600 socket (owned by worker)     open its own export rootfd (O_PATH);
  open export rootfd (O_PATH)              poll() loop, one request at a time:
                                             map principal → {uid, gid, gids}
 worker (svc uid, NO caps)                   setgroups + setfsgid + setfsuid
  init_process: connect() ─────────────▶     openat2(rootfd, rel, RESOLVE_BENEATH)
  per request, after auth:                   restore creds
    set principal from identity              reply  (+ fd via SCM_RIGHTS for open)
    confined-open → ask broker ◀──────────
    read/write the returned fd (as svc)
```

- **The broker is the only privileged component.** It drops every capability
  except `CAP_SETUID`/`CAP_SETGID` (so it can `setfsuid`/`setfsgid`/`setgroups`)
  and **deliberately keeps no `CAP_DAC_OVERRIDE`** — otherwise root would bypass
  the impersonated user's DAC and impersonation would be meaningless. It fails
  closed if it cannot drop those caps.
- **Confinement is defence-in-depth.** The broker re-applies
  `openat2(RESOLVE_BENEATH)` under *its own* export rootfd, so a buggy/compromised
  worker that supplies a crafted path still cannot escape the export root.
- **The mapping policy is enforced broker-side.** An unmapped principal, uid 0, or
  a uid below `brix_idmap_min_uid` is **denied** — the broker can never be made
  to act as a system account.
- **Authorization stays in the worker** (the existing 3-tier gate). The broker
  only maps the principal, impersonates, and confines.

## Operating modes

One directive, `brix_impersonation off|single|map`, selects the posture:

| Mode | Broker? | Root? | On-disk owner | When to use |
|---|---|---|---|---|
| **`off`** (default) | none | no | the nginx worker uid | today's behavior; recommended for most sites. The impersonation code is fully inert. |
| **`single <user>`** | none | no | the one configured account | security-conscious sites that want a defined, uniform local identity but refuse a privileged broker. Operationally you also set nginx's `user` directive to that account; impersonation config is validated and any stray grid-mapfile is ignored. |
| **`map`** | yes (root, double-forked) | master root | the real mapped user | sites that need genuine per-user ownership / DAC. |

Invalid combinations fail closed at config time (`nginx -t`): `single` without a
user, `map` without a root master, an unknown mode token, etc.

## Configuration

All directives go in the **`stream {}`** block (or a `server {}` within it). There
is one identity broker per nginx instance.

```nginx
stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /export/data;

        # --- impersonation ---
        brix_impersonation        map;
        brix_impersonation_socket /run/brix/impersonate.sock;  # default shown
        brix_impersonation_export /export/data;     # broker confinement root
                                                      # (defaults to brix_export)
        brix_gridmap              /etc/grid-security/grid-mapfile;  # DN -> user
        brix_idmap_default_user   nobody;           # squash unmapped (else deny)
        brix_idmap_min_uid        1000;             # refuse uid < this (and 0)
        brix_idmap_cache_ttl      600;              # resolution cache seconds
    }
}
```

The nginx master must be started as root (`map` mode), and the `user` directive
sets the unprivileged worker account, e.g. `user xrootd;`.

### Directive reference

| Directive | Mode | Meaning |
|---|---|---|
| `brix_impersonation off\|single\|map` | all | the posture (default `off`) |
| `brix_impersonation_user <name>` | `single` | the single account everything squashes to |
| `brix_impersonation_socket <path>` | `map` | broker `AF_UNIX` socket (default `/var/run/brix/impersonate.sock`) |
| `brix_impersonation_export <path>` | `map` | the broker's confinement root (defaults to the first data server's `brix_export`) |
| `brix_gridmap <file>` | `map` | grid-mapfile: `"<DN>" localuser` lines (optional) |
| `brix_idmap_default_user <name>` | `map` | squash account for unmapped principals; **omit to deny** |
| `brix_idmap_min_uid <N>` | `map` | reserved-uid floor; resolved uids below `N` (and uid 0) are denied (default 1000, hard-clamped to ≥1000) |
| `brix_idmap_cache_ttl <secs>` | `map` | TTL of the principal→creds cache (default 600) |
| `brix_impersonation_broker_user <name>` | `map` | a dedicated **non-root** account the broker drops to (keeping only `CAP_SETUID`/`CAP_SETGID`) — see *Running the broker as non-root* below |
| `brix_idmap_forbidden_users <csv>` | `map` | extra account **names** never allowed as a target (adds to the built-in list; the worker + broker accounts are always forbidden) |
| `brix_idmap_forbidden_groups <csv>` | `map` | privileged group **names** (sudo/wheel/docker/…); a user who is a member of any — primary or supplementary — is denied even if the gid is ≥ the floor |

### Identity → local user resolution

For each request the principal is the authenticated **DN** (GSI), else the **token
subject** / SSS user / krb5 localname. It is resolved in order:

1. **grid-mapfile** match (`"<DN>" user`) → `getpwnam(user)`;
2. else a direct `getpwnam(<principal>)`;
3. else **squash** to `brix_idmap_default_user`, or **deny** if none is set.

A resolved account yields `{uid, primary gid, supplementary gids}` via
`getgrouplist`. Resolutions are cached per worker for `cache_ttl` seconds.

## Protocol coverage

| Protocol | Open / create | Metadata (stat/mkdir/rm/mv/chmod/…) | Notes |
|---|---|---|---|
| `root://` (stream) | ✅ impersonated | ✅ impersonated | bracketed in `brix_dispatch` |
| WebDAV (`davs://`) | ✅ (GET/PUT) | ✅ | sync methods + async PUT body |
| S3 | ✅ (PUT object) | partial | object create impersonated; sync GET/DELETE follow the same post-auth pattern (see *Limitations*) |

The data plane (reads/writes on open fds) is never brokered.

## Security model

- **The master runs as root** — a larger surface; the module's master-side code is
  deliberately tiny (spawn + socket + rootfd).
- **A broker compromise is root-equivalent** (`CAP_SETUID`). Mitigations: a tiny
  audited broker, no network (AF_UNIX only), `0600` + `SO_PEERCRED` gate to the
  worker uid, all other caps dropped + `NO_NEW_PRIVS`, every request validated,
  bounded fixed-size frames, single-threaded (no `setfsuid` race).
- **A worker compromise is contained**: a worker can only ask the broker to act,
  *within the export root*, as a **mapped, non-reserved** user — it cannot escape
  the root (broker re-applies `RESOLVE_BENEATH`) nor become an unmapped/system uid
  (mapping policy + `min_uid` floor).
- **Never uid 0 / system accounts.** Hard floor, enforced in depth (below).
- **Fails closed.** An unreachable broker, a failed cap-drop, or an uncertain
  mapping deny the op — they never fall back to privileged local I/O.

### Reserved-id floor (uid/gid < 1000 is impossible)

It is **impossible, in the code path, for a file operation to execute while the
broker's fsuid or fsgid is 0 or below `BRIX_IMP_HARD_MIN_ID` (1000)** — or while
any supplementary group is reserved. This is enforced at **three independent
layers**, each a single authoritative test (`brix_imp_creds_privileged()`):

1. **Mapping layer** (`idmap.c`). `brix_idmap_resolve()` **denies** any principal
   whose resolved primary uid, primary gid, or any supplementary gid is 0 or below
   the effective floor. `brix_idmap_min_uid` is **clamped up** to at least 1000 at
   init, so a misconfigured lower value cannot widen the floor — it becomes a clean
   deny, logged. Result: a reserved principal gets a normal *deny* (403 /
   NotAuthorized), and the broker stays up.

2. **Syscall edge** (`broker.c imp_become()`). Before **any**
   `setgroups`/`setfsgid`/`setfsuid`, the broker re-checks the credentials against
   the hard floor `BRIX_IMP_HARD_MIN_ID`, **independently of configuration**. If a
   reserved id ever reaches here (a should-be-impossible breach of layer 1), the
   broker performs **no** credential syscall, returns an explicit error to the
   worker, logs `CRIT`, and **terminates** (`_exit`) so it can never be coerced into
   a privileged operation. The realized fsuid/fsgid are also re-read and re-checked
   after the syscalls.

3. **Op execution point** (`broker.c imp_do_op()`). Immediately before the actual
   filesystem syscall, the broker reads the current fsuid/fsgid back one more time
   and returns `EPERM` rather than run a file op under any reserved identity.

The worker side adds nothing here: workers are unprivileged (no `CAP_SETUID`), so
they physically cannot drop to a reserved uid — the only privileged
credential-change site in the entire codebase is the broker's `imp_become()`.

> **Operational note:** because the floor also covers groups, a mapped account
> whose **primary gid** is a system group (< 1000), or who is a **member of a
> system group** (e.g. `wheel` gid 10), is **denied** — impersonating it would
> grant privileged group access. Grid/HEP pool accounts normally use dedicated
> ids ≥ 1000, so this does not affect them; if a site needs a lower floor it is
> intentionally not possible below 1000.

### Forbidden accounts and privileged groups

Two name-based deny-lists harden against privileged *targets* whose numeric ids
are ≥ the floor (so the floor alone would not catch them):

- **Forbidden target accounts** (`brix_idmap_forbidden_users`, plus a built-in
  default of common service/system accounts). In addition, the **nginx worker
  account** and the **broker's own account** are *always* forbidden as targets
  (config-independent, enforced both in the mapper and in the broker), so a
  principal can never be impersonated as the gateway itself — closing a
  confused-deputy where mapping to the service account would act with its identity.
- **Forbidden privileged groups** (`brix_idmap_forbidden_groups`, default
  `root,wheel,sudo,su,admin,sudoers,adm,…,docker,lxd,libvirt,kvm,…`). If the mapped
  user is a **member of any** of these — primary *or* any supplementary group —
  the whole mapping is **denied**, even when the gid is ≥ 1000 (e.g. a site
  `docker` group at gid 1600, or a custom `siteadmins` sudo-granting group). This
  is what makes "a sudo/su-capable account can never be a file-op identity" hold
  regardless of group numbering, and it explicitly covers users who are members of
  *multiple* groups (every group is checked).

Group/account names are resolved to numeric ids once at startup (and on reload);
names that do not exist on the host are skipped.

> **Large group sets fail closed.** On multi-VO/HEP hosts a user can belong to
> more than the 32-group working buffer. When `getgrouplist()` overflows, the
> mapper does **not** trust the truncated prefix (which could hide a forbidden
> group past the cap) — it re-resolves the *full* set and refuses the mapping if
> **any** group is reserved or forbidden. A heavy-group user with no forbidden
> group is still allowed (the impersonation `setgroups` applies a 32-group subset,
> which only ever grants *less*). A deny-list overflow never fails open.

## Running the broker as a non-root user (hyper-hardened)

The broker only ever needs **`CAP_SETUID` + `CAP_SETGID`** (for `setfsuid`/
`setfsgid`/`setgroups`). It does **not** need to *be* uid 0. Two setups let you
minimise root:

**1. Root master → broker drops to a service account (recommended, in-code).**
Run the nginx master as root (so it can open the export `rootfd` and spawn the
broker), and set:

```nginx
brix_impersonation            map;
brix_impersonation_broker_user xrootd-broker;   # dedicated, non-root, non-worker
```

The broker then, after the master opens the export rootfd, drops its real/effective/
saved uid+gid to `xrootd-broker` while retaining **only** `CAP_SETUID`/`CAP_SETGID`
(via `PR_SET_KEEPCAPS` + `setresuid` + a re-raised capability set). After startup
**nothing runs as root**: the broker's idle state, its NSS lookups, and its path
handling all run as `xrootd-broker`; per request it `setfsuid`s to the *mapped*
user. The one root action is the master-side `O_PATH` open of the export root,
before the broker begins serving. The unprivileged nginx **workers** additionally
shed `CAP_SETUID`/`CAP_SETGID`/`CAP_DAC_*`/… at startup, so a worker can never
change identity or override DAC.

**2. No root at all — capabilities on a non-root master.** Grant the two caps to a
non-root nginx via systemd or file capabilities and run the whole stack unprivileged:

```ini
# /etc/systemd/system/nginx.service.d/impersonate.conf
[Service]
User=xrootd
AmbientCapabilities=CAP_SETUID CAP_SETGID
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
NoNewPrivileges=no            # ambient caps require this; the broker re-asserts NNP
```

or, equivalently, file capabilities on the binary:

```bash
setcap 'cap_setuid,cap_setgid=ep' /usr/sbin/nginx
```

Here the export `rootfd` must be openable by the `xrootd` account (so point
`brix_impersonation_export` at a tree that account can traverse), and the broker
runs as `xrootd` holding just the two caps. The workers still drop them at startup.

> **Honest caveat (important):** a process holding `CAP_SETUID` is **root-equivalent
> if its code is exploited** — `CAP_SETUID` inherently allows `setuid(0)`. Running
> the broker as a non-root account therefore **reduces incidental-root exposure**
> (idle state, NSS, path bugs run as the service account, and auditing is cleaner)
> but does **not** contain a code-execution exploit. The real containment is the
> broker being *tiny and audited*, AF_UNIX-only, `SO_PEERCRED`-gated, fixed-frame,
> single-threaded, and `NO_NEW_PRIVS`. Keep the broker account dedicated, with no
> login shell, no group memberships, and owning nothing in the export.

## Requirements & limitations

- **Kernel ≥ 5.6** (the broker relies on `openat2`/`RESOLVE_BENEATH`).
- **Single export root.** The broker confines to one `brix_impersonation_export`
  root. Deployments with multiple distinct export roots per server block should
  set it explicitly; multi-root brokering is a follow-up.
- **Directory listing confidentiality is enforced** across PROPFIND, WebDAV
  SEARCH (DASL), `dirlist`, **and S3 `ListObjectsV2`**. Each consults the broker
  (an `O_RDONLY|O_DIRECTORY` open *as the mapped user*) before enumerating a
  directory: if that user has no UNIX permission to read it, the entries are
  withheld even though the worker uid could read them. The check **fails closed**.
  The walkers also `lstat` (never follow a symlink), so a symlink inside the export
  pointing outside it (or at another tenant) is **not traversed** — it cannot be
  used to enumerate the host filesystem or cross tenants. (The `readdir` itself
  still runs worker-side; only the *access decision* is impersonated. Per-entry
  `stat` DAC remains a follow-up.)
- **Unmappable / unauthenticated requests fail closed.** Under `map` mode, a
  request whose authenticated identity yields no mappable principal (e.g. a token
  with an empty subject) is routed to the broker, which denies the empty mapping —
  the FS op fails closed rather than falling back to the unprivileged worker
  (which owns the export and could otherwise read service-only paths). Housekeeping
  that runs with no active request (checkpoint recovery, FRM) is unaffected and
  still runs as the worker, by design.
- **Extended attributes are brokered** for the WebDAV operations that use them.
  WebDAV `LOCK` lock-tokens and `PROPPATCH` dead-properties are stored as `user.*`
  xattrs on the resource; the broker performs the `f{get,set,remove,list}xattr`
  **as the mapped user** (on a `RESOLVE_BENEATH`-confined fd, restricted to the
  `user.` namespace), so the metadata is written with — and DAC-checked for — the
  real user. (Before this, the worker `svc` could not `setxattr` a user-owned
  file, so LOCK/PROPPATCH failed under impersonation.) Residual, best-effort and
  documented: the COPY/MOVE xattr-**preservation** copy and the S3 multipart
  staging-dir cleanup still run worker-side; the stream-protocol `kXR_fattr` /
  `kXR_Qxattr` xattr ops are not yet bracketed.
- **All namespace mutations route through the broker** (as the mapped user):
  open/create, `mkdir`/MKCOL, `unlink`/DELETE, `rename`/MOVE, hard-link, and the
  POSIX extensions `setattr` (utimensat + fchownat), `symlink` and `readlink`
  (`kXR_setattr`/`kXR_symlink`/`kXR_readlink`, used by the native xrootdfs FUSE
  driver). So a `chgrp`/`touch`/`ln -s`/readlink under impersonation is owned by,
  and DAC-checked for, the mapped user — e.g. `chown` to a *different* owner
  correctly fails (the broker holds no `CAP_CHOWN`), while `chgrp` to a group the
  user belongs to succeeds.
- **S3 runs every op as the mapped user.** The S3 content handler brackets the
  whole post-auth dispatch with the principal (subject = the SigV4 access key), so
  the **synchronous** ops — `GetObject`, `HeadObject`, `DeleteObject`, `ListObjects`,
  multipart-initiate — open/stat/unlink as the mapped user (a `GetObject` cannot
  read a file the mapped user has no UNIX permission for — closing a cross-tenant
  read that running as the worker would allow). The **async-body** handlers (`PUT`,
  `POST` form-upload, `CompleteMultipartUpload`, bulk `DeleteObjects`) re-establish
  the principal in their body callbacks. A dedicated S3 user-namespace E2E
  (`tests/userns/e2e_redteam.py`) verifies PUT / GET / multipart-complete / DELETE
  produce objects owned by the mapped uid. All of this is inert when impersonation
  is off.
- **Performance:** one IPC round-trip per open/stat/mkdir/rename/unlink. The data
  plane is unaffected. Negligible for data-heavy workloads; measure for
  metadata-storm workloads.

## Verifying it works

```bash
# config validation (no root needed): map must be refused as non-root
nginx -t -c your.conf

# with map enabled and a mapping for your DN, create a file and check ownership
xrdcp /etc/hostname root://gw//export/data/hello
stat -c '%U:%G %n' /export/data/hello     # -> the MAPPED user, not 'xrootd'
```

The full security properties (ownership, **DAC enforcement**, supplementary
groups, confinement, deny policy, squash, no credential leak under concurrency)
are proven end-to-end without real root by the user-namespace test suite in
[`tests/userns/`](../../tests/userns/) — see its README.

## Implementation

`src/auth/impersonate/` — `idmap.c` (mapping), `broker.c` (privileged broker),
`client.c` (worker client), `lifecycle.c` (directives + spawn + request hooks),
`impersonate_proto.h` (wire frames). The confined-FS seam lives in
`src/fs/path/beneath.c` (stream) and `src/fs/path/resolve_confined_ops.c` (HTTP/S3).
Design doc: [`docs/refactor/phase-40-unix-impersonation.md`](../../docs/refactor/phase-40-unix-impersonation.md).
