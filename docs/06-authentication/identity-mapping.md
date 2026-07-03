# Identity → local-UNIX account mapping (X.509 / VOMS / VO / token → UNIX user & group)

> **Audience:** site administrators configuring how grid (X.509/VOMS) and token
> (JWT/WLCG/SciToken) identities are turned into authorization decisions and
> local UNIX user/group ownership, and how to **force, override, or adjust** a
> particular mapping.
>
> **Scope:** `root://` (stream) and `davs://`/`http://` (WebDAV) and S3. The
> authorization engine is shared across all three protocols.
>
> Companion docs: [`auth-overview.md`](auth-overview.md) (authn methods),
> [`authorization.md`](authorization.md) (native authdb), and
> [`authorization-xrdacc.md`](authorization-xrdacc.md) (the XrdAcc-compatible
> engine grammar — read it alongside this file).

---

## 0. TL;DR — read this first

This module is an **nginx gateway**, not a per-user file server. Two facts shape
everything below and are the single most common source of confusion:

1. **By default there is no per-request UNIX impersonation.** Out of the box there
   is **no grid-mapfile, no `setuid`/`seteuid`, no `XrdSecgsiMapToLocalUser`**, and
   every filesystem operation runs as the **single UNIX user the nginx worker runs
   as** (whatever `user` is set to in `nginx.conf`, e.g. `nginx`). A grid DN is not
   turned into a distinct local login that owns the bytes on disk.

   > **Optional (phase 40):** impersonation *can* be enabled with
   > `brix_impersonation map` (off by default), which runs each open/metadata
   > op as the mapped local user via a privileged broker — so files are owned by,
   > and kernel DAC is enforced for, the real user. This is a deliberate
   > security-posture change (the master runs as root) and is documented
   > separately in [impersonation.md](impersonation.md). The rest of *this*
   > document describes the default (no-impersonation) behavior.

2. "Mapping a grid/token identity to a local UNIX account" therefore means two
   *separate* things in this module:

   | What | Where it happens | What "UNIX account" means there |
   |---|---|---|
   | **Authorization** | the auth gate (`src/auth/authz/auth_gate.c`) + the authz engine (`src/auth/authz/acc/`, `src/auth/authz/authdb.c`, `src/auth/authz/acl.c`) | the engine can match a `g <unixgroup>` / `n <netgroup>` rule against the principal's **OS supplementary groups** (`getpwnam`→`getgrouplist`) and NIS netgroups — i.e. local UNIX *groups* are consulted for the *allow/deny decision*, even though no process changes uid/gid |
   | **Created-object ownership** | `src/auth/authz/group_policy.c` (`brix_inherit_parent_group`) | a freshly created file/dir is owned by the **worker uid**, but its **group** can be forced to the parent directory's group (with `setgid` propagation) |

If you came here expecting "DN `/DC=org/CN=Rob` becomes local user `rob` who owns
the file" — that is **not** what happens. The DN becomes an *authorization
identity*; the file is owned by the nginx worker; the file's *group* is whatever
the parent dir / your `inherit_parent_group` policy dictates.

The rest of this document is the precise, exhaustive version of those two columns.

---

## 1. The identity pipeline: credential → `brix_identity_t`

Every connection (or HTTP request) is authenticated by exactly one method, which
populates one canonical identity object, `brix_identity_t`
(`src/core/types/identity.h`). The authz engine and the mapping logic only ever look
at this object — the wire credential is gone by then.

```c
typedef struct {
    ngx_str_t    dn;            /* GSI DN, SSS user, krb5 localname, or token sub */
    ngx_str_t    subject;       /* JWT sub or S3 access key id                   */
    ngx_str_t    issuer;        /* JWT iss; empty for non-token auth             */
    ngx_array_t *vo_list;       /* VOMS FQANs / token groups                     */
    ngx_array_t *scopes;        /* raw OAuth scope tokens                        */
    ngx_str_t    acc_vorg_csv;  /* VO names      e.g. "cms,atlas"   (parsed)     */
    ngx_str_t    acc_role_csv;  /* VOMS/token roles  e.g. "production,"          */
    ngx_str_t    acc_group_csv; /* group paths   e.g. "/cms,/atlas"              */
    ngx_str_t    scope_raw;     /* raw OAuth scope claim                         */
    brix_token_scope_t token_scopes[BRIX_MAX_TOKEN_SCOPES];
    ngx_uint_t   auth_method;   /* BRIX_AUTHN_* bitmask                        */
    unsigned     is_authenticated:1;
    unsigned     is_admin:1;
    unsigned     has_write_scope:1;
    unsigned     has_read_scope:1;
} brix_identity_t;
```

### 1.1 What each authn method fills in

| Auth method | `dn` ← | `subject` ← | `issuer` ← | `vo_list` ← | scopes ← | Notes |
|---|---|---|---|---|---|---|
| **GSI / X.509** (`src/auth/gsi/auth.c`) | certificate **subject DN** | — | — | VOMS FQANs (if `vomsdir`+`voms_cert_dir` set) | — | DN is the *full* RFC2253 DN, e.g. `/DC=org/DC=cilogon/CN=Rob Currie`. |
| **VOMS** (on top of GSI; `src/auth/voms/`) | (DN as above) | — | — | the VOMS attribute cert FQANs | — | Each FQAN parsed into VO/role/group (§1.2). |
| **Bearer token** (JWT/WLCG/SciToken; `src/auth/token/`, `src/auth/gsi/token.c`) | **mirror of `sub`** | `sub` claim | `iss` claim | `wlcg.groups` (or `groups`) | `scope` claim | `sub` is copied into `dn` so token principals can also match `u <name>` and OS-user rules (§3). |
| **SSS** (Simple Shared Secret; `src/auth/sss/`) | the **UNIX user** the keytab maps to | — | — | the **UNIX group** the keytab maps to | — | Both come straight from the keytab entry (`u:` / `g:`), or from the decrypted credential when the entry is `anybody`/`allusers`. |
| **Kerberos 5** (`src/auth/krb5/`) | **localname** (`krb5_aname_to_localname`, honoring `krb5.conf` `auth_to_local`) or the raw `user@REALM` | — | — | — | — | The localname is the natural bridge to a local UNIX user. |
| **UNIX** (`src/auth/unix/`, loopback-only by default) | client-asserted user | — | — | client-asserted group | — | Unverified; gated to loopback/AF_UNIX unless `unix_trust_remote`. |
| **S3 SigV4** (`src/protocols/s3/`) | — | the **access key id** | — | — | — | Identity is the access key; group/VO mapping comes from authz rules keyed on the access key as `u <name>`. |
| **Anonymous** (`brix_auth none`) | — | — | — | — | — | `is_authenticated = 0`; the engine sees the principal name as `*` (the `u *` default applies). |

> **The single most important column is `dn`.** It is the string the authz engine
> uses as the *principal name*, and it is the string handed to `getpwnam()` when
> resolving OS UNIX groups (§3). For tokens it is the `sub`; for SSS it is the
> mapped UNIX user; for Kerberos it is the localname; for GSI it is the raw DN.

### 1.2 The VOMS-FQAN / token-group parser (VO, role, group)

VOMS FQANs and WLCG token groups are split into three **index-aligned** CSV views
by `brix_identity_derive_attrs()` (`src/core/types/identity.c`). These feed the
XrdAcc `o` (organization/VO), `r` (role) and `g` (group) records.

Given an FQAN like `/cms/Role=production/Capability=NULL`:

| View | Value | Rule it feeds | Derivation |
|---|---|---|---|
| `acc_vorg_csv` | `cms` | `o cms` | first path component after the leading `/` |
| `acc_role_csv` | `production` | `r production` | text between `/Role=` and the next `/` (`Role=NULL` → empty) |
| `acc_group_csv` | `/cms` | `g /cms` | everything before `/Role=`; trailing `/Capability=…` stripped |

A plain group FQAN `/atlas` (no `Role=`) yields `vorg=atlas`, `role=` (empty,
position preserved), `group=/atlas`. Multiple FQANs accumulate, e.g.
`acc_vorg_csv="cms,atlas"`, `acc_role_csv="production,"`, `acc_group_csv="/cms,/atlas"`.

> Note these are the **credential-asserted** groups (what the VO/IdP says you are).
> They are matched directly by `o`/`r`/`g` records. They are **distinct** from the
> *OS* groups resolved from `/etc/group`/NIS in §3 — an `g <name>` record matches
> if **either** source contains the group.

---

## 2. The authorization gate: three tiers, fail-closed

Every namespace/file operation passes through `brix_auth_gate*()`
(`src/auth/authz/auth_gate.c`), which checks three tiers **in order** and denies on the
first failure (kXR_NotAuthorized / HTTP 403):

```
   ┌─────────────────────────────────────────────────────────────────┐
   │ 1. AUTHDB / XrdAcc engine                                         │
   │    native  (brix_authdb_format native)  → src/auth/authz/authdb.c     │
   │    xrdacc  (brix_authdb_format xrdacc)   → src/auth/authz/acc/  (engine)    │
   │    → matches the identity (DN/VO/role/group/host/OS-group) to a   │
   │      path + privilege rule.   THIS is where local UNIX groups     │
   │      enter the decision (xrdacc only).                            │
   ├─────────────────────────────────────────────────────────────────┤
   │ 2. VO ACL    (brix_require_vo <path> <vo>)  → src/auth/authz/acl.c     │
   │    → requires the identity's vo_list to contain <vo> on <path>.   │
   ├─────────────────────────────────────────────────────────────────┤
   │ 3. Token scope (WLCG/SciToken)              → token_scopes        │
   │    → the request path must fall under a storage.read/write/...    │
   │      scope carried in the bearer token.                           │
   └─────────────────────────────────────────────────────────────────┘
```

- **All three must pass.** A grant in the authdb does not bypass a missing token
  scope, and vice-versa.
- **`conf->allow_write` is checked globally** before any token scope — a
  read-only server refuses writes regardless of identity.
- Tiers 2 and 3 are **skipped when not configured** (no `brix_require_vo`
  rules ⇒ no VO gate; non-token auth ⇒ no scope gate).

The rest of this document is mostly about **tier 1** (the authdb/XrdAcc engine)
and the **created-file group** side effect.

---

## 3. From identity to local UNIX **user** and **group**

This is the section the title of the doc is about. It only applies to the
**XrdAcc engine** (`brix_authdb_format xrdacc`) for OS-group resolution; the
native engine consults credential VO/groups only (§4.2).

### 3.1 The principal *name* and the OS *user*

The engine's principal name is `name = brix_identity_dn_cstr(identity)` — i.e.
the `dn` field (§1.1). When the engine needs the principal's OS supplementary
groups it calls, in `src/auth/authz/acc/groups.c`:

```c
pw = getpwnam(name);                       /* name == the dn / sub / sss-user */
if (acc_primary_only) gids[0] = pw->pw_gid;             /* brix_acc_pgo on  */
else getgrouplist(name, pw->pw_gid, gids, &ng);         /* all supplementary  */
for each gid:  if (!gidretran(gid))  getgrgid(gid)->gr_name;   /* → group set */
```

**Consequence — the rule that surprises everyone:**

| Principal name (`dn`) | `getpwnam(name)` | OS groups resolved? |
|---|---|---|
| token `sub = "alice"` | succeeds if `alice` is in `/etc/passwd`/NSS | **yes** → alice's UNIX groups |
| SSS `u:alice` | (SSS already carries the group too) | the mapped group is used directly |
| krb5 localname `alice` | succeeds if `alice` exists | **yes** |
| UNIX `alice` | succeeds if `alice` exists | **yes** |
| GSI DN `/DC=org/CN=Rob Currie` | **fails** (no passwd entry named that) | **no** — OS groups are empty |

So **a bare X.509 DN does not pick up `/etc/group` membership** unless that exact
DN string is also a local username (it almost never is). For GSI/VOMS users you
authorize on the **VOMS attributes** (`o`/`r`/`g` against the FQAN) — see §3.3.
To give a GSI user OS-group membership you must give them a username-shaped
identity (see "force/override", §6.5).

> **There is no UNIX *user* mapping beyond this lookup.** The result of
> `getpwnam(name)` is used only to enumerate groups; the uid is **not** adopted by
> any process. Files are still created by the nginx worker uid.

### 3.2 The OS *group* resolver — knobs

`src/auth/authz/acc/groups.c` resolves and **caches** the OS group set per principal:

| Directive | Default | Effect |
|---|---|---|
| `brix_acc_gidlifetime <secs>` | `43200` (12 h) | TTL of the per-worker `getpwnam`/`getgrouplist` cache. Lower = pick up `/etc/group` edits faster; higher = fewer NSS calls. |
| `brix_acc_pgo on` | off | "primary group only": resolve just `pw_gid`, skip the supplementary list (`getgrouplist`). |
| `brix_acc_nisdomain <domain>` | — | NIS domain used for `n <netgroup>` (`innetgr`) lookups. Required for netgroup records to resolve. |
| `brix_acc_gidretran "<gid> <gid> …"` | — | gids to **exclude** from name resolution (e.g. `nobody`/`nogroup` or any ambiguous shared gid). A gid in this list contributes **no** group name, so it can never satisfy a `g` rule. |

### 3.3 How XrdAcc records match the resolved user & groups

In `src/auth/authz/acc/access.c`, for principal `ent->name` (the dn) the engine accumulates
privileges from **all** matching identity categories (this is *additive* — see
[authorization-xrdacc.md](authorization-xrdacc.md)):

| Record | Matches | Source consulted |
|---|---|---|
| `u <name>` | the principal name exactly | the `dn` |
| `u *` | every authenticated principal (the default) | — |
| `u =` | any principal *not* matched by a specific `u <name>` (fungible; enables `@=` templates) | — |
| `g <group>` | the principal is in `<group>` | **both** the credential FQAN group (`acc_group_csv`) **and** the **OS supplementary groups** (`getpwnam`→`getgrouplist`, gated on `ent->isuser`) |
| `n <netgroup>` | the principal/host is in the NIS netgroup | `innetgr()` (needs `nisdomain`) |
| `o <vo>` | VO/organization | the credential VO (`acc_vorg_csv`) |
| `r <role>` | VOMS/token role | the credential role (`acc_role_csv`) |
| `h <host>` / `h .<domain>` | the peer host/domain | peer IP, or reverse-DNS name with `brix_acc_resolve_hosts on` |
| `= <id> …` + `x`/`s` | a **compound** identity (AND of selectors) | see §6 |

So **`g <name>` is the bridge to local UNIX groups**: it fires when the
principal's `/etc/group`/NIS membership *or* their VO group contains `<name>`.

---

## 4. The authorization engines (tier 1) in detail

Select the engine per server/location:

```nginx
brix_authdb_format  xrdacc;   # or: native (the default)
brix_authdb         /etc/brix/authdb;
```

### 4.1 XrdAcc engine (`brix_authdb_format xrdacc`) — recommended

Full grammar, privilege letters, accumulation order, templates and the legacy
encoding tunables are documented in
[**authorization-xrdacc.md**](authorization-xrdacc.md). The mapping-relevant
record types are summarized in §3.3 above. Key points for mapping:

- `g`/`n` consult **local UNIX groups / NIS netgroups** (§3).
- `o`/`r` consult the **VOMS / token** VO and role.
- `=` + `x`/`s` let you pin an **exact compound identity** (§6).
- Privilege letters: `a`=all, `r`=read, `w`=write, `l`=lookup(stat), `i`=insert
  (create), `d`=delete, `n`=rename, `k`=lock; a leading `-` is a **negative**
  (explicit deny); effective = `positive & ~negative`. **`r` does *not* imply
  `l`.**

### 4.2 Native engine (`brix_authdb_format native`, the default)

`src/auth/authz/authdb.c`. One rule per line, longest-path-prefix wins, **single**
privilege check (no accumulation, no compound identities, no templates):

```
<type> <id> <path> <privs>
```

| `<type>` | `<id>` matches | against |
|---|---|---|
| `u` | a user DN, or `*` (all users) | the `dn` |
| `g` | a **VO / credential group**, or `*` | `vo_list` only — **NOT** `/etc/group`/OS groups |
| `p` | a host / IP / CIDR (`10.0.0.0/8`) | the peer address |
| `a` | (everyone) | — |

Privilege chars (native): `r` read (**implies** `l`), `l` lookup, `w`/`a`
write/append, `d` delete, `m` mkdir, `k` admin.

> **Critical native-vs-xrdacc difference:** native `g` matches only the
> **VO/credential group list**. It has **no** `/etc/group` or NIS resolution. If
> you need to authorize on local UNIX groups, use `brix_authdb_format xrdacc`.

### 4.3 VO ACL (tier 2): `brix_require_vo`

```nginx
brix_require_vo  /cms   cms;       #  <path-prefix>  <required-VO>
brix_require_vo  /atlas atlas;
```

`src/auth/authz/acl.c`: longest-prefix path match, then the identity's `vo_list` must
contain the required VO. No matching rule ⇒ unrestricted (this tier only *adds*
a requirement on the listed prefixes). This is a coarse, fast VO gate that
complements (does not replace) the authdb.

### 4.4 Token scope (tier 3)

For bearer tokens, the WLCG/SciToken `scope` claim carries path-scoped
capabilities, e.g. `storage.read:/data storage.write:/data/out`. The gate
requires the request path to fall under a scope of the right kind
(`storage.read`/`storage.stage` for reads; `storage.write`/`create`/`modify` for
writes). `has_read_scope`/`has_write_scope` are fast-path flags derived at token
validation. This tier is independent of the UNIX user/group mapping.

---

## 5. Created-object ownership (the *write* side of "UNIX account")

When a client **creates** a file or directory, who owns it?

- **User (uid):** always the **nginx worker uid**. There is no per-identity uid.
  (Set the worker user in `nginx.conf` `user <name>;` to control this globally.)
- **Group (gid) + mode:** the default is the worker's primary group, **unless**
  you enable group inheritance:

```nginx
brix_inherit_parent_group  /data;     # path prefix; repeatable
brix_inherit_parent_group  /projects;
```

`src/auth/authz/group_policy.c` (`brix_apply_parent_group_policy_*`) then, for any
created object **under a matching prefix** (longest-prefix wins):

1. `stat`s the parent directory.
2. If the child's gid ≠ the parent's gid → `chown(child, -1, parent_gid)` (group
   only; uid untouched).
3. Recomputes the child's **group mode bits** from the parent: directories
   inherit `rwx` group bits, regular files inherit `rw` (and keep `x` if already
   present); strips any stale `setgid`.
4. **Propagates `setgid`**: if the child is a directory and the parent has the
   `setgid` bit, the child gets `setgid` too — so the whole subtree keeps
   inheriting the group automatically.

> **Tip:** the cleanest way to make all data under `/data/cms` land in UNIX group
> `cms` is the classic POSIX recipe — `chgrp cms /data/cms && chmod g+rwxs
> /data/cms` once, then `brix_inherit_parent_group /data;`. The `setgid` bit on
> the directory does most of the work; the directive guarantees the group/mode
> even for clients/paths the kernel's `setgid` semantics wouldn't cover.

---

## 6. Forcing, overriding, and adjusting a mapping

This is the "how do I make *this* identity map to *that* account/permission"
playbook. Pick the mechanism by what you want to pin.

### 6.1 Pin one principal to an exact privilege set

XrdAcc or native — a specific `u <name>` rule for the exact `dn`/`sub`:

```
# xrdacc authdb
u /DC=org/DC=cilogon/CN=Rob Currie   /data/rob  rwid
u alice-token-sub                    /data/alice rwid
```

Because XrdAcc accumulates additively, this **adds** to whatever `u *`/`g`/`o`
grant. To make it the **only** thing that applies, use an exclusive rule (§6.2).

### 6.2 Override the default with an exclusive rule (beats even `u *`)

The XrdAcc `=` (compound identity) + `x` (exclusive) pair is the strongest
override: when an `x` rule matches, it is the **only** rule consulted — the `u *`
default and every other category are skipped.

```
# Define a precise identity (AND of selectors), then pin it exclusively:
= cms_prod   u /DC=org/CN=Carol   o cms   r production
x cms_prod   /devarea   rwid           # Carol+cms+production: ONLY this, ONLY here
```

Use `s` instead of `x` for an **inclusive** compound rule (OR-accumulated with
other matches) when you want to *add* a grant rather than replace.

### 6.3 Force a created file's UNIX group

See §5 — `brix_inherit_parent_group <prefix>;` plus a `setgid` parent dir.
This is the only built-in way to force created-object group ownership (there is
no "force uid").

### 6.4 Force / fix the SSS service-account mapping

For service-to-service (SSS) credentials, the UNIX user **and** group are pinned
in the keytab — this is the most direct "force this credential to this account":

```
# /etc/brix/sss.keytab   (mode 0600, or 0640 for a .grp keytab)
0 N:1 k:<hex-key> u:svccms g:cms n:cms-mover
0 N:2 k:<hex-key> u:anybody g:allusers n:gateway+    # decrypt user/group from cred
```

```nginx
brix_sss_keytab  /etc/brix/sss.keytab;
```

`u:`/`g:` set `identity.dn`/`identity.vo_list` directly; `anybody`/`allusers`
defer to the user/group inside the presented credential. Change the mapping by
editing the keytab and reloading nginx.

### 6.5 Give a GSI/VOMS DN local-UNIX-group membership

Because `getpwnam(DN)` fails (§3.1), a raw DN never picks up `/etc/group`. Two
ways to bridge it:

- **Preferred — authorize on the VO attributes instead of OS groups:** use
  `o <vo>` / `r <role>` / `g <fqan-group>` records that match the VOMS FQAN. No
  local accounts needed.
- **If you genuinely need `/etc/group` for a DN:** make the DN resolvable as a
  username (e.g. add a passwd/NSS alias whose login name equals the DN string),
  or front the DN with a token whose `sub` is a local username. This is unusual;
  prefer the VO-attribute route.

### 6.6 Exclude an over-broad OS group from the decision

If `getgrouplist` returns a shared/ambiguous gid (e.g. `nobody`, or a gid reused
across names) that you do **not** want to satisfy `g` rules, drop it:

```nginx
brix_acc_gidretran  "65534 100";     # these gids contribute no group name
```

### 6.7 Tighten or loosen OS-group resolution

```nginx
brix_acc_pgo on;                 # only the primary group counts (ignore supplementary)
brix_acc_gidlifetime 300;        # re-read NSS every 5 min (pick up /etc/group edits faster)
brix_acc_nisdomain  example.org; # enable NIS netgroup (n <name>) resolution
```

### 6.8 Per-user home directories (template substitution)

`@=` in an XrdAcc path expands to the principal name, so one rule covers every
user:

```
u = /home/@=/   rwid      # alice → /home/alice, bob → /home/bob, …
```

### 6.9 Deny a sub-path while granting the parent

XrdAcc negative privileges (`-`):

```
u alice  /data  a   /data/archive  ra-d     # all on /data, but never delete /data/archive
```

(Native has no negation; carve-outs there require a separate, longer-prefix rule
granting fewer privileges.)

### 6.10 Pin by host / domain

```
h .cern.ch   /pub  rl       # any *.cern.ch peer
h wn001.example.org /scratch rwid
brix_acc_resolve_hosts on;            # reverse-DNS the peer so the names match
```

### 6.11 Hot-reload an authdb edit (no restart)

```nginx
brix_authdb_refresh 60;     # re-read the authdb on mtime change every 60s
brix_authdb_audit   all;    # log every grant/deny while you tune the rules
```

Works on both stream (`root://`) and HTTP (WebDAV/S3) tiers.

---

## 7. Worked end-to-end examples

### 7.1 WLCG token user → OS groups → access

Token: `sub = "alice"`, `wlcg.groups = ["/cms"]`, `scope =
"storage.read:/ storage.write:/cms"`. `alice` is a local user in UNIX group
`cms`.

```nginx
brix_auth            token;
brix_authdb_format   xrdacc;
brix_authdb          /etc/brix/authdb;
```
```
# /etc/brix/authdb
g cms   /cms   rwidl       # matches BOTH the token group /cms AND alice's UNIX group cms
u *     /pub   rl
```
Result: `getpwnam("alice")` → groups include `cms` → `g cms` fires → read/write on
`/cms`; tier-3 token scope also allows write on `/cms`. Files alice creates are
owned by the **nginx worker** uid; add `brix_inherit_parent_group /cms;` (and
`chmod g+s /cms`) to keep them in group `cms`.

### 7.2 GSI + VOMS user → VO/role → access (no OS groups)

Proxy with VOMS FQAN `/cms/Role=production`. DN is `/DC=org/CN=Rob`.

```
o cms          /cms  rl        # any cms VO member: read
r production   /cms  rwid       # production role: also write/create
```
Result: VO `cms` and role `production` from the FQAN drive the decision.
`getpwnam("/DC=org/CN=Rob")` fails → **no** `/etc/group` is consulted; that's
fine because we authorized on VO attributes.

### 7.3 SSS service account → fixed user/group

Keytab `N:1 u:svcmover g:cms` (§6.4). The mover authenticates with SSS; the
engine sees `dn = "svcmover"`, `vo_list = ["cms"]`. A `u svcmover …` or `g cms …`
rule authorizes it. Deterministic, no token/cert needed.

### 7.4 Override exactly one user

Everyone gets read on `/data`; user `bob` (by token sub) must be denied entirely
there, while keeping the default elsewhere:

```
= just_bob  u bob
x just_bob  /data  -ra-w-l-i-d        # bob: explicit deny on /data (exclusive → nothing else applies)
u *         /data  rl                 # everyone else: read
```

---

## 8. Gotchas & FAQ

- **"My grid (DN) user has no UNIX groups."** Expected — `getpwnam(DN)` fails
  (§3.1). Authorize on VOMS `o`/`r`/`g` (FQAN), or give them a username-shaped
  identity. Only token/SSS/krb5/unix principals get `/etc/group` resolution.
- **"Native `g cms` doesn't see my `/etc/group`."** Native `g` matches the
  **VO/credential** group only (§4.2). Switch to `brix_authdb_format xrdacc`.
- **"`r` doesn't let me `stat`."** In XrdAcc, `r` ≠ `l`; grant `rl`. (Native `r`
  *does* imply `l`.)
- **"Created files are owned by `nginx`, not the user."** By design — no
  impersonation (§0, §5). Control the worker user with nginx's `user` directive
  and the group with `brix_inherit_parent_group` + `setgid`.
- **"My `/etc/group` edit didn't take effect."** Group sets are cached for
  `brix_acc_gidlifetime` (default 12 h). Lower it, or restart the worker.
- **"Netgroup (`n`) rules never match."** Set `brix_acc_nisdomain`.
- **"SSS keytab rejected at startup."** It must be mode `0600` (or `0640` for a
  `.grp` keytab); world-readable fails closed.
- **Different identities, one cache key.** The XrdAcc auth-result cache (when
  `brix_auth_cache` is configured) keys on DN + VO + scope + path + op + host,
  so a cached decision is never replayed across principals; OS-group changes are
  bounded by `gidlifetime`.

---

## 9. Code map (where each step lives)

| Step | File |
|---|---|
| Canonical identity struct | `src/core/types/identity.h` |
| FQAN → VO/role/group split; token claims → identity | `src/core/types/identity.c` |
| GSI/X.509 DN extraction | `src/auth/gsi/auth.c` |
| VOMS FQAN extraction | `src/auth/voms/` |
| Token (JWT/WLCG) validation + claims | `src/auth/token/`, `src/auth/gsi/token.c` |
| SSS keytab parse + credential → user/group | `src/auth/sss/config.c`, `src/auth/sss/auth_request.c` |
| Kerberos principal → localname | `src/auth/krb5/auth.c` |
| S3 access-key identity | `src/protocols/s3/` |
| Three-tier auth gate | `src/auth/authz/auth_gate.c` |
| Native authdb parse + match | `src/auth/authz/authdb.c` |
| XrdAcc engine (grammar / decision) | `src/auth/authz/acc/authfile.c`, `src/auth/authz/acc/access.c`, `src/auth/authz/acc/entity.c` |
| OS user/group + NIS netgroup resolution (`getpwnam`/`getgrouplist`/`innetgr`) | `src/auth/authz/acc/groups.c` |
| VO ACL (`brix_require_vo`) | `src/auth/authz/acl.c`, `src/core/config/policy.c` |
| Created-object group inheritance (`brix_inherit_parent_group`) | `src/auth/authz/group_policy.c` |
| Directive tables | `src/protocols/root/stream/module.c` (root://), `src/protocols/webdav/module.c` (WebDAV/S3) |

---

## 10. Directive quick reference (mapping-relevant)

| Directive | Context | Arg | Purpose |
|---|---|---|---|
| `brix_authdb_format` | srv / loc | `native`\|`xrdacc` | choose the authz engine |
| `brix_authdb` | srv / loc | `<path>` | the authdb rule file |
| `brix_authdb_refresh` | srv / loc | `<secs>` | hot-reload on mtime change (0 = off) |
| `brix_authdb_audit` | srv / loc | `none`\|`deny`\|`grant`\|`all` | log authz decisions |
| `brix_require_vo` | srv | `<path> <vo>` | tier-2 VO requirement on a prefix |
| `brix_sss_keytab` | srv | `<path>` | SSS credential → fixed UNIX user/group |
| `brix_inherit_parent_group` | srv | `<path>` | created files/dirs inherit parent group + setgid |
| `brix_acc_gidlifetime` | srv / loc | `<secs>` | OS-group cache TTL (default 43200) |
| `brix_acc_pgo` | srv / loc | `on`\|`off` | resolve primary group only |
| `brix_acc_nisdomain` | srv / loc | `<domain>` | NIS domain for `n` netgroup rules |
| `brix_acc_gidretran` | srv / loc | `"<gid> …"` | exclude ambiguous gids from resolution |
| `brix_acc_resolve_hosts` | srv / loc | `on`\|`off` | reverse-DNS peer for `h` host rules |
| `brix_acc_spacechar` | srv / loc | `<char>` | substitute char→space in authdb identity names |
| `brix_acc_encoding` | srv / loc | `on`\|`off` | URI-decode authdb path tokens (`%20`→space) |

*(srv = `server{}` stream block; loc = `location{}` http block. The `brix_acc_*`
/ `brix_authdb*` directives exist in both; `brix_require_vo`,
`brix_sss_keytab`, `brix_inherit_parent_group` are stream-side.)*
