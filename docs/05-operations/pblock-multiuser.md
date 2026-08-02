# pblock per-group multi-user (zero-provisioning) — operations guide

The pblock storage backend keeps its namespace in a SQLite catalog and its bytes
in shared block files, so **kernel file ownership cannot enforce per-user
isolation** — the impersonation broker's `setfsuid()` reaches the confined POSIX
ops, never the catalog. The chosen posture is therefore **gate decides, catalog
attests**: one authorization gate makes every allow/deny decision, and the
catalog records the resulting `uid`/`gid` as ground truth (never as a second
enforcement point).

This page is the worked configuration for running a pblock store shared by many
grid users with **no per-user server-side provisioning** — a new member of an
already-configured group works immediately, no config reload.

## 1. The three moving parts

1. **`brix_gridmap`** — maps the authenticated **DN** (GSI proxy) to a **local
   username**. Resolved worker-side at login whenever a gridmap is configured,
   independent of whether the privileged impersonation broker is running
   (P80.21) — mapping alone does not require `brix_impersonation map`.
2. **Local accounts + groups** — the local username's **unix group
   membership** (`getgrouplist`) supplies the `g`-rule groups.
3. **`brix_authdb` `g`-rules** — the group→path→permission matrix, evaluated on
   the **resolved** path with a longest-prefix, boundary-aware match. No rule =
   permissive; a rule that matches the path but not the caller's groups = deny.

## 2. Worked config

```nginx
stream {
    # DN -> local username. One line per principal:
    #   "/DC=org/DC=example/OU=People/CN=Alice Example" alice
    brix_gridmap        /etc/grid-security/grid-mapfile;
    brix_idmap_min_uid  1000;                 # reserved-id floor (chown guard)

    server {
        listen 127.0.0.1:1094;
        brix_root on;
        brix_auth gsi;
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/certificates;

        brix_export           /srv/pblock;
        brix_storage_backend  pblock:///srv/pblock;
        brix_allow_write      on;
        brix_upload_resume    off;             # see §4

        brix_authdb           /etc/brix/authdb;
    }
}
```

`/etc/brix/authdb` (xrdacc grammar), the entire per-group policy in three lines:

```
g phys /phys a      # phys group: full access (read/write/create/delete) on /phys
g eng  /phys rl     # eng group: read + lookup only on phys space
g eng  /eng  a      # eng group: full access on /eng
```

Everything not matched by a rule under a governed prefix is denied by default.
Adding a sixth user is `useradd`/`usermod -aG` + one `grid-mapfile` line —
**nothing on the server changes**.

## 3. FQAN-vs-unix: two sources feed the same `g`-rule

A `g`-rule's group field is matched against the caller's groups from **either**
source, and they share one namespace:

- **unix groups** of the gridmap-resolved local user (`getgrouplist`), and
- **VOMS FQAN / token group** names carried on the credential itself.

So a rule `g phys /phys a` fires for a user who is in the **local** `phys` group
**or** who presents a VOMS FQAN whose VO/group parses to `phys`. This is a
feature (a VO can be honored without local accounts) and a footgun (a VOMS group
that happens to be named like an unrelated local group matches the same rule).
**Choose deliberately:** either name the local group to match the VO on purpose,
or namespace the rules (e.g. local-only `phys` vs VO paths under a distinct
prefix) so the two sources cannot alias each other by accident.

## 4. `brix_upload_resume off`

Resume divert routes an interrupted write through a staged-resume path. On a
pblock catalog the clean, attributable posture is a single owner stamp at
create/commit; leave resume **off** for the multi-user store so every object has
exactly one create event to attribute an owner from.

## 5. De-provisioning latency — the group cache TTL

Group membership is cached. Removing a user from a group (or removing their
gridmap line) does **not** take effect instantly:

- **Positive group cache** — `gidlifetime`, default **43200 s (12 h)**. A user
  dropped from `phys` keeps `phys` access until their cached membership expires,
  up to the TTL.
- **Negative cache** — **60 s**. A newly-added membership or mapping is picked up
  within a minute.

For immediate revocation (security incident, not routine churn) you must flush
the cache / restart workers rather than wait out `gidlifetime`. Plan routine
de-provisioning around the 12 h window, not around instant effect.

## 6. Ownership attestation — the catalog is the oracle

The catalog's `uid`/`gid` columns are stamped from the request identity (the
mapped `{uid,gid}`) at create — open-for-create, `mkdir`, and staged commit —
and returned in `stat`/dirlist. To verify who owns what, query the catalog
directly — external ground truth, no server instrumentation:

```sh
sqlite3 /srv/pblock/catalog.db \
  "SELECT path, uid, gid FROM objects ORDER BY path;"
```

Legacy rows written before the ownership columns existed are `NULL` and stat as
the service identity ("unowned"); the upgrade is idempotent and in place. The
driver **never** re-checks permissions on these values — enforcement is the
gate's alone; the columns are attestation, not a second gate.

## 7. Verifying the posture

- **Grant:** a `phys` member reads and writes under `/phys`.
- **Default-deny:** the same member is denied on `/eng` (no rule grants them).
- **Read-only crossing:** an `eng` member reads `/phys` but a write returns
  `kXR_NotAuthorized` (3010) in microseconds — the gate denied before any VFS
  work.
- **Unmapped DN:** a principal with no gridmap line and no VO membership matches
  **no** `g`-rule and is denied everywhere — an unmapped DN must never fall
  through to a group grant.
- **Ownership:** the object a mapped user wrote shows their `uid`/`gid` both over
  the wire (`stat`) and in the direct `sqlite3` query above.

See `tests/test_pblock_group_multiuser.py` for the automated form of this matrix.
```
