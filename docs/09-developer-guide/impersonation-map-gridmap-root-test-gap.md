# brix_impersonation map + gridmap: How It Works, and the Host-Root Ownership Test Gap

**Scope:** `src/auth/impersonate/` (`idmap.c`, `idmap_gridmap.c`, `idmap_denylist.c`,
`broker.c`, `broker_creds.c`, `broker_ops.c`), directive registration in
`src/protocols/root/stream/directives_tier.h`, tests in `tests/userns/`,
`tests/mu_authz_lib/`, and the gridmap-ownership root suite
(`tests/test_impersonation_gridmap_root.py`).
**Companion:** [`../06-authentication/impersonation.md`](../06-authentication/impersonation.md),
[`../06-authentication/identity-mapping.md`](../06-authentication/identity-mapping.md).

> **TL;DR.** `brix_impersonation map` runs the nginx master as root and hands per-request
> `setfsuid`/`setfsgid` to a double-forked privileged broker so backend files land owned by the
> real UNIX user that an authenticated identity maps to. Ownership was already proven WITHOUT
> real root (unprivileged user namespace, no gridmap) and authz verdicts were proven separately,
> but until the gridmap-ownership root suite landed, nothing launched the real nginx binary **as
> host root** with a **grid-mapfile** and asserted the real on-disk uid/gid. This record
> preserves how the mechanism works and documents the gap that suite filled.

---

## 1. What `brix_impersonation map` does

`brix_impersonation map` (`src/auth/impersonate/`) makes the nginx **master run as root** and
spawns a double-forked, privileged **broker** that calls `setfsuid`/`setfsgid` per request to the
local account an authenticated identity maps to, so backend files land owned by that real UNIX
user. Enforcement is kernel DAC: the broker holds only **CAP_SETUID / CAP_SETGID** and never
**CAP_DAC_OVERRIDE** (see `broker_creds.c` — `permitted = (1u << CAP_SETUID) | (1u << CAP_SETGID)`).

Note (`broker_creds.c`): the broker does NOT probe "can't regain root" — it must keep CAP_SETUID
for `setfsuid`, and CAP_SETUID inherently allows `setuid(0)`. This is documented and accepted; the
guarantee is that no DAC override is available, not that root is unreachable.

## 2. Principal derivation

The **principal** presented to the mapper is:

- **GSI DN first** — the OpenSSL oneline slash form of the proxy *leaf* subject, e.g.
  `/DC=test/.../CN=12345/CN=12346`. It **includes the proxy CNs** (extract via
  `openssl x509 -subject -nameopt compat`).
- **else the token `sub`** (also SSS user, where applicable).

## 3. Resolution order and the reserved-id floor

Resolution is implemented in `src/auth/impersonate/idmap.c` (`brix_idmap_resolve()`), with the
grid-mapfile parse/lookup split into `idmap_gridmap.c` and the numeric-id deny-list / squash policy
in `idmap_denylist.c`:

1. **grid-mapfile match** — line form `"<principal>" localuser`, exact `strcmp` on the DN
   (`idmap_gridmap.c`: `strcmp(idmap_gridmap[i].dn, dn) == 0`).
2. **`getpwnam(principal)`** — direct lookup of the principal as a local username.
3. **squash to `brix_idmap_default_user`**, **or DENY if none is set** (`idmap_default_user[0]`
   empty ⇒ `BRIX_IDMAP_DENY`).

**Reserved-id floor.** Any resolved uid/gid below `brix_idmap_min_uid` is refused so the broker can
never be asked to act as a system account. `brix_idmap_min_uid` defaults to
`BRIX_IDMAP_DEFAULT_MIN_UID = 1000` and is clamped up to the hard floor
`BRIX_IMP_HARD_MIN_ID = 1000` (`idmap.c` raises any lower configured value with a warning). With a
`default_user` set, a sub-floor resolution **squashes** to that default; without one it **hard-denies
(403, no file created)**.

## 4. Directives

The impersonation directives are registered in `src/protocols/root/stream/directives_tier.h` and
live in the **`stream {}`** block (one broker per nginx instance; the same broker also governs the
`http{}` webdav/S3 servers):

- `brix_impersonation` (`off | single | map`)
- `brix_impersonation_socket`
- `brix_impersonation_export`
- `brix_gridmap`  — path to the DN→local-username grid-mapfile (`""` = none)
- `brix_idmap_default_user`  — squash target (`""` = deny)
- `brix_idmap_min_uid`  — reserved-id floor (default/hard 1000)

A `stream {}` block carrying **only** these directives and **no `server {}`** is valid.

## 5. The test gap

**Pre-existing coverage.**

- `tests/userns/` (`test_userns_impersonate.py`) proves ownership **WITHOUT real root**: an
  unprivileged user namespace drives the broker C directly / launches nginx in-namespace and maps a
  token `sub` via `getpwnam` — **no gridmap** involved.
- The multi-user (MU) conformance fleet (`tests/mu_authz_lib/`, the
  `nginx_mu_*` / `multiuser/*_noimp.conf` configs) runs with `brix_impersonation off` and only
  checks authz **verdicts**. `test_mu_impersonation_e2e.py` targets a `ROOT_CACHE` port the fleet
  never starts, so it was effectively inert.

**The gap.** Nothing launched the real nginx binary **as host root** with a **grid-mapfile** and
verified real on-disk uid/gid end-to-end.

**Filled by** the gridmap-ownership root suite: `tests/test_impersonation_gridmap_root.py` with
`tests/impersonation_gridmap_helpers.py` and configs `tests/configs/nginx_impersonate_gridmap_root.conf`,
`nginx_impersonate_gridmap_s3.conf`, and `nginx_impersonate_gridmap_webdav.conf`.
