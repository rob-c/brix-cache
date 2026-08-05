# Test-Suite Combinatorial Coverage Audit — 2026-08-04

**Question asked:** where does the test suite form an *incomplete burn-down* of the
API/feature combination space — i.e. which combinations of (protocol × backend ×
auth × operation × cross-cutting feature) are reachable in `src/` but have no test?

This is **not** a failure-triage document. For "which tests fail and why", see
`testsuite-state-2026-07-28.md`. This document is about **cells that were never
written**, plus two cells that were written and have since gone stale.

Method: five parallel read-only sweeps over `tests/` (851 Python modules, ~388
configs) and `src/`, each building one axis of the matrix; every claimed gap was
checked against the code to confirm the combination is *reachable* before being
called a gap. Two findings were then independently verified by the author — one
by code-read, one by executing the test. Provenance is marked per finding.

**Status 2026-08-04 (same day):** both P0 items in §7 are **closed** — see §2.1
and §2.2. Closing them turned up three product bugs, all fixed: the WebDAV TPC
push branch skipped the Layer-2 naming allowlist, the S3 origin 500'd on a
folder-marker `PUT`, and it 404'd on a folder-marker `HEAD` (the latter two broke
`sd_remote` mkdir/rename over `s3://`). P1-3 (`unix` auth) is also closed — see
§4. P1-5 (macaroon × `root://`) is closed too, by
`tests/test_macaroon_root_wire.py` (17/17), which also gives
`brix_macaroon_secret_old` its first live coverage on any plane and pins two
previously undocumented configuration constraints — both recorded in §4. P1-4
(authorization granularity behind `krb5` / `sss` / `pwd` / `host`) is closed by
`tests/test_authdb_mechanism_scope.py` (33) and
`tests/test_authdb_auth_scheme_gate.py` (6), and turned up a **fourth product
bug**: the native `brix_authdb` gate whitelisted only `gsi`/`token`, so those
four mechanisms could authenticate a user but could not authorize one — the cell
was empty because the feature was config-gated off. The gate now refuses only an
anonymous server; see §4. P1-6 (WebDAV COPY integrity gate) is closed as well,
and was flagged in this document as product work rather than a test gap: the HTTP
TPC plane now carries the native plane's completion pair as
`brix_webdav_tpc_require_source_size` / `brix_webdav_tpc_verify_checksum`
(`src/protocols/webdav/tpc_verify.c`, `tests/test_webdav_tpc_completion_gate.py`,
18/18), closing the truncation and bit-flip classes on COPY — see §6. The rest of
P1–P3 remains open as written.

**Status 2026-08-05 — the ranked backlog in §7 is burned down.** P1-7, P2-8
through P2-13 and P3-14 through P3-18 are closed as marked in place, and so is
**P3+-19, the structural fix this document argued for**: the suite now has a
combinatorial parametrization layer (`tests/matrix_layer.py`, a
`pytest_generate_tests` hook and a `matrix_node` fixture, two generic templates,
`tests/test_matrix_layer.py`). Both §7 fold-ins are closed too — dead
`tests/configs/` templates are frozen by `tools/ci/check_template_refs.py`, and
`TEST_CROSS_BACKEND`'s never-run parity axis is now driven in every ordinary run
by `tests/test_cross_backend_parity.py`. The named dead fleet *specs* are closed
too: the two stub-backed upstream cells now have the backend handlers they never
had, and the gotoTLS pair is documented and tested as unreachable by
construction. Ten product bugs were fixed along the way — the tenth being that
**every `stub-upstream-*` test had been running against a dead upstream**, an
error a proxy makes look exactly like a correctly forwarded one — and one
missing feature was built (P1-6). What remains open is recorded per-item in the
RESOLVED blocks below rather than summarised here — chiefly the per-subsystem
parity list and the three resilience legs in §6.

Separately, running the suite's own guards found
`tests/test_no_hardcoded_hosts.py` **RED**: 45 host literals across 14 modules had
accumulated since the migration that guard pins (it grandfathers nothing). All 45
are gone — routed through `settings.HOST` where the test dials or binds a fleet
endpoint, or annotated `# net-literal-allow: <reason>` where the literal *is* the
subject (a cert subject, an `EPRT` argument, a fuzz payload's `Host:` header, or
loopback **inside** a test network namespace, which `settings.HOST` must not
follow). Guard green; every touched suite re-run green.

---

## 1. The structural root cause

**The standing fleet is ~100 % posix.** Of ~126 registered specs in
`tests/fleet_specs.py`, exactly two are non-posix (`cache-only`,
`chaos-tier2`). Every non-posix backend in the suite is booted **ad hoc** by a
`LifecycleHarness` test or a `tests/cmdscripts/` live scenario.

**There is no combinatorial parametrization layer anywhere.** Verified counts
across the whole repo (**as of 2026-08-04 — CLOSED 2026-08-05 by backlog item
19**: `tests/matrix_layer.py` + the `pytest_generate_tests` hook and
`matrix_node` fixture in `tests/conftest.py`; the counts below are the
before-state and are left as written):

| Machinery | Occurrences |
|---|---|
| `pytest_generate_tests` | **0** |
| `indirect=True` (parametrized fixture) | **0** |
| `pytest.mark.parametrize` | 206 modules — but exclusively over *values inside an already-fixed server* |
| Hand-written `NginxInstanceSpec(...)` outside `fleet_specs.py` | **299 constructions across 212 modules** |

The consequence is the shape of every gap below: coverage grows **linearly with
author effort**, one hand-written module per cell, so the matrix is dense along
whichever axis each phase happened to care about and empty everywhere else.
Adding an axis value (a new backend, a new auth mode) does not automatically
test it against anything.

The pattern that *should* generalize already exists once:
`make_cache_node(backend, *, tmp, lifecycle, ...)` in
`tests/_cache_partial_helpers.py:73-90`, consumed as
`@pytest.mark.parametrize("backend", ["posix","pblock"])` in
`test_cache_partial_fill.py`. All the pieces for a real sweep are present and
unused: `NginxInstanceSpec` is a frozen dataclass (cheap `dataclasses.replace`),
`config_templates.render_config(..., strict=True)` already does placeholder
substitution, and `nginx_lc_cachemx.conf` proves a template can take
`brix_auth {AUTH}` as a substitutable placeholder — it is the **only** `{AUTH}`
occurrence in the entire config tree.

---

## 2. Verified findings (author-confirmed, highest confidence)

### 2.1 `test_readonly_backend_wire.py` is RED and encodes an obsolete contract — VERIFIED BY EXECUTION · **RESOLVED 2026-08-04**

> **Resolved.** The two stale assertions are inverted to the phase-92 contract
> and a positive end-to-end test added (`test_mkdir_granted_over_markers`,
> `test_rename_granted_over_markers`, `test_rename_is_observable_end_to_end`);
> `test_truncate_denied_enotsup` kept as the negative-capability leg. Restoring
> the tests exposed **two real product bugs in the S3 origin**, both fixed —
> see "What the fix turned up" below. 5/5 green.

```
FAILED test_readonly_backend_wire.py::test_mkdir_denied_eperm
FAILED test_readonly_backend_wire.py::test_rename_denied_eperm
2 failed, 2 passed in 0.55s
E   AssertionError: mv must fail on a read-only catalog, got 0
```

The file's docstring (lines 4-11) states that an `s3://` backend "advertises
CAP_RANGE_READ | CAP_MEMFILE only — no CAP_DIRS_WRITE", and asserts
`kXR_mkdir`/`kXR_mv` → `kXR_NotAuthorized`. Phase-92 added
`BRIX_SD_CAP_DIRS_WRITE` to `src/fs/backend/remote/sd_remote.c:376` plus real
marker-based `.mkdir`/`.rename` slots; the gates at `vfs_mkdir.c:182` /
`vfs_rename.c:117` are pure cap checks. Both ops now **succeed** (status 0).

Two things follow, and the second is the more valuable one:

1. The two assertions must be inverted or retired — they describe behaviour that
   no longer exists. `test_truncate_denied_enotsup` remains **correct**
   (sd_remote still has no `CAP_TRUNCATE` / no `truncate_path`) and is the model
   for what a genuine negative-capability test looks like.
2. **The phase-92 remote-mutation path demonstrably works end-to-end over the
   native wire, and nothing asserts it.** The positive contract
   (mkdir/rename/rmdir over `s3://` via `path/` markers) is currently proven
   only by *this failing negative test* accidentally exercising it. Note this
   also contradicts the premise recorded in `tests/test_s3_driver_namespace.py:26-30`,
   which declares mkdir/rmdir deliberately un-coverable e2e because the
   co-hosted `brix_s3` origin 500s on a `"coll/"` marker PUT — on this topology
   it does not.

#### What the fix turned up — two S3-origin bugs (both fixed 2026-08-04)

Inverting the assertions did **not** simply make them pass. `kXR_mkdir` came
back `kXR_IOError`, and a rename into the new directory came back
`"invalid destination path"`. Both traced to the S3 **server**, which had no
folder-marker path at all — so BriX-talking-to-BriX could not create or see a
folder even though the `sd_remote` driver emits exactly the AWS-standard form:

| | Before | After |
|---|---|---|
| `PUT "dir/"` (`s3/put_inner.c`) | fell into the object-write path; its parent-prefix mkdir created the directory as a side effect, then the atomic publish tried to `rename()` the staged temp **onto** that directory → `EINVAL` → 500, directory left behind | `s3_put_try_folder_marker()`: create the directory (parents, `EEXIST` = success/idempotent), 200; a marker carrying a body is 400 `InvalidRequest` rather than silently dropped |
| `HEAD "dir/"` (`s3/object_meta.c`) | 404 `NoSuchKey` like every other directory path, so a folder that existed stat'd as absent and `sd_remote_stat_impl()` step (2) could never classify a directory | 200 + zero length **for the marker form only**; a slash-free key that resolves to a directory stays 404 |

Consequence chain worth remembering: the driver classifies a path as a directory
*solely* by probing `"path/"`, and `kXR_mv`'s `BRIX_PATH_WRITE` gate
(`op_path.c:117-158`) probes the destination **parent** through that same VFS
stat — so a missing marker-read path did not fail as "no marker", it failed as
"invalid destination path" one layer up.

Tests: `tests/test_s3_folder_marker_put.py` (new, 6 cases — success/idempotent,
body→400, three traversal forms, and directory-without-slash still 404) drives
the fix directly on the S3 plane. `tests/test_s3_driver_namespace.py` gains the
marker slots its docstring had declared un-coverable (`MKCOL` → 201 + PROPFIND +
object-inside-prefix; re-`MKCOL` refused; traversal `MKCOL` refused).

**Traversal-test trap:** `requests` collapses `..` segments client-side, so a
traversal assertion written with it passes without the server ever seeing the
traversal. `test_s3_folder_marker_put.py` sends those probes with `http.client`
verbatim, and covers `..`, `%2e%2e` and `%2E%2E`; verified against the access log.

### 2.2 WebDAV TPC **push** skips the Layer-2 egress allowlist — VERIFIED BY CODE READ · **RESOLVED 2026-08-04**

> **Resolved.** The push branch of `ngx_http_brix_webdav_tpc_handle_copy()` now
> runs `webdav_tpc_source_guard()` on the `Destination` authority before
> `webdav_tpc_handle_push()` — the same verdict core, the same 403, the same
> `signal=tpc_egress` audit line as a pull. Covered by four new cases in
> `tests/test_webdav_tpc_source_egress_guard.py` (`TestWebdavPushGuardRefuse`:
> non-allowlisted RFC-1918 destination, non-matching suffix, unparseable
> `Destination` fails closed; plus an allow-side fall-through that asserts the
> absence of the audit line). Suite 9/9 green.

`src/protocols/webdav/tpc.c:341-356`:

```c
if (source_hdr == NULL) {
    /* Push mode: Destination present, no Source. */
    return webdav_tpc_handle_push(r, conf, dest_hdr);   /* line 343 — returns */
}
...
rc = webdav_tpc_source_guard(r, conf, source_url);      /* line 353 — pull only */
```

Push returns at 343, before the naming-allowlist guard at 353.
`src/protocols/webdav/tpc_push.c` contains no reference to the guard, and
`webdav_tpc_push_dest_url()` (`:97-114`) validates only that the
client-supplied `Destination` is `https://` and control-char-free before
curl-PUTting to it.

**Scope this correctly — it is an asymmetry, not an open SSRF hole.** Push *does*
get the Layer-1 range/DNS preflight: `tpc_thread_ssrf_preflight()`
(`tpc_thread.c:135-173`) applies `allow_local`/`allow_private` +
`require_https` to `t->url` on the worker thread, and `tpc_curl_setup.c:50-51`
carries the same policy on the sync path. What push lacks is the **Layer-2
naming allowlist** added by commit `4fde99418` — the control that says "only
these named hosts, regardless of address range".

Native root:// TPC is **pull-only** (`launch_prepare.c:299-323`, `"tpc-pull"`),
so push exists solely on the WebDAV plane and there is no native analogue to
compare against. Both existing guard suites
(`test_tpc_source_egress_guard.py`, `test_webdav_tpc_source_egress_guard.py`)
test pull only.

This was a product finding, not just a test gap. The dispatch fix and its tests
landed together, as noted above.

---

## 3. Matrix 1 — Protocol × Backend

Backends (`src/core/types/fs_list.h`): posix, block, pblock, http, xroot,
cache, stage, remote(s3), frm/tape, ceph, cephfs_ro.
**D** = direct · **I** = indirect/parse-only · **—** = untested · **N/R** = not reachable.

| | posix | pblock | block | cache | stage | xroot | http | s3 | frm | ceph |
|---|---|---|---|---|---|---|---|---|---|---|
| **root:// (kXR)** | D | D | D (ro) | D | D | D | D (ro) | D | D (ro) | D† |
| **WebDAV** | D | D | **—** | D | D | D | I (ro) | D | D (ro) | I† |
| **S3 inbound** | D | **—** | **—** | D | D | D (ro) | I parse | **—** | D (ro) | **—** |
| **gridftp** | D | D | **—** | N/R | N/R | D (ro) | **—** | D | N/R | **—** |
| **CVMFS** | D | — | — | D | N/R | — | D | — | — | — |

† docker/opt-in gated.

**Not gaps (unreachable, confirmed in src):** gridftp × {cache, stage, frm} —
`BRIX_TIER_DIRECTIVES` is included only by `root/stream/module.c:34` and
`http_common.c:334`, never by the ftp module. CVMFS × stage and CVMFS × write —
rejected at merge (`cvmfs_module_build.c:80,99`).

**Reachable-but-empty cells:**

1. **S3 inbound × `s3://` outbound** (nested S3 gateway). Legal per
   `vfs_backend_config_s3.c`; both halves proven separately
   (`nginx_ce_driver_s3.conf` = WebDAV→s3, `nginx_gridftp_s3.conf` = gridftp→s3).
   Verified absent by per-server-block parse over all 388 configs and 1050 test
   modules: **no block anywhere has `brix_s3 on` + `brix_storage_backend s3://`**.
2. **WebDAV × block**, **S3 × block** — block is HTTP-all-conf legal
   (`vfs_backend_config.c:83-110`) but exercised only over root:// in one
   cmdscript.
3. **gridftp × block**, **gridftp × http origin** — both parse through
   `brix_vfs_backend_config_str`; zero tests.
4. **S3 × pblock** — wired for HTTP planes, proven for WebDAV, never for S3.
5. **ceph/cephfs_ro as primary from WebDAV or S3** — reachable, and
   `sd_ceph_dir.c` / `sd_ceph_object_rename.c` exist, but in
   `cmdscripts/ceph_operator.py` the co-hosted `http{}` server (L293, L345) has
   **no** `brix_storage_backend`, so it serves posix `/export`. Both ceph smokes
   prove root:// only.
6. **`remote` decorator with impersonation from the S3 frontend** — reached from
   root://, WebDAV and gridftp, never from `brix_s3`.

**Orphaned scripts — code written, never collected by pytest.** ~~Nothing in
`conftest.py`, `cmdscripts/operator_runtime.py`, `Makefile` or `tools/` invokes
these.~~ **CLOSED 2026-08-04** — all five now have `test_cmd_*.py` wrappers
(§7 item 8); the table below is kept for what each one buys:

| Orphan | Would cover |
|---|---|
| `cmdscripts/http_store_writable.py` | **WebDAV × http origin WRITE** — the *only* sd_http write-path test in the tree |
| `cmdscripts/tier_matrix_drivers.py` | stage-store driver matrix posix/pblock/**xroot**/**rados** — only rados-as-tier-store coverage anywhere |
| `cmdscripts/remote_backend.py` | WebDAV × xroot read+multi-chunk write, range GET, cross-protocol |
| `cmdscripts/tier_remote.py` | remote stage/evict/store + sidecar-meta |
| `cmdscripts/cvmfs_verify.py` | cvmfs verify plane |

**Read-only cells (happy-path reads, zero mutation):** root:// × block (write
vtable exists in `sd_block.c`, never driven) · root:// × http origin
(`sd_http_write.c` never driven from kXR) · ~~gridftp × xroot (**RETR only** — yet
`brix_gridftp_allow_write on` *is* set in `nginx_gridftp_gsiftp_ev_xrd.conf:29`,
so the write path is configured but never exercised; contrast gridftp×pblock and
gridftp×s3 which both have STOR→RETR round-trips)~~ **CLOSED 2026-08-05, item 14**
· ~~S3 × xroot (`requests.get`
only, despite the token being minted with `storage.modify:/`)~~ **CLOSED
2026-08-05, item 14** · S3 × frm/tape
(residency ladder only) · root:// × ceph (whole-object create only — no
overwrite, rename, unlink, or dir ops).

---

## 4. Matrix 2 — Auth × Protocol

`A` accept · `R` reject · `S` authz granularity (path/scope/VO/ACL) · `F` forwarding to backend.

| Mechanism | root:// | WebDAV | S3 | gsiftp | CVMFS |
|---|---|---|---|---|---|
| GSI/X.509 proxy | A R S F | A R S F | n/a (carrier only, untested) | A R S F | A R S — |
| VOMS | A R S — | A R S — | n/a | A R S — | A R S — |
| WLCG token | A R S F | A R S F | A R S ~ | n/a | A R S — |
| Macaroons | A R S — *(new 2026-08-04)* | A R S — | n/a | n/a | **— — — —** |
| S3 SigV4 | n/a | n/a | A R ~ — | n/a | n/a |
| krb5 | A R S F F *(S new 2026-08-04)* | n/a | n/a | n/a | n/a |
| sss | A R S F *(S new 2026-08-04)* | n/a | n/a | n/a | n/a |
| pwd / Basic | A R S — *(root:// S new 2026-08-04)* | A R **— —** | n/a | n/a | n/a |
| host | A R S — *(behind `brix_auth host` new 2026-08-04)* | n/a | n/a | n/a | n/a |
| unix | A R S F *(new 2026-08-04)* | n/a | n/a | n/a | n/a |

**Zero-test mechanisms that exist in code:**

1. ~~**`unix` × root://**~~ — **CLOSED 2026-08-04** by
   `tests/test_unix_auth_wire.py` (21 cases). Was: `src/auth/unix/auth.c`
   (`brix_handle_unix_auth`, `brix_unix_trust_remote` at
   `directives_auth.inc:414`), accepted by `module_enums.c:40-51`, with the only
   reference in the entire suite a *source-string guard*
   (`test_cross_protocol_shared_helpers_b.py:584,596,607`) asserting the literals
   exist — no handshake ever executed. It was the highest-value auth gap because
   `unix` is a *trust-assertion* mechanism (the client asserts its own uid/gid)
   behind a remote-trust flag, the shape where a missing negative test is an auth
   bypass rather than a coverage statistic. The suite now drives the real kXR_auth
   round-trip: accept over loopback (and a post-auth read proving the session is
   genuinely unlocked), six credential-parse rejections, five unsafe-name-byte
   rejections, ops-before-auth refused, four wrong-credtype refusals, and both
   sides of the trust boundary — a **non-loopback** peer refused with
   `brix_unix_trust_remote off` and admitted with it `on`, while name validation
   stays tight either way.

   Testing the trust gate unprivileged needed one trick worth reusing: bind the
   instance to one of this host's own **non-loopback** interface addresses
   (`SIOCGIFADDR` over `socket.if_nameindex()`, not the hostname — that commonly
   resolves into `127.0.0.0/8` and would silently skip the leg) and dial it from
   the same host; the server then sees a non-loopback peer with no namespace, no
   container, and no root.
2. ~~**Macaroon × root://**~~ — **CLOSED 2026-08-04** by
   `tests/test_macaroon_root_wire.py` (17 cases) +
   `tests/configs/nginx_root_macaroon.conf`, two lifecycle instances
   (`lc-macaroon-root`, `lc-macaroon-root-rotate`). Was: `brix_macaroon_secret`/
   `_old` registered on the stream module (`directives_auth.inc:343-354`) with
   every macaroon test targeting WebDAV. The suite now drives the same C
   validator through the kXR `ztn` credential: accept + a post-auth read proving
   `activity:DOWNLOAD` really conveys `storage.read`, wrong secret, one flipped
   signature byte, expired `before:`, a `path:` caveat disjoint from the target,
   an `activity:UPLOAD`-only token that must not open for read, a foreign
   `location`, and three unparseable bearers. It also gives
   **`brix_macaroon_secret_old` its first live coverage on any plane**: a token
   signed with the previous secret is accepted during rotation, the current one
   keeps working, and a third secret is still refused — so the grace-period retry
   widens the key set by exactly one rather than weakening the signature check.

   Two facts the port turned up, neither of them documented before:

   * **A macaroon-only root:// server cannot be configured.** `brix_auth token`
     on the stream plane rejects the config at `nginx -t` unless
     `brix_token_jwks`, `brix_token_issuer` and `brix_token_audience` are all
     set (`src/auth/token/config.c`
     `brix_token_require_single_issuer_fields`), even when only
     `brix_macaroon_secret` is in use — `brix_webdav_auth` accepts a macaroon
     secret on its own. So the realistic stream shape is a *mixed* JWT+macaroon
     server, and the suite asserts both families authenticate on one instance
     with neither shadowing the other. Relaxing the precondition to accept "a
     macaroon secret alone" is a candidate product change, not done here.
   * **The macaroon `location` packet is matched against `brix_token_issuer`.**
     A macaroon minted with the right root key but another service's location is
     refused ("issuer/location mismatch"), which is what stops a shared-key peer
     from replaying its tokens here. Tests that mint macaroons for the stream
     plane must therefore set `location=` to the configured issuer or every
     positive case fails for a reason that looks like a signature problem.
3. **Macaroon × CVMFS** — `src/protocols/cvmfs/secure.c:108,265` sets
   `ra.macaroon_secret`; no test.
4. **GSI delegation carrier × S3 front** — `X-Brix-Delegate-Proxy` captured at
   `src/protocols/s3/handler.c:259,429`, exercised only on the WebDAV front.
5. `tests/gsihs/` **is an empty directory.**

~~**Identity-tested but authorization-untested (no `S`)**~~ — **CLOSED
2026-08-04** for all four mechanisms by `tests/test_authdb_mechanism_scope.py`
(33 cases, 2 skips) + `tests/configs/nginx_authdb_{pwd,sss,host,krb5}.conf` +
four lifecycle instances (`lc-authdb-{pwd,sss,host,krb5}`), and
`tests/test_authdb_auth_scheme_gate.py` (6 config-parse cases). Was: the
mechanism proved *who you are* but never *what you may do* — no krb5/sss/pwd
principal ever reached `brix_authz_check`, authdb, or a VO ACL
(krb5: 5 suites + 2 C tests of identity/delegation, zero authz; sss: strong
crypto/key negatives, zero path/ACL enforcement; pwd/Basic: 16 accept/reject
tests, zero path scope; host: host-rule authz lived in `test_authdb.py` but was
never combined with `brix_auth host` as the login mechanism).

Each mechanism now runs one server carrying the same rule battery — a `u` rule
for its own identity, a `u` rule for someone else, a `g` rule for its own VO, a
`g` rule for a foreign VO, an `l`-only rule, an `rwl` rule, and one directory
with no rule at all — and is asserted on all three axes: **path** scope (own
grant vs another identity's rule vs unlisted → default-deny), **privilege**
scope (`l` authorizes `stat` but must refuse an open-for-read; `rl` must refuse
an upload even with `brix_allow_write on`), and **VO/ACL** denial. Every
negative was verified against the server log to be an `authdb denied` line
naming the right `dn` (`pwduser` / `sssuser` / `localhost` / `alice`), not an
authentication failure arriving at the same exit code. `host` additionally
covers the `p` (peer-address) rule type on both sides.

**This gap was a product bug, not just missing tests.** `brix_authdb` in its
native format was refused at `nginx -t` for every scheme except
`gsi`/`token`/`both`:

```
nginx: [emerg] brix_authdb (native format) requires brix_auth gsi, token
       or both; use `brix_authdb_format xrdacc` for anonymous rules
```

The stated rationale — "the native authdb engine matches by DN/VO and so needs
an authenticating scheme" — is right, but the whitelist did not follow from it:
`sss`, `krb5`, `pwd`, `host` and `unix` all stamp `ctx->login.dn` exactly as
gsi/token do (`src/auth/sss/auth_request.c:282`, `src/auth/krb5/auth.c:353`,
`src/auth/pwd/auth.c:257`, `src/auth/host/auth.c:121`), and `pwd`/`sss` fill the
VO list too. So the four mechanisms were locked out of authorization entirely —
a server authenticating with `sss` could not restrict what the authenticated
user reached, on any path. The gate in
`src/core/config/server_conf_merge_security.c` now rejects exactly one thing,
an anonymous server (`brix_auth none`), with `brix_authdb_format xrdacc` still
exempt even there; `test_authdb_auth_scheme_gate.py` pins both sides.
`docs/06-authentication/identity-mapping.md` §4.2 records which scheme feeds
which rule type. Not changed: `brix_require_vo` carries the same
gsi/token-only whitelist (`src/core/config/policy.c:125-133`), but it also
demands `libvomsapi` + `brix_vomsdir`, so relaxing it is a VOMS-coupling
question rather than an oversight — left as a candidate follow-up.

**No forwarding coverage:** VOMS attributes → backend (never shown to survive a
hop) · CVMFS/scvmfs all three modes · S3-in → S3-out per-user hop (STS
forwarding is proven only from a **root://** front door).

**Effectively-uncovered-in-CI cells:** `test_tpc_delegation.py::test_dest_pulls_as_user_via_delegation`
is **xfail** pending F6 — multi-hop X.509 proxy delegation is *not* proven.
`fwd-brix-brix` davs→davs token two-hop is **xfail**, declared a product issue.
Pairing-A token backend leg **skips** ("https backend leg is GSI-only"). Every
`test_cmd_*_live.py` forwarding suite is `@pytest.mark.optin` — **the credential
forwarding matrix does not run by default.**

**Structural-only tests** (assert on Python helpers, never on the server):
`test_token_macaroon.py`, `test_macaroon_discharge.py` — the C validator's
discharge-bundle path (`brix_macaroon_validate_bundle`) is never driven over the
wire.

**Known-RED, correctly asserted:** `test_mu_cross_protocol.py` — "S3 authorizes
on SigV4 identity but never checks token scope."

---

## 5. Matrix 3 — Operation × Backend

Caps are from each driver's `.caps` field; a cell is only a gap if the cap is
advertised **and** the slot is implemented.

**pgread / pgwrite / vector-read are posix-only.** `test_pgread_wire_conformance.py`,
`test_pgwrite_checksum.py`, `test_pgwrite_cse.py`, `test_root_require_pgwrite.py`,
`test_conf_pgio{,_b}.py`, `test_conf_readv.py`, `test_aio.py` all bind to the
shared `posix:` fleet instance. The sole exception is
`test_pgwrite_staged_sync_gate.py` (pgwrite into `s3://` *through the stage
decorator*, not the leaf). Notably `pblock` and `block` are the only other
backends implementing `.preadv/.preadv2` — and `kXR_readv` is never driven
against either. **CLOSED 2026-08-04** by `tests/test_pgio_nonposix.py` — see
§7 item 9 for the cells it now covers.

**Remote-backend mutation is unit-only.** The phase-92 marker machinery is
exercised almost entirely against *fake transports* in `tests/c/`:

| mutation | sd_remote (s3://) | sd_http (WebDAV origin) | sd_xroot (root://) |
|---|---|---|---|
| mkdir | unit only | unit only | e2e |
| rmdir | unit only | **no test at all** | **no test** |
| rename | e2e (3 cases) + unit | **unit only** | e2e (1 case) |
| unlink | e2e via async queue | e2e via async queue | **no test** |
| setxattr/setattr | unit only | n/a | **no test** |
| server_copy | unit only | n/a | n/a |

There is **no nginx config in `tests/` that puts a writable `http://` backend
behind a WebDAV or root:// edge** — all 21 `http://` backend configs are
cvmfs/cache read paths.

**Advertised-cap-but-zero-test cells:** `sd_xroot` unlink, rmdir, the xattr quad
(`CAP_XATTR_WRITE`), dirlist (`CAP_DIRS`), `.fsync`, `truncate_path_cred` ·
`sd_cache.server_copy` (`CAP_SERVER_COPY`, `sd_cache.c:294`) — no TPC/COPY over
a cache backend · `sd_cache`/`sd_stage` truncate (both advertise `CAP_TRUNCATE`)
· `sd_cache` xattr set/remove · `pblock`/`ceph` `.ftruncate` · the `block`
backend data plane generally (one out-of-range-extent GET is its entire
coverage) · `BRIX_SD_CAP_CATALOG` enumerate.

**Error-path holes:**

- **EXDEV / copy-fallback rename is untested through any protocol.** `vfs_copy.c`,
  `namespace_ops_copy.c`, `copy_range.c` and `webdav/copy.c` all carry EXDEV
  branches; the only exercise is an incidental tmpfs cross-device commit in
  `test_shutdown_resume.py:247` and a redteam script. The posix rename tests
  (`test_conf_rename.py:29,169`) test cross-*directory* success, not cross-*device*.
- **Unlink-of-open-file** has no root:// or WebDAV coverage on any backend.
- **Staged-commit failure/abort contract** — verified only for `sd_posix`
  (`tests/c/test_staged_commit_contract.c`). The same "free only on success"
  contract is documented for remote and pblock but untested on `sd_http`,
  `sd_xroot`, `sd_stage`, `sd_cache`. Given that this exact contract produced a
  double-free family fixed on 2026-07-31, the untested drivers are the residual
  risk.
- **No negative capability tests against real driver structs** — `tests/c/test_vfs_caps.c`
  proves accessor logic on *synthetic* drivers only. No test asserts fattr over
  an `http://` export is ENOTSUP, or that ceph (CAP_DIRS without CAP_DIRS_WRITE)
  returns EPERM on mkdir.
- **Cache-fill error paths** — truncation poison is covered; an origin error
  *mid-fill* over `s3://`/`http://` is not, nor is eviction racing an in-progress
  fill or read.

**Concurrency:** covered — disconnect-mid-read ASan drivers (`test_aio.py:462,533-596`),
fill-lock reclaim, concurrent handles on a remote origin. **Absent** — TPC while
cache-fill in progress (no test), unlink during active transfer (no test), cache
eviction during active read (no test). All existing mid-transfer tests are
SIGHUP/reload/failover, and all are posix.

---

## 6. Matrix 4 — Cross-cutting features

**TPC.** Every native TPC config in the tree was `brix_auth none` or `brix_auth
gsi` — **TPC with token or sss auth had no config at all** (`test_tpc_token_mode.py`
is pure opaque-string parsing, not a live transfer). The **token** half is
**RESOLVED 2026-08-04** (§7 item 7); `sss` remains open. Every TPC config is
`posix:` — **TPC × any non-posix backend and TPC × cache_store are entirely
empty**. TPC × TLS × GSI is empty (TLS tests are `auth none`, GSI tests are
cleartext). Push exists only on WebDAV and only with cert-auth to the source —
no GSI/delegation push case.

~~**WebDAV COPY has no size or checksum completion gate at all**~~ — **CLOSED
2026-08-04.** It had neither, while native root:// TPC has both
(`brix_tpc_require_source_size`, `brix_tpc_verify_checksum`): `tpc.c`/`tpc_push.c`
contained no digest or size verification, so the truncation/bit-flip class proven
by `test_tpc_pull_integrity.py` was both untested *and* unimplemented on the HTTP
TPC plane — a product gap surfaced by a coverage audit. The HTTP plane now has
the same pair, deliberately named and behaving like the native one so an operator
reasons about one contract: `brix_webdav_tpc_require_source_size on|off` and
`brix_webdav_tpc_verify_checksum <alg>`, implemented in
`src/protocols/webdav/tpc_verify.c` (`webdav_tpc_verify_pulled()`) and hooked
into `webdav_tpc_run_curl_pull()` plus the multi-stream Range driver, which
between them cover all three pull tiers (202-marker, thread-pool, synchronous)
exactly once. After the last byte lands and before the staged temp is committed,
one HEAD re-probes the source — carrying `Want-Digest` when a checksum algorithm
is configured — and the reply's `Content-Length` is compared against the bytes on
disk, then the RFC-3230 `Digest` is recomputed over the temp. Both halves default
off, so no existing deployment sees a new refusal; whenever either is on the size
comparison runs (it is free once the HEAD is paid for) and
`require_source_size` decides only what a source declaring *no* length means. The
checksum half is fail-closed exactly like the native one — no `Digest`, an
unparseable one, an algorithm brix cannot compute, or a mismatch all refuse. Every
refusal is `502`, which the three tiers already treat as a failed transfer, so the
staged temp is aborted and nothing is published. Covered by
`tests/test_webdav_tpc_completion_gate.py` (18: 8 parse-time + 10 live against an
in-test https source scripted to truncate, over-declare, corrupt or omit its
digest), including the non-vacuity control that the *same* dishonest sources are
still accepted with both halves off.

**Cache passthrough** (`brix_cache_passthrough`, store-then-evict) was tested on
**WebDAV GET only**, cleartext, anon, `root://` origin, posix store — and the
live scenario is `@pytest.mark.optin`. The code path is reachable from
`s3/object.c` and `cvmfs/handler.c` (both include `http_cache_fill.h`), neither
tested. The root:// stream plane cannot passthrough by construction
(`sd_cache_maint.c:134` passes `allow_pt = 0`) — but there was no negative test
pinning that either. **CLOSED 2026-08-05** by backlog item 17 — see there.

**TLS.** INVARIANT 2 (TLS memory-backed vs cleartext file-backed/sendfile) was
asserted **only as a source-marker guard** (`test_cross_protocol_shared_helpers_b.py:110-113`),
never as behaviour. The `serve_send_sendfile` vs `serve_send_driver` fork
(`file_serve.c:343-524`) — "an object backend forces memory-backed even on
cleartext" — had no behavioural assertion, and no davs/davsg config in the tree
was backed by anything but posix. **CLOSED 2026-08-04** by backlog item 18 —
`test_tls_sendfile_matrix.py` drives both branches over both transports on a
pblock export and byte-compares them against a posix control; see item 18 for
the branch table. Still open on this axis: kTLS is parse-time only (`nginx -t`
NOTICE, 4 tests), with no negotiated-cipher or data-path case, and io_uring
remains posix + cleartext only.

**Checksums.** All per-page CRC32c and all Qcksum algorithm coverage is posix.
No test asserts `xrdfs query checksum` is correct — or even answered — when the
export is backed by `root://`/`s3://`/`rados://`, or for a cache copy vs its
origin. `brix_webdav_checksum_on_write` is tested only against a local posix
export (xattr sidecar); its behaviour on backends *without* xattrs is unasserted.

**Metrics grid** (`tests/_cachemx*.py`, 24 files, ~2 k cases) is dense but has
declared-vocabulary holes: **ops `tpc`, `xattr`, `copy` never appear in any
cachemx test** (3 of the 10 unified ops); proto `cvmfs` is headers-only, no rows;
**gridftp books nothing at all** (21 test files, not a `BRIX_PROTO_*`, no unified
ledger); auth values `unix`/`krb5`/`host`/`pwd` never exercised; no Range read on
the stream plane; no S3-over-TLS plane; and the entire HTTP+S3 half of the grid
is `posix:DATA_ROOT`, so `brix_cache_hits{proto=webdav|s3}` is never measured
against a real remote origin. `brix_tpc_transfers_total` / `brix_tpc_bytes_total`
/ `brix_webdav_tpc_total{event="push_started"}` are **catalogued but never
value-asserted after a real transfer**.

**Resilience.** `tests/resilience/` is **root:// + GSI + cleartext only** — the
sweep harness hard-codes GSI (`resilience/servers.py`). ~~No TLS leg in any fault
sweep (so TLS record-boundary behaviour under loss/corruption is unexercised);
no token/sss leg; no S3 or WebDAV *download*-side loss/truncation sweep (HTTP
fault coverage is upload-corruption only); no TPC leg through the fault proxy;
no fault injection against an `http://` origin; no fault injection against an
`s3://` origin specifically. Four `run_*.py` sweeps are standalone runners
**not collected by pytest**.~~ **§6 is fully closed.**

> **CLOSED 2026-08-05 by backlog item 16** (struck clauses only). TLS leg +
> token leg (`test_tls_token_leg_sweep.py`), download-side WebDAV/S3 loss and
> truncation sweep (`test_download_loss_sweep.py`), and all four runners
> collected (`test_sweep_runners.py`). See item 16 for the measured fault tables
> and the two defects that work surfaced.
>
> **REMAINING THREE LEGS CLOSED 2026-08-05.** `test_sss_leg_sweep.py` (7) adds
> the sss login leg; `test_server_leg_faults.py` (12) adds the two legs with no
> client on them — a root:// front pulling from an `http://` origin, and the
> native TPC destination→source pull. `test_tls_token_leg_sweep.py` gains three
> payload-integrity tests (13 total). Whole directory: **84 passed, 3 skipped**.
>
> **AND THE `s3://` ORIGIN, same day** — six more tests in
> `test_server_leg_faults.py` (18 total; directory **90 passed, 3 skipped**),
> driving the same topology through sd_s3 instead of sd_http
> (`nginx_resilience_s3_origin.conf`, `NginxS3OriginFront`, port 30517). It was
> listed as a separate line item rather than folded into the `http://` one
> because the two drivers share no fetch code, and that turned out to be the
> right call: **the two legs do not behave the same**, and the differences are
> the two most useful results in this whole section (below). **§6 is now closed.**
>
> **What the work established, beyond "these legs are now covered":**
>
>   * **Truncation and corruption are different problems on a server-side leg.**
>     A severed origin fetch is refused (rc 54, nothing delivered); a
>     length-preserving flip is *relayed under a clean rc 0*, because nothing in
>     the path is checking. Same on the TPC pull leg with
>     `brix_tpc_verify_checksum` off — which is the documented stock-parity
>     default (history-storage-and-caching.md #13), pinned here on the raw
>     transport path the surgical kXR-aware proxy in
>     `tests/test_tpc_pull_integrity.py` cannot produce.
>   * **`--pgrw` does not protect the origin leg**, structurally: the per-page
>     CRC32c is computed by the *front* over bytes it has already read from the
>     origin, so an upstream flip is faithfully CRC'd and delivered. This was
>     prose until the `s3://` leg made it assertable — there `--pgrw` returns in
>     ~0.1 s with a full-length wrong file, where on the `http://` leg it hits the
>     stall below and never returns a usable verdict. Only an end-to-end checksum
>     (`--verify`) covers that leg, and it mostly does — see the next point.
>   * **`--verify` is FAIL-OPEN when the checksum query itself fails, and the
>     query crosses the same damaged leg.** Measured over 20 corrupted fetches
>     from the `s3://` origin: 19 were refused on an adler32 mismatch, and on the
>     twentieth the server's re-read died, the client printed `checksum
>     computation failed` and **exited 0 keeping the corrupted file**. The policy
>     is deliberate and reasonable in isolation (`download_reconcile_cksum`,
>     `client/lib/xfer/copy_local.c`: `UNVERIFIED` warns and clears the status,
>     because a query hiccup is not a transfer failure). What makes it worth
>     recording is that the two events are **correlated, not independent** — the
>     damage `--verify` exists to catch is the damage that disables it — so the
>     escape hatch opens exactly when it is least wanted. The `http://` leg
>     refused 20/20 because sd_http fetches in one GET while sd_s3 issues many
>     ranged GETs, giving ~30x more response headers for a flip to land in; the
>     policy is identical on both, only the trigger rate differs. The test asserts
>     the union (refused, **or** rc 0 *with* the explicit warning) because
>     asserting `rc != 0` would be a 5%-flaky test — but a silent pass on corrupt
>     data still fails it, which is the regression worth catching. A strict mode
>     for `--verify` (treat UNVERIFIED as a failure) is the obvious follow-up and
>     is **not** implemented.
>   * **`--cksum <alg>` with no mode suffix verifies nothing** — it prints a
>     digest (`copy_cksum_verify.c`; only `:source`/`:end2end` query the server).
>     Documented behaviour, but it reads like a check, so it is now pinned as a
>     security-negative test.
>   * **One corruption rate cannot test two things.** The proxy flips at
>     `pct * 10000` ppm/byte. A rate that reliably mangles a few-hundred-byte
>     handshake obliterates any payload-integrity premise; a rate that spares the
>     handshake leaves credentials intact most of the time. The first version of
>     these tests used one rate for both and failed on a coin toss. The modules
>     now carry two constants 1000x apart, each chosen so its own tests are
>     deterministic (residual risk of the low rate touching a handshake: ~0.15%).
>
> **NEW OPEN DEFECTS surfaced (robustness, not integrity), reproducer in the
> `test_server_leg_faults.py` docstring:** `xrdcp --pgrw` against a *corrupted*
> `http://` origin leg stalls ~180 s (3x `BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS`)
> before failing with a misleading `FileNotOpen`; afterwards the same object
> returns `NotFound` instantly, though the origin is unreachable rather than
> empty — and `NotFound` is the one errno a grid client may act on
> destructively. Both need a fix in the `sd_http` retry/health path. Neither is
> asserted: a test that waits out a 180 s stall hangs CI, and pinning the second
> would pin a bug as a contract.
>
> The `s3://` work **narrowed the first defect's diagnosis**: the identical fault
> through sd_s3 returns in 0.1 s, so the stall is not a property of pgread, of
> remote backends, or of corruption in general — it is sd_http retrying a
> corrupted fetch without a client-visible deadline. That is now asserted from
> the other side (`test_pgrw_does_not_protect_the_s3_origin_leg` is both the
> architectural contract and the control for this defect).

---

## 7. Ranked backlog

Ordered by (risk × cheapness). "Cheap" = an existing fixture/config can be
reused or a written-but-orphaned script wired up.

### P0 — correctness of the suite itself — **BOTH DONE 2026-08-04**

1. ~~**Fix `test_readonly_backend_wire.py`** (§2.1).~~ **Done.** Assertions
   inverted; mkdir and rename-into-the-new-directory now assert `kXR_ok` over the
   wire, with a positive end-to-end leg (the moved bytes read back byte-exact and
   the old path is gone, proving move rather than copy); `truncate` kept as the
   correct-shaped `kXR_Unsupported` negative. 5/5 green. Doing so exposed and
   fixed two S3-origin bugs (§2.1, "What the fix turned up"), now covered by
   `tests/test_s3_folder_marker_put.py` (6 cases). The false premise in
   `test_s3_driver_namespace.py:26-30` is reconciled and that suite gained three
   real marker slots (`MKCOL` create / re-`MKCOL` refused / traversal `MKCOL`
   refused), 6/6 green.
2. ~~**TPC push egress-guard test + dispatch fix** (§2.2).~~ **Done.** Guard call
   landed on the push branch of `webdav/tpc.c`; four push cases added to
   `tests/test_webdav_tpc_source_egress_guard.py`, 9/9 green.

### P1 — security-relevant empty cells

3. ~~**`unix` auth handshake tests**~~ — **DONE 2026-08-04.**
   `tests/test_unix_auth_wire.py` + `tests/configs/nginx_unix_auth.conf`, three
   lifecycle instances (`lc-unix-loopback`, `lc-unix-remote-deny`,
   `lc-unix-remote-trust` in `fleet_lifecycle_ports.py`), 21/21 green. See §4.
4. ~~**Authorization granularity for krb5 / sss / pwd / host**~~ — **DONE
   2026-08-04.** `tests/test_authdb_mechanism_scope.py` (33 cases) +
   `tests/test_authdb_auth_scheme_gate.py` (6 config-parse cases) +
   `tests/configs/nginx_authdb_{pwd,sss,host,krb5}.conf`, four lifecycle
   instances (`lc-authdb-{pwd,sss,host,krb5}` in `fleet_lifecycle_ports.py`),
   39/39 green. Went past the port: the cell was empty because the native
   authdb was **config-gated off** for all four mechanisms, so this closed a
   product bug as well as a test gap (see §4).
5. ~~**Macaroon × root://**~~ — **DONE 2026-08-04.**
   `tests/test_macaroon_root_wire.py` + `tests/configs/nginx_root_macaroon.conf`,
   two lifecycle instances (`lc-macaroon-root`, `lc-macaroon-root-rotate` in
   `fleet_lifecycle_ports.py`), 17/17 green. Went beyond the port: the
   grace-period `brix_macaroon_secret_old` retry now has live coverage, and two
   undocumented constraints are recorded in §4 (a macaroon-only stream server is
   not configurable; the macaroon `location` must equal `brix_token_issuer`).
6. ~~**WebDAV COPY integrity gate**~~ — **DONE 2026-08-04.** Product work + test:
   `brix_webdav_tpc_require_source_size` / `brix_webdav_tpc_verify_checksum`
   (`src/protocols/webdav/tpc_verify.c`), hooked into both pull drivers so all
   three tiers pass through the gate, plus
   `tests/test_webdav_tpc_completion_gate.py` (18) and
   `tests/configs/nginx_webdav_tpc_completion_gate.conf` with three lifecycle
   destinations (`lc-tpcgate-{both,size,off}` in `fleet_lifecycle_ports.py`).
   This was a **product** gap, not a test gap — see §6.
7. ~~**Native TPC with token auth** — no config exists; add one plus a
   pull-with-token transfer.~~ **Done 2026-08-04.**
   `tests/configs/nginx_tpc_token.conf` (one nginx, four `brix_auth token`
   `brix_root` planes: a read-only SOURCE plus three destinations that differ
   only in how the outbound pull leg is credentialed — passthrough, static
   `brix_tpc_outbound_bearer_file`, and nothing at all) +
   `tests/test_tpc_token_auth.py` (9) + `lc-tpc-token` in
   `fleet_lifecycle_ports.py` (ports 30501–30504). First live coverage of
   `tpc_outbound_ztn()` (`src/tpc/gsi/gsi_outbound_common.c`) and of
   `tpc_pull_capture_passthrough_token()` (`src/tpc/engine/launch.c`).

   **This exposed a 5th product bug — BriX's `ztn` login block was unparseable
   by every stock XrdCl.** `src/protocols/root/session/login.c` advertised
   `&P=ztn,v:10000`, a form borrowed from the GSI dialect;
   `XrdSecProtocolztn`'s constructor wants `<expiry>:<maxtsz>:` (strtoll, ':',
   strtol > 0, ':') and aborts the login with *"Secztn: Malformed client
   parameters"* otherwise. **Token auth over `root://` had therefore never
   worked with a stock client** — every existing ztn test in the tree drives
   the wire by hand (`lib/tokenconf.root_ztn`,
   `test_macaroon_root_wire._auth_ztn`), which is exactly why nothing caught
   it. Fixed to `&P=ztn,0:4096:` (`BRIX_ZTN_PARMS`, matching the reference
   server's default `-maxsz 4096`), both in the token-only and the
   `brix_auth both` block; pinned by
   `test_token_auth.py::test_ztn_params_match_the_stock_client_grammar`.

   Two client-side constraints this cell has to satisfy, worth not
   re-deriving: `XrdSecProtocolztn` refuses to send a credential over a
   cleartext connection, so **every plane needs `brix_tls on` and every
   destination `brix_tpc_outbound_tls on`**; and it refuses a
   `BEARER_TOKEN_FILE` that is not `0600`, failing the login with a bare
   "No protocols left to try" that reads like a server fault.

   The regression sweep behind this item also found **four stale tests that had
   been red against committed behaviour**, all now fixed:
   `test_token_aud_array.py` (×3) and `test_token_es256.py` (×2) still expected
   `403` for a token that fails validation, but the WebDAV plane implements RFC
   6750 §3 — an unusable credential is `401` + `error="invalid_token"` and `403`
   is reserved for a *valid* token that is out of scope
   (`src/protocols/webdav/access_auth.c`); `test_wlcg_token_conformance_proto.py`
   PROTO-07 still characterised dual-transport (header **and** `?authz=`) as
   "header wins", but the server implements the RFC 6750 §2 MUST and refuses
   with `400 invalid_request` rather than letting the request fall through to
   Basic/anonymous — the test now pins the 400 and its challenge. Separately
   `tests/cmdscripts/c_auth_units.py`'s `deleg_gate` link list was missing
   `vfs_deleg_x509.o` (`brix_vfs_deleg_proxy()` moved there in the file-size
   burndown), so that C unit failed to link at all.

### P2 — reachable-but-empty functional cells

8. ~~**Wire up the five orphaned cmdscripts** (§3) — highest coverage-per-effort
   in this document; the code is already written. `http_store_writable.py` alone
   closes the only sd_http write-path gap.~~ **DONE 2026-08-04.**

   Wrappers: `tests/test_cmd_http_store_writable.py`,
   `test_cmd_tier_matrix_drivers.py`, `test_cmd_cvmfs_verify.py` (single
   `run_port` flow each), `test_cmd_remote_backend.py` (6 scenarios) and
   `test_cmd_tier_remote.py` (5 scenarios) — 19 tests, each `@pytest.mark.optin`
   with its own `xdist_group` (the scripts use fixed ports) and an importability
   test pinning the exact `SCENARIOS` key set.

   Every script was RUN before it was wrapped, which is what found three defects
   a blind wrapper would have inherited:

   - **Product — `brix_cache_meta sidecar` was inert on any xattr-capable store.**
     `brix_xmeta_save()` prefers the `user.xrd.cinfo` xattr whenever the driver
     has `setxattr`, so an explicitly configured sidecar mode never produced a
     sidecar. Split into `xmeta_save_carrier(..., force_sidecar)` with a new
     `brix_xmeta_save_sidecar()`; `brix_cstore_cinfo_store()` calls it when
     `meta_mode == BRIX_CMETA_SIDECAR` (mode is a request, not a hint).
   - **Product — a root:// store could not hold a sidecar at all.** With the
     above fixed, the sidecar `kXR_open` came back `kXR_NotFound` (3011): the
     root plane answers every reserved name as absent, and unlike the HTTP planes
     it had no trusted-store exception. `brix_cache_store_endpoint` (the switch
     WebDAV/S3 already carry) is now registered on the stream plane and gates the
     reserved-name guard in `open_request.c`, `stat.c` and `statx.c`. Listing
     still hides internal names, and the default stays OFF. Covered by four new
     tests in `test_mu_sidecar_hidden.py`, including the paired control that the
     same file stays absent on a node without the directive.
   - **Test-logic — `tier_remote remote-evict` asserted a vacuous eviction.**
     The check tuples are built at the end of the function, so `cached.exists()`
     was evaluated *after* the refill had re-created both objects. Existence is
     now snapshotted at the step it describes.
   - Also fixed: `LiveRun.call()` had no explicit binary mode, so
     `remote_backend stream-write` died in `communicate()` decoding an `xrdfs
     cat` of random bytes; and `test_mu_sidecar_hidden.py` planted its
     `.xrd-tmp.` probe with a dead owner pid, which the orphan-temp reaper
     unlinked at worker start — every "is it hidden?" assertion on that name had
     been passing against a file that no longer existed.
9. ~~**pgread/pgwrite/readv against a non-posix backend** — start with `pblock`
   and `block`, the only other `.preadv`-capable drivers.~~ — **CLOSED
   2026-08-04** by `tests/test_pgio_nonposix.py` (20 cases, 2 registry servers:
   `lc-pgio-pblock` 31210 via the existing `pblock_lab_spec`, `lc-pgio-block`
   31211 via the new `configs/nginx_block_dev.conf`). Both engines
   (`pgread_encode.c` → `driver->preadv2`, `readv_engine.c`) are now driven off
   posix:
   - **pblock:** pgread page-split/bytes/per-page CRC32c at five geometries
     including one straddling the 1 MiB block boundary and the short EOF page;
     readv across non-contiguous segments and the block boundary; pgwrite
     round-trip at an unaligned boundary-crossing offset; a corrupt-CRC page
     flagged (error or CSE list), and pgwrite through a **read-only handle**
     refused with the object unmodified.
   - **block:** the whole-device extent `/0` reports **extent-relative** page
     offsets with correct CRCs; readv is byte-exact and a segment running past
     the extent end is refused; an in-extent pgwrite touches only its own range
     and does not grow the device, while a boundary-crossing one is refused
     (fixed extents cannot grow); `/1`, `/etc`, `/0/passwd` and
     `/../../etc/passwd` all fail to open.
   The device is a plain regular file (`sd_block_init` falls back to `st_size`
   off `S_ISBLK`), so the plane needs no loop device and no privilege.
10. ~~**Staged-commit abort contract for `sd_http`, `sd_xroot`, `sd_stage`,
    `sd_cache`** — extend `tests/c/test_staged_commit_contract.c` per driver;
    this contract has already produced one double-free family.~~ — **CLOSED
    2026-08-04** by two new C units, and it produced **two more members of that
    same family**. The contract (stated in `vfs_staged.c`) is: `staged_commit`
    frees the heap handle **only on success**; on failure the handle stays valid
    and the caller releases it via `staged_abort`. Every abort site was
    enumerated first — `stage_engine.c:250,259`, `staged_file_commit.c:150,162,175`,
    `cache/fetch.c:278,287,310`, `cstore.c:178`, `xmeta_carrier.c:69` — all of
    them abort **after** a failed commit, so a commit that frees on the failure
    path makes the mandatory abort a use-after-free.
    - **Product fix — `sd_stage_write.c` (two defects).** (a) After the inner
      store commit consumed `ss->inner`, the pointer was left dangling, so a
      later `sd_stage_staged_abort` aborted an already-released handle; it is
      now `NULL`ed and the abort skips a consumed inner. (b) The SYNC write-back
      tail freed `ss` **and** `st` unconditionally, including when the inline
      flush failed — the caller's abort then re-entered both allocations. The
      failure path now returns `rc` with the handle intact.
    - **Product fix — `sd_frm.c`.** A failed `mss->migrate()` freed `ss`+`st`
      before returning `NGX_ERROR`, giving the same UAF plus a second purge of
      the online buffer. Only the success path frees now.
    - **`tests/c/test_staged_contract_tiers.c`** (6 arms) drives `sd_stage` +
      `sd_frm` under ASan off a scriptable fake store driver and a fake
      `brix_mss_adapter_t`: SYNC success; SYNC flush failure followed by the
      mandatory abort (the pre-fix source SEGVs here at
      `sd_stage_write.c:550`); inner-commit failure as the security-negative —
      no flush is attempted and the object is never published; ASYNC submit;
      frm migrate failure (pre-fix SEGV at `sd_frm.c:372`) and success.
    - **`tests/c/test_staged_contract_origin.c`** (6 arms) pins the drivers that
      were already conformant so they stay that way: `sd_http` commit over a
      scripted `brix_s3_transport_t` for 200/201/204; a transport failure → EIO
      with the abort **not** re-PUTting; a 403 → EACCES (security-negative);
      `sd_cache_staged_commit`/`_abort` forwarding a 500 to the source driver
      stamped on the handle; and `sd_xroot` sync-failure vs success, asserting
      the file and connection handles close exactly once and only via abort.
    - Survey result for the rest: posix ✔ (fixed earlier in this family),
      remote ✔, pblock ✔, http ✔, xroot ✔, cache ✔ (thin forwarders), ceph is
      pool-allocated and never frees — leak-by-design, not memory-unsafe.
    - **Lane repairs.** The object-linked C units were failing wholesale for a
      shared reason: `/tmp/nginx-1.28.3` is built `--coverage`, so every `.o`
      carries `__gcov_*` references and any harness linked without `--coverage`
      died at LD time. `_compile_and_run` now detects that generically and also
      redirects `.gcda` writes (`GCOV_PREFIX`) so a unit run cannot clobber the
      lcov lane's profile. Plus: `staged_commit_contract` was missing a
      `brix_mkdir_recursive_confined_canon` stub, and the five `sd_remote`
      runners' hand-copied object list (now the single `SD_REMOTE_OBJS`) was
      missing `sd_s3_sign_ext.o` and `sd_remote_dir.o`. The lane went from
      **9 failed / 10 passed → 19 passed**.
11. ~~**EXDEV rename fallback** through at least one protocol.~~ — **CLOSED
    2026-08-04** by `tests/test_stage_cross_device_commit.py` (9 tests, server
    `lc-stage-xdev` 31212 on the new `configs/nginx_lc_stage_xdev_webdav.conf`).
    Test-only; no product change. The fallback lives in
    `core/compat/staged_file_commit.c::commit_cross_device` and was reachable
    only through root:// close
    (`test_shutdown_resume.py::test_upload_resume_stage_dir`). The HTTP door to
    it is a `Content-Range` PUT under `brix_webdav_upload_resume on` **plus**
    `brix_webdav_stage_dir` — a directive that had no behavioural coverage
    anywhere and was undocumented; both it and `brix_webdav_upload_resume` are
    now in `docs/04-protocols/webdav-directives.md`.
    - The cross-device condition is real, not mocked: the stage dir is created on
      `/dev/shm` (tmpfs) and the export on the ordinary filesystem, and the
      module **skips** unless `st_dev` actually differs — otherwise `rename(2)`
      would serve the commit and every assertion would pass vacuously. One test
      re-asserts the partial's `st_dev` mid-upload, so the claim "this commit had
      to copy" is checked, not assumed.
    - Covered: single-chunk commit (byte-exact, and neither the partial, the
      pending-commit marker, nor the temp adjacent to the destination survives);
      three-chunk resume with the partial provably on the stage device and the
      destination invisible until the last chunk; a 5 MiB payload through the
      copy loop; overwrite replacing the object with a **new inode** (atomic
      replace, not truncate-in-place); the append-only refusal (`409` +
      `X-Upload-Offset`, partial preserved, then resumed to completion); and four
      traversal targets refused with nothing written on either device.
    - TRAP re-confirmed: `requests` collapses `..` client-side, so the traversal
      arm started out passing `201` against a legal in-export path. The
      security-negative uses raw `http.client` with a verbatim request-target.
    - **Product bug found by the regression sweep that followed** (uncommitted
      work in the tree, not by this item's tests): `open_resolved_file.c`'s P80.2
      resume divert had been widened to fire on any non-NULL
      `brix_vfs_backend_resolve()`. Since phase-68 every plain `brix_export`
      registers a **default-POSIX** census row
      (`fs/vfs/vfs_backend_config.c:169-192`), so the resolve is never NULL and
      `use_resume` was cleared for **every** root:// upload — `brix_stage_dir`
      and upload resume were dead on the stream plane (bytes still landed, but
      unstaged: the final path was touched mid-write and an interrupted upload
      could not resume). Four existing tests caught it
      (`test_shutdown_resume.py::test_upload_resumes_across_restart` /
      `::test_upload_resume_stage_dir`,
      `test_file_api.py::test_sync_durable_via_handle_resume_on`,
      `test_pgwrite_cse.py::TestWriteThenCorrectResumeOn`). Fixed by keying the
      divert on `driver != brix_sd_default_driver()` — the same discriminator
      `brix_commit_staged()` uses (`staged_file_commit.c:378-382`) — which keeps
      the widening's intent (a driver **with** `pwrite`, e.g. `sd_xroot` or a
      composed `sd_cache` tier, still diverts to the whole-object staged seam)
      without disabling staging for local POSIX exports.
    - The **driver-backed** side of that discriminator had no direct pin, so
      `test_stage_hydration.py::test_driver_backed_write_diverts_upload_resume`
      was added: a create through the write-stage gateway must leave no
      `.xrdresume.*.part` skeleton (and no published object) inside the gateway
      export, with the bytes byte-exact at the origin.
    - Also repaired in the same sweep:
      `test_metrics_coverage_webdav.py::test_move_rename` still asserted MOVE in
      the `OTHER` method bucket after the unified-rename work gave MOVE its own
      enum slot (`observability/metrics/webdav.c`, pinned by
      `test_cachemx_move_rename.py`); and `client/bin/` had never been built in
      this tree, which skipped/failed the `xrdfs`-driven metrics coverage arms.
12. ~~**Negative capability tests against real driver structs** — fattr on
    `http://` → ENOTSUP; ceph mkdir → EPERM. `test_vfs_caps.c` proves only
    synthetic drivers.~~ — **CLOSED 2026-08-04** by
    `tests/test_backend_caps_negative.py` (12 tests, server `lc-caps-http`
    31213 + origin 31214 + stage-off 31215 on the new
    `configs/nginx_lc_caps_http.conf`), **plus one product fix**.
    - Topology: a WebDAV origin and **two** root:// exports storing through it —
      one with the default write-stage tier, one with `brix_stage off` — because
      "this backend has no xattrs" reaches the protocol layer as two different
      errnos. The VFS's own NULL-slot checks raise `ENOTSUP`
      (`fs/vfs/vfs_xattr.c`), while the storage seam raises **`ENOSYS`** when the
      *leaf* has no slot (`brix_sd_listxattr_maybe_cred`,
      `fs/backend/sd_cred_forward.h`) — which is what a composed tier over an
      xattr-less origin produces.
    - **Product bug:** `fattr_list()` matched only `ENOTSUP`/`EOPNOTSUPP` for its
      documented degrade-to-empty behaviour, so the staged arm answered
      `kXR_FSError "listxattr failed"` where the direct arm answered an empty
      list — for the same healthy backend. `protocols/root/fattr/list.c` now
      accepts `ENOSYS` as well; `fattr/README.md` records why three errnos mean
      one thing. get/set/del were already honest (`kXR_Unsupported`).
    - Covered per arm: byte-exact read of a file that exists ONLY at the origin
      (non-vacuity — without it the module could pass against local POSIX and
      prove nothing), get/set/del refused `kXR_Unsupported`, list an empty
      success, truncate refused (`kXR_Unsupported` staged / `kXR_IOError` EROFS
      direct — both honest, neither a silent no-op), and two
      security-negatives: a refused set must not fall back onto a
      **world-writable** local decoy under the export root (a storage-domain
      split: metadata local, bytes remote), and an fattr target above the export
      writes nothing there or at the origin.
    - **`ceph mkdir → EPERM` is NOT covered and cannot be here**: this build has
      no `BRIX_HAVE_CEPH` (the ceph drivers are compiled out), and the driver
      structs that are reachable from a C unit are the registry's `BACKEND` rows
      — `sd_http`/`sd_xroot` are `ORIGIN` rows whose structs are `static`, so a
      real-struct C unit cannot see them at all. That half belongs to the
      ceph lab (`PHASE81_RUN_CEPH_PORTS=1`, `tests/ceph/`).
13. ~~**Nested S3 gateway** (`brix_s3 on` + `brix_storage_backend s3://`) — a
    whole reachable topology with zero configs.~~ — **CLOSED 2026-08-04** by
    `tests/test_s3_nested_gateway.py` (8 tests, server `lc-s3-nested` 31216 +
    origin 31217 on the new `configs/nginx_lc_s3_nested.conf`), **plus one
    security fix**.
    - Topology: an S3 front (`brix_s3 on` + `brix_export`) whose
      `brix_storage_backend` is a co-hosted `s3://` origin, the two blocks
      carrying **different** SigV4 key pairs. `worker_processes 2` (the front
      blocks on its own outbound leg; one worker self-deadlocks — same rule as
      `nginx_ce_driver_s3.conf`).
    - **Why the cell was empty:** `nginx_ce_driver_s3.conf` recorded an S3 front
      over an `s3://` backend as blocked by "a separate, pre-existing whole-object
      staged-open failure that also breaks a plain identity PUT". That diagnosis
      was wrong, and the real defect was a **cross-tenant authentication bypass**:
      the worker-local SigV4 signing-key cache
      (`protocols/s3/auth_sigv4_verify_crypto.c`) was keyed on **date+region
      only**. One worker verifies for every `brix_s3` block, so the first block
      to sign captured the one slot; from then on the other block **accepted a
      request forged with the first block's secret** against its own (public)
      access key id, and **rejected its own legitimate credential** for the rest
      of the calendar day, because the cache-hit path never re-derives.
      Reproduced live in a two-block single-worker lab (forged GET returned the
      other tenant's object body, 200). Fixed by adding a SHA-256 of the secret
      to the cache key — a digest, so the static holds no key material.
    - Coverage: PUT through the front lands byte-exact in the **origin's** bucket
      with nothing under the front's export root; a key seeded only at the origin
      is readable/statable/listable through the front; DELETE removes the origin
      object; a miss is 404 `NoSuchKey` (not a backend I/O error) and deleting a
      missing key is never a 5xx; unsigned and wrong-secret writes are 403 and
      create nothing at the origin; six alternating rounds prove the front refuses
      the origin's secret while both blocks keep their own credentials working
      (the cache-isolation pin); and a `..` key writes above neither root.
    - Verified as a real regression pin: with the secret dropped from the cache
      key, 3 of the 8 tests fail (including the isolation test); with it, 8 pass
      and 243 pre-existing S3 tests stay green.
14. **Mutation cells:** `sd_http` rmdir (no test at any level), `sd_xroot`
    unlink/rmdir/xattr/dirlist, gridftp × xroot STOR (config already has
    `allow_write on`), S3 × xroot PUT/DELETE (token already minted with
    `storage.modify:/`).
    **RESOLVED 2026-08-04 for the two origin-driver namespaces** (`sd_http`,
    `sd_xroot`); **the two remaining cells RESOLVED 2026-08-05** — see the
    "gridftp × xroot STOR" and "S3 × xroot PUT/DELETE" blocks at the end of this
    item. `tests/test_ns_mutation_gateways.py` (37 tests) runs every namespace
    mutation — mkdir / rmdir / rm / mv / mkpath / dirlist / xattr — three ways in
    ONE nginx (`configs/nginx_lc_ns_gateways.conf`): a POSIX **control** plane and
    the two gateway planes, asserting the three answers agree. That three-way
    comparison is what made each defect below visible: none of them is detectable
    from a single plane, because a driver that answers a mutation wrongly still
    answers it *consistently*.
    - **Product bug A — `sd_http` rmdir destroyed a regular file.** DELETE is one
      method for both kinds of resource, so `sd_http_unlink` ignored its `is_dir`
      argument: `xrdfs rmdir /some/file.bin` deleted the FILE and reported
      success, where the POSIX control refuses `ENOTDIR`.
    - **Product bug B — a populated collection could be deleted
      non-recursively.** The VFS only ever calls the driver `unlink` slot
      non-recursively (recursive deletes are walked by
      `brix_vfs_driver_rmtree`), but WebDAV DELETE of a collection is recursive
      by RFC 4918 §9.6 — so against a spec-conforming origin an `rmdir` of a
      non-empty collection would have wiped the whole subtree. Against our own
      origin it returned **success while the data survived** (origin 409 →
      shared status map's `ENOENT` → the root layer's idempotent-rmdir success).
      `sd_http_unlink` now gates on an emptiness probe (`ENOTEMPTY`) and maps a
      DELETE 409 to `ENOTEMPTY` instead of `ENOENT`.
    - **Product bug C — `sd_http_stat` reported EVERY path as a regular file.**
      HTTP has one spelling for both kinds of resource (a HEAD of a collection
      and of an empty object are the same `200`/`Content-Length: 0`), so a
      collection stat'd as a 0-byte file: `xrdfs stat` lied, and any caller that
      branches on the type took the file branch. Fixed with an ambiguity-gated
      PROPFIND `Depth: 0` probe (`sd_http_probe_type`, shared with the delete
      gate) — it costs an extra RTT only for a zero-sized stat, so a plain
      HTTP/CVMFS origin keeps its flat-object view and pays nothing.
    - **Product bug D — a stage tier made every nested write impossible.** With
      `brix_stage` configured, a create-open of ANY subdirectory key failed
      `kXR_NotFound`: the client's `mkdir`/`kXR_mkpath` builds the chain in the
      export and (at flush) on the origin, but never in the **private spool**, and
      the write-back leg opens the spool object directly. Reproduced with no
      remote backend at all (plain POSIX export + `brix_stage_store posix:`), so
      it was never gateway-specific. `sd_stage_open_write` now builds the key's
      parent chain in the store (`sd_stage_store_mkparents`); the staged
      whole-object leg never hit this because the POSIX store's `staged_open`
      already mkpaths its own parents. Covered in `tests/test_stage_hydration.py`
      (nested create lands byte-exact; an unwritable spool fails the open cleanly
      instead of stranding bytes; a traversal key materialises no directory).
    - **Two further defects fell out of the same status/type handling.**
      (i) *Delete of a missing path reported success* — a DELETE 404 was folded
      into the idempotent-rmdir path, so `rm /gone` answered OK where the POSIX
      control answers `kXR_NotFound`; 404 is now `ENOENT` end-to-end.
      (ii) *`mkdir -p` over a regular file reported success* — downstream of bug
      C: with every path stat'ing as a file the "exists, is it a directory?"
      test could not fail, so the recursive-mkdir walk accepted a FILE as the
      parent component. With the type probe in place it is `kXR_ItExists`, the
      file's bytes intact.
    - Also covered, and agreeing across all three planes: `mkdir -p` over an
      existing directory is idempotent while `mkdir -p` over a regular FILE is
      `kXR_ItExists` with the bytes intact; `rm` of a missing path is
      `kXR_NotFound`; `rm` of an EMPTY directory succeeds (the stock oss
      behaviour the POSIX control pins) while a POPULATED directory is never
      removed non-recursively by either `rm` or `rmdir`; per-attribute xattr is
      `kXR_Unsupported`; and two traversal security-negatives (mkdir + rm) over
      both gateways.
    - **gridftp × xroot STOR — RESOLVED 2026-08-05.**
      `tests/test_gridftp_delegate_xrootd.py` grew from 3 to **8 tests**: the
      gateway's `allow_write on` is now actually driven. A 300 KiB delegated STOR
      is asserted by reading the bytes off the UPSTREAM export (never a RETR back
      through the gateway — a read-through would pass either way), together with
      a fresh `CN=Test User` login on the upstream, proving the write leg
      re-delegated rather than reusing a read connection. Also: the object round
      trips back out through the gateway; an overwrite truncates; and a
      nested-key STOR mkpaths **on the upstream only** — the premise that it
      would fail was wrong (the upstream creates the parent chain), so the test
      pins the measured behaviour plus the half that matters, that nothing
      materialises in the gateway's own export. Security-negative: a traversal
      key is refused and writes nothing above either root.
    - **S3 × xroot PUT/DELETE — RESOLVED 2026-08-05.**
      `tests/test_s3_xroot_mutations.py` (15 tests, new
      `configs/nginx_lc_s3_xroot.conf`, ledger `lc-s3-xroot`) puts an S3 REST
      front in front of a native `root://` origin **in the same nginx** and
      drives the sd_xroot create-open / write / close / unlink slots that the
      cell's `storage.modify:/` token had been minting permission for and never
      using. The front's own `brix_export` is a separate, deliberately empty
      tree, so "the write left the front" is a filesystem fact rather than an
      inference: every test ends with that tree still empty. Measured contract —
      `PUT → 200`, `GET → 200` byte-exact, `HEAD → 200` + `Content-Length` with
      no body, `GET /<bucket>/ → 200` ListBucketResult, `DELETE → 204`, and a
      subsequent `GET → 404`. Covered: multi-chunk (3 MiB) PUT, truncating
      overwrite, and a listing that follows both the PUT and the DELETE.
      Error side: a missing key is 404 on GET and an idempotent 204 on DELETE
      (S3 semantics, not a defect), and a PUT to an unconfigured bucket is
      `NoSuchBucket` with nothing written. Security-negative: four traversal
      spellings — `../`, `a/../../`, `%2e%2e%2f`, `..%2F` — all normalise out of
      the bucket, are refused, and leave no file above or inside the origin
      export. They are sent through `http.client`, not `requests`, because
      `requests` collapses `..` client-side and would credit the server with a
      refusal it was never asked to make. No product bug surfaced: both cells
      behaved correctly once driven; what was missing was the driving.

### P3 — grid completion / structural

15. **Metrics grid:** add ops `tpc`/`xattr`/`copy`, an S3-over-TLS plane, stream
    Range, and one HTTP-plane-with-remote-origin cell; value-assert the TPC
    counters instead of only cataloguing them.
    **RESOLVED 2026-08-04** — `tests/test_cachemx_ops_grid.py` (19 cases) plus
    three new cachemx planes: `{S3_TLS_PORT}` (S3 SigV4 over TLS),
    `{DAV_ORIGIN_PORT}` (WebDAV over a `root://` origin — the only HTTP plane not
    backed by the local posix tree), `{DAV_TPC_PORT}` (the only plane with
    `brix_webdav_tpc on`, so a `COPY` + `Source:` is a real curl pull leg).
    Cataloguing the declared cells against the cells any test had ever moved
    turned up **three product bugs**, all fixed here:
    - `brix_io_ops_total{op="tpc"}` had **no booking owner** — declared, mapped,
      and permanently zero. New count-only recorder `brix_metric_op_count()`
      (`unified_record.c`) booked from `brix_tpc_metric_book()`
      (`src/tpc/common/metrics.c`), the one funnel both transports reach.
      Count-only is deliberate: a TPC's clock lives in the registry across a
      detached thread, so there is no honest request-scoped duration.
      → metrics-bug-patterns.md **Pattern 13** (new).
    - `sd_posix_server_copy()` handed root-RELATIVE keys to `brix_ns_local_copy`,
      which demands absolutes under `root_canon` → EXDEV. Server-side copy could
      not succeed on **any** export with an explicit `brix_storage_backend`
      (WebDAV COPY 403, S3 CopyObject 500); a plain export worked because the VFS
      namespace branch runs there instead. Exactly the `sd_posix_rename` bug of
      2026-08-03, in the sibling slot the fix did not check.
      → metrics-bug-patterns.md **Pattern 10, instance 2**.
    - A WebDAV GET that parks on the off-loop cache fill re-entered through the
      raw handler, so the one request that paid for the origin fetch was missing
      from `brix_webdav_responses_total` and `brix_io_ops_total{op="read"}` while
      its bytes still landed; the fill **failure** tail (404/403/502) booked
      nothing at all. Fixed in `src/protocols/webdav/get.c` (metrics-wrapped
      re-entry + a non-NULL `on_fail`). → metrics-bug-patterns.md **Pattern 7**,
      second instance.

    Known gaps recorded, not fixed (both pinned as current behaviour so the day
    they change a test notices, not a dashboard):
    - WebDAV COPY of a **missing source** books no `op="copy"` row at all — the
      pre-copy probe is deliberately unmetered ("the COPY op accounts for
      itself") and the copy never runs. S3 CopyObject *does* book `not_found` on
      the same input; the two protocols disagree.
    - On a remote-backed export the fill is offloaded and the re-entered open
      then finds a genuine cache hit, so `brix_cache_misses_total{proto="webdav"}`
      never moves there — a cold object is booked as a HIT. The inline-fill path
      (local posix) books MISS for the same logical event. The label therefore
      depends on whether a thread pool was available, not on what happened.
16. ~~**Resilience:** add a TLS leg and a token leg to the sweep harness; add a
    download-side S3/WebDAV loss sweep; collect the four orphaned `run_*.py`.~~
    **RESOLVED 2026-08-05** — all three parts, 26 new tests in three modules
    under `tests/resilience/`, plus two new harness classes
    (`NginxTlsAnon`, `NginxTokenRoot` in `servers.py`) and their configs
    (`nginx_resilience_tls_anon.conf`, `nginx_resilience_token.conf`).
    - **Download-side sweep** (`test_download_loss_sweep.py`, 14 cases over both
      the WebDAV and S3 planes). Every HTTP-family fault test in the folder had
      injected on the UPLOAD leg only. Measured: loss and truncation are always
      surfaced as a client-side failure — never a silent 200 with a short body —
      while a length-preserving bit flip arrives with a clean 200 on both planes.
      A truncation point armed beyond a Range request does not disturb it.
    - **Finding — the S3 ETag is not an integrity token.** WebDAV answers
      `Want-Digest: md5|adler32|sha-256` with a real `Digest` over the object, so
      a corrupted download IS detectable. S3 has no digest channel at all, and
      `s3_etag()` (`src/protocols/s3/util.c:167`) is nginx's weak mtime+size
      ETag, not the object MD5 that the AWS contract promises for a single-part
      object — on PUT, GET, HEAD and in `ListBucketResult` alike. An S3 client
      that verifies a download the documented way is verifying nothing, and a
      same-size rewrite inside the same second is additionally invisible to a
      conditional GET. Pinned as a KNOWN EXPOSURE by
      `test_s3_etag_does_not_detect_corruption` (it fails the moment the ETag
      becomes digest-backed, so closing the gap has to be deliberate). Not fixed
      here: making the ETag a digest means hashing on the read path and changing
      an externally-visible identifier, which is a design decision, not test
      scope.
    - **TLS and token legs** (`test_tls_token_leg_sweep.py`, 10 cases). Measured:
      TLS turns the same length-preserving flip into a hard failure with nothing
      written — the direct contrast with the cleartext planes above, and the
      first evidence in the suite that the record layer earns its cost. A cut
      inside the handshake fails closed on both legs; a missing, expired or
      corrupted-in-flight token is refused and delivers nothing. A cut MID
      TRANSFER is transparently recovered — the client reconnects and the output
      is byte-exact, which on the token leg means it re-ran the ztn login.
    - **The four orphaned runners are collected** (`test_sweep_runners.py`, 16
      cases): each imports (bit-rot guard against `servers.py` drift), each
      accepts its documented arguments and exits 2 with a message on a bad one,
      and the three non-FUSE runners complete a 2 MiB / 1 level / 1 rep
      micro-sweep with every transfer byte-exact. `run_mount_sweep.py` is
      imported and argument-checked but not run: a wedged FUSE mount takes the
      whole fleet with it. Security-negative: every runner writes under a
      per-user `PREFIX`, so one user's sweep cannot clobber another's export
      tree — these servers run `brix_allow_write on`.
    - **Bug found by collecting them: `run_http_reorder.py` was dead.** It
      registers the lifecycle spec `resil-http-reorder`, which was never added to
      `fleet_lifecycle_ports.py`, so the runner aborted at startup with
      "lifecycle spec 'resil-http-reorder' has no fixed port". Being standalone
      is exactly why nobody noticed. Ledger entry added; the runner now completes
      4/4 client×server pairs.
17. ~~**Cache passthrough** on the S3 and CVMFS planes; a negative pinning
    root://-declines-passthrough.~~ — **RESOLVED 2026-08-05.**
    `tests/test_cache_passthrough_planes.py` (21 cases) over a new six-plane
    instance, `lc-cache-passthrough` /
    `tests/configs/nginx_lc_cache_passthrough.conf`: an S3 and a CVMFS plane
    with `brix_cache_passthrough on`, a byte-identical OFF control for each,
    and the `root://` stream plane with passthrough *configured*.

    Three objects sized against the two caps — the only geometry in which
    admission and passthrough disagree — give the grid (all measured, not
    assumed):

    | plane | `small` ≤ `max_object` | `mid` > `max_object`, ≤ `passthrough_max` | `huge` > both |
    |---|---|---|---|
    | S3 / CVMFS, passthrough **on** | 200, stored | **200, NOT stored** | 502 |
    | S3 / CVMFS, passthrough **off** | 200, stored | **502** | 502 |
    | `root://` stream | 200, stored | 200 | **200** |

    Three findings came out of building it:

    * **`allow_pt` is inherited by cvmfs, and the source said otherwise.** The
      comment at `sd_cache_fill.c:125` read "Other planes (root://, cvmfs)
      never opt in" — but `cvmfs/handler.c:198` calls
      `brix_http_cache_fill_if_needed`, the shared HTTP worker that sets
      `allow_pt = 1` (`http_cache_fill_worker.c:51`). cvmfs passes through
      today; the comment is corrected and now names the test that pins it.
    * **The cache tier is keyed by the canonical EXPORT root, not by the
      location.** `brix_vfs_backend_config_cache_store()` registers into the
      VFS backend registry under `root_canon`, so two locations that share an
      export root share ONE tier — last registration wins. A first draft of
      this config gave five fronts no `brix_export` at all; every one of them
      collapsed onto the stream plane's `/` anchor, and the passthrough-OFF
      control silently ran the ON policy. Each front now carries its own
      `brix_export`. (The same collapse is latent in
      `nginx_lc_cachemx.conf`, whose planes share `posix:{DATA_ROOT}` — it
      does not affect those tests, which assert metrics rather than store
      contents, but it is why a per-plane store directory there is not a
      per-plane store.)
    * **The stream plane's decline is not a refusal.** With `allow_pt = 0` the
      declined object is served by ordinary remote read-through, so
      "root:// refuses" would have been the wrong assertion. The
      discriminator is `huge`: it is over the passthrough *spool* cap, so any
      plane that actually ran the passthrough gate refuses it — the stream
      plane serves it, and its store still holds only the admitted object.

    Security-negatives pin that passthrough loosens the size policy and
    nothing else: a key outside the configured bucket stays `404
    NoSuchBucket`, a non-CAS URL on the cvmfs plane is still rejected by the
    grammar, and traversal is refused with passthrough enabled.
18. ~~**TLS × sendfile behavioural matrix** — {cleartext, TLS} × {GET, Range, HEAD}
    × {sendfile-capable, object backend}, replacing the source-marker guard for
    INVARIANT 2.~~ — **RESOLVED 2026-08-04.** `tests/test_tls_sendfile_matrix.py`
    (66 cases) over a new four-plane instance, `lc-tls-sendfile` /
    `tests/configs/nginx_lc_tls_sendfile.conf`: {cleartext, TLS} × {posix,
    pblock}.

    The vehicle is **pblock, because one backend takes both branches of the
    fork.** `sd_pblock_read_sendfile_fd()` lends the block-0 fd only for a range
    starting at offset 0 that fits inside one block and returns
    `NGX_INVALID_FILE` for anything spanning blocks, which is exactly the
    condition `file_serve.c:519` turns into `serve_send_memory_backed()`. So the
    same export serves a sub-block object zero-copy and a multi-block one
    memory-backed, with a posix export of identical bytes as the always-sendfile
    control — the four planes must return one octet stream, and that equality is
    the assertion the source-marker guard structurally could not make.

    Covered: whole-object GET on every plane; the four-way agreement assert;
    HEAD on the multi-block object (the length the memory-backed path computes
    rather than fstats); six Range windows chosen to land on named branches
    (inside block 0, exactly one block, crossing into block 1, straddling the
    0/1 boundary, starting in a later block, the short final block); suffix and
    open-ended ranges; 416 on all four planes; a range overrunning EOF clamped
    identically (sendfile stops at file size by itself, the memory-backed path
    has to clamp deliberately — a missing clamp would be pblock-only); traversal
    refused before a send path is chosen; and a 416 leaking no object prefix.

    Verified as real coverage rather than a silent posix fallback: a probe of
    `PB_ROOT` after a 300 KiB PUT shows five 64 KiB block files plus
    `catalog.db`, with byte-exact readback. The source-marker guard in
    `test_cross_protocol_shared_helpers_b.py` is left in place — it pins the
    code shape cheaply and now has behaviour behind it.

### P3+ — the structural fix

19. ~~**Introduce the parametrization layer.**~~ **RESOLVED 2026-08-05** —
    `tests/matrix_layer.py` (the `make_node(cell)` factory), a
    `pytest_generate_tests` hook plus a module-scoped `matrix_node` fixture in
    `tests/conftest.py`, two generic templates
    (`configs/nginx_matrix_{stream,http}.conf`), and
    `tests/test_matrix_layer.py` as both demonstrator and regression test —
    **63 passed / 39 skipped in 15 s**, four test bodies covering 28 reachable
    cells. Ledger: `lc-matrix-node` 31240, `lc-matrix-origin` 31241 (two names
    for the whole matrix — one cell runs at a time under
    `xdist_group("lc-matrix")`).
    - A test now reads `@pytest.mark.matrix(protocols=[…], auths=[…], tls=[…],
      backends=[…])` and takes the `matrix_node` fixture; `Node.seed()` /
      `Node.read()` hide the per-protocol client (xrdcp with `X509_USER_PROXY`
      or `BEARER_TOKEN`, urllib with a bearer, a client certificate, or SigV4
      headers), so one body runs against every cell. Adding a backend to
      `matrix_layer.BACKENDS` adds it to every matrix test at once — which is
      the property whose absence made the matrix re-sparsify.
    - **Unreachable cells are parametrized, not filtered.** `supported()` is the
      single place that says why a combination cannot exist, and an impossible
      cell shows up as a skip carrying that reason: *S3 authenticates with SigV4,
      never a bearer* (INVARIANT 6); *XrdCl refuses to put a token on a cleartext
      wire*; *WebDAV GSI is a client certificate, which requires TLS*. §3's
      complaint was that an empty cell and an impossible cell looked identical
      from outside; now they don't.
    - Two constraints the generic renderer surfaced, both now encoded: a stream
      GSI plane already names the service certificate, so adding `brix_tls on`
      must NOT re-emit it (`[emerg] "brix_certificate" directive is duplicate`);
      and a remote-backed S3 front still needs its own `brix_export`, without
      which every key is answered `NoSuchKey` before the backend is dialled.
    - TRAP re-confirmed the hard way: **a template comment that quotes its own
      `{PLACEHOLDER}` gets substituted**, and a multi-line block then lands at
      main scope — the `[emerg]` points at the comment. Both new templates name
      their placeholders without braces and say why.

    Original text: Generalize
    `_cache_partial_helpers.make_cache_node` into a
    `make_node(protocol, auth, tls, backend)` spec factory plus either an
    `indirect=True` fixture or a `pytest_generate_tests` hook in `conftest.py`
    (beside the marker registration at L618-626). Templates need `{AUTH}`-style
    placeholders — `nginx_lc_cachemx.conf` already proves the mechanism, and is
    currently the only file using it. Without this, every cell above stays a
    hand-written module and the matrix re-sparsifies with the next backend added.

Also worth folding in while touching the harness:

- ~~**`TEST_CROSS_BACKEND` is nearly vestigial**~~ — 6 modules import
  `backend_matrix.py`, two more duplicate its logic inline, and **nothing in
  `tests/`, `Makefile`, or `.github/` ever sets it**; the only both-backends
  sweep is a bash loop in `k8s-tests/remote-suite/`. A default `pytest tests/`
  run exercises the nginx side only. Zero cross-implementation parity exists for
  S3, WebDAV TPC/COPY, WLCG tokens, GSI/VOMS/CRL, krb5/sss/pwd, CMS clustering,
  cache tiers, checksums, IPv6, proxy mode, or metrics exposition.

  > **CLOSED 2026-08-05.** The diagnosis was right but the cause was narrower
  > than "the axis is unused": `selected_backend_name()` is a **process-wide**
  > switch that the six modules bind to endpoint constants at *import* time, so
  > covering both implementations structurally required two `pytest` invocations
  > — and nothing ever launched the second one.
  >
  > Both servers were reachable the whole time. `fleet_specs.core_specs()` gives
  > `main` (nginx) and `ref-anon` (stock `/usr/bin/xrootd`) the *same*
  > `_data("data")` export, and both are always-on backbone, so neither needs a
  > `registry_server` declaration and both boot on every run. The fix is
  > therefore to resolve the backend **per test** rather than per process:
  > `backend_matrix.BACKENDS` + `anon_url(backend)`, driven by
  > `tests/test_cross_backend_parity.py` — one seeded file, two servers, one
  > expected answer, in one ordinary run. It asserts only what both
  > implementations must agree on (byte-exact read, identical `stat` size, an
  > absent path erroring rather than answering an empty body, and a traversal
  > escaping neither export, judged on content) so an implementation difference
  > surfaces as a failure rather than a skip.
  >
  > `TEST_CROSS_BACKEND` is left in place and still documented: the two-run form
  > is the right tool for sweeping a *whole existing module* against stock, which
  > is what `cmdscripts/official_interop.py` does. What changed is that parity is
  > no longer contingent on someone remembering to set it.
  >
  > Still open from this bullet: the per-subsystem parity list (S3, WebDAV
  > TPC/COPY, tokens, GSI/VOMS/CRL, ~~krb5/sss/pwd~~, ~~CMS~~, cache tiers,
  > checksums, IPv6, proxy mode, metrics exposition) — the parity probe covers
  > the root:// read/stat/absent/traversal contract, not those.
  >
  > > **CMS CLOSED 2026-08-05** (phase-97). The clustering half needed a
  > > different lever than `backend_matrix`: a manager is not an endpoint the
  > > per-test switch can swap, it is a *topology*. `cms_mesh_lib` already ran
  > > two meshes that differ in exactly one variable — `b` (BriX manager + real
  > > data node) and `bl` (real `cmsd` manager + real data node) — so
  > > `tests/test_cms_cross_impl_parity.py` seeds byte-identical content into
  > > both export roots (not through a manager: a write-path difference would
  > > contaminate the read comparison) and drives both front doors with the same
  > > `xrdfs`/`xrdcp`. Locate, stat size, byte-exact read, `ls`, an absent path,
  > > and a traversal are asserted to agree across implementations, so a
  > > divergence is a failure and not a skip. 6/6 green against a live mesh.
  > >
  > > Applying this audit's own method (declared-but-never-driven cells) to CNS
  > > while there also surfaced two **product** gaps no test had reached:
  > > `kXR_mv` and path-based `kXR_truncate` emitted no namespace event at all,
  > > so a manager served the pre-rename path and the pre-truncate size forever.
  > > Both are fixed and covered — see
  > > `docs/refactor/phase-97-cms-cns-coverage-closure.md`.
- **Dead fleet specs** — `upstream-gotorls-notls(+-be)`, `stub-upstream-redirect`,
  `stub-upstream-error`, `interop-off` have zero references; `token-multikey`,
  `token-registry`, `proxy-dead` are reached only by port constant. ~~**54
  templates are unreferenced**~~, several being pre-lifecycle duplicates whose
  `nginx_lc_*` twin is live (`nginx_native_sss.conf` and `nginx_pwd_auth.conf`
  are dead while their `_lc_` twins are used) — the sss/pwd axis was migrated
  *out* of the fleet, not into it, which is why no session endpoint offers them.

  > **RATCHETED 2026-08-05.** The dead-template half is now frozen rather than
  > growing. `tools/ci/check_template_refs.py` fails on any *new* `tests/configs/*.conf`
  > that nothing in the repo names, and equally on a backlog entry that has since
  > been wired up or deleted — so the frozen count can only fall. The seed is
  > **49** entries in `tools/ci/template_refs_backlog.txt` (the audit's 54 counted
  > with a narrower scan; this guard also credits a mention from `docs/`,
  > `k8s-tests/` and the CI tooling, which is the honest definition of "something
  > names it"). `--regen` is deliberately shrink-only: it refuses and exits 1 if
  > regenerating would *add* an entry, which is the only way a ratchet quietly
  > stops ratcheting.
  >
  > The 49 files are **not deleted**. Deletion is destructive and irreversible
  > here in a way the ratchet is not: a template can be named at runtime by an
  > f-string, which no static scan sees, so the backlog is an allowlist rather
  > than a delete-list. Burn one down by wiring it to a test or removing it, then
  > `tools/ci/check_template_refs.py --regen`.
  >
  > Registered in `tests/test_ci_guards.py::_FAST`, `.github/workflows/guards.yml`
  > and the `tools/ci/README.md` table. Three negatives pin it: a new dead
  > template reddens, `--regen` refuses to bless one (and leaves the backlog
  > byte-identical), and a backlog entry that becomes referenced reddens too.
  >
  > TRAP for whoever writes the next negative: `tests/test_ci_guards.py` is
  > itself inside the tree the guard greps, so a probe filename written out as a
  > literal in the test *is* a reference and the probe reads as live. The probe
  > names are assembled from a stem plus `".conf"` for exactly that reason —
  > which is the guard working, not a flaw in it.
  >
  > **CLOSED 2026-08-05 — the dead *specs* half.** Resolved one spec at a time,
  > because the four had three different causes and only one was "nobody wrote
  > the test".
  >
  > `stub-upstream-redirect` (11130→13120) and `stub-upstream-error`
  > (11133→13123) were nginx fronts pointing at ports **nothing listened on**:
  > `tests/upstream_protocol_stubs.py::main()` started five threads and had no
  > `_handle_redirect` and no `_handle_error`. Both handlers now exist, with the
  > expected payloads stated once as module constants (`REDIRECT_TARGET_HOST`,
  > `REDIRECT_TARGET_PORT`, `ERROR_CODE`, `ERROR_MESSAGE`) and imported by the
  > tests rather than duplicated as literals. Four tests in
  > `tests/test_a_upstream_redirect.py` drive them: the redirect target survives
  > the proxy host-and-port exact; the error survives code-and-message exact;
  > and two security negatives — a forwarded redirect must never name the front
  > or the private backend (redirect loop / topology disclosure), and forwarded
  > error text must never have the upstream endpoint appended to it.
  >
  > These are not duplicates of the real-backend tests above them. A real
  > xrootd picks its own redirect target and its own error code, so
  > `test_locate_redirected` and `test_upstream_error_forwarded` can only assert
  > the response *kind*. The stub emits bytes this repo chose — including
  > `kXR_NotAuthorized`, a code no missing path produces — so a proxy that
  > rewrote a redirect or synthesised its own error fails here and only here.
  >
  > **`upstream-gotorls-notls(+-be)` is unreachable by construction, and that is
  > now a test rather than an absence.** `brix_upstream_build_bootstrap()`
  > (`src/net/upstream/bootstrap.c`) sends the cleartext `kXR_protocol` request
  > with `protocol_flags = 0`; an XRootD server answers `kXR_gotoTLS` only to a
  > client that advertised `kXR_ableTLS`, which on this codebase is the manager
  > health-check leg alone. A real backend therefore *cannot* drive the
  > gotoTLS-with-`brix_upstream_tls off` abort — which is exactly why the stub
  > twin `stub-upstream-gotorls` exists. Per this audit's own "check
  > reachability before calling any empty cell a gap" rule the pair is not a
  > gap; `test_a_real_upstream_never_forces_tls_on_the_cleartext_leg` pins the
  > reason by asserting the *absence* of the abort, so if a future change ever
  > advertises `kXR_ableTLS` on the ordinary upstream leg the test flips and
  > says so.
  >
  > **A live bug fell out of this.** None of the seven `stub-upstream-*` fronts
  > declared `requires=("upstream-stubs",)`. Under the zero-boot gate a
  > `registry_server` marker boots only the dependency closure, so the stub
  > process never started and each front answered every locate with `kXR_error`
  > — which reads as "the proxy forwarded an error" and passed the loose
  > assertions. `test_locate_wait_then_redirect` was **failing outright**
  > (`4003 != 4004`) before the fix. All seven specs now name the stub;
  > `tests/test_a_upstream_redirect.py` is 12/12 green.
  >
  > `interop-off`, `token-multikey`, `token-registry` and `proxy-dead` need no
  > work: each is reached by port constant (`token-multikey` via
  > `NGINX_TOKEN_MULTIKEY_PORT` from the three WLCG multikey/alg/edge modules),
  > which is a declared reference the gate honours.
  >
  > Nothing is left open from this bullet.

---

## 8. Provenance and caveats

- §2.1 was **verified by running the test**; §2.2 by **direct code read** of
  `tpc.c`, `tpc_push.c`, `tpc_thread.c`, `tpc_curl_setup.c`, `launch_prepare.c`
  and a repo-wide grep for `brix_tpc_source_guard_check` callers.
- §§3-6 come from five parallel read-only sweeps. Every gap was checked for
  *reachability* in `src/` before being listed, and unreachable combinations are
  called out as N/R rather than silently dropped. They are **not** execution-verified:
  a cell listed as untested means no test was found by name, config-content, and
  call-graph search — confidence is high but not absolute for a suite this size.
- Counts (`0` for `pytest_generate_tests`/`indirect=True`, 299 spec
  constructions, 126 fleet specs, 54 unreferenced templates — the last now
  ratcheted at 49 by `check_template_refs.py`, which scans wider) are grep-derived and
  reproducible.
- This audit deliberately says nothing about *failing* tests except where a
  failure is itself the coverage finding (§2.1). For failure triage see
  `testsuite-state-2026-07-28.md`.
