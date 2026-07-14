# Phase-80 — S3-backend forwarding closure (findings from the MinIO labs)

**Goal:** turn the two 2026-07-14 MinIO lab scenarios (`s3fwd`, `s3gsi`) from
"exploration that found the edges" into a fully-working, uniformly-credentialed
S3 storage plane: fix the stream credential-replay wipe (a drift bug between
three hand-copied mappers), wire root:// writes to object backends, close the
per-user write-attribution gap, and make unsupported namespace ops fail
honestly. **Brix source was deliberately untouched during the labs** — every
finding below is reproducible by the committed tests before any fix lands.

---

## 0. What was built (the labs — already landed, keep green)

| Piece | Where | What it proves |
|---|---|---|
| MinIO docker harness | `tests/minio_harness.sh` (idempotent `start\|stop\|status\|env`, port 29000, health-gated) | known-working S3 backend on demand |
| WebDAV→S3 forwarding suite | `tests/test_minio_s3_forward.py` (5/5 PASS local) | upload+download through brix to MinIO byte-exact; wrong-secret rejected (credential is load-bearing); ENOENT→404 |
| root://+GSI multi-user suite | `tests/test_s3gsi_multiuser.py` (11 PASS / 9 FAIL / 4 XFAIL / 1 XPASS) | per-DN authdb isolation + per-user `.s3` selection work; positive-path storage ops blocked by bug 1.1 |
| k8s charts | `k8s-tests/charts/s3-forward` (MinIO + WebDAV role), `k8s-tests/charts/s3-gsi` (MinIO + mc provision job + PKI bootstrap job + stream GSI role, 2 lanes: fallback allow/deny) | in-cluster reproduction: `./xrd-lab test s3fwd` / `test s3gsi` |
| Role configs | `k8s-tests/charts/topology-role/configs/s3_minio_forward.conf`, `s3_gsi_multiuser.conf` | the exact working (and deliberately-degraded) config postures |

**Two design patterns worth reusing everywhere:**

1. **Layer fault-attribution.** Every brix-side assertion re-probes the backend
   directly (stdlib SigV4 — boto3/aws4auth are NOT in the test env) and fails
   as `[backend]` (MinIO broken, not brix) vs `[brix-machinery]` (backend
   proven healthy, forwarding path at fault). A test failure names the guilty
   layer without instrumentation.
2. **External credential attribution.** MinIO policy scoping makes "which
   credential did brix sign with" observable from outside: atlas keys are
   denied on `cms/*` and on `PutObject atlas/wprobe/*`, the service credential
   is not. Reads/writes landing where only one credential could reach is an
   unforgeable attribution oracle — no server instrumentation, no log parsing.

---

## 1. Verified findings (file:line anchors checked 2026-07-14)

### 1.1 KILLER BUG — stream worker credential replay wipes S3 keys

Three hand-copied `brix_credential_t → brix_vfs_backend_cred_t` mappers exist:

| Site | Maps s3_ak/sk/region? | bearer? |
|---|---|---|
| WebDAV parse-time — `src/protocols/webdav/config_merge.c:218` (`webdav_set_storage_credential`) | yes | yes |
| stream parse-time — `src/core/config/runtime_server.c:94-107` | yes | yes |
| **stream worker replay — `src/core/config/process_server_init.c:63-96`** (`brix_init_server_backend_credential`, called from worker init at `:344`) | **NO** | **NO** |

`brix_vfs_backend_set_credential` (`src/fs/vfs/vfs_backend_config.c:64`) treats
NULL fields as "clear to empty", so the worker replay CLOBBERS the parse-time
S3 keys with `""` → every stream-plane S3 request signs
`Credential=/date/...` (empty access key, proven live via `mc admin trace`) →
403 on everything. This is why `s3_gsi_multiuser.conf` carries the deliberate
"NO `brix_storage_credential`" posture (anonymous + per-user `.s3` `open_cred`
is the only working stream configuration today). The WebDAV plane doesn't
replay, which is why the `s3fwd` suite passes.

**Root cause class: copy-drift between three mappers, not a one-line typo.**

### 1.2 root:// writes to an s3:// primary are not wired

- `brix_upload_resume on` (default): the resume engine stages to a LOCAL
  `.part` and commits by LOCAL rename (close.c POSC path) — bypasses the VFS
  staged seam entirely → commit EIO, bytes never reach MinIO.
- `brix_upload_resume off`: plain open-for-write requires `CAP_RANDOM_WRITE`,
  which `sd_remote` honestly does not advertise (`sd_remote.c:372-374`) →
  EROFS → kXR 3007 at open.
- The working path — `sd_remote.staged_open/write/commit` delegating to
  `sd_s3_write.c` single-PUT/multipart — is only driven by the HTTP plane
  (WebDAV PUT via `vfs_staged.c`; `brix_webdav_storage_staging` has no stream
  equivalent).

### 1.3 Per-user write attribution gap (predicted, then confirmed by XPASS/XFAIL)

`sd_remote` has `.open_cred` (per-user SigV4 reads, phase-3 T3,
`sd_remote.c:146-180`) but **no `staged_open_cred` / `stat_cred` /
`unlink_cred`** — writes and metadata sign with the static service credential
even when the user has their own `.s3`. Compare `sd_http`, which already has
`.staged_open_cred` (`sd_http.c:45`).

**Precision note on the live evidence:** the s3gsi wprobe test XPASSed, but
for a masked reason — 1.1 empties the service credential too, so the probe
write failed at MinIO with *anonymous* signing, not with atlas keys.
`mc admin trace` showed ZERO brix-originated requests carrying a per-user key
(reads died at the anonymous open-flow HEAD before `open_cred` ever signed a
GET). So 1.3 is code-verified but **not yet live-verified**; the wprobe oracle
only becomes meaningful after P80.1 lands. Same masking applies to the
deny-lane nuance: with `fallback_deny` and a VALID `.s3`, writes/stat/unlink
EACCES anyway because the `*_maybe_cred` forwarders (sd.h) refuse when the
leaf lacks the matching `_cred` slot — a valid credential that cannot be
honored is treated as deny, never as silent service-cred fallback (correct
posture, surprising UX; P80.3 removes the trigger).

### 1.4 Namespace ops on s3:// error dishonestly

`sd_remote` has no dirlist/mkdir/rename slots; the resulting ENOTSUP/ENOSYS
falls through the root:// errno mapping to **kXR_IOError** instead of a clean
kXR_Unsupported — users see "I/O error" for "this backend can't do that".

### 1.5 authz/gate path mismatch without `brix_export`

With an s3 plane and no export root, the gate checks `root_canon+wire` =
`//atlas/...` while authdb rules canonicalize (realpath) to `/atlas/...` —
nothing matches, all ops die `3010 authdb denied`. Setting `brix_export
<real-local-dir>` aligns both sides. Works, but is a silent foot-gun.

Two sub-findings from the debugging ladder:

- Doubling the rules (`//atlas/...`) in the authdb file does NOT work around
  it: `brix_finalize_path_rules` (`src/fs/path/helpers.c:122`) realpath-
  canonicalizes every rule at load, collapsing `//` back to `/`. The mismatch
  is strictly gate-input-side.
- **Open question for P80.1 verification:** whether request-path resolution on
  the s3 plane needs local *skeleton directories* under `brix_export`
  (`/data/xrootd/atlas/bob/...`). The lab created them mid-debug and it made
  no difference, but that observation is confounded by 1.1 (everything was
  failing on credentials). Retest with creds fixed; if skeleton dirs turn out
  to be required, that's a second foot-gun for P80.5 to guard (or the resolve
  should go no-exist-tolerant for origin-scheme backends).

### 1.6 Stale "read-only" comments (contradicted by the passing upload test)

`vfs_backend_config_s3.c:28`, `sd_remote.c:372-373`, and the registry comment
(`vfs_backend_registry.h` — already flagged in phase-71 §0) all say "S3
primary is read-only"; what's true is "no RANDOM pwrite — whole-object staged
PUT works". Misleads exactly the way phase-71 warned about.

### 1.7 k8s ucred gotcha — `O_NOFOLLOW` vs secret mounts

k8s secret/configmap mounts are `..data/` symlink farms; the (correct,
mandatory) `O_NOFOLLOW` credfile hardening in `ucred.c` reads them as
"credential missing". Worked around in `topology-role`: `role.auth.extraSecret`
runs an `extra-init` initContainer that `cp -rL`s into an emptyDir. This is an
ops-docs matter, NOT a reason to weaken the hardening.

---

## 2. The plan

### P80.1 — ONE credential mapper (fixes 1.1 as a class) — S, do first

Add `brix_credential_to_backend_cred(const brix_credential_t *, char *bearer_buf,
size_t, brix_vfs_backend_cred_t *out, ngx_log_t *)` to
`src/core/config/credential_block.c` (it owns the struct; the bearer resolve
`brix_credential_bearer` already lives there). Replace all three copies
(config_merge.c:218 / runtime_server.c:94 / process_server_init.c:63) with
calls to it. The replay site then maps s3_ak/sk/region + bearer by
construction — drift is impossible, not just fixed.
**Verify:** re-run `./xrd-lab test s3gsi` with `brix_storage_credential svc`
restored in `s3_gsi_multiuser.conf` (drop the workaround comment) — the 9
positive-path FAILs must flip to PASS. Add a stream-plane static-S3-credential
regression to `tests/test_minio_s3_forward.py` (root:// front on the same
MinIO) so the WebDAV/stream asymmetry can never silently return. 3 tests:
success (stream read with static cred) + error (bad cred 403) + security-neg
(cred must not leak into logs).

### P80.2 — root:// staged writes to object backends (fixes 1.2) — M

Mirror the phase "writable remote root://" playbook (sd_xroot got this
exactly): when the primary backend lacks `CAP_RANDOM_WRITE` but has
`staged_open`, route stream open-for-write through the VFS staged seam
(`vfs_staged.c`) instead of rejecting EROFS, and make the close/POSC commit
drive `staged_commit` instead of local rename. Gate `brix_upload_resume` off
(or transparently divert it) for staged-only backends — a config that silently
EIOs at commit is not acceptable. Capability-driven per phase-71: branch on
caps bits, never on `backend == s3`.
**Verify:** s3gsi xfail write tests flip; add root://-plane upload/download to
the s3fwd local suite (xrdcp against the MinIO-backed stream server).

### P80.3 — per-user credentials for writes + metadata (fixes 1.3) — S/M

Add `.staged_open_cred` to `sd_remote` (parametrize the existing
`sd_remote_staged_open` by cred exactly as `sd_remote_open_cred` does for
reads; `sd_http.c:45` is the template), plus `.stat_cred`/`.unlink_cred` while
there. **Verify:** the s3gsi write-attribution XFAIL (bob writing
`atlas/wprobe/*` must now FAIL — atlas keys are policy-denied there) flips to
its hard form; the suite's attribution oracle does the proving.

### P80.4 — honest kXR_Unsupported for missing namespace ops (fixes 1.4) — S

In the root:// errno→kXR mapping, send ENOTSUP/ENOSYS/EOPNOTSUPP to
`kXR_Unsupported` instead of falling through to `kXR_IOError`; have VFS
namespace wrappers return ENOTSUP (not EIO) when the driver slot is NULL.
Optional follow-on (separate, M): real `dirlist` on `sd_remote` via
ListObjectsV2 (`sd_s3_meta.c` already speaks the XML) — decide after P80.2.

### P80.5 — config-time guardrails (fixes 1.5's foot-gun) — S

At merge time, when `brix_storage_backend` is an origin-scheme (s3/http/xroot)
and authz rules are configured (`brix_authdb`/ACL) but `brix_export` is unset,
emit a config ERROR naming the `//path` vs `/path` mismatch (or synthesize a
canonical export root). A silent everything-denied server is the worst outcome
the lab hit.

### P80.6 — truth in comments + docs — S

- Reword `vfs_backend_config_s3.c:28`, `sd_remote.c:372-373`, and the
  registry comment to "no random pwrite; writes are staged whole-object PUTs"
  (coordinate with phase-71 §0's same item).
- New ops doc `docs/05-operations/s3-backend.md`: supported matrix per plane
  (WebDAV/S3-front/root://), credential postures (static / per-user dir /
  fallback allow-deny), the `brix_upload_resume off` requirement until P80.2,
  the k8s secret-mount `cp -rL` pattern (1.7), and the attribution-test
  pattern for operators debugging "is it my backend or the gateway".

### P80.7 — CI wiring — S

Add `tests/test_minio_s3_forward.py` to the docker-gated test tier (it
self-skips without docker, so `--fast`/`--pr` stay clean); keep
`./xrd-lab test s3fwd` and `test s3gsi` in the k8s lab rotation. After P80.1
lands, the s3gsi suite's xfail/hard split is the regression net for
P80.2/P80.3 — re-tighten (xfail→hard) as each phase closes its gap.

---

## 3. Order & effort

P80.1 (S, unblocks 9 failing tests, kills the drift class) → P80.4 + P80.5 +
P80.6 (each S, independent) → P80.2 (M, the real feature) → P80.3 (S/M, needs
P80.2 for write-path testing) → P80.7 alongside each. Lab-side P80.8-P80.10
(appendix §4) ride along: P80.8 immediately after P80.1, the rest opportunistic.

## 4. Appendix — lab/test-infra learnings (k8s-tests side, landed with the s3gsi chart)

Everything below is already in the tree (chart `k8s-tests/charts/s3-gsi`,
`topology-role` extensions, `labtools` wiring) — recorded here so the patterns
get REUSED, plus three small follow-ups.

**Patterns that worked and should be the default for future scenarios:**

- **DN-derived provisioning, correct by construction.** The PKI bootstrap job
  mints the user proxies FIRST, then generates every DN-dependent artifact
  (authdb `u <DN>` rules, `x5h-<sha256(DN)[:32]>.s3` filenames — byte-matched
  to `ucred.c`'s `brix_sd_ucred_key`) from the ACTUAL proxy leaf DN
  (`openssl x509 -noout -subject -nameopt compat` = `X509_NAME_oneline` form).
  No guessing about proxy-CN suffixes: `utils/make_proxy.py` uses a fixed
  serial (`/CN=12346`), so DNs are deterministic, but deriving from the minted
  artifact makes the scenario immune to that ever changing.
- **`role.auth.extraSecret`** (topology-role): generic per-role file delivery
  (authdb + credential dirs) via a Secret, dereferenced through the
  `extra-init` initContainer (`cp -rL` into an emptyDir) because k8s secret
  mounts are `..data/` symlink farms that `O_NOFOLLOW` consumers refuse.
  Any future role needing server-side files should reuse this instead of
  inventing a mount.
- **Fixed, release-independent published object names** (`s3gsi-pki`,
  `s3gsi-ca-bundle`, `s3gsi-server-extra`, `s3gsi-jwks`): sidesteps the
  values-can't-see-Release.Name problem that otherwise forces
  release-name-coupled values files.
- **Per-VO MinIO users via `mc admin` post-install Job** with prefix-scoped
  policies + deliberate deny-traps (`atlas/wprobe/*` PutObject deny, cms-only
  canary) = the external attribution oracle described in §0.

**Gotchas (cost real time; check these first next time):**

- The `brix-client` runner image has NO local nginx — any suite driven through
  `charts/test-runner` with that image must set
  `testRunner.env.TEST_SKIP_SERVER_SETUP=1` or conftest's
  `manage_test_servers.sh start-all` INTERNALERRORs the whole session.
  (`s3fwd` dodges this only because it uses the `brix-test-runner` image.)
- `lab_suite._collect` uninstalls the releases after every `xrd-lab test` run
  — debug by re-installing manually (`helm upgrade --install sg charts/s3-gsi
  …` + the runner) and keep the releases alive; recreate the runner Job with
  `kubectl delete job run-test-runner && helm upgrade run … --reuse-values`.
- In-pod nginx reload needs the conf path: `nginx -s reload -c
  /etc/brix/nginx.conf` (pid-file lives per-conf, not at the default).
- Config-parse `NOTICE`s (e.g. the "backend credential … for …" line that
  would have shortcut 1.1 by a few hours) never reach `error.log` — the known
  parse-time-log gap; don't rely on them for in-cluster debugging. `mc admin
  trace -v --all` against MinIO is the fastest ground truth for "what did brix
  actually sign/send".
- Lab image staleness: `brix-server:dev` etc. must be rebuilt after brix
  commits (`lab.plan_images(profile)` + `minikube image load`); the 07-05
  images silently lacked the whole per-user-credential machinery.

**Follow-ups (small, lab-side):**

- **P80.8 (S):** register the s3gsi suite in `k8s-tests/TEST_REGISTRY.md` +
  README scenario table; after P80.1 restores the static credential, drop the
  "deliberately NO brix_storage_credential" posture from
  `s3_gsi_multiuser.conf` and re-tighten the suite per P80.7.
- **P80.9 (S):** consider promoting `TEST_SKIP_SERVER_SETUP=1` into the
  test-runner chart as a values flag tied to the client image choice, so the
  next scenario author can't hit the conftest trap.
- **P80.10 (S):** VOMS lane — the scenario encodes VO membership at
  provisioning time (per-user `.s3` content). A faithful `brix_require_vo`
  tier needs in-cluster VOMS AC proxies (`voms_proxy_fake.py`) + vomsdir LSC
  in the bootstrap job + `libvomsapi` in the server image; today VOMS is
  local-suite-only (`test_vo_acl.py` is `# brix-remote-skip`). Decide whether
  the s3gsi lab should grow that lane after P80.1-P80.3 land.

## 5. Non-goals

- Making s3:// a random-write (`pwrite`) backend — object stores don't do
  that; staged whole-object is the correct contract.
- Weakening `O_NOFOLLOW` credfile hardening for k8s convenience (1.7 stays an
  init-container concern).
- S3-front → S3-backend passthrough of the CLIENT's SigV4 (signature covers
  host — cannot be replayed upstream; per-user re-signing via `.s3` files is
  the design, already working for reads).
