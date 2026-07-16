# Phase-80 — S3-backend forwarding closure (findings from the MinIO labs)

**Goal:** turn the two 2026-07-14 MinIO lab scenarios (`s3fwd`, `s3gsi`) from
"exploration that found the edges" into a fully-working, uniformly-credentialed
S3 storage plane: fix the stream credential-replay wipe (a drift bug between
FOUR hand-copied mappers — see 1.1), close the residual root://-write gaps
(the staged route itself is in-tree — see the 1.2 revision), close the
per-user write-attribution gap, and make unsupported namespace ops fail
honestly. **Brix source was deliberately untouched during the labs** — every
finding below is reproducible by the committed tests before any fix lands.

**Provenance & verification status:** findings originally anchored 2026-07-14;
every file:line anchor in this document was **re-verified against the tree on
2026-07-16** (post `bff6bf92`). Drifts found during re-verification are marked
`DRIFT:` inline and folded into the plan. The two biggest revisions vs the
07-14 draft: (a) there are FOUR credential mappers, not three — the S3-front
parse-time mapper at `src/protocols/s3/module_merge.c:189` was missed; (b) the
stream plane ALREADY routes open-for-write through the VFS staged seam when
the backend lacks `CAP_RANDOM_WRITE` — finding 1.2 is rewritten to the actual
residual gaps.

**Implementation status (2026-07-16):** the in-scope plan (P80.1–P80.7) is
LANDED; the stretch goals (P80.11–P80.14, P80.21–P80.25) remain open.

- **P80.1** unified credential mapper — done (stream replay wipe fixed).
- **P80.4** honest `kXR_Unsupported` mapping (ENOTSUP/ENOSYS→3013) — done.
- **P80.5** config-time origin-backend guardrail — done
  (`tests/test_p805_remote_authz_guard.py`).
- **P80.6** truth in comments + `docs/05-operations/s3-backend.md` — done.
- **P80.2** staged-write residue — done: resume divert, lazy single-PUT with
  mid-stream MPU upgrade (`sd_s3_write.c`), noreplace HEAD-before-publish in
  `sd_remote_staged_commit`, plus a production fix the security-negative test
  exposed: `s3put_ensure_parent_dirs` (put_inner.c) now skips prefix creation
  when the leaf lacks `CAP_DIRS_WRITE` (virtual prefixes on object stores —
  the phase-71 caps gate was turning every first S3-front PUT into a 403).
  `TestStagedWriteResidue` in the MinIO suite covers all three.
- **P80.3** per-user credentials for writes + metadata — done: sd_remote
  registers `staged_open_cred`/`stat_cred`/`unlink_cred` (shared
  `sd_remote_cred_gate`, per-user triple carried into the staged state so the
  noreplace probe presents the upload's identity; `stat_cred` also flips on
  `brix_vfs_ns_cred()` for the driver). `TestPerUserWriteCredential`
  (pwd-auth lane, wrong static secret, fallback deny) covers
  success/error/security-negative.
- **P80.7** CI wiring — done: `test_minio_s3_forward.py` is `serial`-marked
  (fixed MinIO port + shared container stay out of the xdist pool; self-skips
  without docker so `--fast`/`--pr` stay clean), the s3gsi suite's two
  P80.3-closed xfails (`XFAIL_WRITE_CRED`, `XFAIL_DENY_WRITE`) are re-tightened
  to hard requirements, and `./xrd-lab test s3fwd`/`s3gsi` remain in rotation.
  MinIO suite: 14/14 local.

---

## 0. What was built (the labs — already landed, keep green)

> **DRIFT (paths):** the lab suites live under `k8s-tests/remote-suite/tests/`,
> NOT the top-level `tests/` tree (the 07-14 draft implied otherwise). The
> top-level `tests/` is the native/local tier; per the tests_k8s split, all
> container/cluster material stays under `k8s-tests/`.

| Piece | Where | What it proves |
|---|---|---|
| MinIO docker harness | `k8s-tests/remote-suite/tests/minio_harness.sh` | known-working S3 backend on demand |
| WebDAV→S3 forwarding suite | `k8s-tests/remote-suite/tests/test_minio_s3_forward.py` (5/5 PASS local) | upload+download through brix to MinIO byte-exact; wrong-secret rejected (credential is load-bearing); ENOENT→404 |
| root://+GSI multi-user suite | `k8s-tests/remote-suite/tests/test_s3gsi_multiuser.py` (11 PASS / 9 FAIL / 4 XFAIL / 1 XPASS on 2026-07-14) | per-DN authdb isolation + per-user `.s3` selection work; positive-path storage ops blocked by bug 1.1 |
| k8s charts | `k8s-tests/charts/s3-forward`, `k8s-tests/charts/s3-gsi` | in-cluster reproduction: `./xrd-lab test s3fwd` / `test s3gsi` |
| Role configs | `k8s-tests/charts/topology-role/configs/s3_minio_forward.conf`, `s3_gsi_multiuser.conf` | the exact working (and deliberately-degraded) config postures |

### 0.1 `minio_harness.sh` — docker-managed MinIO (79 lines)

Subcommands `start|stop|status|env`, modeled on `ceph_harness.sh`. Idempotent
`start`: a running+healthy container is reused; running-but-unhealthy is
`docker rm -f`'d and recreated. Health gate = `curl -sf --max-time 2` against
`/minio/health/ready`, polled 30×1s. Exit code **3** = docker unavailable
(tests treat as skip); **2** = start/health failure. Bucket creation is NOT
the harness's job — the tests do it via signed SigV4 (no `mc` dependency).

| Env var | Default |
|---|---|
| `MINIO_CONTAINER` | `brix-test-minio` |
| `MINIO_IMAGE` | `minio/minio:latest` |
| `MINIO_PORT` | `29000` (host, loopback-only publish → container 9000) |
| `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` | `minioadmin` / `minioadmin` |

Run command: `docker run -d --name brix-test-minio -p 127.0.0.1:${MINIO_PORT}:9000 -e MINIO_ROOT_USER -e MINIO_ROOT_PASSWORD minio/minio:latest server /data`.

### 0.2 `test_minio_s3_forward.py` (360 lines) — WebDAV→S3 forwarding

Topology: `client → HTTP PUT/GET → brix (WebDAV front, brix_storage_backend
s3://minio/brixfwd) → signed S3 → MinIO`. Local mode writes an inline nginx
conf (`_fwd_conf`) and launches `NGINX_BIN` (default
`/tmp/nginx-1.28.3/objs/nginx`, override `TEST_NGINX_BIN`; see
`remote-suite/tests/settings.py:106`). Remote mode is selected by
`TEST_MINIO_HOST` presence and reads `TEST_S3FWD_HOST`/`TEST_S3FWD_PORT`.
Load-bearing directives: `brix_credential minio { s3_access_key / s3_secret_key
/ s3_region }`, `brix_webdav on`, `brix_webdav_auth none`, `brix_export`,
`brix_storage_backend s3://…/brixfwd`, `brix_storage_credential minio`,
`brix_allow_write on`, `dav_methods PUT DELETE`.

**The fault-attribution primitive** (design pattern 1 below): a hand-rolled
stdlib-only AWS SigV4 signer — `_sign` (HMAC-SHA256), `_sigv4_headers`
(canonical request, scope `datestamp/us-east-1/s3/aws4_request`, signed
headers `host;x-amz-content-sha256;x-amz-date`), `minio_request` (one signed
path-style request straight to MinIO, bypassing brix), `_backend_healthy`
(direct signed PUT+GET of `/{bucket}/_health_probe`). `attribute_failure(what)`
re-probes the backend and fails as `[brix-machinery]` if MinIO is healthy,
`[backend]` if not. boto3/requests_aws4auth are deliberately NOT used — they
are not in the test env.

| Test | Asserts |
|---|---|
| `test_backend_direct_roundtrip` | leg 0: direct signed PUT+GET roundtrips byte-exact — backend proven without brix |
| `test_download_through_brix` | object seeded directly into MinIO (300 KB) served through brix; sha256 matches |
| `test_upload_through_brix` | PUT through brix (staged whole-object) lands in MinIO byte-exact (verified by direct GET) |
| `test_missing_object_maps_to_404` | upstream NoSuchKey surfaces as 404, not ≥500 |
| `test_wrong_credentials_are_rejected_upstream` | security-neg: instance with `"definitely-wrong-secret"` must fail PUT/GET (≥400) and NOT write `forged.bin` — SigV4 credential proven load-bearing. Skips in remote mode (wrong-cred instance is local-only) |

### 0.3 `test_s3gsi_multiuser.py` (452 lines) — root://+GSI multi-user over S3

Module-level skip unless `TEST_S3GSI_HOST` is set (k8s remote-only suite).
Env: `TEST_S3GSI_PORT` (1094, fallback-**allow** lane), `TEST_S3GSI_DENY_PORT`
(1095, fallback-**deny** lane), `TEST_S3GSI_BUCKET=brixgsi`, `TEST_ROOT=/tmp/tr`,
`PKI_SRC=/auth/pki`. Fixed users: bob/alice/mallory→atlas, tom/jane→cms;
VO backend creds `atlas-svc/atlas-secret-1`, `cms-svc/cms-secret-1`; canary
`/cms/shared/canary.dat` = `cms-canary-payload-v1`. The `gsi` fixture copies
`{u}_proxy.pem` from the PKI secret to 0400 tmp files and exports
`X509_USER_PROXY`/`X509_CERT_DIR`/`XrdSecPROTOCOL=gsi`/`XrdSecGSISRVNAMES=*`;
data ops drive real `xrdcp -f` / `xrdfs`. Same stdlib SigV4 probe as 0.2 but
parameterized on `(ak,sk)` so MinIO can be interrogated *as* atlas-svc,
cms-svc, or admin.

XFAIL reasons (all `strict=False`):
`XFAIL_WRITE_CRED` = "sd_remote has no staged_open_cred — writes signed with
static service credential"; `XFAIL_DENY_WRITE` = "fallback deny refuses writes
even with a valid .s3 (no staged_open_cred slot to dispatch to)";
`XFAIL_NO_DIRLIST` / `XFAIL_NO_MKDIR` / `XFAIL_NO_RENAME` = missing sd_remote
namespace slots.

Full matrix with 2026-07-14 status:

| Class / test | Marker | Asserts | 07-14 status |
|---|---|---|---|
| `TestBackendProvisioned::test_bucket_and_canary_present` | — | canary present+correct via admin keys | PASS |
| `::test_atlas_keys_cannot_read_canary` | — | atlas keys 403 on cms canary | PASS |
| `::test_cms_keys_can_read_canary` | — | cms keys read canary 200 | PASS |
| `::test_atlas_keys_denied_on_wprobe` | — | atlas keys 403 PutObject on `atlas/wprobe/*` | PASS |
| `TestUserRoundtrip::test_write_read_roundtrip[bob,alice,tom,jane]` | parametrize ×4 | xrdcp up+down roundtrip, MinIO ground truth | FAIL ×4 (bug 1.1) |
| `::test_stat_own_file` | — | seed direct, `xrdfs stat` shows size | FAIL (read HEAD 403, bug 1.1) |
| `::test_rm_own_file` | — | `xrdfs rm`, then object 404 direct | FAIL |
| `::test_dirlist_own_tree` | xfail NO_DIRLIST | `xrdfs ls` shows file | XFAIL |
| `::test_mkdir_own_tree` | xfail NO_MKDIR | `xrdfs mkdir` ok | XFAIL |
| `::test_mv_own_tree` | xfail NO_RENAME | `xrdfs mv`, dst present | XFAIL |
| `TestIsolation::test_bob_cannot_read_alice` | — | cross-user read denied | PASS |
| `::test_bob_cannot_write_alice` | — | cross-user write denied + not in MinIO | PASS |
| `::test_bob_cannot_read_cms` | — | cross-VO read denied | PASS |
| `::test_unlisted_path_denied` | — | authdb default-deny for `/elsewhere/…` | PASS |
| `::test_mallory_cannot_read_bob` | — | same-VO user isolation | PASS |
| `TestCredentialAttribution::test_read_uses_users_vo_credential` | — | bob's read of cms canary must fail (his atlas `.s3`) | PASS/FAIL* |
| `::test_read_same_vo_credential_works` | — | jane (cms keys) reads canary | FAIL (bug 1.1) |
| `::test_write_uses_users_vo_credential` | xfail WRITE_CRED | bob write to wprobe must be rejected | the 1 XPASS — masked, see 1.3 |
| `TestFallbackLanes::test_allow_lane_nocred_uses_service` | — | mallory (no `.s3`) rides service cred | FAIL (bug 1.1) |
| `::test_deny_lane_nocred_rejected` | — | deny lane refuses mallory | PASS |
| `::test_deny_lane_read_with_cred` | — | deny lane read with valid `.s3` works | FAIL (bug 1.1) |
| `::test_deny_lane_write_with_cred` | xfail DENY_WRITE | deny-lane write with valid `.s3` | XFAIL |

Tally: 11 PASS (the whole identity/authz story), 9 FAIL (every positive
storage op — all bug-1.1-caused), 4 XFAIL, 1 XPASS (masked, see the 1.3
precision note).

### 0.4 Charts, provisioning, and the attribution oracle

**`charts/s3-forward`** (deps `brix-common` + `topology-role` alias `s3fwd`):
just a MinIO Deployment+Service (`{release}-minio`, readiness on
`/minio/health/ready`); no provision/PKI jobs — the test creates bucket
`brixfwd` itself. Brix role `s3fwd`, WebDAV port 8446.

**`charts/s3-gsi`** (deps alias `s3gsi`): MinIO + three hook resources —
`bootstrap-rbac.yaml` (pre-install SA/Role/RoleBinding, weight −5),
`pki-bootstrap-job.yaml` (pre-install, image `brix-authority:dev` — mints
CA/host + 5 user proxies, derives authdb + `.s3` files from the ACTUAL leaf
DNs, publishes fixed-name objects), `minio-provision-job.yaml` (post-install,
`minio/mc:latest`). Two lanes on one bucket: port 1094 =
`brix_storage_credential_fallback allow`, port 1095 = `deny`. Fixed
release-independent object names: Secret `s3gsi-pki`, ConfigMaps
`s3gsi-ca-bundle` / `s3gsi-jwks`, Secret `s3gsi-server-extra`.

**MinIO provisioning (the oracle, quoted):** `mc alias set` (60×2s retry),
`mc mb -p m/brixgsi`, then:

```json
atlas.json: {"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject",
    "s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],
   "Resource":["arn:aws:s3:::brixgsi/atlas/*"]},
  {"Effect":"Deny","Action":["s3:PutObject"],
   "Resource":["arn:aws:s3:::brixgsi/atlas/wprobe/*"]},
  {"Effect":"Allow","Action":["s3:ListBucket"],
   "Resource":["arn:aws:s3:::brixgsi"],
   "Condition":{"StringLike":{"s3:prefix":["atlas/*"]}}}]}
```

`cms.json` is the same shape scoped to `cms/*` (no deny trap); `svc.json` is
`s3:*` on the whole bucket. Then `mc admin policy create` ×3, `mc admin user
add` (atlas-svc / cms-svc / svc), `mc admin policy attach`, and the canary
seed `echo -n "cms-canary-payload-v1" | mc pipe m/brixgsi/cms/shared/canary.dat`.
The **wprobe PutObject deny** is the write-attribution probe; the **cms-only
canary** is the read-attribution probe.

**`s3_gsi_multiuser.conf`** (stream block, two near-identical servers for the
two lanes): `brix_root on; brix_auth gsi; brix_allow_write on;
brix_upload_resume off; brix_authdb /etc/brix/extra/authdb; brix_export …;
brix_storage_backend s3://…; brix_storage_credential_dir /etc/brix/extra;
brix_storage_credential_fallback allow|deny`. The bug-1.1 workaround comment,
verbatim (lines 46-50):

```
# NOTE deliberately NO brix_storage_credential: the stream worker-init
# credential replay (process_server_init.c) clobbers the parse-time
# s3_access_key/secret with empty strings (bug found by this lab), so a
# static service credential is UNUSABLE on the stream plane — anonymous
# + per-user .s3 open_cred is the only working posture.
```

### 0.5 labtools wiring & exact run commands

`xrd-lab test <scenario>` → `labtools/lab.py:cmd_test` → `lab_suite.run`.
`_s3fwd` (ns `brix-s3fwd`, release `fwd`): helm dep build + install
`charts/s3-forward` (`--wait --timeout 3m`), then test-runner with
`TEST_MINIO_HOST=fwd-minio, TEST_S3FWD_HOST=fwd-s3fwd, TEST_S3FWD_PORT=8446`,
`extraArgs=-p no:xdist -v`. `_s3gsi` (ns `brix-s3gsi`, release `sg`, timeout
5m): runner gets `TEST_S3GSI_HOST=sg-s3gsi` ports 1094/1095,
`clientPki.enabled=true` (pkiSecret `s3gsi-pki`, jwks `s3gsi-jwks`), and
**`testRunner.env.TEST_SKIP_SERVER_SETUP=1`** — the runner image for both
suites is `brix-client:dev` (they live only in `remote-suite/`), which has NO
local nginx; without the flag conftest's `start-all` INTERNALERRORs the
session (`remote-suite/tests/conftest.py` `_should_skip_local_lifecycle`).
`XRD_LAB_DRY_RUN=1` prints the helm/kubectl plan without executing.

```bash
# s3fwd — local (skips cleanly without docker)
bash k8s-tests/remote-suite/tests/minio_harness.sh start
cd k8s-tests/remote-suite/tests && PYTHONPATH=. pytest test_minio_s3_forward.py -v -p no:xdist
bash k8s-tests/remote-suite/tests/minio_harness.sh stop

# in-cluster
cd k8s-tests && ./xrd-lab test s3fwd
cd k8s-tests && ./xrd-lab test s3gsi     # s3gsi is cluster-only
```

### 0.6 Proxy minting utilities

- `k8s-tests/remote-suite/utils/make_proxy.py` — RFC-3820 proxy with a
  hand-DER-encoded critical `proxyCertInfo` (OID `1.3.6.1.5.5.7.1.14`, policy
  inheritAll) + critical `keyUsage=digitalSignature`. **Fixed
  `proxy_serial = 12346`** used both as cert serial AND the appended
  `/CN=12346` subject component — this pin is what makes the lab's per-DN
  artifacts deterministic (and what P80.11 exists to make unnecessary).
- `k8s-tests/remote-suite/utils/voms_proxy_fake.py` — pure-Python
  `voms-proxy-fake`: proxy carrying a VOMS Attribute Certificate (FQAN OID
  `1.3.6.1.4.1.8005.100.100.4`) that libvomsapi `VOMS_Retrieve()` accepts.
  NOTE its proxy serial is **random**, not 12346 — the fixed serial belongs
  only to `make_proxy.py`.

**Two design patterns worth reusing everywhere:**

1. **Layer fault-attribution.** Every brix-side assertion re-probes the backend
   directly (stdlib SigV4) and fails as `[backend]` (MinIO broken, not brix)
   vs `[brix-machinery]` (backend proven healthy, forwarding path at fault).
   A test failure names the guilty layer without instrumentation.
2. **External credential attribution.** MinIO policy scoping makes "which
   credential did brix sign with" observable from outside: atlas keys are
   denied on `cms/*` and on `PutObject atlas/wprobe/*`, the service credential
   is not. Reads/writes landing where only one credential could reach is an
   unforgeable attribution oracle — no server instrumentation, no log parsing.

---

## 1. Verified findings (anchors re-verified 2026-07-16)

### 1.1 KILLER BUG — stream worker credential replay wipes S3 keys

**DRIFT (count): FOUR hand-copied `brix_credential_t → brix_vfs_backend_cred_t`
mappers exist, not three** — the S3-front parse-time mapper was missed in the
07-14 draft. Every construction site of `brix_vfs_backend_cred_t` in the tree:

| Site | Function | bearer | x509 proxy/key | ca_dir | s3 ak/sk/region | sss_keytab |
|---|---|---|---|---|---|---|
| WebDAV parse-time — `src/protocols/webdav/config_merge.c:244-252` | `webdav_set_storage_credential` (:217) | yes | proxy only (**no x509_key** — proxy-only by design) | yes | yes | yes |
| stream parse-time — `src/core/config/runtime_server.c:93-100` | `brix_server_set_storage_credential` (:65) | yes | proxy-or-cert + key (`brix_server_fill_x509_credential`, :49-63) | yes | yes | yes |
| S3-front parse-time — `src/protocols/s3/module_merge.c:189` | `s3_export_attach_credential` | yes | no x509_key | yes | yes | yes |
| **stream worker replay — `src/core/config/process_server_init.c:83-95`** | `brix_init_server_backend_credential` (:62), called from `brix_init_one_server` (:341) at **:344** | **NO** | yes | yes | **NO ×3** | yes |

The two structs being mapped between:

- `brix_credential_t` (`src/core/config/credential_block.h:33-53`) — 15 fields:
  `name, x509_proxy, x509_cert, x509_key, ca_dir, token, token_file,
  token_forward, tls, vo, s3_access_key, s3_secret_key, s3_region, sss_keytab,
  last_def_cycle`. Stored in a fixed process-wide table
  `brix_credentials[32]` (`BRIX_CREDENTIAL_MAX`), looked up linearly by name
  (`brix_credential_lookup`, `credential_block.c:19-36`).
- `brix_vfs_backend_cred_t` (`src/fs/vfs/vfs_backend_registry.h:76-85`) — 8
  `const char *` fields: `bearer, x509_proxy, x509_key, ca_dir, s3_access_key,
  s3_secret_key, s3_region, sss_keytab`. (No `vo`/`token_forward`/`tls` — those
  stay config-side.)

The defective replay body, quoted (`process_server_init.c:83-95`):

```c
ngx_memzero(&bcred, sizeof(bcred));
bcred.x509_proxy = cred->x509_proxy.len > 0
    ? (const char *) cred->x509_proxy.data
    : (cred->x509_cert.len > 0
        ? (const char *) cred->x509_cert.data : NULL);
bcred.x509_key = (cred->x509_proxy.len == 0 && cred->x509_key.len > 0)
    ? (const char *) cred->x509_key.data : NULL;
bcred.ca_dir = cred->ca_dir.len > 0 ? (const char *) cred->ca_dir.data : NULL;
bcred.sss_keytab = cred->sss_keytab.len > 0
    ? (const char *) cred->sss_keytab.data : NULL;
brix_vfs_backend_set_credential(xcf->common.root_canon, &bcred);
```

It maps 4 of 8 fields. Missing: **`bearer`** (it never calls
`brix_credential_bearer` at all) and **all three `s3_*` fields**. Also unlike
the parse-time sites, a lookup miss here is a *silent return* (:79-81), not an
error.

**Why the partial copy is fatal — the setter's clobber semantics.**
`brix_vfs_backend_set_credential` (`src/fs/vfs/vfs_backend_config.c:63-105`)
does `ngx_cpystrn(e->origin_<field>, cred-><field> ? cred-><field> : "")`
**unconditionally for all 8 slots on every call** — there is no only-if-set
merge; a NULL field WIPES the corresponding registry slot to `""`. It then
sets `e->inst = NULL` so the driver instance is rebuilt with the (now empty)
credential on next resolve. A whole-struct `cred == NULL` is explicitly
"clear to anonymous". Registry slot sizes
(`src/fs/vfs/vfs_backend_internal.h:49-58`): `origin_token[4096]`,
`origin_x509_proxy[1024]`, `origin_x509_key[1024]`, `origin_ca_dir[1024]`,
`origin_s3_access_key[256]`, `origin_s3_secret_key[256]`,
`origin_s3_region[64]`, `origin_sss_keytab[1024]`.

**Why the replay exists and when it fires.** Per the header comment
(`process_server_init.c:39-61`): the parse-time `set_credential` calls run in
the throwaway config-load process; the serving workers' registry entry does
not carry the derived credential across that boundary, but the srv-conf
`ngx_str_t` fields DO inherit — so each worker re-derives the credential at
init. The call chain is `ngx_stream_brix_init_process`
(`src/core/config/process.c:157`) → per-server loop (:208-231) →
`brix_init_one_server` (:228 → `process_server_init.c:341`) →
`brix_init_server_backend_credential` (:344) as step 1. It is the standard
nginx per-worker `init_process` hook — it fires on initial fork, **every
worker respawn**, and SIGHUP reload. So the S3 keys installed at parse time
are clobbered to `""` before any worker serves its first request.

Net effect, proven live via `mc admin trace`: every stream-plane S3 request
signs `Credential=/date/...` (empty access key) → 403 on everything. This is
why `s3_gsi_multiuser.conf` carries the deliberate "NO
`brix_storage_credential`" posture (anonymous + per-user `.s3` `open_cred` is
the only working stream configuration today). The WebDAV and S3-front planes
don't replay (http plane has no equivalent worker-init re-derivation), which
is why the `s3fwd` suite passes.

**Root cause class: copy-drift between four mappers, not a one-line typo.**

### 1.2 root:// writes to an s3:// primary — REVISED 2026-07-16

**The 07-14 claim "the staged path is HTTP-plane only" is stale.** The stream
plane already routes open-for-write through the VFS staged seam when the
backend leaf can't do random writes. What the re-verified tree shows:

**(a) The staged route exists.** `brix_open_write_needs_staged`
(`src/protocols/root/read/open_resolved_file_dispatch.c:162-174`):

```c
return leaf != NULL
    && !(brix_sd_caps(leaf) & BRIX_SD_CAP_RANDOM_WRITE)
    && (leaf->driver == NULL || leaf->driver->pwrite == NULL);
```

When true, `brix_open_dispatch_driver` (:184-218, branch at :205) calls
`brix_open_dispatch_staged` (:60-91) → `brix_vfs_staged_open(vctx,
a->create_mode, 16, &serr)` (:72). The kXR_write leg goes through
`brix_write_staged` → `brix_staged_append`
(`src/protocols/root/write/write_staged.c:45,67` — sequential-append
enforced; a random-offset write is refused as kXR_Unsupported) →
`brix_vfs_staged_write` → `driver->staged_write`. Close drives
`brix_close_staged_commit` (`close.c:167-184`) → `brix_vfs_staged_commit`
(`vfs_staged.c:321-392`) → `driver->staged_commit`. Abort on teardown:
`connection/fd_table_teardown.c:65`.

**(b) sd_remote implements the staged trio.** Driver table at
`src/fs/backend/remote/sd_remote.c:370-387` (DRIFT: the file is
`src/fs/backend/remote/`, not backend root): populated slots `open,
open_cred, close, pread, fstat, stat, unlink, staged_open, staged_write,
staged_commit, staged_abort`; `.caps = BRIX_SD_CAP_RANGE_READ |
BRIX_SD_CAP_MEMFILE` (:374 — `CAP_RANDOM_WRITE` deliberately absent, comment
at :372-373); no `.pwrite`. `sd_remote_staged_open` (:266-302) delegates to
`sd_s3_open_write(&p, -1, SD_REMOTE_PART_SIZE /* 16 MiB */, …)`;
`sd_remote_staged_write` (:304-316) → `sd_s3_pwrite`;
`sd_remote_staged_commit` (:318-335) → `sd_s3_commit`. In `sd_s3_write.c`:
`sd_s3_open_write` (:283-324) picks **single buffered PUT** when
`0 <= expected_size <= part_size`, else creates a **multipart upload**
(`POST ?uploads`); `sd_s3_pwrite` (:326-381) enforces strictly sequential
offsets (`EINVAL` otherwise) and flushes full 16 MiB parts; `sd_s3_commit`
(:383-420) completes the MPU (uploading one empty part for zero-byte files)
or issues the single PUT; `sd_s3_abort` (:422-433) best-effort
`DELETE ?uploadId=`.

**(c) The residual, still-real gaps:**

1. **`brix_upload_resume on` (the default) bypasses the seam entirely.**
   `a.use_resume = (is_write && conf->upload_resume)` and
   `a.stage = a.use_posc || a.use_resume`
   (`open_resolved_file.c:269-270`); the dispatch at
   `open_resolved_file_dispatch.c:246` takes the driver/staged branch only
   `if (sd_inst != NULL && !a->from_cache && !a->use_resume)` — resume forces
   `brix_open_posix_dispatch` (:254): a LOCAL identity-keyed `.part`
   (`brix_make_resume_path`, `open_resolved_file_staging.c:191-230`) committed
   at close by `brix_close_posc_commit` (`close.c:230-300`) →
   `brix_commit_staged` (:261-262) — a local fsync+rename that never touches
   the VFS seam. On an s3:// primary the bytes land in the local export
   skeleton (or the commit EIOs), never in MinIO. The two close-time commit
   paths (`brix_close_staged_commit` :167 vs `brix_close_posc_commit` :230)
   are mutually exclusive per handle (staged handle: `fd=-1, staged!=NULL`;
   POSC/resume handle: real fd + `posc_final_path`).
2. **`noreplace`/POSC exclusivity is silently dropped by sd_remote.**
   `sd_remote_staged_commit` does `(void) noreplace;` (:325 — "S3 PUT/MPU
   always replaces"): an exclusive-create publish is not honored on s3.
3. **Always-multipart.** sd_remote passes `expected_size = -1`, so even a
   1-byte upload pays MPU create/complete round-trips. The client-announced
   open size (when present) could select the single-PUT path.
4. **Error surface at open:** `brix_open_dispatch_staged` maps a NULL staged
   handle via `brix_open_map_open_error(…, serr != 0 ? serr : EROFS, …)`
   (:75-76), and EROFS has no case in that mapper
   (`open_resolved_file_open.c:214-262`) → default **kXR_IOError (3007)**
   (`opcodes.h:156`). The direct sd_remote EROFS refusal for non-staged write
   opens is `sd_remote_open_impl` (`sd_remote.c:89-93`).
5. **Live verification is outstanding.** The s3gsi roundtrip FAILs were all
   credential-caused (1.1) — the staged route has never been proven
   end-to-end against MinIO on the stream plane. The 07-14 lab may also have
   run on stale images. First action after P80.1: re-run the lab and let the
   roundtrip tests attribute whatever is left.

### 1.3 Per-user write attribution gap (predicted, then confirmed by XPASS/XFAIL)

`sd_remote` has `.open_cred` (per-user SigV4 reads, phase-3 T3 —
`sd_remote.c:166-190`, DRIFT from the 07-14 anchor 146-180) but **no
`staged_open_cred` / `stat_cred` / `unlink_cred`** — writes and metadata sign
with the static service credential even when the user has their own `.s3`.

**The exact drop point.** The VFS seam's driver branch
(`vfs_staged.c:167-193`, dispatch at :182) resolves the per-open backend cred
and calls `brix_sd_staged_open_maybe_cred` (`src/fs/backend/sd.h:593-619`):

```c
if (cred != NULL && inst->driver->staged_open_cred != NULL) {
    return inst->driver->staged_open_cred(inst, final_path, mode, cred, err_out);
}
if (cred != NULL && cred->fallback_deny
    && inst->driver->staged_open_cred == NULL
    && inst->driver->staged_open != NULL)
{
    *err_out = EACCES;  return NULL;    /* deny: cred cannot be honored */
}
...
return inst->driver->staged_open(inst, final_path, mode, err_out);
```

So for sd_remote today: cred + `fallback_deny` → **EACCES** (a valid
credential that cannot be honored is treated as deny, never silent
service-cred fallback — correct posture, surprising UX; explains the
deny-lane write XFAIL); cred without deny → **falls through to plain
`staged_open`**, PUT signed with the service credential. The same
three-branch pattern guards every namespace op
(`brix_sd_{stat,unlink,mkdir,rename,setattr,getxattr,listxattr,setxattr,removexattr,server_copy,opendir}_maybe_cred`,
sd.h:636-868; design rationale in the header comment sd.h:550-565). The
credential struct is `brix_sd_cred_t` (sd.h:200-215 — carries
`s3_ak/s3_sk/s3_region` + `fallback_deny:1`); the vtable slot is declared at
sd.h:454-457.

**Templates already in-tree:**

- `sd_http` — `.staged_open_cred = sd_http_staged_open_cred` (`sd_http.c:45`);
  shared body `sd_http_staged_open_common(inst, final_path, mode, cred,
  err_out)` (`sd_http_write.c:70-114`) captures bearer→Authorization header /
  proxy→client-cert path at open, applies them at the commit PUT, with a
  deny-mode transport gate (`sd_http_cred_gate`, :83). sd_http has the same
  caps/no-pwrite shape as sd_remote — it is the closest structural template.
- `sd_xroot` — full cred suite including `.staged_open_cred =
  sd_xroot_staged_open_cred` (`sd_xroot.c:225`, impl
  `sd_xroot_staged.c:161-166` → `_common` :107-140, cred threaded via
  `sd_xroot_copy_cred_into_task` :129). NOTE (corrects the 07-14 "sd_xroot got
  this exactly" framing for P80.2): sd_xroot's writability is NOT the staged
  seam — it advertises `CAP_RANDOM_WRITE` + a real `.pwrite`
  (`sd_xroot.c:194,205`), so root:// writes to xroot take the live
  session-write path; its staged_open_cred serves the stage-tier/whole-object
  bridge. sd_remote stays on the staged-adapter route by design (S3 has no
  random write).

The fix shape is mechanical: parametrize `sd_remote_staged_open` by cred
exactly as `sd_remote_open_cred` already threads
`cred->s3_ak/s3_sk/s3_region` into `sd_remote_open_impl` for reads, and
register the slot at `sd_remote.c:382-386`.

**Precision note on the live evidence:** the s3gsi wprobe test XPASSed, but
for a masked reason — 1.1 empties the service credential too, so the probe
write failed at MinIO with *anonymous* signing, not with atlas keys.
`mc admin trace` showed ZERO brix-originated requests carrying a per-user key
(reads died at the anonymous open-flow HEAD before `open_cred` ever signed a
GET). So 1.3 is code-verified but **not yet live-verified**; the wprobe oracle
only becomes meaningful after P80.1 lands.

### 1.4 Namespace ops on s3:// error dishonestly

`sd_remote` has no dirlist/mkdir/rename slots. Two layers compound into the
dishonest error:

- **VFS wrappers are inconsistent about the NULL-slot errno** (none return
  EIO directly, but they disagree): dirlist/opendir → ENOTSUP
  (`vfs_dir.c:109-111,539`), sync → ENOTSUP (`vfs_sync.c:38`), xattr ops →
  ENOTSUP (`vfs_xattr.c:87,138,187,239,282`); but mkdir → ENOSYS
  (`vfs_mkdir.c:47-52,124`; mkpath `vfs_walk.c:360-365`), rename → ENOSYS
  (`vfs_rename.c:136-142`), unlink → ENOSYS (`vfs_unlink.c:47,149`), copy →
  ENOSYS (`vfs_copy.c:83,110`). The maybe_cred forwarders also produce ENOSYS
  for absent slots.
- **The forward errno→kXR map cannot express "unsupported".**
  `brix_kxr_from_errno` (`src/core/compat/error_mapping.c:34-73`) handles
  ENOENT/EACCES/EPERM/EXDEV/ELOOP/ENOTEMPTY/EEXIST/ENOTDIR/ENOMEM/ENOSPC/EINVAL
  and defaults everything else — including ENOTSUP, ENOSYS, EOPNOTSUPP — to
  **kXR_IOError** (:70-71). `kXR_Unsupported` exists (`opcodes.h:162`,
  **value 3013** — DRIFT: an earlier note said 3011, which is kXR_NotFound)
  and even appears in the *reverse* table (`error_mapping.c:113`
  `{kXR_Unsupported, ENOSYS}`), but no forward entry produces it.

Users see "I/O error" for "this backend can't do that".

### 1.5 authz/gate path mismatch without `brix_export`

With an s3 plane and no export root, the gate checks `root_canon+wire` =
`//atlas/...` while authdb rules canonicalize (realpath) to `/atlas/...` —
nothing matches, all ops die `3010 authdb denied`. Mechanics, verified:

- **The join** is `brix_beneath_full_path`
  (`src/fs/path/beneath.h:113-135`, static inline; representative stream
  caller `src/protocols/root/path/op_path.c:77`, compat wrapper
  `src/core/compat/path.c:53`, 18 call sites total). `brix_beneath_rel`
  (beneath.h:72-77) strips ALL leading slashes from the wire path, then the
  join unconditionally re-inserts one: with `root_canon = "/"` (rlen 1) the
  result is `"/" + "/" + "atlas/..."` = **`//atlas/...`**.
- **Why root_canon is `/`:** `brix_server_setup_export`
  (`src/core/config/runtime_server.c:159-177`) is the only place stream
  `root_canon` is canonicalized (`brix_prepare_export_root`, directive
  `brix_export`, required=1) — and the whole block is gated at :164 on
  `brix_server_has_runtime_export(xcf)`; unset `brix_export` means the setup
  never runs.
- **The rule side:** `brix_finalize_path_rules`
  (`src/fs/path/helpers.c:122`, realpath via `brix_resolve_path_noexist` at
  :161-166; `/` special-cased at :146-149) canonicalizes every
  authdb/VO/group rule path at load — which is why doubling the rules
  (`//atlas/...`) in the authdb file does NOT work around it; the mismatch is
  strictly gate-input-side.
- **Nuance for the guardrail:** the gate authorizes the LOGICAL wire path for
  the xrdacc engine but the RESOLVED backing path for the native authdb / VO
  ACL (`auth_gate.c:186-188, 402-403, 414`) — the P80.5 error message should
  name which side broke.

Setting `brix_export <real-local-dir>` aligns both sides. Works, but is a
silent foot-gun.

**Open question for P80.1 verification:** whether request-path resolution on
the s3 plane needs local *skeleton directories* under `brix_export`
(`/data/xrootd/atlas/bob/...`). The lab created them mid-debug and it made no
difference, but that observation is confounded by 1.1 (everything was failing
on credentials). Retest with creds fixed; if skeleton dirs turn out to be
required, that's a second foot-gun for P80.5 to guard (or the resolve should
go no-exist-tolerant for origin-scheme backends).

### 1.6 Stale "read-only" comments (contradicted by the passing upload test)

`vfs_backend_config_s3.c:28`, `sd_remote.c:372-373` ("phase-71: read-only S3
primary…"), and the registry comment (`vfs_backend_registry.h` — already
flagged in phase-71 §0) all say "S3 primary is read-only"; what's true is "no
RANDOM pwrite — whole-object staged PUT works" (and post-1.2-revision, works
from BOTH planes modulo the resume bypass). Misleads exactly the way phase-71
warned about.

### 1.7 k8s ucred gotcha — `O_NOFOLLOW` vs secret mounts

k8s secret/configmap mounts are `..data/` symlink farms; the (correct,
mandatory) `O_NOFOLLOW` credfile hardening in `ucred.c` (and in
`brix_credential_bearer`'s token_file open,
`credential_block.c:200-247` — `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`) reads them as
"credential missing". Worked around in `topology-role`: `role.auth.extraSecret`
runs an `extra-init` initContainer that `cp -rL`s into an emptyDir. This is an
ops-docs matter, NOT a reason to weaken the hardening.

---

## 2. The plan

### P80.1 — ONE credential mapper (fixes 1.1 as a class) — S, do first

Add to `src/core/config/credential_block.c` (it owns `brix_credential_t`; the
bearer resolve `brix_credential_bearer` already lives there, :193-247):

```c
ngx_int_t brix_credential_to_backend_cred(const brix_credential_t *cred,
    char *bearer_buf, size_t bearer_cap,
    brix_vfs_backend_cred_t *out, ngx_log_t *log);
```

Semantics = today's fullest mapper (stream parse-time): memzero `out`; derive
bearer via `brix_credential_bearer` into the caller's buffer (`out->bearer`
points at it when non-empty); x509 = proxy-or-cert with key only when no
proxy (`brix_server_fill_x509_credential` logic, `runtime_server.c:49-63`);
str-or-NULL for ca_dir, all three s3 fields, sss_keytab. Returns NGX_ERROR on
bearer failure.

Replace **all FOUR** copies with calls to it:

| Site | Today | Notes |
|---|---|---|
| `runtime_server.c:93-100` | full | becomes the reference call |
| `webdav/config_merge.c:244-252` | no x509_key | gains x509_key — additive, WebDAV proxy-only configs unaffected |
| `s3/module_merge.c:189` | no x509_key | same |
| `process_server_init.c:83-95` | missing bearer + s3×3 | **the fix**: gains bearer derivation (needs a local bearer buf at worker init — the `O_NOFOLLOW` token_file read is fine there) + s3 fields, by construction |

Drift becomes impossible, not just fixed. Also fix the replay's
silent-return-on-lookup-miss (:79-81) to at least log at error level — a
worker serving with a wiped credential must not be quiet.

**Verify:** re-run `./xrd-lab test s3gsi` with `brix_storage_credential svc`
restored in `s3_gsi_multiuser.conf` (drop the workaround comment, §0.4) — the
9 positive-path FAILs must flip to PASS (or, if any remain, they now
attribute the true 1.2/1.3 residue). Add a stream-plane static-S3-credential
regression to `test_minio_s3_forward.py` (root:// front on the same MinIO) so
the WebDAV/stream asymmetry can never silently return. 3 tests: success
(stream read with static cred **after a worker respawn** — kill a worker or
SIGHUP first, since the bug only manifests post-replay) + error (bad cred
403) + security-neg (cred must not leak into logs).

### P80.2 — root:// staged writes to object backends: close the residue (fixes 1.2c) — S/M (revised down from M)

The staged route already exists (1.2a/b); the work is the residue:

1. **Resume bypass:** when the primary leaf lacks `CAP_RANDOM_WRITE` and has
   `staged_open`, either reject `brix_upload_resume on` at config merge with
   a clear error, or (better) transparently divert: force
   `a.use_resume = 0` for staged-only backends at
   `open_resolved_file.c:269-270` so the dispatch (:246) takes the seam. A
   config that silently strands bytes in the local skeleton is not
   acceptable. Capability-driven per phase-71: branch on caps bits, never on
   `backend == s3`.
2. **Exclusive publish:** honor `noreplace` in `sd_remote_staged_commit`
   (:325) — a HEAD-before-PUT gives POSC/O_EXCL semantics (racy against
   external writers, but honest; document the race) or return EEXIST-mapped
   failure when the object exists.
3. **Single-PUT fast path:** thread the client-announced open size through
   `staged_open` so `sd_s3_open_write` (`sd_s3_write.c:294`) can pick single
   buffered PUT for small objects instead of unconditional MPU
   (`expected_size = -1` today, `sd_remote.c:283`).

**Verify:** after P80.1, the four s3gsi roundtrip tests are the end-to-end
proof of the staged route (never yet live-verified — 1.2c.5); add
root://-plane upload/download to the s3fwd local suite (xrdcp against a
MinIO-backed stream server), one resume-divert test (`brix_upload_resume on`
must still land bytes in MinIO or fail loudly at config time — pick per the
option chosen), and one MPU-boundary test (>16 MiB upload → byte-exact, plus
`mc ls --incomplete` empty after abort).

### P80.3 — per-user credentials for writes + metadata (fixes 1.3) — S/M

Add `.staged_open_cred` to `sd_remote`: split `sd_remote_staged_open` into a
`_common(inst, final_path, mode, cred, err_out)` + two thin wrappers (the
sd_http `sd_http_staged_open_common` shape, `sd_http_write.c:70-114`),
threading `cred->s3_ak/s3_sk/s3_region` into the `sd_s3_open_params` exactly
as `sd_remote_open_cred` (:166-190) does for reads. Register at
`sd_remote.c:382-386`. Add `.stat_cred`/`.unlink_cred` while there (the
`maybe_cred` forwarders, sd.h:636-674, dispatch to them as soon as they
exist — no caller changes). This also dissolves the deny-lane UX surprise:
`brix_sd_staged_open_maybe_cred`'s EACCES branch stops firing once the slot
exists.

**Verify:** the s3gsi write-attribution XFAIL (bob writing `atlas/wprobe/*`
must now FAIL — atlas keys are policy-denied there, §0.4's oracle) flips to
its hard form; `test_deny_lane_write_with_cred` XFAIL→hard PASS; the suite's
attribution oracle does the proving.

### P80.4 — honest kXR_Unsupported for missing namespace ops (fixes 1.4) — S

Two-sided, both small:

- `brix_kxr_from_errno` (`error_mapping.c:34-73`): add
  `case ENOTSUP: case ENOSYS:` (and `EOPNOTSUPP` where it differs) →
  `kXR_Unsupported` (3013, `opcodes.h:162`). The reverse entry
  (`error_mapping.c:113`) already exists — the pair becomes symmetric.
- Normalize the VFS NULL-slot errnos to ONE value (recommend ENOTSUP, the
  POSIX "operation not supported on this object" — today mkdir/rename/unlink/
  copy say ENOSYS while dirlist/sync/xattr say ENOTSUP; anchors in 1.4). With
  the forward map handling both, this half is hygiene, but it stops the next
  drift.

Optional follow-on (separate, M): real `dirlist` on `sd_remote` via
ListObjectsV2 (`sd_s3_meta.c` already speaks the XML) — decide after P80.2.

**Verify:** the three s3gsi namespace XFAILs (`dirlist/mkdir/mv`) stay xfail
but their failure mode changes from "I/O error" to kXR_Unsupported — assert
the error string in the xfail bodies so the honesty is pinned; plus a unit on
the mapper (ENOTSUP→3013, ENOSYS→3013, EIO→3007 unchanged).

### P80.5 — config-time guardrails (fixes 1.5's foot-gun) — S

At merge time, when `brix_storage_backend` is an origin-scheme (s3/http/xroot)
and authz rules are configured (`brix_authdb`/ACL) but the runtime export is
unset (`brix_server_has_runtime_export` false — the exact gate that skips
`brix_server_setup_export`, `runtime_server.c:164`), emit a config ERROR
naming the `//path` vs `/path` mismatch (or synthesize a canonical export
root). Name which check breaks per 1.5's nuance (xrdacc = wire path, native
authdb/VO = resolved path). A silent everything-denied server is the worst
outcome the lab hit. Resolve the skeleton-directory open question (1.5) in
the same change and guard or fix accordingly.

### P80.6 — truth in comments + docs — S

- Reword `vfs_backend_config_s3.c:28`, `sd_remote.c:372-373`, and the
  registry comment to "no random pwrite; writes are staged whole-object PUTs
  (both planes; resume path diverted per P80.2)" (coordinate with phase-71
  §0's same item).
- Fix the reversed operand comment at `policy.c:43` — the real syntax is
  `brix_require_vo <path> <vo>` (value[1]=path :69, value[2]=vo :75; the
  WebDAV twin documents it correctly). Found during P80.11 anchor
  verification; two-minute fix, do it here.
- New ops doc `docs/05-operations/s3-backend.md`: supported matrix per plane
  (WebDAV/S3-front/root://), credential postures (static / per-user dir /
  fallback allow-deny + the deny-lane "valid-but-unhonorable cred = EACCES"
  rule), the `brix_upload_resume` behavior on staged-only backends (per
  P80.2's chosen option), MPU part size + sequential-write contract, the k8s
  secret-mount `cp -rL` pattern (1.7), and the attribution-test pattern for
  operators debugging "is it my backend or the gateway".

### P80.7 — CI wiring — S

Add `test_minio_s3_forward.py` to the docker-gated test tier (it self-skips
without docker — harness exit 3 — so `--fast`/`--pr` stay clean); keep
`./xrd-lab test s3fwd` and `test s3gsi` in the k8s lab rotation. After P80.1
lands, the s3gsi suite's xfail/hard split is the regression net for
P80.2/P80.3 — re-tighten (xfail→hard) as each phase closes its gap, per the
matrix in §0.3.

---

### Stretch goal — zero-provisioning multi-user posture (P80.11–P80.14)

The s3gsi lab proves the mechanics but its security posture is **manually
enumerated**: a per-DN authdb rule and a per-user `x5h-<hash>.s3` file for
every user, both generated by the bootstrap job. That is a gridmap by another
name. The target posture is: **adding a user to the VO (cert + VOMS
membership) requires ZERO server-side change** — the gateway derives
everything from the presented credential, and the backend carries ONE
credential per VO. What must remain static is only standard grid trust
(CA bundle, vomsdir LSC, host cert), one `<vo>.s3` per VO, and one policy
template line — nothing that scales with users.

The pieces already in the tree that make this a short path (anchors
re-verified 2026-07-16):

- the **xrdacc engine** (`brix_authdb_format xrdacc`) already supports `@=`
  template capabilities — locate: `authfile_record.c:120-125` (finds the `@=`
  point, records `pins`/`prem`); match+substitute: `brix_acc_cap_subcomp`
  (`src/auth/authz/acc/capability.c:25-52` — prefix match at :37,
  substitution value compared at :42, fixed tail at :54). "Every
  authenticated user gets privs under a path containing their own name"
  without enumerating users;
- **ucred** already defines the canonical fs-safe identity token
  (`brix_sd_ucred_key`, `ucred.c:453-481` — literal when fs-safe, else
  `"x5h-"` + first 16 bytes of SHA-256 as 32 hex chars). The resolve order
  (`brix_sd_ucred_resolve`, :500-592) is `<key>.pem` (expiry-checked; an
  EXPIRED `.pem` is a hard NGX_DECLINED stop, never silent fallthrough) →
  `.token` → `.s3` → `.keyring`;
- **VOMS extraction** already lands the VO list on the login state
  (`gsi_cert_extract_voms`, `src/auth/gsi/auth.c:462-488` — guarded by
  `brix_voms_available()` + `vomsdir`+`voms_cert_dir`; writes
  `ctx->login.primary_vo` / `ctx->login.vo_list`; never fails login), and the
  gate consumes it (`auth_gate.c:87`).

What's missing, as phases:

**P80.11 — canonical identity token + EEC normalization (S/M, the keystone).**
Two defects block credential-derived identity today: (a) the acc `@=`
substitution uses the RAW DN — `brix_acc_gate_identity`
(`auth_gate.c:76-89`) sets `ent->name = brix_identity_dn_cstr(...)` (:81; DN
fallback from `ctx->login.dn` at :86), and `access.c:283` feeds `ent->name`
into the fungible-user match — a DN contains `/` and `=`, so a substituted
path is broken at best, injectable at worst; (b) every identity consumer
(authz, ucred keying) keys on the **proxy leaf DN** including the RFC-3820
`/CN=<serial>` suffix — the leaf subject is taken at
`src/auth/crypto/gsi_verify.c:234` (DRIFT: file moved from `src/auth/gsi/`;
it reads the `leaf` param, `X509_NAME_oneline(X509_get_subject_name(leaf))`)
— so a re-minted proxy changes the user's identity, home path, and `.s3`
hash key (the lab only survives because `make_proxy.py` pins serial 12346,
§0.6). Fix: normalize the principal to the **EEC DN** (strip proxy CN
components per RFC 3820 when walking the verified chain) and expose ONE
shared `brix_identity_user_token()` = ucred's literal-or-`x5h-` rule over the
EEC DN; make `@=` substitute the token, and ucred key on the same token. One
derivation, three consumers, no mapping file.
**Verify:** same user, two different proxy serials → same token, same authz
verdict, same credential selection (a regression the current lab cannot
express — add it; `voms_proxy_fake.py`'s random serials, §0.6, exercise it
for free).

**P80.12 — VO-derived group credential selection (S).**
Extend the ucred resolve order (`brix_sd_ucred_resolve`/`_select`,
`ucred.c:494-592`) from `<user-key>.{pem,token,s3,keyring}` to:
`<user-key>.*` → **`vo-<primary_vo>.*`** → static/fallback-policy. The
`vo-` prefix keeps the two namespaces from colliding (a VO named like a
user token). With VOMS present, "bob@atlas" with no per-user file selects
`vo-atlas.s3` — the **single group credential on the backend** with zero
per-user provisioning. Fallback semantics unchanged (`allow` → static cred,
`deny` → EACCES); preserve the expired-`.pem` hard-stop rule per tier; log
line gains the tier that matched (user/vo/static).
**Verify:** s3gsi lab drops all per-user `.s3` files, provisions only
`vo-atlas.s3`/`vo-cms.s3`; attribution oracle must still prove bob signs
with atlas keys and jane with cms keys.

**P80.13 — template policy instead of per-DN rules (S, mostly config+docs).**
With P80.11's token, the entire authdb collapses to (xrdacc grammar):

```
u = /atlas/@=/ a
u = /cms/@=/   a
```

plus `brix_require_vo /atlas atlas` / `brix_require_vo /cms cms` (NOTE
operand order: `<path> <vo>` — `policy.c:69,75`; the :43 comment is reversed,
fixed in P80.6) as the VO tier so an atlas user's template only grants inside
`/atlas`. Enforcement is `brix_check_vo_acl` (`src/auth/authz/acl.c:59-100`),
keyed on the RESOLVED path, longest-prefix boundary-aware match
(`find_rule.c:67+`), no-rule = permissive, rule-without-membership = deny;
already wired at auth_gate.c:414 + statx/prepare/tpc/webdav call sites. No
per-user lines, default-deny everywhere else. If the combined "org-scoped
template" turns out to need a grammar extension (stock XrdAcc can't AND
`o <vorg>` with `u =` on one line), prefer wiring the existing
`brix_require_vo` tier rather than extending the grammar. Config-time
prerequisites (from `brix_config_finalize_policy`, `policy.c:121-163`):
`brix_auth gsi|token|both`, VOMS available, `brix_vomsdir` +
`brix_voms_cert_dir` set.
**Verify:** the s3gsi isolation tests (bob≠alice, cross-VO, unlisted path)
pass against a 2-line authdb + 2 `require_vo` lines and NO bootstrap-generated
rules; adding a 6th user to the lab requires touching nothing server-side.

**P80.14 — VOMS in the k8s lab (M, prerequisite for P80.12/13 verification).**
Same as appendix P80.10 but now load-bearing rather than optional: the
bootstrap job mints VOMS AC proxies (`voms_proxy_fake.py`, §0.6), publishes a
real vomsdir (LSC) ConfigMap, the server image gains `libvomsapi.so.1`, and
the role config sets `brix_vomsdir`/`brix_voms_cert_dir` +
`brix_require_vo`. Until this lands, P80.12/13 can be smoke-tested locally
with `test_vo_acl.py`-style fixtures.

**Definition of done for the stretch:** on a fresh gateway with the 2-line
template authdb, two `vo-*.s3` files, and standard grid trust anchors, a
NEVER-SEEN user cert with a valid atlas VOMS AC can immediately
write/read/delete under `/atlas/<their-token>/`, is denied everywhere else,
and MinIO's trace shows every one of their requests signed with the atlas
group key. No gridmap, no per-user file, no config reload.

## 3. Order & effort

P80.1 (S, unblocks 9 failing tests, kills the drift class) → P80.4 + P80.5 +
P80.6 (each S, independent) → P80.2 (S/M — revised down; mostly the resume
divert + noreplace + verification, since the staged route exists) → P80.3
(S/M, needs P80.2's verification for write-path testing) → P80.7 alongside
each. Lab-side P80.8-P80.10 (appendix §4) ride along: P80.8 immediately after
P80.1, the rest opportunistic.

The zero-provisioning stretch orders as: P80.11 (keystone — do before P80.3 so
the new `_cred` slots key on the normalized token from day one) → P80.12 +
P80.13 (each S, independent of each other) → P80.14 to prove it in-cluster.
Note P80.11 changes identity keying: existing `x5h-*` credential files hashed
from PROXY-leaf DNs (like the lab's) must be re-derived from EEC DNs — a
one-time migration the lab bootstrap regenerates automatically.

The pblock per-group posture (§6) is independent of every S3 phase: P80.21
(its keystone) touches only the gate-identity seam, P80.22 rides the existing
`brix_sd_setattr_t` owner fields. It can start immediately; only P80.24/25
(labs) benefit from landing after P80.21+22 so they open green-or-xfail rather
than all-red.

## 4. Appendix — lab/test-infra learnings (k8s-tests side, landed with the s3gsi chart)

Everything below is already in the tree (chart `k8s-tests/charts/s3-gsi`,
`topology-role` extensions, `labtools` wiring) — recorded here so the patterns
get REUSED, plus three small follow-ups.

**Patterns that worked and should be the default for future scenarios:**

- **DN-derived provisioning, correct by construction.** The PKI bootstrap job
  mints the user proxies FIRST, then generates every DN-dependent artifact
  (authdb `u <DN>` rules, `x5h-<sha256(DN)[:32hex]>.s3` filenames —
  byte-matched to `ucred.c:453`'s `brix_sd_ucred_key`) from the ACTUAL proxy
  leaf DN (`openssl x509 -noout -subject -nameopt compat` =
  `X509_NAME_oneline` form). No guessing about proxy-CN suffixes:
  `utils/make_proxy.py` uses a fixed serial (`/CN=12346`, §0.6), so DNs are
  deterministic, but deriving from the minted artifact makes the scenario
  immune to that ever changing.
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
  canary — full JSON in §0.4) = the external attribution oracle described in
  §0.

**Gotchas (cost real time; check these first next time):**

- The `brix-client` runner image has NO local nginx — any suite driven through
  `charts/test-runner` with that image must set
  `testRunner.env.TEST_SKIP_SERVER_SETUP=1` or conftest's
  `manage_test_servers.sh start-all` INTERNALERRORs the whole session
  (`remote-suite/tests/conftest.py` `_should_skip_local_lifecycle`). Both
  s3fwd and s3gsi run on `brix-client:dev`; `_s3gsi` sets the flag, `_s3fwd`
  survives only because its fixtures skip local-server setup by env presence.
- `lab_suite._collect` uninstalls the releases after every `xrd-lab test` run
  — debug by re-installing manually (`helm upgrade --install sg charts/s3-gsi
  …` + the runner) and keep the releases alive; recreate the runner Job with
  `kubectl delete job run-test-runner && helm upgrade run … --reuse-values`.
  `XRD_LAB_DRY_RUN=1` previews the exact helm/kubectl plan.
- In-pod nginx reload needs the conf path: `nginx -s reload -c
  /etc/brix/nginx.conf` (pid-file lives per-conf, not at the default).
- Config-parse `NOTICE`s (e.g. the "backend credential … for …" line at
  `runtime_server.c:101-106` that would have shortcut 1.1 by a few hours)
  never reach `error.log` — the known parse-time-log gap; don't rely on them
  for in-cluster debugging. `mc admin trace -v --all` against MinIO is the
  fastest ground truth for "what did brix actually sign/send".
- Lab image staleness: `brix-server:dev` etc. must be rebuilt after brix
  commits (`lab.plan_images(profile)` + `minikube image load`); the 07-05
  images silently lacked the whole per-user-credential machinery. (This is
  also the leading suspect for why the 07-14 lab observed the pre-staged-route
  behavior described in the original finding 1.2 — see the 1.2 revision.)

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
  local-suite-only (`test_vo_acl.py` is `# brix-remote-skip`). Superseded by
  **P80.14** (§2 stretch), where the VOMS lane becomes load-bearing for the
  zero-provisioning posture rather than optional.

## 5. Non-goals

- Making s3:// a random-write (`pwrite`) backend — object stores don't do
  that; staged whole-object is the correct contract (sequential-append
  enforced at `sd_s3_write.c:270-281` and `write_staged.c`).
- Weakening `O_NOFOLLOW` credfile hardening for k8s convenience (1.7 stays an
  init-container concern).
- S3-front → S3-backend passthrough of the CLIENT's SigV4 (signature covers
  host — cannot be replayed upstream; per-user re-signing via `.s3` files is
  the design, already working for reads).

---

## 6. Sibling use-case — multi-user root://+GSI gateway, per-UNIX-GROUP r/w, pblock:// backend (P80.21–P80.25)

**The posture:** same forward-gateway shape as the s3gsi lab — many GSI users,
one gateway — but the primary is **pblock://** (local packed-block store) and
the isolation contract is **per-unix-group read/write per path subtree**: DN →
local account via `brix_gridmap`, the account's OS groups (getgrouplist) decide
which subtrees the user may read vs write. Because pblock is local there is no
backend credential to select — the interesting axis flips from *credential
attribution* (§0–§2's whole story) to **authorization + ownership metadata**.
Enforcement decision lives at the authz gate; the pblock catalog additionally
records true ownership so stat/dirlist tell the truth (gate decides, catalog
attests).

### 6.0 What already works (anchors re-verified 2026-07-16)

- **pblock is write-capable on the stream plane today.** The driver advertises
  full POSIX parity (`sd_pblock.c:346-354`: FD | SENDFILE | RANDOM_WRITE |
  RANGE_READ | TRUNCATE | APPEND | IOURING | SERVER_COPY | XATTR |
  XATTR_WRITE | HARD_RENAME | DIRS | DIRS_WRITE — note NO owner/chown
  capability bit, consistent with 6.1.3; block 0 is a real kernel fd), so
  root:// open-for-write works — with the known `brix_upload_resume off`
  requirement (same class as 1.2c's resume bypass; pre-dates this doc, see
  the pblock metadata-GSI plan). Nothing here waits on P80.2.
- **The `g` rule machinery is complete** — grammar (`authfile_record.c:208`,
  `:255`, `:363`), evaluation (`access.c:311`), a per-worker TTL group cache
  (`groups.c:32` — `acc_gidlifetime = 43200` s, negative-cache 60s), and the
  unix resolver `getpwnam`+`getgrouplist` (`groups.c:163-184` —
  `acc_resolve_unix`, primary-only short-circuit at :181-183; public
  TTL-cached entry `brix_acc_unix_groups`, :354). Subtle and doc-worthy: a
  `g` rule matches EITHER the FQAN/VO-derived group (`access.c:79-80`, the
  `acc_sel_group` predicate) OR the OS gidlist (`access.c:272-277`, guarded
  on `acc_unixgrp_resolver != NULL`) — one namespace, two sources.
- **DN→account mapping exists** — `brix_idmap_resolve` (`idmap.c:191`, with
  TTL cache :210-224): exact grid-mapfile DN match
  (`idmap_gridmap.c:105-117` — quoted-DN + username line parse) →
  literal-username fallback → squash-to-default, producing `{uid, gid,
  supplementary gids}` with fail-closed >32-group overflow and a
  reserved/forbidden uid-gid denylist (`idmap_denylist.c:31-48` —
  `gid==0 || gid < idmap_min_uid` reserved, plus a 256-slot forbidden list).

### 6.1 Verified gaps

**6.1.1 The gate feeds the DN, so unix-group rules are dead for GSI.**
`brix_acc_gate_identity` (`auth_gate.c:76-89`) sets `ent->name =
brix_identity_dn_cstr(...)` (:81) — the raw subject. The engine then calls the
unix resolver with that name (`access.c:272-277`), and
`getpwnam("/DC=ch/DC=cern/...")` fails. Net: `g <unixgroup>` grants work only
for principals whose wire name is already a local username (SSS/krb5
localname), never for a GSI DN. This is the keystone gap.

**6.1.2 idmap is broker-locked.** `brix_idmap_resolve` is called from exactly
one place — inside the privileged broker (`broker.c:276`, fail-closed unless
OK/SQUASH at :277-280) — and only when `brix_impersonation != off`
(`lifecycle.c:147-149` — `brix_imp_validate` short-circuits when unconfigured
or mode OFF). There is no worker-side DN→username resolve the gate could
consume; the gridmap knowledge never reaches authorization.

**6.1.3 pblock has no ownership.** The catalog schema
(`sd_pblock_catalog.c:331-341` — `objects(path PK, parent, is_dir, blob_id,
size, block_size, mtime, ctime, mode)`) has no uid/gid column (no atime
either); `sd_pblock_setattr` accepts-and-ignores `set_owner` (and atime) —
`sd_pblock_namespace.c:130-154`, comment at :130-135 says so explicitly;
only mode+mtime+ctime reach `pblock_catalog_setattr`. The driver-facing
plumbing already half-exists: `brix_sd_setattr_t` carries
`set_owner:1`/`uid`/`gid` (`sd.h:272-281`, header contract at :266-271 —
`(uid_t)-1` = unchanged) — pblock just drops them. And the impersonation
broker cannot compensate: it intercepts only the posix/confined-path ops
(`resolve_confined_ops.c:113-232` — open→`brix_imp_open` :119-121,
unlink :193-200, mkdir :225-232, rename further down), never the pblock
driver — kernel enforcement structurally cannot reach a SQLite namespace +
shared block files. That is WHY the decision must live at the gate (chosen
posture: gate decides, catalog attests).

**6.1.4 No test exercises the unix source of `g` rules.** Every existing
`g`-rule test (`test_authdb.py:156-157`, `test_vo_acl.py:368-429`,
`root_cache_noimp.conf:6`) matches via the FQAN/VO `grup` field. The
getgrouplist path (`access.c:272-277`) has zero coverage against a mapped DN —
it cannot have any until 6.1.1 is fixed.

### 6.2 The plan

**P80.21 — mapped identity reaches the gate, broker-independent (fixes
6.1.1+6.1.2 as one seam) — S/M, keystone.** Factor the DN→username resolve out
of the broker so it also runs worker-side at login when a `brix_gridmap` (or
`brix_idmap_default_user`) is configured — impersonation may be off; mapping
alone must not require the privileged broker. Land the mapped username on
`ctx->identity`, and make `brix_acc_gate_identity` pass it as `ent->name`
(DN fallback when unmapped, preserving today's behavior bit-for-bit for
DN-keyed `u` rules — existing authdbs must not change verdicts). When full
impersonation IS on, gate identity and broker identity now derive from the
same map by construction — the P80.1 one-mapper lesson applied to identity.
Log line at login gains the mapped name (sanitized).
**Verify (3):** success — mapped user in group `phys` admitted by `g phys
/phys a`; error — same user denied on `/eng` (default-deny); security-neg — an
UNMAPPED DN must not fall through to any `g` grant (and a DN crafted to look
like a local username must not resolve groups unless the gridmap maps it —
the literal-username fallback tier is impersonation's squash semantics, decide
explicitly whether the gate inherits it and test the decision).

**P80.22 — pblock ownership metadata (fixes 6.1.3) — S/M.** Add `uid`/`gid`
columns via the catalog's existing idempotent best-effort-ALTER pattern
(`sd_pblock_catalog.c:363-365`, comment :360-362 — `sqlite3_exec` with
duplicate-column error ignored; old catalogs upgrade in place, NULL = legacy
"unowned" rows stat as the service identity, today's behavior). Honor
`set_owner` in `sd_pblock_setattr`; stamp owner at create — open-for-create,
`mkdir`, and `staged_commit` — from the request identity (the mapped
`{uid,gid}` of P80.21); return it in `stat`/dirlist entries. Decision, not
enforcement: the driver never re-checks perms (single-enforcement-point at the
gate; a second checker would drift — the 1.1 lesson again).
**Verify (3):** success — file written by mapped user stats with their
uid/gid over the wire AND in a direct `sqlite3` catalog query; error — chown
to a reserved uid (<`brix_idmap_min_uid`, the `idmap_denylist.c` rule) refused;
security-neg — legacy NULL-owner rows unreadable-as-someone-else (no ownership
forgery via the upgrade path).

**P80.23 — the posture itself: reference config + docs — S.** A worked config
in `docs/05-operations/` (extend the P80.6 ops doc or sibling page):
`brix_gridmap` + `brix_export` on a pblock store + authdb

```
g phys /phys a      # phys group: read/write
g eng  /phys rl     # eng group: read-only on phys space
g eng  /eng  a
```

plus `brix_upload_resume off`, the FQAN-vs-unix dual-source note
(`access.c:79-80` vs `:272-277` — a VOMS group named like a unix group matches
the same rule; name deliberately or namespace the rules), and the group-cache
TTL (`gidlifetime`, default 43200 s) implications for de-provisioning
(removing a user from a group takes effect within the TTL, not instantly;
negative cache is 60 s).

**P80.24 — local lab suite — M.** `tests/test_pblock_group_multiuser.py`:
one pblock-backed GSI stream server (reuse `run_pblock_meta_gsi.sh`'s inline
config + `pki_helpers.blitz_test_pki()` pattern, own port band), gridmap
mapping 2 users→group `phys`, 1 user→group `eng`, plus 1 unmapped DN; test
accounts/groups provisioned via `groupadd`/`useradd` in the harness (skip
cleanly when not root/no perms — same self-skip philosophy as the docker gate).
**The attribution-oracle analog of §0:** direct `sqlite3` queries against the
pblock catalog prove who owns what — external ground truth, no server
instrumentation, exactly the `mc admin trace` role. Matrix: phys-user rw on
`/phys`; eng-user r-only on `/phys` (write → kXR 3010), rw on `/eng`;
cross-group deny both directions; unmapped DN denied everywhere; ownership
rows byte-checked in the catalog.

**P80.25 — k8s chart (`pbgsi` scenario) — S/M.** Reuse the s3gsi bootstrap
patterns wholesale (§4): DN-derived provisioning job (mints proxies first,
generates the gridmap from actual leaf DNs), `role.auth.extraSecret` +
`extra-init` `cp -rL` for gridmap/authdb delivery, fixed release-independent
object names. The container replaces MinIO+mc with an initContainer that
`groupadd`/`useradd`s the mapped accounts in the server image. Register in
`TEST_REGISTRY.md` per P80.8's pattern; wire `./xrd-lab test pbgsi`.

### 6.3 Order, and how this meets the stretch goal

P80.21 → P80.22 (needs 21's identity for stamping) → P80.23 alongside →
P80.24 → P80.25. Independent of P80.1–P80.7 throughout.

**Provisioning honesty:** unlike the §2 stretch, this posture is inherently
NOT zero-provisioning — unix groups require local accounts, so a gridmap line
+ `useradd` per user is the contract, not a smell. The zero-provisioning
ambitions stay with the VO-derived S3 posture (P80.11–14); the two postures
share P80.21's principle (ONE identity derivation feeding gate, broker, and
backend) without sharing mechanism.

**Non-goals (this section):** kernel/broker-enforced perms inside pblock
(structurally impossible — SQLite namespace + shared block files, see 6.1.3);
per-user quota/accounting (ownership metadata enables it later, not now);
extending the impersonation broker to speak the pblock driver protocol.

---

## 7. Drift ledger (07-14 draft → 07-16 re-verification)

Corrections applied above, collected for anyone diffing against the original:

1. **FOUR mappers, not three** — `s3_export_attach_credential`
   (`src/protocols/s3/module_merge.c:189`) is a third parse-time site whose
   S3 keys the replay also drops. P80.1 replaces all four.
2. **Finding 1.2 rewritten** — the stream plane already routes
   no-random-write backends through the VFS staged seam
   (`brix_open_write_needs_staged`, `open_resolved_file_dispatch.c:162`);
   sd_remote implements `staged_open/write/commit/abort`. Residue: resume
   bypass, `noreplace` dropped, always-MPU, and zero live verification
   (masked by 1.1). P80.2 re-scoped S/M accordingly.
3. **Paths:** lab suites are under `k8s-tests/remote-suite/tests/`;
   sd_remote is `src/fs/backend/remote/sd_remote.c`; gsi_verify is
   `src/auth/crypto/gsi_verify.c` (moved from `src/auth/gsi/`).
4. **kXR_Unsupported = 3013** (`opcodes.h:162`), not 3011 (that's
   kXR_NotFound). A reverse-map entry already exists
   (`error_mapping.c:113`); only the forward map is missing.
5. **VFS NULL-slot errnos are inconsistent** (dirlist/sync/xattr = ENOTSUP;
   mkdir/rename/unlink/copy = ENOSYS; none EIO) — folded into P80.4.
6. **`brix_require_vo` operand order** is `<path> <vo>`; the comment at
   `policy.c:43` is reversed — fix rides P80.6.
7. Minor anchor drifts: `sd_remote_open_cred` :166-190 (was 146-180);
   `brix_acc_gate_identity` spans :76-89; `brix_sd_setattr_t` opens sd.h:272;
   catalog ALTER at :363-365; `gsi_cert_extract_voms` body :462-488; ucred
   key = first 16 bytes of SHA-256 rendered as 32 hex chars.
