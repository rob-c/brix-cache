# s3-gsi — root://+GSI multi-user gateway over MinIO S3

Exploratory scenario: does a brix instance backed by S3 *look and feel* like a
normal `root://` gateway to GSI users, with **per-VO backend credentials** and
**per-user authorization** on a shared bucket?

```
xrdcp/xrdfs as bob|alice (atlas), tom|jane (cms), mallory (no backend cred)
    │  root://+GSI (RFC-3820 proxies)
    ▼
brix  brix_auth gsi
      brix_authdb /etc/brix/extra/authdb          # per-DN default-deny rules
      brix_storage_backend s3://<rel>-minio:9000/brixgsi
      brix_storage_credential svc                 # static service identity
      brix_storage_credential_dir /etc/brix/extra # per-user <x5h-hash>.s3
      lane :1094 fallback allow · lane :1095 fallback deny
    │  SigV4
    ▼
MinIO bucket brixgsi
      atlas-svc → atlas/* only (DENY PutObject on atlas/wprobe/*)
      cms-svc   → cms/* only
      svc       → full bucket
```

## How the mapping stays correct by construction

`templates/pki-bootstrap-job.yaml` (pre-install hook, authority image) mints
the CA/host material and the five user proxies, then derives everything
DN-dependent **from the actual proxy leaf DN** (`openssl -nameopt compat`,
i.e. exactly the `X509_NAME_oneline` string brix stores):

* `authdb` — `u <proxyDN> /<vo>/<user> rwlmd` rules (default-deny engine,
  `src/auth/authz/authdb.c`), plus `/cms/shared` read grants for bob+jane
  (the read-attribution canary) and `/atlas/wprobe` for bob (write probe).
* `<key>.s3` — per-user backend credential files named by the
  `src/fs/backend/ucred.c` rule: a DN is not fs-safe, so
  `key = "x5h-" + sha256(DN).hexdigest()[:32]`.  bob/alice get the atlas
  MinIO keys, tom/jane the cms keys, mallory none.

Published objects (release-independent names): Secret `s3gsi-pki` (CA, host
cert, per-user proxies, `identities.env`), ConfigMap `s3gsi-ca-bundle`,
ConfigMap `s3gsi-jwks`, Secret `s3gsi-server-extra` (mounted at
`/etc/brix/extra` via the topology-role `role.auth.extraSecret` mount).

`templates/minio-provision-job.yaml` (post-install, `minio/mc`) creates the
bucket, the three scoped users/policies, and seeds the canary object
`cms/shared/canary.dat`.

## The attribution trick

Which credential brix signs with is observable *externally* through the MinIO
policy scoping — no brix instrumentation needed:

* **Read attribution**: bob has an authdb grant on `/cms/shared`, but his
  `.s3` carries atlas keys → MinIO must 403 his canary read.  jane (cms keys)
  reads it fine.  A successful bob read would mean a service-credential leak.
* **Write attribution**: atlas keys are DENIED `PutObject` on
  `atlas/wprobe/*` but the service credential is not.  bob's write there
  succeeding proves writes are signed by the *service* credential (the
  predicted `sd_remote` gap: no `staged_open_cred`).

## Run it

```bash
cd k8s-tests
./xrd-lab test s3gsi          # deploy ns brix-s3gsi (release sg) + run suite
```

The suite (`tests/test_s3gsi_multiuser.py`, remote mode) asserts the desired
"normal gateway" behaviour; predicted machinery gaps (dirlist/mkdir/mv
unsupported on `sd_remote`, writes riding the service credential, deny-lane
writes refused) are `xfail` so the outcome map reads directly from the
PASS/XFAIL/XPASS/FAIL tally.  Every brix-side failure is attributed
`[backend]` vs `[brix-machinery]` by re-probing MinIO directly.

## Findings (2026-07-14 run — brix source untouched by design)

11 PASS / 9 FAIL / 4 XFAIL / 1 XPASS.  Everything identity-side works: GSI
multi-user auth, per-DN authdb default-deny isolation on every op, per-user
`.s3` credential selection (incl. fallback allow/deny semantics).  Every
positive-path storage op fails, all traced to `[brix-machinery]`:

1. **Stream worker-init credential replay wipes the S3 keys**
   (`src/core/config/process_server_init.c`,
   `brix_init_server_backend_credential` maps x509/ca/sss but not
   `s3_access_key/secret/region` — then clobbers the parse-time entry).
   `mc admin trace` shows every brix request signed `Credential=/...` (empty
   access key) → MinIO 403 on all service-signed ops, and the open-flow
   HEAD probes kill reads before per-user `open_cred` signing is reached.
2. Without `brix_export` the authz gate compares raw `//atlas/...` request
   paths against realpath-canonicalized `/atlas/...` rules — nothing matches
   (all ops 3010).  This conf sets `brix_export` to align them.
3. root:// writes to an s3 backend are not wired: `upload_resume on` commits
   via LOCAL rename (EIO, bytes never reach S3); `off` needs RANDOM_WRITE
   which `sd_remote` lacks (kXR 3007 at open).  The vfs staged-multipart
   path is only driven from the HTTP plane.
4. k8s gotcha (worked around here): secret volumes are `..data/` symlinks,
   which the `O_NOFOLLOW` ucred loader refuses — topology-role's
   `role.auth.extraSecret` now dereferences via an `extra-init` container.
