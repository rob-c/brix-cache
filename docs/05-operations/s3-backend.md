# S3 storage backend — operator guide

How to run a brix gateway whose bytes live in a remote S3 bucket
(`brix_storage_backend s3://host[:port]/bucket`), what works on each protocol
plane, how credentials flow to the origin, and how to tell a backend problem
from a gateway problem. (Phase-80; driver: `src/fs/backend/remote/sd_remote.c`
delegating to the shared `sd_s3` libcurl transport.)

## 1. What the backend can and cannot do

The S3 driver is an object-store seam, not a filesystem:

| Operation | Support | Mechanics |
|---|---|---|
| Ranged read (`read`, `readv`, `pgread`) | yes | signed Range GETs, coalesced per request vector; each GET is capped at 7 MiB (`SD_S3_PREAD_MAX`), larger reads loop |
| Whole-file upload (`xrdcp` in, WebDAV PUT) | yes | staged whole-object write: single PUT for small objects, multipart upload with 16 MiB parts (`SD_REMOTE_PART_SIZE`) otherwise |
| Random in-place write (`pwrite` at arbitrary offsets) | **no** | rejected at the capability layer (no `CAP_RANDOM_WRITE`); uploads must be sequential whole-object transfers |
| Delete | yes | S3 DELETE via the driver's `unlink` slot |
| `stat` / size | yes | HEAD request |
| `dirlist`, `mkdir`, `mv` | **no** | fail honestly with `kXR_Unsupported` (3013, "Operation not supported") — never a generic I/O error (P80.4) |

**Sequential-write contract:** clients must write an object front-to-back in
one transfer. `xrdcp` and WebDAV PUT already do this. Anything that seeks
backwards or leaves holes is refused — the object store has no notion of
patching a byte range.

**`brix_upload_resume` on staged-only backends:** the resume path parks bytes
in a local skeleton file and later publishes them with random writes — which
this backend cannot do. On staged-only backends resume is diverted so bytes
always land in the bucket (or the config is rejected loudly); it is never
allowed to silently strand data in the local skeleton. Leave
`brix_upload_resume` off for S3-backed servers unless you have verified the
divert behaviour on your build (P80.2).

## 2. Required export, and the everything-denied trap

An S3-backed server still needs `brix_export` pointing at a real local
directory: the export root anchors path resolution and authorization even
though the bytes are remote.

- **Writes** auto-create the local skeleton directories under the export root;
  you do not need to pre-create the tree.
- **Reads** tolerate a missing skeleton entirely — a fresh gateway can serve
  a populated bucket immediately.

If the server runs in a mode that skips export setup (manager / supervisor /
proxy) **and** has authorization rules (`brix_authdb`, `brix_require_vo`,
`brix_inherit_parent_group`), every request would be denied 3010 — the gate
compares `//<path>` against rules canonicalized to `/<path>` and nothing ever
matches. Since P80.5 this combination is a hard `nginx -t` error
("… requires a runtime export"); the fix is to set `brix_export` or drop the
rules from that server block.

## 3. Credential postures

The gateway signs origin requests with SigV4. Three postures, from simplest
to most granular:

### 3.1 Static service credential

One credential for all users:

```nginx
brix_credential minio {
    s3_access_key AKIA...;
    s3_secret_key ...;
    s3_region us-east-1;      # optional, defaults to us-east-1
}
server {
    ...
    brix_storage_backend s3://minio.example:9000/mybucket;
    brix_storage_credential minio;
}
```

The bucket sees one identity; per-user isolation must come from the gateway's
own authz rules (authdb / VO ACLs).

### 3.2 Per-user credential directory

`brix_storage_credential_dir <dir>;` maps each authenticated principal to its
own origin credential. The filename stem is the principal verbatim when it is
already filesystem-safe (S3/JWT subjects), otherwise `x5h-` + the first 32 hex
chars of the SHA-256 of the DN. For S3 the file is `<stem>.s3`, exactly three
lines, mode 0600:

```
line 1: access key id   (required)
line 2: secret key      (required)
line 3: region          (optional, defaults to us-east-1)
```

Precedence when multiple files exist for the same stem: `.pem` (x509) wins
over `.token` (bearer) wins over `.s3` wins over `.keyring` (CephX). An
**expired `.pem` is a hard decline** — it does not fall through to the
`.token`/`.s3` file for the same user.

### 3.3 Fallback policy — `brix_storage_credential_fallback allow|deny`

- `allow` (default): a user with no per-user credential falls back to the
  static service credential.
- `deny`: no per-user credential → refused with EACCES / `kXR_NotAuthorized`
  **before the origin is ever contacted**.

**The "valid-but-unhonorable credential" rule:** in `deny` mode, a per-user
credential that exists and parses but cannot be honored for the requested
operation is also an EACCES refusal — the gateway never silently substitutes
the service identity in deny mode. If a user reports 3010 on an S3-backed
server in deny mode, check their `.s3` file exists, is 0600-readable by the
worker, and has non-empty key lines before suspecting the bucket policy.

## 4. Kubernetes: secret mounts and `O_NOFOLLOW`

Credential files are opened with `O_NOFOLLOW` (deliberate hardening — do not
weaken it). Kubernetes secret/configmap volumes are `..data/` **symlink
farms**, so a credfile mounted straight from a Secret reads as "credential
missing". The supported pattern (see `topology-role`'s `role.auth.extraSecret`)
is an init container that dereferences the links into an emptyDir:

```yaml
initContainers:
- name: extra-init
  command: ["sh", "-c", "cp -rL /secret-mount/. /creds/"]
```

and point `brix_storage_credential_dir` (or `token_file`, authdb, …) at the
emptyDir copy. Any role that needs server-side files should reuse this
mechanism rather than inventing a new mount.

## 5. Debugging: "is it my bucket or the gateway?"

The attribution test — run the same operation once through each layer:

1. **Origin direct:** `mc` (or `aws s3api`) against the bucket with the exact
   credential the gateway would use (the service cred, or the user's `.s3`
   triple). Failure here = bucket/policy/credential problem, not brix.
2. **Gateway:** the same logical operation via `xrdcp`/`davix` through brix.

Reading the failure when only step 2 fails:

- **3010 `NotAuthorized` in microseconds** (see the brix access log latency
  field): the gateway's own authz gate denied before any VFS or network work —
  authdb/VO rules or deny-mode credential lookup. The bucket was never
  contacted.
- **3013 `Unsupported`**: you asked the object store for a namespace op it
  doesn't implement (`ls`, `mkdir`, `mv`). Expected; not an error to chase.
- **3011/3032 I/O errors after a real delay**: the origin leg — check
  connectivity, TLS, clock skew (SigV4 is time-sensitive), and the origin's
  own logs.
- **Slow large reads**: remember reads are chunked into ≤7 MiB signed GETs;
  origin round-trip latency multiplies accordingly.
- **Interrupted uploads**: verify no multipart residue is accruing:
  `mc ls --incomplete <alias>/<bucket>` should be empty after aborts.

## 6. Plane matrix

| Plane | Read | Write | Notes |
|---|---|---|---|
| root:// (XRootD) | yes | yes (staged) | `pgread`/`readv` vectored reads coalesce into ranged GETs |
| WebDAV | yes | yes (PUT) | COPY/MOVE limited by the namespace-op gaps above |
| S3 front (gateway's own S3 endpoint) | yes | yes | gateway re-signs to the origin; front and origin credentials are independent |

Per-user origin credentials on the write/metadata path require the
`*_cred` driver slots (P80.3); until your build has them, deny-mode per-user
posture is fully enforced on reads, while writes use the service credential
under `allow`.
