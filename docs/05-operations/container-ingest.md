# Container images and folders as a CVMFS filesystem

**Status: source-verified 2026-08-18.** The executable forms of this page are
`tests/test_cvmfs_ingest_dir.py`, `tests/test_cvmfs_ingest_image.py`
(mock registry, block 13640), `tests/test_cvmfs_ingest_oracle.py`
(block 13660, needs podman) and `tests/test_oci_compose_secure.py`
(block 14200).

Companion pages: [cvmfs-stratum0.md](cvmfs-stratum0.md) — the publish plane
this rides on · [oci-registry.md](oci-registry.md) and
[oci-mirror.md](oci-mirror.md) — where the images come from ·
[rpm-on-cvmfs.md](rpm-on-cvmfs.md) — the same trick for an RPM repository.

---

## 1. Why

Pulling a container image copies every layer onto every node that runs it.
Publishing it into CVMFS copies it **once**, and every node mounts the
already-extracted rootfs and reads only the files it actually opens. For a
6 GB image where a job touches 200 MB, that is the difference between a
minute of cold start per node and a few seconds.

Both verbs are unprivileged tool surfaces — no FUSE, no root, no container
engine:

```console
$ brixcvmfs ingest image <ref> --repo <repo_dir> [--prefix /images] \
      [--layout flat|layered]
$ brixcvmfs ingest dir  <src>  --repo <repo_dir> --prefix /sw/foo/1.2
$ brixcvmfs ingest prune       --repo <repo_dir> [--prefix /images] [--keep N]
```

They are **front-ends to the existing publish plane**, not a second
publisher: each builds an overlay upper tree, scans it with
`cvmfs_changeset_scan()`, and hands the changeset to the same engine
`brixcvmfs repo transaction … publish` uses. The transaction lock
(`.brixtxn/lock`) is shared, so an ingest and a hand-made transaction can
never interleave.

---

## 2. `ingest dir` — the folder path

```console
$ brixcvmfs repo mkfs sw.example.org /srv/cvmfs/sw.example.org
$ brixcvmfs ingest dir ./build/rootfs --repo /srv/cvmfs/sw.example.org \
      --prefix /sw/myapp/1.2
```

The source tree is scanned exactly as a transaction upper tree — containment
checks, hardlink groups, xattrs — and the changeset is re-rooted under
`--prefix`.

- Default is **add/overwrite only**. `--delete` marks the prefix root opaque,
  so published content absent from the source is removed (mirror-exact).
- A source tree is *not* an overlay upper, so a name that spells the reserved
  `.brix.wh.` / `.brix.opq` grammar is **refused**, not interpreted.
- Symlinks are stored verbatim, never followed (`--follow-symlinks=no` is the
  only accepted spelling — it names the default).
- `--dry-run` reports the changeset without publishing; `--no-wait` skips the
  post-publish settle.

This is the smallest verb in the phase and the one most sites will use most:
any directory a build produced becomes a versioned, globally-mountable path.

---

## 3. `ingest image` — the container path

```console
$ brixcvmfs ingest image registry.example.org/lab/app:v1 \
      --repo /srv/cvmfs/img.example.org --prefix /images
```

Pipeline: resolve the reference → **memo check** → take the transaction lock
→ fetch layers, hashing on the stream → flatten → write sidecars and the tag
symlink → scan, re-prefix → publish → write the memo and ledger.

### Published layout (DUCC-compatible, flat)

```
<prefix>/.images/sha256/<manifest-hex>/                  the flattened rootfs
<prefix>/.images/sha256/<manifest-hex>/.config.json      image config
<prefix>/.images/sha256/<manifest-hex>/.manifest.json    manifest, verbatim
<prefix>/<host>/<name>:<tag>  →  relative symlink → the digest root
```

Images are addressed by **digest**; the human-readable tag is a relative
symlink. Retagging moves a symlink and no bytes, and one authorization rule
on `<prefix>` covers the whole image space however the tags move.

### Published layout (layered, `--layout layered`)

The flat layout publishes one merged rootfs per image. The CAS already
deduplicates the stored *files* two images share; what it cannot deduplicate
is the **work** — a shared base layer is fetched, inflated and scanned once
per image. `--layout layered` publishes each layer at its own
content-addressed root and gives the image root a descriptor naming them:

```
<prefix>/.layers/sha256/<layer-hex>/                     one layer, flattened
<prefix>/.images/sha256/<manifest-hex>/.layers           the recipe, lowest first
<prefix>/.images/sha256/<manifest-hex>/.config.json      image config
<prefix>/.images/sha256/<manifest-hex>/.manifest.json    manifest, verbatim
<prefix>/<host>/<name>:<tag>  →  relative symlink → the digest root
```

`.layers` holds one relative path per line, lowest layer first:

```
../../../.layers/sha256/9f3c…
../../../.layers/sha256/2b71…
```

Publishing three images off one base fetches and flattens that base **once**;
the two children pay only for their own top layers. Reuse is decided from
`<repo>/.brix-ingest/layers<prefix>/<layer-hex>`, written after the publish
that materialized the layer — an advisory ledger like the memo, so a failed
ledger write warns and never rolls back a publish.

`<prefix>/.layers` is the tool's own namespace, like the digest root: two
images sharing a base both `ADD` the same layer root, so the overlap guard
does not apply there. `--verify-diffids` composes with reuse — the ledger
records each layer's diff_id, and a layer published before the flag existed
(no recorded diff_id) is materialized again rather than silently skipped.

**Limitation, stated plainly:** a layered image root is *not* a runnable
rootfs. `podman run --rootfs /cvmfs/<repo>/<prefix>/<host>/<name>:<tag>`
needs the flat layout. A layered image needs a consumer that composes the
roots — an overlayfs mount with the `.layers` lines as `lowerdir=`, **lowest
last** (overlayfs orders `lowerdir` top-first, `.layers` lists bottom-first).
Flat stays the default for exactly that reason.

### Incremental by memo

`<repo>/.brix-ingest/memo<flat-path>` records the manifest digest a tag last
resolved to. Re-running with an unchanged digest is a **no-op** — no fetch,
no publish, no transaction. That is what makes `ingest image` safe to put in
a cron or a CI step: the cost of "already current" is one HEAD.

### Pinning what you ingest — `--require-digest`

Every byte that lands in the tree is verified: the manifest digest pins the
config and layer digests, and each is checked on receipt (`--verify-diffids`
extends that through the uncompressed layers). What none of it proves is
that the *manifest* is the one you meant. `app:v1` is a name the registry
can repoint at any time — legitimately, by a re-push, or otherwise — so two
ingests of the same command can publish different software and neither run
has anything to complain about.

```sh
brixcvmfs ingest image registry.example.org/lab/app@sha256:9f3c… \
    --repo /srv/cvmfs/img.example.org --require-digest
```

`--require-digest` refuses any reference that does not carry `@sha256:<hex>`,
exiting **2** (usage) before the first request leaves the host. Only you know
whether a given ingest is a pinned deployment or a deliberate follow-the-tag
mirror, which is why this is a flag and not the default — but for anything
reproducible (a release tree, a CI-published environment, anything an audit
will ask about later), it is the line that makes the reference mean one
thing forever.

Pair it with the memo: a pinned ref that is already published is the same
one-HEAD no-op, so pinning costs nothing in the steady state.

### Flattening rules

`shared/oci/flatten.c` applies layers in manifest order into an upper tree:
OCI `.wh.<name>` becomes `.brix.wh.<name>` and `.wh..wh..opq` becomes the
opaque marker, so the changeset scanner sees an ingested image exactly as it
sees a hand-edited tree.

Every write descends from an `O_DIRECTORY` dirfd with per-component
`O_NOFOLLOW openat` — never a joined string path. A layer that plants a
symlink and a later layer that writes through it hits the containment wall
at the component. Layers that name the reserved marker grammar themselves
are refused: **layers do not get to smuggle whiteouts.**

| Flag | Effect |
|---|---|
| `--platform os/arch` | which manifest to select from an index |
| `--squash-owner U:G` | rewrite every owner (the usual answer for an unprivileged publisher) |
| `--max-bytes N` | decompression-bomb budget for the **whole image**, not per layer |
| `--strict` | device nodes and FIFOs are fatal instead of skipped-and-counted |
| `--tag-path name:tag-dir` | override where the tag symlink lands |
| `--force-overlap` | permit an ADD that would retype an existing published non-directory |
| `--insecure`, `--token-file F` | cleartext/lab registries; bearer for a private one |

Foreign layers (Windows base images) are refused with a clear message.

### Lazy-pull layer encodings

eStargz and `zstd:chunked` layers ingest like any other. Both are ordinary
tars in a *chain* — eStargz one gzip member per file (plus its TOC member and
a footer), `zstd:chunked` one zstd frame per file with the TOC in trailing
skippable frames — and the reader follows the chain to its end rather than
stopping at the first unit. eStargz's own entries (`stargz.index.json` and the
two prefetch landmarks) are dropped at the archive root, so the published
rootfs is the one the unconverted image would have given you; they are counted
separately from the files that land. `zstd`-compressed layers need a build
with `libzstd` (`pkg-config --exists libzstd` at configure time); without it
such a layer is refused with a message naming the missing dependency, never
half-read.

Producing an eStargz image is `brixoci convert --estargz` (see
`oci-registry.md`); ingesting the result is this same path, and it publishes
the same rootfs the unconverted image publishes.

Serving those layers to a *containerd snapshotter* is a different thing and is
not implemented — that wants an out-of-tree containerd plugin, which is Go
inside containerd's process. Everything on this side of that boundary is
here: reading their blobs correctly, writing eStargz, and `Range` on blobs,
which both `/v2/` surfaces already answer.

A crash before the publish leaves only scratch, reaped on the next run; the
publish engine's manifest-swap-last gives the rest crash-safety for free.

### Retiring old images

```console
$ brixcvmfs ingest prune --repo /srv/cvmfs/img.example.org --keep 3
```

Referenced = named by **any** memo (a root stays while any tag anywhere
points at it). Unreferenced roots are ordered newest-first; `--keep N` spares
the N newest and the rest go in one publish. Ledger entries are unlinked
after the publish, so a crash between the two leaves a re-prunable entry,
never a dangling root.

Prune runs in **two ordered passes, never merged into one publish**: image
roots first, then layer roots. A layer root is retired when no surviving
image's `imglayers` record names it — so the image pass has to have landed
before the layer pass can tell an orphan from a shared base. Pass 2 runs even
when pass 1 found nothing, since a root can also be removed some other way,
and reports separately:

```
pruned 2 root(s) under /images (revision 41)
pruned 3 layer root(s) under /images (revision 42)
```

`--dry-run` lists both passes (`would prune …` / `would prune layer …`)
without publishing either. A flat repository has no layer ledger, so pass 2
finds nothing and stays silent.

---

## 4. Serving what you ingested

An ingested tree is ordinary published content. Serve the repository as a
Stratum-0 ([cvmfs-stratum0.md](cvmfs-stratum0.md)):

```nginx
location /cvmfs/ {
    brix_cvmfs               on;
    brix_cvmfs_stratum0_root /srv/cvmfs;
}
```

Private images get the scvmfs gate on their own listener. The gate is
**TLS-only by construction** — a cleartext request is refused before any
credential is examined — so there is no way to also serve a gated repository
on port 80:

```nginx
server {
    listen 8443 ssl;
    ssl_certificate        /etc/brix/host.crt;
    ssl_certificate_key    /etc/brix/host.key;
    ssl_client_certificate /etc/brix/clients-ca.crt;
    ssl_verify_client      optional;

    location /cvmfs/ {
        brix_cvmfs               on;
        brix_cvmfs_stratum0_root /srv/cvmfs;
        brix_scvmfs              on;
        brix_scvmfs_authz        x509;
        brix_scvmfs_x509_dn      "*CN=release-bot*";
    }
}
```

Anonymous → `401`; a certificate that verifies against the CA but is not
listed → `403`. Put private images in a **repository** of their own rather
than a subtree: authorization maps to a path prefix, and a repository name
is the only prefix the client and the server already agree on.

The same tree also re-exports over the other read planes where configured —
a read-only WebDAV view of the materialized software area serves consumers
with no CVMFS client. That needs its own listener: **one brix protocol per
port**, and the server refuses an ambiguous configuration at startup rather
than guessing.

---

## 5. Composition: one box, three surfaces

`deploy/oci-mirror/full-stack.conf.example` is the whole story in one file —
`/v2/` mirroring an upstream, `/local/v2/` accepting your own pushes,
`/cvmfs/` serving the images ingested from either, and a TLS listener for the
private tree. It is pure configuration: deleting any one location leaves the
others byte-identical in behaviour.

On the consuming side, a site fronts the origin and unions the image
repository behind its main software repository, so a worker node mounts
exactly one name:

```nginx
location /cvmfs/ {
    brix_cvmfs              on;
    brix_storage_backend    https://s0.example.org;
    brix_cache_store        posix:/var/cache/brix/cvmfs;
    brix_cvmfs_virtual_repo sw.example.org main.example.org img.example.org;
    brix_cvmfs_repo_authz   img.example.org /etc/brix/scitokens.cfg;
}
```

Declaration order is precedence, and **only a 404 advances the walk**. A
401/403/5xx from a member is terminal: composition never elevates access, and
an unauthorized read of a gated member can never fall through to whatever an
ungated sibling happens to hold at the same path. `brix_cvmfs_repo_authz`
answers `400` to a cleartext request and `401` to any bearer it will not
accept — missing, expired, forged or out of scope alike.

---

## 6. Running an image straight off the mount

```console
$ export BRIXCVMFS_SERVER=https://s0.example.org BRIXCVMFS_PUBKEY=/etc/brix/keys/img.pub
$ brixMount cvmfs img.example.org /cvmfs/img.example.org -o auto_unmount,allow_other -f &
$ podman run --rm \
      --rootfs /cvmfs/img.example.org/images/registry.example.org/lab/app:v1:O \
      /bin/app
```

(`brixMount autofs` gives the same tree on demand under a `/cvmfs` root —
see [cvmfs-automount.md](cvmfs-automount.md).)

Two rootless traps, both of which surface as a misleading `ENOENT`:

1. the mount needs `-o allow_other` **and** `user_allow_other` in
   `/etc/fuse.conf`, or podman's user namespace cannot see into it;
2. podman's pause process snapshots the mount table at first use — a mount
   created afterwards does not exist inside the namespace until
   `podman system migrate`.

The `:O` suffix asks podman for an overlay on top of the read-only rootfs,
which is what lets the container write to `/tmp` without touching CVMFS.

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ingest image` does nothing and exits 0 | the memo says this tag already resolves to this digest | that is the incremental path working; `--dry-run` shows the same verdict |
| `ingest image` exits 2 naming `--require-digest` | the reference is a tag, and this run asked for a pinned one | resolve the tag once without the flag and re-run against the `@sha256:…` the memo recorded, or drop the flag if following the tag is what you meant |
| refusal naming `.brix.wh.` | a source name or a layer entry spells the reserved grammar | rename it; the grammar is not interpretable from untrusted input |
| publish fails on a structural ADD | something published at `<prefix>/<host>/…` is not a directory | `--force-overlap`, deliberately |
| budget exhaustion mid-image | `--max-bytes` bounds the **whole** image | raise it, or ingest a slimmer image |
| `ENOENT` from `podman run --rootfs` | §6, one of the two traps | `allow_other` + `podman system migrate` |
| a gated repo answers 400 to a working token | the request was cleartext | the gate is TLS-only; use the TLS listener |
