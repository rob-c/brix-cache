# Deploy a CVMFS Stratum-0 with BriX — unprivileged cookbook

How to publish your own files into a CVMFS repository and serve them as the
master copy, start to finish, as an **ordinary user**: no root, no `cvmfs_server`,
no Apache, no overlayfs, no kernel automount. Two pieces do all of it — the
`brixcvmfs` client binary (release-manager surface: `brixcvmfs repo …`) and one
nginx directive (`brix_cvmfs_stratum0_root`).

The split matters and is enforced, not conventional: **publishing happens on the
tool surface and the server never writes.** `brixcvmfs repo publish` produces an
on-disk tree; nginx serves that tree read-only and 405s every write method. A
compromised web tier cannot mint a revision.

Every command and every output in this page is exercised by
`tests/test_cvmfs_stratum0_quickstart.py`, which drives the *installed* binary
through this exact sequence — documentation drift fails that lane. The
byte-level anatomies (manifest, whitelist, catalog schema, CAS naming, client
cache) are dumps of a real repository, not illustrations.

- Protocol contract for the serve plane: [`docs/04-protocols/cvmfs.md` §3.6](../04-protocols/cvmfs.md)
- Site-cache (Stratum-1 consumer) deployment: [`deploy/cvmfs/README.md`](../../deploy/cvmfs/README.md)
- Client-side `/cvmfs` automounting: [cvmfs-automount.md](cvmfs-automount.md)
- Directive reference: [`docs/03-configuration/directives.md`](../03-configuration/directives.md)
- Command reference: `man brixcvmfs` (`client/man/brixcvmfs.1`)

---

## Table of contents

| § | Section | Read it when |
|---|---|---|
| 0 | [The whole thing in ten commands](#0-the-whole-thing-in-ten-commands) | you want the shape before the detail |
| 1 | [Architecture and vocabulary](#1-architecture-and-vocabulary) | first time; or before debugging anything |
| 2 | [Prerequisites](#2-prerequisites) | planning the deployment |
| 3 | [Create the repository](#3-create-the-repository) | day one |
| 4 | [Publish your custom files](#4-publish-your-custom-files) | every release |
| 5 | [Serve it](#5-serve-it) | day one, then never again |
| 6 | [Mount it](#6-mount-it) | validating what you published |
| 7 | [Private repositories](#7-private-repositories) | the data is not public |
| 8 | [Maintenance](#8-maintenance) | before you go to production |
| 9 | [The integrity model](#9-the-integrity-model) | security review |
| 10 | [Troubleshooting](#10-troubleshooting) | something is wrong |
| 11 | [Reference](#11-reference) | you know what you want, need the syntax |
| 12 | [Coverage and implementation map](#12-coverage-and-implementation-map) | you are changing the code |

---

## 0. The whole thing in ten commands

```sh
# --- create ---------------------------------------------------------------
mkdir -p ~/stratum0/cvmfs
brixcvmfs repo mkfs sw.example.org ~/stratum0/cvmfs/sw.example.org

# --- publish --------------------------------------------------------------
REPO=~/stratum0/cvmfs/sw.example.org
brixcvmfs repo transaction $REPO
cp -a /path/to/release/* $REPO/.brixtxn/upper/
brixcvmfs repo publish $REPO
brixcvmfs repo fsck $REPO

# --- serve ----------------------------------------------------------------
nginx -c ~/stratum0/nginx.conf -p ~/stratum0     # one location block, §5

# --- consume --------------------------------------------------------------
BRIXCVMFS_SERVER=http://localhost:8080/cvmfs/sw.example.org \
BRIXCVMFS_PUBKEY=$REPO/keys/sw.example.org.pub \
brixcvmfs --check sw.example.org
```

Everything else on this page is detail, hardening and maintenance for those ten
lines.

---

## 1. Architecture and vocabulary

### 1.1 Where a Stratum-0 sits

CVMFS is a one-way content distribution network. The Stratum-0 is the single
writable origin; everything downstream is a read-only cache that can be rebuilt
from it.

```
   PUBLISHER            ORIGIN                REPLICAS            SITE CACHES        CLIENTS
   (release mgr)       (Stratum-0)           (Stratum-1)           (proxies)         (jobs)

   brixcvmfs repo         nginx +             cvmfs_server         nginx BriX        cvmfs2 /
   transaction     --->   brix_cvmfs_    ---> add-replica    --->  cache node  --->  brixcvmfs
   publish                stratum0_root       (or BriX)            (squid-like)      FUSE mount
      |                        |                   |                    |                |
      | writes files           | serves bytes      | pulls over HTTP    | caches         | verifies
      | signs manifest         | verifies nothing  | serves the same    | immutables     | every object
      |                        |                   |   signed manifest  |                |
      v                        v                   v                    v                v
   +--------+            +-----------+       +-----------+       +-----------+     +-----------+
   | repo   | =========> |  HTTP GET | ====> |  HTTP GET | ====> |  HTTP GET | ==> | POSIX     |
   | on disk|            |  read-only|       |           |       |           |     | read-only |
   +--------+            +-----------+       +-----------+       +-----------+     +-----------+

   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   this page: the two boxes on the left        (site caches: deploy/cvmfs/README.md)
```

You do not need any of the downstream tiers to have a working repository — a
Stratum-0 plus a client is a complete, correct CVMFS deployment. Replication is
an availability decision, not a correctness one.

### 1.2 The write boundary

The most important structural fact about this design: **the code that can create
a revision is not running in the server.**

```
        TOOL SURFACE                     |          SERVE PLANE
        (your shell, your uid)           |          (nginx worker)
                                         |
   brixcvmfs repo publish                |     ngx_http_brix_cvmfs_*
     |                                   |       |
     +-- reads  .brixtxn/upper/**        |       +-- classifies the URL
     +-- writes data/**  (CAS puts)      |       +-- serves bytes from disk
     +-- writes .cvmfsreflog             |       +-- 405s every write method
     +-- signs  .cvmfspublished          |       +-- never opens a key
     +-- renames it into place  <--------|-------    never writes a byte
                                         |
        linked against shared/cvmfs/     |     linked against src/protocols/cvmfs/
        publish/ + signature/            |     (no publish/, no signature private key)
                                         |
   ======================================+======================================
        can mint a revision              |          cannot mint a revision
```

Consequences worth internalising: an attacker who owns the web tier can delete
or corrupt bytes (denial of service, detected — §9) but cannot forge content
that any client accepts; and you can serve a repository from infrastructure you
do not trust, including a shared CDN or someone else's object store fronted by
HTTP.

### 1.3 Vocabulary

| Term | What it is | Where it lives |
|---|---|---|
| **FQRN** | fully-qualified repository name, e.g. `sw.example.org` | manifest `N`, every client mount, the URL path |
| **Revision** | one atomic snapshot of the whole tree; monotonically increasing | manifest `S` |
| **Manifest** | `.cvmfspublished` — signed pointer to the root catalog; the entry point | repo root |
| **Whitelist** | `.cvmfswhitelist` — masterkey-signed, time-limited list of allowed certificate fingerprints | repo root |
| **Certificate** | short-lived signing identity for manifests; itself a CAS object (`X`) | `keys/` + `data/` |
| **Catalog** | SQLite database holding one directory subtree's metadata | CAS object (`C`) |
| **Nested catalog** | a catalog for a subtree, mounted lazily by clients | CAS object (`C`) |
| **CAS object** | immutable content-addressed blob under `data/` | `data/<2>/<38>[suffix]` |
| **Chunk** | fixed-size slice of a large file, addressed independently | CAS object (`P`) |
| **Reflog** | `.cvmfsreflog` — SQLite log of every object a revision anchored; the GC root set | repo root |
| **Tag** | named, pinned revision; survives GC | history object (`H`) |
| **Transaction** | an open staging directory plus an exclusive lock | `.brixtxn/` |

---

## 2. Prerequisites

| Need | Why | Note |
|---|---|---|
| `brixcvmfs` (or `brixMount`) | mkfs / publish / maintenance, and the client mount | `make -C client brixMount brixcvmfs`; `brixcvmfs` is a symlink to `brixMount` selected by `argv[0]` |
| nginx with the BriX module | the serve plane | any listener ≥ 1024 works as a non-root user |
| Disk for the repo tree | content-addressed objects + catalogs | roughly the compressed size of the payload, plus retained older revisions until `gc` |
| `/dev/fuse` | **only** to mount the result locally | not needed to publish or serve |

No system packages, no `/etc/cvmfs` writes, no service account. Everything below
runs as `$USER` and writes only under directories you own.

`brixcvmfs <args>` and `brixMount cvmfs <args>` are the same code path — the
personality is chosen by program name. Use whichever reads better in your
scripts; this page uses `brixcvmfs`.

### Is a Stratum-0 what you want?

```
   Do you need to PUBLISH files that you own?
     |
     +-- yes --> Do clients need to see updates as atomic, signed revisions?
     |             |
     |             +-- yes --> STRATUM-0 (this page)
     |             +-- no  --> a plain HTTP export (brix_export) is simpler
     |
     +-- no  --> Are you caching someone ELSE's repository for a site?
                   |
                   +-- yes --> cache node: brix_cvmfs_upstream_allow + brix_cache_store
                   |           (deploy/cvmfs/README.md — NOT this page)
                   +-- no  --> you want a client mount only (§6, cvmfs-automount.md)
```

A Stratum-0 and a cache node are mutually exclusive in one location block, and
that exclusion is enforced at `nginx -t` (§5).

---

## 3. Create the repository

### 3.1 Choose the name and the path

Pick a **fully-qualified repository name** (FQRN) — a DNS-like name of the form
`<repo>.<your-domain>`, e.g. `sw.example.org`. It is baked into the signed
manifest and into every client mount, so choose it once.

The repository must end up at `<webroot>/cvmfs/<fqrn>/` because the serve
directive is a strict alias for `brix_export` (URI path = fs path):

```
   brix_cvmfs_stratum0_root  /home/you/stratum0
                             `-------.-------'
                                     |  the URI is appended verbatim
   GET /cvmfs/sw.example.org/.cvmfspublished
       `--------------.--------------------'
                      |
   open("/home/you/stratum0" "/cvmfs/sw.example.org/.cvmfspublished")
        `-------.-------'  `------------.----------------------'
             the root            the request URI, unmodified
```

Point the directive at the directory **above** `cvmfs/`. Pointing it *into*
`cvmfs/` is the single most common misconfiguration and shows up as 403 on
everything (§10).

Create the parent yourself; `mkfs` creates the leaf directory only and refuses
to create parents:

```sh
mkdir -p ~/stratum0/cvmfs
brixcvmfs repo mkfs sw.example.org ~/stratum0/cvmfs/sw.example.org
```

```
repository sw.example.org created at /home/you/stratum0/cvmfs/sw.example.org
  revision 1, root catalog c123b8a99a9a98b877ef4cdb5d42daa13c665557
  keys in /home/you/stratum0/cvmfs/sw.example.org/keys (public key: sw.example.org.pub)
```

`mkfs` mints the RSA master key pair, the repository certificate and key, a
30-day signed whitelist, an empty root catalog, and the signed manifest at
revision 1. The repository is already valid and mountable — just empty.

### 3.2 What is on disk

```
~/stratum0/cvmfs/sw.example.org/
│
├── .cvmfspublished        signed manifest — THE entry point, swapped atomically
│                          (mutable, ~300 B + signature)
├── .cvmfswhitelist        masterkey-signed certificate whitelist, 30-day expiry
│                          (mutable, re-minted by `repo resign`)
├── .cvmfsreflog           SQLite: every object anchored by a live revision
│                          (mutable, the GC root set)
│
├── data/                  content-addressed store — IMMUTABLE, append-only
│   ├── a0/e49b39d0a7c0091714003e6f9baec661fe8bfb      whole file
│   ├── c3/457b662d5fbb873c079a123e0a7f03c0f921d0X     certificate
│   ├── e7/3ee935ad4a9c79575514cff4b27048e9df9285C     root catalog (rev 2)
│   └── ea/6800012c3c5cacd0b3f846a975936af402c608C     root catalog (rev 1, retained)
│
├── keys/                  see §3.6 — move this out of the served tree if you can
│   ├── sw.example.org.masterkey    RSA private — repository IDENTITY
│   ├── sw.example.org.pub          RSA public  — client trust anchor
│   ├── sw.example.org.crt          certificate (also stored as the X object)
│   └── sw.example.org.key          certificate private key
│
└── .brixtxn/              present only while a transaction is open (§4)
    ├── lock               O_CREAT|O_EXCL, holds pid + boot id
    └── upper/             your staging tree
```

Only three files at the top are ever rewritten. Everything under `data/` is
write-once — which is what makes the whole thing cacheable forever and safe to
replicate by dumb byte copy.

### 3.3 CAS object naming

```
   data/e7/3ee935ad4a9c79575514cff4b27048e9df9285C
        \/ \____________________________________/|
        |                  |                     |
        |                  |                     +-- suffix: object kind
        |                  |                          (none) whole file content
        |                  |                          C      catalog (SQLite)
        |                  |                          X      certificate (PEM)
        |                  |                          P      file chunk
        |                  |                          H      history / tag db
        |                  |
        |                  +-- SHA-1 hex digits 3..40
        +-- SHA-1 hex digits 1..2  (fan-out directory, 256 buckets)

   identity = SHA-1( the bytes AS STORED )        <-- note: stored, not plaintext
```

Objects are zlib-deflated and then hashed **in their stored form**; the reader
(`shared/cvmfs/object/object.c`) and the publisher
(`shared/cvmfs/object/object_write.c`) agree on that one rule, so integrity
checking never has to decompress:

```
   plaintext bytes ──deflate──> stored bytes ──sha1──> object name
                                     |                     |
                                     +---------------------+
                                  fsck --data re-derives this pair
                                  without inflating anything (§9)
```

Two consequences: deduplication happens on compressed bytes (identical input
deflates identically, so it still works file-to-file and revision-to-revision),
and a rot check is a straight read-and-hash at disk speed.

### 3.4 The manifest, byte for byte

`.cvmfspublished` from a real two-revision repository:

```
   Ce73ee935ad4a9c79575514cff4b27048e9df9285   <- C  root catalog object hash
   B45056                                      <- B  root catalog size, uncompressed
   Rd41d8cd98f00b204e9800998ecf8427e           <- R  md5("") — root path, always this
   Xc3457b662d5fbb873c079a123e0a7f03c0f921d0   <- X  certificate object hash
   Y9e8cd502bf9a67e03aca1eb50814d852110c3777   <- Y  reflog checksum
   Gyes                                        <- G  garbage-collectable
   Ano                                         <- A  alternative root path: no
   S2                                          <- S  REVISION
   Nhp.example.org                             <- N  FQRN
   T1785892139                                 <- T  publish timestamp (unix)
   D240                                        <- D  TTL in seconds
   --                                          <- end of signed body
   <sha1 of everything above, as hex text>
   <256 raw bytes: RSA-2048 signature>         <- 297-byte signature block
```

An `H<hash>` line appears once the repository has tags (§8.5). The signature
covers everything up to and including the `--\n`, so a single flipped byte
anywhere above invalidates the revision.

### 3.5 The trust chain

Two different RSA conventions are in play; conflating them produces repositories
that verify in one stack and fail in the other, so they are worth seeing laid
out:

```
   masterkey  (offline, never on the web tier)
      |
      | raw RSA over the ASCII hash text (no DigestInfo)
      v
   .cvmfswhitelist ────────────────────────────────────┐
      |  20260805010859        <- created (UTC, 14 digits)
      |  E20260904010859       <- expiry  <-- 30 days; `resign` moves this
      |  Nhp.example.org       <- FQRN binding
      |  7F:B5:67:...:2B:98    <- ALLOWED CERTIFICATE FINGERPRINT (SHA-1)
      |  --                                            |
      v                                                | client checks:
   certificate (X object)  ── fingerprint must match ──┘  1. whitelist sig vs .pub
      |                                                   2. not expired
      | PKCS#1 v1.5 over a SHA-1 DigestInfo               3. cert fp is listed
      v                                                   4. manifest sig vs cert
   .cvmfspublished  ── C ──> root catalog (C object)
                                 |
                                 +-- nested_catalogs rows --> nested C objects
                                 +-- catalog rows ----------> content objects
                                 +-- chunks rows -----------> P objects
                                       (every hop verified by SHA-1 on fetch)
```

The client's trust anchor is exactly one file: `<fqrn>.pub`. Everything else —
certificate, manifest, catalogs, content — is authenticated transitively from
it. That is why the public key must reach clients out of band, and why the
masterkey must not live on the machine that serves HTTP.

### 3.6 Keys

| File | Role | Handling |
|---|---|---|
| `<fqrn>.masterkey` | signs the whitelist | **the identity of the repository** — back it up offline; losing it means clients must be re-keyed |
| `<fqrn>.pub` | master public key | ship this to every client; it is the whole client-side trust anchor |
| `<fqrn>.crt` / `.key` | repository certificate, signs manifests | rotatable: `mkfs`/`resign` reuse whatever is present in the keys directory |

Keys default to `<repo_dir>/keys`, which is *inside* the served directory. That
is safe by construction — the serve plane answers only CVMFS traffic shapes, so
`GET /cvmfs/<fqrn>/keys/<fqrn>.masterkey` is a 403, as is anything under
`.brixtxn/` (§5.3) — but defence in depth is cheap. Pass a keys directory
explicitly and give it to every subsequent command that takes one:

```sh
mkdir -p ~/stratum0-keys && chmod 700 ~/stratum0-keys
brixcvmfs repo mkfs sw.example.org ~/stratum0/cvmfs/sw.example.org ~/stratum0-keys
```

```
   RECOMMENDED SPLIT

   offline / vault          publisher host             web tier
   +---------------+        +------------------+       +--------------+
   | *.masterkey   |  --->  | *.crt  *.key     |       |  (no keys)   |
   | *.pub  (copy) |        | *.pub            |       |              |
   +---------------+        +------------------+       +--------------+
     needed only for          needed for every           needed never
     `resign` and for         `publish` (manifest
     minting a whitelist      signature)
```

`resign` needs the masterkey; `publish` does not. If you keep the masterkey
offline, run `resign` on the vault host against the repository over a share, or
mint a longer-lived whitelist on the vault host and copy it in.

Only `<fqrn>.pub` needs to be readable by clients; distribute it out of band (or
from a separate location) rather than relying on the served copy.

### 3.7 Check it any time

```sh
brixcvmfs repo info ~/stratum0/cvmfs/sw.example.org
```

```
repository ...... sw.example.org
revision ........ 1
root catalog .... c123b8a99a9a98b877ef4cdb5d42daa13c665557 (1218 bytes stored)
certificate ..... cec314e689b555626bec38d77820858a4aa2d334
published ....... 1785890584  (ttl 240s)
trust chain ..... OK
```

`trust chain ..... OK` means the whitelist signature, the certificate and the
manifest signature all verify with the same parsers the client and the proxy
use — not a self-report.

---

## 4. Publish your custom files

### 4.1 The loop

```sh
REPO=~/stratum0/cvmfs/sw.example.org

brixcvmfs repo transaction $REPO
# → transaction open: /home/you/stratum0/cvmfs/sw.example.org/.brixtxn/upper

UPPER=$REPO/.brixtxn/upper
mkdir -p $UPPER/tools $UPPER/data/samples
printf '# quickstart repo\n'                       > $UPPER/README.md
printf '#!/bin/sh\necho hello from stratum-0\n'     > $UPPER/tools/hello.sh
chmod 755 $UPPER/tools/hello.sh
cp -a /path/to/release/*                             $UPPER/data/samples/
ln -s tools/hello.sh $UPPER/run-me

brixcvmfs repo publish $REPO
# → published revision 2
```

The staging tree is a plain directory. Anything you can create with ordinary
tools — `cp`, `rsync`, `tar -x`, a build system's `make install DESTDIR=$UPPER`
— is a valid changeset. File modes, executable bits, symlinks, hardlinks and
nested directories survive verbatim into the mounted repository.

### 4.2 Transaction lifecycle

```
                  +-------------------------------------------------+
                  |                                                 |
                  v                                                 |
        +------------------+   transaction    +------------------+  |
        |      IDLE        | ---------------> |      OPEN        |  |
        |  no .brixtxn/    |                  |  .brixtxn/lock   |  |
        |                  | <--------------- |  .brixtxn/upper/ |  |
        +------------------+     abort        +------------------+  |
                  ^              (discards)            |            |
                  |                                    | publish    |
                  |                                    v            |
                  |                          +------------------+   |
                  +------------------------- |   PUBLISHED      | --+
                       lock+upper removed    |  revision N+1    |
                                             +------------------+

   transaction while OPEN  -> refused: "repository is in a transaction (pid): N"
   publish   while IDLE    -> refused: "no open transaction under <repo>"
   gc        while OPEN    -> refused
```

The lock (`.brixtxn/lock`, `O_CREAT|O_EXCL`, recording pid and boot id) is
**never broken automatically**, because breaking it would discard staged writes.
A second `transaction` fails and names the holding pid. Retire a transaction
explicitly:

```sh
brixcvmfs repo abort $REPO      # discard everything staged
```

### 4.3 The staging overlay

The staging tree is an overlay over the published revision: it can add and
replace, and it deletes through whiteout markers.

```
   PUBLISHED rev 2                 .brixtxn/upper                  RESULT rev 3
   +---------------------+         +---------------------+         +---------------------+
   | README.md      "v2" |         | README.md      "v3" | ------> | README.md      "v3" |
   | tools/hello.sh      |         |                     |  keep   | tools/hello.sh      |
   | data/samples/a.dat  |         | .brix.wh.a.dat      | ------> |  (a.dat DELETED)    |
   | data/samples/b.dat  |         |                     |  keep   | data/samples/b.dat  |
   |                     |         | tools/new.sh        | ------> | tools/new.sh        |
   +---------------------+         +---------------------+         +---------------------+
        untouched files are not re-read, not re-hashed, not re-stored
```

```sh
touch $UPPER/data/samples/.brix.wh.a.dat      # deletes data/samples/a.dat
```

Modifying is just staging the new content at the same path. One publish can add,
modify and delete in any combination; it becomes exactly one new revision.

### 4.4 What publish actually does

```
   .brixtxn/upper/**                                       (1) SCAN
        |  walk the staging tree, resolve whiteouts
        v
   changeset: [ADD_DIR|ADD_FILE|ADD_LINK|DELETE] x N        (2) CHANGESET
        |
        |  for each change, find the catalog that owns the path
        v
   +----------------------------------------------+        (3) ROUTE
   | root catalog  <- /README.md, /tools/hello.sh  |
   | /data/samples <- /data/samples/*              |   (nested catalogs are
   +----------------------------------------------+    materialized from CAS
        |                                               only if touched)
        |  files: read -> [chunk if > chunk-size] -> deflate -> sha1
        v         -> immutable-put at data/<2>/<38>[P]
   CAS puts (idempotent; re-storing an existing object is a no-op)   (4) INGEST
        |
        v
   catalog upserts (SQLite rows: mode, size, mtime, uid, gid,        (5) UPSERT
   hardlink group, symlink target, xattrs, content hash / chunk map)
        |
        |  bottom-up: a rewritten nested catalog updates its parent's
        |  nested_catalogs row, up to the root
        v
   recompute self_* and subtree_* counters, set revision property    (6) FINALIZE
        |
        v
   deflate + store each dirty catalog (C object)                     (7) STORE
        |
        v
   append every anchored hash to .cvmfsreflog                        (8) REFLOG
        |
        v
   build manifest body, sign with the certificate key                (9) SIGN
        |
        v
   rename(tmp, .cvmfspublished)   <-- ATOMIC, LAST, POINT OF NO RETURN  (10) SWAP
```

Steps 1–9 write only new, unreferenced objects. Until step 10, clients see the
previous revision, in full.

### 4.5 Chunking large files

Files larger than the chunk size are split so clients fetch only what they read.
The default is 32 MiB; the floor is 4096 bytes (smaller is refused).

```sh
brixcvmfs repo publish $REPO --chunk-size 4096
```

```
   big.dat, 56000 bytes, --chunk-size 4096
   +------+------+------+------+------+------+------+------+ ... +------+
   | 4096 | 4096 | 4096 | 4096 | 4096 | 4096 | 4096 | 4096 |     | 2624 |   14 slices
   +---+--+---+--+---+--+---+--+---+--+---+--+---+--+---+--+     +---+--+
       |      |      |      |      |      |      |      |           |
       |      |      +------+------+------+------+------+           |     identical
       |      |             (repeated content collapses)            |     slices ->
       v      v                        v                            v     same sha1
   +--------+--------+ ................................. +--------+       -> stored
   |   P    |   P    |     8 distinct P objects on disk  |   P    |          once
   +--------+--------+ ................................. +--------+

   catalog row for big.dat:  flags = FILE|FILE_CHUNK,  size = 56000
   chunks table:             (offset 0, 4096, hash) (offset 4096, 4096, hash) ...
                             14 rows -> 8 unique objects
```

The same deduplication applies across files and across revisions — republishing
an unchanged file costs nothing but a catalog row. A client reading bytes
20000–24000 fetches exactly one 4096-byte object.

### 4.6 Nested catalogs

A single catalog for a huge tree makes every client download the whole thing.
Split it with a `.cvmfsdirtab`-style policy file (same syntax as the official
server: one glob per line, `!` to exclude, **last match wins**):

```sh
cat > ~/dirtab <<'EOF'
/data/samples/*
!/data/samples/tiny
EOF
brixcvmfs repo publish $REPO --dirtab ~/dirtab
```

```
   DIRTAB EVALUATION (fnmatch, top to bottom, last match wins)

     /data/samples/*        -> matches /data/samples/alpha   : NEST
                            -> matches /data/samples/tiny    : NEST
     !/data/samples/tiny    -> matches /data/samples/tiny    : do NOT nest  <-- wins

   RESULTING CATALOG TREE

     root catalog  (/)
       ├── README.md, tools/**, data/            rows in the ROOT catalog
       ├── nested_catalogs: /data/samples/alpha -> sha1, size
       └── nested_catalogs: /data/samples/beta  -> sha1, size
            |
            +--> catalog /data/samples/alpha     mounted lazily by the client
            +--> catalog /data/samples/beta      only when that path is entered

     /data/samples/tiny stays inline in the root catalog (excluded above)

   PUBLISH COST: touching /data/samples/beta/x rewrites
     beta's catalog  ->  root's nested_catalogs row  ->  root catalog  ->  manifest
   alpha is never opened, never re-signed, never re-stored.
```

### 4.7 Inside a catalog

Each catalog is a plain SQLite database, stored as one `C` object:

```
   catalog          md5path_1, md5path_2,        <- 128-bit md5 of the path, split
                    parent_1, parent_2,             (root row carries 0,0)
                    hardlinks, hash BLOB, size,
                    mode, mtime, flags, name,
                    symlink TEXT (never NULL), uid, gid, xattr

   chunks           md5path_1, md5path_2, offset, size, hash    <- chunked files

   nested_catalogs  path TEXT, sha1 TEXT, size                  <- child catalogs

   properties       revision, schema=2.5, schema_revision=2, last_modified
                    (+ root_prefix on a nested root)

   statistics       self_dir        self_regular   self_symlink   self_nested
                    self_chunked    self_chunks    self_chunked_size
                    self_file_size  self_xattr
                    subtree_*  (the same nine, summed over all descendants)
```

Those `statistics` counters are why `fsck` is more than a hash check: it
recomputes all eighteen from the actual rows and reports drift, which is how a
subtly wrong publish gets caught before a client ever sees it.

### 4.8 Crash safety

```
   time ---->
   [1 scan][2 changeset][3 route][4 ingest][5 upsert][6 finalize][7 store][8 reflog][9 sign] | [10 swap]
                                                                                             |
   kill here ------------------------------------------------------------------------------>|<-- or here
        |                                                                                    |
        v                                                                                    v
   rev N still live, in full.                                              rev N+1 live, in full.
   Orphan CAS objects may exist (unreferenced, harmless, collected by gc).
   The transaction is intact -> just re-run `publish`; CAS puts are
   idempotent, so re-storing an object is a no-op.

   There is no window in which a client can observe a half-written revision:
   .cvmfspublished is replaced by rename(2), which is atomic on POSIX.
```

Test hook: setting `$BRIXCVMFS_PUBLISH_CRASH` makes the engine `_exit(66)`
immediately before the swap — that is the injection point the crash-safety tests
use, and it is available to you for rehearsing recovery.

### 4.9 Verify after every publish

```sh
brixcvmfs repo fsck $REPO
# → fsck clean
```

`fsck` fetches every catalog reachable from `.cvmfspublished`, CAS-verifies it,
recomputes each catalog's self/subtree counters from the actual rows, and
bounds-checks xattr BLOBs. It is cheap and never writes — put it at the end of
your publish script. The heavier payload sweep (`--data`) belongs in cron; see
§8.

### 4.10 Lifecycle errors

Every out-of-order call is refused non-zero and leaves the repository valid:

| Command | Result |
|---|---|
| `publish` with no open transaction | `no open transaction under <repo>` |
| `mkfs` over a published repository | refused (it will not clobber a live repo) |
| `mkfs` into a missing parent directory | refused; nothing is created |
| a second `transaction` | `repository is in a transaction (pid): <pid>` |
| `gc` during an open transaction | refused |
| `tag rollback` to an unknown tag | refused |
| `publish --chunk-size` below 4096 | `chunk size below the 4096-byte floor` |

---

## 5. Serve it

### 5.1 The configuration

One location block. The directive points at the directory **above** `cvmfs/`:

```nginx
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 256; }

http {
    server {
        listen 8080;

        location /cvmfs/ {
            brix_cvmfs on;
            brix_cvmfs_stratum0_root /home/you/stratum0;   # repo at .../stratum0/cvmfs/sw.example.org/
        }
    }
}
```

```sh
nginx -t -c ~/stratum0/nginx.conf -p ~/stratum0     # configuration file test is successful
nginx    -c ~/stratum0/nginx.conf -p ~/stratum0
```

### 5.2 The `nginx -t` contract

**The Stratum-0 contract is checked at configuration time, not at runtime.** A
Stratum-0 has no upstream, so any cache-fill grammar in the same block is an
EMERG rather than a silent downgrade to a cache node:

| Also in the block | `nginx -t` says |
|---|---|
| `brix_cache_store …` | `a Stratum-0 serves its published tree directly - remove brix_cache_store (cache-fill) from this block` |
| http(s) `brix_storage_backend …` | `a Stratum-0 has no upstream - remove the http(s) brix_storage_backend from this block` |
| `brix_cvmfs_upstream_allow …` | `a Stratum-0 has no upstream - remove brix_cvmfs_upstream_allow (proxy mode) from this block` |
| `brix_export …` | `brix_cvmfs_stratum0_root and brix_export both name an export root - the alias replaces brix_export; configure exactly one` |

The failure mode this prevents is subtle and expensive: a Stratum-0 that quietly
behaves as a cache would serve stale revisions from a fill path that has no
origin to fill from.

### 5.3 How a request is answered

The gate classifies the URL; it does not hand out files. Anything that is not a
CVMFS traffic shape never reaches the filesystem.

```
   GET /cvmfs/sw.example.org/<tail>
        |
        v
   [ scvmfs authz ]  (§7 — only if configured; runs BEFORE classification)
        |
        v
   cvmfs_classify_url()        shared/cvmfs/grammar/classify.h
        |
        +-- data/<2hex>/<38hex>[CXPH]        -> CAS       -> 200, immutable, cache forever
        +-- .cvmfspublished                  -> MANIFEST  -> 200, TTL-bounded
        +-- .cvmfswhitelist                  -> MANIFEST  -> 200, TTL-bounded
        +-- .cvmfsreflog                     -> MANIFEST  -> 200, TTL-bounded
        +-- api/v1.0/geo/...                 -> GEO       -> 200, synthesized
        +-- .cvmfs-bundle                    -> BUNDLE    -> batch fetch (opt-in)
        +-- .cvmfs-dict/<id>                 -> DICT      -> shared dictionary (opt-in)
        |
        +-- .cvmfs_master_replica            -> REJECT, but intercepted:
        |                                       200 text/plain, synthesized (§5.4)
        |
        +-- ANYTHING ELSE                    -> REJECT    -> 403
              keys/sw.example.org.masterkey  -> 403
              keys/sw.example.org.pub        -> 403
              .brixtxn/upper/secret.txt      -> 403   <- staged, unpublished: invisible
              .brixtxn/lock                  -> 403
              README.md, anything you drop
                in the repo directory        -> 403
```

That last group is not a filesystem permission accident — it is the classifier
refusing to recognise the shape. `tests/test_cvmfs_stratum0_quickstart.py::test_serve_plane_hides_keys_and_staging`
asserts each of those paths exists on disk **and** answers 403, so the property
cannot rot silently.

### 5.4 The replication marker

`GET /cvmfs/<fqrn>/.cvmfs_master_replica` returns 200 `text/plain`:

```
This repository is a Stratum-0 master copy (replication source for cvmfs_server add-replica).
```

The marker is synthesized in the gate — never a file on disk — and only when
`brix_cvmfs_stratum0_root` is set, so a plain cache node still 403s it and cannot
be spoofed into advertising itself as a master copy.

### 5.5 Write methods

```sh
curl -o /dev/null -w '%{http_code}\n' -X PUT -d x http://localhost:8080/cvmfs/sw.example.org/.cvmfspublished
# → 405     (same for DELETE, POST, MKCOL, PROPPATCH)
```

### 5.6 Caching and TTL

```
   MUTABLE (revalidate; honour the manifest TTL — D240 = 240 s by default)
     /cvmfs/<fqrn>/.cvmfspublished     <- changes every publish
     /cvmfs/<fqrn>/.cvmfswhitelist     <- changes every resign
     /cvmfs/<fqrn>/.cvmfsreflog        <- changes every publish/gc

   IMMUTABLE (cache forever, anywhere, with no revalidation)
     /cvmfs/<fqrn>/data/**             <- content-addressed; a given URL's bytes
                                          can never change without changing the URL

   A CDN in front of a Stratum-0 needs exactly one rule: long TTL on data/**,
   manifest-TTL on the three dotted files. Getting it backwards is the classic
   "clients stuck on an old revision" incident.
```

`brix_cvmfs_geo_answer rtt;` and the per-class accounting/metrics apply
unchanged.

---

## 6. Mount it

### 6.1 With the BriX client

Three environment variables pin server, trust anchor and cache:

```sh
export BRIXCVMFS_SERVER=http://localhost:8080/cvmfs/sw.example.org   # URL includes the FQRN
export BRIXCVMFS_PUBKEY=~/stratum0/cvmfs/sw.example.org/keys/sw.example.org.pub
export BRIXCVMFS_CACHE=~/.cache/brixcvmfs

brixcvmfs sw.example.org ~/sw
```

The mount daemonizes; add `-f` to keep it in the foreground, and
`-o auto_unmount` if you want it to clean up when the process dies. Unmount with
`fusermount3 -u ~/sw`.

```sh
cat ~/sw/README.md            # → # quickstart repo
~/sw/tools/hello.sh           # → hello from stratum-0
ls -l ~/sw/run-me             # → run-me -> tools/hello.sh
```

| Variable | Meaning |
|---|---|
| `BRIXCVMFS_SERVER` | single server URL, including the FQRN |
| `BRIXCVMFS_PUBKEY` | master public key file, or a directory of rotated `*.pub` keys |
| `BRIXCVMFS_CACHE` | local cache directory |
| `BRIXCVMFS_ETC` | configuration cascade root (default `/etc/cvmfs` layout) |
| `BRIXCVMFS_TMP` | scratch directory override |

### 6.2 What a read costs

```
   open("/sw/data/samples/big.dat") ; read(fd, buf, 4096) at offset 20000
        |
        v
   (1) manifest, if older than the TTL          GET /.cvmfspublished     ~300 B
        |    verify: whitelist sig, cert fp, manifest sig
        v
   (2) root catalog, if not cached              GET /data/e7/3ee...C     (deflated)
        |    verify sha1(stored) == name, inflate, open as SQLite
        v
   (3) nested catalog for /data/samples         GET /data/1a/2b3...C
        |    (only if the dirtab nested it, and only on first entry)
        v
   (4) chunk map row: offset 20000 -> chunk #4  (pure SQLite lookup, no I/O)
        |
        v
   (5) chunk object                             GET /data/9f/0e1...P     4096 B
        |    verify sha1(stored) == name, inflate
        v
   (6) cache it as verified plaintext, serve the 4096 bytes to the caller

   Steps 1-4 are amortized across the whole mount. A warm re-read is step 6 only.
```

### 6.3 The client cache

```
   ~/.cache/brixcvmfs/
     09/bf764b9f561d33c796e2d0dcb3e768d8ab2dd6C        <- VERIFIED PLAINTEXT (45056 B)
     09/bf764b9f561d33c796e2d0dcb3e768d8ab2dd6C.chk    <- "1eeabddaba3b...de21 45056"
                                                           sha1(plaintext) + length

   Filename    = the CAS name (hash of the STORED/compressed bytes)
   File body   = the INFLATED bytes
   .chk sidecar= hash+length of the body, so a restart can re-validate what is
                 already on disk without re-fetching or re-inflating anything

   Nothing enters this directory until it has been verified against the hash the
   catalog named. A corrupt or substituted object never reaches the cache, and
   therefore never reaches a read().
```

### 6.4 Verify without mounting

Useful as a monitoring probe — it needs no FUSE at all:

```sh
brixcvmfs --check sw.example.org
```

```
CVMFS-brix repository check: sw.example.org
  trust chain .... OK (whitelist + manifest signature verified)
  revision ....... 2
  root catalog ... 09bf764b9f561d33c796e2d0dcb3e768d8ab2dd6
  root dir ....... OK (4 entries)
  active server .. http://localhost:8080/cvmfs/sw.example.org
  active proxy ... DIRECT
  ttl ............ 240s
HEALTHY
```

Exit status is 0 only when the repository is healthy. `brixcvmfs --prewarm
sw.example.org` populates the cache ahead of a job. For stock-client-style
on-demand `/cvmfs/<fqrn>` paths without root or autofs, see
[cvmfs-automount.md](cvmfs-automount.md).

### 6.5 With the official CVMFS client

The repository is ordinary CVMFS on the wire, so the stock client mounts it with
its normal configuration cascade:

```sh
# /etc/cvmfs/keys/sw.example.org.pub  ← copy of the master public key
# /etc/cvmfs/config.d/sw.example.org.conf:
CVMFS_SERVER_URL=http://s0.example.org:8080/cvmfs/@fqrn@
CVMFS_PUBLIC_KEY=/etc/cvmfs/keys/sw.example.org.pub
CVMFS_HTTP_PROXY=DIRECT
```

This is not a claim of intent — it is a test. `tests/test_cvmfs_official_client_live.py`
runs the upstream `registry.cern.ch/cvmfs/service` container, mounts a
repository published by `brixcvmfs` over loopback HTTP with `cvmfs2`, and
diff-walks the result against the ground truth: paths, file types, sizes,
hardlink counts, symlink targets, xattrs and a `sha1sum` of every file through
the mount, including a chunk-reassembled one and a nested catalog. It also
asserts the stock client *refuses* the repository under a wrong public key, a
tampered catalog object and a tampered whitelist. The lane self-skips without a
container runtime, `/dev/fuse` or the image.

---

## 7. Private repositories

Gating a Stratum-0 is **pure configuration** — add the scvmfs preamble to the
same location. It runs before the gate, so the manifest, the CAS objects, the
GeoAPI *and* the replication marker all sit behind the credential wall, and
`.cvmfspublished` is not fetchable anonymously:

```nginx
server {
    listen 8443 ssl;
    ssl_certificate     /path/host.crt;
    ssl_certificate_key /path/host.key;
    ssl_client_certificate /path/ca.pem;
    ssl_verify_client   optional;

    location /cvmfs/ {
        brix_cvmfs on;
        brix_cvmfs_stratum0_root /home/you/stratum0;

        brix_scvmfs on;
        brix_scvmfs_authz x509;             # or: voms, bearer
        brix_scvmfs_x509_dn "*CN=alice*";
    }
}
```

```
   TLS handshake (client cert optional)
        |
        v
   +----------------------+   deny   +-------------------------------+
   |  brix_scvmfs authz   | -------> | 401/403 — nothing below runs   |
   |  x509 DN / VOMS FQAN |          | (no manifest, no CAS, no geo,  |
   |  / bearer token      |          |  no master-replica marker)     |
   +----------+-----------+          +-------------------------------+
              | allow
              v
   cvmfs_classify_url()  --> §5.3, unchanged
```

VOMS mode swaps the last two lines for `brix_scvmfs_authz voms` plus
`brix_scvmfs_vomsdir`, `brix_scvmfs_voms_cert_dir` and `brix_scvmfs_voms <vo>`.
See [`docs/04-protocols/cvmfs.md`](../04-protocols/cvmfs.md) for the full authz
matrix. Proven end to end by `tests/test_cvmfs_stratum0_scvmfs.py`.

Note what gating does *not* change: content is still end-to-end signed, so
authorization controls **who may fetch**, never **what is trusted**.

---

## 8. Maintenance

### 8.1 Replication to a Stratum-1

**There is no push protocol.** A correct on-disk repository plus HTTP GET *is*
the feed — point any stock Stratum-1 at it:

```sh
cvmfs_server add-replica http://s0.example.org:8080/cvmfs/sw.example.org /etc/cvmfs/keys
```

```
   Stratum-0 (you)                    Stratum-1 (anyone)
   +-------------------+              +-------------------+
   | .cvmfspublished   | <--- GET --- | poll for a new S   |
   | .cvmfswhitelist   | <--- GET --- | verify the chain   |
   | data/**  (C objs) | <--- GET --- | walk the catalogs  |
   | data/**           | <--- GET --- | pull new objects   |
   | .cvmfs_master_    | <--- GET --- | probe: is this a   |
   |   replica (200)   |              |   master copy?     |
   +-------------------+              +-------------------+
        pull-only, stateless, restartable, cacheable
```

The replication marker (§5.4) is what makes `add-replica` accept the endpoint.

### 8.2 Cron

```cron
17 3 * * *   brixcvmfs repo resign ~/stratum0/cvmfs/sw.example.org
47 4 * * 0   brixcvmfs repo gc     ~/stratum0/cvmfs/sw.example.org --keep 8
23 5 * * 0   brixcvmfs repo fsck   ~/stratum0/cvmfs/sw.example.org --data
```

### 8.3 `resign` — not optional

The whitelist expires 30 days after it is minted; once it does, **every client
refuses the repository**, including ones that have it mounted. Re-signing is
cheap and idempotent.

```
   day 0                       day 23                  day 30
   |---------------------------|-----------------------|--------------->
   mkfs / resign            last daily resign        HARD EXPIRY
   E = now + 30d               moves E to day 53      all clients refuse
   |                           |                      |
   +-- daily cron re-mints here, every day, far inside the window
       a single missed night is harmless; a missed month is an outage
```

```
re-signed sw.example.org (revision 2, whitelist +30d)
```

`resign` needs the masterkey (§3.6) and nothing else — it does not touch content
or catalogs, and it can run against a repository that is being read.

### 8.4 `gc` — reflog-anchored

Garbage collection is not mark-and-sweep-the-world. The reflog is the root set:

```
   .cvmfsreflog:  refs(hash, type, timestamp)      type 0=catalog 1=cert 2=history 3=metainfo

   revisions:   r1     r2     r3     r4     r5     r6     r7     r8     r9    r10
                |      |      |      |      |      |      |      |      |      |
   --keep 8 ----+------+--[ drop ]---+------+------+------+------+------+------+---> keep
                |      |             `-------------------- retained window --------'
                |      |
                |      +-- TAGGED "v1.0" -> PINNED, never dropped even outside the window
                +-- untagged, outside the window -> its refs are removed

   then, and only then:
     sweep data/** for objects no RETAINED revision references
     --grace S protects any object whose mtime is younger than S seconds
     (set --grace above your longest publish, or a concurrent publish can lose a race)

   ORDER: refs are dropped BEFORE the CAS sweep. A crash mid-GC therefore leaves
   unreferenced garbage (re-collectable next run) and never a dangling reference.
```

```sh
brixcvmfs repo gc $REPO --keep 8              # newest 8 revisions
brixcvmfs repo gc $REPO --keep-since 1785000000 --grace 3600
```

```
gc: kept 2 revision(s), dropped 0, swept 0 object(s)
```

Because older revisions are retained until swept, an object under `data/` may be
unreferenced by the current revision and still perfectly healthy — do not
conclude anything from a raw directory listing. `fsck --data` is the authority on
what is live.

### 8.5 Tags and rollback

```sh
brixcvmfs repo tag add  $REPO v1.0 -m "first release"     # → tagged 'v1.0'
brixcvmfs repo tag list $REPO
# v1.0    rev 2   09bf764b9f561d33c796e2d0dcb3e768d8ab2dd6   1785890599   first release
brixcvmfs repo tag rollback $REPO v1.0
```

```
   BEFORE                                    AFTER `tag rollback v1.0`
   rev 2  root catalog A   <- tag v1.0       rev 2  root catalog A   <- tag v1.0
   rev 3  root catalog B                     rev 3  root catalog B
   rev 4  root catalog C   <- current        rev 4  root catalog C
                                             rev 5  root catalog A   <- current

   The counter NEVER rewinds. Rollback republishes the tagged revision's root
   catalog as a NEW revision, so clients and Stratum-1s see an ordinary forward
   update and their caches stay coherent. Objects are already present, so a
   rollback stores almost nothing.
```

Tag your releases before running `gc`: the tag is what pins the objects.

### 8.6 `fsck --data` — the rot check

Plain `fsck` (§4.9) verifies catalogs and counters; `--data` additionally checks
that the certificate and *every* referenced content object and file chunk are
present and CAS-identical.

```
   fsck            : manifest -> catalogs -> counters -> xattrs        O(catalogs)
   fsck --data     : the above, plus certificate + every content
                     object + every chunk, read and re-hashed          O(repository)
                     (stored form only — nothing is inflated)
```

It is linear in repository size — which is exactly why it is opt-in and belongs
on a weekly schedule rather than in the publish script.

```
fsck clean (data verified)
```

---

## 9. The integrity model

Three parties, each verifying independently — and the web tier is deliberately
the weakest of them:

```
   PUBLISHER                     SERVER                        CLIENT
   brixcvmfs repo fsck           nginx                         cvmfs2 / brixcvmfs
   +---------------------+       +---------------------+       +---------------------+
   | catalogs CAS-verify |       |                     |       | whitelist signature |
   | counters recomputed |       |   verifies NOTHING  |       | cert fingerprint    |
   | xattrs bounds-check |       |   serves raw bytes  |       | manifest signature  |
   | --data: every       |       |   from disk         |       | sha1 of EVERY       |
   |   object + chunk    |       |                     |       |   fetched object    |
   +----------+----------+       +----------+----------+       +----------+----------+
              |                             |                             |
       non-zero exit,                 by design: it holds            EIO on the read;
       names object + path            no key and can forge           the cache only ever
                                      nothing                        holds verified plaintext

              `--------------- the same SHA-1s, checked three times ------------'
```

| Tamper | Publisher `fsck` | Publisher `fsck --data` | Client (BriX or stock) |
|---|---|---|---|
| flip a byte in a payload object | clean (by design — catalog-only) | `object <hex> of <path> fails CAS verification` | `EIO` on read of that file |
| delete a payload object | clean | `object <hex> of <path> missing` | `EIO` on read |
| flip a byte in a catalog object | fails: CAS verify | fails | mount or subtree traversal refused |
| flip a byte in `.cvmfspublished` | fails: signature | fails | mount refused |
| tamper with `.cvmfswhitelist` | `trust chain` not OK | same | mount refused |
| swap in a different `.pub` | n/a | n/a | mount refused |

Concretely, flipping one byte in a live CAS object:

```
$ brixcvmfs repo fsck $REPO
fsck clean                                  # catalog-only check is unaffected — expected
$ brixcvmfs repo fsck $REPO --data
brixcvmfs repo: fsck failed: object 3f2b… of /data/samples/big.dat fails CAS verification
```

On the client side the tampered object is refused at read time (`EIO`), for both
whole-file and chunked content — nothing corrupt is ever admitted to the cache.
This is the property that makes an untrusted or shared web tier acceptable, and
it is why the honest answer to "what does the server check?" is *nothing, on
purpose*.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `nginx -t`: `a Stratum-0 has no upstream …` | cache-fill grammar in the Stratum-0 block | remove it; a Stratum-0 is never also a cache (§5.2) |
| Clients 403 on everything | repo is not at `<root>/cvmfs/<fqrn>/`, or the directive points *into* `cvmfs/` | point `brix_cvmfs_stratum0_root` at the directory above `cvmfs/` (§3.1) |
| 403 on one odd path only | the URL is not a CVMFS traffic shape | by design (§5.3) — serve auxiliary files from a different location block |
| Mount fails, `repo info` says `trust chain` not OK | whitelist expired (30 days) | `brixcvmfs repo resign`; then schedule it (§8.3) |
| Mount fails with the right key on a healthy repo | `BRIXCVMFS_SERVER` missing the FQRN component | the URL must end in `/cvmfs/<fqrn>` |
| `repository is in a transaction (pid): N` | a previous publish died or another publisher holds it | check the pid, then `brixcvmfs repo abort` |
| `no open transaction under <repo>` | `publish` without `transaction` | open one first |
| Publish rejected: `chunk size below the 4096-byte floor` | `--chunk-size` under the floor | raise it, or drop the flag for the 32 MiB default |
| Clients see stale content for a few minutes | manifest TTL / intermediate caches | the TTL is in `repo info`; only the three dotted files are mutable (§5.6) |
| Clients stuck on an old revision for hours | a CDN is caching `.cvmfspublished` | fix the cache rule: long TTL on `data/**` only (§5.6) |
| Reads fail with `EIO` on one path | the CAS object is corrupt | `brixcvmfs repo fsck <repo> --data` names it; restore from backup or republish the file |
| `mkfs` fails and nothing is created | the parent directory does not exist | `mkdir -p` the parent; `mkfs` creates only the leaf |
| `data/` keeps growing after `gc` | retained revisions still reference the objects, or `--grace` protected them | `--keep` fewer revisions; remember tags pin their revision (§8.4) |
| Publish is slow on a huge tree | one catalog for everything | split it with `--dirtab` (§4.6); cost then tracks the touched subtree |

---

## 11. Reference

### 11.1 Command matrix

```
brixcvmfs repo mkfs        <fqrn> <repo_dir> [keys_dir]
brixcvmfs repo info        <repo_dir> [keys_dir]
brixcvmfs repo resign      <repo_dir> [keys_dir]
brixcvmfs repo transaction <repo_dir>
brixcvmfs repo abort       <repo_dir>
brixcvmfs repo publish     <repo_dir> [keys_dir] [--chunk-size N] [--dirtab F]
brixcvmfs repo fsck        <repo_dir> [--data]
brixcvmfs repo gc          <repo_dir> [keys_dir] (--keep N | --keep-since T) [--grace S]
brixcvmfs repo tag         add      <repo_dir> <name> [keys_dir] [-m <message>]
brixcvmfs repo tag         list     <repo_dir>
brixcvmfs repo tag         rollback <repo_dir> <name> [keys_dir]

brixcvmfs <fqrn> <mountpoint>          mount (add -f to stay in the foreground)
brixcvmfs --check   <fqrn>             verify without mounting; exit 0 = HEALTHY
brixcvmfs --prewarm <fqrn>             populate the cache
```

| Needs the masterkey | Needs the certificate key | Needs neither |
|---|---|---|
| `mkfs`, `resign` | `mkfs`, `publish`, `gc`, `tag add`, `tag rollback` | `info`, `transaction`, `abort`, `fsck`, `tag list` |

### 11.2 Directives

| Directive | Context | Meaning |
|---|---|---|
| `brix_cvmfs on;` | location | enable the CVMFS protocol plane |
| `brix_cvmfs_stratum0_root <dir>;` | location | serve the published tree under `<dir>/cvmfs/<fqrn>/`; strict alias for `brix_export`, adds the `nginx -t` contract and the replication marker |
| `brix_cvmfs_geo_answer rtt;` | location | answer the GeoAPI |
| `brix_scvmfs on;` + `brix_scvmfs_authz …` | location | gate the whole plane behind x509 / VOMS / bearer (§7) |

Mutually exclusive with `brix_cvmfs_stratum0_root`, enforced at `nginx -t`:
`brix_export`, `brix_cache_store`, http(s) `brix_storage_backend`,
`brix_cvmfs_upstream_allow`.

### 11.3 File inventory

| Path | Mutable | Written by | Served |
|---|---|---|---|
| `.cvmfspublished` | yes (atomic rename) | `publish`, `resign`, `tag rollback` | yes, TTL-bounded |
| `.cvmfswhitelist` | yes | `mkfs`, `resign` | yes, TTL-bounded |
| `.cvmfsreflog` | yes | `publish`, `gc`, `tag` | yes, TTL-bounded |
| `data/**` | no (immutable) | `publish` (add), `gc` (remove) | yes, cache forever |
| `keys/**` | no | `mkfs` | **no — 403** |
| `.brixtxn/**` | yes | `transaction`, you | **no — 403** |

### 11.4 Environment

| Variable | Used by | Meaning |
|---|---|---|
| `BRIXCVMFS_SERVER` | client | server URL including the FQRN |
| `BRIXCVMFS_PUBKEY` | client | master public key file or directory of rotated `*.pub` |
| `BRIXCVMFS_CACHE` | client | local cache directory |
| `BRIXCVMFS_ETC` | client | configuration cascade root |
| `BRIXCVMFS_TMP` | client | scratch directory override |
| `BRIXCVMFS_PUBLISH_CRASH` | publisher | test hook: `_exit(66)` immediately before the manifest swap (§4.8) |

---

## 12. Coverage and implementation map

| Lane | What it pins |
|---|---|
| `tests/test_cvmfs_stratum0_quickstart.py` | this page, against the shipped `brixcvmfs` binary: personality, mkfs → publish → serve → mount, second publish (add/modify/whiteout), tag/resign/gc, lifecycle refusals, 405s, keys/staging not served, tamper detection |
| `tests/test_cvmfs_official_client_live.py` | the external oracle: stock `cvmfs2` mounts and diff-walks our repo; refuses it under wrong key / tampered catalog / tampered whitelist |
| `tests/test_cvmfs_stratum0_serve.py` | the open serve plane, including a real client mount |
| `tests/test_cvmfs_stratum0_scvmfs.py` | the gated serve plane (x509 + VOMS) |
| `tests/test_cvmfs_repo_cli.py`, `_publish_txn.py`, `_catalog_completeness.py`, `_tags.py` | the publish engine itself (standalone repotool build) |

```
   TOOL SURFACE                              SHARED ENGINE (pure C, no nginx)
   client/apps/fs/                           shared/cvmfs/
     brixmount.c        argv[0] personality    publish/publish.c        pipeline (§4.4)
     brixcvmfs_repo.c   repo subcommand CLI    publish/changeset.c      overlay -> changes
     brixcvmfs_publish.c publish + fsck        publish/publish_dirtab.c nesting policy
     brixcvmfs_admin.c  resign / gc / tag      publish/publish_counters.c statistics
                                               publish/fsck.c           fsck [--data]
                                               publish/admin.c          reflog GC, tags
   SERVE PLANE                                 signature/manifest.c     parse + verify
   src/protocols/cvmfs/                        signature/sign.c         emit + sign
     cvmfs_module_build.c  nginx -t contract   object/object_write.c    CAS put (deflate+sha1)
     gate.c                classify + marker   object/object.c          CAS get (verify+inflate)
     handler.c             serve the bytes     catalog/catalog.c        SQLite catalog reader
                                               reflog/reflog.h          refs(hash,type,ts)
                                               grammar/classify.h       the URL classifier
                                                                        (shared with the client
                                                                         and the fuzz corpus)
```

The classifier is deliberately one implementation shared by the server, the FUSE
client and the 12,800-case fuzz corpus: a URL that the server would serve and the
client would not ask for (or vice versa) is a bug that cannot exist by
construction.
