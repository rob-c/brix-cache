# Serving an RPM/dnf repository from CVMFS

**Status: source-verified 2026-08-18.** The executable form of this page is
`tests/test_rpm_cvmfs_compose.py` (Stratum-0 on 13620). Every command below
is a real flag surface of `brixrpm` / `brixcvmfs` as built from this tree —
check with `brixrpm --help` and `brixcvmfs ingest dir` if they drift.

Companion pages:
[cvmfs-stratum0.md](cvmfs-stratum0.md) — standing up and signing the
repository this page publishes into ·
[rpm-mirror.md](rpm-mirror.md) — the *other* RPM plane: caching someone
else's repo rather than publishing your own.

---

## 1. What problem this solves

An RPM repository is static HTTP: a mutable `repodata/repomd.xml` pointing
at checksum-named, therefore immutable, metadata files, plus the packages.
That shape is a poor fit for a plain filesystem export and an excellent fit
for CVMFS, which gives you three things a bare HTTP repo cannot:

1. **Atomic publication.** A CVMFS publish flips one root hash. Readers see
   the old repodata or the new repodata — never a `repomd.xml` that points
   at a `-primary.xml.gz` that has not landed yet. On a plain filesystem
   repo that window is real, and dnf falls into it.
2. **Snapshots, for free.** Every publish is a revision, and a tag pins one.
   "Install exactly what production had on the 3rd" stops being an archive
   restore and becomes a mount option. This is the actual reason to do
   this — see §5.
3. **One distribution tree.** The same bytes are already reaching every
   worker node over CVMFS. An RPM repo inside it needs no new mirror, no new
   ACLs, and no new firewall holes.

The cost is one ordering rule (§3) and one GC rule (§5.2).

---

## 2. The pipeline

```
/srv/repo/                     brixrpm createrepo
  Packages/*.rpm        ───────────────────────────►  /srv/repo/repodata/
                                                        repomd.xml
                                                        <sha256>-primary.xml.gz
                                                        …
        │
        │  brixcvmfs ingest dir
        ▼
/srv/cvmfs/software.example.org/rpm/el9/     ← one publish, one revision
        │
        │  clients mount
        ▼
/cvmfs/software.example.org/rpm/el9/   →  baseurl=file:///cvmfs/…
```

Nothing here is new machinery: `createrepo` is the D12 emitter, `ingest dir`
is the D9 folder path, and the publish is the ordinary Stratum-0 publish.

---

## 3. The ordering rule

**Run `createrepo` before `ingest`, always.**

```sh
brixrpm createrepo /srv/repo --update
brixcvmfs ingest dir /srv/repo \
    --repo /srv/cvmfs/software.example.org \
    --prefix /rpm/el9
```

The reason is the atomicity claim in §1.1. `brixrpm` already stages and
renames within `/srv/repo`, writing `repomd.xml` last — but that only makes
the *staging* directory consistent. What clients read is the CVMFS tree, and
that becomes consistent when the publish commits. Running `createrepo`
first means the packages **and** the metadata that describes them enter the
tree in the same revision.

Invert the order — ingest, then createrepo against the published tree — and
you get a revision whose `repodata/` describes the previous package set.
dnf will happily install from it and then fail a checksum on a package that
does not exist yet.

`--update` is safe and wanted here: it reuses the `.brixrpm-cache` memo for
packages whose `(size, mtime)` are unchanged, so a repo that gained one
package rescans one package. Drop it only if you suspect the memo (it is
discarded automatically if malformed).

### 3.1 When `(size, mtime)` is not enough — `--paranoid`

`--update` believes a timestamp. That is the right trade for a repo whose
packages only ever arrive (a new build lands under a new NEVRA, so it is a
new file), and the wrong one for a repo whose packages can be *rewritten*:
a rebuild copied in with `cp -p`, an `rsync` without `--checksum`, a mirror
leg you do not own. Any of those can leave a package the same length under
the same mtime with different bytes inside, and `--update` will republish
the checksum it recorded last time — metadata that names bytes the file no
longer holds. dnf finds out, one download later, as a checksum failure on a
package that looks fine on disk.

```sh
brixrpm createrepo /srv/repo --update --paranoid
```

re-reads each memo hit and compares its sha256 against the recorded one
instead of trusting the timestamp. An unchanged package still skips the
header walk and the XML render, so the flag costs one read pass over the
repo, not a rebuild; a changed one is re-parsed, warned about by name, and
counted in the summary line as `changed-in-place`. That counter is the
point — a non-zero there means something rewrote a package behind your
back, which is worth knowing whichever of the three causes above it was.

It also makes the reverse case free: a package whose mtime moved but whose
bytes did not is a memo *hit* under `--paranoid`, where `--update` alone
would re-parse it.

Without `--update` there is no memo to check and `--paranoid` changes
nothing — a full run parses every package anyway.

### 3.2 Dry-run first on a large repo

```sh
brixcvmfs ingest dir /srv/repo --repo /srv/cvmfs/software.example.org \
    --prefix /rpm/el9 --dry-run
```

Prints the changeset without opening a transaction. Worth doing once when
you add a repo; the number it prints is how much the next publish will move.

### 3.3 Removing packages

`ingest dir` is additive by default. To make the published tree mirror the
source exactly — including deletions — add `--delete`:

```sh
brixcvmfs ingest dir /srv/repo --repo /srv/cvmfs/software.example.org \
    --prefix /rpm/el9 --delete
```

Without it, a package you deleted from `/srv/repo` stays in `/cvmfs`,
unreferenced by the new `repodata/`. That is harmless for dnf (it resolves
through repodata, not by listing the directory) but it grows the tree
forever, so prefer `--delete` on repos with churn and let §5.2's GC reclaim
the objects.

---

## 4. The client side

```ini
# /etc/yum.repos.d/software-el9.repo
[software-el9]
name=software.example.org EL9
baseurl=file:///cvmfs/software.example.org/rpm/el9
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///cvmfs/software.example.org/rpm/el9/RPM-GPG-KEY-software
```

`file://` is the point: the client needs no network path to the repo beyond
the CVMFS mount it already has. If you would rather serve it over HTTP,
point `baseurl=` at the Stratum-0's own URL for the same path — the tree is
identical either way.

### 4.1 GPG signing is unchanged, and stays yours

CVMFS signs the *repository* (the manifest and the whitelist). That is
transport integrity for the tree; it says nothing about who built an RPM.
Keep signing packages and `repodata/repomd.xml` with your own key exactly as
you would for an HTTP repo:

```sh
gpg --detach-sign --armor /srv/repo/repodata/repomd.xml   # → repomd.xml.asc
```

A detached `.asc` is just a file. It sits beside `repomd.xml`, `ingest dir`
carries it like any other file, and dnf verifies it client-side with
`repo_gpgcheck=1`. **Sign after `createrepo`, before `ingest`** — the
signature covers the `repomd.xml` that is about to be published, and §3's
ordering already puts both in one revision.

The chain is therefore doubly closed: CVMFS proves the tree is the one your
Stratum-0 signed, and GPG proves the packages are the ones you built.
Neither substitutes for the other, and a tampered `.rpm` inside a validly
signed CVMFS tree is still refused by dnf's checksum chain.

---

## 5. Snapshots — the reason to bother

### 5.1 Tag a revision, mount it later

```sh
brixcvmfs repo tag add /srv/cvmfs/software.example.org prod-2026-08-18
brixcvmfs repo tag list /srv/cvmfs/software.example.org
```

A tag pins a revision, and the revision holds the exact package set *and*
the exact repodata that described it. Reproducing a build environment from
three months ago is a mount, not an archaeology project — and because the
repodata is pinned with the packages, dnf's own dependency resolution
replays as it did then, which a directory of saved `.rpm` files cannot give
you.

Publishing does not disturb existing tags: a republish that adds one package
creates a new revision, clients that follow the head see the new package
after their next catalog refresh (remount or TTL expiry), and the tagged
revision keeps resolving to the old set.

### 5.2 GC interacts with tags — mind the floor

```sh
brixcvmfs repo gc /srv/cvmfs/software.example.org --keep 20 --grace 3600
```

GC reclaims objects no live revision references. **Tags keep revisions
alive, so a tag you promised to keep must stay above the GC floor.** The
failure mode is quiet: GC the revision out from under a tag and the tag
still lists, but mounting it fails to fetch objects.

The rule that avoids it: decide the retention promise first (how far back a
pinned snapshot must work), then set `--keep` / `--keep-since` to cover it
with margin, and treat the tag list as the source of truth for what the
floor must be.

---

## 6. Update cadence

For a repo that changes daily, one cron entry is the whole operation:

```sh
#!/bin/sh
set -e
brixrpm createrepo /srv/repo --update --paranoid --strict
gpg --batch --yes --detach-sign --armor /srv/repo/repodata/repomd.xml
brixcvmfs ingest dir /srv/repo \
    --repo /srv/cvmfs/software.example.org --prefix /rpm/el9 --delete
```

Notes:

- `--paranoid` in the cron path for the same reason `--strict` is: the run
  is unattended, so the one thing it must not do is publish metadata that
  describes bytes nobody checked (§3.1). It costs a read pass over the repo.
- `--strict` in the cron path, deliberately. Interactively a corrupt `.rpm`
  should be a warning you can look past; unattended it should stop the run
  before a silently-incomplete repodata is published. `brixrpm` exits 1 and
  `set -e` does the rest.
- `set -e` matters for the same reason: never publish metadata whose
  generation failed.
- No `--no-wait`. Let the publish complete so the next run does not race it.
- Publishing more often than clients refresh their catalogs buys nothing.
  Match the cadence to the client TTL, not to the build system.

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| dnf: "cannot find a valid baseurl" | repo not mounted | `ls /cvmfs/<fqrn>/rpm/el9/repodata/` — autofs mounts on access; check the client is configured for the repo |
| dnf installs an old package set | client is on a cached catalog | remount, or wait out the catalog TTL; confirm with `brixcvmfs --check <fqrn>` |
| dnf: checksum does not match | ingest ran before createrepo | re-run in §3's order; the published revision is inconsistent, not the packages |
| dnf: checksum does not match, and the order was right | a package was rewritten under an unchanged `(size, mtime)` and `--update` reused the memo | re-run with `--paranoid` (§3.1); the summary line's `changed-in-place` count names how many |
| dnf: "repomd.xml GPG signature verification error" | `.asc` signed a different `repomd.xml` | re-sign after `createrepo`, then re-ingest (§4.1) |
| tagged snapshot fails to mount | GC ran below the tag | §5.2; the objects are gone — restore from the Stratum-0 backup |
| tree grows every publish | additive ingest | add `--delete` (§3.3), then GC |
