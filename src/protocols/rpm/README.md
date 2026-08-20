# rpm — the RPM/dnf pull-through mirror (phase-104 D11 / D15.9)

## Overview

A site mirror for an upstream RPM repository. A dnf client points its
`baseurl` at a `brix_rpm_mirror` location; the server classifies the request,
derives a cache key, and serves it through the ordinary read-through cache
tier — cold objects are fetched once from the configured
`brix_storage_backend` and coalesced, so a hundred nodes doing `dnf update`
at 03:00 cost the upstream one copy of each file.

The whole plane turns on one property of a repository's *file names*.
`createrepo` writes `repodata/repomd.xml` — the mutable freshness root — and
writes every other metadata file beside it as `<checksum>-<name>`, so those
names ARE their digests; packages are immutable in practice and carry their
proof in the RPM header. That distinction is the mirror's only interesting
decision (TTL vs forever, verify-at-edge vs trust), so it is read exactly
once, at the edge, by `rpm_classify.c`, and every later consumer — the cache
TTL policy in `src/fs/backend/cache/sd_cache_policy.c`, the fill-side verify
in `src/fs/cache/verify.c` (`BRIX_CACHE_VERIFY_RPM_REPODATA`) — re-reads the
key with that same grammar rather than growing its own idea of what a
repodata path looks like. The traversal defense rides along: a path that
classifies cannot escape the store, because the grammar rejects every
component that could.

`rpm_prefetch.c` closes the one latency that policy cannot: after a fresh
`repomd.xml` is pulled through, the primary and filelists files it names are
warmed on a timer, so the client's *next* request is already resident.

Everything is gated and default-off: with no `brix_rpm_mirror` directive in
the configuration, not one byte of this plane runs.

## Files

| File | Responsibility |
|---|---|
| `rpm_module.c` | nginx wiring: config lifecycle head, the directive table, handler install |
| `rpm_merge.c` | the location merge — refusals first (an unsupported storage grammar is an EMERG at config load, never a runtime surprise), then the export build |
| `rpm_gate.c` | first step of every request: method policing, classification, cache-key derivation |
| `rpm_mirror.c` | the content handler — route the classified request through the cache tier to the upstream |
| `rpm_classify.c` / `rpm_classify.h` | the route grammar: repomd / digest-named metadata / package / aux, plus the checksum a metadata name carries and the algorithm its hex LENGTH implies |
| `rpm_prefetch.c` | warm the two files a dnf client always asks for next, off a fresh repomd.xml |
| `rpm_repomd.c` / `rpm_repomd.h` | the warm-set extractor: read `<location href="…">` out of a repomd.xml |
| `rpm.h` | loc-conf + request-ctx types and the seams the translation units above share |

## Gating and invariants

- **Default off.** `brix_rpm_mirror` enables the plane per location; nothing
  here is reachable without it.
- **INVARIANT #8 (low-cardinality labels).** The `brix_rpm_*` families label
  by route class and disposition — closed enums from
  `brix_rpm_class_str()` — never by repository, path or package name.
- **INVARIANT #12 (the VFS seam).** Storage is reached through
  `brix_vfs_*`/the cache tier; this directory contains no positional-byte
  syscalls of its own.
- **Self-addressing verify is fail-closed.** A digest-named metadata file
  whose bytes do not hash to its own name is quarantined, never served.

## See also

- `docs/04-protocols/rpm.md` — the protocol surface and its directives
- `docs/05-operations/rpm-mirror.md` — running one, and what to alert on
- `docs/05-operations/rpm-on-cvmfs.md` — publishing a repo *onto* CVMFS with
  `brixrpm createrepo` + `brixcvmfs ingest dir`
- `shared/rpm/` — the clean-room header parser and repomd/primary writers the
  `brixrpm` client tool is built on
- `docs/refactor/phase-104-oci-rpm-distribution.md` — §D11, §D15.9, §D15.10
