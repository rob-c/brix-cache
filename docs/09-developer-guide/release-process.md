# Release process

How a version number becomes a release. Read this before touching
`BRIX_SERVER_VERSION_BARE` — bumping that macro alone is not a release, it just
makes the tree inconsistent until the rest of this page is done.

## The single source of truth

`src/core/ident.h`:

```c
#define BRIX_SERVER_VERSION_BARE  "1.4.0"
#define BRIX_SERVER_VERSION       "v" BRIX_SERVER_VERSION_BARE
```

Everything else *derives* from that line:

| Consumer | How it derives | Drift is |
|---|---|---|
| Server runtime (`Qconfig version`, stats XML, `/healthz`, SRR, Pelican) | compiled in | impossible |
| `packaging/rpm/build-rpm.sh`, `build-rpm-container.sh` | `sed` the macro, pass `--define version_override` | impossible |
| Spec `%global upstream_version` literal fallback | **hand-maintained** | silent — a bare `rpmbuild` mislabels the RPM |
| Spec `%changelog` newest entry | hand-maintained | silent |
| `CHANGELOG.md` newest entry | hand-maintained | silent |
| Git tag `vX.Y.Z` | hand-created | silent |

The three "silent" rows are why `tools/ci/check_version_sync.py` exists: it
fails the build unless the spec fallback, the spec's newest `%changelog` entry
and `CHANGELOG.md`'s newest entry all equal `ident.h`. It deliberately does
**not** check the git tag — the tag is created after CI is green, so requiring
it would deadlock the very push that introduces the bump.

## Versioning

`MAJOR.MINOR.PATCH`, judged from the operator's side of the fence:

- **MAJOR** — an operator must edit their config or their clients break.
- **MINOR** — new directives, new backends, new protocol surface; existing
  configs keep working.
- **PATCH** — fixes and hardening only.

Skipping numbers is allowed and has happened (1.0.6, 1.1.0 and 1.2.x were never
cut). Record the skip in `CHANGELOG.md` rather than back-filling an empty entry
— a missing number that is explained is not a mystery.

## Cutting a release

1. **Bump** `BRIX_SERVER_VERSION_BARE` in `src/core/ident.h`.
2. **Spec fallback** — `%global upstream_version %{?version_override}%{!?version_override:X.Y.Z}`
   in `packaging/rpm/nginx-mod-brix-cache.spec`.
3. **Spec `%changelog`** — add a newest-first entry
   `* <Day> <Mon> <DD> <YYYY> <Name> <email> - X.Y.Z-1`. Keep it to
   *packaging-relevant* notes and point at `CHANGELOG.md` for the rest;
   duplicating the full notes in two files guarantees they diverge.
4. **`CHANGELOG.md`** — add a `## vX.Y.Z — YYYY-MM-DD` section at the top,
   grouped Added / Changed / Fixed / Security. Write it for someone deciding
   whether to upgrade, not for someone reading the diff.
5. **Verify**:
   ```sh
   tools/ci/check_version_sync.py --show   # all four rows equal
   $(tools/ci/guard_set.py --all)          # or push and let CI run them
   PYTHONPATH=tests pytest tests/test_release_hygiene.py -v
   ```
6. **Build the RPM** at least once for the target distro — the spec fallback
   path is only exercised by a bare `rpmbuild`, so build that way *once*:
   ```sh
   packaging/rpm/build-rpm-container.sh          # derived version (normal path)
   rpmbuild -bs packaging/rpm/nginx-mod-brix-cache.spec   # fallback path
   ```
7. **Commit** the bump on its own, message `release: vX.Y.Z`.
8. **Tag**, annotated, after CI is green:
   ```sh
   git tag -a vX.Y.Z -m "BriX-Cache X.Y.Z"
   git push origin vX.Y.Z
   ```

Steps 7 and 8 are git *write* commands: per `CLAUDE.md`, an agent must not run
them without explicit approval in the current conversation.

## Tagging convention

Release tags are **annotated** and named `vX.Y.Z` — matching
`BRIX_SERVER_VERSION` exactly, so `git describe` and the server banner agree.
Annotated (not lightweight) because a release tag should carry its own author,
date and message; a lightweight tag is just a moving bookmark with no record of
who placed it or why.

### The `v6.1.0-ref` tag

The repository carries one pre-existing tag, `v6.1.0-ref`. It is **not a
release of this project**:

- it is a *lightweight* tag on `d9228d5d7` (2026-07-06,
  `test(token): multi-key/EC/ES256 forge + …`), a mid-development commit;
- `6.1.0` corresponds to no BriX-Cache version — the product has never been
  above 1.x. The number is an upstream **XRootD** release line, and the `-ref`
  suffix marks it as a *reference point* for interoperability comparison;
- nothing in the build derives from it.

Leave it in place — deleting a published tag breaks anyone who fetched it — but
do not read it as release history, and do not add more tags in that style. If
future interop reference points are needed, name them unambiguously
(`interop/xrootd-6.1.0`) so they cannot be mistaken for releases.

## Where the history lives

- `CHANGELOG.md` — what changed, per release, for a user of the server.
- `packaging/rpm/nginx-mod-brix-cache.spec` `%changelog` — packaging detail per
  RPM revision, including revisions that carry no upstream version change
  (`1.1.1-3` … `1.1.1-25`). Authoritative for packaging.
- `docs/09-developer-guide/development-history.md` and its `history-*.md` topic
  docs — design rationale and lessons learnt. Not release notes.
