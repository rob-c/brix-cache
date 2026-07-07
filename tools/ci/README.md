# tools/ci — invariant guards

Every script here encodes a project invariant as a red/green check. All of
them run in CI on every PR/push (`.github/workflows/guards.yml`) and in the
pre-push hook (`tools/git-hooks/pre-push`, install once with
`git config core.hooksPath tools/git-hooks`). Run any of them locally with
no arguments; exit 0 = clean.

| Script | Invariant enforced | Backlog / baseline | Regen |
|---|---|---|---|
| `check_config_coverage.sh` | every `src/**/*.c` is built via `./config`, or allowlisted with a reason; no stale `./config` entries | inline allowlist | edit allowlist |
| `check_vfs_seam.sh` | no new storage-plane bypasses of the VFS (tier-2 confined-helper calls, tier-1.5 direct SD vtable I/O) | `vfs_seam_backlog.txt`, `_ns`, `_client` | `--regen` |
| `check_http_helper_reimpl.sh` | protocols must not regrow private copies of the shared HTTP helpers (header scan, preconditions, ETag) | inline allowlist | edit allowlist |
| `check_sd_driver_conformance.sh` | every `fs_list.h` storage driver ships a conforming `brix_sd_driver_t` (+ prints the op-coverage matrix) | — | — |
| `check_file_size.sh` | no `src/` file crosses the ~500-line soft cap; frozen offenders may only shrink | `file_size_backlog.txt` | `--regen` |
| `check_doc_paths.sh` | CLAUDE.md / README.md / docs/index.md reference only paths that exist AND are git-tracked | `<!-- doc-paths:off/on -->` markers for deliberate dead refs | — |
| `check_doc_links.sh` | every relative markdown link in docs/ + src READMEs resolves to a git-tracked target | `doc_links_backlog.txt` (currently empty — keep it that way) | `--regen` |
| `check_readme_coverage.sh` | any depth≤2 `src/` dir with ≥2 C sources carries a README.md | — | — |
| `check_ports_doc.sh` | every `*_PORT*` constant in `tests/settings.py` has a row in `docs/10-reference/test-fleet-ports.md` | — | — |
| `run_fanalyzer.sh` | no NEW gcc `-fanalyzer` finding (UAF/leak/NULL-deref) vs baseline; needs a configured nginx build (`NGX_BUILD`) | `fanalyzer_baseline.txt` | `--regen` |

## The ratchet pattern

Several guards freeze pre-existing violations in a backlog file and fail
only on NEW ones. Rules:

- Backlog entries may only **shrink** — fixing a violation and regenerating
  is the only sanctioned edit.
- `--regen` only after a deliberate, reviewed change (e.g. you split an
  oversized file, or fixed a batch of links). Review the diff before
  committing it.
- Never hand-edit a backlog to silence a failure. The failure is the point.
- A red-and-ignored gate is worse than no gate: both size ratchets drifted
  (18 and 12 violations respectively) during the period nothing ran them.

## Two file-size regimes (both intentional)

- **`tests/lint_loc.sh --strict`** is the **hard wall**: 800 logical LOC,
  baseline `tests/loc_baseline.txt`, enforced by `.github/workflows/loc.yml`.
  Scope includes `src/`, `client/`, plus `tests/`/`utils/`/`k8s-tests/`
  shell and Python. Per-file exemption marker: `loc-lint: exempt` in the
  first 40 lines.
- **`tools/ci/check_file_size.sh`** is the **soft target**: ~500 lines
  (coding-standards §1, one concept per file), `src/` only, backlog-
  ratcheted, enforced by `guards.yml`.

A file under the 800 wall can still fail the 500 ratchet. The soft cap is
where files should live; the hard wall is where growth stops being a
review-taste question and becomes a CI failure.

## Static analysis

`run_fanalyzer.sh` compiles the module under gcc `-fanalyzer` and diffs
findings against `fanalyzer_baseline.txt`. It needs a configured nginx
build tree (`NGX_BUILD=/path/to/nginx-1.28.3`, default `/tmp/nginx-1.28.3`).
It runs weekly + on dispatch in CI (`.github/workflows/fanalyzer.yml`,
non-blocking until proven stable across GCC versions); local runs against
the dev build remain the authoritative gate. `--filter <path-prefix>` for
a fast scoped scan.
