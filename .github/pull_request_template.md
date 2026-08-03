<!--
Delete anything that does not apply — an unedited template tells a reviewer
nothing. The checklist is the project's actual merge bar, not decoration; the
items with a guard next to them are enforced by CI either way, so ticking them
before pushing just saves you a round trip.
-->

## What and why

<!-- What changed, and the problem it solves. Link the issue if there is one.
     If this fixes a bug, say what the root cause was — not just the symptom. -->

## How

<!-- The approach, and anything a reviewer would otherwise have to reconstruct:
     why this seam, what you rejected, which invariant made the decision. -->

## Testing

<!-- Commands you ran and what they proved. "Tests pass" is not evidence;
     `PYTHONPATH=tests pytest tests/test_x.py -v` with a result is. -->

- [ ] **Three tests** for each behaviour change: success, error, **and a
      security negative** proving the rejection actually happens.
- [ ] Fast tier green: `PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite --fast`
- [ ] Guards green: `for g in $(tools/ci/guard_set.py); do "$g"; done` *(the
      pre-push hook runs exactly this set)*

## Checklist

- [ ] **Build wiring** — new `src/*.c` added to the repo-root `./config`; new
      `client/` or `shared/{cvmfs,cache}` `.c` added to `client/Makefile`
      *(guards: `check_config_coverage.py`, `check_client_build_coverage.py`)*
- [ ] **`objs/nginx -t` passes** after a rebuild, if the module changed.
- [ ] **Coding standard** — no `goto`, no new globals, early-return, existing
      helpers reused rather than reimplemented
      *(`docs/09-developer-guide/coding-standards.md`)*
- [ ] **VFS seam** — raw data syscalls only under `src/fs/backend/`, otherwise
      `brix_vfs_*` or a same-line `/* vfs-seam-allow: <reason> */`
      *(guard: `check_vfs_seam.py`, INVARIANT 12)*
- [ ] **File size** — nothing crosses the 600-line cap; the backlog stays empty
      (split, never grandfather) *(guard: `check_file_size.py`)*
- [ ] **Dependencies** — any new Python import is declared with **both** bounds
      in the right requirements file; optional deps are `importorskip`ed
      *(guard: `check_python_deps.py`)*
- [ ] **Docs updated** — the guide that a reader would consult for this
      behaviour, not only the code comment.

## Security

<!-- Required for anything touching auth, authz, credentials, path resolution,
     the cache, or a byte parser. "No impact, because …" is a complete answer;
     leaving this blank is not. See SECURITY.md for what counts as in scope. -->

- [ ] This change does not widen what an unauthenticated client can reach.
- [ ] Identity-derived data (credentials, cache entries, temp paths) stays
      confined to that identity.
- [ ] No dependency bound was widened just to make a build pass.
