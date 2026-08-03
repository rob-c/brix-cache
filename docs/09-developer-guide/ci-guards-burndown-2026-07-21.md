# CI-Guard Burndown 2026-07-21: post sh→py guard-port green-up

This is the durable decision record for the 2026-07-21 CI-guard burndown that
followed the `.sh`→`.py` guard port. Agent memory entries about this work point
here rather than restate it, so the rationale cannot drift from the code.

## Context

After pulling `90c8116e8` (guard fleet ported from `.sh` to `.py`, plus new CMS
and rados code), the `tools/ci` guard fleet was red both locally on the EL9
4-core box **and** on GitHub `main`. The failures split into three classes:
Python-version portability, guards referencing files that upstream never
committed, and exemption regexes that a source-tree split had outrun. All were
fixed in-tree on 2026-07-21; the two ratchet baselines were re-frozen with OP
approval.

## What was fixed

- **EL9 py3.9 portability** — `tools/ci/check_sd_driver_conformance.py` crashed
  on EL9's python3.9 because of a `Path | None` PEP-604 annotation. Fixed with
  `from __future__ import annotations` (confirmed present,
  `check_sd_driver_conformance.py:29`). GitHub's py3.12 runner never saw this
  failure, so it was a local-only red.

- **Missing `readability.py` helper** — `check_complexity.py` imports
  `tools/readability.py`, which upstream never committed. Authored it:
  `find_lizard` / `run_lizard` / `CCN_MAX = 15` / `gate_rows`, plus a
  `--gate-csv` CLI that emits the over-cap `file,func,ccn` rows. Confirmed at
  `tools/readability.py` (`CCN_MAX = 15` at line 37; `find_lizard`, `run_lizard`,
  `gate_rows` present). `lizard` is installed via `pip3 install --user lizard`;
  `check_duplication.py` shares the same `find_lizard` locator
  (`check_duplication.py:56`).

- **16 CCN>15 functions decomposed to ≤15** — CMS `blacklist_file` / `fanout` /
  `meter` / `node_ops`, manager `health_check`, rados `sd_ceph_object`, s3
  `sd_s3_meta`, `runtime_server_backend`, client `cks_verify`, and 3 python
  tools.

- **VFS-identity exemption regex widened** — `check_vfs_identity_branch.py`'s
  `EXEMPT` regex only matched `vfs_backend_(config|registry).c`; the phase-79
  split fanned those into `vfs_backend_config_http.c` etc. Widened the pattern
  to `\w*`. Confirmed at `check_vfs_identity_branch.py:35`:
  `EXEMPT = re.compile(r'/vfs_backend_(config|registry)\w*\.c:')`.

- **6 module READMEs written** — `src/auth/gssapi/README.md`,
  `src/auth/s3/README.md`, `src/core/negcache/README.md`,
  `src/core/seccomp/README.md`, `src/observability/accesslog/README.md`,
  `src/protocols/gridftp/README.md` (all confirmed present).

- **5 port constants documented** — added to
  `docs/10-reference/test-fleet-ports.md` (confirmed present).

- **Client link fix** — `client/Makefile` `CEPH_CORE_SRCS` was missing the new
  `sd_ceph_dir.c`, so the rescue/migrate tools failed to link. Confirmed
  `sd_ceph_dir.c` is now in `CEPH_CORE_SRCS` (`client/Makefile:436`), feeding
  `xrdrados_rescue` / `xrdceph_migrate`.

## Dual-build gotcha

The test fleet runs **RPM nginx 1.20.1 + dynamic modules**
(`build/build-nginx-modules.sh` → install to `/usr/lib64/nginx/modules`), **not**
the static `/tmp/nginx-1.28.3` tree used elsewhere. Any new code that uses
post-1.20 nginx APIs must be `#if (nginx_version …)`-guarded or it breaks the
dynamic-module build the tests actually load. Two such guards were added:

- **Stream virtual-server walk** (`cmcf->ports` / `addr[].servers`, requires
  `nginx_version >= 1025005`) — originally in `postconfiguration.c`. That file
  has since been split; the guard now lives in
  `src/core/config/postconfiguration_proxy_acl.c`
  (`#if (nginx_version < 1025005)` at line 18, closing `#endif` at line 114).

- **`ngx_table_elt_t.next`** (requires `nginx_version >= 1023000`) — originally
  in `webdav/access.c`. That file has since been split; the `>= 1023000` guards
  now live in `src/protocols/webdav/access_auth.c` (lines 129, 178) and
  `src/protocols/webdav/auth_token.c:249`, with a sibling guard in
  `src/observability/dashboard/dashboard_auth_parse.c:35`.

## Ratchets re-frozen (OP-approved)

Two lizard-backed ratchet baselines were regenerated to accept the current
accumulated debt as the ceiling, while still blocking any *new* debt:

- `check_file_size --regen` — 96 entries.
- `check_duplication --regen` — 329 entries.

After the burndown, all 16 `tools/ci` guards were green, and
`tests/test_ci_guards.py -m "not slow"` reported 16 passed.

## pytest-timeout calibration

`check_duplication` runs `lizard` over three source trees: ~18s on an 8-core CI
runner but ~133s on the local 4-core box. The lizard-lane `@pytest.mark.timeout`
in `tests/test_ci_guards.py` was bumped 120→300 so the slow box passes.
Confirmed: `@pytest.mark.timeout(300)` gating `test_ci_lizard_guard_green`
(parametrized over `check_complexity`, `check_duplication`) at
`tests/test_ci_guards.py:143`. GitHub CI was never affected because `guards.yml`
invokes each guard directly, with no pytest timeout wrapping it. Note:
`check_doc_links` under pytest can also transiently exceed its cap under parallel
load, but passes when run solo.

## See also

- [Fast-lane burndown 2026-07](fast-lane-burndown-2026-07.md) — sibling
  post-migration failure burndown on the same root box.
