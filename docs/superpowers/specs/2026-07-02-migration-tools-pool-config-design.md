# Migration-tool pool configuration (`--config` site profile) — design

**Status:** design, 2026-07-02
**Owner:** Rob Currie
**Predecessors:**
[`2026-07-02-python-xrdceph-cephfs-migration-design.md`](2026-07-02-python-xrdceph-cephfs-migration-design.md),
[`../10-reference/xrdceph-cephfs-bidirectional-migration.md`](../../docs/10-reference/xrdceph-cephfs-bidirectional-migration.md)

Add a site-profile config file to **all four** XrdCeph⇄CephFS migration tools
(Python `xrdceph_striper_migrate.py` / `xrdceph_cephfs_to_striper.py` and C++
`xrdceph_striper_migrate.cpp` / `xrdceph_cephfs_to_striper.cpp`) so pools and
connection identity are defined once per site instead of retyped per
invocation, and so the previously hardcoded client id (`admin`) and default-fs
assumption become configurable.

## 1. File format

Flat `key = value` lines, `#` comments (inline comments allowed), blank lines
ignored, no sections. Recognised keys (all optional in the file itself):

| key | used by | meaning | built-in default |
|---|---|---|---|
| `striper_pool` | all four | libradosstriper (stock XrdCeph) pool | — (required) |
| `meta_pool` | reverse tools | CephFS metadata pool | — (required, reverse) |
| `data_pool` | all four | CephFS data pool | — (required) |
| `conf` | all four | ceph.conf path | `$CEPH_CONF` else `/etc/ceph/ceph.conf` |
| `client` | all four | ceph client id (`client.<id>`) | `admin` |
| `fs_name` | forward tools | CephFS filesystem to mount | default fs |
| `dest_prefix` | forward tools | destination path prefix | — (required, forward) |
| `strip` | all four | leading soid/path prefix to strip | empty |

**Unknown keys are a hard error** (typo protection for tools that can delete
data). Values may be empty (= unset). Whitespace around `key`, `=`, and value
is trimmed.

## 2. CLI semantics (identical across all four tools)

- New `--config PATH` option. When absent, env `XRDCEPH_MIGRATE_CONF`
  supplies the path. No implicit CWD search.
- **Precedence: explicit CLI > config file > built-in default.** Existing
  flags (`--conf`, `--strip`) override their file keys; positionals override
  `striper_pool`/`meta_pool`/`data_pool`/`dest_prefix`.
- **Arity rule:** a tool accepts either its full legacy positional arity
  (behaviour unchanged; the file still supplies `client`/`fs_name`/defaults)
  or **zero positionals** (pools/dest come from the file). Any other
  positional count with a config in play → usage error (exit 2) naming what
  is missing/extra. A required key resolvable from neither source → usage
  error naming the key.
- `--conf` CLI default changes from eager `$CEPH_CONF`-or-`/etc/ceph/ceph.conf`
  to unset-then-resolve, so the file's `conf` can take effect beneath it.

## 3. Newly configurable connection identity

- **`client`** replaces hardcoded `"admin"`: C++ forward
  (`g_cluster.init`, `ceph_create`), C++ reverse (`g_cl.init`, and
  `verify_striper`'s own `rados_create`), Python tools
  (`rados.Rados(rados_id=…)`, `LibCephFS` auth id) and
  `ManifestBridge(client=…)` (parameter already exists).
- **`fs_name`** selects the CephFS on multi-fs clusters: C++ forward via
  `ceph_select_filesystem()` before `ceph_mount`; Python forward via
  `LibCephFS.mount(filesystem_name=…)`. Unset keeps today's default-fs mount.

## 4. Implementation shape

- **Python:** `pymigrate/common.py` gains
  `load_tool_config(path) -> dict[str,str]` (parser + unknown-key rejection)
  and `resolve_setting(cli_value, config, key, default)` used by both tools;
  positionals become `nargs="?"` with the arity rule enforced post-parse.
- **C++:** new shared header `tests/ceph/xrdceph_migrate_config.h` — a
  `struct xrdceph_migrate_cfg` + `xrdceph_migrate_cfg_load(path, &cfg, err)`
  parser + accessors, header-only so both single-file `g++` builds keep
  working. Both `.cpp` tools add `--config` to their arg loops, apply the
  same precedence/arity rule, and thread `client`/`fs_name` through connects.

## 5. Testing

- **Unit (no cluster,** `test_cephfs_meta.py`**):** parse (comments, inline
  comments, whitespace, empty values), unknown-key rejection, precedence
  merge, arity-rule validation.
- **e2e Python (`run_py_migrate.sh`):** new config leg — write a profile,
  run both tools with zero positionals (forward redirect+verify+rollback,
  reverse report-only), assert a mixed-arity invocation and an unknown-key
  file are refused with exit 2.
- **e2e C++ (`run_striper_migrate.sh`):** zero-positional config-file leg
  for the forward tool; reverse tool covered by a `--config … --report-only`
  invocation.
- Docs: `tests/ceph/README.md` Python-tools section + the bidirectional
  reference's command section document the file, keys, and precedence.

## 6. Non-goals

- No pool auto-discovery from `ceph fs ls` (rejected alternative).
- No change to any migration semantics, wire behaviour, or safety guards.
- No config keys for per-run knobs (`--verify`, `--threads`, modes, lists).
