# Migration-Tools Pool Config (`--config`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Site-profile config file (`--config` / `$XRDCEPH_MIGRATE_CONF`) for all four migration tools, making pools, ceph.conf, client id, fs name, dest prefix and strip configurable with CLI-over-file precedence.

**Architecture:** Python parser+merge in `pymigrate/common.py` consumed by both `.py` tools; header-only C++ equivalent `tests/ceph/xrdceph_migrate_config.h` consumed by both `.cpp` tools. Arity rule: full legacy positionals OR zero positionals. Spec: `docs/superpowers/specs/2026-07-02-migration-tools-pool-config-design.md`.

**Tech Stack:** Python 3.9 stdlib; C++17 header-only (no new libs). e2e via existing Docker runners.

## Global Constraints
- Keys: `striper_pool meta_pool data_pool conf client fs_name dest_prefix strip`; unknown key = hard error; `#` comments (incl. inline), trimmed whitespace, empty value = unset.
- Precedence: explicit CLI > config file > default (`conf`: `$CEPH_CONF`→`/etc/ceph/ceph.conf`; `client`: `admin`; `fs_name`: default fs).
- Positional arity: full legacy count or zero; otherwise exit 2 with a message naming the gap. Missing required key → exit 2 naming the key.
- No behaviour change for existing full-positional invocations. C++ single-file `g++` builds must keep working (header-only).

### Task 1: Python config parser + merge (`pymigrate/common.py`) with unit tests
- [ ] tests in `test_cephfs_meta.py`: parse file (comments/inline/whitespace/empty), unknown-key ValueError, `resolve_setting` precedence (cli>file>default), env-var default path handling
- [ ] implement `CONFIG_KEYS`, `load_tool_config(path) -> dict`, `resolve_setting(cli, cfg, key, default=None)`
- [ ] pytest green → commit `feat(pymigrate): site-profile config parser (--config)`

### Task 2: Python tools wiring
- [ ] both tools: add `--config` (default `os.environ.get("XRDCEPH_MIGRATE_CONF")`); positionals `nargs="?"`; post-parse: load file, enforce arity rule (all-or-none), resolve pools/dest/strip/conf; `client` → `rados.Rados(rados_id=…)` + bridge + (`LibCephFS` auth id via conf name param) ; `fs_name` → `LibCephFS.mount(filesystem_name=…)` (tool 1 only)
- [ ] container smoke: zero-positional run with a profile == positional run; mixed arity refused
- [ ] commit `feat(pymigrate): --config wiring in both Python tools`

### Task 3: C++ header + forward tool
- [ ] `tests/ceph/xrdceph_migrate_config.h`: `struct xrdceph_migrate_cfg { std::map<std::string,std::string> kv; }`, `xrdceph_migrate_cfg_load(path, cfg, errbuf)` (unknown key → false), `cfg_get(cfg, key, dflt)`
- [ ] `xrdceph_striper_migrate.cpp`: `--config` in arg loop (+`$XRDCEPH_MIGRATE_CONF`), arity rule (3 or 0 positionals), resolve spool/dpool/dest/strip/conf/client/fs_name; `init(client)`, `ceph_create(cm, client)`, `ceph_select_filesystem` when fs_name set
- [ ] compile in container + zero-positional smoke → commit `feat(cephfs-migrate): --config site profile (C++ forward tool)`

### Task 4: C++ reverse tool
- [ ] same wiring in `xrdceph_cephfs_to_striper.cpp` (3-or-0 positionals; client through `g_cl.init` AND `verify_striper`'s `rados_create`)
- [ ] compile + `--config --report-only` smoke → commit `feat(cephfs-migrate): --config site profile (C++ reverse tool)`

### Task 5: e2e runner legs
- [ ] `run_py_migrate.sh`: config leg (profile file; fwd redirect+verify+rollback with 0 positionals; reverse report-only; mixed-arity exit 2; unknown-key exit 2)
- [ ] `run_striper_migrate.sh`: forward zero-positional config leg
- [ ] both runners green → commit `test(cephfs-migrate): config-file e2e legs`

### Task 6: docs + final sweep
- [ ] README Python-tools section + bidirectional reference command section: file format, keys table, precedence, arity rule
- [ ] unit tests + both runners green; commit `docs(cephfs-migrate): --config documentation`
