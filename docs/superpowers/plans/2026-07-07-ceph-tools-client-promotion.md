# Ceph Operator Tools — Client Suite Promotion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the CephFS↔RADOS (XrdCeph) migration + rescue tool family from `tests/ceph/` into `client/apps/ceph/` as official, dep-gated, installed, documented client tools.

**Architecture:** `git mv` the five tools (C++ pair, Python pair + `pymigrate/`, three C utilities) plus their two support headers into a new `client/apps/ceph/` bucket; add a librados-gated optional build section to `client/Makefile` (FUSE3-gating pattern); repoint the `tests/ceph/` runners, docs, and the RPM spec at the new home. The C++ rollback-hazard fix in the spec turns out to be **already landed** — Task 3 verifies it instead of re-fixing.

**Tech Stack:** GNU make, C11 (`cc`), C++17 (`g++`), Python 3, librados/libradosstriper/libcephfs, roff man pages, bash completions, RPM spec.

**Spec:** `docs/superpowers/specs/2026-07-07-ceph-tools-client-promotion-design.md`

## Global Constraints

- Installed binary names are frozen: `xrdceph_striper_migrate`, `xrdceph_cephfs_to_striper` (C++, bare names), `xrdceph_striper_migrate.py`, `xrdceph_cephfs_to_striper.py` (Python), `xrdrados_rescue`, `xrdcephfs_rescue`, `xrdceph_migrate`.
- `make -C client` must stay green on a machine with **no** Ceph dev packages (all five tools silently skipped) — this box has none, so that is the local proof.
- `client/Makefile` and `packaging/rpm/nginx-mod-brix-cache.spec` carry uncommitted user WIP: edits are surgical (Edit tool, exact anchors), never wholesale rewrites, and MUST NOT touch unrelated hunks. Never run `git stash`/`checkout`/`reset`.
- Commit directly to `main` (no branches). Commit ONLY the files each task names — the working tree has unrelated WIP.
- `k8s-tests/remote-suite/` is a never-clobber fork maintained by `k8s-tests/labtools/sync.py`; it keeps its own snapshots of the old layout **by design**. Do not touch it.
- `docs/superpowers/{specs,plans}` history files are immutable records — do not update path references inside them.
- The spec's Task-4 hazard: both C++ tools ALREADY detach stubs before unlink/remove (`detach_stubs()` at `xrdceph_striper_migrate.cpp:279` used by rollback:464 and --force:332; reverse tool `unset_manifest` before `remove` at `xrdceph_cephfs_to_striper.cpp:315-316`). Task 3 verifies and documents; it does not change tool logic.
- NO `goto` in any `.c`/`.h`/`.cpp` you touch; moved files are moved verbatim (no reformatting).

---

### Task 1: Move the tool family into `client/apps/ceph/` and repoint `tests/ceph/`

**Files:**
- Move (git mv): `tests/ceph/{xrdceph_striper_migrate.cpp,xrdceph_striper_migrate.py,xrdceph_cephfs_to_striper.cpp,xrdceph_cephfs_to_striper.py,xrdceph_migrate_config.h,xrdrados_rescue.c,xrdcephfs_rescue.c,xrdceph_migrate.c,ngx_shim.h}` → `client/apps/ceph/`
- Move (git mv): `tests/ceph/pymigrate/{__init__.py,common.py,cephfs_meta.py,radosbridge.py}` → `client/apps/ceph/pymigrate/`, `tests/ceph/pymigrate/shim/rados_manifest_shim.cpp` → `client/apps/ceph/pymigrate/shim/`
- Modify: `tests/ceph/run_py_migrate.sh`, `tests/ceph/run_striper_migrate.sh`, `tests/ceph/run_rescue_tools.sh`, `tests/ceph/run_cephfs_ro_live.sh`, `tests/ceph/run_sd_ceph_live.sh`, `tests/ceph/test_cephfs_meta.py`, `tests/ceph/sd_ceph_live_test.c`, `tests/ceph/sd_cephfs_ro_live_test.c` (comment/build-line references only in the two `.c`)

**Interfaces:**
- Produces: `client/apps/ceph/` as the sole source location; every later task references files there. `tests/ceph/` keeps the harness, seeds, spikes, unit tests, and all `run_*.sh`.

- [ ] **Step 1: Create the bucket and git-mv every tracked file**

```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
mkdir -p client/apps/ceph/pymigrate/shim
for f in xrdceph_striper_migrate.cpp xrdceph_striper_migrate.py \
         xrdceph_cephfs_to_striper.cpp xrdceph_cephfs_to_striper.py \
         xrdceph_migrate_config.h xrdrados_rescue.c xrdcephfs_rescue.c \
         xrdceph_migrate.c ngx_shim.h; do
  git mv "tests/ceph/$f" "client/apps/ceph/$f"
done
for f in __init__.py common.py cephfs_meta.py radosbridge.py; do
  git mv "tests/ceph/pymigrate/$f" "client/apps/ceph/pymigrate/$f"
done
git mv tests/ceph/pymigrate/shim/rados_manifest_shim.cpp \
       client/apps/ceph/pymigrate/shim/rados_manifest_shim.cpp
rm -rf tests/ceph/pymigrate/__pycache__ tests/ceph/__pycache__
rmdir tests/ceph/pymigrate/shim tests/ceph/pymigrate 2>/dev/null || true
```

Note: `xrdceph_striper_migrate.py` / `xrdceph_cephfs_to_striper.py` have uncommitted working-tree edits — `git mv` carries them along; that is intended (the WIP moves with the file). If `git mv` aborts on an untracked file, move that one with plain `mv` + `git add`.

- [ ] **Step 2: Verify nothing tool-related is left behind**

Run: `ls tests/ceph/ | grep -E "xrdceph|xrdrados|xrdcephfs_rescue|pymigrate|ngx_shim"`
Expected: no output.
Run: `ls client/apps/ceph/ client/apps/ceph/pymigrate/`
Expected: all 9 top files + 4 package files + `shim/`.

- [ ] **Step 3: Repoint the runners**

In each file, replace path references to moved files (moved files ONLY — `striper_seed.c`, `cephfs_seed*.c`, unit tests, fixtures stay `tests/ceph/`):

`tests/ceph/run_py_migrate.sh` (lines ~28-30):
```bash
docker cp "$REPO/client/apps/ceph/pymigrate" "$WORK:/work/pymig/" >/dev/null
for f in xrdceph_striper_migrate.py xrdceph_cephfs_to_striper.py; do
    docker cp "$REPO/client/apps/ceph/$f" "$WORK:/work/pymig/$f" >/dev/null
done
docker cp "$REPO/tests/ceph/striper_seed.c" "$WORK:/work/pymig/striper_seed.c" >/dev/null
```
(The original loop copied all three from one dir; split it as above since `striper_seed.c` stays.)

`tests/ceph/run_striper_migrate.sh` (~lines 25-26, 33-34): the docker-cp list and the `g++` build line change `tests/ceph/xrdceph_striper_migrate.cpp` → `client/apps/ceph/xrdceph_striper_migrate.cpp` and `tests/ceph/xrdceph_migrate_config.h` → `client/apps/ceph/xrdceph_migrate_config.h`; keep `tests/ceph/striper_seed.c` as is. Update the in-container destination dirs and `-I` flags to match wherever the script cps them (mirror its existing structure — if it cps into `/work/repo/tests/ceph/`, change that destination to `/work/repo/client/apps/ceph/` for the moved files and fix the compile lines' paths accordingly).

`tests/ceph/run_rescue_tools.sh` (~lines 22-31 cp list, plus the three gcc lines below): `tests/ceph/ngx_shim.h`, `tests/ceph/xrdcephfs_rescue.c`, `tests/ceph/xrdrados_rescue.c`, `tests/ceph/xrdceph_migrate.c` → `client/apps/ceph/...`, add `client/apps/ceph` to the container `mkdir -p` line, and update `-include` / source paths in the gcc commands.

`tests/ceph/run_cephfs_ro_live.sh`, `tests/ceph/run_sd_ceph_live.sh`: same treatment for their `ngx_shim.h` references (cp lines and `-include tests/ceph/ngx_shim.h` → `-include client/apps/ceph/ngx_shim.h`, container mkdir if needed).

`tests/ceph/sd_ceph_live_test.c`, `tests/ceph/sd_cephfs_ro_live_test.c`: their `ngx_shim` mentions are in header BUILD comments — update the documented path.

- [ ] **Step 4: Repoint the pymigrate import in the unit test**

`tests/ceph/test_cephfs_meta.py` line ~20 currently:
```python
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
```
Replace with:
```python
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "client", "apps", "ceph"))
```

- [ ] **Step 5: Verify — unit tests + shell syntax**

Run: `python3 -m pytest tests/ceph/test_cephfs_meta.py -v 2>&1 | tail -3`
Expected: all pass, 0 failures (no cluster needed).
Run: `for s in tests/ceph/run_py_migrate.sh tests/ceph/run_striper_migrate.sh tests/ceph/run_rescue_tools.sh tests/ceph/run_cephfs_ro_live.sh tests/ceph/run_sd_ceph_live.sh; do bash -n $s && echo "OK $s"; done`
Expected: 5× OK.
Run: `grep -rn "tests/ceph/pymigrate\|tests/ceph/xrdceph\|tests/ceph/xrdrados\|tests/ceph/xrdcephfs_rescue\|tests/ceph/ngx_shim" tests/ src/ client/ shared/ packaging/ --include="*.sh" --include="*.py" --include="*.c" --include="*.h" | grep -v Binary`
Expected: only `packaging/rpm/nginx-mod-brix-cache.spec` hits remain (fixed in Task 6).

- [ ] **Step 6: Commit**

```bash
git add client/apps/ceph tests/ceph
git commit -m "refactor(client): promote ceph operator tool family to client/apps/ceph/" \
  -- client/apps/ceph tests/ceph
```

---

### Task 2: Dep-gated build + install in `client/Makefile`

**Files:**
- Modify: `client/Makefile` (three insertion points; file has user WIP — use exact anchors, keep every existing line intact)

**Interfaces:**
- Consumes: `client/apps/ceph/*` from Task 1.
- Produces: make vars `CEPH_EXES`, `CEPH_TOOL_NAMES`, `LIBEXECDIR`; phony `ceph-tools`; binaries in `client/bin/`; `install-bin` installs the Python tools to `$(LIBEXECDIR)` with `bin/*.py` symlinks. Task 6 (RPM) invokes `make -C client ceph-tools`.

- [ ] **Step 1: Insert the gating block**

Anchor: immediately AFTER the FUSE gating block that ends with (Makefile ~line 180):
```make
ifeq ($(HAVE_FUSE3),yes)
  OPT_EXES += $(BINDIR)/xrootdfs
  OPT_EXES += $(BINDIR)/brixMount
endif
```
Insert:
```make
# Ceph operator tools (apps/ceph/) — migration + rescue utilities linking
# librados directly (storage-plane, not root://). Compile-gated like fuse3:
# each tool joins OPT_EXES only when its own dev headers are present. The two
# C++ tools additionally need a C++ compiler. Header probes (not pkg-config —
# the striper/cephfs libs don't reliably ship .pc files) mirror the bzlib
# probe above.
CXX ?= g++
HAVE_CXX          := $(shell command -v $(CXX) >/dev/null 2>&1 && echo yes)
HAVE_RADOS        := $(shell printf '\#include <rados/librados.h>\n' | $(CC) -E -x c - >/dev/null 2>&1 && echo yes)
HAVE_RADOSSTRIPER := $(shell printf '\#include <radosstriper/libradosstriper.h>\n' | $(CC) -E -x c - >/dev/null 2>&1 && echo yes)
HAVE_CEPHFS       := $(shell printf '\#include <cephfs/libcephfs.h>\n' | $(CC) -E -x c - >/dev/null 2>&1 && echo yes)
CEPH_EXES :=
ifeq ($(HAVE_RADOS),yes)
  CEPH_EXES += $(BINDIR)/xrdrados_rescue $(BINDIR)/xrdcephfs_rescue $(BINDIR)/xrdceph_migrate
  ifeq ($(HAVE_CXX)$(HAVE_CEPHFS),yesyes)
    CEPH_EXES += $(BINDIR)/xrdceph_striper_migrate
  endif
  ifeq ($(HAVE_CXX)$(HAVE_RADOSSTRIPER),yesyes)
    CEPH_EXES += $(BINDIR)/xrdceph_cephfs_to_striper
  endif
endif
OPT_EXES += $(CEPH_EXES)
CEPH_TOOL_NAMES := xrdrados_rescue xrdcephfs_rescue xrdceph_migrate \
                   xrdceph_striper_migrate xrdceph_cephfs_to_striper
```
(This sits before `all:` so `OPT_EXES` is complete when the `all` prerequisites are read.)

- [ ] **Step 2: Insert build rules + `ceph-tools` target**

Anchor: immediately AFTER the `$(BINDIR)/brixMount:` recipe block (ends `@echo " + built $@ (CVMFS-brix + XRootDFS-brix; libfuse3/libcurl/libsqlite3)"`). Insert:
```make
# --- Ceph operator tools (apps/ceph/) -------------------------------------
# Build recipes mirror tests/ceph/run_rescue_tools.sh and the RPM spec. The C
# tools force-include the ngx shim and compile the sd_ceph driver sources
# directly; the reverse C++ tool keeps its CephFS decoders as C objects (g++
# would treat the .c inputs as C++ and break their extern "C" boundary).
CEPH_RADOS_DIR := $(SRC)/fs/backend/rados
CEPH_C_FLAGS   := -std=c11 -Wall -Wextra -D_FILE_OFFSET_BITS=64 $(HARDEN) $(OPT) \
                  -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH \
                  -I$(SRC)/fs/backend -I$(CEPH_RADOS_DIR) -Iapps/ceph \
                  -include apps/ceph/ngx_shim.h $(CFLAGS)
CEPH_CXX_FLAGS := -std=c++17 -Wall -Wextra -D_FILE_OFFSET_BITS=64 $(HARDEN) $(OPT) \
                  -Iapps/ceph $(CFLAGS)

$(BINDIR)/xrdrados_rescue: apps/ceph/xrdrados_rescue.c $(CEPH_RADOS_DIR)/sd_ceph.c \
		$(CEPH_RADOS_DIR)/sd_ceph_compat.c apps/ceph/ngx_shim.h | $(BINDIR)
	$(CC) $(CEPH_C_FLAGS) $(LDFLAGS) $(LDFLAGS_PIE) $(filter %.c,$^) -lrados -o $@
	@echo " + built $@ (librados)"

$(BINDIR)/xrdceph_migrate: apps/ceph/xrdceph_migrate.c $(CEPH_RADOS_DIR)/sd_ceph.c \
		$(CEPH_RADOS_DIR)/sd_ceph_compat.c apps/ceph/ngx_shim.h | $(BINDIR)
	$(CC) $(CEPH_C_FLAGS) $(LDFLAGS) $(LDFLAGS_PIE) $(filter %.c,$^) -lrados -o $@
	@echo " + built $@ (librados)"

$(BINDIR)/xrdcephfs_rescue: apps/ceph/xrdcephfs_rescue.c $(CEPH_RADOS_DIR)/sd_cephfs_ro.c \
		$(CEPH_RADOS_DIR)/sd_ceph.c $(CEPH_RADOS_DIR)/sd_ceph_compat.c \
		$(CEPH_RADOS_DIR)/cephfs_denc.c $(CEPH_RADOS_DIR)/cephfs_layout.c \
		apps/ceph/ngx_shim.h | $(BINDIR)
	$(CC) $(CEPH_C_FLAGS) $(LDFLAGS) $(LDFLAGS_PIE) $(filter %.c,$^) -lrados -o $@
	@echo " + built $@ (librados; cephfsro core)"

apps/ceph/cephfs_denc.o: $(CEPH_RADOS_DIR)/cephfs_denc.c
	$(CC) -std=c11 -Wall -Wextra -D_FILE_OFFSET_BITS=64 $(OPT) -I$(CEPH_RADOS_DIR) $(CFLAGS) -c $< -o $@
apps/ceph/cephfs_layout.o: $(CEPH_RADOS_DIR)/cephfs_layout.c
	$(CC) -std=c11 -Wall -Wextra -D_FILE_OFFSET_BITS=64 $(OPT) -I$(CEPH_RADOS_DIR) $(CFLAGS) -c $< -o $@

$(BINDIR)/xrdceph_striper_migrate: apps/ceph/xrdceph_striper_migrate.cpp \
		apps/ceph/xrdceph_migrate_config.h | $(BINDIR)
	$(CXX) $(CEPH_CXX_FLAGS) $(LDFLAGS) $(LDFLAGS_PIE) \
	    apps/ceph/xrdceph_striper_migrate.cpp -lrados -lcephfs -pthread -o $@
	@echo " + built $@ (librados/libcephfs; C++17)"

$(BINDIR)/xrdceph_cephfs_to_striper: apps/ceph/xrdceph_cephfs_to_striper.cpp \
		apps/ceph/xrdceph_migrate_config.h apps/ceph/cephfs_denc.o apps/ceph/cephfs_layout.o | $(BINDIR)
	$(CXX) $(CEPH_CXX_FLAGS) -I$(CEPH_RADOS_DIR) $(LDFLAGS) $(LDFLAGS_PIE) \
	    apps/ceph/xrdceph_cephfs_to_striper.cpp \
	    apps/ceph/cephfs_denc.o apps/ceph/cephfs_layout.o \
	    -lrados -lradosstriper -o $@
	@echo " + built $@ (librados/libradosstriper; C++17)"

# `make -C client ceph-tools` — build exactly this group (used by the RPM spec).
.PHONY: ceph-tools
ceph-tools: $(CEPH_EXES)
ifeq ($(strip $(CEPH_EXES)),)
	@echo "ceph-tools: skipped — librados dev headers not found" \
	     "(need librados-devel; + libradosstriper-devel/libcephfs-devel and a C++ compiler for the migration pair)"
endif

# Bare-name aliases (`make -C client xrdrados_rescue`), like $(BINS).
.PHONY: $(CEPH_TOOL_NAMES)
$(CEPH_TOOL_NAMES): %: $(BINDIR)/%
```

- [ ] **Step 3: Python install into libexec**

Anchor 1: after the `PKGCONFDIR ?= $(LIBDIR)/pkgconfig` line add:
```make
# Python migration tools + their pymigrate package live under libexec; bin/
# gets *.py symlinks (relative, so DESTDIR staging keeps working).
LIBEXECDIR ?= $(PREFIX)/libexec/brix
```
Anchor 2: inside the `install-bin:` recipe, append after the two `for m in man/*...` lines:
```make
	install -d $(DESTDIR)$(LIBEXECDIR)/pymigrate/shim
	install -m755 apps/ceph/xrdceph_striper_migrate.py \
	              apps/ceph/xrdceph_cephfs_to_striper.py $(DESTDIR)$(LIBEXECDIR)/
	install -m644 apps/ceph/pymigrate/__init__.py apps/ceph/pymigrate/common.py \
	              apps/ceph/pymigrate/cephfs_meta.py apps/ceph/pymigrate/radosbridge.py \
	              $(DESTDIR)$(LIBEXECDIR)/pymigrate/
	install -m644 apps/ceph/pymigrate/shim/rados_manifest_shim.cpp \
	              $(DESTDIR)$(LIBEXECDIR)/pymigrate/shim/
	ln -sf ../libexec/brix/xrdceph_striper_migrate.py $(DESTDIR)$(PREFIX)/bin/xrdceph_striper_migrate.py
	ln -sf ../libexec/brix/xrdceph_cephfs_to_striper.py $(DESTDIR)$(PREFIX)/bin/xrdceph_cephfs_to_striper.py
```
(Recipe lines are TAB-indented.)

- [ ] **Step 4: Verify — no-deps build proof (this box has no librados)**

Run: `make -C client ceph-tools`
Expected: the `ceph-tools: skipped — librados dev headers not found ...` notice, exit 0.
Run: `make -C client -j$(nproc) 2>&1 | tail -3`
Expected: full suite builds, exit 0, no ceph binaries attempted.
Run: `make -C client install-bin DESTDIR=/tmp/claude-1000/-home-rcurrie-HEP-x-nginx-xrootd/2ba1d4ce-5af4-4184-a67a-1061e6212c95/scratchpad/stage PREFIX=/usr && ls -l /tmp/claude-1000/-home-rcurrie-HEP-x-nginx-xrootd/2ba1d4ce-5af4-4184-a67a-1061e6212c95/scratchpad/stage/usr/bin/*.py /tmp/claude-1000/-home-rcurrie-HEP-x-nginx-xrootd/2ba1d4ce-5af4-4184-a67a-1061e6212c95/scratchpad/stage/usr/libexec/brix/`
Expected: two `*.py` symlinks → `../libexec/brix/...`; libexec holds the 2 tools + `pymigrate/` (4 files + `shim/`).
Run: `python3 /tmp/claude-1000/-home-rcurrie-HEP-x-nginx-xrootd/2ba1d4ce-5af4-4184-a67a-1061e6212c95/scratchpad/stage/usr/bin/xrdceph_striper_migrate.py --help >/dev/null 2>&1; echo "exit=$?"`
Expected: the symlinked tool resolves `pymigrate` (exit 0, or 1/2 only from a missing `rados` python module — NOT `ModuleNotFoundError: pymigrate`). Capture the stderr to confirm which.
Run: `make -C client test 2>&1 | tail -5`
Expected: `client unit tests: ALL PASS` + both guards green.

- [ ] **Step 5: Syntax-only C++ sanity (no librados here, so compile can't run — check make dry-run wiring instead)**

Run: `make -C client -n ceph-tools`
Expected: only the skip-notice echo (no compile commands — gates correctly closed).

- [ ] **Step 6: Commit**

```bash
git add client/Makefile
git commit -m "build(client): dep-gated ceph operator tools + libexec python install" -- client/Makefile
```

---

### Task 3: Rollback-safety audit (verify, don't fix)

**Files:**
- Read-only audit of `client/apps/ceph/xrdceph_striper_migrate.cpp`, `client/apps/ceph/xrdceph_cephfs_to_striper.cpp`
- Modify: `docs/superpowers/specs/2026-07-07-ceph-tools-client-promotion-design.md` (§4 amendment)

**Interfaces:**
- Produces: written confirmation that every unlink/remove of a possibly-redirect-migrated object is preceded by a detach; Task 5's docs cite it.

- [ ] **Step 1: Audit the forward tool**

Read `client/apps/ceph/xrdceph_striper_migrate.cpp` around `detach_stubs` (~line 279) and every caller. Confirm ALL of:
1. `rollback_one()` calls `detach_stubs(soid, ino)` BEFORE `ceph_unlink`.
2. The `--force` re-migrate path calls `detach_stubs` before its `ceph_unlink`.
3. The `--finalize` path detaches (`unset_manifest`) only AFTER the promote/copy that makes the object owned.
4. Redirect stubs are created WITHOUT a reference (`set_redirect(..., 0)` — comment "rollback never GCs the source").

- [ ] **Step 2: Audit the reverse tool**

Read `client/apps/ceph/xrdceph_cephfs_to_striper.cpp` rollback (~lines 311-318) and finalize (~lines 340-365). Confirm: rollback issues `unset_manifest` on each stub before `remove`; finalize detaches after materialization; `--delete-source` removal targets only CephFS data objects of files already finalized.

- [ ] **Step 3: Amend spec §4 with the finding**

In `docs/superpowers/specs/2026-07-07-ceph-tools-client-promotion-design.md`, replace the §4 body's claim that the C++ tool lacks the fix with a dated note: the detach-before-unlink sequence is already present in both C++ tools (forward: `detach_stubs()` used by rollback and `--force`; reverse: `unset_manifest` before `remove`); audit re-verified at promotion time; no code change required. Keep the section heading so the spec's numbering stands.

If (and only if) the audit finds a real gap: STOP, do not patch ad-hoc — report the exact call path and get sign-off on a fix task first.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-07-07-ceph-tools-client-promotion-design.md
git commit -m "docs(specs): ceph promotion §4 — detach-before-unlink already present in both C++ tools (audit)" \
  -- docs/superpowers/specs/2026-07-07-ceph-tools-client-promotion-design.md
```

---

### Task 4: Man pages + completions

**Files:**
- Create: `client/man/xrdceph_striper_migrate.1`, `client/man/xrdceph_cephfs_to_striper.1`, `client/man/xrdrados_rescue.1`, `client/man/xrdcephfs_rescue.1`, `client/man/xrdceph_migrate.1`
- Modify: `client/completions/brix-tools.bash` (new completion functions + registrations), `client/Makefile` (`install-completions` name loop)

**Interfaces:**
- Consumes: flag inventory (verified against sources):
  - `xrdceph_striper_migrate` (C++): `--mode --rollback --finalize --list --strip --threads --verify --delete-source --force --dry-run --conf --config --sample-mb --progress --help`; Python adds `--json --state --prefix --match`.
  - `xrdceph_cephfs_to_striper` (C++): `--assume-quiesced --report-only --rollback --finalize --strip --threads --verify --delete-source --dry-run --conf --config`; Python adds `--json --state --prefix --match --list --progress --help`.
  - C tools: subcommand-style (`ls|stat|get|cp` / `ls|stat|cat|get|cp -r`), no `--flags`.
- Produces: pages passing `man/check_man.sh`; completions passing `completions/check_completions.sh`.

- [ ] **Step 1: Write `client/man/xrdceph_striper_migrate.1`**

```roff
.TH XRDCEPH_STRIPER_MIGRATE 1 "July 2026" "brix client tools" "User Commands"
.SH NAME
xrdceph_striper_migrate \- enable CephFS over an existing libradosstriper (XrdCeph) RADOS pool
.SH SYNOPSIS
.B xrdceph_striper_migrate
.I striper_pool cephfs_data_pool dest_prefix
[\fIOPTIONS\fR]
.SH DESCRIPTION
Migrates a stock-XrdCeph (libradosstriper) pool to CephFS. For every logical
file the MDS builds the namespace, checksum/xattrs are carried over, and the
size is set via the MDS. Striper and CephFS share Ceph's striping algorithm,
so object index N maps to the same byte range in both; only the object NAME
differs.
.PP
The default mode is \fBzero-move\fR: a RADOS redirect stub at each data object
points at the existing striper object. No bytes are copied and the source pool
stays the single copy. \fBREAD-ONLY ONLY\fR: a write to a redirect-migrated
file writes THROUGH to the source object \(em serve the migrated CephFS
read-only until \fB\-\-finalize\fR, or the original data is silently modified
and rollback can no longer restore it.
.SH OPTIONS
.TP
.BI \-\-mode " redirect|copy"
\fBredirect\fR (default): zero-move stubs. \fBcopy\fR: server-side copy_from
(OSD-to-OSD) \(em real owned copies, transient ~2x space.
.TP
.B \-\-rollback
Remove the CephFS overlay. Every stub is DETACHED from its source first, so
the async MDS purge cannot delete-through; the source pool is left intact.
.TP
.B \-\-finalize
Materialize redirect stubs into owned objects (tier_promote, in-cluster) so
the result is a normal read-write CephFS.
.TP
.BI \-\-list " FILE"
Migrate only the soids listed (one per line); otherwise enumerate the pool.
.TP
.BI \-\-strip " PFX"
Strip a leading PFX from each soid before joining \fIdest_prefix\fR.
.TP
.BI \-\-threads " N"
Parallel workers (default 4).
.TP
.B \-\-verify
Read the migrated file and compare adler32 against the carried
user.XrdCks.adler32 checksum.
.TP
.B \-\-delete\-source
(copy mode only) Remove the striper objects after verify.
.TP
.B \-\-force
Re-migrate a file that already exists at the destination (its old stubs are
detached before the unlink).
.TP
.B \-\-dry\-run
Print what would be done without writing.
.TP
.BI \-\-sample\-mb " N"
Limit verification sampling to N MiB.
.TP
.BI \-\-conf " PATH"
Ceph configuration file (default /etc/ceph/ceph.conf).
.TP
.BI \-\-config " PATH"
Site-profile tool configuration (pool names, prefixes).
.SH PYTHON VARIANT
.B xrdceph_striper_migrate.py
is the pure-Python implementation with identical semantics plus
.BR \-\-json " (JSONL output), " \-\-state " (resumable manifest), "
.BR \-\-prefix " and " \-\-match " (worklist filters), and " \-\-progress .
It requires python3-rados and python3-cephfs.
.SH EXIT STATUS
0 all ok/skipped, 1 any per-file failure, 2 usage or guard error.
.SH SEE ALSO
.BR xrdceph_cephfs_to_striper (1),
.BR xrdrados_rescue (1),
.BR xrdcephfs_rescue (1)
```

- [ ] **Step 2: Write `client/man/xrdceph_cephfs_to_striper.1`**

```roff
.TH XRDCEPH_CEPHFS_TO_STRIPER 1 "July 2026" "brix client tools" "User Commands"
.SH NAME
xrdceph_cephfs_to_striper \- expose an unmounted CephFS as libradosstriper (XrdCeph) storage
.SH SYNOPSIS
.B xrdceph_cephfs_to_striper
.I meta_pool cephfs_data_pool striper_pool
.B \-\-assume\-quiesced
[\fIOPTIONS\fR]
.SH DESCRIPTION
Reverse migration: walks the CephFS namespace directly from RADOS (no mount,
no MDS) and creates striper-named redirect stubs in the target pool pointing
at the CephFS data objects, stamping the striper layout and size xattrs so
libradosstriper (XrdCeph) can read each file. Zero-move by default; reversible
with \fB\-\-rollback\fR (stubs are detached first, CephFS data intact).
.PP
\fBREQUIRES THE CEPHFS TO BE QUIESCED\fR (MDS down or fs failed, journal
flushed): the mandatory \fB\-\-assume\-quiesced\fR flag is the operator's
assertion of that state.
.SH OPTIONS
.TP
.B \-\-assume\-quiesced
REQUIRED safety assertion: the filesystem is unmounted and its journal is
flushed.
.TP
.B \-\-rollback
Remove the striper overlay. Each stub is detached (unset_manifest) before
removal; the CephFS data is left intact.
.TP
.B \-\-finalize
Materialize redirects into owned striper objects (tier_promote, in-cluster)
so the whole CephFS can be torn down.
.TP
.B \-\-report\-only
Walk and report what would be migrated; write nothing.
.TP
.BI \-\-strip " PFX"
Strip a leading path prefix when forming the striper soid.
.TP
.BI \-\-threads " N"
Parallel workers (default 4).
.TP
.B \-\-verify
Verify migrated data via libradosstriper reads.
.TP
.B \-\-delete\-source
Remove CephFS data objects after finalize+verify.
.TP
.B \-\-dry\-run
Print what would be done without writing.
.TP
.BI \-\-conf " PATH"
Ceph configuration file (default /etc/ceph/ceph.conf).
.TP
.BI \-\-config " PATH"
Site-profile tool configuration (pool names, prefixes).
.SH PYTHON VARIANT
.B xrdceph_cephfs_to_striper.py
is the pure-Python implementation with identical semantics plus
.BR \-\-json ", " \-\-state ", " \-\-list ", " \-\-prefix ", " \-\-match ", and " \-\-progress .
It requires python3-rados; the namespace walk uses the pure-Python
pymigrate.cephfs_meta decoders.
.SH EXIT STATUS
0 all ok/skipped, 1 any per-file failure, 2 usage or guard error.
.SH SEE ALSO
.BR xrdceph_striper_migrate (1),
.BR xrdcephfs_rescue (1)
```

- [ ] **Step 3: Write the three C-tool pages**

`client/man/xrdrados_rescue.1`:
```roff
.TH XRDRADOS_RESCUE 1 "July 2026" "brix client tools" "User Commands"
.SH NAME
xrdrados_rescue \- offline pure-RADOS recovery from a flat pool
.SH SYNOPSIS
.B xrdrados_rescue
.I pool
.BR ls " [\fIprefix\fR] | " stat " \fIkey\fR | " get " \fIkey local_file\fR | " cp " \fIprefix local_dir\fR"
.SH DESCRIPTION
Enumerates and extracts objects from a flat RADOS pool (the block-only `ceph`
backend's storage, or any pool of opaque objects) with no namespace service.
For pools where the object key equals the logical path this recovers files
directly. The flat-pool counterpart to
.BR xrdcephfs_rescue (1).
.SH COMMANDS
.TP
.BI ls " [prefix]"
List object keys (optionally under \fIprefix\fR).
.TP
.BI stat " key"
Print an object's size and mtime.
.TP
.BI get " key local_file"
Extract one object's bytes to a local file.
.TP
.BI cp " prefix local_dir"
Bulk-extract every object under \fIprefix\fR into \fIlocal_dir\fR.
.SH ENVIRONMENT
.TP
.B CEPH_CONF
Overrides /etc/ceph/ceph.conf.
.SH SEE ALSO
.BR xrdcephfs_rescue (1),
.BR xrdceph_migrate (1)
```

`client/man/xrdcephfs_rescue.1`:
```roff
.TH XRDCEPHFS_RESCUE 1 "July 2026" "brix client tools" "User Commands"
.SH NAME
xrdcephfs_rescue \- offline CephFS recovery via pure RADOS (no mount, no MDS)
.SH SYNOPSIS
.B xrdcephfs_rescue
.I meta_pool data_pool
.BR ls | stat | cat | get | "cp \-r"
.I path
.RI [ local ]
.SH DESCRIPTION
Reads a CephFS directly from its RADOS pools \(em no kernel mount, no MDS, no
libcephfs \(em to list, stat, cat, and recursively copy data OUT when the
filesystem cannot be mounted but the pools are intact. It drives the same
read-only `cephfsro` storage-driver core the nginx export uses, so the decode
and read path is shared and identically tested.
.PP
SAFETY: assumes a QUIESCED filesystem (MDS down / fs failed, journal
flushed). It only ever reads.
.SH COMMANDS
.TP
.BI ls " path"
List a directory.
.TP
.BI stat " path"
Print file metadata.
.TP
.BI cat " path"
Write a file's bytes to stdout.
.TP
.BI get " path local_file"
Copy one file out.
.TP
.BI "cp \-r" " path local_dir"
Recursively copy a subtree out.
.SH ENVIRONMENT
.TP
.B CEPH_CONF
Overrides /etc/ceph/ceph.conf.
.SH SEE ALSO
.BR xrdrados_rescue (1),
.BR xrdceph_striper_migrate (1)
```

`client/man/xrdceph_migrate.1`:
```roff
.TH XRDCEPH_MIGRATE 1 "July 2026" "brix client tools" "User Commands"
.SH NAME
xrdceph_migrate \- copy a flat RADOS pool into a filesystem tree (copy-through-mount)
.SH SYNOPSIS
.B xrdceph_migrate
.I pool dest_dir
.SH DESCRIPTION
Reads every object from a flat `ceph`-backend pool (object key = logical
path) and writes it as a file at the corresponding path beneath
\fIdest_dir\fR, recreating parent directories and carrying user xattrs
(including user.XrdCks.* checksums-at-rest). When \fIdest_dir\fR is a mounted
CephFS the MDS allocates inodes and builds the namespace \(em the
copy-through-mount migration (the only sound flat-pool\(->CephFS upgrade:
CephFS keys data by MDS-allocated inode, so in-place conversion is
impossible).
.SH ENVIRONMENT
.TP
.B CEPH_CONF
Overrides /etc/ceph/ceph.conf.
.SH SEE ALSO
.BR xrdrados_rescue (1),
.BR xrdceph_striper_migrate (1)
```

- [ ] **Step 4: Completions**

In `client/completions/brix-tools.bash`, add (before the `complete -F` registration block at the bottom — read the file's tail first to match its registration style exactly):
```bash
_xrdceph_striper_migrate() {
  local opts="--mode --rollback --finalize --list --strip --threads --verify
    --delete-source --force --dry-run --conf --config --sample-mb --progress
    --json --state --prefix --match --help"
  _brix_opts_filter "$opts" && return
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    --mode)                  COMPREPLY=($(compgen -W "redirect copy" -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
    --list|--conf|--config|--state) COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
  esac
  COMPREPLY=()
}

_xrdceph_cephfs_to_striper() {
  local opts="--assume-quiesced --report-only --rollback --finalize --strip
    --threads --verify --delete-source --dry-run --conf --config
    --json --state --list --prefix --match --progress --help"
  _brix_opts_filter "$opts" && return
  local prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    --list|--conf|--config|--state) COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}")); return ;;
  esac
  COMPREPLY=()
}

_xrdrados_rescue() {
  [[ $COMP_CWORD -eq 2 ]] && COMPREPLY=($(compgen -W "ls stat get cp" -- "${COMP_WORDS[COMP_CWORD]}"))
}

_xrdcephfs_rescue() {
  [[ $COMP_CWORD -eq 3 ]] && COMPREPLY=($(compgen -W "ls stat cat get cp" -- "${COMP_WORDS[COMP_CWORD]}"))
}
```
Then register (matching the file's existing pattern):
```bash
complete -F _xrdceph_striper_migrate xrdceph_striper_migrate xrdceph_striper_migrate.py
complete -F _xrdceph_cephfs_to_striper xrdceph_cephfs_to_striper xrdceph_cephfs_to_striper.py
complete -F _xrdrados_rescue xrdrados_rescue
complete -F _xrdcephfs_rescue xrdcephfs_rescue
complete -o default -F _xrdcephfs_rescue xrdceph_migrate 2>/dev/null || complete -F _xrdcephfs_rescue xrdceph_migrate
```
(For `xrdceph_migrate` a plain positional file/dir default is fine — if the file has a simpler convention for argument-only tools, follow it instead.)

In `client/Makefile` `install-completions`, extend the name loop:
```make
	for n in xrdcp xrdfs xrddiag xrdcksum xrd xrdprep xrdgsiproxy xrdsssadmin brixMount xrdstorascan xrootdfs \
	         xrdceph_striper_migrate xrdceph_cephfs_to_striper xrdrados_rescue xrdcephfs_rescue xrdceph_migrate; do \
```

- [ ] **Step 5: Verify guards**

Run: `bash client/man/check_man.sh`
Expected: PASS (ceph binaries absent on this box → "skipped" notices, no FAIL).
Run: `bash client/completions/check_completions.sh`
Expected: PASS (bash -n clean; no injection patterns).
Run: `man --local-file client/man/xrdceph_striper_migrate.1 >/dev/null && echo roff-ok` (repeat for all five)
Expected: 5× roff-ok.

- [ ] **Step 6: Commit**

```bash
git add client/man/xrdceph_*.1 client/man/xrdrados_rescue.1 client/man/xrdcephfs_rescue.1 \
        client/completions/brix-tools.bash client/Makefile
git commit -m "docs(client): man pages + completions for the ceph operator tools" \
  -- client/man client/completions/brix-tools.bash client/Makefile
```

---

### Task 5: READMEs + reference docs

**Files:**
- Modify: `client/apps/README.md`, `client/README.md`, `tests/ceph/README.md`
- Modify: `docs/10-reference/{cephfs-migration-glasgow-ral.md,cephfs-to-xrdceph-migration.md,python-migration-tools.md,xrdceph-cephfs-bidirectional-migration.md,xrdceph-cephfs-migration-test-record.md}`

**Interfaces:**
- Consumes: `make -C client ceph-tools` (Task 2) as the canonical build command; Task 3's audit finding.

- [ ] **Step 1: `client/apps/README.md` — new section**

After the "Optional (built only when `libfuse3` is present…)" section, add:
```markdown
## Ceph operator tools (`apps/ceph/` — built only when the Ceph dev headers are present)

Storage-plane migration and rescue utilities linking librados directly (they
do not speak `root://`). Compile-gated per tool; `make -C client ceph-tools`
builds exactly this group. The migration pair ships BOTH a compiled C++
primary and a pure-Python variant (`.py` suffix) with extra operator plumbing
(`--json`, resumable `--state`, `--prefix`/`--match` filters, `--progress`)
backed by the `pymigrate/` package (ctypes bridge to librados's C++-only
manifest ops, with a compiled shim fallback).

| Binary | Purpose |
|---|---|
| `xrdceph_striper_migrate` (+ `.py`) | libradosstriper (stock XrdCeph) pool → CephFS. Zero-move redirect default, `--mode copy`, `--rollback` (detaches stubs first — source always intact), `--finalize`. |
| `xrdceph_cephfs_to_striper` (+ `.py`) | Quiesced CephFS → libradosstriper pool (namespace walked from pure RADOS). Zero-move redirects, `--rollback`, `--finalize`; requires `--assume-quiesced`. |
| `xrdrados_rescue` | Offline recovery from a flat RADOS pool (`ls`/`stat`/`get`/`cp`). |
| `xrdcephfs_rescue` | Offline CephFS recovery via pure RADOS — no mount, no MDS (drives the read-only `cephfsro` driver core). |
| `xrdceph_migrate` | Flat pool → filesystem tree copy-through-mount (the only sound flat→CephFS upgrade). |
```

- [ ] **Step 2: `client/README.md` — feature summary + layout row**

In the directory-layout table's `apps/` row, nothing changes (covered by apps README). In the "Feature summary" section, add a short `### Ceph operator tools` subsection: one paragraph naming the five tools, the dep gating (`librados`/`libradosstriper`/`libcephfs` + C++ compiler probed at make time; missing deps skip silently), and `make -C client ceph-tools`. Also amend the intro sentence "Pure-C, libXrdCl-free client suite" to note the one exception: `apps/ceph/` holds C++/Python storage-plane operator tools linking librados (still libXrdCl-free).

- [ ] **Step 3: `tests/ceph/README.md` — repoint the tool sections**

Update the sections listing the five tools + pymigrate (lines ~137-215): each `tests/ceph/<file>` path → `client/apps/ceph/<file>`; add one line up front: "The operator tools were promoted to `client/apps/ceph/` (2026-07-07) and build via `make -C client ceph-tools`; this directory keeps the Ceph harness, seeds, spikes, fixtures, and e2e runners." Runner paths (`tests/ceph/run_*.sh`) stay unchanged.

- [ ] **Step 4: `docs/10-reference/` path updates**

In each of the five docs, update references to MOVED files only (the runners stay at `tests/ceph/`):
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd
for d in docs/10-reference/cephfs-migration-glasgow-ral.md \
         docs/10-reference/cephfs-to-xrdceph-migration.md \
         docs/10-reference/python-migration-tools.md \
         docs/10-reference/xrdceph-cephfs-bidirectional-migration.md \
         docs/10-reference/xrdceph-cephfs-migration-test-record.md; do
  sed -i -e 's#tests/ceph/xrdceph_striper_migrate#client/apps/ceph/xrdceph_striper_migrate#g' \
         -e 's#tests/ceph/xrdceph_cephfs_to_striper#client/apps/ceph/xrdceph_cephfs_to_striper#g' \
         -e 's#tests/ceph/xrdceph_migrate_config#client/apps/ceph/xrdceph_migrate_config#g' \
         -e 's#tests/ceph/xrdceph_migrate#client/apps/ceph/xrdceph_migrate#g' \
         -e 's#tests/ceph/xrdrados_rescue#client/apps/ceph/xrdrados_rescue#g' \
         -e 's#tests/ceph/xrdcephfs_rescue#client/apps/ceph/xrdcephfs_rescue#g' \
         -e 's#tests/ceph/pymigrate#client/apps/ceph/pymigrate#g' \
         -e 's#tests/ceph/ngx_shim#client/apps/ceph/ngx_shim#g' "$d"
done
```
CAUTION: the `xrdceph_migrate_config` substitution must run BEFORE `xrdceph_migrate` (as ordered above) or the latter mangles the former. Then hand-review each doc's hand-written `g++`/`gcc` BUILD blocks: where a doc shows the manual compile line, add "or simply `make -C client ceph-tools`" and fix any `-I tests/ceph` → `-I client/apps/ceph`.

- [ ] **Step 5: Verify**

Run: `grep -rn "tests/ceph/xrdceph\|tests/ceph/xrdrados\|tests/ceph/xrdcephfs_rescue\|tests/ceph/pymigrate\|tests/ceph/ngx_shim" docs/10-reference client/ tests/ceph/README.md`
Expected: no hits.
Run: `grep -rn "client/apps/ceph" docs/10-reference | wc -l`
Expected: > 20 (the rewritten references).

- [ ] **Step 6: Commit**

```bash
git add client/apps/README.md client/README.md tests/ceph/README.md docs/10-reference
git commit -m "docs: ceph operator tools promoted to client/apps/ceph — repoint references" \
  -- client/apps/README.md client/README.md tests/ceph/README.md docs/10-reference
```

---

### Task 6: RPM spec repoint

**Files:**
- Modify: `packaging/rpm/nginx-mod-brix-cache.spec` (has user WIP — surgical edits only), `packaging/rpm/README.md` (path mentions, if any)

**Interfaces:**
- Consumes: `make -C client ceph-tools` (Task 2); binaries in `client/bin/`; Python sources in `client/apps/ceph/`.

- [ ] **Step 1: Replace the `%build` ceph block**

Replace the entire hand-rolled block from the comment `# --- Ceph/XrdCeph migration operator tools ---` through the final `-o tests/ceph/xrdceph_cephfs_to_striper` line with:
```
# --- Ceph/XrdCeph migration operator tools ---
# Built by the client Makefile's dep-gated ceph-tools target (BuildRequires
# guarantees librados/libradosstriper/libcephfs are present, so all five build).
make -C client ceph-tools %{?_smp_mflags} CFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}"
```

- [ ] **Step 2: Replace the `%install` ceph block**

Replace the two `install -Dpm0755 tests/ceph/...` pairs with:
```
# --- Ceph/XrdCeph migration + rescue operator tools (brix-tools) ---
for t in xrdceph_striper_migrate xrdceph_cephfs_to_striper \
         xrdrados_rescue xrdcephfs_rescue xrdceph_migrate; do
    install -Dpm0755 client/bin/$t %{buildroot}%{_bindir}/$t
done
install -Dpm0755 client/apps/ceph/xrdceph_striper_migrate.py \
    %{buildroot}%{_libexecdir}/brix/xrdceph_striper_migrate.py
install -Dpm0755 client/apps/ceph/xrdceph_cephfs_to_striper.py \
    %{buildroot}%{_libexecdir}/brix/xrdceph_cephfs_to_striper.py
for f in __init__.py common.py cephfs_meta.py radosbridge.py; do
    install -Dpm0644 client/apps/ceph/pymigrate/$f \
        %{buildroot}%{_libexecdir}/brix/pymigrate/$f
done
install -Dpm0644 client/apps/ceph/pymigrate/shim/rados_manifest_shim.cpp \
    %{buildroot}%{_libexecdir}/brix/pymigrate/shim/rados_manifest_shim.cpp
ln -sf ../libexec/brix/xrdceph_striper_migrate.py \
    %{buildroot}%{_bindir}/xrdceph_striper_migrate.py
ln -sf ../libexec/brix/xrdceph_cephfs_to_striper.py \
    %{buildroot}%{_bindir}/xrdceph_cephfs_to_striper.py
```

- [ ] **Step 3: Extend `%files -n brix-tools` + subpackage metadata**

After the existing two `%{_bindir}` entries add:
```
%{_bindir}/xrdrados_rescue
%{_bindir}/xrdcephfs_rescue
%{_bindir}/xrdceph_migrate
%{_bindir}/xrdceph_striper_migrate.py
%{_bindir}/xrdceph_cephfs_to_striper.py
%{_libexecdir}/brix/
%{_mandir}/man1/xrdceph_striper_migrate.1*
%{_mandir}/man1/xrdceph_cephfs_to_striper.1*
%{_mandir}/man1/xrdrados_rescue.1*
%{_mandir}/man1/xrdcephfs_rescue.1*
%{_mandir}/man1/xrdceph_migrate.1*
```
The man pages must also be INSTALLED: check how the client subpackage installs its man pages in `%install` (search the spec for `man1`); if pages are copied by a wildcard loop the new pages flow in automatically BUT then they land in brix-cache-client's `%files` glob — in that case either exclude the five from the client glob or (simpler) keep them in the client subpackage and drop the five `%{_mandir}` lines above; pick whichever matches the spec's existing man handling and note it in the commit message. If no man wildcard exists, add explicit `install -Dpm0644 client/man/<page>.1 %{buildroot}%{_mandir}/man1/<page>.1` lines to the ceph `%install` block.
In the `%package -n brix-tools` header add:
```
Recommends:     python3-rados
Recommends:     python3-cephfs
```
and extend `%description -n brix-tools` with one sentence: the package now also carries the three offline rescue utilities and the Python tool variants (`.py`, libexec-backed).

- [ ] **Step 4: `%changelog` + README**

Add a `%changelog` entry (bump release, today's date, author line matching the existing style) noting the tools now build from `client/apps/ceph/` via `make -C client ceph-tools` and the rescue tools + Python variants joined brix-tools. Update any `tests/ceph` tool paths in `packaging/rpm/README.md`.

- [ ] **Step 5: Verify**

Run: `rpmspec -P packaging/rpm/nginx-mod-brix-cache.spec > /dev/null && echo spec-parses` (skip with a note if `rpmspec` is unavailable on this box).
Run: `grep -n "tests/ceph" packaging/rpm/nginx-mod-brix-cache.spec`
Expected: no tool-source references remain (harness/test-suite payload references, if any, are fine).

- [ ] **Step 6: Commit**

```bash
git add packaging/rpm/nginx-mod-brix-cache.spec packaging/rpm/README.md
git commit -m "packaging(rpm): brix-tools builds via make -C client ceph-tools; add rescue + python variants" \
  -- packaging/rpm/nginx-mod-brix-cache.spec packaging/rpm/README.md
```
CAUTION: `git add` on these two files sweeps the user's WIP hunks into the commit. Before committing, run `git diff --cached packaging/rpm/nginx-mod-brix-cache.spec | head -100` and confirm every hunk is either (a) this task's edit or (b) obviously the same ceph-tools packaging work; if unrelated WIP hunks appear, commit with `git add -p`-style selection is unavailable to you — STOP and ask the user.

---

### Task 7: Final verification sweep + memory correction

**Files:**
- No repo changes (verification only), except the memory file `/home/rcurrie/.claude/projects/-home-rcurrie-HEP-x-nginx-xrootd/memory/pymigrate_python_migration_tools.md`

- [ ] **Step 1: Full local matrix**

```bash
make -C client clean && make -C client -j$(nproc) && make -C client test
python3 -m pytest tests/ceph/test_cephfs_meta.py -v
bash client/man/check_man.sh && bash client/completions/check_completions.sh
```
Expected: all green; ceph tools skipped (no librados on this box).

- [ ] **Step 2: Container build proof (conditional)**

Run: `docker ps --format '{{.Names}}' | grep -x xrd-ceph-work || echo NO-HARNESS`
If the harness container is up: run `tests/ceph/run_rescue_tools.sh` and `tests/ceph/run_striper_migrate.sh` (covers the rescue smoke + migrate/rollback legs) and `tests/ceph/run_py_migrate.sh`. Expected: PASS.
If NO-HARNESS: do NOT start Docker infrastructure unprompted; record in the final report that container e2e is deferred to the next harness session, and list the three commands to run.

- [ ] **Step 3: Repo-wide stale-reference sweep**

Run: `grep -rn "tests/ceph/xrdceph\|tests/ceph/pymigrate\|tests/ceph/ngx_shim\|tests/ceph/xrdrados\|tests/ceph/xrdcephfs_rescue" . --include="*.md" --include="*.sh" --include="*.py" --include="*.spec" --include="Makefile" --include="*.c" --include="*.h" --include="*.cpp" 2>/dev/null | grep -v "k8s-tests/remote-suite" | grep -v "docs/superpowers" | grep -v __pycache__`
Expected: no hits (remote-suite and historical specs/plans are the two sanctioned exceptions).

- [ ] **Step 4: Correct the stale memory**

Edit the memory file `pymigrate_python_migration_tools.md`: replace the "(C++ tool unfixed)" hazard clause with "(C++ tools fixed — detach-before-unlink present in both; re-verified 2026-07-07)" and add a line that the tool family now lives in `client/apps/ceph/` (built via `make -C client ceph-tools`). Update the corresponding one-liner in `MEMORY.md`.
