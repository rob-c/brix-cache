# BriX Symbol & Namespace Rebrand — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebrand the project's *own* namespace — `xrootd_` / `XROOTD_` / `ngx_xrootd*` in the server, `xrdc_` / `libxrdc` in the client — to the BriX namespace (`brix_` / `BRIX_` / `ngx_brix*` / `libbrix`), across C code, nginx config directives, Prometheus metrics, the embedded dashboard (symbols **and** URL routes), operator-facing log-line prefixes, env-var contracts, log filenames, the client shared library, deploy assets, and documentation — while **preserving** every reference to the upstream *XRootD project*, the `root://` *protocol* (`kXR_*`, `XrdCl`/`XrdHttp`, `root://`, upstream-mirroring tools `xrdcp`/`xrdfs`), and the nginx module identity `nginx-xrootd`.

**Architecture:** Two complementary mechanisms. (1) A deterministic, idempotent, case-sensitive **token-rewrite engine** (`tools/refactor/brix_rebrand.py`) handles the ~41,000 underscore-anchored occurrences whose anchoring (`xrootd_`, `XROOTD_`, `\bxrdc\b`) structurally guarantees protocol prose and tool names are never touched. (2) A small set of **targeted literal rewrites** (a dedicated task) handles the self-references that are *not* underscore-anchored — dashboard URL routes (`/xrootd/…`), operator log-line prefixes (`"xrootd: …"`), and a JSON download name — which a broad regex could confuse with user data paths, so they are done surgically on named files with per-file review. A companion verifier (`brix_verify.sh`) proves zero residuals and byte-for-byte invariance of the KEEP set. Work is phased by **token class and green-gate boundary**: a compiled C namespace cannot be half-renamed, so each phase moves an entire class across every referring tree and ends with a clean build + green suite + zero-residual scan, one commit per phase, committed directly to `main`.

**Tech Stack:** C (nginx dynamic module: stream + http modules), Python 3 (rename tooling + pytest suite), GNU Make (client library), Prometheus text exposition, Grafana JSON, fail2ban filters, Bash (test harness + CI guards).

---

## Scope Census (measured 2026-07-03, `main` @ `ef9c518`)

The magnitude below is *occurrences* (every textual hit), not unique identifiers — it is the true edit churn.

### Server — `xrootd_` / `XROOTD_` / `ngx_xrootd*`

| Subsystem            | Occurrences | Files |
|----------------------|------------:|------:|
| `src/protocols`      |     10,295  |  356  |
| `src/fs`             |      7,207  |  178  |
| `src/core`           |      5,009  |  159  |
| `src/net`            |      3,499  |  108  |
| `src/auth`           |      3,468  |  127  |
| `src/observability`  |      3,282  |   64  |
| `src/tpc`            |        882  |   30  |
| **server total**     |  **≈33,642**| **1,022** |

- Unique `xrootd_`/`XROOTD_`/`ngx_xrootd` identifiers: **3,303** (`xrootd_*`) + **1,502** (`XROOTD_*` macros) + **59** (`ngx_(http_|stream_)?xrootd*` module/type names).
- Config directives named `xrootd_*`: **429 unique** (e.g. `xrootd_cache_store`, `xrootd_allow_write`, `xrootd_admin_secret`, `xrootd_bandwidth_limit`).
- Prometheus metric names `xrootd_*`: **167 unique** (e.g. `xrootd_auth_l1_hits_total`, `xrootd_cvmfs_fills_total`, `xrootd_frm_purge_total`, `xrootd_cache_dirty_reaped_total`).
- Env-var contracts `XROOTD_*` read via `getenv`: **7** (see Global Constraints).
- Access-log filename literals: **3** (`xrootd_access.log`, `xrootd_access_anon.log`, `xrootd_access_token.log`).
- `XROOTD_OP_*` / `XROOTD_PROTO_*` / `XROOTD_TPC_PROTO_*` opcode/enum macros: **~60** — the `XROOTD_` prefix rebrands to `BRIX_`; the protocol-semantic suffix (`_OP_OPEN_RD`, `_PROTO_ROOT`) is preserved verbatim, e.g. `XROOTD_OP_OPEN_RD` → `BRIX_OP_OPEN_RD`.

### Server — non-underscore self-references (edge cases, Task 2)

| Kind                        | Literal(s)                                             | Files | Decision |
|-----------------------------|--------------------------------------------------------|------:|----------|
| Dashboard URL route base    | `/xrootd`, `/xrootd/`, `/xrootd/api/v1/…`, `/xrootd/login`, `/xrootd/transfers` (23 route literals) | 6 | **RENAME → `/brix…`** |
| Operator log-line prefix    | `"xrootd: …"` (log message leader)                     |  132 | **RENAME → `"brix: …"`** |
| Dashboard snapshot download | `xrootd-dashboard-snapshot.json`                       |    1 | **RENAME → `brix-dashboard-snapshot.json`** |
| On-disk cache sentinels     | `.ngx-xrootd-part`, `.ngx-xrootd-lock`, `.ngx-xrootd-evict-lock`, `.nginx-xrootd-ckp-recovery.lock` | 2 | **KEEP** (rolling-upgrade safety, see Risk R4) |
| nginx module identity       | `nginx-xrootd`, `nginx-xrootd.conf`, `nginx-xrootd-cache`, repo URL, AGPL attribution, `nginx-xrootd-tpc-cred` | many | **KEEP** (module/repo name) |

### Client — `xrdc_` / `libxrdc`

| Subsystem          | Occurrences |
|--------------------|------------:|
| `client/lib`       |      5,305  |
| `client/apps`      |      2,249  |
| `client/preload`   |         50  |
| `client/examples`  |         35  |
| **client total**   |  **≈7,639** |

- Library artifacts: `libxrdc.so.0.1.0` (SONAME `libxrdc.so.0`), `libxrdc.so.0`, `libxrdc.so`, `libxrdc.a`, `libxrdc.pc` (all tracked in git); preload `libxrdposix_preload.so`.
- Tool binaries **kept** (mirror upstream CLI, no trailing `_`): `xrdcp`, `xrdfs`, `xrdcinfo`, `xrdckverify`, `xrdcrc32c`, `xrdcrc64`, `xrootdfs`.

### Docs — 374 markdown files; ~8,328 case-insensitive "xrootd" mentions

The vast majority are prose naming the *upstream XRootD project* or the `root://` *protocol* — **preserved**. Only underscore-anchored identifiers, `XROOTD_*` macros, and directive/metric names inside code fences are rewritten (Task 6).

---

## Global Constraints

These apply to **every** task. Values are copied verbatim from the decisions locked at plan time.

- **Hard rename, no compatibility aliases** — config directives (`xrootd_*` → `brix_*`), Prometheus metrics (`xrootd_*` → `brix_*`), dashboard routes (`/xrootd…` → `/brix…`), env vars (`XROOTD_*` → `BRIX_*`), and access-log filenames (`xrootd_access*.log` → `brix_access*.log`) are renamed outright; old names stop working. An operator migration map is a Phase-1 deliverable (`docs/refactor/brix-rename-migration.md`).
- **Client scope = library + symbols + preload, keep tool binary names** — rename `libxrdc.{so,a,pc}` → `libbrix.*`, `xrdc_` C symbols → `brix_`, `libxrdposix_preload.so` → `libbrixposix_preload.so`. Keep `xrdcp`/`xrdfs`/`xrdcinfo`/`xrdckverify`/`xrdcrc32c`/`xrdcrc64`/`xrootdfs`.
- **KEEP list — must survive byte-for-byte** (upstream/protocol/module-identity, not our namespace):
  - URL schemes: `root://`, `roots://`, `scvmfs://`, `cvmfs://`, `davs://`
  - Wire protocol: `kXR_*`, `XProtocol`, all opcode/status constants from `XProtocol.hh`
  - Upstream components / xattr namespaces: `XrdCl`, `XrdHttp`, `XrdSsi`, `XrdCeph`, `XrdSec*`, `XrdCks`, `user.XrdCks.*`
  - Upstream client env vars: `XRD_*` (e.g. `XRD_LOGLEVEL`) — prefix is `XRD_`, **not** `XROOTD_`
  - Tool binary names (above) and the FUSE client `xrootdfs`
  - **nginx module identity `nginx-xrootd`** and all its derivatives (config filename, cache id, repo URL, AGPL attribution, installed helper `nginx-xrootd-tpc-cred`)
  - **On-disk cache sentinels** `.ngx-xrootd-part`, `.ngx-xrootd-lock`, `.ngx-xrootd-evict-lock`, `.nginx-xrootd-ckp-recovery.lock` (Risk R4)
  - The English word "XRootD"/"xrootd" in prose when it names the upstream project or the protocol
- **RENAME map — Group A (underscore/word-anchored, engine-automated, case-sensitive, applied in order; confluent):**

  | Rule | Match (Python `re`)      | Replacement            | Scope   |
  |------|--------------------------|------------------------|---------|
  | S1   | `ngx_http_xrootd_`       | `ngx_http_brix_`       | server  |
  | S2   | `ngx_stream_xrootd_`     | `ngx_stream_brix_`     | server  |
  | S3   | `ngx_xrootd_`            | `ngx_brix_`            | server  |
  | S4   | `XROOTD_`                | `BRIX_`                | server  |
  | S5   | `xrootd_`                | `brix_`                | server  |
  | C1   | `libxrdposix_preload`    | `libbrixposix_preload` | client  |
  | C2   | `xrdposix_preload`       | `brixposix_preload`    | client  |
  | C3   | `libxrdc`                | `libbrix`              | client  |
  | C4   | `xrdc_`                  | `brix_`                | client  |
  | C5   | `\bxrdc\b`               | `brix`                 | client  |

  S1–S3 are subsumed by S5 (`ngx_xrootd_module` → S5 → `ngx_brix_module`) and exist only for reviewer-legible dry-run grouping. C5's `\b…\b` deliberately excludes `xrdcp`/`xrdcinfo`/… (a word char follows `xrdc`). All rules are confluent and idempotent.
- **RENAME — Group B (non-underscore self-references, targeted per file in Task 2, NOT the engine):**
  - `/xrootd` route base → `/brix` (dashboard only)
  - `"xrootd: ` log-line prefix → `"brix: ` (src only, dry-run reviewed; fail2ban filters updated in lockstep)
  - `xrootd-dashboard-snapshot` → `brix-dashboard-snapshot`
- **File renames (Tasks 3 & 4):**
  - `src/core/ngx_xrootd_module.h` → `ngx_brix_module.h`
  - `src/protocols/root/fattr/ngx_xrootd_fattr.h` → `ngx_brix_fattr.h`
  - `client/lib/xrdc.h` → `brix.h`; `xrdc_auth.h` → `brix_auth.h`; `xrdc_net.h` → `brix_net.h`; `xrdc_ops.h` → `brix_ops.h`
  - `client/examples/xrdc_readv_demo.c` → `brix_readv_demo.c`; `xrdc_stat_demo.c` → `brix_stat_demo.c`
  - `client/preload/xrdposix_preload.c` → `brixposix_preload.c`
  - `contrib/xrootd.conf.example` → `contrib/brix-cache.conf.example`
  - `deploy/fail2ban/samples/xrootd-guard-audit.sample.log` → `brix-guard-audit.sample.log`
  - **NOT renamed:** `client/apps/xrdcp*.c`, `xrdcinfo.c`, `xrdckverify.c`, `xrdcrc32c.c`, `xrdcrc64.c`, `xrootdfs*.c/.h`, `client/man/xrootdfs.1`
- **Env-var contract renames** (hard, caught by S4): `XROOTD_FRM_STAGECMD`, `XROOTD_FRM_STUB_RECALL_DELAY_MS`, `XROOTD_OIDC_TOKEN_BIN`, `XROOTD_STAGE_JOURNAL_DIR`, `XROOTD_UPLOAD_RESUME_TTL`, `XROOTD_VMP`, `XROOTD_XFER_AUDIT_LOG` → `BRIX_*`. Setters live in `tests/run_tape_recall_stream.sh`, `tests/test_xfer_resume_sweep.py`, `tests/run_storage_backend_schemes.sh`, `tests/run_tape_exec_adapter.sh`, `tests/run_stage_reconcile.sh`, `tests/run_tape_recall_async.sh`, `tests/test_xrootdfs.py`, `tests/run_s3_tape_residency.sh` — all in scope for Task 1.
- **Log filename renames** (hard, caught by S5): `xrootd_access.log`, `xrootd_access_anon.log`, `xrootd_access_token.log` → `brix_access*.log`. Harness (`tests/manage_test_servers.sh`, `tests/lib/*.sh`) + docs move in Task 1.
- **Version bump:** `src/core/ident.h` `XROOTD_SERVER_VERSION_BARE "1.0.7"` → `BRIX_SERVER_VERSION_BARE "1.0.8"` (macro name via S4).
- **No git branches — commit directly to `main`** (project convention). One commit per phase.
- **Preserve `git blame`:** `.git-blame-ignore-revs` gets each rename-commit SHA; `git config blame.ignoreRevsFile .git-blame-ignore-revs`.
- **Historical docs EXCLUDED (verbatim):** `docs/refactor/phase-66-map.tsv`, `docs/refactor/phase-67-map.tsv`, `docs/09-developer-guide/postmortem-shmtx-semaphore-stall.md`, and this plan.
- **Build governance** (module/header renames change nginx's generated `objs/ngx_modules.c` and dep graph — clean reconfigure required; always use the literal repo path):
  ```bash
  REPO=/home/rcurrie/HEP-x/nginx-xrootd
  rm -rf /tmp/nginx-1.28.3/objs
  ( cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module \
      --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO ) \
    && make -C /tmp/nginx-1.28.3 -j"$(nproc)"
  ```

---

## File Structure (new files created by this plan)

- `tools/refactor/brix_rebrand.py` — the Group-A rename engine (rule table, `--scope`, `--dry-run`, `--emit-map`).
- `tools/refactor/brix_verify.sh` — residual-scan + KEEP-invariance verifier.
- `docs/refactor/brix-rename-migration.md` — generated operator migration map.
- `.git-blame-ignore-revs` — rename-commit SHAs.

Modified trees: `src/**`, `./config`, `client/**`, `tests/**`, `deploy/**`, `contrib/**`, `docs/**` (living only), `tools/ci/*.sh`, `CLAUDE.md`, `README.md`, `CHANGELOG.md`.

---

## Task 0: Rename tooling & guardrails

**Files:**
- Create: `tools/refactor/brix_rebrand.py`, `tools/refactor/brix_verify.sh`, `.git-blame-ignore-revs`

**Interfaces:**
- Produces: `brix_rebrand.py` — `--scope {server,client,docs}` selects the rule subset (server/docs = S1–S5, client = C1–C5), positional files/dirs, `--dry-run` (per-file change counts + `--- path` listing, no writes), `--emit-map PATH` (old→new map from matched directive/metric/env string literals). Skips binaries (NUL sniff) and the historical EXCLUDE set. Idempotent.
- Produces: `brix_verify.sh <scope> <path…>` — non-zero exit on any residual namespace token (minus whitelist); prints a KEEP-token census for invariance comparison.

- [ ] **Step 1: Write `tools/refactor/brix_rebrand.py`**

```python
#!/usr/bin/env python3
"""BriX rebrand engine — deterministic, idempotent, case-sensitive token rewrite.

Renames the project's OWN namespace (xrootd_/XROOTD_/ngx_xrootd*/xrdc_) to the
BriX namespace, leaving upstream XRootD/protocol references untouched. Rules are
anchored (trailing '_' or \\b) so prose 'XRootD', 'root://', 'nginx-xrootd', and
tool names 'xrdcp'/'xrdfs' are never matched. Non-underscore self-references
(dashboard routes, log prefixes) are handled by Task 2, NOT here. See
docs/refactor/2026-07-03-brix-symbol-rebrand.md for the authoritative rule table.
"""
import argparse
import os
import re
import sys

SERVER_RULES = [
    (re.compile(r'ngx_http_xrootd_'),   'ngx_http_brix_'),
    (re.compile(r'ngx_stream_xrootd_'), 'ngx_stream_brix_'),
    (re.compile(r'ngx_xrootd_'),        'ngx_brix_'),
    (re.compile(r'XROOTD_'),            'BRIX_'),
    (re.compile(r'xrootd_'),            'brix_'),
]
CLIENT_RULES = [
    (re.compile(r'libxrdposix_preload'), 'libbrixposix_preload'),
    (re.compile(r'xrdposix_preload'),    'brixposix_preload'),
    (re.compile(r'libxrdc'),             'libbrix'),
    (re.compile(r'xrdc_'),               'brix_'),
    (re.compile(r'\bxrdc\b'),            'brix'),
]

EXCLUDE = {
    'docs/refactor/phase-66-map.tsv',
    'docs/refactor/phase-67-map.tsv',
    'docs/09-developer-guide/postmortem-shmtx-semaphore-stall.md',
    'docs/refactor/2026-07-03-brix-symbol-rebrand.md',
    'tools/refactor/brix_rebrand.py',
    'tools/refactor/brix_verify.sh',
    '.git-blame-ignore-revs',
}


def rules_for(scope):
    return CLIENT_RULES if scope == 'client' else SERVER_RULES


def is_binary(path):
    try:
        with open(path, 'rb') as fh:
            return b'\x00' in fh.read(8192)
    except OSError:
        return True


def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        else:
            for root, _dirs, files in os.walk(p):
                for name in files:
                    yield os.path.join(root, name)


def rewrite_text(text, rules):
    out, changed = [], 0
    for line in text.splitlines(keepends=True):
        new = line
        for pat, repl in rules:
            new = pat.sub(repl, new)
        if new != line:
            changed += 1
        out.append(new)
    return ''.join(out), changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--scope', choices=('server', 'client', 'docs'), required=True)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--emit-map', metavar='PATH')
    ap.add_argument('paths', nargs='+')
    args = ap.parse_args()
    rules = rules_for(args.scope)

    total_files = total_lines = 0
    mapping = {}
    token_re = re.compile(r'"(xrootd_[a-z0-9_]+|XROOTD_[A-Z0-9_]+)"')

    for path in iter_files(args.paths):
        rel = os.path.relpath(path)
        if rel in EXCLUDE or is_binary(path):
            continue
        with open(path, 'r', encoding='utf-8', errors='surrogateescape') as fh:
            original = fh.read()
        new_text, changed = rewrite_text(original, rules)
        if changed == 0:
            continue
        total_files += 1
        total_lines += changed
        if args.emit_map:
            for m in token_re.finditer(original):
                old = m.group(1)
                new, _ = rewrite_text(old, rules)
                mapping[old] = new
        if args.dry_run:
            print(f'--- {rel}  ({changed} lines)')
        else:
            with open(path, 'w', encoding='utf-8', errors='surrogateescape') as fh:
                fh.write(new_text)

    if args.emit_map and mapping:
        with open(args.emit_map, 'w', encoding='utf-8') as fh:
            fh.write('# BriX rename migration map (old -> new)\n')
            for old in sorted(mapping):
                fh.write(f'{old}\t{mapping[old]}\n')

    verb = 'would change' if args.dry_run else 'changed'
    print(f'{verb} {total_lines} lines in {total_files} files (scope={args.scope})',
          file=sys.stderr)


if __name__ == '__main__':
    main()
```

- [ ] **Step 2: Write `tools/refactor/brix_verify.sh`**

```bash
#!/usr/bin/env bash
# BriX rebrand verifier. Usage: brix_verify.sh <server|client|docs> <path...>
set -euo pipefail
scope="$1"; shift

exclude='(phase-6[67]-map\.tsv|postmortem-shmtx-semaphore-stall\.md|2026-07-03-brix-symbol-rebrand\.md|tools/refactor/brix_)'
# nginx-xrootd module identity + on-disk sentinels are KEEP; whitelist them.
keep_ident='(nginx-xrootd|ngx-xrootd-part|ngx-xrootd-lock|ngx-xrootd-evict-lock|nginx-xrootd-ckp-recovery)'

case "$scope" in
  server|docs) forbidden='xrootd_|XROOTD_|ngx_xrootd' ;;
  client)      forbidden='xrdc_|libxrdc|(^|[^A-Za-z0-9_])xrdc([^A-Za-z0-9_]|$)' ;;
  *) echo "unknown scope $scope" >&2; exit 2 ;;
esac

hits=$(grep -rInE "$forbidden" "$@" 2>/dev/null | grep -vE "$exclude" | grep -vE "$keep_ident" || true)
if [ -n "$hits" ]; then
  echo "RESIDUAL namespace tokens ($scope):" >&2
  echo "$hits" | head -50 >&2
  exit 1
fi

for tok in 'root://' 'kXR_' 'XrdCl' 'XrdHttp' 'xrdcp' 'xrdfs' 'xrootdfs' 'nginx-xrootd'; do
  n=$(grep -rIF "$tok" "$@" 2>/dev/null | wc -l)
  echo "KEEP $tok = $n"
done
echo "brix_verify: OK ($scope)"
```

- [ ] **Step 3: Make executable + scaffold blame-ignore**

```bash
chmod +x tools/refactor/brix_rebrand.py tools/refactor/brix_verify.sh
printf '# Bulk BriX rebrand — mechanical renames, ignored by git blame.\n' > .git-blame-ignore-revs
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

- [ ] **Step 4: Idempotency + safety smoke test on scratch files**

Run:
```bash
tmp=$(mktemp -d)
printf 'xrootd_vfs_io_account XROOTD_OP_OPEN_RD ngx_xrootd_dashboard_shm_zone\n' > "$tmp/a.c"
printf 'root:// XrdHttp xrdcp nginx-xrootd XROOTD_PROTO_ROOT the xrootd protocol /xrootd/login\n' > "$tmp/b.c"
tools/refactor/brix_rebrand.py --scope server "$tmp/a.c" "$tmp/b.c"
tools/refactor/brix_rebrand.py --scope server "$tmp/a.c" "$tmp/b.c"   # 2nd pass = no-op
cat "$tmp/a.c" "$tmp/b.c"
```
Expected `a.c`: `brix_vfs_io_account BRIX_OP_OPEN_RD ngx_brix_dashboard_shm_zone`
Expected `b.c`: `root:// XrdHttp xrdcp nginx-xrootd BRIX_PROTO_ROOT the xrootd protocol /xrootd/login` — KEEP tokens intact; only `XROOTD_` prefix changed; prose "xrootd protocol", `nginx-xrootd`, and the `/xrootd/login` route (Group B, handled in Task 2) all untouched by the engine. Second pass: `changed 0 lines`.

- [ ] **Step 5: Commit tooling**

```bash
git add tools/refactor/brix_rebrand.py tools/refactor/brix_verify.sh .git-blame-ignore-revs
git commit -m "chore(rebrand): add BriX namespace rename engine + verifier"
```

---

## Task 1: Server underscore-namespace hard-rename (code + directives + metrics + env + log filenames)

Group-A server rules (S1–S5) move at once across `src/`, `./config`, `tests/`, `deploy/`, `contrib/`, `tools/ci/` — a compiled namespace cannot be half-renamed, and the pytest suite asserts on the renamed metric/directive names, so the whole class + its consumers must land in one green commit. Dashboard routes and log-line prefixes are deliberately **out of scope here** (Task 2); the engine's anchors leave them alone.

**Files:**
- Modify: `src/**/*.{c,h}` — all `xrootd_`/`XROOTD_`/`ngx_xrootd*` identifiers; `src/core/ident.h` `XROOTD_SERVER_*` macros; `src/observability/**` metric-name string literals; config-directive name strings in `src/*/module.c` command tables; `XROOTD_*` env-var string literals
- Modify: `config`
- Modify: `tests/**` — Python assertions on metric/directive/env/log names; C unit tests referencing `XROOTD_*`/`xrootd_*`; `tests/manage_test_servers.sh` + `tests/lib/*.sh` (env vars, log filenames); the 8 env-var setter files
- Modify: `deploy/cvmfs/docker/nginx.conf.in`, `deploy/cvmfs/docker/smoke.sh`, `deploy/cvmfs/**/README.md`, any `deploy/**` Grafana JSON referencing `xrootd_*` metrics
- Modify: `contrib/xrootd.conf.example` (content; file renamed in Task 5)
- Modify: `tools/ci/check_vfs_seam.sh`, `tools/ci/check_http_helper_reimpl.sh` (grep patterns keyed on `xrootd_`/`XROOTD_`)
- Create: `docs/refactor/brix-rename-migration.md`
- Bump: `src/core/ident.h` `"1.0.7"` → `"1.0.8"`

**Interfaces:**
- Consumes: the Task 0 engine.
- Produces: server tree with every Group-A token as `brix_`/`BRIX_`/`ngx_brix*`; module structs `ngx_brix_module`, `ngx_stream_brix_module`, `ngx_http_brix_webdav_module`, … (referenced by nginx's generated `ngx_modules.c`); directives `brix_*`; metrics `brix_*`; env vars `BRIX_*`; access logs `brix_access*.log`.

- [ ] **Step 1: Baseline — build + full suite green BEFORE any edit**

Run:
```bash
REPO=/home/rcurrie/HEP-x/nginx-xrootd
rm -rf /tmp/nginx-1.28.3/objs
( cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module \
    --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO ) \
  && make -C /tmp/nginx-1.28.3 -j"$(nproc)"
tests/run_suite.sh --pr 2>&1 | tail -20
```
Expected: build exit 0; `--pr` gate green. If red here, STOP and reset the environment first — a rebrand must not inherit pre-existing breakage.

- [ ] **Step 2: Dry-run + review the categorized diff**

Run:
```bash
tools/refactor/brix_rebrand.py --scope server --dry-run \
  src config tests deploy contrib tools/ci 2>&1 | tail -30
```
Expected: `would change ~33,600+ lines in ~1,050 files`. Confirm no `root://`, `kXR_`, `Xrd*`, `xrdcp`, `xrootdfs`, `nginx-xrootd`, or `/xrootd/` route line appears in the diff. If a `deploy/`/`contrib/` fence quotes a *verbatim upstream* `xrootd.conf`, add it to `EXCLUDE` and re-dry-run.

- [ ] **Step 3: Emit the operator migration map**

Run:
```bash
tools/refactor/brix_rebrand.py --scope server --dry-run --emit-map /tmp/brix_map.tsv \
  src config tests deploy contrib tools/ci
{
  echo "# BriX Rename Migration Map"; echo
  echo "> Generated $(date +%F). Hard rename — old names no longer work. Update"
  echo "> nginx.conf directives, Grafana/alert metric queries, environment"
  echo "> variables, dashboard route bookmarks (/xrootd -> /brix), and log paths."
  echo; echo '| Old | New |'; echo '|-----|-----|'
  grep -v '^#' /tmp/brix_map.tsv | sed -E 's/^([^\t]+)\t(.+)$/| `\1` | `\2` |/'
} > docs/refactor/brix-rename-migration.md
```

- [ ] **Step 4: Apply the server rename**

```bash
tools/refactor/brix_rebrand.py --scope server src config tests deploy contrib tools/ci
```

- [ ] **Step 5: Bump the server version**

```bash
sed -i 's/BRIX_SERVER_VERSION_BARE  "1.0.7"/BRIX_SERVER_VERSION_BARE  "1.0.8"/' src/core/ident.h
grep -n 'BRIX_SERVER_VERSION_BARE' src/core/ident.h
```
Expected: shows `"1.0.8"`.

- [ ] **Step 6: Residual scan (Group A)**

```bash
tools/refactor/brix_verify.sh server src config tests deploy contrib tools/ci
```
Expected: `brix_verify: OK (server)` + KEEP census. Residuals are either upstream quotes (→ `EXCLUDE`) or a genuine miss (investigate — anchored rules only miss novel contexts). Fix via the tool, never hand-edit around it. Note: the verifier whitelists `nginx-xrootd*` and `.ngx-xrootd-*` (KEEP), and does **not** flag `/xrootd` routes or `"xrootd: "` prefixes (Task 2).

- [ ] **Step 7: Clean reconfigure + full rebuild**

```bash
REPO=/home/rcurrie/HEP-x/nginx-xrootd
rm -rf /tmp/nginx-1.28.3/objs
( cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module \
    --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO ) \
  && make -C /tmp/nginx-1.28.3 -j"$(nproc)" 2>&1 | tail -20
```
Expected: exit 0. A link error naming `ngx_xrootd_module` means `objs/ngx_modules.c` was stale — the `rm -rf objs` + reconfigure regenerates it against `ngx_brix_module`.

- [ ] **Step 8: Validate a running config with renamed directives**

```bash
tests/manage_test_servers.sh restart 2>&1 | tail -5
/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/xrd-test/conf/nginx.conf
```
Expected: `configuration file ... test is successful`. `unknown directive "brix_cache_store"` means a harness config template still emits an old name — grep `tests/` and confirm Step 4 covered it.

- [ ] **Step 9: `.so` identity + no old exported symbols**

```bash
strings /tmp/nginx-1.28.3/objs/nginx | grep -i 'brix-cache v1.0.8' | head -1
nm -D /tmp/nginx-1.28.3/objs/nginx 2>/dev/null | grep -E '\bxrootd_|\bngx_xrootd' || echo "no old exported symbols"
```
Expected: shows `BriX-Cache v1.0.8`; prints `no old exported symbols`.

- [ ] **Step 10: Focused metric/directive/env tests**

```bash
PYTHONPATH=tests pytest tests/ -k "metric or metrics or directive or config or health or srr or dashboard_config or xfer_resume or tape or stage" -v --tb=short 2>&1 | tail -30
```
Expected: green. Narrows the blast radius of the hard metric/directive/env rename before the full run.

- [ ] **Step 11: Full PR-gate suite**

```bash
tests/run_suite.sh --pr 2>&1 | tail -25
```
Expected: green.

- [ ] **Step 12: Commit + record blame SHA**

```bash
git add -A src config tests deploy contrib tools/ci docs/refactor/brix-rename-migration.md
git commit -m "refactor(rebrand): rename server namespace xrootd_->brix_ (code, directives, metrics, env, log filenames) [v1.0.8]"
git rev-parse HEAD >> .git-blame-ignore-revs
git add .git-blame-ignore-revs && git commit -m "chore(rebrand): record server-rename SHA in blame-ignore"
```

---

## Task 2: Dashboard routes, log-line prefixes & snapshot name (Group B, targeted)

The self-references that are **not** underscore-anchored — and therefore invisible to the engine — are rewritten surgically on named files with per-file review, so a broad regex can never confuse `/xrootd/…` with a user data path. fail2ban filters that parse `"xrootd: "` log lines are updated in lockstep. The on-disk cache sentinels are **left alone** (Risk R4).

**Files:**
- Modify (routes, 6 files): `src/observability/dashboard/module.c`, `page.c`, `api_admin_cluster.c`, `api_admin_config.c`, `api_transfers.c`, `dashboard_api_admin_internal.h`
- Modify (snapshot download name): `src/observability/dashboard/page.c`
- Modify (log prefixes, ~132 files): `src/**/*.c` emitting `"xrootd: …"`
- Modify (fail2ban): `deploy/fail2ban/filter.d/*.conf` (or equivalent) if they match `xrootd:`
- Modify (route consumers): `tests/**` and `deploy/**`/`docs/**` referencing `/xrootd` dashboard URLs; nginx `location /xrootd` blocks in test/deploy configs

**Interfaces:**
- Consumes: the Task 1 tree (dashboard symbols already `ngx_http_brix_dashboard_*`).
- Produces: dashboard served under `/brix` (`/brix/login`, `/brix/api/v1/…`); log lines prefixed `brix:`; snapshot download `brix-dashboard-snapshot.json`.

- [ ] **Step 1: Enumerate the exact route literals (fresh, in case Task 1 shifted lines)**

```bash
grep -rhoIE '"/xrootd[a-z/0-9_]*"' src/observability/dashboard | sort -u
grep -rIln '"/xrootd' src | sort -u
grep -rIln 'location\s*/xrootd\|/xrootd/login\|/xrootd/api' tests deploy | sort -u
```
Expected: the 23 route literals listed in the Scope Census, plus any test/deploy `location /xrootd` blocks and JS `location.href='/xrootd/login'` consumers.

- [ ] **Step 2: Rewrite the dashboard route base + snapshot name**

```bash
for f in src/observability/dashboard/module.c src/observability/dashboard/page.c \
         src/observability/dashboard/api_admin_cluster.c \
         src/observability/dashboard/api_admin_config.c \
         src/observability/dashboard/api_transfers.c \
         src/observability/dashboard/dashboard_api_admin_internal.h; do
  sed -i -e 's#"/xrootd#"/brix#g' \
         -e "s#location.href='/xrootd#location.href='/brix#g" \
         -e 's#xrootd-dashboard-snapshot#brix-dashboard-snapshot#g' "$f"
done
grep -rn '"/xrootd\|/xrootd/login\|xrootd-dashboard-snapshot' src/observability/dashboard || echo "dashboard routes clean"
```
Expected: `dashboard routes clean`. (The `sed` covers both C string literals `"/xrootd…"` and the embedded-JS single-quoted `'/xrootd/login'`.)

- [ ] **Step 3: Update route consumers in tests, deploy, docs**

```bash
grep -rIl "/xrootd/login\|/xrootd/api\|location.*[= ]/xrootd\b\|/xrootd/transfers" tests deploy docs \
  | grep -vE 'phase-6[67]-map|2026-07-03-brix-symbol-rebrand' | while read -r f; do
  sed -i -E 's#/xrootd(/api|/login|/transfers|"|/)#/brix\1#g' "$f"
done
grep -rIn '/xrootd/login\|/xrootd/api\|/xrootd/transfers' tests deploy docs \
  | grep -vE 'phase-6[67]|2026-07-03-brix' || echo "route consumers clean"
```
Expected: `route consumers clean`. (Anchored to `/xrootd` immediately followed by a route segment or quote so filesystem paths like `/tmp/...` are never touched.)

- [ ] **Step 4: Log-line prefix — dry-run review first (fail2ban coupling)**

```bash
grep -rIl '"xrootd: ' src | wc -l
grep -rhoIE '"xrootd: [a-zA-Z]+' src | sort -u | head -20
# fail2ban dependency check:
grep -rIn 'xrootd:' deploy/fail2ban 2>/dev/null || echo "fail2ban does not key on 'xrootd:'"
```
Expected: ~132 files; a list of leaders (`"xrootd: cache`, `"xrootd: admin`, …). Note whether any fail2ban filter regex contains `xrootd:` — if so, Step 6 must update it in the same commit.

- [ ] **Step 5: Rewrite the log-line prefix**

```bash
grep -rIl '"xrootd: ' src | while read -r f; do
  sed -i 's/"xrootd: /"brix: /g' "$f"
done
grep -rIn '"xrootd: ' src || echo "log prefixes clean"
```
Expected: `log prefixes clean`. (Pattern requires the exact `"xrootd: ` opener — a quote, the token, a colon, a space — so it only matches log-message leaders, never identifiers or the `xrootd` protocol word.)

- [ ] **Step 6: Update fail2ban filters + guard-audit sample references (if Step 4 found a dependency)**

```bash
grep -rIl 'xrootd:' deploy/fail2ban 2>/dev/null | while read -r f; do
  sed -i 's/\bxrootd:/brix:/g' "$f"
done
grep -rIn '\bxrootd:' deploy/fail2ban 2>/dev/null || echo "fail2ban filters clean"
```
Expected: `fail2ban filters clean` (or the "does not key" note from Step 4, in which case this step is a no-op).

- [ ] **Step 7: Rebuild (only string literals changed — incremental is enough)**

```bash
make -C /tmp/nginx-1.28.3 -j"$(nproc)" 2>&1 | tail -6
```
Expected: exit 0.

- [ ] **Step 8: Smoke-test the new dashboard route end-to-end**

```bash
tests/manage_test_servers.sh restart 2>&1 | tail -3
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8443/brix/login      # expect 200/302
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8443/xrootd/login     # expect 404 (old route gone)
curl -s http://localhost:8443/brix/api/v1/snapshot 2>/dev/null | head -c 80; echo
grep -rh 'brix:' /tmp/xrd-test/logs/error.log 2>/dev/null | head -2
```
Expected: `/brix/login` → 200 or 302; `/xrootd/login` → 404; snapshot endpoint returns JSON; error log lines now read `brix: …`.

- [ ] **Step 9: Dashboard + guard test groups**

```bash
PYTHONPATH=tests pytest tests/ -k "dashboard or guard or fail2ban or transfers or admin_cluster" -v --tb=short 2>&1 | tail -30
```
Expected: green. Any 404 on a `/xrootd/…` assertion means a test route consumer was missed in Step 3.

- [ ] **Step 10: Commit + blame SHA**

```bash
git add -A src deploy tests docs
git commit -m "refactor(rebrand): dashboard routes /xrootd->/brix, log prefixes 'xrootd:'->'brix:', snapshot name (fail2ban updated)"
git rev-parse HEAD >> .git-blame-ignore-revs
git add .git-blame-ignore-revs && git commit -m "chore(rebrand): record dashboard/log-prefix SHA in blame-ignore"
```

---

## Task 3: Server header-file renames

Rename the two headers whose *filenames* carry `ngx_xrootd_`, and fix every `#include` plus the `./config` dep list, atomically.

**Files:**
- Rename: `src/core/ngx_xrootd_module.h` → `src/core/ngx_brix_module.h`
- Rename: `src/protocols/root/fattr/ngx_xrootd_fattr.h` → `src/protocols/root/fattr/ngx_brix_fattr.h`
- Modify: every `#include` of those headers (src-rooted or bare); `config` dep paths

- [ ] **Step 1: `git mv` (preserve history)**

```bash
git mv src/core/ngx_xrootd_module.h src/core/ngx_brix_module.h
git mv src/protocols/root/fattr/ngx_xrootd_fattr.h src/protocols/root/fattr/ngx_brix_fattr.h
```

- [ ] **Step 2: Fix include references**

```bash
grep -rIl 'ngx_xrootd_module\.h\|ngx_xrootd_fattr\.h' src config | while read -r f; do
  sed -i -e 's#ngx_xrootd_module\.h#ngx_brix_module.h#g' \
         -e 's#ngx_xrootd_fattr\.h#ngx_brix_fattr.h#g' "$f"
done
grep -rIn 'ngx_xrootd_module\.h\|ngx_xrootd_fattr\.h' src config || echo "no stale include paths"
```
Expected: `no stale include paths`.

- [ ] **Step 3: Rebuild (dep graph changed → reconfigure)**

```bash
REPO=/home/rcurrie/HEP-x/nginx-xrootd
rm -rf /tmp/nginx-1.28.3/objs
( cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module \
    --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO ) \
  && make -C /tmp/nginx-1.28.3 -j"$(nproc)" 2>&1 | tail -10
```
Expected: exit 0. `fatal error: core/ngx_xrootd_module.h: No such file` = a missed `#include`.

- [ ] **Step 4: Full-suite smoke (compile-time change only)**

```bash
tests/run_suite.sh --pr 2>&1 | tail -15
```
Expected: green.

- [ ] **Step 5: Commit + blame SHA**

```bash
git add -A src config
git commit -m "refactor(rebrand): rename ngx_xrootd_{module,fattr}.h -> ngx_brix_*"
git rev-parse HEAD >> .git-blame-ignore-revs
git add .git-blame-ignore-revs && git commit -m "chore(rebrand): record header-rename SHA in blame-ignore"
```

---

## Task 4: Client library rebrand (libxrdc → libbrix, xrdc_ → brix_)

Rename the shipped library, SONAME chain, pkg-config, the `xrdc_` symbol prefix, the LD_PRELOAD shim, and the public headers — keeping tool binaries. Regenerate the tracked `.so`/`.a` artifacts.

**Files:**
- Rename: `client/lib/xrdc.h` → `brix.h`; `xrdc_auth.h` → `brix_auth.h`; `xrdc_net.h` → `brix_net.h`; `xrdc_ops.h` → `brix_ops.h`
- Rename: `client/examples/xrdc_readv_demo.c` → `brix_readv_demo.c`; `xrdc_stat_demo.c` → `brix_stat_demo.c`
- Rename: `client/preload/xrdposix_preload.c` → `brixposix_preload.c`
- Rename: `client/libxrdc.pc` → `client/libbrix.pc`
- Modify: `client/**/*.{c,h}` (`xrdc_` → `brix_`, include paths, `-lxrdc`); `client/Makefile` (lib vars, targets, install, preload path, clean list)
- Remove + regenerate: tracked `client/libxrdc.{so,so.0,so.0.1.0,a}`, `client/libxrdposix_preload.so`
- Modify: `tests/**` referencing `libxrdc`, `libxrdposix_preload`, pkg-config `libxrdc`, `LD_PRELOAD`

**Interfaces:**
- Consumes: the Task 0 engine (client scope, C1–C5).
- Produces: `libbrix.so.0.1.0` (SONAME `libbrix.so.0`) + `libbrix.a` + `libbrix.pc`; `brix_*` symbols; `libbrixposix_preload.so`. Tool binaries unchanged.

- [ ] **Step 1: `git mv` sources/headers/examples/preload/pc**

```bash
git mv client/lib/xrdc.h        client/lib/brix.h
git mv client/lib/xrdc_auth.h   client/lib/brix_auth.h
git mv client/lib/xrdc_net.h    client/lib/brix_net.h
git mv client/lib/xrdc_ops.h    client/lib/brix_ops.h
git mv client/examples/xrdc_readv_demo.c client/examples/brix_readv_demo.c
git mv client/examples/xrdc_stat_demo.c  client/examples/brix_stat_demo.c
git mv client/preload/xrdposix_preload.c client/preload/brixposix_preload.c
git mv client/libxrdc.pc        client/libbrix.pc
```

- [ ] **Step 2: Rewrite client sources + Makefile + pc, fix umbrella include**

```bash
tools/refactor/brix_rebrand.py --scope client \
  client/lib client/apps client/examples client/preload client/Makefile client/libbrix.pc
# C4 covers xrdc_auth.h etc.; the bare "xrdc.h" umbrella needs an explicit fix:
grep -rIl '"xrdc\.h"' client | while read -r f; do
  sed -i 's#"xrdc\.h"#"brix.h"#g' "$f"
done
grep -rIn '"xrdc\.h"\|"xrdc_' client || echo "client includes clean"
```
Expected: `client includes clean`.

- [ ] **Step 3: Confirm tool-binary names survived + client residual scan**

```bash
grep -nE 'BINS\s*[:=]|xrdcp|xrdfs|xrootdfs|xrdcrc32c|xrdckverify' client/Makefile | head
tools/refactor/brix_verify.sh client client/lib client/apps client/examples client/preload client/Makefile client/libbrix.pc
```
Expected: `BINS` still lists `xrdcp xrdfs xrdcinfo xrdckverify xrdcrc32c xrdcrc64` (+`xrootdfs`); `brix_verify: OK (client)`; KEEP census shows tool names non-zero.

- [ ] **Step 4: Remove stale tracked artifacts**

```bash
git rm client/libxrdc.a client/libxrdc.so client/libxrdc.so.0 client/libxrdc.so.0.1.0 \
       client/libxrdposix_preload.so 2>/dev/null || true
ls client/libxrdc* client/libxrdposix* 2>/dev/null || echo "old artifacts removed"
```
Expected: `old artifacts removed`.

- [ ] **Step 5: Rebuild library, preload, tools**

```bash
make -C client clean
make -C client lib 2>&1 | tail -8
make -C client 2>&1 | tail -12
ls -l client/libbrix.so* client/libbrix.a client/libbrix.pc client/libbrixposix_preload.so
```
Expected: `libbrix.so.0.1.0` + symlinks `libbrix.so.0`→`libbrix.so.0.1.0`, `libbrix.so`→`libbrix.so.0`; `libbrix.a`, `libbrix.pc`, `libbrixposix_preload.so`; tool binaries rebuilt.

- [ ] **Step 6: Verify SONAME + pkg-config**

```bash
readelf -d client/libbrix.so.0.1.0 | grep SONAME
PKG_CONFIG_PATH=client pkg-config --libs --cflags libbrix
grep -n 'Name:\|Description:\|Libs:' client/libbrix.pc
```
Expected: `SONAME  Library soname: [libbrix.so.0]`; pkg-config prints `-lbrix`; `Name: libbrix`.

- [ ] **Step 7: Update tests/harness referencing old client names**

```bash
grep -rIl 'libxrdc\|libxrdposix_preload\|-lxrdc\|pkg-config.*\bxrdc\b' tests | while read -r f; do
  sed -i -e 's#libxrdposix_preload#libbrixposix_preload#g' \
         -e 's#libxrdc#libbrix#g' -e 's#-lxrdc#-lbrix#g' \
         -e 's#\(pkg-config[^\n]*\)\bxrdc\b#\1brix#g' "$f"
done
grep -rIn 'libxrdc\|libxrdposix_preload\|-lxrdc' tests || echo "no stale client refs in tests"
```
Expected: `no stale client refs in tests`.

- [ ] **Step 8: Client-facing test groups**

```bash
PYTHONPATH=tests pytest tests/ -k "client or clientconf or xrootdfs or preload or vfs_seam_client" -v --tb=short 2>&1 | tail -30
```
Expected: green (except the pre-existing XrdCl-proxy-worker env failures noted in project memory — environmental, not from this rename). No failure should reference a missing `libxrdc`/`libxrdposix_preload`.

- [ ] **Step 9: Commit + blame SHA**

```bash
git add -A client tests
git commit -m "refactor(rebrand): client libxrdc->libbrix, xrdc_ symbols->brix_, preload->libbrixposix (tool names kept)"
git rev-parse HEAD >> .git-blame-ignore-revs
git add .git-blame-ignore-revs && git commit -m "chore(rebrand): record client-rename SHA in blame-ignore"
```

---

## Task 5: Ancillary asset renames (contrib + deploy samples)

Rename the two remaining namespaced asset files and fix referrers. Content was rewritten in Task 1; only filenames + referrers remain.

**Files:**
- Rename: `contrib/xrootd.conf.example` → `contrib/brix-cache.conf.example`
- Rename: `deploy/fail2ban/samples/xrootd-guard-audit.sample.log` → `brix-guard-audit.sample.log`
- Modify: any doc/test/deploy referencing those paths

- [ ] **Step 1: Move the files**

```bash
git mv contrib/xrootd.conf.example contrib/brix-cache.conf.example
git mv deploy/fail2ban/samples/xrootd-guard-audit.sample.log \
       deploy/fail2ban/samples/brix-guard-audit.sample.log
```

- [ ] **Step 2: Fix referrers**

```bash
grep -rIl 'xrootd\.conf\.example\|xrootd-guard-audit\.sample\.log' . \
  --include='*.md' --include='*.conf' --include='*.sh' --include='*.py' --include='*.in' \
  | grep -vE '2026-07-03-brix-symbol-rebrand\.md' | while read -r f; do
  sed -i -e 's#xrootd\.conf\.example#brix-cache.conf.example#g' \
         -e 's#xrootd-guard-audit\.sample\.log#brix-guard-audit.sample.log#g' "$f"
done
grep -rIn 'xrootd\.conf\.example\|xrootd-guard-audit\.sample\.log' . \
  --include='*.md' --include='*.conf' --include='*.sh' --include='*.py' --include='*.in' \
  | grep -vE '2026-07-03-brix' || echo "no stale asset refs"
```
Expected: `no stale asset refs`.

- [ ] **Step 3: Commit**

```bash
git add -A contrib deploy docs
git commit -m "refactor(rebrand): rename contrib/deploy sample assets to brix-*"
```

---

## Task 6: Documentation self-references (living docs only)

Rewrite own-namespace tokens in living docs (guides, reference, architecture, READMEs, CLAUDE.md) with the anchored server rules — so prose "XRootD", `root://`, `kXR_*`, `nginx-xrootd`, and the historical-exclude set are untouched; only `xrootd_`-prefixed identifiers, `XROOTD_` macros, directive/metric names in code fences, and `ngx_xrootd*` symbols change. Route references (`/xrootd`→`/brix`) were already handled in Task 2 Step 3.

**Files:**
- Modify: `docs/**/*.md` (minus EXCLUDE), `README.md`, `CLAUDE.md`, `client/**/README.md`, `client/man/*`
- Not modified: the four EXCLUDE-set files

- [ ] **Step 1: Dry-run + eyeball for prose false-positives**

```bash
tools/refactor/brix_rebrand.py --scope docs --dry-run docs README.md CLAUDE.md client 2>&1 | tail -20
```
Expected: changed lines are code-fence identifiers / directive names / metric names / `ngx_xrootd*` / `XROOTD_*` only. Sentences like "speaks the XRootD `root://` protocol" and "the upstream XRootD project" show **no** change. Spot-check 3–4 `--- path` entries.

- [ ] **Step 2: Apply**

```bash
tools/refactor/brix_rebrand.py --scope docs docs README.md CLAUDE.md client
```

- [ ] **Step 3: Residual scan**

```bash
tools/refactor/brix_verify.sh docs docs README.md CLAUDE.md client
```
Expected: `brix_verify: OK (docs)`. Residuals = a legitimate upstream-config quote (→ `EXCLUDE`) or an already-whitelisted historical file.

- [ ] **Step 4: KEEP-word presence sanity**

```bash
grep -rIlc 'XRootD' docs README.md | head -3
grep -rIn 'root://' README.md docs/00-overview* | head -3
grep -rIn 'nginx-xrootd' README.md | head -2
```
Expected: "XRootD", `root://`, and `nginx-xrootd` still present.

- [ ] **Step 5: CLAUDE.md operational read-through**

Confirm CLAUDE.md's "Logs:" line reads `brix_access*.log`, HELPERS/OP→FILE/DEBUG tables read `brix_*`/`ngx_brix_*`/`BRIX_*` where they name our code, and the dashboard route hints (if any) read `/brix`. Fix any half-sentence the mechanical pass produced.

```bash
grep -nE 'xrootd_access|xrootd_cache_store|ngx_xrootd|XROOTD_' CLAUDE.md || echo "CLAUDE.md clean"
```
Expected: `CLAUDE.md clean`.

- [ ] **Step 6: Commit**

```bash
git add -A docs README.md CLAUDE.md client
git commit -m "docs(rebrand): rename own-namespace refs xrootd_->brix_ in living docs (upstream/protocol/module-name prose preserved)"
```

---

## Task 7: Final repo-wide verification & changelog

**Files:**
- Modify: `CHANGELOG.md`
- Read-only: entire repo (invariance + residual audit)

- [ ] **Step 1: Repo-wide residual audit**

```bash
tools/refactor/brix_verify.sh server src config tests deploy contrib tools
tools/refactor/brix_verify.sh client client
tools/refactor/brix_verify.sh docs docs README.md CLAUDE.md
# Group-B residuals (routes/log-prefix) that the engine ignores:
grep -rIn '"/xrootd\|"xrootd: ' src && echo "GROUP-B RESIDUAL" || echo "group-B clean"
```
Expected: three `brix_verify: OK` lines + `group-B clean`.

- [ ] **Step 2: KEEP-token invariance vs pre-rebrand baseline**

```bash
firstrev=$(sed -n '2p' .git-blame-ignore-revs)   # server-rename SHA
for tok in 'root://' 'kXR_' 'XrdCl' 'XrdHttp' 'xrdcp' 'xrdfs' 'xrootdfs' 'XrdCks' 'nginx-xrootd' '.ngx-xrootd-part'; do
  before=$(git grep -IF "$tok" "${firstrev}^" -- . 2>/dev/null | wc -l)
  after=$(git grep -IF "$tok" HEAD -- . 2>/dev/null | wc -l)
  printf '%-18s before=%s after=%s %s\n' "$tok" "$before" "$after" \
    "$([ "$before" = "$after" ] && echo OK || echo DRIFT)"
done
```
Expected: every KEEP token reports `OK`. A `DRIFT` means the rename leaked into a preserved surface — locate with `git log -S"$tok"` and correct.

- [ ] **Step 3: Clean build (module + client) + full PR gate from scratch**

```bash
REPO=/home/rcurrie/HEP-x/nginx-xrootd
rm -rf /tmp/nginx-1.28.3/objs
( cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module \
    --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO ) \
  && make -C /tmp/nginx-1.28.3 -j"$(nproc)" 2>&1 | tail -8
make -C client clean && make -C client 2>&1 | tail -6
tests/run_suite.sh --pr 2>&1 | tail -25
```
Expected: both builds exit 0; `--pr` gate green.

- [ ] **Step 4: Externally-visible identity end-to-end**

```bash
tests/manage_test_servers.sh restart 2>&1 | tail -3
curl -s http://localhost:9100/metrics | grep -E '^brix_' | head -3
curl -s http://localhost:9100/metrics | grep -E '^xrootd_' && echo "OLD METRIC LEAK" || echo "no old metrics"
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8443/brix/login
curl -s http://localhost:8443/healthz 2>/dev/null | grep -o 'BriX-Cache[^"]*' | head -1
strings /tmp/nginx-1.28.3/objs/nginx | grep -iE 'brix-cache v1\.0\.8' | head -1
```
Expected: `/metrics` emits `brix_*` and `no old metrics`; `/brix/login` → 200/302; `/healthz` service `BriX-Cache`; binary advertises `BriX-Cache v1.0.8`.

- [ ] **Step 5: Changelog + commit**

```bash
cat >> CHANGELOG.md <<'EOF'

## v1.0.8 — BriX namespace rebrand
- Renamed the project's own namespace: server `xrootd_`->`brix_`, `XROOTD_`->`BRIX_`,
  `ngx_xrootd*`->`ngx_brix*`; client `xrdc_`->`brix_`, `libxrdc.*`->`libbrix.*`,
  `libxrdposix_preload`->`libbrixposix_preload`.
- **Breaking:** config directives (`xrootd_*`->`brix_*`), Prometheus metrics
  (`xrootd_*`->`brix_*`), dashboard routes (`/xrootd`->`/brix`), env vars
  (`XROOTD_*`->`BRIX_*`), access-log filenames (`xrootd_access*.log`->`brix_access*.log`),
  and operator log-line prefixes (`xrootd:`->`brix:`; update fail2ban filters).
- Preserved: upstream XRootD/`root://` protocol references (`kXR_*`, `XrdCl`, `XrdHttp`),
  tool binaries (`xrdcp`/`xrdfs`/…), the nginx module identity `nginx-xrootd`, and the
  on-disk cache sentinels (`.ngx-xrootd-*`). Migration map: docs/refactor/brix-rename-migration.md
EOF
git add CHANGELOG.md
git commit -m "docs(rebrand): changelog v1.0.8 + migration pointer"
```

---

## Verification Matrix

| Surface                         | Proven by                                                    | Task/Step   |
|---------------------------------|-------------------------------------------------------------|-------------|
| Server C symbols renamed        | `brix_verify.sh server` = OK; clean build exit 0            | T1.6, T7.1  |
| No old exported symbols in `.so`| `nm -D … | grep xrootd_` = empty                            | T1.9        |
| Config directives renamed       | `nginx -t` on regenerated conf succeeds                      | T1.8        |
| Prometheus metrics renamed      | `/metrics` emits `brix_*`, no `xrootd_*`                     | T7.4        |
| Dashboard routes renamed        | `/brix/login`→200, `/xrootd/login`→404                       | T2.8, T7.4  |
| Log-line prefixes renamed       | error.log lines read `brix:`; fail2ban filters updated      | T2.8, T2.6  |
| Env-var contracts renamed       | tape/stage/xfer tests green with `BRIX_*`                    | T1.10       |
| Access-log filenames renamed    | harness writes `brix_access*.log`                            | T1.8        |
| Client library renamed          | `readelf SONAME`=`libbrix.so.0`; pkg-config `-lbrix`         | T4.6        |
| Tool binaries preserved         | KEEP census `xrdcp`/`xrdfs` non-zero; `BINS` unchanged      | T4.3, T7.2  |
| Upstream/protocol preserved     | KEEP-token before==after invariance                         | T7.2        |
| Module identity preserved       | `nginx-xrootd` before==after; `/healthz` service `BriX-Cache`| T7.2, T7.4  |
| Version bumped                  | binary advertises `BriX-Cache v1.0.8`                        | T1.9, T7.4  |
| `git blame` preserved           | each rename SHA in `.git-blame-ignore-revs`                  | every commit|

---

## Risk Register

| # | Risk | Likelihood | Mitigation |
|---|------|-----------|------------|
| R1 | Broad `xrootd_`→`brix_` corrupts an upstream/protocol reference | Low | Rules are underscore/word-anchored + case-sensitive; upstream refs are CamelCase (`XrdCl`), scheme (`root://`), or hyphenated (`nginx-xrootd`) — structurally unmatched. T7.2 invariance check is the backstop. |
| R2 | Dashboard route regex hits a user data path (`/xrootd/` in a `root://…//xrootd/…` URL) | Med | Group-B routes are rewritten **only** on the 6 named dashboard files + anchored route-segment consumers, never tree-wide; T2.3 anchors `/xrootd` to a following route segment or quote. |
| R3 | Log-prefix rename breaks fail2ban ban rules | Med | T2.4 explicitly greps `deploy/fail2ban` for `xrootd:`; T2.6 updates filters in the **same commit**; T2.8 confirms `brix:` lines are emitted. |
| R4 | Renaming on-disk cache sentinels (`.ngx-xrootd-part/-lock`) orphans locks / double-fills during a rolling upgrade (old workers write old suffix, new workers don't see them — the exact class in the reboot-lockup postmortem) | Med→High | **Decision: KEEP** these on-disk names. They are internal, invisible to operators, and not brand-facing. Documented in the KEEP list; verifier whitelists them. (Opt-in rename would require a one-shot migration + fleet-wide stop, out of scope.) |
| R5 | Metric/directive hard rename breaks operators' Grafana/alerts/nginx.conf | High (by design) | Generated migration map (`brix-rename-migration.md`) enumerates every old→new pair; CHANGELOG flags the break; version bumped to v1.0.8. |
| R6 | Stale nginx `objs/` links against old `ngx_xrootd_module` symbol | Med | Every module/header-touching task does `rm -rf objs` + full reconfigure (T1.7, T3.3, T7.3), never an incremental relink. |
| R7 | A doc pastes a verbatim upstream `xrootd.conf` and gets wrongly rewritten | Low | Called out in T1.2 and T6.1 dry-run reviews; add the file to the engine's `EXCLUDE` set before applying. |
| R8 | `git blame` destroyed across ~41k-line churn | High (by design) | `.git-blame-ignore-revs` populated per commit + `git config blame.ignoreRevsFile`. |

---

## Pre-flight Checklist (run once before Task 1)

- [ ] Working tree state understood: `git status` reviewed; the uncommitted WIP noted in project memory is expected — **do not** `git stash`/`reset`/`checkout` (project HARD BLOCK).
- [ ] Baseline green: Task 1 Step 1 passes (build exit 0 + `--pr` gate green) *before* any rename.
- [ ] Disk/host healthy: no orphaned fuse mounts or wedged workers (`pgrep -f nginx`; `mount | grep fuse`) — a poisoned box produces false test failures unrelated to the rebrand (see project memory on fleet hygiene).
- [ ] `REPO` exported to the literal path (never empty): `REPO=/home/rcurrie/HEP-x/nginx-xrootd`.
- [ ] nginx build tree present at `/tmp/nginx-1.28.3`.

---

## Self-Review

**1. Spec coverage** — every requested surface maps to a task:
- "`xrootd_vfs_io_account`→`brix_vfs_io_account`" → T1 (rule S5).
- "`ngx_xrootd_dashboard_shm_zone`→`ngx_brix_dashboard_shm_zone`" → T1 (S3/S5).
- "keep references to root / XRootD (upstream project / protocol)" → Global Constraints KEEP list + anchored rules; proven by T7.2 invariance.
- "code" → T1/T3/T4; "prometheus metrics" → T1 (metric strings, hard rename); "dashboard" → T1 (symbols) + **T2 (routes + snapshot name)**; "docs" → T6.
- "rename `client/libxrdc.so`→`client/libbrix.so`" → T4 (+ SONAME chain, `.a`, `.pc`, symbols, preload; tool names kept per decision).
- "draft a plan, save under docs/refactor" → this file: `docs/refactor/2026-07-03-brix-symbol-rebrand.md`.

**2. Placeholder scan** — no `TBD`/"handle edge cases"/"write tests for the above": every step carries exact commands + expected output; the engine and verifier are given in full; the 429 directives / 167 metrics / 7 env vars / 23 route literals / on-disk sentinels are enumerated or scoped by exact grep.

**3. Type/name consistency** — target spellings agree everywhere: `brix_`, `BRIX_`, `ngx_brix_*`, `libbrix`, SONAME `libbrix.so.0`, real `libbrix.so.0.1.0`, `Name: libbrix`, `libbrixposix_preload`, `brix_access*.log`, `/brix`, `brix:` prefix, `brix-dashboard-snapshot.json`. KEEP spellings agree: `nginx-xrootd`, `.ngx-xrootd-part/-lock/-evict-lock`, `xrdcp`/`xrdfs`.

**Residual risk deliberately accepted:** R4 (on-disk sentinels kept) and R7 (upstream-config doc quote) — both documented with explicit handling.

---

## Rollback

Each phase is a single commit on `main`. To revert a phase: `git revert <SHA>` (**never** `git reset`/`checkout` — uncommitted WIP exists; project HARD BLOCK). Because the rename is mechanical and the verifier proves invariance, a clean revert restores the prior namespace exactly. `.git-blame-ignore-revs` entries are harmless after a revert.

**Recovery from a bad pass before it is committed:** the engine rewrites in place and is not reversible by re-running it, and `git checkout`/`git restore`/`git reset` are all forbidden here (they would destroy the uncommitted WIP that predates this work). So the safe recovery is: **commit the bad pass first** (isolating it as its own commit), then `git revert` that commit. This is why every task commits promptly and in small, single-purpose units — a committed phase is always cleanly revertible, an uncommitted one is not.
