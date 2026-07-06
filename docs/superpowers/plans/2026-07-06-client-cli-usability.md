# Client CLI Usability Implementation Plan (all phases)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `docs/superpowers/specs/2026-07-06-client-cli-usability-design.md` — all six phases (P1 primitives/env, P2 help/version, P3 hints, P4 aliases, P5 man pages, P6 completions) plus the P0 golden baseline.

**Architecture:** New shared primitives (`lib/cli/cli_hint.c`, `lib/core/config/envalias.c`, `lib/cli/suggest.c`, `lib/core/version.h`) consumed by targeted edits in `lib/cli/cli_opts.c`, the auth env sites, `lib/net/url.c` + the shared error printer, and each `apps/` front-end. Docs/completions are new files under `client/man/` and `client/completions/` with drift guards wired into `make -C client test`.

**Tech Stack:** C (client tree conventions: no goto, WHAT/WHY/HOW headers, `docs/09-developer-guide/coding-standards.md`), POSIX shell for guards, pytest for the golden/pty harnesses. Client builds with `make -C client` (no nginx configure needed — `client/` is standalone).

## Global Constraints

- **Spec §2 compat contract C1–C5 is binding on every task.** In particular C3: all new interactive output goes through `brix_cli_hint*()`, gated on `isatty(STDERR_FILENO)` && `BRIX_NO_HINTS` unset/`"0"`.
- Coding standard: `docs/09-developer-guide/coding-standards.md` (no goto, small pure helpers, WHAT/WHY/HOW block per function).
- 3 tests per change (success + error + security-negative) — each task lists its triple; they land in the same commit.
- New `.c` files must be added to the client Makefile object lists (`LIB_OBJS` area / `<name>_OBJS`) — client only; the nginx `./config` is NOT touched (nothing here is server-side).
- Commit per task directly to `main`. Trailer:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` + `Claude-Session: https://claude.ai/code/session_013rNKxzDhfAqzeBq138fFg6`
- Verified anchors: `lib/cli/cli_opts.c:44-76` (`brix_opts_parse_arg`), `lib/net/url.c:89-94` (slash collapse), `lib/auth/sss/sss_keytab.c:63-70` (keytab env), `lib/auth/sec/sec_pwd.c:47,140-150` (pwd env), `apps/copy/xrdcp.c:377` (`-P` = posc → alias `--posc`), `apps/diag/wait41.c` (`brix_wait41_main`), `lib/brix_net.h:434` (`brix_shellcode`), `lib/cli/cli_conn.c` (shared connect-fail printer), `client/Makefile:439` (`test:` target).

---

### Task 0: Golden non-TTY baseline (spec §12)

**Files:**
- Create: `tests/test_cli_golden.py`
- Create: `tests/cli_pty.py`

**Interfaces:**
- Produces: `tests/cli_pty.py` exposing `run_pty(cmd: list[str], env: dict|None) -> (exit, stdout, stderr)` (pty-backed) and `run_pipe(cmd, env)` (pipes). `tests/test_cli_golden.py` with a `GOLDEN` command matrix and `--capture-baseline` mode writing `tests/golden/cli_baseline.json`.

- [ ] **Step 1: Write `tests/cli_pty.py`** — helper module: `run_pipe` uses `subprocess.run(capture_output=True)`; `run_pty` allocates `pty.openpty()` for stderr only (stdout stays a pipe), reads until EOF with a 30 s guard. Pure stdlib.
- [ ] **Step 2: Write `tests/test_cli_golden.py`** — matrix (each entry: argv, env, needs_fleet flag): `--help`-less baselines for every binary in `client/bin/` (`<tool>` with no args), `xrdfs HOST ls /` + `xrdcp root://HOST//missing /tmp/x` + `xrdfs HOST staat` against the test fleet when up (skip cleanly when down), all via `run_pipe`. Baseline mode: `python tests/test_cli_golden.py --capture-baseline` stores `{key: {exit, stdout_sha, stderr_sha}}`. Test mode (pytest): recompute and compare against `tests/golden/cli_baseline.json`; skip entries whose fleet dependency is unavailable.
- [ ] **Step 3: Build client + capture baseline on CURRENT main** — `make -C client -j$(nproc)`, start fleet if available (`tests/manage_test_servers.sh start`), run `--capture-baseline`, commit the JSON.
- [ ] **Step 4: Commit** — `test(client): golden non-TTY CLI baseline harness`.

---

### Task 1 (P1): `cli_hint` + `envalias` + migrations + `brix-env.7`

**Files:**
- Create: `client/lib/cli/cli_hint.c`, `client/lib/cli/cli_hint.h`
- Create: `client/lib/core/config/envalias.c`, `client/lib/core/config/envalias.h`
- Modify: `client/lib/auth/sss/sss_keytab.c:63-70`, `client/lib/auth/sec/sec_pwd.c` (both getenv sites + the error string at ~:144), `client/Makefile` (add the two new objects to the lib object list)
- Create: `client/man/brix-env.7`
- Test: `client/tests` unit (follow the existing client unit-test pattern — see `apps/fs/brixmount_unittest.c` / `make test` wiring) `client/lib/cli/cli_hint_unittest.c` or equivalent under the existing test harness; pty tests in `tests/test_cli_hints.py`

**Interfaces (produces, used by ALL later tasks):**

```c
/* cli_hint.h */
void brix_cli_hint(const char *fmt, ...) __attribute__((format(printf,1,2)));
void brix_cli_hint_once(const char *key, const char *fmt, ...)
    __attribute__((format(printf,2,3)));
int  brix_cli_hints_enabled(void);   /* isatty(2) && !BRIX_NO_HINTS */
/* envalias.h */
const char *brix_env_resolve(const char *const *chain, const char **which);
```

- [ ] **Step 1: `cli_hint.c`** — `brix_cli_hints_enabled()`: `isatty(STDERR_FILENO)` && (`BRIX_NO_HINTS` unset || `"0"`), computed once (static int, lazy). `brix_cli_hint`: if enabled, `vfprintf(stderr, …)` prefixed `"hint: "` iff fmt doesn't already start with a prefix word — implementation: print fmt verbatim; callers include their own `hint:`/`note:` prefix (keeps the helper dumb). `brix_cli_hint_once`: fixed table of ≤16 seen keys (static array of `const char *`, strcmp match). Sanitize: the helper does NOT sanitize; callers pass pre-sanitized strings — enforced by review + the security-neg tests.
- [ ] **Step 2: `envalias.c`** — per spec §WS-1 change 1.1: walk the chain; remember first-set (highest precedence) value+name; keep scanning to detect a second set-name with a DIFFERENT value; on divergence call `brix_cli_hint_once(chain[0], "note: both %s and %s are set and differ; using %s (see brix-env(7))\n", nameA, nameB, winner)`. Values are NOT printed (no secrets in terminal). Return winner.
- [ ] **Step 3: migrate the two sites** — `sss_keytab.c`: chain `{"XRDC_SSS_KEYTAB","XrdSecSSSKT","XrdSecsssKT",NULL}` replacing the two getenv calls. `sec_pwd.c`: chain `{"XRDC_PWD","XrdSecCREDS",NULL}` at BOTH `pwd_have()` and the loader; update the error string to `"pwd: no password (set XRDC_PWD or XrdSecCREDS)"` (unchanged text — verify). `XRDC_PWD_USER` stays raw getenv (no alias).
- [ ] **Step 4: `client/man/brix-env.7`** — the full env inventory table from spec §WS-1 (all `XRDC_*`, `XrdSec*`, `X509_*`, `AWS_*`, `KRB5CCNAME`, `BEARER_TOKEN`/`_FILE`, `TMPDIR`, `OIDC_ACCOUNT`, `XRDRC`, `XRDSTORASCAN_PASSWORD`, `BRIX_VMP`, `BRIXCVMFS_*`, `BRIX_NO_HINTS`), one `.TP` entry each: aliases, precedence, consumers, meaning, default.
- [ ] **Step 5: tests (triple)** — success: unit test for chain order/`which`/legacy-only/canonical-only + `brix_cli_hints_enabled` under pipe (0). error: pty test (`tests/test_cli_hints.py` via `cli_pty.run_pty`) — both SSS vars set differing ⇒ exactly one `note:` line; piped ⇒ zero. security-neg: env value with `\x1b]0;pwn\x07` — assert the note line (which prints NAMES only) contains no byte < 0x20.
- [ ] **Step 6: build + `make -C client test` + golden suite green; commit** — `feat(client): TTY-gated hint helper + env alias resolver (spec WS-1)`.

---

### Task 2 (P2): `--help`/`--version` everywhere + footers + wait41

**Files:**
- Create: `client/lib/core/version.h` (`#ifndef BRIX_CLIENT_VERSION` → `"dev"`; `const char *brix_client_version(void)` static-inline returning the macro)
- Modify: `client/Makefile` (append `-DBRIX_CLIENT_VERSION=\"$(BRIX_CLIENT_VERSION)\"` to ALL_CFLAGS when the make var is set)
- Modify: `client/lib/cli/cli_opts.c` — `brix_opts_parse_arg` gains: `--version` ⇒ print `"%s (BriX-Cache client) %s\n"` (basename of `argv[0]`, version) to stdout and `exit(0)`; `--help` returns a NEW code `2` ("caller must print its usage and exit 0") so each tool keeps its own usage text.
- Modify: every front-end in `client/apps/` (19 entry points incl. multi-call personalities): handle parse-code 2 → print usage to STDOUT, exit 0; tools NOT on the shared parser (`xrdprep`, `xrdgsiproxy`, `xrdsssadmin`, `xrdstorascan`, `brixMount`, `wait41`/`mpxstats`/`xrdqstats` mains inside xrddiag, cksum personalities) add explicit `--help`/`--version` as their FIRST checks.
- Modify: every usage text — append the spec §WS-2 footer verbatim (2 lines: `config: ~/.xrdrc …` / `docs: man <tool> …`).
- Modify: dispatcher tools (`xrdfs`, `xrd`, `xrddiag`, `xrdcksum`, `xrdstorascan`, `brixMount`) — accept `<subcommand> --help` (print that subcommand's usage block, exit 0) and ensure `help [subcommand]` works; `xrdfs` `COMMANDS[]` entries each gain a one-line usage string if missing.
- Test: extend `tests/test_cli_golden.py` with a help/version matrix.

- [ ] **Step 1** version.h + Makefile define.
- [ ] **Step 2** cli_opts.c: the two flags (note `exit(0)` inside the parser is acceptable for `--version` only; `--help` must return code 2 because usage text is per-tool).
- [ ] **Step 3** sweep the 19 entry points (mechanical; keep each tool's existing `-h` semantics untouched — `xrdfs ls -h` still humanize).
- [ ] **Step 4** footers on every usage string.
- [ ] **Step 5** tests (triple) — success: loop over all binaries `--help`/`--version` exit 0, stdout non-empty, version matches `^\S+ \(BriX-Cache client\) \S+$`. error: `xrdcp --help extra` behavior golden-pinned (whatever current-tool convention is, capture and assert). security-neg: version output regex forbids `/` (no paths) except in the tool name.
- [ ] **Step 6** golden suite green (baseline entries for no-arg invocations UNCHANGED — footers only appear in usage output, which no-arg tools print… **CAREFUL:** tools that print usage on no-args WILL change stderr → this is a DELIBERATE, user-visible improvement allowed by C1 (usage text is not a stable interface; exit codes/flags are). Re-capture baseline AFTER this task with a note in the commit message.) Commit — `feat(client): --help/--version + usage footers across the suite (spec WS-2)`.

---

### Task 3 (P3): double-slash hint + did-you-mean + doctor referral

**Files:**
- Modify: `client/lib/brix.h` — `brix_url` gains `unsigned single_slash_path:1;`
- Modify: `client/lib/net/url.c:89-94` — set the bit when the collapse branch does NOT fire and `path[0]=='/'` came from a single slash (i.e. `path[0]=='/' && path[1]!='/'` at entry).
- Modify: the shared failure printers (`lib/cli/cli_conn.c` + the `brix_ops.h:295` "credential hint" printer) — after a not-found-class failure (`kXR_NotFound`/ENOENT-mapped/HTTP 404) on a URL with the bit set: `brix_cli_hint_once("url-double-slash", "hint: XRootD URLs take a double slash before absolute paths —\n      try root://HOST//PATH (you wrote a single '/'); see man xrd, URLS.\n")`.
- Create: `client/lib/cli/suggest.c` + `suggest.h` — `const char *brix_suggest(const char *arg, const char *const *candidates)`: Damerau-Levenshtein ≤2, first-in-table tiebreak, returns NULL for no match; caps `arg` consideration at 64 bytes.
- Modify: unknown-command sites — `apps/fs/xrdfs.c:117-120`, `xrd` dispatch, `xrddiag` subcommand table, `xrdcksum` dispatch, `brixMount` type table: AFTER the existing error line, `if ((s = brix_suggest(tok, names))) brix_cli_hint("hint: did you mean '%s'?\n", s);` — existing line + exit code untouched.
- Modify: the exit-53 (auth-class) path in the shared printer — `brix_cli_hint_once("doctor", "hint: diagnose with: xrddiag check %s\n", sanitized_url)`; sanitize via the existing client-side control-byte escaper (add a 128-byte-capped local sanitizer in cli_hint.c if none exists in `lib/`).
- Test: `tests/test_cli_hints.py` additions.

- [ ] Steps: implement → tests (triple per spec §WS-3/§WS-7: pty hint fires once; pipe = golden-identical; escape-sequence URL/command sanitized) → build + suites → commit `feat(client): URL double-slash hint, did-you-mean, doctor referral (spec WS-3/WS-7)`.

---

### Task 4 (P4): long-flag aliases

**Files:**
- Modify per the spec §WS-4 table (verified `-P`=posc → `--posc`): `apps/copy/xrdcp.c` (`--verbose --debug --no-progress --posc`), `apps/fs/xrdfs_meta.c` (`--human` on ls/du/df; `--verbose` on rm; `--timestamp` on touch), `apps/fs/xrdfs_walk.c` (`--dirs-only`, `--depth` on tree), `apps/prep/xrdprep.c` (`--stage --cancel --wmode --fresh --evict --priority`), `apps/auth/xrdgsiproxy.c` (double-dash twins of `-valid -cert -key -out -bits -file`), `apps/auth/xrdsssadmin.c` (`--keytab`).
- Modify: each touched usage string shows `-x, --long-form`.
- Test: `tests/test_cli_aliases.py` — for each table row, run short vs long against the fleet (or `--help` parse where fleet-free) and assert identical behavior/output.

- [ ] Steps: implement (alias = extra strcmp beside the existing one, same assignment) → tests (triple: equivalence loop; unknown `--nonsense` keeps current error+code golden; value-taking aliases reject garbage identically to short) → build + suites → commit `feat(client): long-form flag aliases, short flags untouched (spec WS-4)`.

---

### Task 5 (P5): man pages + drift guard

**Files:**
- Create: `client/man/xrdcp.1`, `xrdfs.1`, `xrddiag.1`, `xrdcksum.1` (+ `.so` links `xrdcrc32c.1 xrdcrc64.1 xrdadler32.1 xrdckverify.1 xrdcinfo.1`), `xrdprep.1`, `xrdgsiproxy.1`, `xrdsssadmin.1`, `xrdstorascan.1`, `brixMount.1`
- Create: `client/man/check_man.sh` (drift guard: every `--[a-z-]+` token in `bin/<tool> --help` appears in the page; greps pages for `/home/` and fails)
- Modify: `client/Makefile` — `install-man` target; hook `check_man.sh` into `test:`
- Content rules: spec §WS-6 change 6.2 mandatory sections; EXIT CODES tables verbatim from spec §WS-8; URLS section (copy from `man/xrd.1:22-24` wording) wherever URLs are accepted.

- [ ] Steps: write pages (source of truth = each tool's `--help` after Task 4, plus spec §WS-8 exit tables) → guard → `man --warnings -l` lint clean → Makefile wiring → tests (triple: lint+guard green; guard self-check fails when a flag is removed from a page; `/home/`-grep negative) → commit `docs(client): man pages for the full tool suite + drift guard (spec WS-6)`.

---

### Task 6 (P6): shell completions + guard + install

**Files:**
- Create: `client/completions/bash/brix-client.bash` (all tools/subcommands/flags incl. the enum values from spec §WS-5 change 5.1)
- Create: `client/completions/zsh/_brix-client` (`#compdef` all tool names)
- Create: `client/completions/check_completions.sh` (flag-drift guard vs `--help` output; `--self-check` mode; fails on `eval`/backtick-on-current-word)
- Modify: `client/Makefile` — `install-completions` target (`$(PREFIX)/share/bash-completion/completions/`, `$(PREFIX)/share/zsh/site-functions/`); guard into `test:`

- [ ] Steps: write completions → guard → `bash -n`/`zsh -n` (zsh optional if not installed: guard skips with notice) → tests (triple per spec §WS-5) → commit `feat(client): bash+zsh completions with drift guard (spec WS-5)`.

---

### Task 7: Final sweep

- [ ] Full rebuild `make -C client clean && make -C client -j$(nproc)`; `make -C client test` green.
- [ ] Golden suite green against the post-Task-2 baseline; pty hint tests green.
- [ ] Spec conformance pass over §§WS-1..WS-8 acceptance criteria (the loops/greps listed there).
- [ ] Update `client/apps/README.md` with the compat contract pointer + alias table pointer (spec §13).
- [ ] Commit any sweep fixes — `fix(client): CLI usability final-sweep fixes`.
