# Client CLI usability hardening — backwards-compatible UX spec

**Date:** 2026-07-06
**Status:** draft — pending Rob's review
**Scope:** the CLI tools under `client/apps/` and the shared option/env
machinery under `client/lib/` (notably `lib/cli/cli_opts.c`,
`lib/core/config/xrdrc.c`, `lib/auth/*`, `lib/net/url.c`), plus `client/man/`,
a new `client/completions/`, and `client/Makefile` install targets.
**Source review:** conversation review of 2026-07-06 (two repo surveys:
per-tool CLI surface + cross-tool inconsistency hunt).

---

## 1. Goals and non-goals

**Goal.** Make the BriX client tools materially easier to use — discoverable
help, predictable environment variables, actionable errors, completions and
man pages — while guaranteeing that **no existing script, flag, environment
variable, output format, or exit code changes behavior**.

**Non-goals (explicitly out of scope):**
- Changing any exit-code VALUE (documented instead — §WS-8).
- Changing URL parse semantics (`lib/net/url.c` behavior is frozen; we add a
  hint, not a new grammar — §WS-3).
- Renaming, removing, or repurposing any existing flag or env var.
- New features unrelated to usability (no new transfer modes, auth methods).
- The server side and `shared/` — this spec is `client/` only.

---

## 2. The compatibility contract (normative)

Every workstream below MUST obey all five rules. A change that cannot obey
them is out of scope for this spec.

- **C1 — No renames.** Existing flags, env vars, subcommands, positional
  syntax, config paths, and exit codes keep their exact current meaning.
  New spellings are strictly additive aliases.
- **C2 — Legacy env vars live forever.** Every legacy name (`XrdSec*`,
  mixed-case variants) remains accepted. New canonical names are additions
  with documented precedence (§WS-1); nothing is deprecated-and-removed.
- **C3 — Non-TTY output is byte-identical.** All new hints, warnings,
  notices, and suggestions are emitted ONLY when `isatty(STDERR_FILENO)` is
  true AND `BRIX_NO_HINTS` is unset/`0`. When stderr is redirected (every
  script, every cron job, every pipeline), output is unchanged from today.
  This is enforced by golden-output tests (§12).
- **C4 — stdout is sacred.** No new output ever goes to stdout. Hints go to
  stderr (TTY-gated per C3); `--help`/`--version` go to stdout only when
  explicitly requested.
- **C5 — Exit codes are frozen.** New failure paths reuse the tool's
  existing convention. `--help`/`--version` exit 0. Unknown-option handling
  keeps each tool's current code (50 where that is the convention).

**Shared enforcement helper (new).** One tiny module,
`client/lib/cli/cli_hint.c` + `cli_hint.h`:

```c
/* Emit a one-line usability hint to stderr, only on an interactive stderr
 * and only when BRIX_NO_HINTS is unset or "0". printf-style. Never touches
 * stdout, never changes exit codes. */
void brix_cli_hint(const char *fmt, ...) __attribute__((format(printf,1,2)));
/* Same gate, but at most once per (process, key) — for repeated-loop sites. */
void brix_cli_hint_once(const char *key, const char *fmt, ...)
    __attribute__((format(printf,2,3)));
```

All hint text in this spec goes through these two functions — there is
exactly one place to audit the C3 gate. `BRIX_NO_HINTS=1` is the documented
opt-out (and belongs in the env-var table of §WS-1).

---

## 3. WS-1 — Environment variables: one resolver, aliases, precedence

**Problem.** `XrdSecSSSKT` vs `XrdSecsssKT` differ only by case
(`lib/auth/sss/sss_keytab.c:66-70`); `XRDC_PWD` vs `XrdSecCREDS` have
undocumented precedence (`lib/auth/sec/sec_pwd.c:47,144`); prefixes are
mixed (`XRDC_*`, `XrdSec*`, standard `X509_*`/`AWS_*`/`KRB5CCNAME`/
`BEARER_TOKEN*`, tool-specific `XRDSTORASCAN_PASSWORD`, `OIDC_ACCOUNT`,
`XRDRC`, `BRIX_VMP`, `BRIXCVMFS_*`). Setting a near-miss name fails
silently.

**Change 1.1 — shared resolver.** New `client/lib/core/config/envalias.c`
+ `envalias.h`:

```c
/* Resolve the FIRST set variable in a NULL-terminated alias chain.
 * Returns the value and (via out param) which name matched, or NULL.
 * If two or more names in the chain are set to DIFFERENT values, emits
 * brix_cli_hint_once(chain[0],
 *   "note: both %s and %s are set and differ; using %s (see brix-env(7))")
 * and still returns the highest-precedence one. */
const char *brix_env_resolve(const char *const *chain, const char **which);
```

Precedence within a chain is array order: canonical name first, legacy
names after, most-legacy last.

**Change 1.2 — alias chains (normative table).** All lookups below migrate
from raw `getenv()` to `brix_env_resolve()` with these chains. Column 1 is
the canonical (documented-first) name; every other column entry remains
accepted forever (C2).

| Concept | Chain (highest precedence first) | Today's lookup site |
|---|---|---|
| SSS keytab path | `XRDC_SSS_KEYTAB`, `XrdSecSSSKT`, `XrdSecsssKT` | `lib/auth/sss/sss_keytab.c:66-70` |
| Password credential | `XRDC_PWD`, `XrdSecCREDS` | `lib/auth/sec/sec_pwd.c:47` |
| Password user | `XRDC_PWD_USER` (no legacy alias) | `lib/auth/sec/sec_pwd.c` |
| Bearer token | `BEARER_TOKEN` (standard; no alias added) | xrdcp/xrdfs/xrddiag/xrootdfs |
| Bearer token file | `BEARER_TOKEN_FILE` (standard; no alias) | `lib/auth/cred/` |
| Dashboard password | `XRDSTORASCAN_PASSWORD` (kept; no alias) | `apps/scan/xrdstorascan.c:821` |
| Hint suppression | `BRIX_NO_HINTS` (new) | `lib/cli/cli_hint.c` |

Rules for the table: standard third-party names (`X509_*`, `AWS_*`,
`KRB5CCNAME`, `BEARER_TOKEN*`, `TMPDIR`, `OIDC_ACCOUNT`) get NO new
aliases — they are ecosystem conventions, not ours to fork. `XRDC_*`
tuning vars (`XRDC_MAX_STALL_MS`, `XRDC_IO_URING`, `XRDC_IO_URING_LOOP`,
`XRDC_NO_IPV6_FALLBACK`, `XRDC_BACKOFF_BASE_MS`, `XRDC_GSI_VERSION`,
`XRDC_GSI_DELEGATE`) are already canonical — they enter the documentation
table but gain no aliases. Only the two genuinely-confusing chains (SSS
keytab, password credential) gain a canonical `XRDC_*` spelling.

**Change 1.3 — divergence warning.** Exactly the `brix_env_resolve`
behavior above: when ≥2 chain members are set with different values, one
TTY-gated note naming both variables and the winner. Same values set twice
⇒ silent.

**Change 1.4 — the environment man page.** New `client/man/brix-env.7`
listing EVERY variable the client stack reads (the full inventory from the
2026-07-06 survey, §WS-1 problem statement), one row each: name, aliases,
precedence, consumer tools, meaning, default. Every tool's man page and
`--help` footer references it (§WS-2).

**Acceptance criteria.**
- `XrdSecsssKT=…` alone still selects the keytab (regression: legacy-only
  environment behaves identically).
- `XRDC_SSS_KEYTAB` alone works; both set + different + TTY stderr ⇒ one
  note line; both set + non-TTY ⇒ zero extra output, canonical wins.
- `grep -rn 'getenv("XrdSec' client/lib client/apps` shows only
  `envalias.c` chain definitions (single point of truth).

**Tests (per CLAUDE.md rule: success + error + security-negative).**
- success: unit test `client/tests` (or `tests/`) — chain resolution order,
  `which` out-param, legacy-only, canonical-only.
- error: divergence note fires exactly once per key on a fake TTY (pty
  harness), never on a pipe.
- security-neg: chain values containing control bytes are passed through
  untouched to consumers but the NOTE line sanitizes them via
  `brix_sanitize_log_string`-equivalent before printing (no terminal escape
  injection through env var names/values).

---

## 4. WS-2 — `--help`, `--version`, and usage footers, everywhere

**Problem.** `xrdcp` supports `-h` but its long form is undocumented;
`wait41` has no help at all (`apps/diag/wait41.c:40`); only `xrdcp` has a
version flag and it is `-V`; `~/.xrdrc` appears in zero help texts;
`xrdfs ls -h` humanizes rather than helps (see WS-4 for the alias answer).

**Change 2.1 — shared handling.** Extend `lib/cli/cli_opts.c`
(`brix_opts_parse_arg`) to recognize `--help` and `--version` for every
tool that already routes args through it; tools not on the shared parser
(`wait41`, `mpxstats`, `xrdqstats` personalities, `brixMount`,
`xrdsssadmin`, `xrdgsiproxy`, `xrdprep`, `xrdstorascan`) add the two flags
in their own arg loop, FIRST, before any other parsing.

- `--help` ⇒ print the tool's existing usage text to stdout, exit 0.
  Existing `-h` behavior is untouched wherever it exists today — including
  the `xrdfs ls/du/df` humanize meaning (C1).
- `--version` ⇒ one line to stdout, exit 0, format:
  `"<argv0-basename> (BriX-Cache client) <version>"`, where `<version>`
  comes from one new constant in `client/lib/core/version.h`
  (`BRIX_CLIENT_VERSION`), populated from the existing release/versioning
  source at build time (`-DBRIX_CLIENT_VERSION=…` in `client/Makefile`;
  fallback literal `"dev"`). `xrdcp -V` remains a synonym.
- multi-call personalities report their personality name in `<argv0>`
  (e.g. `xrdadler32 (BriX-Cache client) 1.2.0`).

**Change 2.2 — usage footer.** Every usage text gains the same final two
lines (exact wording):

```
config: ~/.xrdrc defines endpoint aliases and credentials (see brix-env(7))
docs:   man <tool>   ·   exit codes are listed at the end of the man page
```

**Change 2.3 — subcommand help.** Dispatcher tools (`xrdfs`, `xrd`,
`xrddiag`, `xrdcksum`, `xrdstorascan`, `brixMount`) accept
`<tool> help [subcommand]` AND `<tool> <subcommand> --help`, both printing
the subcommand's usage block. `xrdfs` already has `help`; the requirement
is the `--help`-after-subcommand form and per-subcommand usage strings for
every entry in its `COMMANDS[]` table (one line minimum: synopsis +
flag list).

**Change 2.4 — `wait41`.** Gains `-h`/`--help`/`--version` only. Flags
`--timeout`/`--full` unchanged.

**Acceptance criteria.**
- `for t in xrd xrdfs xrdcp xrdcksum xrdprep xrdgsiproxy xrdgsitest \
   xrdsssadmin xrdmapc xrddiag xrdstorascan wait41 mpxstats xrdqstats \
   xrdcrc32c xrdcrc64 xrdadler32 xrdckverify xrdcinfo; do bin/$t --help
   >/dev/null && bin/$t --version >/dev/null; done` — all exit 0.
- `xrdfs ls -h <url>` still humanizes (golden test).
- `xrdcp -V` output unchanged in meaning; `--version` matches format above.

**Tests.** success: the loop above as a shell test (`tests/` or
`client/tests/run_cli_help.sh`). error: `--help` with trailing garbage
(`xrdcp --help extra`) still exits 0 and ignores the rest (or 50 if that is
the tool's existing behavior — pick per tool by CURRENT behavior, never
change it; golden-test it). security-neg: `--version` output contains no
build paths, hostnames, or user names (assert format with a regex).

---

## 5. WS-3 — The double-slash URL hint

**Problem.** `root://host//path` is required; the parser collapses `//`→`/`
(`lib/net/url.c:89-94`), so `root://host/path` yields a different path than
users expect and the failure surfaces as a bare not-found. Documented only
in `man/xrd.1:22-24` and the `xrdcp` usage header.

**Change 3.1 — detection, not reparsing.** `lib/net/url.c` records one new
bit on the parsed-URL struct: `single_slash_path` = the original text had
exactly one `/` between authority and path (i.e. the collapse branch did
NOT fire and the path is non-empty). No parse result changes (C1).

**Change 3.2 — the hint.** At the shared error-reporting site used by the
tools (the `brix_shellcode`/status-print path in `lib/`, plus `xrdfs`'s
command-status printer), when ALL of: operation failed with
not-found/does-not-exist class (kXR_NotFound, ENOENT-mapped, HTTP 404), the
URL had `single_slash_path`, TTY+hints enabled (C3) — emit exactly:

```
hint: XRootD URLs take a double slash before absolute paths —
      try root://HOST//PATH (you wrote a single '/'); see man xrd, URLS.
```

(one call to `brix_cli_hint_once("url-double-slash", …)`, per process).

**Change 3.3 — documentation.** A `URLS` section (same text as `xrd.1`)
added to every new man page (WS-7) and to the `xrdcp`/`xrdfs` usage
headers if not already present.

**Explicit non-change.** Accepting single-slash-as-absolute is NOT in this
spec. Follow-up investigation may compare stock-client grammar; until then
the grammar is frozen.

**Tests.** success: `xrdcp root://host/onlyoneslash .` against the test
fleet on a pty ⇒ hint appears once, exit code unchanged. error: same
command with stderr piped ⇒ byte-identical stderr to today (golden).
security-neg: URL with embedded control chars/escape sequences in the path
⇒ hint prints the sanitized form only.

---

## 6. WS-4 — Long-form flag aliases (short flags untouched)

**Problem.** `-d` = debug in `xrdcp` (`apps/copy/xrdcp.c:379`) but
dirs-only in `xrdfs tree` (`apps/fs/xrdfs_walk.c:281`); `-h` = humanize in
`xrdfs ls/du/df` (`apps/fs/xrdfs_meta.c:162,437`) but help elsewhere;
`-t` = timestamp in `xrdfs touch` (`apps/fs/xrdfs_meta.c:487`).

**Change 4.1 — aliases (normative table).** Add the long form beside each
existing short form; short forms keep their exact current meaning per tool:

| Tool / subcommand | Existing | New alias |
|---|---|---|
| `xrdcp` | `-v` / `-d` | `--verbose` / `--debug` |
| `xrdfs ls`, `du`, `df` | `-h` | `--human` |
| `xrdfs tree` | `-d` | `--dirs-only` |
| `xrdfs tree` | `-L` | `--depth <n>` |
| `xrdfs rm` | `-v` | `--verbose` |
| `xrdfs touch` | `-t` | `--timestamp <t>` |
| `xrdcp` | `-N` | `--no-progress` |
| `xrdcp` | `-P` | (already has long? if not) `--posc` |
| `xrdprep` | `-s/-c/-w/-f/-e` | `--stage/--cancel/--wmode/--fresh/--evict` |
| `xrdprep` | `-p <n>` | `--priority <n>` |
| `xrdgsiproxy init` | `-valid H[:M]` | `--valid H[:M]` (single-dash kept) |
| `xrdgsiproxy` | `-cert/-key/-out/-bits/-file` | `--cert/--key/--out/--bits/--file` |
| `xrdsssadmin` | `-k` | `--keytab <path>` |

(Implementation note: `xrdgsiproxy` uses single-dash long options today —
keep them AND accept the double-dash spellings; both listed in help.)

**Change 4.2 — help text shows both** (`-d, --dirs-only` style), so the
discoverable spelling is unambiguous even where short letters collide
across tools.

**Tests.** success: each alias drives the same code path as its short form
(one assertion per row of the table — a loop test comparing outputs).
error: unknown long flag still produces the tool's current
unknown-option behavior and exit code (golden). security-neg:
`--timestamp` and other value-taking aliases reject embedded NUL /
non-numeric garbage exactly as the short form does today.

---

## 7. WS-5 — Shell completions

**Problem.** None exist anywhere in the repo.

**Change 5.1 — bash.** New `client/completions/bash/brix-client.bash`
providing completions for: `xrd` (all subcommands from its dispatch table),
`xrdfs` (host arg then subcommands then per-subcommand flags), `xrdcp`
(flags incl. value enums: `--auth gsi|ztn|krb5|sss|unix`,
`--cksum adler32|crc32c|md5`, `--compress gzip|deflate|zstd|br|xz|bzip2`,
`--tpc first|only|delegate`, `--sync-check size|mtime|cksum`), `xrddiag`
(subcommands + flags), `xrdcksum` personalities, `xrdprep`, `xrdgsiproxy`,
`xrdsssadmin`, `xrdstorascan`, `brixMount` (types
`cvmfs|cvmfs-rw|eos|root|roots`, `--overlay-list`, `--overlay-reset`),
`xrootdfs` (flag set from its usage table).

**Change 5.2 — zsh.** `client/completions/zsh/_brix-client` with the same
coverage (zsh `_arguments` style; one file, `#compdef` line listing all
tool names).

**Change 5.3 — source of truth + drift guard.** Flag lists in completions
are generated or checked from the tools themselves: a script
`client/completions/check_completions.sh` runs each `bin/<tool> --help`,
extracts `--[a-z-]+` tokens, and fails if the completion file is missing
any (allowlist for intentionally hidden flags). Wired into `make test` in
`client/Makefile` alongside the existing client tests.

**Change 5.4 — install.** `client/Makefile` gains
`install-completions` (respecting `DESTDIR`/`PREFIX`:
`$(PREFIX)/share/bash-completion/completions/`,
`$(PREFIX)/share/zsh/site-functions/`); `packaging/` (rpm/deb specs, if
present for the client) lists the new files.

**Tests.** success: `check_completions.sh` green; `bash -n` / `zsh -n`
parse checks. error: deliberately remove a flag from the completion file ⇒
guard fails (self-test mode `--self-check`). security-neg: completion
functions never `eval` user input; guard greps the files for `eval`/
backtick substitution on the current word and fails if present.

---

## 8. WS-6 — Man pages

**Problem.** Only `client/man/xrd.1` and `client/man/xrootdfs.1` exist; no
pages for `xrdcp`, `xrdfs`, `xrddiag`, the checksum family, or the rest.

**Change 6.1 — new pages (hand-written, usage-text-faithful):**

| Page | Covers |
|---|---|
| `client/man/xrdcp.1` | all flags from the usage table, URLS section, env vars it reads, exit codes, `~/.xrdrc` aliases, progress-bar TTY behavior (WS-8) |
| `client/man/xrdfs.1` | connection flags, full subcommand table (one paragraph each), interactive-shell section (incl. the root://-only rule, WS-8), URLS, exit codes |
| `client/man/xrddiag.1` | all subcommands, the cause→remedy philosophy, exit codes |
| `client/man/xrdcksum.1` | the multi-call design; `.so`-style link pages `xrdcrc32c.1`, `xrdcrc64.1`, `xrdadler32.1`, `xrdckverify.1`, `xrdcinfo.1` |
| `client/man/xrdprep.1`, `xrdgsiproxy.1`, `xrdsssadmin.1`, `xrdstorascan.1`, `brixMount.1` | per tool |
| `client/man/brix-env.7` | the WS-1 environment table |

**Change 6.2 — mandatory sections per page:** NAME, SYNOPSIS, DESCRIPTION,
OPTIONS (both spellings per WS-4), URLS (where URLs are accepted),
ENVIRONMENT (only vars that tool reads, referencing brix-env(7)),
EXIT CODES (the tool's exact current values, WS-8 table), FILES
(`~/.xrdrc`), SEE ALSO.

**Change 6.3 — install + guard.** `client/Makefile` `install-man` target;
a `check_man.sh` drift guard: every flag token in `--help` output appears
in the page (same mechanism as WS-5's guard).

**Tests.** success: `man --warnings -l client/man/*.1` clean (groff lint);
drift guard green. error: guard self-check. security-neg: N/A beyond lint
(no executable content) — document that pages contain no absolute
build-host paths (guard greps for `/home/`).

---

## 9. WS-7 — Did-you-mean and cross-tool referrals

**Change 7.1 — did-you-mean.** New helper
`client/lib/cli/suggest.c`: `const char *brix_suggest(const char *arg,
const char *const *candidates)` — Damerau-Levenshtein distance ≤ 2,
ties broken by first-in-table. Wired into: `xrdfs` unknown command
(`apps/fs/xrdfs.c:117-120`), `xrd` unknown subcommand, `xrddiag` unknown
subcommand, `xrdcksum` unknown personality/subcommand, `brixMount` unknown
type. The suggestion line is TTY-gated (C3); the existing
`"<tool>: unknown command '%s'"` line and exit code print exactly as today
in ALL cases (the suggestion is an ADDITIONAL line after it):

```
xrdfs: unknown command 'staat'
hint: did you mean 'stat'?
```

**Change 7.2 — doctor referral.** When `xrdcp`/`xrdfs` exit through the
`brix_shellcode` path with an auth-class failure (the codes that map to
exit 53), emit (TTY-gated, once):

```
hint: diagnose with: xrddiag check <URL-you-used>
```

The URL is reprinted after `brix_sanitize_log_string`-equivalent
sanitization.

**Tests.** success: `xrdfs HOST staat` on a pty shows the hint;
`xrd verzion` suggests `version`. error: non-TTY ⇒ stderr golden-identical
to today; distance-3 typos produce NO suggestion. security-neg: a
command name of escape sequences/1KB garbage is sanitized and truncated in
the echo (suggest.c caps candidate echo at 64 bytes).

---

## 10. WS-8 — Documentation of existing behavior (no code change)

- **Exit codes.** Each man page's EXIT CODES section documents the tool's
  CURRENT values, verbatim from the 2026-07-06 survey: the 0/50/51/53
  `brix_shellcode` convention (incl. the honest note that several kXR
  classes share 53); `xrdckverify` 0/1/2/3; `xrdstorascan` 0/1/2/3/64;
  `xrd` 127-on-exec-failure; mount tools' 2. No values change (C5).
- **Progress bar.** `xrdcp.1` + usage text: progress renders automatically
  on a TTY, `--progress` forces it on, `-N`/`--no-progress` forces it off;
  redirected stderr gets no bar.
- **xrdfs shell scope.** `xrdfs.1` + usage: interactive shell is
  `root://`-only; on `http(s)/dav(s)` endpoints with no command, print the
  existing usage PLUS (TTY-gated) `note: the interactive shell requires a
  root:// endpoint; web endpoints run one-shot commands only.` — today's
  silent degrade becomes explained, output unchanged for scripts.
- **`~/.xrdrc`.** Documented in WS-2's footer, every man page FILES
  section, and brix-env(7) (the `XRDRC` override var).

---

## 11. Delivery phases (each independently shippable)

| Phase | Contents | Size |
|---|---|---|
| P1 | C-contract helpers (`cli_hint.c`), WS-1 env resolver + chains + brix-env(7) | S |
| P2 | WS-2 help/version/footers (incl. wait41), WS-8 doc text in usage strings | S |
| P3 | WS-3 URL hint, WS-7 did-you-mean + doctor referral | M |
| P4 | WS-4 long-flag aliases | M |
| P5 | WS-6 man pages + drift guard | M |
| P6 | WS-5 completions + drift guard + install targets | M |

Ordering rationale: P1 provides the primitives every later phase uses; P2
is the highest-visibility/lowest-risk win; P3–P4 touch parsing paths and
need the golden-output harness from P1's test work; P5–P6 are mechanical
once flags are final (P4 before P5/P6 so pages/completions are written
once).

## 12. Test strategy (cross-cutting)

- **Golden non-TTY harness (new, P1):** `tests/test_cli_golden.py` runs a
  fixed matrix of commands against the test fleet with stderr/stdout piped,
  and asserts byte-identical output before/after each phase (C3/C4
  enforcement). The baseline is captured on main BEFORE P1 merges.
- **PTY harness:** a small `tests/cli_pty.py` helper (pseudo-terminal
  runner) for every hint test.
- **Per-change 3-test rule** (CLAUDE.md): each WS section above names its
  success / error / security-negative tests; they land in the same commit
  as the change.
- **Drift guards** (WS-5/WS-6) run in `make test` so completions and man
  pages cannot rot silently.

## 13. Documentation deliverables recap

`client/man/`: 10 new/updated pages incl. `brix-env.7` · usage footers on
every tool · URLS sections · `client/completions/{bash,zsh}` · README
updates in `client/apps/README.md` (flag-alias table pointer) — plus the
compat contract (§2) copied into `client/README` or `client/apps/README.md`
as the standing rule for future flag work.

## 14. Open questions (resolve at plan time, defaults stated)

1. `BRIX_CLIENT_VERSION` source — default: a literal in
   `client/lib/core/version.h` bumped manually, overridable via make var.
2. `xrdcp -P` long alias — verify current meaning in source before naming
   it `--posc`; if `-P` is progress-related instead, alias accordingly
   (the table row is provisional; the rule "alias matches the REAL meaning"
   is normative).
3. Whether `mpxstats`/`xrdqstats` personalities take `--help` themselves or
   defer to `xrddiag help <name>` — default: both.
