# Valgrind memory-safety harness

Runs the production nginx-xrootd binary under **Valgrind Memcheck** while
exercising the external-handle code paths (GSI/TLS x509, bearer JWT, macaroon,
libcurl TPC, S3 SigV4), then reports any leak / uninitialised-read / invalid
access / leaked fd in **module** frames.

On this WSL2 host Valgrind is the correct leak tool — LeakSanitizer's at-exit
reporting does not fire for nginx here (see `docs/07-security/valgrind-findings.md`).
Two real defects were found this way: an uninitialised `addr_text` read in
`src/dashboard/http_tracking.c` and a JWKS `EVP_PKEY` reload leak in
`src/auth/token/jwks.c`.

## Files

| File | Purpose |
|---|---|
| `nginx.conf.in` | Self-contained config template (GSI/TLS + token + macaroon + TPC + S3), `master_process on` + 1 worker so TLS actually serves. Derived from `tests/configs/nginx_shared.conf` + `nginx_webdav_tpc.conf`. |
| `run_valgrind.sh` | Renders the template, launches valgrind (`--trace-children`, per-pid logs), drives the request mix, shuts down gracefully, triages the logs. |
| `valgrind.supp` | Native-format suppressions for benign nginx-core/library residuals only. Never suppresses module frames. |

## Prerequisites

The test PKI + token fixtures must already exist (the harness does not regenerate
certs/JWKS). Create them once with any pytest session or:

```bash
tests/manage_test_servers.sh start-all
```

## Running

The Bash sandbox on this host blocks foreground `sleep` and kills
`&`-backgrounded long-lived processes when the calling tool returns, so launch
the script **fully detached** and poll its marker file from a separate shell
call:

```bash
setsid bash tests/valgrind/run_valgrind.sh </dev/null >/dev/null 2>&1 & disown
# … later, in a separate invocation:
grep -E "FINISHED|MODULE-FRAME" /tmp/xrd-vg/results.txt
cat /tmp/xrd-vg/results.txt
```

Outputs land under `$VG_WORK` (default `/tmp/xrd-vg`):

- `results.txt` — request HTTP codes, per-log leak counts, and the
  **MODULE-FRAME HITS** section (must read `(none)` for a clean run).
- `logs/vg.<pid>.log` — one Memcheck report per process; the worker pid's log is
  the interesting one (it handled the requests).

### Triage

A clean run shows `(none)` under *MODULE-FRAME HITS*. Any hit in an
`xrootd_*` / `ngx_http_xrootd_*` / `src/<module>/` frame is a real finding —
investigate and fix in source. Benign nginx-core/library residuals
(`ngx_set_environment`, libc thread-local, epoll/log fds held at exit) are
expected and either suppressed in `valgrind.supp` or excluded by the triage grep.

## Environment overrides

`NGINX_BIN`, `TEST_ROOT`, `PKI_DIR`, `TOKEN_DIR`, `VG_WORK`, and the port vars
(`GSI_TLS_PORT` 28444, `HTTP_PORT` 28080, `S3_PORT` 29051, `METRICS_PORT` 29100)
can all be overridden. Ports default to a dedicated 127.0.0.1 high range so the
harness can run alongside the managed fleet without conflicts.

## Fleet-wide mode

For the most faithful coverage (real generated configs, all planes), run the
whole managed fleet under valgrind via `VALGRIND=1`:

```bash
VALGRIND=1 tests/manage_test_servers.sh restart
# drive tests, then stop; reports land in $TEST_ROOT/valgrind/vg.<pid>.log
```
