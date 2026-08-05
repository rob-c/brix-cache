# Phase-2 GSI (X.509) Benchmark Rig

Phase-2 of the brix-cache conformance benchmark (Phase-1 = no-auth): custom-CA GSI (X.509 proxy) auth, with a BriX GSI gateway fronting a GSI XRootD origin. All working as of 2026-08-04.

## PKI

Pre-generated at `/tmp/xrd-test/pki`:

- CA `CN=Test XRootD CA` — `ca.pem` / `ca.key`
- Host cert `CN=localhost` + SAN(127.0.0.1) — `server/hostcert.pem`, `server/hostkey.pem`
- User cert `/DC=test/DC=xrootd/CN=Test User/CN=12345` — `user/usercert.pem`, `user/userkey.pem`
- Proxies add a numeric CN.
- CRL hash = `03628dcb`.

## Trust dir

`X509_CERT_DIR` = `/tmp/xrd-test/certdir` — built by hand:

- `<hash>.0` → `ca.pem`
- `<hash>.signing_policy` → signing-policy
- `<hash>.r0` → CRL

Clients and servers point `X509_CERT_DIR` here.

## Ports (all localhost)

- GSI origin xrootd `:21195` — cfg `configs/xrootd-origin-gsi.cfg`, localroot `/tmp/brixbench/origin-gsi`, run as `-R nobody`.
- GSI BriX gateway `:21196` — cfg `configs/nginx-brix-gsi.conf`, staged → origin, export `/tmp/brixbench/gwdata-gsi`.
- No-auth rig from Phase-1 stays up: origin `:21095`, BriX `:21094`.
- Do NOT touch the system xrootd-brix cluster (`:11094`, pids 75666-75671).

## BriX GSI config surface

This is the `root://` stream plane — NOT the webdav directives.

Client-facing GSI server:
- `brix_auth gsi;`
- `brix_certificate <host.pem>`
- `brix_certificate_key <hostkey.pem>`
- `brix_trusted_ca <certdir>`
- `brix_crl <certdir>`
- `brix_crl_mode try|off|require`
- (DN→uid mapping would be `brix_gridmap` + `brix_impersonation map`, not used here — GSI auth alone doesn't need it.)

BriX→origin GSI client:
- `brix_storage_backend root://127.0.0.1:21195;`
- `brix_storage_credential origin;`
- a **stream-context** `brix_credential origin { x509_proxy <proxy.pem>; ca_dir <certdir>; }` block.
- Worker runs as `user nginx` → cert/key/proxy must be nginx-readable (copies in `/tmp/xrd-test/brix-creds`, key `0600` nginx-owned).

## Client env for all drivers

- `X509_USER_PROXY=/tmp/xrd-test/x509up` (combined proxy PEM)
- `X509_CERT_DIR=/tmp/xrd-test/certdir`

Generate the proxy with:

```
voms-proxy-init -rfc -cert <usercert> -key <userkey> -out x509up
```

The key must be `0600` and owned by the running user — copy to a root-owned tmp key first. go-hep, XrdRust, PyXRootD, xrdcp/xrdfs all honor this env; XrdRust GSI is transparent via `Config::from_env()`.

## Gotchas (each cost real time)

1. **BriX→origin needs a PROXY, not a bare host cert.** `x509_cert`+`x509_key` (1 cert) → origin rejects `"wrong number of certificates (received:1, expected:>=2)"`. Must supply a delegated proxy chain via `x509_proxy` (voms-proxy-init from the host cert → 2 certs).

2. **`-gmapopt` semantics.** Origin `sec.protocol ... gsi -gmapopt:2` = REQUIRE a grid-mapfile match (fails if DN absent); `-gmapopt:1` = use gridmap if matched, else fall back to DN-as-name. Use `:1` so BriX's host-proxy DN (not necessarily in the gridmap) still authenticates while the user DN still maps to `testuser`. **`-vomsfun:off` is a BUG** — it's parsed as a plugin path `"off"` and fails init; just OMIT vomsfun to disable VOMS.

3. **The pre-generated CRL revokes the test user.** `test-user.crl.pem` REVOKES the test user's exact serial (EEC serial `6E8E67D5…1AF53A`) — it's a revocation-test artifact. For the positive benchmark, generate a fresh empty CRL (`openssl ca -gencrl` with an empty index.txt) and install as `<hash>.r0`; keep the revocation CRL for a negative test. BriX caches the CRL — a SIGHUP does NOT refresh it, needs a full restart.

   **Correction / rigorous result** (see the BriX-vs-stock CRL/proxy revocation finding): the first pass claimed "stock `-crl:1` accepts the revoked cert" — that was a **CRL-dir MISCONFIGURATION**, not a stock defect. XRootD GSI loads CRLs from a **separate `-crldir:` param** (debug: `Secgsi CRL dir:`) that DEFAULTS to `/etc/grid-security/certificates/`, NOT from `-certdir:`. The revoking CRL was only in `-certdir`, so stock never loaded it. After adding `-crldir:/tmp/xrd-test/certdir-revoked -crl:3` (require), stock's own `-d:2` debug shows it DID load the CRL (`cryptossl_LoadCache: 1 certificates have been revoked`) — but then `crypto_X509Chain::EECname/EEChash: EEC not found in chain` and it authenticated the revoked user anyway (`login as testuser`). The SAME revoked proxy + SAME CRL is REJECTED by openssl (`-crl_check` → err 23 "certificate revoked") AND by BriX (`brix_crl_mode require` → "GSI client cert rejected: certificate revoked"). So the confirmed finding is narrow and mechanism-pinned: **stock v5.9.6 fails to apply a loaded EEC revocation to a delegated proxy chain; BriX + openssl reject it.** The blunt "stock ignores CRLs" claim is FALSE — do not repeat it.

4. **Origin won't restart if stale admin sockets remain.** `-R nobody` xrootd fails silently (launch exit != 0, empty log) when `/tmp/brixbench/admin-gsi/.xrd` etc. from a prior run persist, or when the log dir isn't writable by nobody (`-k fifo` needs to create `.<log>` fifo). Fix: `rm -rf` admin-gsi/run-gsi and recreate nobody-owned; log dir nobody-writable (chmod 1777 or nobody-owned).

5. **xrootd refuses to run as root** (`"Security reasons prohibit running as superuser"`) — always launch with `-R nobody` (and chown localroot/admin/run/log to nobody).

## Result

Full GSI chain works — client(proxy) → BriX:21196 → origin:21195 write/read/stat OK.

**Phase-2 GSI matrix COMPLETE** (`compare.py results/gsi`): **PASS 68 · FAIL 0 · N/A 1.**

- py 18/18 == 18/18
- go 17/17 == 17/17 (go-hep GSI OK via the streaming-write fix)
- rust 17/17 BriX vs 16/17 official — the one `brix-only` = checksum: stock origin returned `kXR_wait` for async checksum computation and XrdRust's 300s retry cap tripped (`limit exceeded: server asked this client to wait past its 300s cap`); BriX returns checksums synchronously → **behavioral difference, NOT a stock defect**.
- cli 16/17 == 16/17 and brixcli 16/17 == 16/17 (both miss only `vector_read` = no CLI primitive, identical).

The ONLY rigorous "BriX stricter/more-correct than stock" finding is the proxy-EEC CRL revocation one above; the checksum and the Phase-1 secblock/mkdir items are NOT stock defects (checksum = timing; secblock + mkdir were BriX bugs, now fixed).

## vector_read gap CLOSED (2026-08-04)

The lone matrix `N/A` was `vector_read` on the CLI clients — stock `xrdcp`/`xrdfs` v5.9.6 ship NO scatter/gather primitive. But the BriX client already has one: `brix-xrdfs readv <path> <off len>...` (kXR_readv 3025, `client/apps/fs/xrdfs_data_xfer_vec.c` → `brix_file_readv`). Only the harness hard-coded "unsupported".

Fixed in `brixbench/`: `bench_brixcli.sh` now runs a real 3-segment `readv` with det() byte-verify; `bench_cli.sh` message corrected (stock CLI truly lacks it); `compare.py` CLIENTS now includes `brixcli`.

Result on the no-auth rig (both server types): **PASS 85 · FAIL 0 · N/A 1** — vector_read PASS for py/go/rust/**brixcli** vs both stock origin :21095 and BriX gateway :21094; only the stock CLI stays N/A. GSI spot-check: `brix-xrdfs readv` byte-identical from stock GSI origin :21195 AND BriX GSI gateway :21196 (auth transparent). Doc: `docs/09-developer-guide/vector-read-cli-conformance.md`. All harness-only changes (no server/client C touched).

## Uncommitted state

As of this session: the 3 Phase-1 conformance fixes (secblock, streaming write + substreams knob, mkdir idempotency) + tests. No git-write approval given.
