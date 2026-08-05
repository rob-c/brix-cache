# GSI Delegation alice→bob Full Command Matrix

**2026-08-04.** Demonstrated and origin-log-verified end-to-end GSI (X.509) credential **delegation** for the WHOLE client command surface: end user **alice** (X.509 proxy) → BriX server running as unix **bob** → OFFICIAL xrootd v5.9.6 origin, with the origin authenticating **every** op as alice (never bob).

## The decisive architecture point — two different "BriX-in-front-of-XRootD" modes

- **Staged storage-backend gateway** (`brix_storage_backend root://origin` + `brix_credential origin { x509_proxy hostproxy.pem }`, e.g. the benchmark `nginx-brix-gsi.conf` :21196): BriX terminates the client GSI, stages locally, and talks to the origin as a **FIXED host proxy** = bob. Origin sees **bob, NEVER alice**. This is NOT delegation. (Ref: the Phase-2 GSI benchmark rig, gotcha #1.)

- **Tap / MITM reverse proxy** (`brix_tap_proxy on` + `brix_tap_proxy_auth gsi` + `brix_tpc_delegate on` + `brix_gsi_signed_dh require`): BriX **captures the client's delegated proxy** and logs into the upstream **AS the user**, then byte-relays. Origin sees **alice** for every relayed op. This IS delegation — the mode the user wanted. Built on the F6 delegation-capture fixes (DER→PEM proxy req, AKID/SKID-tolerant check_issued): see `docs/09-developer-guide/gsi-delegation-capture-investigation.md` and `docs/09-developer-guide/gsi-delegation-capture-fix-walkthrough.md`.

## Client requirement

Delegation-send is opt-in and lives in the **repo C client** (`client/bin/xrdcp`, `client/bin/xrdfs`), gated on env **`XRDC_GSI_DELEGATE=1`** (`client/lib/auth/sec/sec_gsi.c:344`, shared by xrdcp + xrdfs so metadata ops delegate too). Stock `/usr/bin/xrdcp` only delegates for `--tpc delegate`, not plain ops. Since the tap relays post-login traffic, ALL ops (data + metadata) execute at the origin under alice with just the one client env var.

## Rig (reusable)

`/root/dev/brixbench/gsi_deleg_alice_bob.sh`.

- Origin :21197 — xrootd `-R nobody`, gridmap: alice EEC DN → alice, host DN `CN=localhost` → bob, `-gmapopt:2 -crl:0`.
- Tap proxy :21198 — nginx `user bob;`, `load_module ngx_stream_module.so` FIRST then the brix module.
- PKI = `tests/pki_helpers.blitz_test_pki()` (CA + keyUsage EEC + RFC `proxy_std.pem` = alice).

## Result: 20/20 checks PASS

- 7 DATA (write/read small+large byte-exact, vector_read)
- 13 META (stat / exists / ls / mkdir / rename / truncate / chmod / cksum / locate / statvfs / query / rm / rmdir)
- origin log = **18 login-as-alice, 0 login-as-bob**
- tap logs 18 `"captured delegated proxy dn=.../CN=12345/CN=12346"`.

**Negative control** (same client + proxy, env UNSET): client declines (rc=53), tap has no proxy to forward, origin login count stays 18 → proves the alice logins are the delegated identity, not the client's own connection.

## Setup gotchas (cost time)

1. Origin runs `-R nobody` so it needs a **nobody-readable** host key copy (blitz key is `0400 root` → errno 13).
2. Give the origin a **clean certdir** (CA `<hash>.0` + signing_policy only) — the blitz `ca/` dir also holds `ca.key` / a revoking `test-user.crl.pem` which trip `"unable to generate ca cert hash list"` / false revocation.
3. nginx `user bob;` needs a bob-readable host key copy too.
4. Created unix users alice(977) + bob(976) via `useradd -r`.

See also `docs/09-developer-guide/root-launch-privilege-hardening.md` and `docs/09-developer-guide/impersonation-map-gridmap-root-test-gap.md`.

All harness-only; no server/client C changed; no git-write.
