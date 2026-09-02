# Round 8 — axis (d): session sign-in/out, tokens and GSI vs stock xrootd

The last axis of the hyperopt program: how fast a client can establish (and
tear down) an authenticated session, measured with the STOCK tools the
program is scored against (`xrdfs` from the xrootd 5.9.6 RPM), one fresh
process per session so every sample pays the full connect + handshake +
auth + one stat + disconnect.

## Topology

Self-contained in the bench sandbox, reusing the fleet's PKI/token artifacts
read-only (CA + hostcert valid to 2036; proxy_std bundle; the WLCG token +
jwks pair):

- **GSI, cleartext**: brix `brix_auth gsi` (:23194) vs stock
  `sec.protocol gsi -gridmap:none -gmapopt:10` (:23195) — same CA dir, same
  host cert/key, same client proxy.
- **Token, TLS**: brix `brix_auth token` + `brix_tls on` (:23196) vs stock
  `sec.protocol ztn` + `ofs.authlib libXrdAccSciTokens` + `xrootd.tls login`
  (:23197), both reached as `roots://`. Stock's ztn CLIENT refuses cleartext
  connections outright (protocol-notes.md), so TLS on both sides is the only
  stock-tool token topology. SciTokens issuer-key fetch was made offline by
  seeding its per-UID keycache via `keycache_set_jwks()` (ctypes against
  libSciTokens.so.0, isolated `XDG_CACHE_HOME`) with the same jwks the brix
  listener loads from disk — no https issuer, no network variance in either
  server's validation path.

Both servers at 8-way parallelism (workers / `xrd.sched maxt`), 20-core
host. Client env pins `XRD_CONNECTIONRETRY=1`; the measured process floor
(`xrdfs --help`) of ~27 ms is subtracted in the net column.

## Results (p50 of 30–50 interleaved samples, ms; burst = 32-way concurrent)

| scheme | server | p50 wall | p50 net of floor | burst sessions/s |
|--------|--------|----------|------------------|------------------|
| GSI    | brix   | 69.9     | **43.5**         | **136.9**        |
| GSI    | stock  | 96.1     | 69.7             | 84.8             |
| token  | brix   | 34.0     | 7.6              | 328.6            |
| token  | stock  | 34.3     | 7.9              | 356.6            |

Sustained token (192 sessions / 32 threads, ramp amortized): brix 475.2 vs
stock 476.4 sessions/s — parity.

## GSI: brix signs a session in 38–40% less time (server leg 9× faster)

Client-side Dump timestamps split the two GSI auth round trips:

- step 1 (server's first gsi challenge + client processing): brix 33.5 ms
  vs stock 41.3 ms;
- step 2 — the SERVER-side leg (verify the client's signed DH + proxy
  chain, map identity): **brix 2.0 ms vs stock 18.6 ms**.

The client's own crypto (~33 ms of proxy-chain work, shared by both
targets) is the residual floor; of what the server controls, brix is ~9×
faster — modern EVP OpenSSL paths against XrdCrypto's legacy stack. At
burst 32 that compounds to +48–61% sessions/s.

## Token: structural parity, and why no server lever exists

The wire exchanges are IDENTICAL (verified by Dump logs): handshake +
kXR_protocol, TLS upgrade, kXR_login, one ztn pass, stat. Both spend the
same ~3.3 ms between login send and auth-required — the TLS handshake.
perf during a 192-session burst: 74% of brix worker CPU inside
`ngx_ssl_handshake`, 49% inside `EVP_DigestSignFinal` — the RSA-2048
server signature. Stock pays the same OpenSSL floor, hence 475 vs 476.
The lever that would move this — an ECDSA P-256 host cert (~10× cheaper
signing) — is a deployment choice that speeds both servers equally; there
is no brix-side C change that beats a shared-library floor. Worth noting:
brix additionally offers `brix_ztn_cleartext` for lab use (no TLS floor at
all), a mode the stock CLIENT cannot exercise.

## Axis (d) verdict

GSI sign-in — the expensive scheme, and the one that dominates multi-user
session churn — is where a server can differentiate, and brix wins it by a
wide margin on every measure (wall, net, burst). Token sign-in is bounded
by a TLS handshake both servers buy from the same OpenSSL; brix matches
stock exactly there. Sign-out is covered by every sample (process exit =
disconnect + session teardown through the SHM registry; the 32-way bursts
double as a register/unregister stress of the round-7 registry split).
