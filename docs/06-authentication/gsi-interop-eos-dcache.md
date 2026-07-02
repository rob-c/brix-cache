# GSI Interoperability with Real XRootD Servers (EOS, dCache, stock XRootD)

> **What this is.** A record of the GSI handshake work that made the native
> client and the gnuBall server interoperate with production XRootD storage
> — verified live against **EOS** (`eoslhcb.cern.ch`, modern stock `XrdSecgsi`,
> `v:10600`) and **dCache** (`lhcbdcache-kit.gridka.de`, Java `xrootd4j`,
> `v:10400`, `sha1:md5`) using an LHCb VOMS proxy — plus the regression guards
> that keep it working and the xcache/TPC fronting scenarios.
>
> Companion deep-dive: [`../10-reference/comparison/xrootd-implementations.md`](../10-reference/comparison/xrootd-implementations.md).
> Guard tests: `tests/test_gsi_interop_guards.py`, `tests/c/gsi_interop_test.c`.

---

## 1. The interop landmines (and the fixes)

The GSI *shape* is identical everywhere (two rounds, typed buckets terminated by
`kXRS_none`, DH key agreement, AES-CBC session cipher keyed from the first N
bytes of the DH secret, RSA proof-of-possession). The breakage was always in the
byte-level details, each fixed and now guarded:

| # | Symptom | Root cause | Fix |
|---|---------|-----------|-----|
| 1 | `TLS verify failed: unable to get local issuer certificate` | client loaded only the system CA bundle, not the grid IGTF CAs | CA-dir resolver: `--ca-dir` → `$X509_CERT_DIR` → `/etc/grid-security/certificates` → system (`client/lib/conn.c`) |
| 2 | dCache NPE `StringBucket.getContent() … digestBucket is null` | client never emitted the `kXRS_md_alg` bucket | always emit `kXRS_md_alg` (`client/lib/sec/sec_gsi.c`) |
| 3 | `all sender digests are unsupported: [sha256]` | hardcoded `sha256`; dCache offers only `sha1:md5` | negotiate the digest from the server's offered list (prefer `sha256`, else its first token) |
| 4 | `Could not decrypt encrypted client message` (dCache) | IV prepended but the `cipher_alg` was bare; dCache reads `ivlen=0` and mis-aligns | advertise the IV length via the `kXRS_cipher_alg` **`name#ivlen`** suffix when `use_iv` |
| 5 | `readerIndex exceeds writerIndex` (dCache parse overrun) | encrypted bucket list lacked the terminator | append the `kXRS_none` terminator to the inner buffer |

### The IV rule (the subtle one)
Stock XRootD/EOS set `useIV` from the **negotiated version** (`RemVers >= 10400`
⇒ IV on), and the `name#ivlen` suffix only conveys the IV **length**. dCache
learns the IV is present **only** from that suffix. So the IV-present bit and the
suffix must travel together:

- **bare cipher name + prepended IV** → EOS tolerates it (version-gated), **dCache
  fails to decrypt**.
- **suffix + IV** (the fix) → **both** accept it.

This is why an "IV-less" shortcut once passed EOS but silently broke dCache.

### Server side
The nginx server's signed-DH path hardcodes `use_iv=1` (sound: signed-DH ⇒
`v>=10400` ⇒ stock `useIV=true`) and its cipher-name parser strips the `#ivlen`
suffix, so it interoperates with IV-advertising stock/EOS clients
(`src/auth/gsi/parse_x509.c`, `src/auth/gsi/parse_crypto_helpers.c`).

---

## 2. Using the module as an xcache in front of EOS/dCache

The read-through cache fetches a **GSI origin** by fork/exec'ing the native
client (`cache_origin_client`, default `xrdcp`; `src/fs/cache/fetch.c`,
`writethrough_flush.c`) — the built-in origin client only does anonymous login,
which EOS/dCache reject. **Therefore the xcache origin GSI path is exactly the
native-client path** and inherits all five fixes above.

**Status: fully verified.** `test_xcache_origin_fetch_live` runs the literal
`xrdcp -f <origin> <part>` the cache executes against **both** EOS and dCache and
checks the result against the origin's own `adler32`. ✅ both pass.

Config sketch:

```nginx
xrootd_cache on;
xrootd_cache_origin root://eoslhcb.cern.ch;       # or the dCache endpoint
# xrootd_cache_origin_client /path/to/xrdcp;       # default: xrdcp
# the fork/exec inherits $X509_USER_PROXY / $X509_CERT_DIR
```

---

## 3. TPC with EOS/dCache as origin

TPC uses a **separate, in-process** outbound GSI implementation
(`src/tpc/gsi_outbound_*.c`) — distinct from the native client and able to
regress independently. It is the plain-DH (`kXRS_puk`, `use_iv=0`) dialect.

- **Verified (EOS-class):** the module's outbound path performs a native TPC pull
  from a real GSI source (**stock XRootD v5.9.5**) into a local nginx dest —
  `tests/test_tpc_gsi_outbound.py::test_tpc_pull_over_gsi`. ✅
- **dCache-correctness added:** the outbound round-2 now also emits
  `kXRS_cipher_alg` (bare `aes-128-cbc`) and `kXRS_md_alg` (digest chosen from the
  server's offer) — the dCache NPE trigger — without regressing the stock path
  (the EOS-class test still passes after the change).

### Operational note (not a code defect)
A client-orchestrated TPC pull **from production EOS/dCache to a private
localhost destination** is rejected at the source open
(`Invalid request; user not authenticated`). That is the **site's TPC
authorization policy** (WLCG TPC expects delegated credentials / registered
endpoints), independent of our GSI handshake (which works for plain reads). Full
live confirmation of TPC-from-dCache therefore needs a TPC-authorized
destination; the guard test is gated on `TEST_TPC_DEST_ENDPOINT`.

---

## 4. Verified matrix

| Path | GSI implementation | EOS | dCache |
|---|---|---|---|
| native client read | `client/lib/sec/sec_gsi.c` | ✅ live | ✅ live |
| **xcache origin** | execs native `xrdcp` (`src/fs/cache/fetch.c`) | ✅ live (fetch + integrity) | ✅ live (fetch + integrity) |
| **TPC outbound** | `src/tpc/gsi_outbound_*.c` | ✅ live (stock-XRootD-class) | ✅ dialect correct (md_alg/cipher_alg) — live needs a TPC-authorized dest |

---

## 5. Regression guards — `tests/test_gsi_interop_guards.py`

Five tiers, from always-on to opt-in, so the framework cannot silently stop
supporting these servers:

1. **`gsi_core` wire invariants** (CI-safe C unit test, `tests/c/gsi_interop_test.c`):
   the IV is load-bearing (a `use_iv=1` ciphertext must NOT decrypt as `use_iv=0`),
   the cipher allowlist stays closed and `aes-128-cbc`-first, the `kXRS_none`
   terminator is emitted.
2. **client ↔ our own server** GSI handshake + read (behavioral; skips w/o fleet).
3. **live native client → EOS/dCache** — force GSI, then list (opt-in via
   `TEST_GSI_ENDPOINTS` / `TEST_EOS_ENDPOINT`).
4. **wire-contract tripwires** for the facts only a strict peer (dCache) rejects:
   the `kXRS_md_alg` bucket, the `#ivlen` suffix, the inner terminator, the CA-dir
   grid fallback, and the server's IV handling.
5. **xcache + TPC origin guards:** xcache execs the native client; TPC outbound
   reuses the shared `gsi_core` and emits `kXRS_cipher_alg`/`kXRS_md_alg`; plus a
   live xcache origin-fetch (with integrity) and a (dest-gated) live TPC pull,
   parameterized over the same endpoints.

Run:

```bash
# CI-safe tiers
PYTHONPATH=tests pytest tests/test_gsi_interop_guards.py -v

# live tiers against real servers (with a valid proxy)
TEST_GSI_ENDPOINTS="root://eoslhcb.cern.ch=/eos/lhcb/,root://lhcbdcache-kit.gridka.de:1094=/pnfs/gridka.de/lhcb/LHCb-Disk/ETFTest/" \
  X509_USER_PROXY=/tmp/x509up_u$(id -u) \
  PYTHONPATH=tests pytest tests/test_gsi_interop_guards.py -k "live or xcache" -v

# local TPC outbound (module dest pulls from a stock GSI source)
PYTHONPATH=tests pytest tests/test_tpc_gsi_outbound.py -v
```

Latest run: GSI guard suite **10 passed, 2 skipped** (the dest-gated TPC live
tests); local TPC outbound **1 passed**.
