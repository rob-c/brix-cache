# kernel-TLS (kTLS) — `brix_ktls`

`brix_ktls on|off` opts a brix TLS context into **kernel-TLS** (OpenSSL
`SSL_OP_ENABLE_KTLS`): the kernel encrypts TLS records in place, so HTTPS
downloads `sendfile(2)` zero-copy over the encrypted socket and uploads decrypt
in-kernel — cutting the userspace `SSL_write`/`memmove` crypto that otherwise
dominates the TLS data path (~95% of on-CPU work in a `https://` flame graph).

## Scope & default

One unified directive across every TLS surface:

| plane | context | reads `common.ktls` / `tls_ktls` |
|---|---|---|
| `root://` / `roots://` | `stream { server { … } }` | `ngx_stream_brix_srv_conf_t.tls_ktls` |
| WebDAV `https://`/`davs://` | `http { server { … } }` | webdav `common.ktls` |
| S3 `https://` | `http { server { … } }` | (enabled via the shared webdav server-level conf) |

**Default: ON.** `SSL_OP_ENABLE_KTLS` is a *transparent no-op* when the
negotiated cipher or the running kernel cannot offload — OpenSSL falls back to
userspace TLS with byte-identical results. On the HTTP plane the flag is read
from the **server-level** webdav conf, so it applies to every `listen … ssl`
brix server (WebDAV and S3) unless overridden.

Disable per server: `brix_ktls off;`

## When it helps vs hurts

- **Helps:** HW TLS-offload NICs (crypto runs on the NIC), or copy-bound bulk
  transfer (eliminates the file→userspace copy that TLS otherwise forces).
- **Can hurt:** software-only kTLS on AES-NI CPUs — kernel AES-GCM is not always
  faster than OpenSSL's, and you lose OpenSSL's write batching. Measure, and set
  `brix_ktls off` where it regresses.

kTLS is enabled at config time (a NOTICE is logged per SSL context); actual
engagement is decided by OpenSSL/kernel **per connection**.

## Verifying engagement

kTLS TX/RX sessions are counted in `/proc/net/tls_stat`:

```bash
before=$(awk '/^TlsTxSw/{print $2}' /proc/net/tls_stat)
curl -sk --tls13-ciphers TLS_AES_128_GCM_SHA256 https://host:PORT/file -o /dev/null
after=$(awk '/^TlsTxSw/{print $2}' /proc/net/tls_stat)
echo "kTLS TX sessions: $((after-before))"   # >0 == engaged (software kTLS)
```

`TlsTxSw`/`TlsRxSw` count software-kTLS sessions; `TlsTxDevice`/`TlsRxDevice`
count HW-offloaded ones. Requires `CONFIG_TLS` (`modprobe tls`).

## Requirements & known limits

- OpenSSL 3.0+ built with kTLS (`ktls_meth.c` present in libssl), nginx ≥ 1.21.4,
  kernel `tls` ULP (`CONFIG_TLS=m`, loaded).
- Zero-copy HTTPS `SSL_sendfile()` additionally needs nginx built with
  `SSL_sendfile` support (`NGX_HAVE_OPENSSL_SSL_SENDFILE`); without it, kTLS
  still offloads record crypto on `SSL_write`, just not the file copy.
- **WSL2 (6.18.6-WSL2) kTLS TX is broken** — enabling kernel `SSL_sendfile`
  there aborts encrypted GETs mid-transfer. `brix_ktls` stays safe (it only sets
  the OpenSSL option; OpenSSL falls back to userspace, transfers succeed), but
  kTLS will not *engage* on that kernel. Verify on a mainline kernel.
