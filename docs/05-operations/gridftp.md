# brix as a GridFTP (gsiftp://) gateway

**Status: source-verified 2026-07-17.** The executable form of the verb
surface, GSI transfers, and MODE E parallel streams is
`tests/test_gridftp_verbs.py`, `tests/test_gridftp_gsiftp.py`,
`tests/test_gridftp_mode_e.py`, and `tests/test_gridftp_evil.py`
(configs: `tests/configs/nginx_gridftp_plain.conf`,
`tests/configs/nginx_gridftp_gsiftp.conf`). The container-tier interop matrix
against the reference Globus client lives in
`k8s-tests/remote-suite/tests/test_gridftp_interop.py`
(chart `k8s-tests/charts/gridftp-interop`).

Design record and the framing gotchas behind MODE E:
[docs/refactor/phase-82-gridftp-gateway.md](../refactor/phase-82-gridftp-gateway.md).

---

## 1. What this is

brix speaks the GridFTP dialect of FTP (RFC 959 + RFC 2228 GSI security + RFC
3659 metadata verbs + GFD.020 extended-block MODE E) as an nginx **stream**
module, so `globus-url-copy`, `gfal-copy`, and FTS can push and pull data
through brix the same way they talk to a dCache or StoRM door.

The gateway is a compact synchronous door: one blocking worker per control
connection, transfers run inline. It exports a **posix tree** — `brix_gridftp`
does not (yet) route through `brix_storage_backend`, so pblock/s3/Ceph backends
are not served over gsiftp today (see §6).

---

## 2. Minimal cleartext gateway

For an anonymous, unencrypted door (test rigs, trusted networks):

```nginx
stream {
    server {
        listen 2810;
        brix_gridftp on;
        brix_gridftp_export      /data/xrootd;
        brix_gridftp_allow_write on;
    }
}
```

Drive it with any FTP client:

```console
$ python3 -c "import ftplib; f=ftplib.FTP(); f.connect('host',2810); f.login(); \
              print(f.retrlines('LIST'))"
```

`brix_gridftp_allow_write off` (the default) makes the door read-only: STOR,
APPE, DELE, MKD, RNFR/RNTO all return `550 Permission denied (read-only)`.

---

## 3. GSI-secured gsiftp:// gateway

The production form: an RFC 2228 GSI control channel authenticated by an X.509
(proxy) certificate.

```nginx
stream {
    server {
        listen 2811;
        brix_gridftp on;
        brix_gridftp_export      /data/xrootd;
        brix_gridftp_allow_write on;
        brix_gridftp_gsi         on;
        brix_gridftp_certificate     /etc/grid-security/hostcert.pem;
        brix_gridftp_certificate_key /etc/grid-security/hostkey.pem;
        brix_gridftp_trusted_ca      /etc/grid-security/certificates;   # CApath dir or CAfile bundle
    }
}
```

Transfer with the reference client:

```console
$ voms-proxy-init -voms cms
$ globus-url-copy file:///tmp/big.root gsiftp://host:2811/big.root      # PUT
$ globus-url-copy gsiftp://host:2811/big.root file:///tmp/back.root     # GET
```

**Data-channel protection** is per-transfer and client-driven:

| globus-url-copy flag | FTP `PROT` | brix data channel |
|---|---|---|
| `-nodcau` | C (clear) | raw socket |
| `-dcsafe` | S (integrity) | TLS |
| `-dcpriv` | P (private) | TLS |

The peer DN on a PROT P/S data leg is pinned to the control-channel DN
(accepting a trailing `/CN=` proxy RDN — GSI delegation), so a third party
cannot splice into a data connection whose port it guessed.

---

## 4. MODE E parallel streams

globus negotiates parallelism after login:

```console
$ globus-url-copy -p 4 -dcpriv file:///tmp/big.root gsiftp://host:2811/big.root
```

`-p N` puts the transfer into **MODE E** (GFD.020 extended block): the sender
opens N data connections at once and addresses every block by file offset, so
blocks arrive out of order and are reassembled by offset. brix caps the honoured
stream count at 64 and reassembles with per-block `pwrite`, committed-range
overlap rejection, and offset/overflow guards (the security boundary — see §5).

Progress markers are emitted inline on the control channel: `112 Perf Marker`
(bytes moved) and `111 Range Marker` (contiguous committed ranges).

Framing gotcha worth knowing when reading logs or a packet capture: globus folds
the EOF and EOD flags into one block on the last stream (`desc=0x48`), and the
**total EOD count rides in the OFFSET field, not the count field**. That block
carries no payload.

---

## 5. Hardening / what the gateway refuses

Exercised by `tests/test_gridftp_mode_e.py` and `tests/test_gridftp_evil.py`:

- **MODE E offset attacks** — a block overlapping an already-committed range, or
  an `offset+count` that overflows the signed 64-bit file offset, fails the
  transfer (`550`) instead of corrupting the file. The overflow is caught at the
  block header, before any `pwrite`.
- **Short-framed block** — a block whose payload is shorter than its declared
  count fails; there is no partial commit.
- **Over-long command line** — a control line larger than the 128 KiB read
  buffer is refused and the connection dropped (no unbounded buffering).
- **Passive listener reclaim** — each PASV/EPSV closes the previous listener
  before opening the next, so repeated PASV cannot leak descriptors.
- **REST beyond EOF** — a restart offset past end-of-file clamps to the start
  rather than reading out of bounds.
- **FTP bounce** — on a cleartext (no-DCAU-A) session, an active-mode `PORT` to
  any IP other than the control peer is refused (`500`). Only a
  GSI-authenticated DCAU A leg (gsiftp↔gsiftp TPC) may target a third party.

Known gap: `brix_gridftp` does not gate file verbs behind FTP login (the
`authed` flag is tracked but not enforced). This is benign on the anonymous
cleartext door; on a GSI door the control channel is only usable after the GSSAPI
handshake, so the effective gate is the security layer, not the login verb.

---

## 6. Backends and limits

- **posix only.** `brix_gridftp_export` is a real filesystem tree; there is no
  `brix_storage_backend` hook on the gateway yet, so pblock/s3/Ceph are not
  served over gsiftp. The interop matrix marks those rows `xfail` until the hook
  lands.
- **Synchronous door.** Transfers run inline on the worker; there is no async
  ABOR of an in-flight transfer (ABOR simply drops a pending passive listener).
- **TPC.** gsiftp↔gsiftp third-party copy between two brix doors is supported
  (DCAU A); see the phase-82 record.

---

## 7. Container-tier interop lab

`k8s-tests/charts/gridftp-interop` brings up a gateway serving one posix export
on both a GSI (`2811`) and a cleartext (`2810`) listener. The client image
(`k8s-tests/Dockerfiles/gridftp-client`) ships `globus-url-copy`, `gfal-copy`,
and `voms-clients`. Point the driver at the release:

```console
$ TEST_GRIDFTP_HOST=<gateway-svc> \
  TEST_GRIDFTP_GSIFTP_PORT=2811 TEST_GRIDFTP_FTP_PORT=2810 \
  X509_USER_PROXY=/tmp/x509up \
  pytest k8s-tests/remote-suite/tests/test_gridftp_interop.py -v
```

It runs `{PROT C,P} × {MODE S,E}` over gsiftp, `{active,passive}` over the
cleartext leg, a second-client `gfal-copy` round-trip, and an FTS-style bulk
batch — each asserting a byte-identical round-trip.
