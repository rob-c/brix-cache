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

The gateway runs on the non-blocking nginx **stream** event engine — the control
dialogue, the GSI handshake, and MODE E data channels all drive off the event
loop, not a blocking worker-per-connection. Like `root://`, WebDAV and S3, it
terminates on the shared `brix_vfs_*` storage seam, so the same export can be a
plain **posix tree** *or* any other storage backend — `brix_gridftp_storage_backend`
selects `posix` (default), `pblock`, `s3://…` or Ceph, and every transfer is
served transparently through the VFS (see §6). Because all four front-ends share
one VFS namespace, a byte written over gsiftp is byte-identical when read back
over root/WebDAV/S3 and vice versa: gsiftp is a fully-fledged bidirectional
protocol, usable both as a front-end (ingress) and as the egress translation of a
namespace another protocol wrote.

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

- **Any storage backend.** `brix_gridftp_storage_backend` selects what the export
  is backed by: `posix` (default, a real filesystem tree rooted at
  `brix_gridftp_export`), `pblock` (block store; needs the SQLite build), `s3://…`
  (an object store, keys carried by `brix_gridftp_storage_credential`), or Ceph.
  STOR/RETR/LIST/CKSM travel `brix_vfs_*` → the storage driver, so the object-store
  path uses the same staged-write-then-verify writer as WebDAV/S3. `s3` and
  `pblock` are covered by `test_gridftp_s3.py` / `test_gridftp_pblock.py`.
- **Cross-protocol translation.** The gsiftp namespace is the *same* VFS export
  root/WebDAV/S3 serve, so bytes cross-translate between all four protocols
  byte-for-byte — write over gsiftp, read over WebDAV (and the reverse), proven in
  both directions by `test_gridftp_translation.py`.
- **Async ABOR.** There is no async ABOR of an in-flight transfer (ABOR simply
  drops a pending passive listener).
- **TPC.** gsiftp↔gsiftp third-party copy between two brix doors is supported
  (DCAU A); see the phase-82 record.

---

## 7. Observability

The gateway is **in the shared metrics zone** like every other plane. The zone is
process-wide, so a single `brix_metrics on;` location in `http {}` exports the
gsiftp door even though the door itself only ever runs inside `stream {}` — no
extra directive, no per-listener wiring:

```nginx
http {
    server {
        listen 8080;
        location /metrics { brix_metrics on; }
    }
}
```

Everything the gateway books carries `proto="gridftp"`, drawn from the same
frozen label vocabulary as `stream`, `webdav`, `s3` and `cvmfs`
(see [metrics-overview.md](../08-metrics-monitoring/metrics-overview.md#unified-protocol-labeled-metrics)):

| What you see | Where it comes from |
|---|---|
| `brix_io_ops_total{proto="gridftp",op="read"\|"write",status=…}` | RETR / STOR / APPE at transfer completion, plus transfers refused before a data channel ever opened |
| `brix_io_ops_total{proto="gridftp",op="stat"\|"mkdir"\|"delete"\|"rename"\|"dirlist",…}` | the VFS observer — SIZE/MDTM/MLST, MKD, DELE/RMD, RNFR+RNTO, LIST/NLST/MLSD are metered inside `brix_vfs_*`, never a second time by the protocol |
| `brix_io_bytes_read{proto="gridftp"}` / `brix_io_bytes_written{proto="gridftp"}` | payload bytes per transfer, MODE E committed blocks included |
| `brix_io_latency_seconds_bucket{proto="gridftp",op=…,le=…}` | measured from the verb, so it includes the PASV accept or active connect, not just the byte pump |
| `brix_auth_total{proto="gridftp",method="gsi"\|"none",status="ok"\|"fail"}` | the ADAT/GSSAPI handshake terminals, and `none` for a cleartext login |

Useful queries:

```promql
# gsiftp throughput next to every other plane
sum by (proto) (rate(brix_io_bytes_read[1m]))

# is the GSI door rejecting proxies?
rate(brix_auth_total{proto="gridftp",method="gsi",status="fail"}[5m])

# refusals (bounce guard, MODE E overlap, denied LIST) vs. real errors
sum by (status) (rate(brix_io_ops_total{proto="gridftp"}[5m]))
```

Two behaviours worth knowing before you alert on this:

- **A refused transfer books an op row with no latency sample.** Nothing ran, so
  filing a 0 µs duration would drag the lowest bucket down; the counter moves,
  the histogram does not.
- **The gateway does not register dashboard live-transfer slots.** The JSON
  dashboard's per-transfer table shows root/WebDAV/S3/cvmfs transfers; gsiftp
  transfers are visible in Prometheus but not (yet) as live rows there.

---

## 8. Container-tier interop lab

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

### 8.1 Running the matrix locally (no k8s cluster)

The same matrix runs against a locally-booted gateway under **rootless podman**,
so a cluster is not required to exercise the reference-client interop:

```console
# once — build the grid-client image (needs network for the EL9 grid RPMs):
$ cd tests && python3 -m cmdscripts.gridftp_interop_local build-image
# boot a combined gsiftp+ftp gateway locally and drive the matrix in-container:
$ python3 -m cmdscripts.gridftp_interop_local run
# inspect the exact podman invocation without building/booting anything:
$ python3 -m cmdscripts.gridftp_interop_local run --dry-run
```

The runner boots `tests/configs/nginx_gridftp_interop.conf` (the chart's
two-listeners-over-one-export topology), mounts the local test PKI proxy + CA
dir into the image, points `TEST_GRIDFTP_*` at the host gateway via
`--network=host`, and tears the gateway down on exit. Any missing prerequisite
(podman, image, nginx build, PKI) self-skips (exit `77`). The image/runner/matrix
contract is held by `tools/ci/check_gridftp_interop_image.py`.
