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
        brix_export      /data/xrootd;
        brix_allow_write on;
    }
}
```

Drive it with any FTP client:

```console
$ python3 -c "import ftplib; f=ftplib.FTP(); f.connect('host',2810); f.login(); \
              print(f.retrlines('LIST'))"
```

`brix_allow_write off` (the default) makes the door read-only: STOR,
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
        brix_export      /data/xrootd;
        brix_allow_write on;
        brix_gridftp_gsi         on;
        brix_certificate     /etc/grid-security/hostcert.pem;
        brix_certificate_key /etc/grid-security/hostkey.pem;
        brix_trusted_ca      /etc/grid-security/certificates;   # CApath dir or CAfile bundle
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
  `brix_export`), `pblock` (block store; needs the SQLite build), `s3://…`
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

---

## 9. The other direction — a remote GridFTP door as a storage backend

Everything above is brix as a **door**: a client speaks gsiftp to brix. brix
also speaks gsiftp **outbound**, as a client of somebody else's door, so a
`root://`/WebDAV/S3 export can be backed by storage that only exposes GridFTP:

```nginx
brix_storage_backend gsiftp://grid.example.org/store mode=e prot=p streams=4;
```

The driver (`src/fs/backend/gsiftp/`) is the read/write path of a normal
storage backend — `sd_gsiftp_pread` issues a **bounded** read per operation,
and writes are staged locally and published by one whole-file `STOR` plus a
rename. Three store-line parameters shape the data channel; all are documented
in
[directives.md](../03-configuration/directives.md#brix_storage_backend-ftpgsiftp--outbound-ftpgridftp-origin).

| Parameter | Effect | Refusal |
|---|---|---|
| `mode=e` | negotiates GFD.020 extended block mode on the data channel | origin answers `504` → the transfer fails |
| `prot=p` | RFC 2228 `PBSZ`/`PROT` TLS on the data channel, peer leaf DN pinned to the control identity | origin answers `534` → the transfer fails; `ftp://` + `prot=p` is refused at `nginx -t` |
| `streams=<n>` | ceiling on the data connections one read may open with GFD.020 §5.1 `SPAS` striping (`1`–`16`, default `1`); needs `mode=e` | any refusal → the same bytes over one connection |

Four properties are worth knowing before you read a packet capture:

- **The first two parameters do not degrade; the third is meant to.** An
  operator who asked for an offset-addressed channel, or for a protected one,
  and silently got stream mode or cleartext would have neither the property nor
  a way to notice. Both are requirements. `streams=` is different in kind: it
  says how *fast* the same, identically framed, identically verified bytes
  arrive, so every way of not striping still serves the file over the single
  connection.
- **`prot=p` needs an authenticated control channel.** The value of PROT P here
  is the *pin* — the data peer's leaf DN must match the identity the control
  channel already authenticated. An anonymous `ftp://` origin authenticates
  nobody, so there is nothing to pin against and the combination is rejected at
  configuration time rather than served encrypted-to-whoever-answered.
- **`ERET` is automatic, and only under `mode=e`.** A ranged read of a MODE E
  origin sends `ERET P <offset> <length> <path>` instead of `REST`+`RETR`, so
  the origin stops at the end of the window instead of streaming to EOF behind
  a driver that has already stopped reading. The capability comes from a lazy
  `FEAT` probe (issued from the retrieve path only, once per session), so there
  is nothing to configure and nothing to turn on. It is not sent in stream
  mode on purpose: a door that ignores the window and replies with the file
  from offset 0 sends genuine bytes that are simply the wrong part, and only
  MODE E's per-block absolute offsets let the driver detect that instead of
  handing back the head of the file under a `Content-Range` that lies. An
  origin that advertises `ERET` and then refuses it falls back to the
  *positioned* `REST`+`RETR` path and is not asked again on that session.
  `ESTO` is deliberately not implemented — the write path has no partial-write
  caller to emit it.
- **Every `SPAS` stripe must be the control channel's own peer.** This is the
  one place in the protocol where the origin hands the driver a *list of
  addresses*; everywhere else the advertised PASV address is discarded and the
  pinned numeric control peer is dialled instead, so a redirected data channel
  is not expressible. Following a stripe elsewhere would make the storage
  backend open connections to arbitrary hosts inside your network on the
  origin's instruction — an FTP bounce with your egress rules as the only
  remaining control. One foreign stripe abandons the whole striped attempt
  before any socket is opened, and the read completes over one connection. The
  practical consequence: a genuinely **multi-host** striped door (stripes on
  different servers, which is what a large dCache or Globus deployment looks
  like) is read over a single connection here. That is a throughput ceiling and
  never a wrong answer. If you need multi-host striping, that is a design
  conversation and not a configuration change. `SPOR` — the client offering
  addresses for the server to dial — is not implemented at all, because it
  would require this driver to listen, and it never binds.

  In a capture, a striped read is `FEAT` → `SPAS` → several `229-` continuation
  lines then `229 End` → *n* data connections → `RETR`. A refusal is
  `SPAS` → 5xx (or an over-budget list) → `EPSV` → `RETR` on the same control
  channel, and is not re-asked on that session.
- **A `COPY` within one gsiftp export no longer travels through the client.**
  FTP has no server-side copy verb, so the bytes still move — but only on the
  gateway↔origin link, over ONE control session: `SIZE` the source, `RETR` it
  into a local scratch file, `STOR` that to a random temp name, then
  `RNFR`/`RNTO` onto the destination. Two consequences are worth knowing. The
  destination appears whole or not at all, because a failed copy renames
  nothing and deletes its own temp — storing straight onto the destination
  would leave a good object half-replaced for the length of every transfer.
  And a copy is refused, not truncated, if the origin sends fewer bytes than
  the `SIZE` it just reported: a bounded read that stops early is not an error
  the origin reports, so it is checked here. A copy of a path onto ITSELF is
  refused outright (`EINVAL`) — it would work, and it would rewrite a healthy
  object for no gain. Before this the slot was empty and every `COPY` on a
  gsiftp export was `ENOTSUP`. Under `brix_read_only on` the copy is refused by
  the export's mutation policy before a single FTP command is written.
- **GridFTP-over-SSH (`sshftp://`) is not implemented and the scheme is not
  accepted.** It needs the control transport to terminate on the storage host,
  which means a per-session child process; nginx workers may not fork (see
  `src/fs/xfer/xfer.h`). An `ssh -L` sidecar does not substitute, because the
  data channel dials the *control channel's pinned peer* — which would be
  `127.0.0.1`, not the storage host.

### Testing brix against a real door

Everything above is exercised in-tree against `ftp_origin_server.py`, a Python
origin written from the same reading of GFD.020 as the driver it tests — so a
shared misreading of the spec would pass both halves. The `gridftp-outbound`
lab lane exists to close that gap: it deploys four WebDAV fronts whose storage
plane is **your** Globus or dCache door, differing only in the store line
(nothing, `mode=e`, `mode=e prot=p`, `mode=e streams=n`), and runs the same
round-trip, ranged-read, `COPY` and striping assertions across all four.

It is off by default and cannot be otherwise: no door and no grid credential
ships with this repository. You supply both.

```
kubectl -n brix-gridftp create secret generic outbound-proxy \
    --from-file=user_proxy.pem=$X509_USER_PROXY
kubectl -n brix-gridftp create configmap outbound-ca \
    --from-file=/etc/grid-security/certificates

BRIX_OUTBOUND_DOOR=door.example.org \
BRIX_OUTBOUND_PATH=/pnfs/example.org/brix-interop \
    xrd-lab test gridftp-outbound
```

Without `BRIX_OUTBOUND_DOOR` the scenario refuses to deploy rather than
defaulting to a placeholder host — a lane pointed at a host that does not
answer skips every cell and exits 0, which looks exactly like a lane that
passed. For a cleartext `ftp://` door (`BRIX_OUTBOUND_SCHEME=ftp`) the `prot=p`
front is not rendered at all: `prot=p` needs a control-channel identity to pin
the data channel's certificate against, and on an anonymous door there is none,
so the front would fail `nginx -t` and take the other three with it.

Exercised by `tests/test_phase115_gridftp_mode_e.py`,
`tests/test_phase115_gridftp_prot_p.py`, `tests/test_phase115_gridftp_eret.py`,
`tests/test_phase115_gridftp_eret_static.py`,
`tests/test_phase115_gridftp_spas.py`,
`tests/test_phase115_gridftp_spas_parse.py`,
`tests/test_phase115_gridftp_spas_static.py`,
`tests/test_phase115_gsiftp_server_copy.py` and
`tests/test_phase115_gsiftp_server_copy_static.py`; the outbound lane by
`k8s-tests/remote-suite/tests/test_gridftp_outbound_interop.py` (needs a real
door) with its chart/runner wiring pinned locally by
`k8s-tests/pytests/test_gridftp_outbound_wiring.py`; design record in
[phase-115](../refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md)
W5.1/W5.2.
