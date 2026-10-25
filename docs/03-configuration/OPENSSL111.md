# AlmaLinux 8 and OpenSSL 1.1.1 compatibility

The compatibility backend targets **OpenSSL 1.1.1**, not 1.0.x or 1.1.0. The
project's AGPL licence is unchanged. OpenSSL 3+ remains the release default;
legacy-linked distribution still needs licensing review. A wrapper layer does
not itself settle the licensing of a combined executable.
The target uses Alma8's vendor-maintained library packages, not arbitrary
unmaintained upstream 1.x builds.

The shared wrappers in [the crypto subsystem](../../src/auth/crypto/README.md)
cover RSA/P-256 key generation, borrowed exponent ownership, public-key
comparison, DH public/group ownership, JWT RSA/P-256 imports, explicit trust
store loaders, typed DNS/IP certificate-name verification and GridFTP
data-channel EOF compatibility. IP literals require matching iPAddress SANs;
a numeric dNSName or CommonName is not a substitute. Digest/MAC helpers
select native HMAC/EVP interfaces on 1.1.1 and provider interfaces on 3+.
Certificate verification, proxy restrictions, trust boundaries and control TLS
policy remain with their existing owners; they are not disabled for legacy
builds.

All identity, signing-policy, delegation, VOMS and peer-pin DN rendering now
uses one shared compatibility seam. Literal slashes, plus signs and backslashes
cannot alias real RDN/AVA boundaries, and bounded output refuses truncation.
Rendering never modifies a verified certificate. Review DN-valued configuration
containing those literal characters against BriX's canonical spelling rather
than relying on a legacy library's ambiguous `X509_NAME_oneline` output.

## Local full-server validation

Install Alma8's native `openssl-devel`, nginx and matching `nginx-mod-devel`,
plus the full-suite dependencies in [BUILD.md](BUILD.md). The nginx 1.24 module
stream must be enabled when modular filtering otherwise hides the SDK:

```sh
dnf module enable -y nginx:1.24
dnf install -y openssl-devel nginx nginx-mod-devel
```

Use a clean build directory and select the **system** pkg-config metadata:

```sh
BRIX_OPENSSL111_COMPAT=1 PKG_CONFIG_PATH=/usr/lib64/pkgconfig \
  cmake -S . -B build/alma8-openssl111 -DBRIX_BUILD_NGINX=ON
BRIX_OPENSSL111_COMPAT=1 PKG_CONFIG_PATH=/usr/lib64/pkgconfig \
  cmake --build build/alma8-openssl111 --parallel 4
```

Do not carry `CPATH`, `LIBRARY_PATH`, linker rpaths or pkg-config overrides from
an OpenSSL 3 build into this build. Inspect `ldd` for nginx, its modules and the
native clients: the legacy proof must resolve `libssl.so.1.1` and
`libcrypto.so.1.1`, not load both OpenSSL ABIs. Use a private test root and the
matching built module paths when running the canonical full suite. A container
tests Alma8 userspace against its host kernel; it does not certify an Alma8
kernel or its kernel-offload capabilities.

General TLS/authentication fixtures do not opt into OpenSSL-3-only kTLS options.
Dedicated offload tests remain separate. An explicit `brix_ktls on` reports a
userspace fallback when this OpenSSL build cannot offer it.

The canonical test CA uses a request configuration without implicit extensions.
OpenSSL 1.1.1 otherwise appends `-addext` extensions to distro defaults, producing
invalid duplicate CA/SKI/AKI extensions. This fix changes test certificate
generation, not certificate verification or the host's crypto policy.
The TLS assessor's certificates and weak-digest rejection fixtures use the
same extension-free request discipline, including the intermediate-CA GSI
fixture's root anchor. PKI generation failure in that scenario is an error,
not a successful skip. The two-step delegation fixture signer
uses the already-required Python cryptography library rather than the
OpenSSL-3-only `x509 -copy_extensions` command-line option.

Alma8's repository liburing 1.x is below the server/client feature minimums
(2.2/2.4). An optional isolated liburing 2.4 SDK was built for validation;
its headers, link paths and runtime loader paths are selected together using
pkg-config. An out-of-prefix module build also sets
`-DBRIX_MODULE_LDFLAGS=-Wl,-rpath,/opt/brix-liburing-2.4/lib` explicitly; a
successful link alone is not a runtime loader proof. This does not replace
Alma8's system library. The validation VM
currently sets `kernel.io_uring_disabled=2`; compiled support is not evidence
that kernel ring execution ran. The thread-pool fallback remains available.

## Recorded evidence — 2026-10-17

Alma8 ARM64 userspace, system OpenSSL 1.1.1k and nginx 1.24.0:

- Complete server module and native client/tool builds succeeded.
- Modules passed `nginx -t` and served a byte-exact `root://` read with the
  newly built native client.
- Native wrapper, canonical CA and proxy-delegation tests passed **12/12**.
- Expanded wrapper/runner/storage-seam contracts passed **61/61** with the
  native 1.1.1 SDK, including DNS/IPv4/IPv6 verification and mismatched-name
  refusals. The three initial export/guard failures passed in a separate,
  normalized correction snapshot; the original full-run evidence is retained.
- The corrected full server passed all **8** shipped example-stack smoke tests
  and **37** live upstream TLS checks. The TLS matrix passed **25**, with **9**
  explicit unreachable-cell skips. Both previously timed-out CVMFS scenarios
  passed, followed by **5** CVMFS build/check contracts including `brix-all`.
  These are focused correction proofs, not a replacement full-suite verdict.
- Full-suite certification remains open. A later container run exhausted its
  PID limit because its original PID 1 did not reap orphaned fixture processes;
  those cascading setup errors are invalid validation evidence. The complete
  container was preserved before replacing it with an init-enabled container.
  A complete zero-failure full-suite result is not yet claimed.
- Further focused corrections passed **9** weak-certificate fixture tests,
  **10** TLS assessor tests, **17** redirect/attention tests, **30** native
  Linux PAL/ring-preparation tests, and **26** OCI conversion/flattening tests.
  The OCI oracle uses real rootless Podman with an isolated VFS storage profile
  and assigned subordinate IDs, not a mocked runtime or a reset shared store.
- Delegation and stored-credential TLS regressions passed **12/12**. The real
  OCI mirror pull/push-refusal oracle passed **3**, with **1** explicitly
  opt-in external-registry skip. VOMS and exact source-ownership contracts
  passed **74**, with four unrelated cases deselected.
- Native X.509 conformance and stale-link refusal passed **2/2**, including
  cross-version slash/plus value escaping, real multi-valued RDNs and unchanged
  non-ASCII spelling. These retain the signing-policy expectations.
- The rebuilt full module passed the complete **520-clause** certificate corpus
  materialization and live DAVS verdict matrix, together with the wrapper,
  signing-policy, canonical PKI and GSI-cipher contracts (**22 passed** in that
  focused run). Its separately enabled native reference-daemon differential
  test also passed; the optional test was not counted as successful while skipped.
- The finalized full-server/client build passed **101/101** native HTTP,
  compression, crypto and runner regressions, with no skips. This includes large
  incompressible WebDAV/S3 transfers, rate-limited CVMFS, strict HTTP framing,
  abandoned-reader recovery and corrupt-fill refusal. All codec dependencies
  selected for these tests loaded and ran.
- The subsequent init-enabled frozen full run was **interrupted**, not
  completed: its fleet sentinel detected the loss of shared servers near 54%
  of the main lane. Aggregate JUnit contains **22,848 passed, 5 failed,
  13 errors and 512 skipped** (including expected failures). These are partial
  counts, not a full-suite denominator or certification. All expected report
  files existing does not mean every collected test executed.
- The five observed failures involved file size, example configuration,
  duplicated code and the pblock benchmark's hand-written link flags. The
  thirteen setup errors shared a proof-lane registry-selection defect.
  Focused corrections passed the affected checks, including real WebDAV LOCK
  and pblock execution (**165 passed**, no skips). Benchmark linkage now uses
  the native client's selected dependency metadata, including its isolated
  liburing SDK, rather than borrowing incompatible system libraries.
- Fleet cleanup now pins child registry paths and requires exact test-root
  ownership before signaling listeners; sharing a port band is not ownership.
  Sentinel failures are checked before teardown and bounded diagnostic tails
  are copied to the report directory before fixture cleanup. The sentinel
  remains enabled. Expanded operator/runner/proof and endpoint contracts passed
  **107/107**, including rejection of foreign/sibling sentinel registries.
- The final broader-refactor server/client build passed **395** regressions
  with zero failures or errors; **9** source-egress tests were skipped because
  this focused fleet did not include their dedicated fixtures. This run also
  verifies that child cleanup leaves a live main-server witness serving.
  The global duplication gate now reports **zero duplicate blocks**, without
  relaxed thresholds or exemptions. A final full-suite rerun remains required;
  focused corrections do not rewrite the frozen run's result.
- Starting both missing dedicated fixtures allowed all **9** source-egress
  cases to run. The expanded final native-client/TPC batch passed **324/324**,
  with no skips, failures or errors, on both Alma8 and macOS. Its single
  warning comes from an intentionally legacy-TLS rejection fixture, not from
  relaxing the server's TLS policy. An initial focused attempt exhausted its
  undersized 128-port mock pool; the corrected runner reserves 1,024 private
  slots and starts a fresh fixture root rather than retrying failed cases.
- A new frozen-source full-suite attempt was launched after these corrections,
  using a separate SDK, non-root account, private Git metadata and reports.
  The earlier interrupted source and results remain unchanged. A launched
  build or an in-progress test count is not a complete full-suite verdict.
- The final lifecycle, process-ownership and native FUSE-argument correction
  set passed **123/123**, with no skips, failures or errors. This uses the
  existing full-server 1.1.1 build in a separate test workspace.

## Follow-up — 2026-10-18

The subsequent frozen full attempt also lost its shared fleet in the main
lane. Its live observer completed **22,088 of 41,005** selected tests. The
final main-lane JUnit has **21,595 passed, 2 failed, 0 errors and 493 skipped**;
these are actual XML records, not a complete execution denominator. Its serial
lane did complete **6,180/6,180**, with **5,886 passed, 1 failed, 0 errors and
293 skipped**, including four expected failures in the skip count. The two
remaining lanes finished with **180 passed / 6 skipped** and **912 passed /
92 skipped**. Aggregate JUnit contains **28,573 passed, 3 failed, 0 errors and
884 skipped** across **29,460 records**. All four reports exist, but the
interrupted main lane makes this incomplete execution, not certification.
The frozen source, SDK and original reports are preserved unchanged. The final
client lane's skips include 44 cases each for unhealthy GSI and TLS endpoints;
these are missing endpoint coverage, not evidence that legacy TLS is unsupported.

One main-lane failure was the typed read-only scratch-capability guard; the
client now carries the typed object through its helpers rather than erasing
it to a raw path. Its focused live checks passed **38/38** on Alma8, macOS and
FreeBSD. The other main-lane failure is an environment incompatibility: the
default `quay.io/ceph/demo:latest-reef` image is AMD64-only and cannot execute
on this ARM64 container host. That frozen result is retained; a separate native
Ceph lab correction is recorded below rather than silently skipping Ceph.

The serial failure was the intermediate-CA GSI fixture's duplicated root-CA
extension under OpenSSL 1.1.1. After correction, all **nine** PKI portability
regressions and the real stock-client intermediate-CA transfer/refusal scenario
passed together (**10/10**), with normal certificate verification unchanged.

The final rebuilt 1.1.1 module passed a combined **462/462** native storage,
HTTP, client, TPC, lifecycle and registry-ownership regression set, with no
errors, failures or skips. Its live parent server survived child cleanup.
These focused results close observed defects but do not replace a full rerun.
The native reporter now distinguishes report-file availability from execution
completeness and requires a finished controller record with conserved collected
and completed counts before any run can report success.

The same final regression set plus PKI and stock-client intermediate-CA tests
passed **472/472** on macOS, with no errors or skips. Its controller recorded
**472 collected and 472 completed**, a normal session finish and a zero exit
status; this also exercises the new execution-completeness reporting path.

A digest-verified native ARM64 demo image restored the separate Ceph lab:
`quay.io/ceph/demo@sha256:241e226c45f290a76a92106e3198903d634dbe0dccb56cfc3e64a53c77fab460`.
Both lifecycle tests passed under the non-root validation account. The existing
real RADOS vtable harness then compiled natively against Alma8's development
libraries and passed **66/66** checks against the dedicated pool, including
data, xattrs, namespace, checksums, capacity and refusal paths. Its link closure
does not load OpenSSL 3/4. This pinned May-2024 demo is an isolated test lab,
not a production Ceph deployment recommendation. A subsequent real-server
cross-plane probe initially found root://-written data returning HTTP 404 with
the same configured backend. The namespace correction below closes that wiring
defect; successful direct-driver checks alone did not establish this.

### RADOS namespace correction — 2026-10-18

The root driver-open path and its existence, forwarding and asynchronous-fill
probes now apply the shared logical-to-physical translation exactly once.
Authorization and read-only policy continue to use the confined logical path.
WebDAV's metadata helper now uses the canonical VFS initializer, preserving
the same mapping for HEAD and DELETE instead of probing unprefixed objects.

The actual Alma8 server passed **both** native Ceph probes with no skips:
byte-exact root-to-HTTP and HTTP-to-root transfers, missing-object refusal,
read-only refusal, and two export prefixes sharing the same pool. The latter
verifies separate bytes at the same logical name, denied reads into the other
prefix, independent overwrite and deletion, and absence of a nested-prefix
alias. Both configurations passed `nginx -t`. These are real module/client
checks, additional to the 66 direct-driver checks above.

Permanent cluster-independent regressions exercise translated pblock writes,
reads, HEAD/DELETE, empty and multi-block objects, absent keys and read-only
refusals. A separate HTTP-origin cache fixture verifies cold and warm reads,
the mapped physical cache file and absence of an unprefixed alias.

Previously written **unprefixed objects are not migrated automatically**.
Moving them without a reviewed ownership inventory could assign data to the
wrong export. Back up the pool and plan any explicit migration separately.

The operator-approved cache metadata extension also fixes stat and probe
dispatch: they retain the composed cache/stage stack rather than bypassing it
to stat the origin. Both decorators have credential-forwarding stat slots.
Credential resolution still precedes any cache hit, while complete cached
objects supply metadata matching the bytes read-open actually serves. Permanent
regressions cover a disappeared origin, shorter and longer replacement origins,
and warm-cache credential refusal on HTTP HEAD/GET and root access, including
proof that refused requests do not contact the origin.

The final combined regression selection passed **622/622 on each of macOS
ARM64, Alma8/OpenSSL 1.1.1 and native FreeBSD**, with zero failures, errors or
skips and one intentional legacy-TLS fixture warning each. Every controller
recorded 622 collected/completed, a normal finish and exit status zero; each
live parent server survived teardown. This includes forwarding, cache hints,
live delegation and the compiled decorator credential-forwarding oracle.
A Darwin-only xattr macro collision in that C oracle was corrected with a
parenthesized function-pointer call; its assertions are unchanged and the
corrected fixture also passed separately on Alma8 and FreeBSD. These are
focused server/client regressions, not a replacement full-suite certification.

A separate cold-cache experiment still exposes synchronous remote metadata
preflight: an origin served by the same worker can stall that worker. The
regression fixture uses an independent origin process; it does not certify
same-worker cold-origin self-connections. No skip, verification budget or
credential fallback was relaxed for either completed correction.

Runtime linkage was also audited for all **20** executables in this native
client/tool build: no OpenSSL 3/4 or unresolved libraries were found; the crypto
consumers use system OpenSSL 1.1.1. The optional isolated liburing loader path
remains selected consistently.

The final expanded client, TPC, TLS and page-verification batch passed **355/355** on
each of Alma8, FreeBSD and macOS: zero failures, errors or skips, with one
intentional legacy-TLS fixture warning each. Controller records independently
confirm 355 collected and completed tests and a normal session finish. Fixture
corrections retain the independent CRC oracle, bounded per-response reuse,
accepted-order fault injection and byte-exact status/page framing; no request,
byte or wall-clock assessment limit was increased. These results do not replace
the required complete post-fix canonical suite.

The release Alma8 recipe remains client-only/OpenSSL 3 while distribution
policy is unresolved. This document does not authorise publishing legacy-linked
server binaries or assert certification of every optional integration.
