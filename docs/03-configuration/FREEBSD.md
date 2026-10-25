# Native FreeBSD server target

The native target is FreeBSD 15+ on ARM64 and x86-64. It builds the real nginx
modules, a matching nginx executable and native clients; it is not a Linux
container or a PAL-only compilation probe. ARM64 has local VM evidence below;
the x86-64 CI lane is configured but has not been certified by this local run.

## Latest local verdict — 23 October 2026

The completed immutable ARM64 **V940** full run is **not release-green**:
**49,637 tests, 47,464 passed (including 8 XPASS), 1,300 failed, 5 errors,
820 skipped and 48 XFAIL**. All four lanes finish; their collection, execution
and JUnit totals reconcile. The runner's raw 868 skipped records include the
48 XFAIL. No runtime-suite process remains after cleanup.

Separate corrected SDK selections and native dependency work are recorded
[at the latest checkpoint](#october-23-completed-native-full-run-and-coverage-recovery).
They do not replace frozen-source failures or certify the native XRootD
dependency. The previous completed V805 result remains recorded
[below](#october-22-final-full-run-checkpoint), alongside the interrupted
[October 23 attempt](#october-23-native-revalidation-and-attribute-boundary-fix).

## Build and validate

Use a disposable VM and install the dependency list in
[the FreeBSD workflow](../../.github/workflows/freebsd.yml). It includes GNU
make, CMake, the nginx source prerequisites, epoll-shim, FUSE 3, Kerberos,
codecs, XML/JSON/SQLite libraries and native Python test packages. The Python
analysis dependencies need the Rust toolchain when no binary wheel exists.
Keep them in a virtual environment with `--system-site-packages` so the native
reference-client bindings remain available.

Full CI also builds the pinned Helm renderer as the dedicated account, because
the native ARM64 package catalogue does not provide it in this environment:

```sh
env GOBIN=/path/to/private-helm/bin GOMAXPROCS=2 GOMEMLIMIT=2GiB \
  GOFLAGS=-p=2 GOTOOLCHAIN=local \
  go install helm.sh/helm/v4/cmd/helm@v4.3.1
export PATH="/path/to/private-helm/bin:$PATH"
```

Use a private prefix and the native Go package; do not build as root. A missing
toolchain or failed build stops setup rather than silently dropping chart
coverage. The native build's Go metadata identifies module version `v4.3.1`;
its default short version banner alone reads `v4.3`. Both chart-rendering test
modules run successfully with this dependency.

Full CI also builds the native GFAL interoperability dependencies with the
[isolated bootstrap](../../tools/ci/freebsd_gfal.py). These are **test clients**,
not additional BriX server runtime dependencies. It verifies pinned upstream
archive checksums, builds Davix/GFAL2 and their matching Python/CLI layer in a
new private directory, and enables the file, HTTP/WebDAV and XRootD plugins.
Its external-only portability patches do not modify BriX's production sources,
the installed XRootD package or system libraries. Use the workflow's native
GFAL prerequisite packages and its Python 3.12/Boost-Python pairing:

```sh
/path/to/test-venv/bin/python tools/ci/freebsd_gfal.py \
  --work-dir /var/tmp/my-new-gfal-lab --jobs 1
/path/to/test-venv/bin/python tools/ci/freebsd_gridftp.py \
  --work-dir /var/tmp/my-new-gridftp-lab --jobs 1

sudo env PATH="/var/tmp/my-new-gfal-lab/install/gfal2/bin:/var/tmp/my-new-gridftp-lab/install/bin:$PATH" \
  /path/to/test-venv/bin/python tools/ci/freebsd_pending_peer.py \
  --user brixvalidate -- /path/to/test-venv/bin/python tools/ci/freebsd_native.py \
  --nginx-source /var/tmp/nginx-1.30.5 \
  --build-dir /var/tmp/brix-freebsd-build --test-level full
```

Run the bootstrap as the dedicated non-root account. An existing work directory
is refused rather than rebuilt or overwritten; checksum and build failures
remain errors. Installed loader paths include GFAL's native `lib64` and its
private Davix libraries, without `LD_LIBRARY_PATH` injection. SFTP, SRM, DCAP,
GridFTP, LFC and RFIO GFAL plugins are not enabled by this recipe. The XRootD
plugin still uses the native reference package: enabling it exposes, rather
than excuses, that package's outstanding offset/local-copy failures.

Full CI separately builds the native GridCF `globus-url-copy` client in a
private prefix. The pinned [GridCF release](https://github.com/gridcf/gct/releases/tag/v6.2.20260123)
is verified against its published SHA512 before extraction. Only the GridFTP
subset and its dependencies are built; GRAM and GSI-OpenSSH are disabled. A
small external-only patch handles FreeBSD's legal indeterminate
`_SC_GETPW_R_SIZE_MAX` result with a 16 KiB fallback, retaining the real native
`getpwnam_r` lookup and credential-owner policy. The bootstrap requires a
successful byte-exact local copy, not merely a version banner. This enables
native GridFTP interoperability tests; it does **not** enable GFAL's separate
GridFTP plugin or repair the installed XRootD reference server.

Use an unpacked, checksum-verified nginx SDK matching the deployed nginx
version. Do not mix OpenSSL ABIs in one server. From a dedicated account which
is **not** in wheel/group 0:

```sh
python tools/ci/freebsd_native.py \
  --nginx-source /var/tmp/nginx-1.30.5 \
  --build-dir /var/tmp/brix-freebsd-build \
  --test-level contracts

sudo /path/to/test-venv/bin/python tools/ci/freebsd_pending_peer.py \
  --user brixvalidate -- /path/to/test-venv/bin/python tools/ci/freebsd_native.py \
  --nginx-source /var/tmp/nginx-1.30.5 \
  --build-dir /var/tmp/brix-freebsd-build \
  --test-level full --no-build
```

Replace `brixvalidate` with the dedicated non-wheel account. The full command
uses root only to lease an isolated VNET pending-connect peer, then runs the
build/tests with that account's own UID/GID/groups. It changes no host firewall,
default route or persistent TCP setting. The wrapper always removes its owned
jail/interface after the child exits. Without it the pending-connect assertions
cannot run correctly; running the entire suite as root is not a substitute.

`contracts` always builds and runs a byte-exact `root://` smoke before native
crypto, namespace, process identity, descriptor, xattr and proxy-delegation
tests. `full` invokes the existing canonical suite scheduler with its optional
suite-job tests enabled, including the native X.509 oracle. Reports are
retained under the build directory, with per-lane JUnit and aggregate counts
for full runs. Missing reports, unfinished lanes and a mismatch between
collected and completed test counts cannot produce a successful verdict.
The runner logs a separate short, private `/tmp/bf-*` test root: reference
daemons' Unix admin-socket names must fit FreeBSD's `sun_path` bound even when
the build directory is deeply nested. Logs remain there for investigation.
`--no-build` reuses an already-built target; it is not evidence of a fresh build.

Read-only analyzer runners must use this target's real compiler working
directory and generated module graph, not an unrelated `/tmp/nginx-*` tree:

```sh
env NGX_BUILD=/var/tmp/brix-freebsd-build/nginx-src \
  NGX_MAKEFILE=/var/tmp/brix-freebsd-build/modules/Makefile \
  JOBS=2 FANALYZER_RAW=/var/tmp/my-new-analyzer-trace.txt \
  /path/to/test-venv/bin/python tools/ci/run_fanalyzer.py
```

The native target runner pins these paths even if a different SDK was inherited
from the caller. GNU make reads flags from the selected graph while compilation
uses its corresponding nginx source directory. Clang's
`-Wconditional-uninitialized` is translated to GCC's `-Wmaybe-uninitialized`,
not discarded; unknown options still fail. `FANALYZER_CC=/usr/local/bin/gcc16`
can explicitly select a separate analyzer compiler without changing the
server's native Clang `CC`. A fatal compilation error cannot be masked by an
earlier analyzer warning. Missing CodeChecker remains an explicit unavailable
dependency; instrumented coverage needs a separate build and must not rebuild
the SDK of an active runtime suite.

Full CI validation also runs a **separate host-root authorization lane** after
the ordinary-user suite, retaining both results even if either fails. To run
that narrow lane manually after building as the dedicated user:

```sh
sudo /path/to/test-venv/bin/python tools/ci/freebsd_native.py \
  --nginx-source /var/tmp/nginx-1.30.5 \
  --build-dir /var/tmp/brix-freebsd-build \
  --test-level privileged --no-build
```

This lane prepares private PKI, runs the multi-user authorization catalogue and
real grid-mapfile ownership/confinement tests, plus pblock group authorization
and worker privilege-drop checks, native worker saved-identity/NNP checks,
checkpoint recovery under split master/worker identities, and the non-devfs
device-policy proof. It writes
`native-privileged.xml` alongside live progress/failure evidence. It requires
root and refuses to build as root. It does not run the broad suite as root or
turn unavailable capabilities into successes. On ZFS the known Capsicum/xattr
failure remains visible; select a separately validated filesystem only when
that is the deployment target, not as a silent test fallback.

Use an isolated source copy for long runs and do not rebuild or replace that
copy while tests run. Strip AppleDouble archive sidecars when exporting from
macOS (`COPYFILE_DISABLE=1 tar --exclude='._*' ...`), including any sidecars
already on disk. Confirm the extracted tree has no `._*` files before starting;
otherwise binary resource-fork metadata can be mistaken for C/Python/docs by
the unchanged repository gates. Never weaken worker identity checks to
run a personal wheel account as a service.

For full cross-device upload coverage, provision a separate bounded filesystem
as root and make it writable by the dedicated test account. The workflow mounts
a private 512 MiB `nosuid` tmpfs and exports its path as
`TEST_STAGE_DEVICE_ROOT`. Manual runs can set the same variable to their own
second filesystem. A configured path that is missing, unwritable or on the
export's device fails the test instead of silently skipping; actual native
device identity and byte-exact transfers remain required.

Keep the complete named-and-mock test-port reservation below the kernel's
**default** anonymous-port floor. In the validation VM that default was
10000–65535, not the separate high-port range beginning at 49152. Server-role
reference CMS daemons choose anonymous listeners; one took a reserved test
port and caused 19 signing-policy setup errors. Their public `-p` option did
not pin that server-role listener in a black-box probe, so it is not used as
a workaround. The test ladder now reads the native default bounds and refuses
an overlap before fleet startup instead of treating FreeBSD's range as unknown.
It reports honestly when no lower test base can fit the full reservation.

Only inside a disposable, dedicated build/test VM, an administrator can reserve
the lower test band for the duration of validation:

```sh
sysctl net.inet.ip.portrange.first net.inet.ip.portrange.last  # record originals
sysctl net.inet.ip.portrange.first=32768
sysctl net.inet.ip.portrange.last=65535
```

These commands do not edit boot settings. Restore the recorded values when
the isolated validation environment is retired. The full-run CI guest applies
this temporary separation; it is not a BriX server installation requirement
and must not be applied indiscriminately to a production host. Existing
reference listeners are not relocated by changing the range.

After reboot, recheck runtime-only test prerequisites: load `fusefs`, grant
only the dedicated account access to `/dev/fuse`, and recreate the bounded
cross-device tmpfs. The full CI guest also adds explicit loopback aliases
`127.0.0.2` through `127.0.0.9` for source-spread storms and reverse-DNS tests,
plus its bounded `127.64.<worker>.<number>` fixture reservation. FreeBSD does
not make every address in `127/8` bindable automatically. Missing aliases
must not be mistaken for an unavailable BriX feature; do not enable non-local
binding as a substitute.

Ensure the VM's hostname resolves through its normal name-service configuration
(for a disposable loopback VM, add its hostname to `/etc/hosts`). The installed
reference daemon refuses to start when the hostname is unresolvable; this is a
test-environment requirement, not a reason to bypass the reference tests.
Reference daemon listeners explicitly use the declared endpoint's address
family. IPv4 tests do not depend on disabling FreeBSD's IPv6-only socket policy.
The installed reference daemon also failed large native reads with repeated
`sendfile failure` disconnects. FreeBSD reference fixtures select its buffered
transport (`xrootd.async nosf`); the identical 2 MiB GSI write/readback then
passed. This workaround does not disable BriX offloads or certify the external
package's sendfile path.

## Native behavior and limits

The PAL uses native saved-ID inspection, `procctl` no-new-privileges,
`LOCAL_PEERCRED`, eventfd, kqueue, native mount snapshots and FreeBSD extended
attributes. Descriptor-relative bounded path walking shares one implementation
with Darwin. No Linux capability or seccomp operation is simulated by success.

Known differences remain explicit:

- Native `brix_idmap map` uses permanently dropped fixed-identity helpers and
  a non-root supervisor, not emulated Linux capabilities. An explicit,
  dedicated `brix_idmap_broker_user` is required. The bounded startup account
  snapshot and complete credential matching fail closed for new/changed
  identities until broker restart. Focused ownership/DAC/confinement validation
  is separate from the still-incomplete full-suite release certification.
  Ordinary service-identity operation and worker de-escalation remain separate.
- Conditional xattr CREATE/REPLACE, atomic rename exchange, KEEP_SIZE space
  reservation and immutable fd sealing are refused where native semantics
  cannot be provided. Plain user xattrs, exclusive rename, metadata and file
  transfers have native implementations. No check-then-write atomicity claim
  is made. Local POSIX WebDAV locks instead use a dedicated portable store:
  a confined inode descriptor, nonblocking kernel `flock`, and an exact
  compare-and-update of the existing lock xattr. This is not an emulation of
  generic conditional xattrs. Kernel lock ownership ends when the process
  dies; the persisted xattr remains the sole cross-protocol lock truth.
  Mapped POSIX operations run that same store in the mapped owner's confined
  helper. Non-POSIX operations retain their credential-aware native xattr path
  and refuse unsupported semantics rather than bypassing it. ZFS `xattr=dir`
  fd xattrs are not currently usable inside Capsicum on the tested host (see
  the native broker checkpoint below); UFS has been verified separately.
  Implicit and explicitly configured POSIX exports use the VFS's existing
  default-driver classification, preserve N2N translation and open beneath the
  instance's physical root. A default backend credential-directory pointer is
  not evidence that a local POSIX driver consumes a remote credential.
- Native TCP RTT is available; full cumulative per-socket byte accounting is
  not fabricated from wrapping sequence numbers.
- io_uring and Linux seccomp are unavailable. The shared BSD AIO implementation
  uses pthreads. The legacy security-profile API refuses enforcement requests.
- Optional Ceph libraries are not supplied by this ARM64 validation setup.
  Native FUSE execution requires the `fusefs` kernel module and appropriate
  permissions; installing headers alone is not a mount proof.
- The current native reference-client package is XRootD 5.x. This does not
  certify interoperability with the separately declared 6.x reference matrix.
  The tested FreeBSD `xrootd-5.6.9_2` / `py312-xrootd-5.9.2` combination also
  sent a 64-bit read offset in host byte order: a loopback packet capture of
  offset 1000 contained `e803000000000000`, not `00000000000003e8`.
  BriX's correct rejection must not be weakened to accommodate that package.
  Independent raw-wire tests verify exact nonzero ranges and refusal of
  negative/overflow offsets. A working native reference package is still
  required for complete differential-client coverage.
  A separate `ktrace` probe also located the stock CLI's local-file copy
  failure at `aio_write`, returning `EINVAL` before a complete transfer. This
  is not evidence that BriX rejected the transfer. Kernel unsafe-AIO policy
  was not relaxed to obtain a passing reference-client result.

Module installation defaults to `/usr/local/libexec/nginx`, loader snippets
to `/usr/local/etc/nginx/modules.d`, and examples to
`/usr/local/etc/nginx/conf.d`. Include the loader snippet only after nginx's
stream core. Use `service nginx reload`, not systemd. Stage installation with
`DESTDIR`; direct installation is not registered in pkg's database. A released
native `.pkg` and a complete full-suite certification are not claimed here.

## Recorded evidence — 2026-10-17

FreeBSD 15.1-RELEASE-p5, ARM64, nginx 1.30.5 and OpenSSL 3.5.6:

- Real server modules and native client/tool builds succeeded.
- A byte-exact native-client `root://` transfer passed with both the built nginx
  executable and FreeBSD's installed nginx package.
- The repeatable native contract target passed **27/27** as an ordinary,
  non-wheel account.
- The broader PAL/tool run passed **135**, skipped **189** other-platform or
  unavailable-capability cases, and reported **8 XPASS**, with zero failures or
  errors. This is not the full project suite.
- Expanded crypto/runner contracts passed **24/24**, including real DNS/IP
  certificate verification. The installed reference daemon, explicitly bound
  to IPv4, also completed a native-client `stat` probe.
- Root-only PAL contracts passed **11/11**. A separate root-master smoke
  passed a byte-exact transfer with mandatory worker de-escalation intact.
- Native SDK/tool closure passed **25/25**, including a real CVMFS repository
  check and its wrong-key refusal, rather than a header-only FUSE probe.
- Full-suite certification remains open. A diagnostic run exposed a reference
  client connection/ranged-read problem and test-harness portability defects.
  Interrupted/corrupted runs are not counted as a green suite.
- The expanded native wire/PAL/crypto/runner/harness contract set passed
  **60/60**, including the independent range and hostile-offset tests above.
- Corrected registry/process-ownership contracts passed **80**, with one
  deselected case, while an independent live-fleet witness survived teardown.
  Native process inspection distinguishes an empty `/proc` from Linux procfs,
  and temporary-registry shutdown cannot inherit another lane's manifest.
- The next diagnostic run identified that FreeBSD's `lsof` port/state
  selections need explicit conjunction (`-a`): an unused port otherwise
  returned unrelated listener PIDs. Corrected listener-isolation and live
  cache-matrix regressions passed **62**, with **2** capability skips and the
  independent witness still alive. The running full-suite source is frozen;
  this focused correction does not retroactively make its verdict green.
- The native X.509 conformance runner and stale-link refusal passed **2/2**,
  including new DN value-delimiter, multi-valued-RDN and encoding contracts.
- Expanded native closure passed **155**, with **1 XFAIL**, zero failures,
  errors or skips. This included a real FUSE read and expired-whitelist and
  wrong-key mount refusals, not only a compile-time availability check.
- Independent Go-HEP tools passed **10/10** native interoperability cases.
- Restart/history regressions passed **16/16**: inactive read-only fixture trees
  are retained separately, so a new instance cannot inherit old scrub/learner
  log events. The unrelated live-fleet witness survived.
- A real outbound-compression defect was reproduced: socket backpressure
  truncated the first HTTP chunk. The corrected bounded, resumable sender
  passed its **9** initial native CVMFS framing/transfer/refusal regressions.
- CVMFS ingestion, Stratum-0 serving, authenticated scvmfs, garbage collection
  and publishing transactions passed **16/16** after standalone native xattr
  link dependencies were included.
- Correcting the VM hostname to the actual `127.0.0.1` listener address allowed
  **73** GSI cases to pass. That diagnostic had **14 failures and 7 setup
  errors** involving external reference clients/daemons; it is not a green GSI
  suite. The dedicated reference fixtures also need explicit listener-family
  selection. Do not substitute Linux's `127.0.1.1` convention for the address
  these FreeBSD loopback fixtures actually bind.
- The integrated follow-up passed **132/132**, with **69** unrelated GSI cases
  deselected and no failures, errors or skips. It includes all **7** previously
  blocked native-client/stock-server GSI cases, large WebDAV/S3 transfers,
  rate-limited CVMFS, crypto contracts and reference-fixture ownership checks.
  The small receive window is configured before connecting: changing it after
  connection stalled both ordinary identity and compressed reads on this VM.
  This does not resolve the separate packaged reference-client defects above.
- The shared BSD FUSE-policy and lifecycle follow-up passed **162**, with
  **1 XFAIL**, no failures, errors or skips, and its independent live-fleet
  witness still serving after teardown. This includes native unmount-argument
  contracts, a real FUSE read, expired-whitelist and wrong-key mount refusals,
  and the inactive-prefix/history ownership checks. The macOS client also
  rebuilt successfully with the same shared policy implementation.
- Before the portable store, the complete two-file HTTP status-code test set
  passed **94** and failed **7**, with no errors or skips. All seven failures
  required LOCK creation. That historical result is not a platform waiver or
  a result for the replacement implementation. The HTTP timeouts seen in the
  older diagnostic were not reproduced in that focused run.
- The portable store's 15 native concurrency/lifecycle/refusal contracts and
  all 101 HTTP status-code cases passed on macOS and Alma8. Coverage includes
  competing creators, stale owners/expiry, bounded contention refusal,
  process-death recovery, special-file refusal and cross-protocol locks.
  FreeBSD compiled the initial portable-store server successfully, but its live run
  did not finish: the VM became unresponsive and its serial log reported swap
  exhaustion. Native FreeBSD LOCK execution and the final broader-refactor
  rebuild were still outstanding then; see the native follow-up below.

The repository-wide duplication gate now reports **zero duplicate blocks**,
with unchanged thresholds. Shared owners cover BSD FUSE policy, typed variable
registration, bounded CVMFS coding, read-offload ownership, TPC audit emission
and client protocol probes. The final combined build passed **395** focused
regressions on each of macOS and Alma8, with nine fixture-related skips each;
these are not native FreeBSD results or a replacement for its full rerun.
Both missing TPC fixtures were then started and a separate expanded native-client
and egress batch passed **324/324** on each host, with no skips. FreeBSD recovery
and the newer external reference dependency were still outstanding then.

## Follow-up — 2026-10-18

The dedicated VM was restarted with 16 GiB RAM; its preserved filesystem pool
reported healthy. Fresh server/client builds passed **35/35** native contracts
as a non-wheel account, **11/11** root PAL checks and a separate root-master,
byte-exact serving smoke with worker de-escalation unchanged.

The portable store now runs on explicitly configured POSIX exports as well as
the implicit local path. The standalone native contracts pass **15/15**; the
full two-file HTTP status-code suite passes **101/101**, including LOCK
creation, refresh, enforcement, conflict, expiry and UNLOCK. The combined
focused batch passes **413** with **one remaining external-client failure**,
zero errors or skips. That failure occurs after successful UNLOCK: the packaged
reference binding sends the wrong truncate length, producing an enormous
sparse file. Verification now checks size before a bounded read, rather than
attempting to allocate that file in memory. This is not a green full-suite
result. The separate typed read-only client checks pass **38/38**. Native FUSE
read, expired-whitelist refusal and wrong-key refusal pass **3/3** after loading
`fusefs` and restricting device access to the test account.

A separate native-client/TPC batch passed **322** with **two failures**, zero
errors or skips. Both large page-read negative fixtures exhausted their
45-second assessment budget before completing. The tool correctly refused to
certify incomplete negative evidence. The fixture's independent Python CRC32c
implementation measured approximately 8.9 MiB/s in a bounded native benchmark;
its contribution needs further profiling. A TCP_NODELAY experiment did not
resolve the failures and was reverted. No assessment budget or verification
requirement was weakened. A bounded fixture correction subsequently closed
both failures: exact-byte-keyed checksum reuse is limited to 64 pages within
one response, never shared across requests, and corruption is injected after
the clean checksum lookup. The independent CRC algorithm is unchanged. Its
success, changed-byte, corruption, cache-bound and unaligned-frame contracts
pass; the expanded native-client/page-verification batch passed **348/348**
before the separate fault-injection ordering correction below.

Alma8 then exposed a handshake fixture race: fault numbering depended on worker
thread scheduling instead of accepted connection order. The correction binds
the number before worker dispatch and preserves the existing `_serve(conn)`
subclass callback, including TLS peers. The explicit reverse-order/subclass
regressions and focused TLS/handshake checks pass **31/31** on FreeBSD, Alma8
and macOS. A further FreeBSD run exposed one 10-second PGR-029 fixture timeout;
the scripted peer now sends identical status-plus-page bytes in one write,
avoiding a small-header/queued-tail delayed-ACK artifact. Normal and hostile
wire-byte contracts cover that change, without changing any assessment limit.
The final expanded batch passed **355/355 on each of FreeBSD, Alma8 and macOS**,
with zero failures, errors or skips and one intentional legacy-TLS warning each.
Each controller recorded 355 collected and completed tests and a normal finish;
these remain focused regressions, not full-suite certification.

The subsequent RADOS namespace correction also builds as a full native
FreeBSD server/client target in a separate SDK. Root driver opens and probes
use the shared name-translation stage, and WebDAV metadata uses the canonical
VFS initializer. Its permanent translated-backend and cache-key regressions
do not require librados. The actual RADOS pool, cross-protocol transfers and
same-pool prefix isolation were exercised on the Alma8 ARM64 Ceph lab, **not**
on FreeBSD. See [the recorded correction](OPENSSL111.md#rados-namespace-correction--2026-10-18)
for evidence and the separately identified cache metadata limitations.
The cache metadata extension now keeps stat/probe on the credential-preserving
composed stack, matching cached read-open bytes even when origin metadata
changes or disappears. The final expanded selection passed **622/622** on
FreeBSD, Alma8 and macOS, with no failures, errors or skips. Controller counts
were conserved and all sessions finished normally. The C decorator fixture's
Darwin macro-safe call spelling also passed a separate native FreeBSD rerun;
no test assertion or server security policy was relaxed.

The final listener-ownership, reporter and PKI correction set passed **217/217**
under the non-wheel account, with no skips, failures or errors. A live parent
server remained reachable after child registry cleanup. Registry teardown
requires both listener identity and exact lane process ownership; an empty
child registry cannot authorize killing a foreign listener. This focused proof
does not establish the cause of the earlier interrupted full run.

XRootD 6.2.0 was checksum-verified and built strictly as an external dependency,
without inspecting or copying its implementation. Native Python 3.12 setuptools
and wheel retain the matching bindings. FreeBSD network declarations were
supplied through a compiler include flag; native `libexecinfo` resolves the
observed `backtrace` link dependency. No system XRootD package was replaced.
The private Python bindings import, but their nonzero-range probe still returns
a negative-offset error, and the new CLI segfaults on both version and copy
probes. These are unresolved reference-dependency results, not passing BriX
interoperability evidence. The approved isolated GCC 14 build retained Python
binding configuration but failed to compile because FreeBSD has no `ETIME`.
A compiler-only `ETIME=ETIMEDOUT` experiment then failed on duplicate switch
cases and was not retried. Neither build inspected or modified dependency
implementation sources; no working GCC-built reference client is claimed.
A subsequent isolated Clang build supplied byte-order compatibility definitions
through compiler flags only. Build, installation and Python binding import
succeeded, but `xrdcp --version` still terminated with SIGSEGV and the nonzero
range probe still received the negative-offset rejection. This experiment did
not replace the system packages or produce a working reference dependency.

## Full-suite repair follow-up — 2026-10-18

The latest full diagnostic was interrupted after it identified repeated
listener-inspection timeouts; its partial JUnit and failure records are retained.
It is not full-suite certification. A fresh server/client SDK and corrected
source snapshot are now running the canonical four-lane suite, including its
suite-job tests, under the non-wheel test account. That snapshot is frozen for
the duration of the run. No failing oracle was replaced with a BriX client and
no new platform skip or exclusion was introduced to hide a failure.

The completed correction selections establish the following narrower results:

- **308 passed**, with no failures, errors or skips: native MinIO STS credential
  issuance and refusal, listener/process ownership, interrupt-safe lifecycle
  cleanup, nested automount and strict refusal, FUSE trust/tamper checks,
  packaging-guard probes and successive cache-matrix module lifecycles.
- **160 passed**, with no failures, errors or skips: the full live FUSE POSIX
  surface, native xattr error propagation, PAL selection and CVMFS Geo/RTT
  corpus. This includes the formerly skipped loopback-listener tests.
- A separate **root-only device-access proof passed**. A non-devfs inode with
  `/dev/zero`'s device number cannot read the device: its bounded read returns
  EOF rather than a NUL byte. Opening that inert inode is not itself proof of
  device access. Native `nosuid` remains required on the child mount; FreeBSD
  does not advertise a fictitious `nodev` mount flag.
- **43 macOS portability contracts passed**, with no skips, including the
  production statfs callback and the shared fixture policies. This is not a
  macOS mount or full-suite result.
- A subsequent **66-test FreeBSD cache/automount selection passed**, with no
  failures, errors or skips. It includes the formerly skipped default-cache
  mount, all cache-directory/quota cases in that selection, both live automount
  scenarios and native shutdown/thread-creation error-path contracts. A matching
  **40-test macOS portability selection passed** without skips; it does not
  establish macOS mount support.

FreeBSD listener ownership now uses structured native `sockstat` output. A real
prefork probe confirmed that both socket owners are retained; the global psutil
connection table was rejected for this purpose because it omitted the parent.
Malformed or failed inspection is an error, never false quiescence. Interrupted
cleanup releases every owned registration and then re-raises the interruption.

The native MinIO lab uses private data/cert directories and an owned child
process, bound only to the test host. Explicit container or binary selections
remain authoritative. The VM has explicit loopback aliases for the two full-run
workers and the isolated correction worker; non-local binding was not enabled.
These aliases are test-host setup, not a server dependency.

The installed Python xattr package falsely reported successful mutations when
the actual native syscall returned `EROFS`. The test inspector now uses native
FreeBSD mutation calls and preserves their errors, fd/link targeting and binary
values; conditional updates remain unsupported. The server's read-only policy
was already refusing the operation and was not weakened. Native inspection also
accounts for FreeBSD's xattr list framing, permitted symlink metadata, kernel
dirent inode assignments and preferred I/O block size. CVMFS's production statfs
callback now explicitly sets its 4 KiB fragment size instead of leaving it zero.

The automount control thread now keeps the FUSE event loop running until its
owned unmount completes. FreeBSD's unmount needs a `FUSE_DESTROY` response;
calling `fuse_exit` first stranded that exchange during the full run. Native
thread-creation errors also no longer cause an uninitialized thread handle to
be joined or allow the mount to serve without its shutdown controller. C
regressions cover termination, child-first teardown, refused unmount, child
reaping, EOF and both thread-creation failure paths.

Default-cache validation checks write/search permission on the provisioned
`/var/lib/brixcvmfs` root, not write permission over all of `/var/lib`. CI creates
only that private test-account cache root. Each test owns an exclusive, unique
repository directory and removes only that directory, never an existing
operator repository cache.

The stock reference's xattr errors were also reproduced on a disposable native
UFS filesystem; changing the filesystem did not fix them. A black-box syscall
trace records `extattr_set_file` returning **6**, and native inspection confirms
the six-byte value was stored as `U.user.probe`, while the stock wire response
reports per-attribute error **3010**. The native API's successful return is a byte
count, as documented by [FreeBSD extattr(2)](https://man.freebsd.org/cgi/man.cgi?query=extattr_set_fd&sektion=2).
This diagnostic is not a passing interoperability result. No reference source
was inspected or changed, no return-value interposer was installed, and BriX's
successful storage behavior was not weakened to imitate the failing oracle.

Full-suite certification and complete external-reference interoperability remain
open until a complete corrected run and a working reference dependency establish
them. Passing focused selections must not be reported as zero-failure full runs.

The next full run collected **41,102** tests, but the VM subsequently entered an
out-of-memory kill loop. Its console repeatedly records nginx processes killed
because memory could not be reclaimed, and SSH stopped responding. Results
after that resource failure cannot certify server correctness. The frozen full
snapshot and separate corrected SDK are retained. The recovered controller
record contains **13,298/41,102** completed tests: **12,832 passed, 255 failed,
25 errored, 151 skipped and 35 XFAIL**. It never finished and has no final
JUnit report. No failed or interrupted run has been relabeled as passing.

Additional repairs are being validated separately: standalone BSD CVMFS test
builds include their shared FUSE policy source, and signed whitelist membership
now includes entries beyond the sixteen-entry inline cache without truncating
fingerprints or accepting bytes from the signature tail. The caller retains the
whitelist input until certificate membership has been checked. A local macOS
signed-corpus/build-contract selection passed **71**, with the **three** real
mount cases skipped because FSKit is inactive. After recovery, the native
FreeBSD CVMFS selection passed **90** with **zero skips**; it included real
FUSE mounts, signed whitelist rejection cases and the standalone client build.
That run also reproduced one GridFTP failure, corrected in the next batch.

The approved recovery changed only `brix-freebsd15-native`: **32 GiB RAM**, a
persistent **4 GiB ZFS ARC cap**, and a separate **8 GiB swap disk** in addition
to its original 1 GiB partition. Swap was not put on ZFS. The preserved pool
reports healthy, and all other Lima VMs were left untouched.

The GridFTP overflow was a real worker **SIGXFSZ** termination, not a timeout.
The VFS writer now bounds destination/source extents and cumulative accounting
before backend I/O, preserving read-only refusal precedence. Local locate
replies also resolve the accepted socket's actual address instead of advertising
a wildcard listener. The rebuilt FreeBSD server passed **84/84** combined
GridFTP/locate/native-C regressions, with no errors, failures or skips. The
13 new writer/locate C cases also passed on macOS. Four bounded fixture-read
contracts pass on both hosts: petabyte sparse output from the broken reference
daemon must produce a diagnostic failure, never an unbounded memory read.

Native full-mutation assessment on the default SA-xattr storage remains blocked
on an independently reproduced storage inconsistency: FreeBSD 15.1-p5 /
OpenZFS 2.4.2 native `extattr_set_file`
can report a complete successful write while a subsequent native read returns
an empty attribute after attribute pressure. This occurs without BriX and on
fresh diagnostic datasets using `xattr=sa`; `xattr=on` is an alias for `sa`, not
a distinct directory-storage test. Switching the compatibility naming tunable,
syncing and overwriting did not repair it. Base packages report up to date.
These are diagnostic observations, not passing storage/interoperability tests.

A controlled, direct-libc comparison now establishes a working configuration
on the same native kernel: create a dedicated export dataset with `xattr=dir`.
All **40** independently read 4 KiB attributes survive pressure, and binary,
64 KiB and empty values round-trip exactly. Missing-attribute and unprivileged
system-namespace writes preserve their native errors. The same probe on a
separate `xattr=sa` dataset acknowledges all writes but reads the later values
as empty. The previously failing BriX write/xattr and basic-query assessment
fixtures pass unchanged on the directory-xattr dataset: **3 passed**, no
failures, errors or skips. This is a supported storage-policy workaround, not
a repaired SA implementation. Existing lost attribute values are not recovered
by changing a dataset property. See the
[OpenZFS xattr policy documentation](https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Datasets/ACLs.html).

The older frozen diagnostic snapshot also lacked existing checkout fixes for
FreeBSD FUSE observations: native mount/fd inspection, preferred I/O block size,
kernel-populated directory inodes, native xattr probes and preservation of
mutation errors from the packaged Python adapter. Applying those fixtures to a
separate validation copy passed **80/80** native FUSE POSIX and adapter cases,
with no skips. In particular, read-only mutation checks still require `EROFS`;
they do not accept the adapter's former false-success result. The active full
diagnostic remains associated with its original snapshot, not these fixes.

The complete current checkout was then rebuilt natively in separate source/SDK
directories. Its combined FUSE, xattr assessment, writer/locate and bounded-read
selection passed **99/99**, with no skips. A subsequent native ownership/CVMFS
selection passed **192/192**, also without skips. FreeBSD `sockstat -l` includes
CLOSED unbound/bound sockets; ownership inspection now requests connection
state and accepts only LISTEN rows. Malformed state still fails closed, and a
PID/creation-time liveness recheck discards already-exited process snapshots
without treating an unreadable live owner's environment as empty.

An approved isolated OpenZFS investigation has also built the checksum-verified
**2.4.4** release against the exact 15.1-p5 kernel headers, using the official
FreeBSD port's `time32_t` compatibility adjustment. Pre-boot symbol inspection
rejected its default INVARIANTS build: it needs `witness_save`/`witness_restore`,
which this kernel does not export. The inactive `brix-zfs-investigate-20261018`
boot environment's original loader settings were restored. A fresh build with
INVARIANTS disabled was initially interrupted by the OOM event. After recovery,
that isolated build completed: the ARM64 module's **457** undefined symbols all
resolve against the original kernel and its non-ZFS loaded dependencies, with
no WITNESS references. This is a necessary link-closure check, not an ABI or
runtime certification. The subsequent isolated boot and its results are recorded
below. No pool feature upgrade was performed, and no assertion, credential
policy, skip or assessment budget was changed.

The frozen four-lane diagnostic was interrupted by another native OOM event,
after **15,359/41,133** cases: **14,579 passed, 519 failed, 13 errored, 213
skipped and 35 XFAIL**. These are incomplete progress counts, not certification
of the current checkout. The largest process was its pytest worker reading
the broken reference daemon's **16 TiB** sparse output to EOF in the truncate
corpus; it occupied about **29 GiB** RSS and exhausted all **9 GiB** swap.
Those truncate comparisons, and the remaining direct EOF comparisons in the
differential corpora, now use the existing bounded fixture reader. Static
regressions cover all **86** differential test/helper files. The false reference
output must fail visibly before allocation; expected byte comparisons are
unchanged.

The approved restart recovered only `brix-freebsd15-native`, booting the original
15.1-p5 kernel and OpenZFS 2.4.2 from the `default` boot environment. All 9 GiB
swap was empty afterward, the pool was healthy, and source/SDK/report directories
were preserved. The actual retained 16 TiB failure fixture is now rejected in
about **60 microseconds**, with no peak-RSS growth. Bounded-reader/static
contracts passed **91/91** on both macOS and FreeBSD. Native post-recovery
ownership, writer/locate and live mutation/query regressions passed **159/159**,
with no failures, errors or skips.

A fresh execution of the formerly OOM-producing sparse case finishes safely:
**2 passed, 1 failed**, no errors or skips, in about 11 seconds. Its two unchanged
invalid-handle checks pass. BriX's sparse file is exactly 1,048,640 bytes with
the correct zero-filled hole and payload; the native reference daemon again
creates a 16 TiB sparse file, now rejected by the fixture reader before content
allocation. That reference failure is retained, not converted to a pass.

A new complete canonical run uses the frozen current source/SDK on a separate
`xattr=dir` dataset, with a short socket-safe path and a 20 GiB quota. Its built
server passed `nginx -t` and the byte-exact `root://` smoke transfer before suite
startup. Its final and interrupted lane counts are recorded below; it is not
a green full-suite result. No other VM or project Git state was changed.

## Native validation and isolated ZFS trial — 2026-10-19

The four-lane V118 run completed its first two lanes, but stalled in the
cross-protocol resilience workload in lane three. Lane four never ran. These
are pytest outcome counts, with XPASS/XFAIL kept separate from pass/skip:

| Lane | Completed | Passed | Failed | Errors | Skipped | XFAIL | XPASS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Main | 41,246 | 37,649 | 2,213 | 408 | 925 | 43 | 8 |
| Serial | 6,180 | 5,733 | 82 | 13 | 352 | 0 | 0 |
| Resilience, interrupted | 33 of 186 | 27 | 4 | 0 | 2 | 0 | 0 |

Both finished lanes have final JUnit reports; the interrupted lane has progress
and failure records only. Host copies are retained under
`build/release-validation/freebsd-full-v118-audit-20261019`. The results include
external-reference defects, native test-build problems, and network timeouts;
they must not all be attributed to one cause without reproducing it.

The approved one-shot boot successfully loaded OpenZFS **2.4.4-1** in the
isolated investigation environment after rebuilding its module with the native
LLVM linker. An earlier GNU-binutils-linked candidate failed to load and was
retained separately. The working module SHA-256 is
`e65145bd98631898bfa1e5cb37931e7a2fd6e7739244cfca2843ab804c4831d5`.
The original `default` environment remained the persistent boot target.

The newer module **did not fix** either observed ZFS problem. The independent
native SA-xattr probe still loses acknowledged values, while the directory-xattr
probe still passes. The unchanged cross-protocol assault also stalled: nginx
threads wait in `zfs_freebsd_getpages`/`zfs_rangelock_enter_impl` from `sendfile`,
while a writer waits in `update_pages`/`zfs_write`; an unlink waits on the vnode.
Swap was empty and the pool reported healthy. Kernel stacks and bounded logs
were preserved before restarting only this VM into the original **2.4.2**
`default` environment. No replacement module is active and no pool was upgraded.
Directory xattrs address the observed metadata problem, not this I/O stall.

Separate corrections on the rebuilt native server/client SDK established:

- **74 passed, one skipped**, no failures or errors: OCI flatten/stargz and
  object/query units. The skip is the unavailable container oracle. The existing
  atomic-exchange unit was explicitly deselected from this focused run and
  remains unresolved; it is not included as a pass.
- **69 passed, one skipped**, no failures or errors: fail2ban regex, RPM parsing
  and repository generation, and real supplementary-group authorization. Native
  `rpm4` and `py312-fail2ban` packages and a dedicated nonprivileged supplementary
  group enabled the formerly missing prerequisites. The remaining skip requires
  Linux DNF/user namespaces; no firewall service was enabled.
- **278 passed**, no failures, errors or skips: CMS resilience and delayed
  discovery, authenticated WebDAV security/operations, token security and S3
  status codes. The reconnect assertion now waits for the second parsed LOGIN
  within its unchanged 20-second budget, and still requires a fresh connection;
  socket acceptance alone raced the peer's reader thread. Three deterministic
  observation regressions also pass on macOS. These isolated successes do not
  explain every timeout in the earlier full run.
- **42 macOS object/query units** and **33 macOS OCI/toolchain cases** passed;
  the latter selection also has one unavailable container-oracle skip.

Standalone units now link the real FreeBSD xattr adapter and retain the selected
SDK's dependency include paths. Query-readiness units retain ASan/UBSan and
explicitly close unreachable translation-unit link boundaries. OCI confinement
also classifies native `EMLINK` as a refused no-follow descent, without changing
the outside-tree or error assertions. The real native build enables nginx's
`auth_request` module; its separate eight-case live selection passed. These
focused results do not establish full-suite or complete-reference certification.
The native 15.1-RELEASE headers expose exclusive rename but not atomic exchange.
At that point, the exchange unit still required a successful swap and remained
red. The approved unsupported-capability contract below resolves that test
without adding a multi-rename emulation or claiming native exchange support.

### Scoped sendfile safety correction

The approved fallback detects the actual descriptor's filesystem in the PAL.
FreeBSD ZFS and failed/unknown filesystem inspection select buffered transfer;
UFS and other hosts retain their normal path. There is no guessed kernel-version
threshold: both tested OpenZFS releases failed. Read-only opens are not exempt,
because concurrent writers can use another handle or protocol.

Root reads use the existing bounded buffered/windowed strategy. HTTP keeps the
backend fd and existing range/cleanup contracts, but disables sendfile only in
that request's nginx copy-filter context. nginx continues to own its bounded
buffers, AIO and backpressure. The connection's sendfile flag is untouched, so
another HTTP/2 stream or subsequent UFS request cannot undo the ZFS veto or
inherit an unnecessary global disable. Multipart WebDAV/S3, stored ZIP members
and diagnostic file responses use the same guarded output edge.

Native ZFS verification passed **89/89**, with no failures, errors or skips:
all eight hostile-actor cases, the TLS/range matrix and fifteen sanitizer/policy
contracts. The unchanged 25-second cross-protocol assault no longer kernel-
stalls, and the final integrity check passes. A separate actual-PAL probe reports
`sendfile_safe=0` on ZFS and `sendfile_safe=1` on a disposable UFS volume. The
unchanged UFS matrix passed **66/66**. On macOS, the fifteen contracts and all
**66** live matrix cases passed. These focused results do not yet certify the
complete suite. The SA-xattr problem still requires directory-xattr storage.

These are bounded validation results, not a claim that every Linux-specific
feature or every optional external integration has been certified on FreeBSD.

### Capability and coverage follow-up

The exchange unit now probes the OS independently of BriX before selecting its
expectations. All successful file/file and populated-directory swap assertions
remain on capable systems. Native FreeBSD instead verifies `ENOTSUP`, unchanged
inodes and content, no half-created missing names, and all three outside-root
confinement refusals. The real-object unit passes on both FreeBSD and macOS;
the latter exercises actual successful swaps. No skip was added.

A clean disposable snapshot passed **149/149** native CI/safety checks, with
the three separately scheduled slow coverage-build jobs deselected. Removing
AppleDouble transport artifacts repairs the source/doc gates without changing
their rules. The active full-run snapshot is retained unchanged, including
its artifact-related failures; these focused results do not replace that run.

Enabling real cross-device coverage exposed a native teardown mismatch:
FreeBSD labels a copied nginx worker `nginx-<session-id>: worker process`, not
only `nginx: worker process`. The shared role classifier now recognizes exact
native spellings. Cleanup still requires both test-root ownership and an owned
declared listener; a worker-like argument or another lane does not authorize a
signal. The corrected native batch passed **82/82**, including all nine
cross-device uploads, error/traversal refusals, and real corruption detection.
The macOS teardown/control batch passed **72/72**. A separate root-only native
device-policy proof passed **1/1**; the ordinary full suite remains non-root.
These reports are retained under
`build/release-validation/freebsd-native-coverage-20261019`.

The corruption fixture now uses the runner-selected nginx rather than an old
Linux SDK path. The hostile-origin comparison also resolves the selected stock
reference client through the existing independent reference helper; it does
not substitute BriX's client to obtain interoperability coverage.

Final launcher/workflow/reference-setup contracts passed **132/132** separately
on FreeBSD and macOS. Both launcher facades now share interrupt-safe teardown:
all owned registrations are released before the first timeout/interrupt is
re-raised. Reference resilience fixtures use the same numeric listener-family
selection and FreeBSD buffered transport policy as the registry; a failed
fixture entry reaps only its spawned child. Independent native cache/range,
offline-cache and reload-during-fill verification passed **19/19**.

The approved fresh Clang **Debug** XRootD 6.2.0 build completed with `-O0 -g`,
no LTO, native LLVM linking and matching Python bindings, but did not repair
the reference defects. Its CLI still dies with `SIGSEGV` even for `--version`.
The Debug binding additionally needs the native `libexecinfo` runtime loaded;
with that dependency, NSS prewarming and explicit IPv4 selection, its offset
1000 range still receives BriX's correct `negative read offset` rejection.
These failures are retained, not skipped or counted as passes. Only generated
build/link metadata and black-box behavior were inspected; no reference
implementation source was consulted or changed.

The newly enabled native hostile-origin baseline now starts, but still errors:
a cache fill against the native official origin ends at one of four MiB. BriX
rejects the short object instead of publishing it as a complete cache entry.
An independent raw-wire probe reproduces the native reference server's range
defect without the cache or stock client: it serves offset zero correctly, but
returns empty bytes at offset 1 MiB in a two-MiB object. That failing diagnostic
is retained separately from the passing native BriX range/cache checks.
The cache-baseline diagnostic completed **132 passed, one setup error**; the separate
132-contract result above excludes the failing baseline explicitly. Complete
native-reference interoperability and zero-failure full-suite certification
remain outstanding.

### Optional external official-client validation

`tools/ci/remote_reference_target.py` and `tools/ci/remote_reference.py` provide
an **opt-in, separate** interoperability check. BriX and its modules execute
natively on the FreeBSD kernel, as the non-root test user. Independently
installed official XRootD CLI tools and Python bindings execute on a working
macOS/Linux client host. This does not replace the full native suite, turn
native reference failures into passes, or certify a complete release.

Start the leased target from the FreeBSD source snapshot, using the built SDK
and a private scratch filesystem with reliable xattrs:

```sh
python3 -m tools.ci.remote_reference_target \
  --build-dir /path/to/native-sdk --scratch-base /path/to/test-scratch \
  --port-start 2000 --lease-seconds 900 --with-gsi
```

The helper binds **loopback only**, uses an isolated registry and ephemeral
test PKI, and prints one JSON readiness record. Preserve that record as
`server-evidence.json`. Forward its selected endpoint ports with operator-owned
SSH `-L 127.0.0.1:LOCAL_PORT:127.0.0.1:NATIVE_PORT` options; do not expose them
publicly or enable an SSH service on the client host. Keep this helper's port
lane separate from any ongoing native suite. Its lease is bounded to at most
30 minutes; SIGTERM also closes only its owned harness.

On the client host, select **official** tools, not the BriX replacements:

```sh
python3 -m tools.ci.remote_reference \
  --url root://localhost:LOCAL_WRITE_PORT/ \
  --read-only-url root://localhost:LOCAL_READONLY_PORT/ \
  --server-evidence /private/path/server-evidence.json \
  --xrdcp /path/to/official/xrdcp --xrdfs /path/to/official/xrdfs \
  --client-python /path/to/python-with-official-XRootD-bindings \
  --profile anonymous --output build/release-validation
```

For GSI, securely copy **only** the generated ephemeral proxy and the
readiness record's `public-ca` directory into a mode-0700 client directory;
the proxy must be owned by the client user and mode 0600 or stricter. Never
copy the CA private key or server private key. Add `--profile gsi --proxy
/private/path/proxy.pem --ca-dir /private/path/public-ca`, using the GSI
endpoint's forward instead. For GSI+TLS select its endpoint, `roots://`, and
`--profile gsi-tls`. Delete these disposable credential copies afterward.
Do not use production credentials or a production export for this check.

The runner clears ambient credential overrides, disallows TLS downgrade/data
plaintext controls, verifies independent `libXrdCl` linkage and matching CLI/
Python versions, and records native server artifact and external client binary
hashes. Assertions must remain enabled: optimized Python (`-O`) is refused.
Mutations and cleanup use one exclusively created UUID namespace; cleanup
never recursively deletes a server-provided listing. JSON/JUnit contain all
passes, failures and errors, explicitly marked `native_full_suite=false`.
After teardown the target retains `final.json`, reporting unchanged fixture
and outside-sentinel content and any remaining test namespaces.

The live ARM64 proof using official Homebrew XRootD **6.2.0** passed
**29/29 anonymous, 29/29 GSI, and 29/29 GSI+TLS**: **87 passed, zero failed,
zero errors, zero skipped**. Coverage includes scalar/vector/nonzero-offset
reads, multi-MiB CLI upload/download, checksum-verified copies, sparse writes,
six truncation boundaries, handle/path metadata, rename/remove, real native
xattr round trips and missing attributes, missing/outside-export refusals,
read-only mutation refusals, and explicit authentication refusals.

The cleartext GSI negative removes its test credentials and pooled session.
The TLS negative instead offers Unix authentication where the server requires
GSI, retaining a valid TLS identity: pointing XrdCl at a nonexistent certificate
only fails its **local** TLS initialization and proves no server refusal.
The official CLI does not provide BriX's `--pgrw` flag; this mode therefore
claims whole-file checksum verification, **not** independent page-CRC testing.
Native page-I/O/wire tests remain separate and unchanged. Failed initial runner
diagnostics and native reference failures are retained beside the corrected
results under `build/release-validation/freebsd-remote-reference-20261019`.

The native preload directory/stdio checks also exposed a test demanding
glibc-only `fopen64`/`freopen64`/`readdir64` on FreeBSD. The corrected test
requires each platform's actual libc entry points; ordinary 64-bit `off_t`
coverage remains on FreeBSD, and Linux still requires all LFS aliases. The
preload/runtime and runner-control batch passed **63/63** on each of FreeBSD
and macOS without a skip.

The standalone lock inventory now reads FreeBSD's native user xattrs through
the installed `py-xattr` package, with no symlink following. Missing attributes
remain absent; unsupported APIs, unreadable attributes and inaccessible
subtrees produce exit **2**, not a false clean inventory. Error diagnostics
do not print attribute contents or lock tokens. The final combined tool and
runtime regression batch passed **95/95** on each host, with no skips. The final
live external-reference repeat again passed **87/87**; its native teardown
evidence confirms unchanged reference/sentinel bytes and no remaining test
namespaces (`transport-o7hmtn4l/server-final.json`).

The ongoing full-run inventory found two further harness issues. Tests planting
"prior-run" leftovers now backdate relative to import time as well as wall
time; after an hour-long lane, an hour-old file can otherwise still belong to
that same run and must remain protected by the janitor. RAM-cache metric tests
now honor the explicitly selected client binaries instead of PATH, and verify
plain `kXR_read` and CRC-checked `pgread` directly through the existing wire
helpers. These are native cache/worker-survival checks, not replacement official
interoperability verdicts. The focused pair passed **19/19** independently on
FreeBSD and macOS. The failed native-binding diagnostic is retained separately;
no native reference failure has been relabeled as an interoperability pass.

Clean-snapshot mutation/auth boundary source checks passed **59/59** with
unchanged gate rules. A further HTTP-origin failure was a fixture lifecycle
bug: closing a `ThreadingHTTPServer` listener left already accepted HTTP/1.1
handlers answering requests, so the supposedly unreachable origin was still
reachable over a pooled connection. The paced origin now closes its own
accepted sockets too. Healthy response, keep-alive closure and foreign-origin
isolation checks accompany the unchanged origin-failure/deadline and
reload-during-fill workloads: **13/13 passed** on each of FreeBSD and macOS,
including the original 60-second deadline bounds. The frozen full-run source
and SDK safety-critical hashes remain unchanged.

The reserve module now attributes advisory log entries to the operation under
test instead of blaming a later undeclared write for an earlier unsupported
reservation. Its initial diagnostic result (**six passed, one failed** on
FreeBSD; **7/7** on macOS) is retained. The subsequently approved native
capability contract resolves that assertion without pretending FreeBSD can
reserve beyond EOF while preserving file size.

An independent native probe exercises the actual export filesystem: Linux's
KEEP_SIZE allocation and Darwin's F_PREALLOCATE must still allocate the full
declared amount without changing EOF. FreeBSD's POSIX allocation operation is
also exercised, but its EOF-extension semantics are not classified as KEEP_SIZE.
The separately linked **real** BriX PAL must agree with that oracle. On
unsupported filesystems it must return EOPNOTSUPP and preserve existing bytes,
inode, ownership/mode, file offset, size, block allocation and modification/
change timestamps. The live write must continue with one explicit unsupported
advisory, remain byte-exact and have only its written length. An always-refusing
PAL cannot hide a working native allocator; a successful no-op or an arbitrary
I/O failure cannot masquerade as support or an unavailable capability.

The final reserve/capacity-preflight batch passed **27/27** independently on
FreeBSD and macOS: **zero failed, errored or skipped**. Probe arguments are
bounded to 8 MiB and malformed sizes/modes/descriptors are rejected. The original
oversized-declaration refusal, partial-allocation release, quota, read-only
refusal and successful-allocation assertions remain. No unsafe extend/truncate
emulation or skip was added. These focused results do not certify a zero-failure
full native release result.

The V152 full run was stopped with operator approval after **23,887 of 41,287**
collected cases completed: **22,373 passed, 789 failed, 81 errored, 596 skipped,
40 xfailed and eight xpassed**. This is an **interrupted inventory**, not a full
suite result. Its JUnit, failure journal and progress record are retained in
`build/release-validation/freebsd-native-coverage-20261019`.

The native reference's malformed write offsets left a **192 TiB sparse AIO
fixture**. Worker backtraces confirmed two whole-object checksum jobs consuming
both file-I/O threads; subsequent otherwise-working transfers queued behind
them. AIO readback now checks its independent expected length before issuing an
explicitly bounded read, and offset-write fixtures have private namespaces which
are removed even on failure. File-API disk comparisons and hashes use the same
bounded fixture reader as the differential corpus. No offset, length, content or
checksum assertion was weakened, and no failure became a skip.

The isolated native AIO repeat still records its **six reference-client
failures**, followed by **13/13 compression edge passes**. The bounded file-API
repeat records **nine reference-client failures and 138 passes**, including the
reader controls and the same compression checks. macOS passed the corresponding
**114/114 AIO/reader** and **134/134 file-API/reader** batches. The invalid native
offsets remain unresolved; BriX must not accept a nonstandard byte order to hide
them. The observed checksum work-isolation/admission problem also remains open:
fixture cleanup prevents this cross-test contamination but is **not** a server
capacity fix. A clean corrected-snapshot full rerun is required.

The final focused batch additionally checks endpoint-based cleanup (including
writer failure, refused cleanup and foreign-file isolation), so remote testing
does not depend on a locally mounted export. Read budgets remain enforced under
optimized Python too. Including the reserve/preflight checks, macOS passed
**192/192**; FreeBSD recorded **177 passed and the same 15 native-reference
failures**, with **zero errors or skips**. The failure names match the earlier
AIO/file-API diagnostic union exactly. These are focused results, not a full
suite verdict.

The V200 canonical rerun is in progress from a separate immutable snapshot,
with the same native SDK, two workers and all four scheduled lanes/suite jobs.
It includes bounded AIO/file-API reads and private local write namespaces; the
subsequent remote-portable cleanup controls above were verified separately and
were not overlaid onto that running snapshot. Final full-run counts remain
pending under `/var/tmp/brix-freebsd-full-v200-results` in the dedicated VM.

### Checksum admission and proxy lifecycle correction checkpoint (V214)

A separate fresh native SDK now carries three checksum corrections. A full
configured worker queue returns a one-second `kXR_wait` for path, handle and
scan requests instead of computing synchronously on nginx's event loop. Each
connection owns one reusable checksum task, with active-task overlap refused
and heap storage released at connection-pool teardown. Path-based async
checksums now carry the same typed export mutation policy as handle-based
checksums: writable exports persist their digest cache, while read-only exports
answer correctly without changing export metadata. Long-running admitted jobs
still share the I/O pool; dedicated capacity and cancellation remain open.

The fresh FreeBSD build and incremental macOS build passed the same **86/86**
focused checks: native scheduling/ownership controls under ASan/UBSan, live
checksum queries and plugin loading, configuration, handle isolation and exact
cache-accounting windows. The accounting test now uses the suite's independent
wire helper instead of the defective native reference binding. Its original
250-byte read assertion remains, with first/last-byte, invalid-offset and
confinement controls added; official interoperability assertions are unchanged.

An additional real one-thread/zero-queue lab holds one checksum worker using a
bounded test plugin. All three checksum forms retry while metadata health
queries remain responsive; an invalid handle is refused, and the same valid
handle works after release. Four live cache-policy cases cover path/handle
requests on writable/read-only exports. This final batch, including proxy
lifecycle controls, passed **32/32 on macOS** and **33/33 on FreeBSD**, the latter
also running the installed Squid and Varnish CVMFS baseline scenario. There
were **zero failures, errors or skips** in either focused batch.

Varnish now runs in the foreground under the harness's process owner. Its
FreeBSD process-title rewrite made the previous argv-matching cleanup miss the
daemon, leaving a listener that broke a later suite. The stale V152 manager
was positively attributed to that disposable run before targeted termination;
no unrelated VM or workload was stopped. Baseline teardown no longer matches
process titles or signals a guessed listener owner.

JUnit and console/build evidence is retained under the ignored
`build/release-validation/freebsd-native-coverage-20261019` artifact directory.
These corrections were **not overlaid onto the running V200 snapshot**. Native
reference byte-order, startup, xattr and copy failures remain visible; neither
these focused passes nor the separate remote-reference passes certify a green
full native suite.

After final test decomposition, the combined selection passed **98/98 on
FreeBSD** and **97/97 on macOS**, with zero failures, errors or skips. The
rebuilt native FreeBSD server also passed **87/87 official external-client
checks** (29 each for anonymous, GSI and GSI-TLS), again with zero failures,
errors or skips. The external run verified teardown of all its servers and
namespaces, preservation of its reference file and outside sentinel, and
cleanup of the host's ephemeral credential copies. Its evidence is retained in
`build/release-validation/freebsd-remote-reference-20261019/transport-_creojoz`;
it remains explicitly separate from native full-suite certification.

### Metadata, process ownership and native FUSE follow-up (V234)

Expanding the independent official-client check found an actual metadata bug:
a short logical attribute name with an 8 KiB value was retrievable but missing
from listing. Large values use the same hashed representation as long names;
listing incorrectly required the name itself to need wrapping. It now checks
the exact physical SHA-256 key for either reason. Native/macOS tests exercise
2048/2049/8192-byte boundaries, an empty sibling, missing chunks and a forged
name envelope. All **90/90** expanded external checks pass (30 per anonymous,
GSI and GSI-TLS profile), including batch get/list/remove, Unicode, empty and
large values, and metadata-write refusal on the read-only endpoint. Evidence:
`build/release-validation/freebsd-remote-reference-20261019/transport-m6wvhhpc`.

FreeBSD process inspection now handles `kvm_getenvv` returning EBUSY for one
process without losing the rest of the snapshot. A vanished PID is ignored
only after the native lifetime check; a live owned process with unreadable
environment remains explicitly unknown, never an empty/foreign declaration.
The ownership gate refreshes an unknown snapshot once before refusing it, so
an exec/exit race does not become a permanent cached refusal. Still-unknown
owners continue to prevent cleanup. Native default anonymous-port detection
also removes the previous unknown-range skip; its refusal cannot recommend a
lower base which still overlaps the kernel's range.

The final combined corrected-build selection passed **235/235 on FreeBSD** and
**234/234 on macOS**, with zero failures, errors or skips. Reports and the
unsuccessful CMS `-p` diagnostic are retained under
`build/release-validation/freebsd-native-coverage-20261019`. The ineffective
CMS CLI experiment and its command-only tests were removed; no claim is made
that they repaired the running native mesh.

The full inventory subsequently found a separate standalone CVMFS-overlay link
failure: its source list omitted the native FreeBSD xattr adapter referenced
by copy-up. The standalone builder now uses the existing PAL dependency
selector; the umbrella keeps its adapter in the client archive, with no
duplicate body. Dependency-discovery failures remain hard errors. The real
FreeBSD writable/persistent/read-only FUSE overlay and dependency controls
passed **17/17**, with zero failures, errors or skips; macOS passed **16/16**
dependency controls. This is not a macOS FUSE-mount claim. These focused
results still do not erase the incomplete V200 run or its native reference
and topology failures.

### Tape enumeration and hybrid listener correction (V243)

The full inventory found an actual native tape-listing failure. The streaming
`dread` launcher still enumerated `/proc/self/fd` rather than using the shared
spawn PAL. It now uses `brix_plat_spawn_closefrom`, retaining descriptor closure
and propagating setup/spawn failures. The live directory-listing tests cover
successful file/directory names, a missing command, and a stage process that
refuses inherited server sockets. Together with the purge-policy regressions,
the corrected native build passed **41/41**, without failures, errors or skips.
macOS passed **30** in that selection, with **11** explicit hardened-worker
subprocess skips; those skipped cases are not claimed as validated there.

The hybrid mesh has a second reference-daemon launcher, separate from the CMS
mesh launcher. It omitted the existing numeric-endpoint address-family helper,
so the native reference daemons opened IPv6-only front doors for IPv4 fixture
endpoints. Both daemon commands now use that helper. Its address-family and
error-propagation controls, together with the reference resilience controls,
pass **17/17 on FreeBSD and macOS**. A separate native black-box probe confirms
an IPv4 root handshake, the expected TLS certificate on the HTTP front door,
and the declared CMS manager listener; it closes only its two identified
reference processes afterward. This proves listener readiness, not successful
completion of the entire hybrid interoperability topology. Existing V200
topology errors remain in that frozen run's report.

### Native build closure and test-lifetime follow-up (V257)

The corrected ownership selection passed **81/81 on both FreeBSD and macOS**.
FreeBSD environment inspection retries only an EBUSY process, at most three
times over 60 ms; persistent uncertainty still refuses cleanup. The teardown
fixture also now waits for its exact `Popen` children after signalling them,
before asking the ownership gate to inspect the host again. An already-exited
child is reaped, while a child-exit timeout remains an error.

Native command-unit dependency closures now include the FreeBSD xattr owner
for source-linked overlay and object-linked cache reaper/watermark helpers.
The Ceph codec recipe test uses the existing GNU-make selector; its normal,
ASan/UBSan and compiler-error cases run natively. Runtime-path assertions allow
unrelated absolute platform SDK paths, but still reject empty/relative paths.

Fuzz recipes select the actual PAL host and resolve their requested dependency
SDKs for both the smoke and corpus-minimization entry points. ZIP/tar/RPM
inputs use the maintained anonymous-descriptor helper instead of calling a
Linux-only primitive. The known-answer parser test now includes the owned wire
flags and uses the selected OpenSSL SDK; a build error is no longer reported
as a missing-header skip. With Homebrew LLVM on PATH, the expanded macOS
build/fuzz selection passed **98/98**, with no failures, errors or skips. This
includes all corpus minimizations and the sanitizer known-answer assertions.
At that checkpoint FreeBSD passed **94** of the corresponding selection, with one failure in the
unavailable full-width TCP byte-counter assertion and three Darwin-specific
discovery skips. The unsupported-counter assertion was subsequently corrected
with operator approval, as recorded below; no counter was manufactured.

The full hybrid-file rerun now gets past setup: **4 passed, 7 failed**, with
zero setup errors or skips. S3 round-trip, S3-to-WebDAV, HTTP idle handoff and
direct-backend equivalence pass. Native reference connection/copy failures and
the resulting component-usage shortfall remain visible. These focused repairs
do not change the frozen V200 full-suite verdict. Its dedicated test-dataset
quota was increased to **28 GiB** to retain all evidence and finish validation;
no pool features or boot environment were changed. The later approved
temporary anonymous-port adjustment is recorded below.

The latest rebuilt native module also passed the separate official-client
comparison again: **90/90** across anonymous, GSI and GSI-TLS. The target's
fixture and outside sentinel remain unchanged, its private namespaces are
empty afterward, and its servers are closed. Evidence:
`build/release-validation/freebsd-remote-reference-20261019/transport-espzbfzg`.
This remains separate from the incomplete native full-suite run.

### Native timeout, dependency and FUSE follow-up (V277)

With operator approval the dedicated VM's temporary default anonymous-port
range changed from **10000–65535 to 32768–65535**. The original values are
retained in `/tmp/brix-freebsd-temporary-portrange-v260.log` on the host. No
boot setting or other VM was changed; existing reference listeners were not
relocated. Exactly the three approved n2n config templates were staged, with
all 12,228 previous index entries preserved. No tracked edit was staged, and
no commit or push was made.

The complete exhaustive policy/configuration selection finished with
**77 passed, 1 skipped**, retaining all sweep domains and budgets, including
the 32-bit flag/form sweeps and their mutation checks. The skip is Linux-only
seccomp enforcement. The native ZIP selection now passes **20/20** on both
FreeBSD and macOS instead of treating missing Linux `ss` as a dead listener.

The native TCP test now verifies FreeBSD's explicit `ENOTSUP` with zero outputs
after a real bidirectional transfer, as approved. Supported hosts still must
report measured transferred bytes. Invalid descriptors, UDP sockets and NULL
outputs remain checked, not skipped.

The pending-connect fixture uses a root-owned disposable VNET jail and epair.
Only that jail drops SYNs to closed ports. The server/tests run as the dedicated
non-wheel user, retaining that account's own groups, not root's groups. Exact
jail/interface ownership is checked before removal, including partial setup
and child-failure paths. The host TCP blackhole sysctl, firewall and persistent
network configuration are not changed. Missing/unresponsive fixtures fail;
they do not fall back to FreeBSD's actively refusing full accept queue.
The original 400 ms, 10 s and 30 s CMS deadlines remain unchanged. A public
native TCP PCB observer also reads the real `SO_KEEPALIVE` flag; a nonzero
idle timer by itself is not counted as an enabled option. Its initial combined
CMS/fixture run passed **34 tests**, with only the genuinely Linux-only
`TCP_USER_TIMEOUT` integration skipped. Full FreeBSD CI now provisions the
isolated peer around its non-root command.

The C-regression launcher now uses the existing dependency-SDK selector for
curl, compression and crypto rather than assuming `/usr/lib`. Pblock units
use the portable xattr definitions and the correct shared-platform symbol
owner. Their four-process/100-file concurrency test execs fresh writers so
they do not inherit SQLite's live locking state. The checksum-cache unit
injects precise unsupported, invalid-descriptor, I/O and read-only errors:
only the documented unsupported/permission cases reach its record fallback.
The final combined FreeBSD C-unit/metadata/observer/handle/CMS selection passed
**137 tests**, with only the Linux-only kernel user-timeout check skipped.
The corresponding macOS C-unit/TCP/offline-fixture selection passed
**116/116**. These are overlapping focused batches, not counts to sum into a
full-suite verdict.

The native FUSE rerun exposed additional real and harness failures. Portable
stat/process inspection and full-input daemonized writes are repaired;
daemon cleanup now signals only its exact PID/creation-time identity. HTTP
mounts no longer pass inode zero to native directory entries: WebDAV supplies
no stable file id. The initial `use_ino` correction was subsequently replaced
by the low-level identity adapter described below. Listing, stable nonzero
identity, missing-path refusal, read-only
policy and all daemonized tests now pass: **15 passed, 3 skipped**. Those
three skips are the explicitly opt-in external XrdHttp comparison, not BriX
HTTP coverage. The corrected client also builds on macOS; no macOS FUSE
mount is claimed while the extension remains unavailable.

Two limitations remain visible in the native FUSE selection: this kernel
rejects regular-file `mknod` with `EINVAL` even in an ordinary native directory,
and the high-level libfuse hard-link reply has a different node ID from the
source. The backing server creates the correct shared inode, but FreeBSD
rejects that reply with `EIO`. At this checkpoint those decisions were pending;
the following update implements the approved independent capability checks
and identity-aware low-level path. Original failures remain in frozen reports,
not relabelled as passes.

The missing GFAL2 dependency was also investigated in a separate build prefix.
Only new GLib, json-c, Crypto++, LDAP and SASL prerequisites were installed;
no existing package was upgraded. Official GFAL2 2.23.5 build metadata was
configured against the installed public XRootD SDK without inspecting XRootD
implementation sources. Compilation then failed on GFAL2's glibc/xattr-header
assumptions. Its HTTP plugin additionally needs a Davix copy library absent
from the installed native package. GFAL2 is **not built or validated**, so the
117 main-lane GFAL2 skips have not been removed or claimed as passes.

V200's frozen main lane had finalized at this checkpoint. All four lanes have
since finished; their final results are recorded below.
The main JUnit contains **41,418 records: 39,718 passed, 867 failed, 56 errors,
777 skipped**. JUnit skips include 45 expected failures; its extra teardown
records differ from the 41,415 unique collected node IDs. Later corrected
focused results do not overwrite these original failures. A complete corrected
canonical run, native reference-client defects and the remaining FUSE work
are still outstanding: **FreeBSD full-suite certification is not complete**.

### Low-level FUSE identity and completed original full run (V295)

All four lanes of the frozen V200 run completed. Its JUnit totals are
**48,788 records: 46,331 passed, 1,233 failed, 74 errors, 1,150 skipped**.
Skipped records include 49 expected failures. Reports are complete, but the
run is **not green**. Original reports and failure journals are preserved under
`build/release-validation/freebsd-native-coverage-20261019/native-full-v200-final`.

| Lane | Records | Passed | Failed | Errors | Skipped |
| --- | ---: | ---: | ---: | ---: | ---: |
| Main | 41,418 | 39,718 | 867 | 56 | 777 |
| Serial | 6,180 | 5,733 | 83 | 18 | 346 |
| Destructive | 186 | 163 | 7 | 0 | 16 |
| Client conformance | 1,004 | 717 | 276 | 0 | 11 |

The approved correction replaces the default async driver's high-level
path-based node allocation with a shared low-level FUSE adapter. Hard-link
aliases return the source's kernel node ID. A bounded mount-owned registry
tracks lookup and open owners independently; aliases and subtree rename keys
are reserved before mutations. Namespace operations serialize with registry
changes, while data I/O retains per-handle locks and retries. Server IDs and
checked WebDAV path candidates give directory listings nonzero, stable inode
hints without treating an unknown ID or a hash collision as alias identity.
The explicitly selected legacy driver remains unchanged.

Every metadata/open operation carries the kernel caller UID explicitly,
including readlink. Per-caller SSS mounts disable shared kernel metadata/page
caching. Native FreeBSD can omit the handle on GETATTR even for `fstat`: only
that caller's still-open handle may supply the missing owner. BriX stats the
actual remote handle through its existing wire codec and shared stat parser,
so external size changes are visible and unlink/recreation cannot redirect
descriptor metadata to a new pathname. Another caller's handle never lends
authority. Invalid components and overlong combined export paths are refused
before rebasing, not mapped to the export root.

The regular-file `mknod` tests independently probe an ordinary native directory.
Where this kernel refuses the operation, both verify its errno and unchanged
mounted/backing namespaces, without emulation or added skips. Unexpected
permission/I/O failures remain failures.

Focused native checks cover real hard links/shared updates, descriptors alive
after both aliases are unlinked, fresh handle metadata after path replacement,
failed-link isolation, parent rename, 1,500-entry paginated listings and network
loss/recovery. Sanitized production-registry controls cover lookup/open
lifetime, replacement, capacity, rename rollback, caller identity/refusal and
export-length boundaries. These corrected focused batches do **not** subtract
failures from the original full run. macOS build/unit evidence is separate;
no macOS kernel mount is claimed while its FUSE extension is unavailable.

The final combined FreeBSD selection passed **94 tests, 0 failures, 0 errors,
3 skipped**. Its three skips are unconfigured opt-in official XrdHttp endpoints,
not BriX HTTP coverage. It includes the existing daemonized, root/HTTP/xattr,
SSS-identity and network-recovery groups plus the new regressions. The macOS
sanitizer/capability selection passed **23/23**; both `xrootdfs` and `brixMount`
build on both hosts. The duplicate macOS link-library warning was removed by
using the already selected dependency closure. Evidence is retained under
`build/release-validation/freebsd-native-coverage-20261019/fuse-lowlevel-v284`.
Native/Python complexity, duplication, file-size, client-build coverage, PAL,
VFS/mutation, logging and documentation-path/link gates pass without waivers.

The two approved pending-peer fixture files and the 15 approved new FUSE
support/regression files were staged individually. Existing index entries
were preserved; original tracked-file edits remain unstaged. No commit or
push was made.

Native official-reference defects, GFAL2 portability/dependency work, remaining
original failures and a complete corrected canonical rerun remain open.
**FreeBSD v2.0.0 full-suite certification is still incomplete.**

### Native credential broker and filesystem isolation checkpoint (V358)

The approved native broker path is implemented without simulating Linux
capability calls. Startup creates bounded, fixed-identity helpers; every real,
effective and saved uid/gid is permanently unprivileged before readiness.
Supplementary groups are verified, no-new-privileges and tracing restrictions
are read back, unrelated descriptors are sealed, and Capsicum removes ambient
filesystem/network/exec authority. A distinct non-root supervisor closes its
export descriptor. Requests require an exact complete credential multiset;
unknown, changed or dead helper identities fail closed. Owned native process
descriptors bound helper lifetime without numeric-PID cleanup races. Internal
transport failure never replays a mutation, and idle helpers do not expire.

The largest previously unavailable authorization group now runs natively as
root: the final combined selection passed **283 tests, 0 failures, 0 errors,
0 skips**, including all **259 multi-user authorization checks**. Ordinary-user
native sandbox/account/process controls separately passed **64 tests, 0
failures, 0 errors, 0 skips** (one privileged case deselected and covered in
the root batch). The corresponding macOS portable controls passed **64/64**;
this is not a claim of macOS Capsicum support. Additional separate selections
passed **52 Kerberos checks**, **9 real cross-device publication checks**, and
**88 native keepalive/timeout fixture checks**, without skips. These batches
overlap and must not be summed into a canonical full-suite total.

The repeatable `--test-level privileged --no-build` target then passed **286
tests, 0 failures, 0 errors, 0 skips**, including mapped WebDAV LOCK lifecycle
and rejection controls. Full CI now selects this narrow root authorization
lane separately after the ordinary-user suite and preserves both verdicts.
The runner's selection, root/build refusal and evidence controls separately
passed **91/91** portable tests. Root authorization did not require weakening
the worker identity, saved-ID, descriptor or capability-mode assertions.

Mapped WebDAV LOCK uncovered two distinct issues. BriX previously declined its
portable inode-bound lock transaction when impersonation was active; it now
routes the bounded compare/exchange through the mapped owner's broker, retaining
VFS mutation policy, N2N translation, exact persisted-record comparison and
nonblocking inode locks. The resulting operation still fails on this host's
ZFS `xattr=dir` dataset: an independent C program using only native public APIs
reproduces `ECAPMODE` for `extattr_{get,set}_fd` after `cap_enter`, even without
limiting descriptor rights. Ordinary xattrs and `flock` work on the same inode.
The [native ZFS directory-xattr implementation](https://cgit.freebsd.org/src/tree/sys/contrib/openzfs/module/os/freebsd/zfs/zfs_vnops_os.c?h=releng/15.1)
performs internal pathname lookup; this is consistent with the measured
failure, not evidence that BriX may bypass confinement.

An isolated 512 MiB UFS image passes the exact native xattr probe. All **4
mapped LOCK/refresh/forged-unlock/foreign-owner checks** pass there with
Capsicum enabled. The initial UFS unit selection reported 39 passing records;
38 executed sandbox/lock-store checks, but the staged-publication unit had
returned an unavailable-object message as a pass. That reporting defect is
fixed: objects and feature-layout flags now come from the selected generated
SDK, and an unbuilt unit is explicitly skipped rather than counted as passed.
The corrected sandbox/lock-store/staged-publication and SDK-provenance selection
passes **70/70** on FreeBSD and macOS, with a real staged-publication executable.
Running the entire native C catalogue then exposed and repaired missing PAL
xattr dependencies, host-private xattr includes, vtable/libc macro collisions
and metrics feature-layout mismatch. All **54 C units** now execute; the
combined C-unit/build-provenance selection passes **87/87**, with no skips, on
both FreeBSD and macOS. Success, failure, stale-owner, concurrency and hostile
input assertions were retained.
The successful standalone root target uses the runner's normal private `/tmp`
root, on a different existing ZFS dataset with default `xattr=sa`. No dataset
property was changed to make it pass. An independent native size/readback
probe there verifies exact ordinary and Capsicum reads for 4, 511, 4096,
16384 and 32768-byte values. A 65536-byte value succeeds outside Capsicum but
fails inside it with `ECAPMODE` when storage spills to the directory path.
Therefore the small-record lock result does not certify every SA xattr size
or remove the directory-storage compatibility gap. Earlier independent SA
readback observations also remain in their original lab reports.

The active full-run dataset's xattr property and kernel were not changed.
ZFS directory-xattr/Capsicum compatibility remains unresolved; no skips,
weakened confinement, worker-owned lock writes or property workaround were
added to conceal it. Completed disposable fixtures and the detached UFS image
were archived and checksum-verified on the host before removing their VM
copies. The dedicated test dataset quota increased from 28 to 32 GiB to avoid
unrelated disk-full failures; active fixtures and reports were preserved.

The Kerberos fixture and six explicitly approved new native-broker files were
staged individually. Every pre-existing index entry was verified unchanged;
tracked-file edits remain unstaged. No commit or push was made.

Reports are retained under
`build/release-validation/freebsd-native-coverage-20261019/native-broker-v327`.
The corrected canonical V300 run uses an immutable earlier snapshot and is
still running with failures; later focused successes neither change that
snapshot nor relabel its failures. Native reference-client defects, GFAL2
portability and other full-run failures remain open. **FreeBSD certification
is not complete.**

### Exact persisted-lock snapshots and isolated OS experiment (V391)

The post-rebuild privileged target passed **289/289**, without failures,
errors or skips; its runner/evidence controls passed **94/94** on FreeBSD and
macOS. A subsequent native process-ownership correction keeps visible,
known non-harness helpers out of harness-only reap queries before inspecting
private environments. General ownership inventory, unknown commands and
unreadable real harnesses still fail closed. Host-wide inventory tests now run
in the serial lane while retaining deliberately competing harness cases.
The expanded ownership/scheduling selection passed **114/114 on macOS**;
quiescent native inventory verification remains pending the full run.

The frozen V300 main lane completed, but is not green. Its console records
39,948 passes, 813 failures, 126 setup/teardown errors, 704 skips, 45 expected
failures and 8 unexpected passes. These are pytest outcome/phase counts, not
an additive count of unique tests. The subsequent serial lane completed with
5,755 passes, 83 failures, 6 errors, 333 skips and 4 expected failures in its
pytest console. Its JUnit contains 6,180 records: 5,754 passed, 83 failed,
6 errors and 337 skips (including expected failures). The destructive and
client-conformance lanes were not yet complete at the V400 observation.
Two CMS/hybrid fleet listeners were missing at main-lane conservation checking;
their cause remains under investigation. A late quota exhaustion affected
122 recorded failure phases; the test-only dataset quota increased again from
32 to 36 GiB, without changing its xattr property. Original failures remain
preserved. The affected fleet-free local-copy/option-parser selection passes
**55 tests on both hosts**, with one live-fleet case deselected, not skipped.

Additional corrections retain real sanitizer and native behavior:

- The upload-pump unit now links the production error-mapping owners and uses
  fatal, unreachable download/local adapters where FreeBSD's sanitizer retains
  those functions. Upload success, fanout, fallback and denial remain driven by
  the actual pump. Upload/scheduling controls pass **21/21 on each host**.
- ZIP readiness controls now expect the existing hard failure for an absent
  required service, not a skip; **4/4 pass on each host**.
- The standalone CSI scrub unit links the native PAL xattr owner. A private
  sysctl fixture symbol prevents FreeBSD libc interposition from bypassing the
  fixture. Portability, lifecycle grouping and address-corpus gates pass **83
  tests on each host**, with one honest Linux-only seccomp skip.
- Startup lock sweeps exposed a real persisted-record CAS mismatch. Decoding
  normalizes legacy expiry and ignores unknown fields; re-encoding that record
  cannot reproduce the bytes originally read. Records now carry a bounded,
  by-value observed snapshot. Only the expected side of compare/exchange uses
  it; replacement records keep canonical v2 encoding. Embedded NULs are refused.
  Policy, owner/credential gates, exact stale-record comparison, inode locking
  and confinement remain unchanged. Both native server builds pass, as do all
  **87 C-unit/provenance checks on each host**, without skips. The initial live
  lock selection passed **28/28 on both hosts**. Expanded refresh, UNLOCK,
  re-lock-after-expiry and read-only preservation coverage passes **37/37 on
  both FreeBSD and macOS**, without failures, errors or skips.

The approved external OpenZFS experiment is built in a fresh isolated copy,
not installed into the running system. Its module SHA-256 is
`af2e84cbb32e1113f25c13cb9f4b38d128ed136960f54b54213af612898cf5cf`;
the preserved original 2.4.4 experiment remains
`e65145bd98631898bfa1e5cb37931e7a2fd6e7739244cfca2843ab804c4831d5`.
The patch restricts its lookup adjustment to internal vnode-anchored directory
xattrs, rejects empty/dot/dot-dot names, and leaves syscall descriptor-rights,
namespace and credential checks intact. An independent public-API probe records
the original kernel's directory-xattr and 64 KiB SA-spill failures, along with
read-only/rightless descriptor refusals and ambient-path/parent-traversal
controls. The exact source, module, debug symbols, baseline and build log are
retained on the host. **Runtime verification of this module is still pending**
the current full run and its teardown. The original kernel/default boot
environment remain active; no pool-feature upgrade or BriX confinement
relaxation was made. This is not a shipped or certified dependency fix.

All these focused selections overlap; do not sum them or subtract them from
the frozen run's failures. Native reference-client defects, GFAL2 portability,
the remaining full-suite failures, experimental OS runtime verification and a
complete corrected canonical rerun remain open. **FreeBSD v2.0.0 certification
is still incomplete.**

### Signed write extents and shared I/O boundaries (V399)

A raw-socket write of three bytes at `INT64_MAX` independently reproduced a
real native BriX bug: FreeBSD terminated its worker with signal 25 (`SIGXFSZ`).
The shared server/client VFS byte loops now reject negative or unrepresentable
extents before backend dispatch, without first forming an overflowing sum.
Full-read/write output counts are reset on refusal. Writer data extents and
accounting reuse that same helper; their existing typed mutation gate still
precedes range and backend diagnostics. The root write handler uses the helper
before special/AIO dispatch, preserving the specific `kXR_ArgInvalid` response
instead of reducing the refusal to a generic I/O error.

Bounded copy windows also validate their complete extent before I/O and compare
buffer sizes without narrowing an unsigned size into a signed offset. Native
units exercise exact valid boundaries, negative/overflowing/SIZE_MAX inputs,
backend errors, EINTR, zero lengths, partial writes, EOF and huge copy buffers;
read-only writer tests retain EROFS precedence and zero backend side effects.
Raw wire tests require unchanged file bytes and successful sync on the **same
connection and handle** after each refusal, not merely a respawned server.

The native FreeBSD server/client build and the macOS module/client builds pass.
The combined raw-wire, shared-core, metrics-link and native mount-inspection
selection passes **92/92 on each host**, without failures, errors or skips.
Expanded coverage of both complete raw I/O edge suites and the shared-core
units passes **128/128 on each host**, including real ASan/UBSan execution.
The standalone range unit selection passes **76/76 on each host**; every C
regression runner also passes (**54/54 on macOS**, **87/87 including native SDK
provenance controls on FreeBSD**). The post-fix root authorization target
passes **289/289**, with no failures, errors or skips. These batches overlap.
The original native crash and intermediate error-code failures are preserved
separately. These are focused corrections, not a replacement full-suite verdict.
At this checkpoint the frozen V300 run was still running and red, and the
approved experimental boot was pending. The subsequent full-run completion
and isolated OS runtime results are recorded below.

### Completed frozen full run (V300 final)

All four lanes finished with collection/execution conservation verified. The
aggregate contains **48,954 JUnit records: 46,589 passed, 1,178 failed, 74 errors
and 1,113 skipped**, in 11,813 seconds. JUnit skips include expected failures;
teardown records can differ from unique collected test IDs. The runner reports
`reports_complete=true`, `execution_complete=true` and exit status 1.
Final XML, failure journals, progress records, console and summary are retained
in `build/release-validation/freebsd-native-coverage-20261019/native-full-v300-final`.

| Lane | JUnit records | Passed | Failed | Errors | Skipped / XFAIL |
| --- | ---: | ---: | ---: | ---: | ---: |
| Main | 41,584 | 39,954 | 813 | 68 | 749 |
| Serial | 6,180 | 5,754 | 83 | 6 | 337 |
| Destructive / resilience | 186 | 164 | 6 | 0 | 16 |
| Client conformance | 1,004 | 717 | 276 | 0 | 11 |
| Total | 48,954 | 46,589 | 1,178 | 74 | 1,113 |

This is a completed **red** run against an immutable earlier snapshot, not a
certification of later corrections. Many final-lane parity failures explicitly
record stock FreeBSD `xrdcp` returning local-error 54 while BriX succeeds; they
remain failures in the original report. Remaining failures are not all assumed
to be external.

After full teardown, the previously pending quiescent native ownership and
scheduling selection passed **114/114**, without failures, errors or skips.
It retains strict rejection of unknown/unreadable live ownership and competing
harness checks. The approved OpenZFS module was then installed only into the
isolated boot environment after backing up its previous experimental module;
the original default BE and original kernel module remain preserved. A one-shot
experimental boot was selected. Runtime results are recorded separately, not
inferred from build success or substituted into the frozen full-run results.

### Isolated OpenZFS runtime validation (V414)

The first patched artifact did not boot: the loader reported an input/output
error loading its seven-program-header ELF module. The VM was recovered to the
original default through its dedicated QMP reset socket. Relinking the same
isolated source/objects with explicit native FreeBSD `LD=/usr/bin/ld` and
`OBJCOPY=/usr/bin/objcopy` restored the bootable nine-program-header layout.
The native-linked module has SHA-256
`ae5dc9cbd56fa29172c3e0a8994da1c03c0431eabaee6bdda7769f00e1ab19d2`;
it adds no unresolved symbol dependencies versus the preserved bootable 2.4.4
module. A second, adjusted one-shot boot succeeded and reported
`zfs-kmod-2.4.4-1`. The original userland remains 2.4.2; no system dependency
upgrade is claimed.

On that isolated kernel, the unchanged independent public-API probe passes
**138/138 assertions** across directory-backed xattrs and SA spill storage:
all six sizes through 64 KiB round-trip byte-exactly; listing, deletion and
missing-value errors remain correct. Get-only/rightless descriptors cannot
write or borrow rights, hostile names and system-namespace writes are refused,
and ambient absolute access and parent traversal remain confined. The full
native privileged catalogue then passes **289/289 on directory-xattr ZFS**,
without failures, errors or skips, including mapped-owner LOCK/refresh and
forged/foreign UNLOCK refusal. It uses the same catalogue and assertions as
the earlier default-storage run, not a reduced substitute. The pool remains
healthy, all pool feature states match the pre-boot record, ARC stays bounded
at 4 GiB and all 9 GiB swap remains unused.

Exact binaries, build/loader/recovery evidence, the independent before/after
probe and native XML/progress records are retained in
`build/release-validation/freebsd-native-coverage-20261019/openzfs-runtime-v408`.
The experimental source/module stays isolated from BriX's AGPL implementation.
The original default BE and kernel module were not modified. After preserving
the completed reports, the VM returned to the original `default` BE and verified
the original module checksum and OpenZFS 2.4.2 runtime. This is an experimental
dependency fix, **not certification of unmodified FreeBSD/OpenZFS**, and it
does not repair the native reference-client or GFAL2 gaps. A complete corrected
canonical run remains required.

### Expanded native root coverage and fresh evidence (V429)

The dedicated privileged target now includes pblock group authorization and
worker privilege-drop tests in addition to the MU/gridmap/account catalogue.
It passes **301/301 on the original FreeBSD kernel**, without failures, errors
or skips, with all 301 collected tests accounted for in its finished progress
record. The pblock-only selection passes **12/12**. This adds nine group-policy
checks and three privilege-drop checks to the former 289-test target; it does
not run the broad suite as root or alter its original skips.

The pblock account fixture uses the existing native command owner (`pw` on
FreeBSD, shadow utilities on Linux), retains exact reserved IDs, removes
duplicate-ID flags and never recursively deletes a home directory. Its root
worker template selects root's actual primary group instead of assuming a
group named `root`. Successful storage fixtures use nobody's group explicitly:
FreeBSD inherits a directory's group even without the SGID bit. Existing
non-root file-owner/group assertions remain, now with exact group matching;
the tests additionally inspect the serving workers' real, effective and saved
UID/GID. The root-owned, non-writable-export refusal remains unchanged.
Initial native group-name and parent-group failures are retained separately.

Fixed-path root reruns also exposed stale diagnostic companions: the reporter
appended previous failures and could retain a previous finished progress file.
A reporting controller now removes only its own prior failure/progress names
at initialization, without following a symlink or recursively removing a
directory. Per-run XML/progress counts were not rewritten, and the frozen
four-lane run used fresh report paths. The final 301-test run has no failure
journal. Account, saved-credential, confinement, runner and report-ownership
controls pass **135/135 on each of FreeBSD and macOS**. They are split by
responsibility across existing test modules, preserving the 600-logical-line
gate and all strict complexity limits.

Evidence is retained in
`build/release-validation/freebsd-native-coverage-20261019/native-pblock-root-v417`.
These focused selections overlap. The completed frozen full run is still red;
native official-reference defects, GFAL2 portability and the remaining
full-suite triage/corrected canonical rerun are not resolved by these results.

The approved separate remote-reference check was repeated against the current
native server build on the restored original kernel: **90/90 pass**, with
30 anonymous, 30 GSI and 30 GSI+TLS official macOS-client checks, no failures,
errors or skips. The native server runs as UID 2101; evidence pins the actual
server/module and independent client artifacts. Teardown confirms all leased
servers closed, reference bytes and the outside sentinel unchanged, and no
test namespaces left. Disposable client credential copies and the owned SSH
forwards were removed. Reports are retained under
`build/release-validation/freebsd-remote-reference-20261019/transport-fg6pa_06`.
Every report explicitly has `native_full_suite=false`: this interoperability
result does not erase the original native reference failures or certify the
full FreeBSD target.

### Native identity, directive and GFAL coverage checkpoint (V480)

The expanded root lane passes **309/309** on the original kernel, without
failures, errors or skips. Its eight additions prove saved worker credentials
and native no-new-privileges, split-identity checkpoint recovery and the
non-devfs device contract. The corresponding identity/runner controls pass
**168/168 on each of FreeBSD and macOS**. Native Unix-auth wire and interface
controls pass **28/28**: replacing a Linux-only interface ioctl with the native
interface inventory removes three false non-loopback skips without weakening
the trust gate. Private staging tests pass **13/13 on macOS**; FreeBSD has
**10 passes and three retained native reference-binding failures**. Independent
raw-wire staging/ENOSPC/read-only checks run even when reference bindings are
absent; each writer fixture has its own namespace and spill accounting.

The fresh canonical run exposed a required-dependency declaration error and a
duplicated TPC directive registration family. `psutil` is now required rather
than optional, and one shared initializer owns the same four TPC identity
directives on HTTP and stream, preserving their scopes, arities and setters.
After rebuilding both native module sets, the positive, syntax-error and
confinement selection passes **84/84 on each host**. The unchanged dependency,
duplication and directive-registry gates pass on FreeBSD; the registry still
reports 752 registrations and 606 unique names. No duplicate-gate waiver or
limit change was introduced.

The isolated native GFAL lab now builds actual file/HTTP/XRootD plugins,
Python bindings and CLI tools. It also exposed and fixed two external issues:
an overlapping `strlcpy` corrupted checksum text on FreeBSD, and Davix omitted
its UUID link dependency. All 17 checksum cases and the complete TLS-verified
WebDAV lifecycle now pass. Namespace tests independently seed and byte-check
their fixtures instead of ignoring a failed upload; recursive deletion now
proves it removed a populated tree, not an empty setup artifact.

The final private-prefix selection has **137 cases: 118 passed, 17 failed and
two existing expected failures, with zero errors or skips**. This includes
18 harness controls; the 119 live GFAL cases account for 100 passes, 17 failures
and two expected failures. The 17 failures remain in the XRootD-backed copy
path, including native local-copy `EINVAL` and reference-server `fchmod`
refusal; no transfer assertion was removed or relabelled. The reproducible
bootstrap subsequently builds from clean pinned archives into a second prefix.
Its complete runtime/control selection records **157 cases: 138 passed,
17 failed and two existing expected failures, with zero errors or skips**;
the extra 20 cases are bootstrap safety/workflow controls, not extra live GFAL
features. All 38 bootstrap/harness controls also pass on macOS. The final
whitespace-clean patch assets reproduce the successful build's source bytes
exactly in independently extracted upstream trees. This does not certify the
unmodified native XRootD reference or enable the other GFAL plugins above.

The new frozen V445 canonical run builds a fresh server/client SDK and runs
all four canonical lanes with optional suite jobs. Its main lane collects
41,756 tests and is **still in progress and red** at this checkpoint. It keeps
its original source and dependency selection; later focused fixes and the new
GFAL prefix do not rewrite that run or retroactively convert its skips/passes.
The earlier completed V300 full-suite result remains red as recorded above.
Corrected focused results are not subtracted from either full-run failure
count. A completed corrected canonical run is still required before release.

Evidence is retained under
`build/release-validation/freebsd-native-coverage-20261019/native-root-and-spill-v447`
and `native-tpc-and-gfal-v475`, including the failing selections and external
dependency patches/build logs. The user-approved cleanup removed only 105
verified inactive 200 MiB random seed files, reclaiming about 20.5 GiB of
physical storage; five uncertain candidates, all reports/logs/configs and
failed-case artifacts were retained. Seed bytes are not recoverable, but the
fixtures are regenerable. The VM remains on the original default boot
environment/module; no pool feature, confinement or unsafe-AIO setting was
relaxed.

### Completed canonical run and reference-lane follow-up (2026-10-20)

The frozen V445 run has now completed **all four canonical lanes**, including
optional suite jobs. Its final JUnit aggregate is **49,164 records: 46,892
passed, 1,167 failed, five errored and 1,100 skipped**. The skipped aggregate
includes 49 existing expected failures; the passed aggregate includes eight
unexpected passes. Reports explicitly record `execution_complete=true` and
`reports_complete=true`, with a failing exit status. This is **not a green
FreeBSD release result**. All XML, progress records, failure journals and the
original summary are preserved under
`build/release-validation/freebsd-native-coverage-20261020/native-full-v445-final`.

Later focused corrections are kept separate, never subtracted from that
aggregate. The expanded privileged lane passes **315/315**, without failures,
errors or skips, on the original kernel. Matching module/test identities shows
that **266 of the original full-run skip records pass in this separate root
lane**, including all 226 MU conformance cases. This is additional coverage,
not a change to the frozen full-run totals. Read-path, authorization, TPC directive
and configuration checks pass **168/168 on each of FreeBSD and macOS**. In
particular, a trailing slash on a regular file is rejected before a cache hit
or fill can silently discard the directory intent, including authenticated
and cached cases.

Further telemetry/transport/port-ledger checks pass **87/87 on each host**;
the final decomposed telemetry-only repeat passes **10/10 on each host**.
These selections overlap. Firefly accounting now independently probes the
real native PAL using a connected socket and known traffic. Supported hosts
still require measured bytes. FreeBSD must return `ENOTSUP` with cleared
outputs, and its Firefly end record must retain zero counters/RTT rather than
invent measurements. The listener-release fixture now leases a port from the
existing session ledger instead of asking the kernel for an untracked port.
Focused evidence is retained in
`build/release-validation/freebsd-native-coverage-20261020/native-corrections-v558`.

Native XRootD reference failures remain visible, including byte-swapped 64-bit
offsets and local-copy failures. An opt-in remote-reference transport exercises
the existing Python client worker, official CLI tools and independent server
without substituting BriX for the oracle. Explicit remote-worker failures are
errors, not native fallbacks or dependency skips. The extended lane retains
BriX's **native FreeBSD build and native ZFS exports**; only the external
oracle and shared fixture namespace use the separate reference host and a
disposable Linux userspace NFS export over owned loopback SSH forwards.
The export contains only a fresh test directory, never the checkout, and does
not change persistent NFS settings or replace native filesystem validation.

Every daemon launch requires an explicitly selected, digest-recorded socket
adapter. It constrains libc wildcard binds to loopback and refuses non-loopback
IP binds; the actual daemon's kernel listener table is checked before publishing
readiness. This adapter does **not** sandbox malicious direct syscalls and is
never loaded into BriX. Its seven independent native socket controls pass on
both hosts. Transport credentials remain fixture-confined, bounded and copied
into fresh private generations; the optional shared-credential optimization
requires an independently verified shared-namespace nonce. Remote results are
labelled `native_full_suite=false` and never replace native dependency failures.

The first shared-fixture file-operation prototype passed 110 tests with one
existing expected failure, but exposed listener-confinement/cleanup gaps and
is not evidence of a correctly confined lab. A later expanded prototype was
deliberately interrupted after **133 passes and six existing expected
failures**, preserving its partial XML and interruption status. Its measured
launcher overhead was 12.2 seconds with Python's cache on NFS versus 1.25
seconds with a native ZFS cache; only the generated launchers' cache location
was changed, with before/after digests recorded. It also exposed the need to
monitor control-connection closure after daemon stdin EOF and to cancel silent
children during lease shutdown. The corresponding lifecycle/shared-credential
and runner controls pass **234/234 on each of FreeBSD and macOS**. The first
complete-catalogue attempt collected 3,464 cases but stopped with 144 errors
from one repeated NFS fixture-seeding timeout; these setup errors remain in
its separate XML. No server assertions or test timeouts were changed. A fresh
attempt prepares the deterministic central fixture before per-test budgets
and enables the existing native GFAL prefix. Neither an interrupted prototype
nor its controls count as a completed full-suite result.

Subsequent drill-down fixed two more harness defects: non-root runs attempted
recursive ownership handoffs to service accounts even though their daemons
retain the invoking identity, and a mechanically loaded continuation replaced
the proven native-ZFS export path with the old shared-directory join. The
complete-module import regressions now detect that override; root ownership
handoffs still use the real service-account IDs. Main/compression seed paths
also use the validated native mapping in the opt-in lane, so the unchanged
200 MiB canonical fixture is not generated over NFS. Ordinary native settings
and the reference export path remain unchanged.

The final combined selection passes **303/303 on FreeBSD and 303/303 on macOS**,
with zero failures, errors or skips. It covers ownership, complete-module
mapping, credential isolation, child/SSH teardown failures, runner identity,
port allocation, actual socket interposition and telemetry. Generated adapter
libraries are explicitly owner-private regardless of other fixtures' umask;
writable/symlink adapters remain rejected. File-backed Kerberos caches and
keytabs are copied into private generations, while operator/default caches and
host cache services cannot be borrowed. Private copies are removed even if
child or reverse-lease retirement fails. These 303 cases overlap earlier
focused selections and are not added to the canonical pass count.

The NFS-backed live lane is **still blocked**: after the ownership/path fixes,
an 18-case stat probe completed with 18 setup errors from a repeated metadata
walk exceeding the unchanged 30-second budget. The intervening interrupted
attempts retain 168 setup errors (V568) and 107 missing-file failures from the
now-fixed initializer override (V574). No further NFS retry is presented as
server validation. All owned reference processes and fixture mounts have been
stopped; the original ZFS module checksum and zero swap usage are verified.
The operator approved replacing only this disposable layer with a
fixture-confined SSHFS/SFTP lane backed by native Linux reference storage.
No operator private keys or persistent SSH/NFS settings have been changed.

Ordinary Linux/Windows/macOS-only kernel tests are not reclassified as FreeBSD
features. Root-only checks run in their separately confined privileged lane,
and the independently built GFAL prefix has its own retained live results.
The unchanged native reference failures, remaining full-suite failures and
experimental OpenZFS dependency work still prevent complete certification.

### SSHFS reference-lane drill-down (20 October 2026)

The isolated replacement uses a new chrooted, key-only SFTP service on Ubuntu
24, pinned disposable SSH host/client keys and owner-private SSHFS access by
FreeBSD UID 2101. The independent official server, CLI tools and Python
bindings are Linux ARM64 XRootD 5.6.9; BriX's frozen server/client build and
storage remain native FreeBSD/ZFS. These are remote-oracle results, **not**
replacement native dependency results or a new complete native-suite result.
The approved native accounting test helper is staged; no tracked edits were
staged and no commits or pushes were made.

SSHFS 3.7.6 and Linux's packaged `python3-psutil` were installed. Listener
attestation now supports both public psutil inspection method names, retaining
the actual owning-process, expected-port and loopback-only checks. The updated
90-case transport selection passes on both FreeBSD and macOS, with zero
failures/errors/skips; the added controls include legacy-API access failures
and wildcard-listener rejection. Complexity, duplication, Python-size and
documentation-link gates remain unchanged and pass.

The first probes retained their authorization-path failures and corrected only
the temporary key/chroot paths; `StrictModes` was not disabled. Real bidirectional
binary writes, renames, permissions, non-wheel identity and native Linux xattrs
pass. The 27-file seed takes about 0.6–0.9 seconds and its metadata walk about
0.4–0.55 seconds, removing the earlier NFS bottleneck without extending test
budgets. A subsequent 12-assertion run exposed pytest's absolute-symlink cleanup
failure. Default SSHFS containment remains enabled; explicit fresh pytest base
directories must stay inside the actual per-run `TEST_ROOT`. The two erroneous
base-directory attempts, including 309 passes plus 161 setup skips, are retained
and are not described as clean validation.

With corrected fixture paths, the 482-case stat/xattr selection finished with
**475 passes, one failure, six existing expected failures and zero errors or
ordinary skips**. Its remaining failure was the Linux reference filesystem
rejecting a 4096-byte xattr while BriX accepted it. The host's ext4 filesystem
lacks `ea_inode`; a fresh disposable 512 MiB image with that feature round-trips
4096- and 65536-byte attributes, rejects 65537 bytes and preserves the previous
value after that refusal. The unchanged 482-case selection then completed with
**476 passes, zero failures/errors or ordinary skips, and six existing expected
failures**. Three SFTP probes refuse a foreign absolute path, a symlink escape
and parent traversal; a positive binary copy succeeds. The original filesystem
and system SSH configuration are untouched. All owned mounts, accounts and
services in this completed selection were retired successfully.

The complete 3464-case differential catalogue finished in 960.78 seconds with
**3385 passes, 32 failures, zero errors, 14 ordinary skips and 33 existing
expected failures**. Its failures comprise 19 native GFAL copy/query cases,
ten comparisons assuming equal directory sizes on ZFS and ext4, two sparse-file
checks relying on SSHFS block accounting, and one independent reference
`spaceinfo` timeout. These are retained failures, not certifications or waived
checks. Nine ordinary skips come from FIFO creation unsupported by the SFTP
fixture layer, not a missing FreeBSD kernel capability.

The other five skips were on-disk xattr inspections. An opt-in read-only metadata
route to the actual oracle filesystem now makes **all five execute and pass**
in a separate unchanged focused selection, with zero failures/errors/skips;
the original complete-catalogue totals remain immutable. No SSHFS xattrs are
invented. The inspector walks
plain path components through confined descriptors, refuses symlinks/FIFOs and
foreign paths, bounds attribute count/value/total size, and propagates explicit
remote failures without native fallback. Its combined transport/runner controls
pass **156/156 on each FreeBSD and macOS**, with zero failures/errors/skips.
These control selections overlap the earlier 90/303-case selections.

The completed live runs retain their manifests, actual official-artifact
digests, fixture proofs, per-case XML/journals, controller and byte-identical
native runner. Their owned SSH services, temporary accounts, SSHFS/chroot bind
mounts and loopback image mounts were stopped successfully. Generated lab keys
and authorization files were retired; no operator key was copied or removed.
Default symlink containment remains enabled. The frozen canonical native
49164-case result above is still red and is not replaced by this remote lane.

All previous failed runs remain archived under
`build/release-validation/freebsd-remote-reference-20261019/sshfs-v600-*`.

### Native validation refresh (21 October 2026)

A fresh read-only checkout snapshot, V620, builds the real native server,
dynamic modules and clients successfully. Its smoke test loads the modules and
verifies byte-exact `root://` data. The complete ordinary-user suite has finished
against that frozen source/build with the isolated native GFAL prefix enabled.
The separate corrected 315-case root authorization catalogue has completed
with 315 passes and zero failures/errors/skips. The ordinary-user run records
**49,361 cases: 47,171 passed, 1,203 failed, six errors and 981 aggregate
skips**, in 18,804.91 seconds. The passed aggregate includes eight unexpected
passes; the skipped aggregate includes 51 expected failures and 930 ordinary
skips. All four lanes and suite jobs have completed, and the progress records
conserve collection and execution. This is a complete **red** result, not
release certification. It does not replace the previously retained complete
results. The original
ZFS module remains active, and no experimental module or pool feature was
enabled for this refresh.

Six native cache-registry/pgwrite completion checks previously skipped because
their generated-header directory was not exported. CMake places those headers
in `modules/`, not `nginx-src/objs/`. The native runner now pins
`TEST_NGINX_BUILD_DIR` to that selected directory, overriding absent, empty or
foreign inherited selections. Those compilation fixtures also reuse the
existing configured-SDK dependency-include reader: enabling the tests exposed
missing PCRE2 includes, rather than a missing installed dependency. All six
real native C cases pass with the correct header/dependency environment; the
first six setup errors are retained as diagnostic evidence. The updated SDK,
runner and include-selection controls pass 145/145 on macOS, including those
six compiled C cases, with zero failures/errors/skips. The combined updated
native controls pass 325/325 on FreeBSD, including the six real C cases, with
zero failures/errors/skips. The frozen full snapshot is not modified.

The optional remote-fixture helpers now support bounded, read-only inspection
of the oracle's actual `st_mode`, `st_size` and `st_blocks`. Differing directory
sizes must equal each server's own backing filesystem; regular-file size
parity, names, flags and byte-content assertions are retained. Sparse checks
use actual backing allocation rather than SSHFS-synthesized blocks. A separate
exclusive-FIFO creation route is confined by descriptor-relative, no-symlink
walks and the existing independently verified fixture lease. It refuses foreign
parents, existing names and special permission bits; the read-only inspector
cannot invoke creation. The native fixture path still calls native `mkfifo`.

These metadata/FIFO and transport controls pass 180/180 on macOS and are
included in the 325 native FreeBSD controls above, with zero failures/errors/
skips. Copies of the test/tool sources into fresh disposable validation
directories were approved. This is not a checkout filesystem export; operator
credentials are excluded and SSHFS symlink containment remains enabled.
Two live attempts passed fixture identity, xattr-capacity and SFTP-containment
checks but timed out during seeding before pytest began, at the unchanged
120-second setup limit. The second retains periodic Python stack diagnostics
and tracks the benchmark's owned process group for cleanup. No successful
live FIFO/metadata result is claimed from those attempts. The host had ten
running VMs with 180 GiB allocated and about 46 GiB of macOS swap in use.
The operator approved stopping exactly the eight non-target VMs; their normal
shutdowns all succeeded, with FreeBSD and Ubuntu24 left running and disks
preserved. Swap use fell to about 9 GiB and free physical memory rose to about
43 GiB. The unchanged benchmark then seeded its 27 files in 0.83 seconds and
harmonized permissions in 0.55 seconds.

The resulting complete focused selection passes 136/136 with zero failures,
errors or skips, including the directory-size, sparse-allocation and FIFO
cases. Its owned mounts, services and temporary account were retired without
cleanup errors. The new complete differential run, V644, executes all 3464
cases: **3411 passed, 20 failed, 0 errors, 0 ordinary skips and 33 expected
failures**, in 1433.39 seconds. BriX and its SDK remain native FreeBSD/ZFS;
the independent reference server/client runs on Ubuntu24. The previous
complete-catalogue totals remain immutable. Native reference-client/GFAL
failures are not reclassified or replaced by this mode. All owned V644 mounts,
services, temporary accounts and generated keys were retired without cleanup
errors; reports and fixture data were preserved.

Seventeen failures are native GFAL transfer/query failures; one additional
GFAL listing check still assumed identical ZFS/ext4 directory inode sizes.
The other two are a reference-bridge process abort and a timeout querying
`spaceinfo` on the independent reference server. The GFAL listing now uses the
same actual-backing-inode verification as the other directory checks, retaining
exact regular-file sizes and the known-file-size oracle. Positive directory,
wrong-wire-size and regular-file-mismatch controls pass 3/3 on macOS.

An isolated open-stdin reproducer identifies the bridge abort as Python's
buffered-reader lock during interpreter shutdown, not a rename assertion or
native BriX crash. Cancellable raw stdin reads, bounded worker-line reassembly
and explicit reader shutdown/join retain binary stdout/stderr and both success
and nonzero remote exit codes. The initial reproducer's four aborts remain
retained. Corrected bridge/fixture/log controls pass 205/205 on each FreeBSD
and macOS; the expanded native selection including the GFAL consumer controls
passes 208/208, without failures/errors/skips. A live complete rename/xrdfs
selection passes 186 cases and retains one reference `spaceinfo` timeout at
the unchanged 60-second limit. Neither focused result changes V644's verdict.

The native full run also exposed four stale enum-table source anchors and an
unclassified build-only dependency-patch suffix. Source assertions now name
the real `module_enums.c` owner. The DNS census explicitly classifies external
dependency diffs only in `tools/ci/dependency-patches/`; compiled C there still
triggers the strict resolver guard, and patches elsewhere are not excluded.
Both complete enum/DNS modules pass 108/108 on each FreeBSD and macOS, without
skips or weakened token/context/unknown-prefix rejection assertions.

A Kerberos access-log assertion read before the existing one-second batch
flush. It now uses the common bounded fresh-row observer, excluding historical
entries and retaining the foreign-peer authentication-refusal checks. The
complete Kerberos/log-observer selection passes 57/57 natively on FreeBSD;
macOS passes 41 controls with 16 environment-gated live Kerberos cases skipped.
No authentication or test timeout was increased. All refreshed full/native
failures remain in their original reports; the ordinary-user full suite is
still in progress and FreeBSD certification remains incomplete.

The initial refreshed root catalogue completed with 314 passes and one
failure: its broker-credential inspection raced PID publication, which occurs
before fixed-helper setup and irreversible privilege loss. The fixture now
requires an authenticated, byte-exact read of an Alice-owned mode-0600 object
before checking the broker's serving credentials. The original piped-launch
timing and every UID/GID/saved-root assertion remain unchanged. Positive,
backend-error and wrong-content controls pass 3/3 on each FreeBSD and macOS.
A focused native directory-xattr-dataset run passes the saved-root check and
16 other cases, but retains four separate mapped-WebDAV-LOCK setup errors.
The retained server log identifies `ECAPMODE` on the lock xattr write.
That dataset is `zroot/brix-full-v118`, with `xattr=dir`; the original
`zroot/tmp` dataset uses `xattr=sa`. Neither the dataset nor its failures are
silently substituted or waived. The complete corrected root rerun on the
original native `/tmp` filesystem passes 315/315 in 527.34 seconds, with zero
failures/errors/skips and full collection/execution conservation. Both earlier
reports remain preserved; success on `xattr=sa` does not certify `xattr=dir`.

The refreshed native suite also finds a real mapped-address connection bug:
FreeBSD's default IPv6-only sockets cannot dial an IPv4 peer through an
`::ffff:` socket address. Native TPC now uses the existing host-unmapping helper
before the DNS seam and checks the actual IPv4 destination against the same
SSRF policy. The original source name and TLS certificate-name checks remain
intact. A separate fresh server/client SDK, V675, builds successfully, and its
complete TLS/GSI TPC plus SSRF-policy selection passes **30/30**, without
failures/errors/skips. It includes mapped transfer, mismatching-certificate
rejection, and explicit mapped loopback/link-local/private refusals. macOS
passes 27 cases, with three existing second-loopback-address skips. Neither
build nor test replaces the running V620 snapshot.

The native client has the same socket-family problem. Its connect chokepoint
now folds mapped numeric hosts using that shared helper while preserving the
original name for identity and diagnostics. Real-tool tests cover dotted and
hex mapped spellings, a closed port, a different mapped peer, and IPv4-compatible
IPv6 which must not be folded. Their first native rerun exposed a separate
fixture defect: `make -W libbrix.a` rebuilt the socket object but deliberately
treated the old archive as current, so the executable still contained the old
function. Disassembly and timestamps retain that attribution. Both network
fixtures now build the actual archive before linking; regression controls pin
that requirement. The expanded client, fallback, resilience and build-graph selection
passes **63 tests with three Darwin-only skips on FreeBSD**, and **66/66 on
macOS**, with zero failures/errors. Shipped `xrd`, `xrdfs`, `xrdcp`, checksum,
prepare, proxy and diagnostic tools are relinked against the corrected archive.
The shipped FreeBSD `xrdfs` then successfully stats `/` through the mapped
loopback endpoint which previously timed out. Native dependency failures are
not changed by this client correction.

The three CMS deadline failures in the current broad run are a validation
launcher error: that invocation omitted the already-supported root-owned VNET
wrapper. The workflow has that wrapper; the manual full-run commands above now
show it too. With the approved isolated peer, the complete node-leg/fixture
selection passes **42 tests**, with one Linux `TCP_USER_TIMEOUT`-specific skip,
zero failures/errors, and explicit successful jail/interface retirement.
The original full-run failures remain recorded; no live-run environment was
patched and no pending-connection assertion was replaced with a refused dial.

Finally, a direct black-box reference probe attributes the `spaceinfo` timeout:
the independent daemon advertises the VM's LAN address although its listener
is deliberately loopback-only. Ordinary `stat`/`statvfs` work; the following
locate/query dial follows the unreachable advertised address. The
[public configuration manual](https://xrootd.web.cern.ch/doc/dev57/xrd_config.htm)
documents interface selection, but this version reports `lo` unusable and
falls back to its hostname-derived address. A private Linux UTS namespace named
`localhost` makes the independent daemon advertise its real loopback listener.
The service still runs as its ordinary account; the VM hostname, network,
firewall and persistent configuration do not change. No protocol bytes or
storage/authentication semantics are rewritten. Direct `stat`, `statvfs` and
`spaceinfo` probes then pass; a real six-case GFAL-listing/rename/spaceinfo
selection passes **6/6**, without skips and at the original test limits. Its
owned services, mounts, namespace and account were retired. The separate
seven-case GFAL listing/known-file-size/missing-path selection also passes
**7/7**. The complete corrected differential run, V683, using V675 finishes
all 3464 cases: **3416 passed, 15 failed, 0 errors, 0 ordinary skips and
33 expected failures**, in 1075.74 seconds. All 15 remaining failures are
native GFAL copies reporting XrdCl local-source/destination `EINVAL`; the
independent Linux reference does not replace that native dependency. BriX's
main process survives the run. All owned services, mounts, temporary accounts
and generated lab keys are retired without cleanup errors. Evidence is in
`build/release-validation/freebsd-remote-reference-20261019/sshfs-v600-y1itbv11/`.
V644's 20 failures remain unchanged in its archived verdict; the ongoing
canonical native run and directory-xattr failures remain separate and red.

An additional live lane uses the corrected native BriX client/server with only
its independent origin on Ubuntu24. Explicit pytest temporary directories keep
the cache store, export and downloaded bytes on native FreeBSD/ZFS rather than
SSHFS. All five unchanged cache-truncation/healing cases pass, without skips,
including byte-exact cold/warm reads and recovery after every truncated fill.
Its fixture identity/confinement checks pass and all owned resources retire
cleanly. A subsequent digest-verification attempt times out at the unchanged
120-second fixture benchmark before pytest starts; cleanup succeeds and no
test result is claimed for it. Both attempts retain their separate evidence.
After the concurrent native build finishes, a fresh retry at the same limits
passes all four digest-verification/corruption-recovery cases in 11.72 seconds,
without errors, failures or skips. Its cache/export/output remain native ZFS;
the owned services, mounts, account and generated keys retire cleanly.

Two post-move refactor ledgers omitted the deliberately added native-export
mapping and remote-worker helpers. They now enumerate only those exact names;
controls still reject an unlisted helper and an unexplained existing-probe
body change. The expanded ledger/remote-reference/CMS selection passes 144/144
on macOS. Native FreeBSD passes 143 and retains one CMS timing failure.

That CMS failure also logs stale kqueue write-filter changes targeting closed
descriptors. The callback now disables its one-shot write event through nginx's
API so close-time cleanup can cancel a pending change after a refused login;
it must neither spin on writable readiness nor retain a deletion for a reused
descriptor. Live CMS tests retain their original timing bounds and now reject
bad-descriptor/double-close diagnostics. macOS passes all four live CMS cases
and six compiled callback cases. The fresh native FreeBSD server/module/client
build completes successfully. One earlier premature live launcher stops before
pytest because that server did not yet exist, and its owned VNET fixture is
retired successfully. Its failed setup evidence remains preserved.

The native compiled callback/descriptor-ownership selection passes 12/12 in
11.64 seconds at the original limits. Six former Linux-only ownership cases
now use FreeBSD's actual pipe/spawn PAL and ELF syscall interposition. They
retain successful registration, rejected registration and refused allocation
checks for both the alternate-DS and perf-feed owners. The first attempt's six
setup errors at the 30-second compilation limit remain preserved; a separate
diagnostic build completes in 8.29 seconds before the successful fresh rerun.
These unit results do not substitute for the full run.

The completed live CMS rerun additionally identifies an immediate-connect
refusal path which warned before the cold-start window expired. That path now
leaves cold-start warning ownership with the existing retry scheduler, while
retaining failure metrics, DNS failure notification and retries. Previously
registered nodes and explicitly disabled fast windows still warn. Three new
compiled controls cover those distinctions. The complete corrected native
CMS/VNET/readiness/ownership selection has **61 passes, one Linux-only
`TCP_USER_TIMEOUT` skip and zero failures/errors**. The original two-second
window and sparse-backoff assertions remain unchanged. All nine callback
controls also pass on Ubuntu24. macOS's combined CMS/preload selection passes
27/27. These focused selections overlap; their totals must not be summed.

The broad native run finds a separate real preload ABI defect: epoll-shim's
`close` macro renamed the interposer to `epoll_shim_close`, leaving libc's
`close` unresolved. Native Python therefore wrote successfully but could not
close remote descriptors. The FreeBSD preload boundary now removes only that
macro; other client translation units retain the dependency's normal socket
bookkeeping. Positive, object-macro and function-macro controls plus the actual
shared-library symbol census verify the exported name and absence of the
accidental dependency override.

FreeBSD `cp` also uses kernel `copy_file_range`, which cannot consume a remote
shadow descriptor. A separate host-owned adapter preserves the native operation
for ordinary descriptors. Remote handles receive the documented invalid-kernel-
file-type refusal (`EINVAL`), without reading caller offset pointers or changing
bytes/offsets; `cp` then uses its ordinary read/write path. Explicit clone-only
requests remain unsupported, not emulated. An independent local-file probe
confirms that this `cp` falls back on `EINVAL`, but not `EOPNOTSUPP`, `EXDEV`,
`ENOSYS` or `EIO`. The original failed adapter attempt remains archived.
The complete supported preload/stdio/directory/ABI/offload selection passes
**42/42 on each FreeBSD and macOS**, with zero failures/errors/skips, including
the actual native FreeBSD `cp` and Python paths. Nine compiled offload controls
retain native delegation/error propagation, forced-clone refusal, invalid flags
and hostile-offset-pointer safety. Earlier failing artifacts are preserved
alongside the corrected source-overlay manifests and reports.

A final combined native CMS/VNET/readiness/descriptor-ownership/preload rerun
passes **75 tests with one Linux-only skip and zero failures/errors**, in
75.06 seconds. Its main server survives, and its owned pending-peer jail and
interface retire successfully. The 42-case preload selection above overlaps
this combined selection; neither is a new full-suite total. The final XML and
console are preserved in `cms-kqueue-v705/focused-final/` beside the original
failed attempts.

Subsequent process inspection finds a separate CMS monitor lifetime defect:
finished workers leave the monitor shell and its sleeping children alive.
Two new black-box cases fail against the preserved old SDK, including a
TERM-ignoring monitor. The corrected spawn must create its own process group
or fail closed; both EOF/error cleanup and worker exit forcibly retire that
stateless group without a blocking wait. Exit also cancels the respawn timer.
The tests preserve an unrelated process as a negative control, and compiled
controls verify refused group setup, no-feature exit and idempotent teardown.
The expanded complete focused selection passes **108 tests with one Linux-only
skip and zero failures/errors**, in 132.97 seconds. A repeat after test-helper
decomposition passes the same 108 cases with one skip in 124.84 seconds. Both
mains survive, both owned VNET peers retire, and a native process census finds
no remaining monitor scripts from either corrected run. Both baseline failures and the successful
XML/console are retained in `cms-kqueue-v705/focused-final/`. macOS builds the
same sources and passes 13 CMS/readiness checks; two live monitor cases remain
excluded by its existing hardened-worker subprocess prohibition, not relabelled
as passes. This focused result overlaps the earlier selections and is not a
replacement full-suite verdict.

V620's first canonical lane has finished all **41,940 cases**: **40,488 passed,
834 failed, zero errors, 563 ordinary skips, 47 expected failures and eight
unexpected passes**. Its progress record conserves collection/execution; JUnit
includes the eight unexpected passes in its passed aggregate. The original
snapshot is unchanged, so its failures are not retroactively removed by the
focused fixes. Its pre-teardown fleet sentinel additionally reports one
unreachable shared `cms-mesh` endpoint, port 11755 (128 reachable fleet ports
became 127). The TCP probe alone does not distinguish a missing listener from
an unresponsive one. Native system logs contain no matching XRootD/CMS crash
record, and the following lane has rebuilt the manager log. That liveness
failure remains unresolved, not presumed external. The subsequent 6,231-case
lane records 5,796 passes, 85 failures, six errors and 344 aggregate skips;
the 186-case lane records 162 passes, eight failures and 16 skips; the final
1,004-case lane records 717 passes, 276 failures and 11 skips. Five errors
come from native-reference cache warm-up; the sixth is a cross-device fixture
teardown timeout. A later unchanged-limit nine-case native cross-device rerun
passes without errors, but does not erase the original error. The final lane
includes 275 stock reference-client download failures; the independently
verified BriX client creates the expected bytes. Those dependency failures
remain red and are not relabelled as native-client passes.

All four XML, progress and failure records, the complete console and final
summary are retained under
`build/release-validation/freebsd-native-coverage-20261021/native-v620-final/`.
Separate CMS/preload artifacts are under its sibling `cms-kqueue-v705/`.

The staged-writer spill and cross-device upload selection additionally passes
**22/22 with zero failures/errors/skips**, in 130.25 seconds, against the
healthy independent Ubuntu24 reference. BriX, the upload stage device and the
export remain native FreeBSD; the SSHFS fixture lane retains symlink
containment. Its owned mounts, services and temporary account retire with no
cleanup errors. The native-reference failures remain separately recorded.
This focused evidence is retained in the remote-reference validation directory,
run `sshfs-v600-rmywwhuz`; it is not a replacement full-suite total.

The adversarial fixture had two observation defects: its control client
treated the first continued read frame as a complete file, and its FRM probe
sent cleartext HTTP to the fixture's TLS metrics listener. The corrected
observer reuses the shared response decoder, bounds the complete response by
the requested length, pins the stream ID and verifies the original exact bytes
and digest. Its negative controls retain short/corrupt response, excess-length,
foreign-stream and terminal-error rejection. The FRM fixture additionally
omitted its separate durable-registry directory; a transfer journal alone
returns the legitimate advisory ID `0`, not a durable ownership handle. The
fixture now configures that directory and treats a missing durable handle as a
failure, not a skip. The original failing attempt is preserved.

All **35 corrected native adversarial/FRM/cross-device cases pass**, with zero
failures/errors/skips, in 155.02 seconds. This includes the unchanged chaos
workload, FRM foreign-session cancellation refusal, flood/recycled-connection
checks and all nine cross-device upload checks at their original limits. The
main server survives. The 18 hermetic observer controls also pass on macOS.
Evidence is retained under the native validation directory in
`adversarial-v766/` (visible durable-handle failure) and `adversarial-v768/`
(corrected selection). These results overlap the selections above and do not
replace the red frozen full-run total.

The native GridCF dependency is now built and verified from the pinned archive
in a fresh non-root prefix. Its initial unpatched client aborts because the
upstream passwd-buffer assertion rejects FreeBSD's indeterminate limit; the
external-only compatibility patch preserves the native lookup. The reproducible
bootstrap completes successfully, and its real local-copy probe preserves all
65,792 bytes. The combined bootstrap/observer controls pass 55/55 on each
FreeBSD and macOS; the expanded portable-readiness controls pass 61/61 on
macOS. Compiled controls execute the exact added passwd-buffer compatibility
block for negative, zero and valid positive limits.

**23 native GridFTP cases that previously skipped now pass**, including
encrypted control/data transfers, parallel mode-E reads/writes, third-party
copy, VOMS allow/deny rules, missing objects and untrusted-CA rejection. The
remaining eight delegated-XRootD checks first skip behind a Linux-only `ss`
readiness probe. Replacing it with the shared TCP readiness helper and checking
the owned process exposes **eight setup errors**, not passes or skips: the
native reference remains alive but does not answer its configured IPv4
listener within the unchanged six-second budget. Its initialization banner
alone does not prove readiness. The repeat using the fresh reproducible
dependency records 29 passes (23 live cases plus six controls), eight errors
and zero skips. The original skipped result and both visible-error results
are retained; this does not certify delegated interoperability.

GridCF bootstrap/provenance and exact byte-copy evidence are retained under
the native validation directory in `gridftp-v778/`; the 55-case native
controls in `gridftp-controls-v780/`; and live baseline/error reports in
`gridftp-v775/`, `gridftp-readiness-v782/` and `gridftp-readiness-v784/`.
No system library, installed XRootD package, default boot environment or pool
feature was replaced. These are focused selections, not a new full-suite total.

The current corrected checkout also builds from scratch as immutable V787:
real nginx, dynamic server modules and native clients all complete. Its
module-load and byte-exact server smoke passes; the ordinary-user native
contracts record **35 passes, one root-only skip and zero failures/errors**.
The build receipt/source hashes are preserved in `snapshot-v787/`. This
new build is not itself a replacement full-suite result.

An additional full nine-case streaming-memory selection against healthy
external Python reference tools does **not** provide successful validation:
eight cases hit the bridge's existing bounded worker-record input path and
report broken-pipe errors; the TLS case cannot initialize its client context.
The native main survives and owned fixture resources retire with no cleanup
errors. No server failure or pass is inferred from these transport/client
setup failures, and the limits are not enlarged to mask them. The failed
evidence remains in remote-reference run `sshfs-v600-7fpldcd7`.

The operator-approved single explicit-address-family retry starts the native
GSI reference successfully. Three delegated checks pass (authenticated GET,
missing-object refusal and disabled-forwarding refusal), in addition to the
23 direct GridFTP checks. During the multi-chunk STOR check, the test's Python
process reaches roughly 28 GiB RSS while its upstream observer uses an
unbounded file read. The VM exhausts RAM/swap, OOM-kills other test workers and
then stops accepting SSH commands. This attempt is **incomplete**: its partial
26 passing cases are not a final 40-case result. Its host console and overlay
hashes remain in `gridftp-ipv4-v792/`. The concurrent fresh 315-case root
catalogue also exits before producing final XML; it is not a new root pass.

The upstream observer now checks the backing file's size against the exact
expected payload length **before** reading, and caps the read at that length
plus one byte. This keeps every original byte-equality assertion and catches
oversized/sparse reference output without allocating its extent. Missing-file,
correct-content, short-file and synthetic 16 TiB-size controls pass on macOS;
the expanded bootstrap/observer/readiness selection passes **68/68**. The latest
bounded-read correction was subsequently verified after the recovery below.

### Native recovery and fresh full run (22 October 2026)

The approved restart affected only `brix-freebsd15-native`, retaining its
32 GiB RAM, original kernel, stock OpenZFS 2.4.2, default boot environment and
pool features. Module fingerprints and pool health were checked after boot.
The isolated loopback, FUSE and cross-device fixtures were restored without
changing persistent boot or network configuration. Ubuntu24 was not restarted.

The preserved STOR output has a logical size of **4,398,046,556,185 bytes**,
versus the expected 307,225 bytes, but occupies only 745,984 allocated bytes.
The corrected observer rejects this actual sparse file before reading its
extent, with less than 8 MiB additional RSS. Its native bootstrap, observer,
readiness and adversarial controls pass **71/71**, with no skips. Round-trip
tests also verify upstream size before downloading and bound local reads,
preserving the original payloads, byte comparisons and timeouts.

The recovered, separately executed root authorization catalogue passes
**315/315**, with no failures, errors or skips. The earlier OOM-interrupted
catalogue remains recorded as incomplete; it is not retroactively a pass.
The complete focused GridFTP selection records **45 passes, two failures,
zero errors and zero skips**: 29 of 31 live interoperability cases pass,
alongside all 16 readiness/observer controls. Both remaining failures reject
incorrect native-reference file sizes safely; no oversized download occurs.

An independent black-box probe uses the same in-repository wire client to
write 17 bytes at offsets zero, 65,536 and 262,144 to both native servers.
BriX creates files of the exact expected sizes (17, 65,553 and 262,161).
The stock reference instead produces 17, 1,099,511,627,793 and
4,398,046,511,121 bytes. This isolates that offset defect to the installed
native reference server, without relying on its client bindings or inspecting
its implementation. The native-reference failures remain red; BriX does not
change its correct wire encoding to accommodate them.

Fresh immutable V805 builds the real server, dynamic modules and clients and
passes module-load plus byte-exact native `root://` smoke. A new canonical
full ordinary-user suite is **in progress**, with native GridCF/GFAL enabled
and the isolated root-supervised pending-connect fixture. The suite itself
runs as the non-wheel test user. There is no new complete full-suite total
yet, and V620 above remains the latest complete canonical result.

Recovery state, module fingerprints, XML reports, console logs, source hashes
and raw-wire proof are retained under
`build/release-validation/freebsd-native-recovery-20261022/` in
`recovery-v800/`, `root-v801/`, `observer-v803/`, `gridftp-bounded-v804/`,
`snapshot-v805/` and `offset-wire-v807/`. Focused totals are not added to or
substituted for a frozen full-suite result.

Two other stock-reference fixtures now reuse the existing numeric-address-family
selector rather than relying on the daemon's dual-stack default. Readiness also
requires the owned daemon to remain alive, so a foreign listener cannot bless
an exited process. Installed dependency startup/authentication failures are
failures, not capability skips. **All six native GSI interoperability cases
pass**, including stock-to-BriX signed-DH authentication. The broader
native-client/fallback/control selection passes **42 cases with one genuine
Linux-only io_uring skip**. Portable parser/verdict checks and TLS/unknown-engine
fallback checks no longer inherit the io_uring-only skip.

The newly enabled official-server FUSE baseline exposes a checksum mismatch;
it is retained as **one failure with 35 passes**, not relabeled unsupported.
Independent bounded reads isolate the reference behavior: a complete 8 MiB
read at offset zero is correct, but reads at offsets 65,536 and 131,072 return
empty data despite the unchanged 8 MiB backing file. Native BriX returns the
exact expected bytes at every tested offset and length.

That exposed a separate BriX FUSE error-handling defect: cached kernel reads
can pad a premature remote EOF with zeros. The client now verifies short root
reads using metadata from the **same authorized open handle**, never a pathname
reopen. Contradictory EOF returns `EIO`; full reads avoid the extra metadata
operation, genuine EOF/truncation remains supported, and metadata denials retain
their errors. All **31 sanitized C controls** pass on each FreeBSD and macOS.
The native inode-lifetime, real-mount, preload and C selection passes **60/60**,
without skips. Its first launch mistakenly used the minimal export instead of
the shared catalogue export and stopped after 31 passes/two missing-file
failures; that incomplete report is retained separately. Correcting the launcher
does not change any assertion. Both native clients build successfully; this is
not a macOS kernel-mount claim.

The approved optional-reference transport now fragments input into bounded
64 KiB pieces, retaining the **8 MiB transport-frame cap** and adding a separate
**64 MiB logical worker-record cap**, checked before each append and after
credential transformation. Requests retain their original payloads, offsets,
ordering and operation boundaries. Truncated/malformed requests never reach the
worker, connection prefixes cannot mix, and endpoint/credential confinement is
unchanged. The expanded transport controls pass **111/111** on both FreeBSD and
macOS. macOS required socket-enabled execution for four local Unix-socket
fixtures; the sandbox-denied attempt remains a setup error, not a code failure.

The full unchanged nine-case streaming-memory selection then records **eight
passes and one TLS-client initialization failure**, with zero skips, native
BriX survival and clean owned-resource retirement. These eight passes replace
neither the earlier nine-case failed attempt nor the native-reference results.
The TLS setup is being diagnosed separately; no verification switch is disabled.
Ubuntu24 was found stopped before the first live retry; that zero-test attempt
is retained, and only the existing reference-helper VM was started. FreeBSD's
full run and the other stopped VMs were not restarted or reconfigured.

Focused XML/source evidence is retained in the recovery directory above under
`fixture-controls-v809/`, `native-fallback-v810/`, `reference-live-v811/`,
`read-wire-v812/`, `fuse-short-read-v813/`, `fuse-short-read-v814/` and
`fragment-controls-v816/`. The complete nine-case reference attempt is
`sshfs-v600-c96jz4m7` in the existing remote-reference validation directory.
The immutable V805 full run remains in progress and its dependency failures
remain visible; these fixes are verified separately without patching that run.

Three additional controlled-origin tests now exercise the actual FreeBSD kernel
FUSE path, not just the C helper: exact bytes and genuine EOF succeed, while a
peer returning EOF before its advertised file size produces `EIO` rather than
zero padding. The expanded native selection passes **63/63**, without skips;
the final macOS bootstrap/observer/transport/sanitized-C selection passes
**226/226**, without skips. The latter is not a macOS mount result.

The same address-family/owned-readiness correction also enables the stock GSI
TPC source and Kerberos reference origins. Its first expanded selection records
**51 passes and one failure**, with zero skips: the native-client Kerberos
download times out while the installed reference repeatedly logs `sendfile
failure`. The fixtures now reuse the existing **reference-only** FreeBSD
`xrootd.async nosf` compatibility helper; BriX's production data path is not
changed. The identical live auth selection plus expanded ownership controls
passes **54/54**, without failures, errors or skips. Its 11 live cases include
server-side-only GSI TPC, Kerberos listing/stat/byte-exact download, delegated
cache fills, nonforwardable-ticket refusal and missing-cache refusal. Failure
before fixture yield now retires the owned origin/control directory, and forced
termination waits for its child to be reaped. Evidence is retained separately
in `fuse-short-read-v820/`, `auth-reference-v821/` and `auth-reference-v822/`.

The isolated Linux reference TLS initialization failure persists with an
explicit certificate/key from the existing disposable test PKI. That failed
single-case diagnostic and its clean resource retirement are retained in
remote run `sshfs-v600-mfrfphg5`; no root cause or TLS success is claimed, and
unchanged retries have stopped. No operator identity or verification bypass is
introduced. The native GSI/signed-DH passes above do not erase this independent
TLS-reference failure.

All **eight unchanged delegated GridFTP cases also pass** against a healthy
independent Linux XRootD origin, including multi-chunk STOR, byte-exact
round-trip, overwrite, parent creation and traversal refusal. BriX and GridCF
execute natively on FreeBSD; only the origin's configuration, certificates and
backing-file observations use the approved contained SSHFS fixture view of
native Linux storage. This is not native-ZFS validation and does not replace
the two red native-reference STOR results. The run retains exact source and
dependency provenance, has zero skips/errors/failures and retires all owned
resources cleanly: remote run `sshfs-v600-z2bt8w08`.

The skip audit exposed a real, portable checksum-path bug. A bare absolute
filename containing spaces or colons was mistaken for the legacy algorithm
prefix, so the server returned `ArgInvalid`. The checksum conformance postcheck
then incorrectly skipped that failure as an unavailable capability. Prefix
detection now stops at the path/CGI boundary; normal path confinement and the
unknown-algorithm refusal remain in force. Every BriX digest is also checked
against the existing independent mathematical oracle over the exact fixture
bytes, even when the optional stock checksum tool cannot answer.

The failing reproduction is retained as one failure before stopping after the
first of 16 selected cases. The corrected native module builds cleanly; its
complete checksum selection records **158 passed, zero failures/errors and 44
token-endpoint health skips**. This includes the formerly skipped space-name
checks on anonymous, GSI and TLS profiles, missing-file/unknown-algorithm
refusals, outside-export traversal refusal, and 15 sanitized bounded-parser
controls. The first expanded run also retains one negative-test diagnostic
spelling mismatch, subsequently corrected without changing server behavior.
All 23 parser/verdict controls pass separately on macOS; its supplementary
module rebuild is not certified because that old local SDK lacks original
source files. Evidence is retained in `checksum-v828/`, `checksum-v829/`,
`checksum-v831/` and `macos-checksum-controls-v830.xml` below the October 22
recovery directory. These focused results do not alter the immutable V805
full-run snapshot or establish a zero-failure full suite.

A follow-up pins the checksum CLI's leading output field: a hex-looking
filename or error message is not a digest. The extended native selection
completes **205 cases: 161 passed, zero failures/errors, 44 token-endpoint
health skips**, with all 26 parser/verdict controls passing on each FreeBSD
and macOS. Evidence is retained in `checksum-v837/` and
`macos-checksum-controls-v836.xml`. The ARM64 package catalogue was also
checked for Ceph/RADOS development libraries; neither is available in this
VM's configured repository or was found in the checked native build/install paths.
No unrelated similarly named package was substituted.

When the VM reached 1.6 GiB free space, twelve exact 200 MiB regenerable seeds
from completed focused runs were retired after inode/size/time, ownership and
process-inactivity checks. All reports, configs, logs and failure artifacts,
and the active V805 test root, remain intact. The pool subsequently reported
3.9 GiB available. Exact file identities and cleanup results are retained in
`seed-space-v834/`; only regenerated replacements, not the deleted original
random bytes, are recoverable.

The subsequent hybrid-mesh timeout was traced without changing the active
topology: the native BriX relay forwards the upstream `kXR_wait` response,
while the independent stock XRootD redirector logs `EINVAL` connecting to its
CMS manager and repeatedly reports no available managers. The native cmsd
process owns the expected IPv4 listener. Stock data cmsd also reports its
default 10 GiB minimum free-space requirement. These observations, not an
inferred BriX fix or a new skip, are retained in `hybrid-v839/`.

The approved inactive-seed cleanup subsequently retired 54 additional exact
200 MiB files, restoring **14 GiB free space** while the full run continued.
Foreign-owned files, roots without completed XML, and active roots were
excluded; every selected inode/size/time and process-inactivity check was
repeated before unlink. `seed-space-v840/` preserves the initial safety-check
refusal; `seed-space-v841/` preserves the eligible/excluded inventory and exact
cleanup results. No reports, logs, configs, failed-case artifacts or active
full-run data were removed. Regeneration is required to replace the deleted
seed bytes. Recovered disk space does not repair the external CMS connector
failure or erase any recorded native failure.

### October 22 final full-run checkpoint

The immutable V805 snapshot completed all four canonical lanes, including
suite-job checks, in **12,523.69 seconds** (about 3 h 29 min). Its final totals
are **49,497 tests: 47,385 passed, 1,175 failed, 5 errors and 932 aggregate
JUnit skips**. The latter separates into **881 ordinary skips and 51 XFAIL**;
the pass count includes **8 XPASS**. Execution and report completeness checks
both pass. These are completed **red** results, not interrupted-run estimates.
The final per-lane XML, live progress/failure records, summary and independently
reconciled counts are retained under
`build/release-validation/freebsd-native-recovery-20261022/native-v805-final/`.
The source/build snapshot was not patched while this run was active.

All five setup errors occur in the native-reference cache-fault lane, whose
origin cannot complete the baseline cache fill. Earlier independent raw-wire
checks demonstrate incorrect native reference offsets and premature EOF;
local-copy, attribute-status and CMS failures also remain visible. These
observations do **not** establish that every full-run failure is external.
The ordinary-account full run also retains root-only and wrong-platform skips;
the separate **315-pass privileged lane** is not merged into these totals.

The approved one-shot TLS diagnostic captured bounded Debug logs and
file-operation names/results only, using disposable fixture credentials. It
found OpenSSL's explicit **certificate/private-key mismatch**: the reference
loaded the proxy certificate and the unrelated end-user key before connecting
to BriX. Using the same disposable proxy PEM for the positive fixture's cert
and key clears initialization without disabling verification. That attempt
then exposes an independent fixture-root mismatch: the main server still
exports the shared view while canonical data is seeded on native storage.
The catalogue now selects `DATA_ROOT` for BriX's main instance, retaining the
independent reference's own shared export; ordinary native paths are unchanged.
Credential/endpoint mediation is not rewritten to repair intentionally absent
or mismatched credentials in negative tests.

After both fixture corrections, the **original nine-case streaming-memory
selection passes 9/9**, including the complete **200 MiB TLS read in 8 MiB
chunks**, with zero failures/errors/skips and clean owned-resource retirement.
The failed diagnostic, intermediate missing-file result, and one zero-test
port-collision setup attempt remain archived separately; they are not passes.
Evidence is retained in the remote-reference validation directory as
`sshfs-v600-zmvj00cy`, `sshfs-v600-z9x52qnx`, `sshfs-v600-14j8_pmt` and
`sshfs-v600-54a_3csn` respectively. The initial diagnostic-controller setup
exception, before any TLS operation, is retained as `sshfs-v600-pp3h1mt1`.

The full-run OCI background-GC failure also exposes a fixture race: its
zero-grace timer may reclaim a newly sealed blob before the manifest naming
it arrives. The reclamation tests now finish their pushes before arming the
**same one-second, zero-grace sweep** through normal config validation/reload.
They still assert orphan removal, shared/live blob retention, manifest
survival and byte-exact serving. The separate grace-window test still runs
maintenance during pushes and verifies young-blob protection. No production
GC behavior, timeout or refusal assertion is relaxed. The native background
and offline GC tests plus fixture/framing controls pass **182/182**, without
skips, in `oci-gc-v847/` below the recovery directory. The address-family unit
corpus now carries reason-bearing host-literal annotations; no operational
endpoint is hard-coded and the host-literal gate passes. The expanded macOS
fixture/namespace/transport controls pass **170/170**, without skips, in
`macos-fixture-controls-v849.xml`; that is not a macOS mount certification.

The two explicitly approved fragmentation files were staged and all preceding
index entries preserved, verified by `staging-v843.json` in the recovery
directory. No tracked edits were staged and no commit or push was made.

#### Follow-up: token coverage and self-provisioned S3 cache

The expanded native-storage/healthy-reference selection completes **311 cases:
264 passed, zero failures/errors, 47 skipped** (`sshfs-v600-ivonsoyu`). It
includes staged-writer spill, file APIs, GSI/TLS connection/read/readv,
readv security, hydration and the unchanged memory workloads. Its skips are
44 token-profile health skips and three retained, empty tests for the retired
protocol-plane slice-cache design. This is an optional-reference result, not
native dependency certification.

A new explicit token-profile availability assertion prevents those 44 health
skips from silently standing in for successful token coverage. The separately
approved bounded diagnostic finds that the *focused runner*, unlike canonical
fleet preparation, never issues `upstream.jwt`. The native ztn plugin loads
correctly and reports no token. The focused runner now reuses the existing
`IssuedTokensStep`; the generic production token lifetime/scope and validation
policy are unchanged. Private client token copies remain 0600 under a 0700
directory in the proven credential-fixture namespace, with cleanup on both
success and client failure. Shared server-token ownership/modes are untouched,
and ztn is selected explicitly rather than borrowing an ambient GSI identity.

Two retries initially used the stale VM copy of that private runner; read-only
hash/content and missing-file checks identify that transfer mistake. The final
runner is copied to a new unique VM path and its SHA256 independently verified
before execution. Its full native checksum/token matrix passes **219/219**, with
**zero skips, failures or errors**, including all 44 formerly skipped token
checks. Evidence, the exact runner receipt and XML are retained in
`token-verify-v858/`. The failed/incomplete attempts in `token-health-v851/`,
`token-verify-v855/` and `token-verify-v857/` remain separate, with their actual
collected/completed counts; they are not green full selections.

The Linux oracle has a separate bearer-only TLS initialization problem: its
credential-isolation sentinel is treated as a client key filename. The approved
diagnostic records that exact error before the request reaches BriX. A trial
using empty cert/key filenames is rejected by the reference and is removed;
it is **not** shipped as a fix. No verification switch is disabled, no proxy is
silently added to the token profile, and generic credential mediation is not
weakened. This optional remote-oracle case remains unresolved, independently
of the passing native token matrix. Diagnostic evidence is retained in
`token-diag-v854/` and remote run `sshfs-v600-r0ql9477`; the earlier explicit
remote failure is `sshfs-v600-aic_trqm`.

The GC/partial-cache/fixture/parser native selection completes **251 cases:
249 passed, zero failures/errors, two skips**, for unavailable S3 and RADOS
origin environments (`final-controls-v853/`). S3 does not actually require an
external service here: the helper now self-provisions a separate native,
read-only anonymous S3 origin using the existing committed template. The cache
still exercises the real `s3://` backend and native cache store. Whole-file
residency and exact returned bytes are checked; two new controls require
wire-level `NotFound` with no cached empty object, and refusal of an origin
symlink targeting an outside-export sentinel. This is not an AWS or signed-S3
authentication certification.

With that S3 lane enabled, the complete current token/checksum and partial-cache
selection records **244 tests: 243 passed, zero failures/errors, one RADOS
environment skip** (`s3-cache-v861/`). No skip was converted into a pass without
executing assertions. The native FreeBSD ARM64 RADOS SDK/cluster limitation
remains explicit. Current macOS fixture/transport/sanitized-parser controls also
pass **209/209** (`macos-final-controls-v856.xml`); the final token/namespace/
host-literal selection passes **29/29** (`macos-token-final-v859.xml`). These
overlapping focused results must not be added together or substituted for the
completed red V805 full-suite totals above.

## October 23 native revalidation and attribute-boundary fix

The fresh **V900** snapshot builds the real native server/modules and client
from the current checkout, including untracked support files. Its byte-exact
`root://` smoke passes. The non-wheel full attempt, including suite jobs and
the isolated pending-connect peer, is **incomplete**: physical-pool exhaustion
aborts execution and prevents final JUnit and summary creation. Its last stored
checkpoint records **41,250 completed cases** in the **42,143-case first lane**:
**39,878 passed, 8 XPASS, 802 failed, 515 ordinary skips and 47 XFAIL**. This
checkpoint is not a final count; subsequent lanes have no complete reports and
full-suite totals are unavailable. Raw progress, all 802 durable failure records
and the ENOSPC console are preserved in `native-v900-incomplete/`. V805 remains
the latest completed canonical result. V900's source and binaries are never
patched during the attempt; corrections use a separate V901 SDK.

The separate root-only authorization catalogue completes **315/315 passed**,
with no failures, errors or skips. Those privileged results are not substituted
for the ordinary full run's skipped root-only cases or counted twice.
The full privileged catalogue is repeated after the shared attribute fix and
again passes **315/315**; its completed collection/execution record and exact
module hashes are retained separately in `root-v913/`.

The native runner now pins the matching dynamic nginx, BriX modules and core
stream module for the dynamic-load tests, including when inherited paths are
missing, invalid or point at another build. FreeBSD's `dpkg` package is installed
for the packaged-artifact check. All four dynamic loading/package checks run
and pass instead of skipping because of a developer-home default path. The
FreeBSD CI dependency list also installs `dpkg`, so this coverage does not rely
on a manually provisioned lab. The native runner/CI controls pass **104/104**
without skips in `runner-controls-v915/`; an earlier port-collision refusal is
preserved separately and is not a successful test run. The native package
catalogue still provides no Ceph/RADOS SDK for this ARM64 lab.

Raw-wire controls reproduce and repair the missing-file attribute response:
authorized Get requests now retain every requested name and return per-attribute
`NotFound` with empty values. Authorization denials, malformed vectors and the
other suboperations retain their own refusal contracts. Three former expected
failures now pass against a healthy independent Linux reference.

The new confinement controls also expose a real defect in the ordinary,
non-impersonated attribute helper: a pathname syscall after a stat can read an
outside symlink's attributes, and admitting a missing Get target also exposes
traversal. The shared POSIX helper now opens through the existing confined-open
boundary, performs every attribute operation on that descriptor, and preserves
failure errno across close. It never reopens the client pathname for the actual
attribute syscall. Mapped-user broker routing remains unchanged. Read/write
controls verify ordinary files, directories, write-only updates without data
reads/truncation, denied lookups and unchanged outside sentinels.

The corrected native regression selection completes **147/147 passed**, without
failures, errors or skips. It includes the real publish/open/resolution kernels
in the object-linked durability tests; only unrelated, sanitizer-retained
startup paths have aborting test boundaries. The native Python-quality gate
also passes after its expanded artifact-selection test is decomposed to meet
the unchanged NPath limit. The failed reproduction and intermediate link/setup
reports remain separate, not relabeled as passes.

An expanded native cross-protocol selection also completes **129/129 passed**,
without skips or errors: S3 tagging, WebDAV properties and locking, lock-startup
sweeps, recursive lock checks, and native root attribute/query operations. The
raw metadata controls additionally preserve legitimate in-export symlinks and
prove that opening a FIFO for metadata cannot park the single nginx worker.

The contained optional reference lane completes **274 cases: 253 passed,
21 existing XFAIL, zero failures/errors/ordinary skips**. BriX runs natively on
FreeBSD; the independent official reference runs on Linux. SSHFS containment
stays enabled, and all owned resources retire cleanly. The remaining expected
failures cover the existing query-access-key and FRM-off prepare differences;
this is not a release-green or native-reference certification.

The independent CRC32C verifier was also missing from the native test Python.
Installing only `py312-crc32c` 2.9 enables the original HTTP Digest and 200 MiB
root checksum comparisons. Their expanded native selection completes
**130/130 passed**, including malformed-request/security controls and the
updated CI dependency checks, without skips. CI now provisions that package.
The exact package transaction and its timing during V900 are retained in
`crc32c-dependency-v917/`; the running snapshot's source and modules are not
patched by this prerequisite install.

Five codec-drop checks and three Kerberos principal checks previously skipped
because their harnesses lacked native include/link inputs. The codec probes
now use the shared dependency selector, preserve explicit LZ4 overrides and
fail on compiler errors; the principal harness links the real nginx formatter
object and likewise fails on link errors. All original success, overflow and
principal-injection assertions remain. The native probe/control selection
passes **28/28**, without skips, in `native-probes-v919/`.

V900 subsequently exposes stale catalogue/cache-helper refactor guards and a
native process-inspection race, in addition to the already repaired quality
test. The ledger now records the native main-export correction and pins the
exact reviewed HTTP/S3 replacement bodies. Portable AST fingerprints omit only
empty formatting fields that differ between Python versions; missing, altered
and added bodies still fail their controls. An `EBUSY` then `AccessDenied`
environment read retains unknown live ownership, rather than aborting the
entire host snapshot or fabricating an empty environment. Cleanup still refuses
unknown live harness ownership. The combined native guard/ownership selection
passes **122/122**, without skips, in `native-probes-v924/`; the portable macOS
countercheck passes **132/132** in `macos-harness-v925.xml`. Failed intermediate
hash/ledger checks remain archived separately. These focused selections overlap
and are not added together or substituted for the frozen full run's failures.

The attempt additionally exposes stale offline GSI ownership controls that
still mock an obsolete readiness helper and expect installed-daemon failures
to skip. They now mock the actual process-aware readiness boundary and retain
explicit startup failures, owned-only teardown, root handoff and foreign-killer
refusals. These **offline** controls pass **20/20** natively in
`native-probes-v933/` and **20/20** on macOS in `macos-gsi-controls-v932.xml`;
they do not certify the failing native external GSI dependency.

The lab reaches physical-pool pressure. Five regenerable 200 MiB
seeds from wholly passing focused fixtures are removed with exact inode,
ownership, completed-JUnit and inactivity checks; all reports and failed-case
artifacts remain. Removing 591 MiB of downloaded package archives leaves the
installed inventory unchanged, but the preserved boot snapshot retains those
blocks, so this is not equivalent physical-space recovery. Following explicit
operator approval, the exact inactive-binary inventory is consolidated using
the pool's already-active CoW facility: **371 duplicate images are replaced**,
and **all 392 inventoried paths** pass the final SHA-256, owner, mode, ACL, flag,
mtime and distinct single-link inode audit. Every path and byte is preserved;
the new inodes remain independently writable. The first copy pass stops on
transient ENOSPC after 240 replacements. A receipt-checked continuation waits
for ZFS transaction settlement between batches and completes the remaining
131; neither the partial pass nor the inventory alone is recorded as success.

After settlement, the lab has **2,104,524,800 bytes (1.96 GiB) available**.
This remains below the stock reference data daemon's recorded 10 GiB
free-space floor and is inadequate headroom for a fresh full attempt; no full
rerun starts. The corrected native server/modules retain their recorded hashes,
and a fresh byte-exact native `root://` smoke passes. Capacity expansion requires
separate operator approval. The boot snapshot, kernel, pool features and other
VMs remain unchanged. The existing fail-closed ownership checker also retires
the two leftover workers from the aborted attempt; its receipt is retained with
the incomplete reports. Space/audit receipts are in `seed-space-v916/`,
`seed-space-v931/`, `package-cache-v926/`, `binary-clone-v929/` and
`post-consolidation-v936/`. Only the two newly approved attribute regression
files are staged in this step; `stage-v934/` verifies every unrelated index
entry is unchanged. No tracked-file edits are staged, committed or pushed.

Evidence is retained under
`build/release-validation/freebsd-native-recovery-20261023/` in
`snapshot-v900/`, `root-v904/`, `root-v913/`, `xattr-v911/`,
`protocol-metadata-v912/` and `runner-controls-v915/`;
live full-run observations are
in `v900-live.json`. The optional lane is retained separately as
`sshfs-v600-tl6nogbi` under the remote-reference validation directory. No commit
or push is made, and no native-reference failure is replaced by a remote pass.

## October 23 build cleanup, capacity expansion and resumed validation

The operator subsequently approves removing obsolete builds, restarting only
FreeBSD, expanding its disk and resuming validation. The exact cleanup removes
**20 inactive native build/SDK directories**, after archiving and SHA-256
verifying **1,705 embedded report/configuration files** on the host. Source
trees, installed external dependencies, the corrected V901 SDK and the V805/V900
baseline SDKs remain. The deleted compiled outputs are regenerable from retained
sources, but their original binary files are not recoverable. Cleanup leaves
**6,569,099,264 bytes available** before the resize; logical directory sizes are
not substituted for measured physical recovery.

Lima gracefully stops and restarts only `brix-freebsd15-native`; Ubuntu24 remains
running. Its existing disk grows from **80 to 128 GiB**. GPT recovery relocates
the backup table, only partition 4 grows, and the existing ZFS vdev expands to
**135,828,340,736 bytes**. EFI, swap and config-drive partition entries remain
unchanged. The original default boot environment and OpenZFS 2.4.2 remain active;
no pool-feature upgrade occurs. The dedicated `/bf118` test dataset's old 36 GiB
quota grows to **64 GiB**, providing about **44 GiB of fixture headroom**. The
temporary loopback aliases, FUSE access, cross-device tmpfs staging, anonymous
port range and 4 GiB ARC limit are restored for validation, without persistent
network or boot-setting changes.

The fresh **V940** source snapshot and native server/client build complete
successfully. All **12,384 captured source files** match their recorded hashes
before testing; exact module and client hashes are recorded separately. Its
byte-exact native `root://` smoke passes, and the canonical full suite resumes
with two workers, suite jobs and the isolated pending-connect fixture under the
ordinary non-wheel test account. This is a **new in-progress attempt**, not a
completed or release-green result. The previous ENOSPC attempt and canonical
V805 failures remain visible, and native reference dependencies are not silently
replaced by remote clients.

Evidence is retained under
`build/release-validation/freebsd-native-recovery-20261023/` in
`old-build-cleanup-v937/`, `resize-v939/`, `snapshot-v940/` and `v940-live.json`.
The embedded report archive is `old-build-cleanup-v937/preserved-reports.tar`.

## October 23 native TPC and namespace-lock regressions

The frozen V940 full attempt exposes new `EXDEV` failures in native TPC and
symlink removal, plus an oversized Python test module. The corrections are
built and exercised in the idle V901 correction SDK, **not applied to the
running V940 source, modules or fleet**.

TPC's destination context was prematurely stripped to a logical storage key.
The lock gate expects a confined export-absolute path, and the hardened
descriptor-based attribute boundary correctly refuses the mismatched path.
The context now retains the confined path; the VFS strips/translates it for the
selected backend. This also ensures ancestor-lock checks reach the export root.
Real native pulls prove exact destination bytes, expired-lock acceptance,
live root-lock refusal before creation, unchanged source bytes and unreaped lock
records. No escape errno is reclassified as an absent lock.

Namespace REMOVE now verifies a trailing symlink without following it and
checks its ancestors without reading the referent's metadata. Inside, outside
and dangling links can be unlinked without changing their targets; a live
ancestor lock still prevents removal. Data opens retain confinement refusal.
The object-linked gate control also proves that a failed inode-type probe
cannot waive a hard lock-read failure.

The native regression selection passes **223/223**, and the broader original
TPC families pass **177/177**, both without failures, errors or skips. They
cover TLS/GSI, SSS, token exchange, credential renewal, async TPC, backend
crossings, capability claims and the original native-client symlink regression.
The final gate/fixture-control selection passes **106/106** natively; the
portable runner/MinIO split also passes **105/105** on macOS. These are
**overlapping selections**, not additive full-suite totals. MinIO lifecycle
controls move to a focused test module without dropping assertions. The
unchanged 600-line Python/native gates, Python/native complexity, duplication,
logging, platform and storage-boundary checks pass.

The corrected SDK's separate root-only catalogue again passes **315/315**,
with completed collection/execution conservation evidence and exact module
hashes. This exercises privileged authorization that the ordinary account must
skip; it does not relabel or subtract that account's skipped cases.

The previously approved contained independent-reference lane completes the
**full 60-module, 3,464-case differential catalogue**: **3,419 passed, 15 failed,
0 errors, 0 ordinary skips and 30 XFAIL**. Collection and execution totals
reconcile. BriX runs natively on FreeBSD and the official reference tools run on
Linux. Fixture-sharing, SFTP containment and seed benchmark controls pass, and
the controller reports successful cleanup. All 15 failures are native GFAL
nonempty upload/download transfers returning `EINVAL`; their cause is not yet
established. A native GFAL local-to-local control passes empty and 4,097-byte
copies without any server. This separate diagnostic lane is **not** native
reference certification or a replacement for the full native suite's failures.

A subsequent private selection records **59/69**, without errors or skips.
Its ten client-feature failures are traced to that diagnostic runner selecting
the minimal read-only security fixture instead of the canonical writable core
fixture. They are not classified as external dependency failures. With the
correct writable fixture, the unchanged native client-feature module passes
**13/13**; the final broader coverage selection passes **84/84**, with no
failures, errors or skips. The cache-residency guard controls now supply the
complete frozen builder ledger instead of omitting unrelated required bodies.
On macOS, **142/142** portable runner, MinIO and historical-move controls pass. The
missing-client diagnostic control no longer requires an installed nginx build:
it supplies an existing executable for the metadata-only earlier prerequisite,
without launching it or weakening the real prerequisite checks.

VM access is restored after an approval-service interruption. V940 continues
without replacement of its frozen sources, modules or fleet and finishes all
four lanes. The completed results supersede earlier partial progress counts,
not the preserved failure evidence.

Evidence is retained under
`build/release-validation/freebsd-native-recovery-20261023/` in `tpc-lock-v941/`,
`tpc-lock-v942/`, `tpc-expanded-v944/`, `root-v945/`, `native-probes-v947/` and
`macos-native-runner-split-v941.xml`. Later results are in
`tpc-final-variants-v951/` and `macos-runner-cache-controls-v954.xml`.
The independent lane is
`build/release-validation/freebsd-remote-reference-20261019/sshfs-v600-wmmi8asv/`.
No native full-suite failure is replaced by an overlapping focused pass.

## October 23 completed native full run and coverage recovery

V940 completes the canonical ordinary-user suite with two workers, suite jobs,
native reference tools and the isolated VNET pending-connect fixture. Every
lane's completed count equals its collected count. Runtime is **12,011.47
seconds**; the final runner exits 1. The VM remains on its original kernel and
OpenZFS 2.4.2, with no swap in use and approximately 40 GiB free afterward.

| Native lane | Tests | Passed | Failed | Errors | Skipped | XFAIL |
|---|---:|---:|---:|---:|---:|---:|
| Main | 42,186 | 40,740 | 896 | 0 | 506 | 44 |
| Lifecycle/serial | 6,231 | 5,804 | 112 | 5 | 306 | 4 |
| Resilience | 186 | 165 | 16 | 0 | 5 | 0 |
| Client conformance | 1,034 | 755 | 276 | 0 | 3 | 0 |
| Total | 49,637 | 47,464 | 1,300 | 5 | 820 | 48 |

The main lane's passed count includes eight XPASS. The scheduler deliberately
excludes the Linux-user-namespace-only directory; it is not native FreeBSD
coverage. Root-only cases remain honestly skipped in the ordinary-user count;
the corrected SDK's separate **315/315** root catalogue exercises privileged
authorization without subtracting those skips.

Further corrections remove avoidable coverage gaps:

- Session/handle fixtures use the authoritative overwrite bit `0x0002`, not
  the unrelated force bit, and seed their own independent files. A failed
  writable open is an assertion failure rather than a skip.
- WebDAV confinement checks test readiness when their fixture runs, after
  fleet setup, not during module import. A genuinely absent listener still
  reports its missing prerequisite.
- Cache eviction discovers the official `xrdfs` through the canonical harness
  instead of assuming `/usr/bin/xrdfs`; FreeBSD's installed reference is under
  `/usr/local/bin`.
- Native Helm now enables both chart-rendering modules: **27/27** pass. The
  final runner/coverage/analyzer prerequisite controls plus those modules pass
  **153/153** natively, with no skips; the portable controls pass **126/126**
  on macOS. These selections overlap earlier focused results.
- The native analyzer now receives the selected SDK's real generated graph
  and compiler working directory. Explicit compiler selection remains separate
  from server Clang, and failed compilation cannot be hidden by a preceding
  analyzer warning.

Other corrected-SDK checks pass **62/62** release TPC stream/multihop/identity
cases and **16/16** bearer-token TPC cases, without failures, errors or skips.
Three additional stock-destination variants still fail with native reference
local-copy `EINVAL`; their successful BriX-destination controls do not erase
those failures.

The native storage spill/overlay diagnostic passes **5/5** using an independent
raw-wire encoder with the original byte-exact and refusal assertions. Three
cache verification diagnostics pass against a separately configured native
BriX origin: valid cold/warm fill, corrupt-fill refusal and recovery, and
persisted checksum verification. The original stock-origin failures remain
recorded; a BriX origin is not an independent reference certification.

The healthy Linux GFAL counterproof passes **22/22** checks against native
FreeBSD BriX over isolated loopback SSH forwarding: ten sizes from empty to
1 MiB upload and download byte-exactly, plus missing-object and read-only
refusals. Owned forwards and disposable namespaces are cleaned up, and outside
fixtures remain unchanged. Native GFAL still fails nonempty remote transfers:
its earlier local-to-local controls pass, so the evidence narrows the problem
to its native remote-transfer path, not all local file I/O. This does not
replace the independent differential lane's 15 native GFAL failures.

Remaining native full-run failures include the installed XRootD client's
malformed 64-bit offsets and local-copy `EINVAL`, reference CMS/HTTP problems,
and V940's pre-correction TPC path/lock regressions. The client-conformance
lane records **275** `xrdcp` parity failures and one cross-client read failure;
captured diagnostics include stock local-copy refusal where BriX produces the
expected nonempty output. The five setup errors are cache-fault warmup failures
against the stock origin. These categories are evidence for investigation,
**not a blanket assertion that every remaining failure is external**.

The newly enabled complete GCC analyzer checks **1,225 sources** without
compilation errors. GCC 14 reports **14 findings**; a separate GCC 16 comparison
reports **11 findings**. Neither result is green. Traces include descriptor
ownership transfers, an archive allocation, S3 marker parsing and completion
pointer contracts; proving or restructuring those paths remains work. No
finding baseline, suppression or waived test is introduced. The server remains
built with native Clang, and no system compiler symlink is changed.

Subsequent S3 contract clarifications independently reject a missing staging
marker or full listing sink before deriving pointers or appending records, and
remove a contradictory nullable-connection check from a completion whose held
request already requires that connection. The incremental native build and
**55/55** multipart/checksum/tagging/sanitizer checks pass without skips.
The nine new bounds/acceptance controls also pass on macOS. Their initial
FreeBSD link-closure error is retained: compiling the complete nginx string
translation unit under ASan retained unrelated allocator dependencies. The
corrected unit extracts the actual selected SDK's copy-helper body and retains
both ASan and UBSan; it does not replace that helper with a stub.

A repeated **complete 1,225-source GCC 16** analysis has **nine remaining
findings**, with no compilation errors. Both earlier S3 contract findings are
gone without suppressions. An independent GCC 14 check of all **54 S3 sources**
reports zero findings; that filtered result is not a whole-tree gate pass.
The remaining GCC 16 report includes descriptor ownership, archive allocation
and checksum/base64 output-initialization reasoning, all still unresolved.

Most remaining skips are foreign-platform/kernel contracts, intentionally
inapplicable authentication combinations, retired features, Linux-container
fixtures or root-only tests covered separately. Native reference startup,
unavailable external dependencies and known project XFAILs also remain visible;
the target is **not** certified as fully working or at a 99% pass threshold.

Final evidence is under
`build/release-validation/freebsd-native-recovery-20261023/`:
`native-v940-checkpoints/summary.json`, `reconciled-summary.json`, all four
JUnit/progress/failure files and SHA256 receipts; `client-features-v957/`,
`coverage-final-v969/`, `release-tpc-v973/`, `token-tpc-v974/`,
`storage-wire-v979/`, `cache-verify-v991/`, `linux-gfal-v964/`,
`coverage-runner-v1004/`, `s3-build-v1009/`, `s3-contracts-v1009/`,
`analyzers-v1005/`, `analyzers-v1010/` and `gates-v1013/`.
GCC 16 retains a complete raw
trace; GCC 14 retains its full findings summary and focused ownership/S3 traces.
