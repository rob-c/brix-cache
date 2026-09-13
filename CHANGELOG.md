# Changelog

Notable changes per release. The version in `src/core/ident.h`
(`BRIX_SERVER_VERSION_BARE`) is the single source of truth; the RPM version,
the spec's literal fallback, this file's top entry and the git tag all derive
from it, and `tools/ci/check_version_sync.py` fails CI if they drift apart.
Cutting a release is documented in
[docs/09-developer-guide/release-process.md](docs/09-developer-guide/release-process.md).

Versions that were never cut: **1.0.6**, **1.1.0**, **1.2.x**. The version line
skipped them; they are not missing entries. Version 1.1.1 was subsequently
revised as RPM releases (`1.1.1-3` … `1.1.1-25`) whose per-revision packaging detail
lives in the `%changelog` of
[`packaging/rpm/nginx-mod-brix-cache.spec`](packaging/rpm/nginx-mod-brix-cache.spec)
— that file remains authoritative for packaging changes; this one summarises
what changed for a user of the server.

---

## v2.0.0 — 2026-09-05

The first release distributed as `.rpm` and `.deb` packages. What a user may
expect and what is actually present, tested, complete and documented is
audited in the [2.0 readiness register](docs/10-reference/release-2.0-readiness.md);
every registered directive now has user-facing prose in
[`docs/03-configuration/directives.md`](docs/03-configuration/directives.md),
and `tests/test_release20_directive_surface.py` together with
`tests/test_release20_surface_pins.py` (which snapshots the whole 2.0 directive
surface in `tests/golden/release20_directive_surface.tsv`) and
`tests/test_release20_ledger_pins.py` (which holds the prose half — the gap
ledger, the quick reference, the operator trees and the status banners) keep the
register, the registry and the prose in step.

### Breaking

- **A native `brix_authdb` line the grammar cannot parse now refuses the
  configuration.** Before 2.0 field 1 was read as its first byte and unknown
  privilege letters were dropped, so a mistyped line was accepted as some
  *other* rule — often a wider one (`gu atlas|alice /data rl` became
  `g atlas /data rl`, granting the whole VO). The native engine now refuses the
  line at `nginx -t`, naming the file, the line number and the offending byte,
  for: a selector outside `u g p a v l`, a privilege letter outside
  `r l w a d m k x`, a repeated selector, `a` combined with another selector, a
  compound id whose component count does not equal the selector count, and an
  empty id component. Check any authdb that was written against the old parser
  before upgrading; a line that "worked" may have been enforcing something other
  than what it said. **This applies to the native engine only** — a file read
  under `brix_authdb_engine xrdacc` is parsed by the XrdAcc grammar exactly as
  before, and the refusal message points there.

- **Staging now requires the `x` privilege in the native authdb.** `kXR_prepare`
  with `kXR_stage` or `kXR_evict` (`xrdfs prepare -s` / `-e`) and the VFS
  stage/evict mutations previously fell inside the update-privilege range, so an
  authdb granting `w` implicitly granted the right to drive a tape or nearline
  recall — and to drop an online copy. They now require `x`, together with `r`,
  and `w` alone no longer grants either. Add `x` to any rule whose subjects are
  meant to stage: `u alice /data rlwx`. A *bare* prepare, which only browses the
  namespace, still needs only `r`. Unchanged under `brix_authdb_engine xrdacc`,
  where staging has always been `AOP_Stage`.

- **VOMS roles now actually reach authorization.** The identity's VOMS attribute
  views were derived from VO *names*, which cannot contain a `/` (they are metric
  labels and log fields), so the derived role list was always empty. Any rule or
  template that matched on a role therefore matched **nothing**, silently: the
  XrdAcc `r <role>` selector, an XrdAcc `g /vo` group path, and — for
  configurations built against a pre-release 2.0 tree — the native `l` selector.
  Those rules now match the credential the operator meant, which can turn a
  previously ineffective grant into a real one. Audit any authdb carrying a role
  or group-path selector before upgrading. VO *names* are untouched:
  `$brix_vo`, `brix_require_vo`, the native `g` selector and every metric label
  keep exactly the values they had.

- **`brix_mirror_opcodes` and `brix_mirror_exclude_opcodes` refuse `read` and
  `readv`.** A read addresses an open handle that only the primary session
  holds, so the one-shot shadow replay never carried it — the names were
  accepted and then silently skipped, and `all` expanded to them, so a mask
  meant less than it said. Both directives now refuse the two names at
  `nginx -t` with that reason, and `all` no longer includes them. Delete them
  from a mask that still lists them; nothing else changes. Pinned by
  `tests/test_release20_mirror_opcode_refusal.py`.

- **`brix_pss_dca` has been removed.** The directive was registered in
  1.4/1.5 but had no consumer: no code path ever issued the kXR_lclfile
  redirect it described, so `on` and `off` behaved identically. A
  configuration that still carries it is now refused at `nginx -t` with
  `unknown directive "brix_pss_dca"`; delete the line. Direct cache access is
  listed as not implemented in the
  [2.0 readiness register](docs/10-reference/release-2.0-readiness.md).

- **`brix_backend_passthrough_persist` has been removed.** Reserved by
  phase-70 §5.1 to let a captured full-proxy credential be spilled into the
  async stage for later replay, the flag parsed, merged and adopted but was
  never read (DEFECT CANDIDATE #35 of the 2026-08-15 coverage audit): `on`
  and `off` behaved identically. A configuration that still carries it is
  refused at `nginx -t` with `unknown directive
  "brix_backend_passthrough_persist"`; delete the line.

- **Seven `brix_frm_*` directives are removed.** `brix_frm_copycmd`,
  `brix_frm_migrate_copycmd`, `brix_frm_residency_cmd`, `brix_frm_xfrhold`,
  `brix_frm_max_per_source`, `brix_frm_stage_dir` and
  `brix_frm_force_scratch` configured the in-process FRM engine dissolved in
  phase 64 and had been parsed and read by nothing since; no surviving
  subsystem could honestly own them (phase-89 ADR-3b, 2026-09-08,
  superseding ADR-3's "retain the grammar"). A configuration that still
  carries one is refused at `nginx -t` with `unknown directive
  "brix_frm_copycmd"` (and likewise for the other six); delete the line. The
  copy runner is the `tape://exec` adapter's `brix_frm_stagecmd`, the PUT
  stage directory is `brix_stage_dir`, scratch policy is
  `brix_zip_force_scratch`. The other six formerly inert names were wired
  (see Added / Changed).
- **`brix_frm_stagecmd` no longer inherits `brix_prepare_command`** at merge
  time, and the value is checked: it must be an absolute program path and,
  when the file exists at load, must not be group- or world-writable
  (`[emerg] … refusing to run a program anyone else can rewrite`). Every
  `brix_frm on` server must publish the same `brix_frm_queue_path`,
  `brix_frm_stagecmd`, `brix_frm_copymax`, `brix_frm_fail_retries`,
  `brix_frm_fail_backoff` and `brix_frm_copy_timeout` — the stage engine is
  process-wide and a disagreeing server is refused at `nginx -t`
  (`… differs from the value another brix_frm server published (…): the
  stage engine is process-wide`).

- **Observability compatibility aliases have been removed.** Update nginx
  `log_format` variables, JSON ingest mappings and Prometheus queries before
  deploying this version. Canonical replacements are:

  | Removed surface | Replacement |
  |---|---|
  | `$brix_session_dn`, `$brix_session_vo`, `$brix_session_user` | `$brix_dn`, `$brix_vo`, `$brix_sub` |
  | `$brix_session_auth`, `$brix_session_tls` | `$brix_auth_method`, `$brix_tls` |
  | `$brix_session_bytes_out`, `$brix_session_bytes_in` | `$brix_bytes_served`, `$brix_bytes_received` |
  | `$cvmfs_cache`, `$brix_cvmfs_cache`, `$oci_cache`, `$brix_oci_cache`, `$rpm_cache`, `$brix_rpm_cache` | `$brix_cache_status` |
  | JSON `bytes`, `latency_us`, `from_cache`, `subject` | `bytes_served`, `backend_time_us`, `cache_status`, `sub` |
  | stream/WebDAV/S3 byte counter aliases | `brix_io_bytes_read{proto}` / `brix_io_bytes_written{proto}` |
  | microsecond I/O latency histogram alias | `brix_io_latency_seconds` |
  | cache hit/miss counter aliases | `brix_cache_requests_total{proto,cache_status}` |

  Latency bucket values and sums are now seconds. The unified byte families use
  a bounded `proto` label and intentionally do not retain the removed per-listener
  `port`/`auth` breakdown. See
  [Phase 112](docs/refactor/phase-112-observability-compatibility-removal.md).

### Added

- **The native `brix_authdb` grammar: `v`/`l` identity selectors, compound
  selector sets, and the `x` (stage) privilege.** Field 1 of a native authdb
  line was documented as one letter from `u g p a` and was implemented as
  `line->type_p[0]` — the *first byte* of whatever was written there, with the
  rest discarded. `ug alice|atlas /data rl` was therefore accepted as
  `u alice|atlas`, a rule matching a DN nobody holds, and `gu atlas|alice`
  became `g atlas`, a rule matching **every** member of the VO. Field 4 dropped
  any letter it did not know, so one typo turned `rlwd` into a weaker grant
  silently. Both are gone. Field 1 is now a **set of one to six distinct
  selectors** drawn from `u g p a v l`, all of which must match — a compound
  rule is strictly *narrower* than any of its selectors alone — where `v` is the
  VOMS virtual organisation and `l` the VOMS role, both new. A compound rule's
  id splits on `|` into exactly one non-empty component per selector,
  positionally; a **single-selector rule still takes its id verbatim**, because
  a DN is full of punctuation and splitting one would break every deployed file.
  `v` and `l` together are resolved as a **positional pair** over the credential's
  index-aligned VOMS attribute lists, so a proxy holding `/cms/Role=NULL` *and*
  `/atlas/Role=production` does **not** satisfy `vl cms|production` — the
  cross-product an independent match would have granted. The privilege alphabet
  gained **`x`**, the stage/recall privilege: `xrdfs prepare -s`/`-e` and the VFS
  stage/evict mutations now require it. Anything the grammar cannot parse —
  an unknown selector or privilege letter, a repeated selector, `a` combined
  with another selector, a wrong id arity, an empty id component — **refuses the
  whole configuration** at `nginx -t`, naming the file, the line and the
  offending byte, rather than silently handing out a rule the operator never
  wrote. XrdAcc-format files are untouched: `brix_authdb` is read by both
  engines' parsers before `brix_authdb_engine` has settled, so a native-grammar
  defect is recorded and only raised at merge time, and only when the native
  engine is the one selected — the message says as much and names
  `brix_authdb_engine xrdacc`. Two further defects surfaced while building it,
  both fixed here: the VOMS **role never reached authorization at all** (the
  identity was derived from VO *names*, which are `/`-free by design, so the
  role list was always empty and both the `l` selector and the XrdAcc `role`
  template were dead code — there is now a dedicated raw-FQAN channel, leaving
  `$brix_vo`, `brix_require_vo`, the `g` selector and every metric label
  byte-identical), and the `v`/`l` cross-product above. Pinned by
  `tests/test_release20_authdb_residuals.py` (21 cases over a GSI+VOMS lab and
  `nginx -t` arms on both planes, including a genuine two-AC multi-VO proxy for
  the cross-tuple negative and an INVARIANT-8 arm proving the raw FQAN never
  reaches a metric label or a log field). *(2.0 F20)*

- **`brix_crl_scope all|last` and `brix_tls_verify_log off|failure|all` — the
  `xrd.tlsca` residuals.** Stock XRootD's `xrd.tlsca` carries two knobs BriX had
  no spelling for: `crlcheck all|last`, which chooses how far up the chain
  revocation is enforced, and `verifylog off|failure|all`, which chooses what
  the server says about a chain it just verified. Both now exist under those
  names on **both** planes — the `root://` stream server and the WebDAV http
  location, server and `http{}` — with the same value tables on each, so a line
  copied between two server blocks means the same thing in both.
  `brix_crl_scope` defaults to `all` (the strict value, unchanged behaviour) and
  `brix_tls_verify_log` to `off`.

  **`last` is not `X509_V_FLAG_CRL_CHECK`, and that is a security property, not
  an implementation detail.** OpenSSL's `check_cert` returns early for any
  certificate carrying `EXFLAG_PROXY`, so on a GSI login — proxy at depth 0, the
  user's end-entity certificate at depth 1 — plain `CRL_CHECK` checks *nothing
  at all*. Measured on OpenSSL 3.0.18 with `openssl verify -allow_proxy_certs`
  against a CA that had revoked the EEC: `-crl_check_all` refuses it
  (`error 23 at 1 depth ... certificate revoked`), `-crl_check` alone answers
  `OK`. A flag-based `last` would therefore have been indistinguishable from
  `brix_crl_mode off` for every proxy login, and a revoked user need only have
  wrapped their credential in a proxy. BriX keeps
  `CRL_CHECK|CRL_CHECK_ALL|USE_DELTAS` armed under **both** scope values and
  narrows `last` inside the verify callback instead
  (`brix_crl_out_of_scope`/`brix_chain_eec_depth`,
  `src/auth/crypto/store_policy_store.c`), tolerating a CRL-class verdict at any
  depth *other* than the end entity's — where the end entity is the shallowest
  non-proxy certificate in the chain, not depth 0. A revoked certificate is
  refused under every scope value, which is the invariant this knob is not
  allowed to break.

  Both values are carried from config parse to the callback on a
  `brix_trust_policy_t` attached to the `X509_STORE`'s ex_data, and **every**
  field of that policy is part of the store's memoisation key: two server blocks
  that differ only in `brix_crl_scope` or `brix_tls_verify_log` no longer share
  one cached store. `brix_tls_verify_log failure` logs one `[warn]` line per
  rejected chain (depth, reason, subject) and `all` adds one `[notice]` per
  accepted certificate; neither ever prints key material or a PEM chain, which
  matters because the error log is world-readable. Pinned by
  `tests/test_release20_tlsca_residuals.py` (74 cases over a lab with two
  three-level hierarchies — a third level is required, because on root→EEC the
  end entity and the root share one CRL and no scope value is distinguishable —
  plus `SC-03/04/05` and `SP-C13..C16` in `tests/c/x509_conformance_test.c` for
  the store-flag half). *(2.0 F19)*

- **`brix_tpc_allow_identity`, `brix_tpc_require`, `brix_tpc_restrict`,
  `brix_tpc_oids` — the stock `ofs.tpc` identity matrix.** BriX has confined
  third-party copy by *host* since 1.x (`brix_tpc_source_guard` +
  `brix_tpc_source_allow`, plus the address-range gate). Stock XRootD also
  confines it by *identity*: `ofs.tpc allow dn|group|host|vo`,
  `require {all|client|dest} <auth>`, `restrict <path>` and `oids`. A site
  migrating a working `ofs.tpc` block had nowhere to put any of it. All four now
  exist on both planes — native `root://` and WebDAV `COPY` — over one pure
  verdict core (`src/tpc/common/identity_matrix.c`) reached from one choke point
  each: `tpc_matrix_gate()` in `src/protocols/root/read/open_tpc.c`, which
  covers all four native roles (`dest`, `source`, `push_src`, `push_dst`) and
  runs **before any dial**, and `webdav_tpc_matrix_gate()` in
  `src/protocols/webdav/tpc.c`. Four properties are load-bearing. **(1) The
  stage order is a security order** — `oids` → `allow` → `require` →
  `restrict`, so a path rule can never rescue an identity the allow stage
  already refused. **(2) Every stage is default-PERMIT while unconfigured and
  fail-CLOSED once configured**: a site that never writes these directives sees
  no behaviour change whatsoever, and a site that writes one rule has denied
  everything that rule does not name — an unauthenticated subject included.
  `oids` is the single exception and is default-DENY, as in stock. **(3) The
  party is read off the wire rather than asserted**: a native leg carrying
  `tpc.org` was opened by the peer SERVER and presents the server's credential
  (`dest`), one without it by the initiating CLIENT (`client`), so
  `require dest gsi` is genuinely not satisfiable by a client credential.
  **(4) `restrict` is stricter than stock** — the prefix match is
  component-aware, so `/data` admits `/data/x` but never `/database`, and it
  runs on the same cleaned logical path `open()` would use, after the resolver's
  traversal rules. The matrix is a policy layer *inside* the existing host-plane
  confinement: a rule can only narrow what the host allowlist already permitted,
  never widen it. `allow ... host` reuses the one host-pattern spelling the
  egress guard already owns and, like the other three hostname consumers, waits
  for the peer PTR so a rule is never evaluated against a name that has not
  landed. Refusals name the directive and nothing else — no DN, VO, group, host
  or path is echoed back — and account through the existing TPC error paths
  rather than a new metric family. Pinned by
  `tests/test_tpc_identity_matrix_unit.py` (20 C cases over the pure core,
  compiled `-Werror` with no nginx),
  `tests/test_release20_tpc_identity_matrix.py` (35 live wiring, ordering,
  party-mapping, grammar and refusal-hygiene cases on the native plane) and
  `tests/test_release20_tpc_matrix_webdav.py` (11 on the WebDAV plane, driving
  both callers of `webdav_tpc_authorize()` — a pull and a push, each refused and
  permitted — against a TLS mock source that records whether the outbound socket
  was ever opened). Note for operators writing `brix_tpc_restrict` on an HTTP
  location: the path the stage evaluates is the request URI, so the prefix must
  include the `location` prefix. *(2.0 F18)*

- **`brix_cms_fsxeq <op>... <program> [<arg>...]` — an operator program in
  place of a forwarded namespace op (stock `cms.fsxeq`).** A CMS manager
  forwards `chmod`, `mkdir`, `mkpath`, `mv`, `rm`, `rmdir` and `trunc` down to
  the data node that holds the file, and BriX has always answered them with the
  local filesystem. A site whose namespace does not live there — a database, an
  archive workflow, a tape front-end — had no way in. This registers the stock
  directive: named ops are answered by the operator's program **instead of** the
  built-in leg, ops left unnamed keep it, and the op's own arguments are
  *appended* to the configured command line the way `XrdOucProg::Run()` appends
  them (`<mode>` four octal digits or `<size>` decimal, then the **physical**
  path; `mv` gets both paths). The op name is deliberately **not** injected —
  stock disambiguates a shared program with a literal argument on each line, and
  so does this. Exit 0 is success and answers the manager the way the built-in
  leg does, *silently*; a non-zero exit, an unrunnable program and one still
  running at `brix_cms_fsxeq_timeout` (default `10s`, whole process group
  `SIGKILL`ed) each fail the op with the byte-shape-identical `kYR_error` a
  stock cmsd sends. The run is an nginx thread-pool task, so a wedged program
  costs one pool slot and one forwarded op rather than the worker's event loop —
  and a configuration with a program but no `thread_pool` fails every named op
  **closed** rather than falling back to the leg the operator replaced. Three
  things it does not relax: the built-in leg's `openat2`/`RESOLVE_BENEATH`
  confinement has no equivalent for an external program, so a forwarded path is
  gated lexically **before the fork** (absolute, bounded, no `..` anywhere —
  both paths for `mv`) and a failing one is answered `fsxeq path denied` with
  the program never run; `brix_allow_write off` refuses the op before anything
  is forked; and a group- or world-writable program is refused at `nginx -t`,
  like `brix_frm_stagecmd`. The program is handed exactly the op's arguments —
  no worker listen socket, client connection, epoll instance or export-root
  descriptor, and no credential material in its argv or environment. Pinned by
  `tests/test_release20_cms_fsxeq.py` (18 tests). *(2.0 F17)*

- **`brix_tpc_push on|off` — native `root://` third-party copy in the PUSH
  direction (`tpc.stage=push`).** Stock native TPC is destination-side pull
  only: the destination dials the source and reads, so a site whose storage may
  make only *outbound* connections — an egress-only firewall, a NAT with no
  inbound port — cannot be the source of a native copy at all. This adds the
  mirrored leg as an explicit BriX dialect: both legs carry `tpc.stage=push`, so
  a stock peer never mistakes one for a pull. The client registers a rendezvous
  key at the destination with a write-open (`?tpc.key=K&tpc.stage=push`, which
  creates the file and dials nothing), then read-opens the source with
  `?tpc.key=K&tpc.dst=<host[:port]>&tpc.dlfn=</dst/path>&tpc.stage=push`; the
  two `kXR_sync`s that arm and fire a pull arm and fire the push unchanged, and
  the source's own write-open at the destination **consumes** the key
  (single-use, `kXR_open_updt` only). `tpc.str=<n>` opens parallel outbound
  sub-streams, clamped by `brix_tpc_streams`. One flag arms both roles on a
  listener; with it off (the default) either leg is refused `kXR_Unsupported` at
  the open, before path resolution and the write gate. The destination the
  source dials is bounded by the same `brix_tpc_source_guard` allowlist and the
  same two-stage SSRF policy as a pull source, refused at the open with
  `signal=tpc_egress` and zero sockets dialled. The failure-path unlink that
  removes a half-written *destination* file on a pull is suppressed on a push,
  where the same field names the operator's own source file. Pinned by
  `tests/test_release20_tpc_push.py` (15 tests). *(2.0 F16)*

- **A push source stays a read-only export.** `kXR_sync` is routed through the
  write dispatch table — correctly, since a sync normally flushes bytes this
  server wrote — so the two syncs that arm and fire a push met "this is a
  read-only server" on exactly the export a push is for. `brix_allow_write` is
  no longer a prerequisite for exporting data by push: `brix_dispatch_require_write`
  now exempts the `allow_write` clause for a `kXR_sync` on a handle that already
  carries the push bit and whose transfer has not finished
  (`brix_write_gate_tpc_push_sync`). Nothing else is relaxed — authentication
  and the bound-stream refusal still apply, and a `kXR_sync` on any other
  handle, a sync after the push completes, and every other write opcode still
  answer `kXR_fsReadOnly`. Three security-negatives in
  `tests/test_release20_tpc_push.py` pin each of those. *(2.0 F16)*

- **`brix_cache_advertise_federation <host[:port]>` names the federation whose
  Director this cache advertises to.** The Pelican advertiser discovers the
  Director from `https://<federation>/.well-known/pelican-configuration`, and
  before 2.0 it read that authority from the host of the `brix_cache_origin`
  family retired in phase-64 — a field no directive can write. Registering the
  rest of the family (below) therefore still advertised nothing: the per-worker
  scheduler declined on every start. The new directive takes an **authority
  only** — a scheme, a path, or a port outside 1-65535 is a parse error — and
  defaults to port 443. The name is resolved when an advertisement is sent, not
  at `nginx -t` (INVARIANT 13), so a federation that is briefly unresolvable
  does not block start-up. Pinned by `tests/test_release20_never_armed.py`.

- **`brix_cache_verify_digest <algorithm>` names the digest a non-`root://`
  origin is asked for.** `brix_cache_verify` compares a completed fill against
  the origin's advertised digest, but only an `xroot://` origin volunteers one
  (`kXR_Qcksum`): an HTTP/Pelican origin has to be asked with `Want-Digest`,
  and an object store has to be asked for its stored checksum. The setter, the
  config field and its merge existed before 2.0 and **no `ngx_command_t`
  registered them**, so the knob was an unknown directive on both planes and
  every non-xroot fill verified against nothing. It is now registered on
  `stream server` and on `http|server|location`, validated against the
  algorithms this build can compute (`brix_checksum_plugin` names included) at
  `nginx -t`, and read by both fill spines — the standalone one through the
  shared preamble, the composed tier through the cache policy it carries by
  value. Pinned by `tests/test_release20_registered_nowhere.py`.

- **The Pelican federation advertiser is configurable.**
  `brix_cache_advertise on|off`, `_key`, `_data_url`, `_web_url`, `_issuer`,
  `_interval` and `_namespace` are registered on `stream server`. The
  advertiser itself — the per-worker timer, the ES256 advertise JWT and the
  `OriginAdvertiseV2` document POSTed to the Director's `registerCache`
  endpoint — shipped earlier with **no directive registering any of its seven
  knobs**, so the feature could not be switched on from a configuration file at
  all. The site label comes from the existing `brix_sitename` (registry prefix
  `/caches/<sitename>`), the interval clamps up to the federation minimum of
  60s, and the registry key handshake remains an out-of-band operator step.
  Documented in
  [`docs/03-configuration/directives.md`](docs/03-configuration/directives.md);
  pinned by `tests/test_release20_registered_nowhere.py`.

- **The `brix_frm_*` engine knobs drive the stage engine (2.0 F1, ADR-3b).**
  `brix_frm_queue_path` is the durable stage journal directory: worker 0
  creates it (mode 0700), every staged write-through flush and recall is
  persisted there as a `<reqid>.req` record, replayed at worker start, and
  moved to `deadletter/` once `brix_frm_fail_retries` (default 5) attempts —
  permanent denies and transient re-drives alike — are exhausted. It replaces
  the env-only `BRIX_STAGE_JOURNAL_DIR`, which stays a fallback for servers
  without `brix_frm on`. `brix_frm_fail_backoff` (default 60s, floor 1s) arms a
  worker-0 sweep that re-drives `FAILED` records without waiting for a
  restart. `brix_frm_stagecmd <program>` names the `tape://exec` MSS adapter
  program (run as `<program> <verb> <key> <online>`) and takes precedence over
  `BRIX_FRM_STAGECMD`; `brix_frm_copy_timeout` (default 0 = none) kills a
  program still running at the deadline (`SIGKILL` to its whole process
  group, `ETIMEDOUT`, one `[error]` line); `brix_frm_copymax` (default 8)
  bounds the engine's in-flight transfers. Every program the adapter runs
  now leads its own session with only fds 0–2 open — a worker's listen
  sockets (not `CLOEXEC` in nginx) and client connections never reach an
  operator program, and no child of a killed program can keep the
  server's ports bound. Documented under "Tape / FRM" in `directives.md`,
  the quick reference and the storage/tape comparison; pinned by
  `tests/test_release20_frm_knobs.py` (21 tests).
- **StageEvents notification feed (`brix_frm_stagemsg <file>`, 2.0 F2).** The
  `oss.stagemsg` / `XRDOFSEVENTS` analogue: every worker appends one
  `<utc> <source> <event> <reqid> <key> [name=value …]` line per stage
  transition — the durable engine (`queued`, `started`, `done`, `failed`,
  `deadletter`, `replayed`, `dropped`), the `kXR_prepare` / Tape REST registry
  (`queued`, `staging`, `online`, `failed`, `cancelled`, `deleted`, `expired`)
  and the `tape://` MSS adapter (`recall-begin`, `recall-online`,
  `recall-failed`, `migrate-done`, `migrate-failed`) — so an external stager
  or tape monitor tails one file. Keys and values are `%`-escaped, the file is
  created `0600`, an existing group- or world-writable one is refused at
  `nginx -t`, and the feed is best-effort: an unwritable file logs one
  `[error]`, never fails a stage, and is re-opened on the next transition.
  Documented under "Tape / FRM" in `directives.md`, the quick reference and
  the storage/tape comparison; pinned by
  `tests/test_release20_frm_stagemsg.py` (12 tests).
- **OssArc backup queue (2.0 F3).** Behind `tape://…?arc=<depth>` the
  dataset seal no longer runs inside the client's close: the completion
  marker's commit freezes the dataset and queues an `archive` record in the
  durable stage journal (`brix_frm_queue_path`), and the engine composes and
  ships the stored ZIP, sidecar and marker off the event loop with the flush
  discipline — `brix_frm_fail_backoff` re-drive, restart replay,
  `brix_frm_fail_retries` dead-letter (`deadletter/<reqid>.req`, move it
  back to re-queue; delete the marker's online copy to withdraw). The MSS
  adapter vtable gains `seal(key)` and `migrate()` may answer
  `BRIX_MSS_MIGRATE_DEFERRED`; the feed gains `frm seal-done` /
  `seal-failed` and `engine … kind=archive`. Without `brix_frm on` the seal
  runs inline as before. Pinned by `tests/test_release20_arc_backup_queue.py`
  (10 tests).

- **Per-space purge policy + policy program (2.0 F4).** The tape-buffer
  purge engine gains `frm_purged`'s `purge.policy` surface:
  `brix_frm_purge_policy {*|<group>} <hi> <lo> [hold <time>] [polprog]`
  gives every `brix_oss_space` group its own owned-bytes arm (sizes or `%`
  of the group's quota) and hold, `*` covering ungrouped keys and groups
  without a rule; `brix_frm_purge_polprog <program>` runs an operator
  program once per pass under the `brix_frm_copy_timeout` deadline
  (`<program> <candidates> <decision>`: one `<group> <touched> <size> <key>`
  line per eligible copy in, one approved key per line out) that chooses
  among — never beyond — its candidates, fail-closed for its groups. Rules
  and program are checked against the server's space table at merge time;
  a rule alone arms the engine. Pinned by
  `tests/test_release20_purge_policy.py` (13 tests).

- **Per-open cache hints `pfc.blocksize` / `pfc.prefetch` (2.0 F5, XrdPfc
  `pfc.urlcgi` parity).** `brix_cache_urlcgi [blocksize {ignore|<min> <max>}]
  [prefetch {ignore|<min> <max>}]` (http + stream) arms, per clause, the
  hints an XRootD client appends to its open: a new slice-cache object's
  block size (clamped into the bounds, rounded to the 1m granule; an
  existing object's recorded geometry always wins, whole-file exports
  ignore it) and a per-handle prefetch runway in blocks (a clamped 0
  switches speculation off for that handle; the engine must be on). Absent
  = both ignored, so no behaviour changes for a deployment that does not
  set it. The opaque schema recognises the `pfc.` namespace and types both
  keys as unsigned integers under `brix_opaque_strict` (`kXR_ArgInvalid`
  otherwise); lenient mode drops a malformed value. Plumbing: an open-hint
  carrier on the VFS context (`brix_sd_open_hints_t`), a new optional
  storage-driver slot `open_hinted` (cache + stage decorators implement
  it; every other driver is reached through the plain open), and the
  partial-object open in `sd_cache_partial.c` doing the clamp. Pinned by
  `tests/test_release20_cache_urlcgi.py` (24 tests: grammar accept ×4 /
  reject ×8 / duplicate; strict typing ×3 + lenient parity; live clamp
  ×7 and runway ×4).
- **Forwarding proxy — client-named root:// origins (2.0 F5, XrdPss
  forwarding mode `pss.origin = *` + `pss.permit`).**
  `brix_storage_backend forward://root[,roots] permit=<host|.suffix>…`
  makes an export a proxy for whichever origin the client names inside
  the path it opens (`/root://host:port//file`). The new `xroot_fwd`
  driver parses the key (ngx-free `sd_xroot_fwd_key.c`), admits it
  against the protocol list (outside → `kXR_Unsupported`) and the
  mandatory permit list (outside → `kXR_NotAuthorized` before any
  resolve or dial; the match rule is the TPC egress guard's, so a
  forwarded open and a TPC pull agree on what `.example.org` permits),
  then relays every slot to one ordinary root:// child per distinct
  origin — `verify_pages`, `nearline`, `credential=` and the cache /
  stage decorators apply per origin; `rename` / `server_copy` refuse a
  cross-origin pair (`EXDEV`). A key naming no origin is
  `kXR_NotFound`. Fail-closed grammar: a `forward://` line without
  `permit=` is refused at `nginx -t` (an empty list would be an open
  relay), `permit=` is refused on any non-forward line, and
  `forward://` is refused on every store tier. Census: `xroot_fwd`
  joins fs_list.h and the machine-checked slot matrix (64 slots × 14
  drivers). Pinned by `tests/test_release20_forward_proxy.py` (19
  tests) and `tests/test_sd_xroot_fwd_key.py`.
- **Site checksum plugins (`brix_checksum_plugin <name> <path.so> [parms]`).**
  The `xrootd.chksum` plugin analog: a shared object exporting `brix_cks_plugin`
  against the plain-C ABI in `src/core/compat/checksum_plugin_abi.h` (name,
  digest length, state size, `init`/`update`/`final`) is loaded at
  configuration time from the stream or http main context into one
  process-wide registry (at most 8, rebuilt on reload). The path must be
  absolute, a regular file and not group/world-writable; the object is
  self-tested with its `parms`, and every malformed registration is refused at
  `nginx -t` with a message naming the cause. A registered name works wherever
  a built-in does — `kXR_Qcksum`, `brix_checksum_default`, the
  `query config chksum` list (built-ins first, then plugins) and WebDAV
  `Want-Digest` — with the host walking the object and hex-encoding the digest.
  `contrib/checksum-plugins/` carries an FNV-1a 64 example and the build
  recipe. `tests/test_release20_checksum_plugin.py` (26).
- **Native root:// TPC follows source redirects and pulls multi-stream (2.0
  F7, `ofs.tpc` multihop + `streams` parity).** A `kXR_redirect` from the TPC
  source no longer ends the pull: the destination decodes the target with the
  shared `xrd_redirect_body_decode`, passes it through the same
  `brix_tpc_source_guard` / `brix_tpc_source_allow` check as the host the
  client named (a refused hop is `kXR_NotAuthorized` and counts on
  `brix_stream_tpc_egress_refused_total`), logs `TPC hop N: from -> to`, and
  re-bootstraps on the target — up to `brix_tpc_max_hops` (default 4, `0`
  never follows, max 16). A malformed body or a hop back to the same host
  fails the pull. `brix_tpc_streams <1..15>` (default 1) caps the client's
  `tpc.str=<n>`: the destination binds `n-1` extra source connections with
  `kXR_bind` and pulls rounds of one 1 MiB read per stream; an unparseable
  hint, a source that refuses `kXR_bind` or one that returns no session id
  all degrade to the single-stream loop with a log line. BriX's own
  `xrdcp -S <n>` now sends the hint (stock XrdCl 5.9 does not).
  `tests/test_release20_tpc_multihop.py` (12),
  `tests/test_release20_tpc_streams.py` (15),
  `tests/test_release20_tpc_unit.py` (4).

- **SSS credentials carry a full identity, not just a name.** The v2
  entity fields — VO, role, group list, endorsements and a proxied
  credential — are parsed from the credential alongside the user and
  group, each with a hard receiver cap (256/256/256/512/1024/4096 bytes)
  that refuses an over-long value rather than truncating it. The keytab
  decides what is believed: a key that pins the identity drops the
  client-asserted VO, role and endorsements (one INFO line), and a proxied
  credential is dropped unless the new **`brix_sss_getcreds on`** keeps
  it. The accept line gained `vorg=`, `role=`, `endo=` and `creds=` after
  the unchanged `user=`/`group=` prefix. **`brix_tap_proxy_sss_identity
  keytab|client`** (default `keytab`, the 1.x wire) makes the tap proxy
  present the authenticated client's own entity upstream instead of the
  keytab account, and refuses the upstream connection outright when the
  front-side session is not authenticated. The native client gained
  `--sss-vorg`, `--sss-role`, `--sss-endorse`, `--sss-creds-file` and
  `--sss-sndlid` (the two-round form where the server names the login id),
  plus a per-connection identity registry for processes that speak for
  many users (`client/lib/auth/sss/sss_id.h`, the `XrdSecsssID` contract),
  whose lookup fails closed on a miss. Client and server mint the entity
  through one shared kernel, so the two ends cannot drift.
  `tests/test_release20_sss_entity.py` (18),
  `tests/test_release20_sss_proxied.py` (9),
  `tests/test_release20_sss_unit.py` (6).

- **Cache occupancy rows from the store itself.** `brix_cache_occupancy_ratio`
  and `brix_cache_bytes` now come from the cache store's own capacity report
  (`brix_cstore_freespace`) first — for `brix_cache_store ram:<size>` that is
  the configured cap as `total` and resident bytes plus in-flight fill
  reservations as `used`, per worker — and from a `statvfs` of the legacy
  `brix_cache_export` root only as the fallback. The HELP text names both
  sources. `tests/test_release20_ram_cache_metrics.py`.

- **2.0 metrics suites** for the areas the readiness register found untested:
  `tests/test_release20_cms_metrics.py` (three-tier manager tree — ownership,
  drop and re-register, tier isolation), `tests/test_release20_dashboard_cross_validation.py`
  (the snapshot API equals the `/metrics` sums once connections close, moves in
  real time, and needs the cookie `/metrics` never does),
  `tests/test_release20_metrics_cardinality.py` (a 1000-unique-path storm adds
  no series, counters survive a reload, a label-shaped path cannot inject a
  series) and `tests/test_release20_vo_acl_metrics.py` (VO and authdb
  verdicts are operation errors, never authentication failures, and no label
  carries a path or a DN). The manager-side cluster and health-check families
  are documented in `metrics-overview.md`, reset semantics included.

- **Runtime DNS from `resolv.conf`, and a server that starts with DNS down**
  (phase-116). `brix_resolver auto [path=…] [valid=] [min_ttl=] [max_ttl=]
  [negative_ttl=] [ipv4=] [ipv6=] [search=]` reads the resolver the host
  actually has — nameservers (with the BriX `ip:port` extension), `search`/
  `domain`, and `options ndots/timeout/attempts`, plus `LOCALDOMAIN` and
  `RES_OPTIONS` — and fills every unset nginx resolver slot (http/server/
  location, stream, and each upstream) without overriding an explicit
  `resolver`. Every name BriX itself resolves — CMS managers, upstreams and
  proxy pools, TPC and cache origins, GridFTP control channels, CVMFS origin
  probes and swarm peers, PMark mapping, health checks — now goes through one
  runtime path with a bounded per-worker cache (`brix_dns_cache_max`, default
  4096) and exponential re-resolve backoff (`brix_dns_retry`, default `1s
  30s`), so a name that does not resolve at startup no longer refuses the
  configuration: the target enters `resolving`, the server starts, and it is
  picked up when DNS recovers. Reverse (PTR) lookups behind `host` auth,
  XrdAcc `h` rules, `brix_protbind` templates and TPC origin ids run off the
  same cache instead of blocking the event loop, and `brix_dns_status_zone`
  publishes per-target state. The one-DNS-path rule is enforced by
  `tools/ci/check_dns_seam.py` — no waiver marker, no backlog.
  See [Phase 116](docs/refactor/phase-116-runtime-dns-resolv-conf.md).
- **Serve-while-filling for the whole-file cache** (phase-115 W4.1).
  `brix_cache_serve_while_filling <time>` (default `0` = off) lets a read whose
  whole-file fill is already in flight FOLLOW that fill instead of waiting for
  it to finish: the reader streams the bytes already pumped and is told to
  retry (`kXR_wait`) at the fill frontier, so a second client of a cold object
  starts at the origin's pace rather than paying the whole transfer first. Block
  (slice) mode already served partial content; this closes the whole-file half.
  Requires a local `posix:` cache store and `brix_cache_verify off` — under any
  verify mode the staged bytes are provisional and are never followed. A fill
  that aborts fails the follower closed (`kXR_IOError`) rather than passing a
  truncated object off as complete, and a filler that dies is bounded by the
  directive's value as a no-progress deadline.
  See [Phase 115](docs/refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md) W4.1.
- **In-memory cache store** (phase-115 W4.2). `brix_cache_store ram:<size>`
  puts the hot cache in memory rather than on a filesystem; the whole location
  is the byte cap and there is no path. **The size is per worker** — `ram:8g`
  across 16 workers is up to 128 GiB resident — and the resolved capacity is
  logged at NOTICE with `PER WORKER` spelled out at startup. The cap is hard,
  reserved at fill-open, and the store evicts its own coldest entries to stay
  under it; the filesystem reaper directives (`brix_cache_eviction_threshold`,
  `brix_cache_max_bytes`, `brix_cache_reap_interval`) do not apply, because they
  take a lock file in a cache root a memory store does not have. An object that
  cannot fit is served straight from the source instead of failing the read.
  `ram:` is refused at `nginx -t` in every other role — `brix_stage_store`
  (a staged write would be ACKed and then lost on restart),
  `brix_storage_backend` (it would be the only copy of every byte), and
  `brix_cache_cold_store` (the demotion target must not be more volatile than
  the tier demoting into it) — as is `ram:0`. Its occupancy rows come from the store's own capacity
  (see "Cache occupancy rows from the store itself" above).
  See [Phase 115](docs/refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md) W4.2.
- **Per-page verification of origin reads** (phase-115 W4.3). The store-line
  parameter `verify_pages[=require|best-effort]` on a `root://` /
  `roots://` `brix_storage_backend` issues every origin read as `kXR_pgread`
  and recomputes the CRC32c of each 4 KiB page before a byte of it reaches the
  cache or the client; a mismatched page fails the read with the offset logged
  and commits nothing. This closes the half of the integrity story
  `brix_cache_verify` cannot reach — that check hashes a COMPLETED fill against
  a whole-file digest, so it is blind to ranged/partial reads and to
  digest-less origins — and over cleartext `root://` it is the only integrity
  BriX has. The bare token means `require`: an origin that cannot page-read is
  refused (`kXR_Unsupported`) rather than quietly serving unverified bytes;
  `=best-effort` is the explicit opt-in that falls back to plain `kXR_read`
  after one warning, for a federation of mixed-vintage origins. Corruption is
  refused under both spellings. Origin support is taken from the `kXR_protocol`
  reply (`kXR_suppgrw`) and remembered on the connection, so a pre-5.x origin
  costs no wasted round trip; an origin that advertises the capability and then
  refuses is handled once per object, and a refusal arriving mid-train — after
  pages were already accepted — is a protocol error, not a fallback. The
  parameter is refused at `nginx -t` on a cache/stage/cold tier, on any
  non-`root://` driver, and for any other value.
  See [Phase 115](docs/refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md) W4.3.
- **Tape dataset archiver** (phase-115 W3.1). `tape://<adapter>/<base>?arc=<depth>`
  (also on tier store URLs) seals every dataset — the first `<depth>` path
  components — into one stored ZIP archive on tape (`<ds>.brixarc.zip`,
  readable by `unzip`) once its completion marker `.brix-dataset-complete` is
  written; members stay in the online buffer until then, reads of a sealed
  member recall the archive and extract that member only, stat/dirlist answer
  from a sidecar index (`<base>/.arcidx/<ds>.idx`), a sealed dataset is
  immutable, and archive member names are validated so an archive can never
  write outside its dataset. Works over the stub, exec and lib MSS adapters.
  See [Phase 115](docs/refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md) W3.1.
- **Tape-buffer purge engine** (phase-115 W3.2). The online buffer behind a
  `tape://` tier now has an eviction policy: one LRU pass per
  `brix_frm_purge_interval` on worker 0 releases online copies whose MSS
  adapter confirms a durable tape copy (new `on_tape` adapter slot), driven by
  the filesystem watermark pair `brix_frm_purge_watermark` (accepted-only since
  phase 64, now live) and the new owned-bytes cap `brix_frm_purge_max_bytes`.
  Copies younger than 30 s, copies pinned by an in-flight prepare(stage), and
  symlinks are never released; passes serialise on `<online>/.brix-purge.lock`;
  the pair on an export without a `tape://` tier warns and never arms. Books
  `brix_frm_purge_total` and `brix_vfs_evict_bytes_total{driver="frm"}`.
  See [Phase 115](docs/refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md) W3.2.
- **Space groups** (phase-115 W3.3). `brix_oss_space <group> <prefix>
  [quota=<size>|quota=-1]` names a storage group over an export-relative prefix
  (longest prefix wins, at a component boundary only). Each group carries its
  own usage and quota: `kXR_Qspace` reports the group owning the queried path
  or the one named by `?oss.cgroup=<name>`, and — under
  `brix_oss_quota_enforce on` — a write past a group's quota is refused with
  `kXR_overQuota` while the export-wide `brix_oss_quota` from here on governs
  only ungrouped paths. `quota=-1` is the unlimited sentinel (accounting only).
  A create/write `kXR_open` that names a group other than the one owning its
  path is refused with `kXR_ArgInvalid` before the file is created.
  See [Phase 115](docs/refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md) W3.3.
- **GridFTP extended block mode and a protected data channel** (phase-115 W5.1).
  A `ftp://` / `gsiftp://` `brix_storage_backend` takes two new store-line
  parameters. `mode=e` negotiates GridFTP MODE E (GFD.020 §5): the data channel
  carries self-describing blocks with absolute offsets instead of an opaque
  byte stream, which is what makes an offset-addressed, restartable transfer —
  and every partial read verifiable — possible at all. `prot=p` negotiates a
  TLS-protected data channel (RFC 2228 `PBSZ`/`PROT`) whose peer leaf DN is
  pinned to the identity already authenticated on the control channel. Both are
  requirements, never preferences: an origin that answers `504` to `MODE E` or
  `534` to `PROT P` fails the transfer rather than silently serving it in
  stream mode or in cleartext, because an operator who asked for the property
  and got neither it nor a diagnostic is worse off than one whose transfer
  failed. `prot=p` on a plain `ftp://` backend is refused at `nginx -t`: an
  anonymous origin never authenticates a control identity, so there is nothing
  to pin the data peer to and the encryption would be to whoever answered.
  See [Phase 115](docs/refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md) W5.1.
- **Bounded GridFTP retrieves (`ERET`)** (phase-115 W5.2). A ranged read of a
  MODE E origin now issues `ERET P <offset> <length> <path>` (GFD.020 §5.3)
  instead of `REST`+`RETR`. RFC 959 can only say "start here" — the transfer
  then runs to EOF — so every ranged read left the origin pushing a tail
  nobody drained; `ERET` carries the window and the origin stops at its end.
  There is nothing to configure: the capability is discovered with a `FEAT`
  probe issued lazily, from the retrieve path only, and remembered for the
  session. It is sent **only** under `mode=e`, and that is a security rule
  rather than a limitation — a door that ignores the window and answers with
  the file from offset 0 sends genuine bytes that are simply the wrong part,
  and only MODE E's per-block absolute offsets let the driver refuse them
  instead of returning the head of the file under a `Content-Range` that lies.
  An origin that advertises `ERET` and then refuses it (a real dCache/Globus
  shape) downgrades to the POSITIONED `REST`+`RETR` path — never to a bare
  `RETR` that would restart at zero — and is not asked again on that session;
  a `550` is passed through as the file being unavailable, not the extension.
  `ESTO` is deliberately not implemented: this driver publishes writes as one
  whole-file `STOR` plus a rename and has no partial-write caller, so the
  command would ship unreachable.
  See [Phase 115](docs/refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md) W5.2.
- **Striped GridFTP reads (`SPAS`)** (phase-115 W5.3). A new store-line
  parameter, `brix_storage_backend gsiftp://… mode=e streams=<n>`, lets one
  read open up to `n` parallel data connections using GFD.020 §5.1 striped
  passive mode (`1`–`16`, default `1` = never ask). Unlike `mode=` and `prot=`,
  which are requirements, `streams=` is a **ceiling and it degrades**: it says
  how fast the same, identically framed, identically verified bytes arrive, so
  an origin that does not advertise `SPAS`, refuses it, answers with more
  stripes than the ceiling, or returns an unparsable or truncated reply is
  served over the single connection with identical bytes, and the refusal is
  remembered for the session. `streams=<n>` above 1 requires `mode=e` — a
  striped transfer is reassembled from blocks carrying their own offsets, and
  stream mode has none — and the check runs on the whole store line, so word
  order cannot change the verdict.

  **Every stripe address must be the control channel's own pinned peer.** A
  `SPAS` reply is the one place in this protocol where an origin hands the
  driver a list of addresses; elsewhere the advertised PASV address is
  discarded and the pinned numeric control peer dialled instead. Following a
  foreign stripe would let an origin drive connections to arbitrary hosts
  inside the operator's network — an FTP bounce with egress rules as the only
  remaining control — so a single foreign stripe abandons the whole striped
  attempt before any socket is opened. The consequence is that a genuinely
  multi-host striped door is read over one connection: a throughput ceiling,
  never a wrong answer. `SPOR` is deliberately not implemented — it would
  require this driver to listen, and it never binds.
  See [Phase 115](docs/refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md) W5.3.
- **Same-origin `COPY` on GridFTP-backed exports** (phase-115 W5.4). A WebDAV
  `COPY` between two paths of one `ftp://`/`gsiftp://` export is now served by
  the gateway instead of being refused. Previously the driver's server-copy
  slot was empty, which is not a slow path but an absent one: every such `COPY`
  answered `ENOTSUP`, and a client that wanted one had to `GET` the object and
  `PUT` it back, carrying the bytes twice across its own link. FTP has no
  server-side copy verb, so this is a gateway relay rather than origin-side
  zero-copy — the bytes still move, but only on the gateway↔origin link, and
  over one control session (FTP is sequential on the control channel, so the
  store leg reuses the session the retrieve leg just finished with).

  The destination appears whole or not at all: the copy stores to a random
  temporary name and promotes it with `RNFR`/`RNTO`, so a failure renames
  nothing, leaves the previous object intact and removes its own temporary.
  A transfer that delivers fewer bytes than the source's own reported size is
  refused rather than published — a bounded read that stops early is not an
  error the origin reports. Copying a path onto itself is refused outright: it
  would work, and it would rewrite a healthy object for no gain while putting
  the only copy at risk. Under `brix_read_only on` the copy is refused by the
  export's typed mutation policy before a single FTP command is written.

  **GridFTP-over-SSH (`sshftp://`) remains unimplemented and the scheme is not
  accepted.** It requires the control transport to terminate on the storage
  host, i.e. a child process per session, and nginx workers may not fork. An
  `ssh -L` sidecar is not a substitute: the data channel dials the control
  channel's pinned peer, which through a tunnel is `127.0.0.1` rather than the
  origin.
  See [Phase 115](docs/refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md) W5.4.
- **A lab lane that points brix at a real GridFTP door** (phase-115 W5.5). The
  new `xrd-lab test gridftp-outbound` scenario deploys four WebDAV fronts whose
  storage plane is an operator-supplied Globus or dCache endpoint, differing
  only in the store line (nothing, `mode=e`, `mode=e prot=p`,
  `mode=e streams=n`), and runs the round-trip, ranged-read, same-origin `COPY`
  and striping assertions across all four. Every other GridFTP test in this
  repository drives an in-tree Python origin written from the same reading of
  GFD.020 as the driver it tests, so a shared misreading would pass both sides;
  this lane is the only one where the reference implementation is the thing
  under test.

  It is **disabled by default and ships no door and no credential** — both are
  the operator's, deliberately, since minting our own would authenticate brix
  to a CA the real door has never heard of. Enabling it without naming a door
  fails loudly instead of defaulting to a placeholder: a lane that cannot
  connect skips every cell and exits 0, which is indistinguishable from one
  that passed. Against a cleartext `ftp://` door the `prot=p` front is not
  rendered, because `prot=p` pins the data channel to a control-channel
  identity that an anonymous door does not have.
  See [Phase 115](docs/refactor/phase-115-deployment-surface-and-remaining-feature-bodies.md) W5.5.

### Documentation

- **Every exported metric family is now documented.** Twenty-three families were
  named in no user-facing page at all — the whole runtime-DNS cache group
  (`brix_dns_cache_*`, `brix_dns_reverse_cache_*`), the storage-export gauges
  (`brix_storage_backend_info`, `brix_storage_bytes_used`/`_available`,
  `brix_storage_occupancy_ratio`), the watermark reaper trio
  (`brix_cache_watermark_*`), `brix_cache_usage_ratio`, the write-through
  staging gauges (`brix_wt_dirty_handles`, `brix_wt_flush_pending`,
  `brix_wt_stage_usage_ratio`), `brix_mirror_errors_total`,
  `brix_stream_io_uring_active` and the rate-limit zone-health pair
  (`brix_rate_limit_eviction_total`, `brix_rate_limit_zone_full_errors_total`).
  [Metrics Overview](docs/08-metrics-monitoring/metrics-overview.md) gains a
  **Complete Family Index**: all 240 families in 40 groups with their Prometheus
  type and exact `# HELP` text, generated from the calibrated catalogue the
  conformance suite pins against a live scrape. A family added, renamed or
  retyped without a row there now fails
  `tests/test_release20_surface_pins.py::test_the_family_reference_covers_every_exported_family`,
  and a doc that pastes a stale `# HELP` line into a sample scrape fails
  `::test_every_help_line_quoted_in_the_docs_matches_the_exporter` — the sample
  in metrics-overview.md had carried the pre-2.0 "Filesystem occupancy ratio"
  wording for `brix_cache_occupancy_ratio` and `brix_cache_bytes`, and its prose
  still had the store/`statvfs` precedence backwards.

- **The checksum surface is stated correctly everywhere.** The comparison set
  and the operator guide said "nine built-ins" and listed six requestable
  algorithms; the server has ten and answers every one of them by name, plus any
  `brix_checksum_plugin`. The candid gap ledger still claimed "No general
  checksum **plugin framework**", which 2.0 F8 closed. Counts and lists are now
  pinned against the built-in table by
  `tests/test_release20_checksum_plugin.py::test_the_comparison_docs_count_the_builtins_they_promise`
  and `::test_the_docs_that_enumerate_the_builtins_enumerate_all_of_them`.

- **`quirks.md` no longer misreads its own table.** The Qconfig `caps` bullet
  presented `version`/`role`/`sitename` as keys the server does not answer; they
  are answered, and the `0` is `brix_qconfig_table`'s `public_safe` column, which
  withholds exactly those three under `brix_read_only_public` (where they fall
  through to the unknown-key echo, indistinguishable on the wire from an unknown
  key). The bullet now names all 17 answered keys and states the exception,
  pinned prose-to-table by two tests in `tests/test_release20_surface_pins.py`.

- **The metric-name guard can see a family composed at runtime.**
  `tools/ci/check_metric_names.py` proves every `brix_*` family the docs cite
  against the C exporters, and it recognised four emission shapes — none of
  which matches a name built from a prefix argument. `src/net/dns/metrics.c`
  renders all eight DNS cache families through `"# HELP %s_hits_total …"` under
  two prefixes its own call sites pass, so documenting them made six honest
  references fail as "unknown metric family". A fifth shape now pairs a
  `%s_<suffix>` HELP/TYPE format with every bare `brix_…` literal in the same
  file; the scoping to one file is what keeps the pairing honest, and three
  tests in `tests/test_ci_guards.py` pin the resolution, the still-caught
  invented suffix, and the log tag in another file that must compose nothing.

- **The gap ledger caught up with axis (e).** The comparison and gap pages are
  what a site reads to decide whether BriX can replace its XRootD deployment,
  and their rows predated the feature work: PSS was "❌ Full upstream PSS is out
  of scope" after F5 shipped `forward://root[,roots] permit=…`; the PFC row said
  nothing about `brix_cache_urlcgi`; `XrdOssMSS` claimed "no in-process MSS
  driver stack" beside a `lib` adapter that dlopens against `sd_frm_lib_abi.h`;
  `XrdOssSpace` was "basic `statvfs`" after `brix_oss_space` and
  `brix_frm_purge_policy`; `XrdFrm` was "partial FRM queue" after F1–F4; the
  client guide still called native-TPC multihop delegation a caveat after F7
  closed it under `brix_tpc_max_hops`; and `kXR_tlsData`/`kXR_tlsSess` were
  "not independently enforced" though `brix_tls_require session data` sets each
  bit and `src/fs/vfs/vfs_secgate.c` refuses the matching operations. Every row
  now states what ships and what is still open (native TPC **push** is F16).
  Three pins in `tests/test_release20_surface_pins.py` keep the ledger honest in
  both directions: each shipped handle is a live registration, each is named
  somewhere in the comparison set, and no table row dispositions one as
  No/❌/Missing in its verdict cell.

- **The operator-facing pages caught up too.** The gap ledger is what a site
  reads before adopting; the quick reference and the operations guide are what
  it reads afterwards, and five 2.0 directives never reached them —
  `brix_cache_urlcgi`, `brix_tpc_max_hops`, `brix_tpc_streams`,
  `brix_sss_getcreds` and `brix_tap_proxy_sss_identity` were fully written up in
  `directives.md` and invisible on the one page an operator opens first.
  `operation-status.md` still listed "PSS / full PFC / full XrdFrm storage
  layers" under **Intentionally not implemented**; that row is now scoped to the
  upstream **plugin ABI** — persona, reproxy and loadable `XrdOss`/`XrdPss`
  objects — because the capabilities themselves ship, and the FRM hard-blocker
  and remote-storage rows now name F1–F5 and the `exec`/`hpss`/`cta`/`lib` MSS
  adapters. `management.md` §Prepare gained a table of the five 2.0 FRM knobs.
  `tests/test_release20_ledger_pins.py::test_the_quick_reference_lists_every_directive_2_0_shipped`
  fails if a future closed gap ships without a row there. A companion pin,
  `::test_every_shipped_capability_is_reachable_from_the_operator_docs`, fails
  when a shipped handle is named only in the comparison ledger and nowhere the
  people running the software would look — which is how the proxy guide came to
  have no `brix_tap_proxy_sss_identity` row, the proxy-model concept page came to
  call the CVMFS listener "the only forward proxy in the tree" after
  `forward://` shipped a second one, and README's WebDAV line still said
  "HTTP-TPC COPY pull" four months after push landed.

- **F-numbers are checked cross-references now.** The register numbers each
  closed gap and the user docs cite those numbers, but nothing verified a
  citation landed on the right row: the checksum plugin loader (F8) was cited as
  **F11** — `brix_mirror_exclude_opcodes` — in four places, including the pin
  that was supposed to keep the ledger honest. Two tests in
  `tests/test_release20_surface_pins.py` now fail on a handle cited under a
  register item whose row never names it, and on a `2.0 F<n>` citation with no
  row at all. The same sweep found the source-verified comparison still listing
  "the checksum plugin framework" among the missing upstream ecosystems, the
  data-plane comparison enumerating nine built-ins with no `sha512` and no
  loader, and two pages stating "no plugin ABI" flatly — true of upstream's C++
  `XrdOss`/`XrdPss`/`XrdCks` objects, which BriX genuinely cannot load, but not
  of the two plain-C ABIs it deliberately exposes
  (`src/core/compat/checksum_plugin_abi.h` and the FRM `lib` adapter's
  `sd_frm_lib_abi.h`).

- **One status banner, checked against the register.** Nine gap and comparison
  pages now open with the same statement of what 2.0 closed and what is still
  open; three of them — including the twelve-page `xrootd-vs-nginx` set's own
  candid gap ledger, the most detailed parity document in the tree — carried
  none, so a reader could work through it with nothing saying the rows predate
  the feature work. `docs/index.md` gained a 2.0 entry pointing at the register.
  `tests/test_release20_ledger_pins.py::test_every_gap_ledger_opens_with_the_register_banner`
  compares each banner's open-item list against the register's own OPEN rows, so
  a banner that keeps naming F16 after F16 ships is a red rather than a lie a
  reader is expected to detect.

- **The WebDAV perimeter reverse proxy is documented as removed.** The
  transport was deleted on 2026-07-20 after a load-dependent heap corruption in
  the upstream response parse, but three pages still described it as
  implemented, one of them naming the deleted `src/protocols/webdav/proxy.c`.
  [operation-status.md](docs/05-operations/operation-status.md) and
  [forward-vs-reverse-proxy.md](docs/02-concepts/forward-vs-reverse-proxy.md)
  (§2 and §3.4) now say so, name the replacement (serve WebDAV at the edge, or
  nginx's stock `proxy_pass`), and call out the three survivors whose names
  invite confusion: `brix_webdav_proxy_certs` is GSI proxy-*certificate*
  acceptance, `src/protocols/webdav/proxy_pool.c` is the SHM backend registry
  behind the dashboard admin API, and `brix_backend_ca_dir` configures the
  stock proxy module. A configuration carrying `brix_webdav_proxy` is refused
  at `nginx -t` as an unknown directive.

- **A fabricated test citation was removed from the client resilience
  claims.** [native-client-tools.md](docs/04-protocols/native-client-tools.md)
  offered a `test_official_brix_resilience.py` under `tests/` as proof of
  reconnect and backoff against an official `xrootd` server; no such file has
  ever existed, and it is deliberately not spelled out here as a path — writing
  it as one would re-plant exactly the citation being corrected. The name came
  from `tests/test_official_xrootd_resilience.py`, whose docstring the 2026-07
  symbol rebrand renamed while leaving the file alone; the module had been
  misnaming itself ever since, and five downstream citations copied it —
  including a remote-suite runner that asked pytest for a path that does not
  exist. All six are corrected.
  The behaviour is real and the evidence is now the harness that produced it —
  `tests/resilience/` (servers and fault proxy in `servers.py`, smoke test
  `test_loss_sweep_gsi.py`, four standalone sweeps collected by
  `test_sweep_runners.py`) together with the recorded curves
  `results-packet-loss-mount-2026-06-23.md` and
  `results-xrdcp-loss-comparison-2026-06-23.md`, byte-exact to roughly 12%
  packet loss. `tests/test_test_module_self_reference.py` now makes a module
  that names a different file in its own docstring title, or a `tests/` README
  that cites a `test_*.py` which resolves nowhere, a test failure.

- **The fuzzing framework is no longer listed as outstanding work.**
  [hardening-strategy.md](docs/07-security/hardening-strategy.md) carried it as
  a **High** priority to-do; `tests/fuzz/` ships 14 libFuzzer harnesses with
  seeded corpora, driven by `tests/test_cmd_fuzz_all.py`,
  `tests/test_fuzz_carved_parsers.py`, `tests/test_fuzz_binary_conformance.py`
  and `tests/test_fuzz_http_conformance.py`, with corpus write-back guarded by
  `tests/test_ci_fuzz_corpus_writeback.py`.

- **Test-fleet commands name the entry point that exists.** The bash fleet was
  dissolved in phase-81, but `manage_test_servers.sh` survived as a *name* in
  89 places across 54 Python modules, configs and READMEs — none of them an
  exec, every one instructing a reader to run a script the tree does not
  contain. All 75 affected files now say `python3 -m
  cmdscripts.manage_test_servers start-all|stop-all|restart|status|start-dedicated`,
  run from `tests/`. Six historical narratives and the successor module's own
  "retired predecessor" line keep the old name deliberately, because there it
  is the record.

- **`docs/05-operations/remote-host-test-suite.md` installs 2.0.0.** Five
  copy-pasteable commands still named `1.1.1-20.el9` packages.
  `tests/test_doc_release_hygiene.py` now fails any user-facing page that
  quotes a package version or `Release:` other than the ones `src/core/ident.h`
  and `packaging/rpm/nginx-mod-brix-cache.spec` carry — scoped to the packages
  that spec actually builds, so a third party's correctly-versioned RPM is left
  alone — and any page that names a pre-rebrand client artifact (`libxrdc*`,
  `-lxrdc`, `xrdc.h`, `libxrdposix_preload`) while leaving the five names that
  really did survive the rebrand (`xrdcp`, `xrdfs`, `.xrdcap`,
  `XRDC_ERESOLVE`, `XRDC_CONNECT_TIMEOUT_MS`) untouched.

- **`tools/diag/lock_scan.py` ships in the package again.** The
  [directives reference](docs/03-configuration/directives.md) tells an operator
  to run this pre-upgrade lock inventory *before* switching an export to
  `brix_lock_enforcement strict`, and the tool was matched by a `.gitignore`
  rule — so it was missing from every fresh clone and the documented upgrade
  procedure could not be followed. It is now exempted and tracked. Being
  ignored had also kept it outside every quality gate and every test:
  `tests/test_lock_scan_tool.py` gives it its first coverage — the three
  documented exit statuses (0 no live locks, 1 found, 2 usage/IO error), the
  decode contract including the rule that a legacy v1 record is treated as
  already expired, and two security properties an operator relies on, namely
  that a lock **token** is never printed (it is a bearer secret, and this
  tool's output goes into tickets and scrollback) and that an expired record is
  counted but never listed.

- **The documentation path guard now covers the documentation.**
  `tools/ci/check_doc_paths.py` proved that every path named in a doc exists
  and is tracked, but scanned only `CLAUDE.md`, `README.md` and
  `docs/index.md` — so the eight user-facing trees were unpoliced, which is how
  a deleted transport and a file that never existed could sit in them for
  months. It now scans those three strictly plus `docs/01-getting-started`
  through `docs/08-metrics-monitoring`, where a token must first look like a
  path (trailing slash, two or more slashes, or a known suffix) so English
  prose is not mistaken for one. It also expands brace lists and exempts build
  products (`client/bin/`, `client/lib/libbrix*`, `objs/`). `docs/09`-`11` stay
  out of scope on purpose: in developer history and refactor records, naming a
  deleted path *is* the content. `tests/test_doc_path_guard_reach.py` pins the
  scope and all three filters with 29 tests, including a security-negative
  proving the build-product exemption does not reach sources — a prefix one
  segment shorter would silence the entire `client/` tree.

- **The impersonation guide now tells an operator what enabling `brix_idmap
  map` costs, and what it does not.** `docs/06-authentication/impersonation.md`
  lists the namespace mutations the broker performs as the mapped user; the
  atomic two-name swap was missing from that list because it was missing from
  the broker, so turning per-user identity on silently withdrew a capability the
  same export had with impersonation off. The bullet now names `exchange`
  (`renameat2(RENAME_EXCHANGE)`), states that it is **never** emulated with two
  renames on any kernel — a caller that asked for atomicity is answered
  `ENOTSUP` rather than handed the window it was trying to close — and
  deliberately contrasts that with the exclusive-rename arm, which *does* fall
  back to a plain rename, because under-claiming exclusivity is survivable and
  losing atomicity is not. It also records the one deliberate exception: the
  content-addressed `.gcas/` dedup farm stays the worker identity.

- **The storage-driver slot matrix described the POSIX per-user identity plane
  incorrectly.** Its `id` verdict read "no assumable per-user identity at this
  backend … deny mode refuses and allow mode runs as the export identity". On
  `posix` the second half was false: the per-user identity is real, it is simply
  not a credential threaded through the storage vtable — it is the calling
  thread's own `setfsuid`/`setfsgid`, installed by the impersonation broker one
  layer below the driver at the confined-path seam, so under `brix_idmap map`
  every namespace syscall the driver issues is already performed as the mapped
  user on that user's own DAC. Operators reading the matrix to decide whether a
  local export supports per-user identity were being told the opposite of the
  truth. The legend, the per-driver reading and §5 are rewritten, and the
  generator now applies one further rule uniformly: a `_cred` cell whose plain
  twin the driver does not implement can never be `id`, because the refusal that
  verdict describes is only reachable when the plain slot exists. Four `posix`
  cells (plus cells on `block` and `frm`) moved off `id` onto their base
  verdicts, and `posix`'s slot count is corrected from 36 to 37.

- **Two deliberate identity decisions are now stated in the source rather than
  inferable from it.** `sd_posix_dedup.c`'s content-addressed hardlink farm runs
  as the export identity on purpose — its names are content-derived, no client
  can address them, and one inode is shared by every publisher of the same
  bytes, so `st_nlink` (the refcount) would be unmaintainable if each publish
  ran as a different user. And `brix_opendir_beneath()` carries no impersonation
  branch on purpose: its single caller checks first and asks the broker for an
  `O_DIRECTORY` fd, so there is no "opendir" broker verb to add.

### Fixed
- **`brix_idmap map` silently disabled atomic two-name swaps.** Every confined
  filesystem operation is performed as the mapped user by the privileged
  impersonation broker — except `exchange`, which had no broker verb and so
  answered `ENOTSUP` for as long as impersonation was active. An export
  therefore ran its whole namespace as the mapped user apart from this one
  operation, and any tier that publishes by swapping two names lost the
  capability the moment per-user identity was switched on: a capability
  regression caused by *enabling* security. The broker now implements
  `renameat2(RENAME_EXCHANGE)` and the confined seam routes to it. **The swap is
  never emulated with two renames**, on any kernel: the only emulation opens
  exactly the window — an instant in which one of the two names does not
  resolve — that a caller asking for an atomic swap asked to avoid, so a kernel
  or filesystem without the flag answers `ENOTSUP`, identical to the
  non-impersonated answer. This is deliberately the opposite of the
  `RENAME_NOREPLACE` arm's policy, which does degrade to a plain rename, because
  under-claiming exclusivity is survivable and losing atomicity is not. The wire
  op was appended, so the worker/broker protocol version is unchanged.
  `tests/test_release20_posix_cred_plane.py` (24).

- **An unreadable CRL inside a CRL *directory* silently disarmed revocation
  checking.** `brix_crl` may name a CRL file or a directory of them. Naming a
  file the worker cannot read has always been refused at `nginx -t`; naming its
  *parent directory* was accepted, because the config-time `access(R_OK)` test
  is asked about the directory and never about its contents. The loader then
  mapped the failed `fopen` to "0 CRLs here", and under `brix_crl_mode try` the
  flags are armed only when at least one CRL loaded — so a `chmod 000` on the
  only CRL in a CRL directory moved a server from refusing a revoked
  certificate to accepting one, with no reload and no configuration change. It
  was reported in the startup log (three lines, one saying outright that
  revoked certificates are still accepted), but a warning is not a gate. A CRL
  that is *present but unreadable* is now a hard load failure on both planes:
  the `root://` server refuses to start with an `[emerg]` naming both the
  `brix_trusted_ca` and the `brix_crl` path, and the WebDAV plane refuses with
  its own. A directory that opens cleanly and yields no CRL is unchanged — hash
  symlinks and stray `.pem` files must not stop a server, and `require` versus
  `try` still decides what an empty feed means. On a reload the failure keeps
  the last-good store rather than clearing it, so a running server never loses
  revocation to a permissions change. Pinned by seven tests in
  `tests/test_release20_tlsca_residuals.py`, including that neither `try` nor
  `off` nor the default can talk the loader out of the refusal. *(2.0 F22)*

- **`brix_checksum_default sha512` advertised `adler32`.** `sha512` is a
  built-in on every checksum surface — Qcksum, `?cks.type=`, Want-Digest,
  `brix_checksum_default` — but was missing from the `query config chksum`
  list clients negotiate from, and the check deciding whether a configured
  default was answerable walked that same short list. So `sha512`, and the
  documented alias spelling `crc64xz`, were dropped from the advertisement
  entirely: computable, configured, and invisible, with every client falling
  back to `adler32`. The list now carries all ten built-ins, and the default
  gate asks `brix_checksum_parse()` — the resolver the Qcksum path itself uses
  — so the two surfaces cannot disagree again. An unanswerable default is
  still dropped rather than echoed. Pinned by six tests in
  `tests/test_release20_checksum_plugin.py`, including a set-equality guard
  between the built-in table and the advertised list.

- **Six features were registered, configurable — and permanently disarmed.**
  Each read `cache_origin_host` / `cache_origin_port`, orphaned when the
  `brix_cache_origin` directives were retired in phase-64 §14 and surviving only
  as the parameter block of the *synthetic* server conf `sd_xroot` hands to the
  in-process origin wire client. On a real server conf both are empty forever,
  so every gate reading them was constant-false and `nginx -t` had nothing to
  complain about. Fixed: (1) the Pelican advertiser now arms on
  `brix_cache_advertise_federation` (above); (2) an object the cache admission
  policy declines — too large to cache — is redirected to the export's
  registered `root://` backend instead of answering `kXR_Unsupported`; (3) a
  `kXR_Qcksum`-by-path cache miss redirects to that backend instead of answering
  "not found"; (4) the fill spine always resolves the registered backend, the
  skip-if-origin-configured branch around it having been unreachable; (5) the
  `kXR_attrCache` login advert and (6) the write-back stage builder each lose a
  constant-false second arm. The start-up NOTICE now prints
  `brix_storage_backend` rather than the always-empty retired string, and the
  origin TLS refusal points at a `roots://` backend URL rather than at
  `brix_cache_origin_tls`, retired two phases ago. The four orphaned fields are
  documented in `srv_conf_fields_net.h` as synthetic-conf-only, with
  `brix_sd_xroot_endpoint()` as the supported way to learn a backend's endpoint,
  and a tree-wide guard holds them to the five files that legitimately touch
  them. Pinned by `tests/test_release20_never_armed.py` (28 tests).

- **`brix_cache_verify off` and `require` now have effect on the standalone
  cache.** The directive wrote the shared preamble's mode field while the
  standalone (`brix_cache` + `brix_cache_export`) fill spine read a *different*,
  stream-only field that no directive could write: every standalone cache
  verified best-effort whatever the configuration said, so `off` never saved
  the checksum round-trip and `require` never gained its teeth there. Both
  spines now read the one field through `brix_cache_verify_effective()`, which
  keeps the documented standalone default (best-effort) for an unset value
  while honouring an explicit setting; the composed tier's own documented
  default (`off` when unset) is unchanged. The dead duplicates are removed from
  the stream server config. Pinned by
  `tests/test_release20_registered_nowhere.py`.

- **Nine `nginx -t` diagnostics named directives that do not exist.** A config
  error that tells an operator to set `brix_proxy_upstream`,
  `brix_proxy_auth`, `brix_proxy_login_user`, `brix_gridftp_require_vo`,
  `brix_kv`, `brix_s3_storage_credential`, `brix_webdav_storage_credential`,
  `brix_webdav_crl` or `brix_token` sends them to a name the server then
  refuses as unknown. Every message now names its registered spelling
  (`brix_tap_proxy_*`, `brix_require_vo`, `brix_kv_zone`,
  `brix_storage_credential`, `brix_crl`, `brix_token_config`), and a tree-wide
  pin keeps every `brix_*` token in a config-time diagnostic a real directive.

- **External programs no longer inherit worker descriptors.** The exec MSS
  adapter's stage command and the F4 policy program spawn in their own
  session with fds 0–2 only (`POSIX_SPAWN_SETSID` + closefrom), and a
  `brix_frm_copy_timeout` kill takes the whole process group; the mover
  runner (`brix_xfer_run_reparented`) closes every inherited fd with
  `close_range` instead of stopping at 1023. Before, a stage program's
  surviving child could keep the server's listen socket bound after a
  deadline kill or restart, and a busy worker leaked client connections to
  `xrdcp`. Pinned by `test_release20_frm_knobs.py` (×3),
  `test_release20_purge_policy.py` (×1) and `xfer_spawn_unittest.c` (×2).

- **The FRM operator programs no longer lose their exit status to nginx.** The
  master's signal handler calls `ngx_process_get_status()` for SIGCHLD in
  workers too, so `waitpid(-1, WNOHANG)` there reaped any direct child of a
  worker before the feature's own wait reached it: the exec MSS adapter's stage
  command and the F4 purge policy program both saw `ECHILD` and reported every
  verb as failed (`unknown process NNNN exited with code 0` beside `stage
  command failed`). Both now run through the shared reparented runner
  (`brix_subprocess_run`), whose double-forked agent the worker never has as a
  child and which owns the deadline, the process-group kill and the spawn
  hygiene; the streaming `dread` listing remains the only direct child.
- **A failed tape seal is retried instead of dropped.** An MSS verb that failed
  without setting an errno of its own left whatever errno the runner had last
  set, and a stale `ENOENT` reads as "the marker was withdrawn" — which dropped
  a journaled `archive` record that owed a retry and a dead-letter. Every verb
  now reports a deterministic `EIO` when it has no reason of its own.
- **`attempts` counts the first failed drive.** The completion path persisted a
  FAILED stage record without bumping it, so a record the `brix_frm_fail_backoff`
  sweep rescued published `attempts=0` — indistinguishable from a crash replay
  that never ran, and one drive short of the `brix_frm_fail_retries` cap. A
  record that never failed still reports 0.
- **A pooled upstream connection is never handed to another identity.** The
  stream proxy's worker-local upstream pool matched on `(upstream_idx,
  auth_type)`, but `upstream_idx` indexes a per-server-block list and, under
  `brix_tap_proxy_sss_identity client`, GSI-as-user or `brix_proxy_login_user
  passthrough`, the upstream leg carries the client's own identity — so a
  connection could be reused across server blocks and across users, including
  serving an anonymous session over a named client's authenticated origin
  session. The pool now keys on the owning server block plus a digest of the
  forwarded identity itself (passthrough login name, bearer token, minted sss
  entity).
- **A forwarding refusal no longer marks the origin down.** Refusing to forward
  an unauthenticated session is our own decision, taken before the origin sees a
  byte, but the abort was charged to upstream health: three anonymous attempts
  against a `client`-mode front blackholed a healthy origin worker-wide for
  `BRIX_PROXY_FAIL_TIMEOUT`.
- **Only an asserted VO and role are forwarded.** The attribute view derives a
  VO from a bare group name (right for the local xrdacc engine), so a v1
  NAME-only client reached the origin as `vorg="nogroup"` — a claim it never
  made. The sss entity now forwards a VO/role only when the peer asserted one;
    `GRPS` still travels verbatim, so the origin derives the same view it always
    did.

---

## v1.5.0 — 2026-08-26

- Added per-host authentication binding and per-capability TLS policy
  directives, alongside an explicit opt-in for cleartext bearer-token tests.
- Removed the retired throttle configuration path; the active per-user
  open-file limit remains supported.

## v1.4.0 — 2026-08-03

- Added the io_uring direct-I/O client tier, remote HTTP cache passthrough,
  expanded CVMFS X.509/VOMS authorization, and remote-storage mutations.
- Added the client diagnostics and mesh-map tools, plus build-coverage guards
  for client and shared sources.

## v1.3.0 — 2026-07-23

- Aligned the server identity, RPM fallback, and release metadata on version
  1.3.0.

## v1.1.1 — 2026-07-07

- Added native CVMFS cache and writable-overlay support, WLCG token and X.509
  conformance hardening, VFS-backed storage drivers, and native client tools.
- Later RPM revisions added co-installable `brix-` compatibility tool names
  and packaging refinements; see the RPM changelog for each revision.

## v0.1.0 — 2026-04-21

- Initial dynamic nginx module release, later expanded with SRR, HTTP filter,
  dashboard, native clients, and the BriX-Cache package branding.
