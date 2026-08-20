# Testsuite combinatorial coverage audit — 2026-08-15 (second pass)

Second-pass audit of feature combinations that BriX correctly supports but the
testsuite never exercises. The first pass
([testsuite-combinatorial-coverage-audit-2026-08-04.md](testsuite-combinatorial-coverage-audit-2026-08-04.md))
had its ranked backlog burned down on 2026-08-04/05; this pass therefore looks
where that one did not: the **full directive surface** (including the
macro-generated grammars the first pass could not see) and a **pairwise
co-occurrence matrix** over every config unit in the tree. Findings only — no
fixes are bundled with this document.

## Closure status — sixteen tranches (2026-08-15, tail on 08-17)

The ranked backlog was burned down tranche by tranche — seven on the day of the
audit, the eighth on 08-16 against every row the first seven had recorded as
still open, the ninth against the rows deferred *by decision* plus the two
unranked sections (§D, §E), the tenth against the one environment-deferred
residual plus a **re-run of the §A measurement itself**, the eleventh, twelfth
and thirteenth against a re-run of **§Method step 3**, which is where the pass's
own method turned out to have scored pairs covered that no server block runs,
the fourteenth on 08-17 against a re-run of **§Method step 2**, which had
scored a directive covered for merely appearing in a template some test
launches, and the fifteenth the same day against a re-run of **§Method steps 1
and 2 at VALUE granularity**, where both steps turned out to be answered by one
token of an enum table however many values it holds, and the sixteenth — still
running — against the same re-run widened from the enum tables to the **128
`ngx_conf_set_flag_slot` flags**, where a name is answered by one of two tokens
and seven directives turn out to have neither. What each file closed, against
the section that ranked it:

> **Running total across the sixteen tranches: 108 files, 4,139 tests** — the
> first 59 files, `PYTHONPATH=tests pytest $(ls tests/test_audit15*.py)`
> measured on 2026-08-16, are **513 passed, 5 skipped, 0 failed in 25 min** on a
> stock build, where the 5 skips are the io_uring file; tranche 14's five files
> add **104 passed, 0 failed in 2 min 50 s** and tranche 15's nine add
> **435 passed, 0 failed in 4 min 07 s**, both measured on 08-17 in one process
> each, so those instances' ledger ports are proven disjoint; tranche 16's first
> ten files add **1,023 passed, 0 failed** (4 min 10 s, 4 s, 6 s, 24 s, 10 s,
> 12 s, 2 min 33 s, 36 s, 10 min 27 s and 1 min 16 s), also 08-17, and its
> `directives_cms.h` trio (files 11–13) adds **130 passed, 0 failed in 40.6 s**
> measured in one process, which is also the statement that the two ledger groups
> they borrow — the CMS parity wave's and the stream guard's — do not collide, and
> its file 14 adds **115 passed, 0 failed in 14.0 s**, its file 15
> **244 passed, 0 failed in 56.7 s**, its file 16
> **83 passed, 0 failed in 40.2 s**, its file 17
> **88 passed, 0 failed in 19.4 s**, its file 18
> **82 passed, 0 failed in 2 min 04 s**, its file 19
> **67 passed, 0 failed in 44.7 s**, its file 20
> **33 passed, 0 failed in 55.2 s** and its file 21
> **43 passed, 0 failed in 6 min 57 s** and its file 22
> **53 passed, 0 failed in 1 min 17 s** and its file 23
> **30 passed, 0 failed in 1 min 15 s** and its file 24
> **32 passed, 0 failed in 44.1 s** and its file 25
> **32 passed, 0 failed in 55.2 s** and its file 26
> **31 passed, 0 failed in 65.0 s** and its file 27
> **32 passed, 0 failed in 21.0 s** and its file 28
> **37 passed, 0 failed in 7.9 s** and its file 29
> **57 passed, 0 failed in 13.1 s** and its file 30
> **131 passed, 0 failed in 27.9 s** attached to a warm prefix, 1 min 56 s cold,
> and 2 min 35 s under `-n 2 --dist loadgroup` beside `test_fleet_ports.py`, and
> its file 31
> **170 passed, 0 failed in 3.6 s** serially, 3.2 s cold against a fresh
> `TEST_ROOT`, and 4.8 s under `-n 2 --dist loadgroup` beside
> `test_fleet_ports.py` — eight gateways in one process, and an FTP control
> dialogue costs a connect and a few lines, so this is the cheapest file of the
> tranche by an order of magnitude, and its file 32
> **131 passed, 0 failed in 17.7 s** serially, 14.4 s cold against a fresh
> `TEST_ROOT`, and 18.0 s under `-n 2 --dist loadgroup` beside
> `test_fleet_ports.py` — seven registry fronts in one process, four of them
> cleartext and three of them TLS, and the whole of an image push is four
> requests, and its file 33
> **99 passed, 0 failed in 4.1 s** serially, 3.8 s cold against a fresh
> `TEST_ROOT`, and 5.0 s under `-n 2 --dist loadgroup` — eight guard fronts in
> one process, a probe is one connect and the parse tier is the rest of the
> file, which puts it beside file 31 as the cheapest of the tranche, and its
> file 34
> **66 passed, 0 failed in 3.0 s** serially, 5.2 s cold against a fresh
> `TEST_ROOT`, and 5.2 s under `-n 2 --dist loadgroup` — TWO stream instances on
> one harness rather than one, because two of its findings are properties of a
> process singleton and a singleton cannot be both absent and present in one
> nginx; twelve fronts between them, and a measurement is a login and one
> request, which makes it the third of the tranche's cheap files, and its
> file 35
> **136 passed, 0 failed in 2.6 s** serially, 2.7 s cold against a fresh
> `TEST_ROOT`, and 4.2 s under `-n 2 --dist loadgroup` — four gateways and one
> `/metrics` face in one process, and every measurement is a login and one or
> two commands, which made it the cheapest file of the whole audit until the
> file that follows it, and its file 36
> **281 passed, 0 failed in 3.1 s** serially, 4.1 s cold against a fresh
> `TEST_ROOT`, and 3.5 s under `-n 2 --dist loadgroup` — THIRTEEN faces on four
> planes in one process (six WebDAV vhosts and five S3 ones across two
> listeners, three stream servers and a `/metrics` face), sharing ONE export
> directory so that a row differing between two faces differs because of the
> directive and not because of the bytes; the largest file of the tranche by
> test count and, at 3.4 s, among the cheapest of the whole audit, which is what
> thirteen faces on one harness buys. (Those are the post-fix numbers: the file
> was written against the defective tree, where it stood at 268 tests and 1.7 s;
> #138-#145 were then fixed and every cell that pinned the old behaviour was
> rewritten to pin the new, which is what the extra thirteen are — the
> per-verb S3 equality, the statx text, rmdir and the two mutating-verb
> negatives, the cross-scope duplicate negative, the deep reserved component,
> and the three §K cells that read the fix off the C.) Those three figures were
> re-measured on 08-20 against a canonically reconfigured and rebuilt tree, after
> the last of the fixes — the `s3_copy_resolve_source()` extraction — had landed;
> the earlier post-fix run stood at 3.4 s / 3.6 s / 4.4 s on the build that
> preceded it.
> green three runs running (files 20 and
> 21 twice, file 22 twice on 08-18 — 1 min 17 s then 1 min 51 s — file 23
> three times on 08-18: 1 min 15 s serially, 1 min 18 s again, and once more
> under `-n 2 --dist loadgroup`, which is the statement that its thirteen
> locations survive being driven from two workers; and file 24 three times on
> 08-18: 44.1 s, 43.9 s and 49.8 s under `-n 2 --dist loadgroup`, which is the
> same statement about its twelve listeners; and file 25 three times on 08-18:
> 55.2 s, 56.3 s and 59.1 s under `-n 2 --dist loadgroup`, which for that
> file is a statement about its three stub upstreams as much as its eight
> planes, since a stub is shared by more than one of them; and file 26 three
> times on 08-18: 65.0 s, 2 min 14 s with `-n 0`, and 5 min 17 s under
> `-n 2 --dist loadgroup`, the last two measured while a second lane was running
> in the same session — the numbers are what they are, and what the runs
> establish is that the file's seven locations and two shadows survive being
> driven from two workers; and file 27 three times on 08-19: 21.0 s, 16.5 s
> with `-n 0`, and 6 min 05 s under `-n 2 --dist loadgroup`, where that last
> figure is mostly a fleet: it ran with `TEST_OWN_FLEET=1`, so the wipe and
> restart of ~150 instances is inside it, and a second lane was running in the
> same session throughout — what the run establishes is that the file's five
> locations, its CMS node and its recording data server survive being driven
> from two workers; and file 28 three times on 08-19: 7.9 s attached to a running
> fleet, 3 min 28 s under `-n 2 --dist loadgroup` with `TEST_OWN_FLEET=1`, and
> 4 min 32 s serially afterwards — the last two are a fleet wipe and restart
> apiece, since the file's own fourteen vhosts are one instance and cost eight
> seconds of it, and what they establish is that those vhosts survive being
> driven from two workers; and file 29 three times on 08-19: 18.5 s against a
> reused instance prefix, 13.1 s from a cold one — the prefix was removed
> between the two, which is what says its log readings attribute a diagnostic to
> a config line rather than to a run — and 23.4 s under `-n 2 --dist loadgroup`,
> which is the statement that its seven stream servers, its CMS registration and
> its dashboard survive being driven from two workers). On a
> **liburing-enabled** binary those 5 skips run and 1 of them fails; that
> failure is real and is defect candidate #29 — see tranche 9.
> **One hundred and forty-four defect candidates** found and pinned
> along the way (#1–#145, with #78 withdrawn on measurement and re-recorded as an
> observation — see tranche 16 — so the numbers run to 145 and the count is 144),
> two of which — #23, the pre-auth TLS-upgrade UAF, and
> #64, the pre-auth OCSP double free that killed the worker on every completed
> round trip — have since been fixed in the tree, and whose files are now the
> regression guards for those fixes; each is written to invert when the defect
> is fixed.
> The §A appendix — the 95 directives with zero coverage of any kind — is
> **closed with no caveats left** (tranche 10 fired the last one,
> `brix_cms_server_tcp_user_timeout`, inside a netns); §B is closed in full
> (§B2.13's build blocker is lifted, and the row's failure is a finding, not a
> gap); §C is **closed in full**, including the three rows the 08-04 audit and
> this one both recorded as needing infrastructure the suite could not stand
> up; and §D and §E now have guards that fail when their claims stop being
> true. §A's measurement was re-run against today's tree (524 → **555**
> directives) and the seven names it newly returned are closed too — including a
> security control that had never been able to work (#34). **Nothing from the
> original document is deferred; the open backlog is now the audit's own, and
> it is a measurement artefact rather than a list** — and both artefacts are now
> closed. Re-running **§Method step 3** per *server block* instead of per file
> showed 16 pairs it had scored as covered that no single block runs: tranche 11
> closed the S3 security cluster (#36–#38), tranche 12 the http-plane
> storage-element cluster (#39–#44, plus the two fresh pairs its own file
> created) and tranche 13 the six stream-plane survivors (#45–#47), taking it
> 16 → 8 → 6 → **0**. Re-running **§Method step 2** per *verdict* instead of per
> name — "is there a test whose outcome changes when this directive's value
> changes?" — showed 13 directives that only ever sat inside a launched `.conf`;
> tranche 14 closed all 13 (#48–#50), taking it **13 → 0**. Re-running **steps 1
> and 2 per (directive, VALUE) pair** over the 36 `ngx_conf_enum_t` tables —
> because both steps are answered by one token of a table however many values it
> holds — showed **93 pairs, 45 of them written nowhere in the corpus**; tranche
> 15 closed all 45 (#51–#63) bar three arms recorded as gaps, taking it
> **45 → 0**. Widening the same re-run from the enum tables to the **128
> `ngx_conf_set_flag_slot` flags** gives **256 pairs, 106 written nowhere**
> across 99 directives — seven of which have BOTH arms unwritten, which is a
> branch nothing has ever entered rather than a coverage gap. Tranche 16 has
> taken **all seven** — the OCSP cluster, `brix_http_query_token`,
> `brix_cvmfs_origin_reuse_conn`, `brix_krb5_ip_check`, and
> `brix_backend_passthrough_persist` at parse tier only because it has no reader
> anywhere — and then 55 of the 92 directives with exactly ONE arm unwritten: the
> five S3 location flags, the six SciTags pmark flags, the six shared-http flags,
> the nine CVMFS resilience flags, the five root:// node-capability flags, all
> twelve arm-gaps of `root/stream/directives_cms.h` — the first whole header
> closed rather than a feature, and the first two gaps in the tranche whose
> unwritten arm is an explicit **`on`** (both keepalive flags merge to 1) — and the
> five location-scoped WebDAV flags, where a third such **`on`** turned up:
> `brix_webdav_upload_resume` merges to 1, so the arm the corpus wrote was the
> redundant one and the arm that disables resumable uploads had never been
> measured at all — and the three WebDAV flags declared in **three** scopes
> (`brix_webdav_zip_access`, `brix_webdav_require_digest`, `brix_webdav_dig`),
> where the arm worth writing is not `off` in a bare location, which the merge
> default already gives, but the per-location **opt-out** under a server that
> wrote `on`, which absence cannot express and nothing in the tree had ever
> configured — and, closing that table, `brix_webdav_proxy_certs`, whose `off`
> the corpus had never written against 88 `on`s and whose only observable is a
> TLS client-certificate verdict, so its arms need one listener each rather than
> one vhost each — and then the three acc-engine flags of the stream plane
> (`brix_acc_pgo`, `brix_acc_resolve_hosts`, `brix_acc_encoding`), the tranche's
> first subjects whose `on` arm the corpus writes only from **test sources and
> prose**, no rendered template writing them at all, and where one of the three
> turns out not to be per-server at all (#92) — and, twelve lines further down
> that same header, the two CSI integrity flags (`brix_csi_require`,
> `brix_csi_trust_fs`), where the never-written `off` is the only way to ask
> what an acceptor does with a file whose at-rest record is in a known state,
> and the answers are that the fail-closed flag is inert under the performance
> one (#93) and that a caught corruption is reported as a disk error (#94), and
> — one line above those, on the same header — `brix_krb5_delegate`, whose
> never-written `off` is the only way to ask what the armed arm COSTS, the
> answers being that a login refused for the reason the directive exists is
> recorded on no operator-visible face at all (#95) and that the user TGT it
> captures lands in `/tmp` under a knob no config file can turn (#96) — and, on
> the security header of the same module, the inline-compression pair
> (`brix_read_compress`, `brix_write_compress`), whose never-written `off` is
> the only way to ask what the nineteen-file compression suite could not,
> because every one of its files runs against the single shared config that
> writes both arms `on`; the answer is that the pair is genuinely two
> independent slots and fails soft exactly as documented, but that neither
> direction is counted anywhere, so an operator can see that one request
> compressed and never how often compression was refused (#97) — and, closing
> the OCSP family the tranche opened with, `brix_ocsp_require_nonce`, the last
> flag whose two arms reached no config at all, where the CWE-294 replay guard
> turns out to survive `brix_ocsp_soft_fail on` only by sharing a return code
> with revocation, and to be REPORTED as one: six distinct refusals, a nonce
> deny among them, all reach the operator as `certificate is REVOKED` (#98) —
> and, last, the two third-party-copy egress families, taken one header at a
> time: the seven `root/stream/directives_tpc.h` flags whose DISARMING arm the
> corpus never spelled, where the one arm the operator turns out not to own is
> an `off` a GSI tap proxy silently re-arms (#99), and the four WebDAV
> HTTP-TPC flags that decide where a destination may DIAL, where the
> never-written arms are what expose an SSRF refusal reduced to the last line of
> a 202 body (#100) and an allowlist that is inert, and silent about it,
> whenever its guard flag is off or absent (#101) — and, last, the four
> `root/stream/directives_security.h` flags whose second token nothing had ever
> written, where the pattern of #101 turns out to have a twin one header away: a
> configured `brix_zip_stage_dir` is inert, and says nothing at any log level,
> whenever `brix_zip_force_scratch` is off or absent (#102).
> It has found **#64–#145**, one of
> them a pre-auth remote crash since fixed. 7 × 2 + 87 is
> **101 pairs closed of the 106, 5 remain** — plus the first 2 of the **12 that
> reached a config only through a `{PLACEHOLDER}`**, which file 21 shows is a
> weaker kind of coverage than the census credited: `brix_ocsp_require_nonce`
> reaches one through `{TLS_DIRECTIVES}`, and every token that placeholder
> carries is spent on an `nginx -t`, so the runtime branch was as unentered as
> any of the 106
> (an earlier revision of this line said 103 after the OCSP cluster; it had
> subtracted the three directives rather than their six pairs).
> **The 106 is the grep's number, and file 30 was its last row — files 31 and
> after are the census correction.** A corpus grep for a flag arm is wrong in
> both directions: a template slot renders a token the grep sees whether or not
> any lane fills it, so `{ANON_LINES}` and `{TLS_DIRECTIVES}` OVER-report, while
> an arm a lane composes programmatically —
> `"brix_gridftp_require_allo_size on;" if require else ""` — is written by a
> real run and UNDER-reports as unwritten. Files 31–34 close ten pairs the first
> census credited as covered: the three GridFTP gates (file 31), the two
> `protocols/oci` securing arms (32), the two `net/httpguard` arms (33), and the
> health-check and two tape-plane flags (34), every one of them a directive
> written `on` somewhere and `off` in NOTHING, whose "not running" control the
> corpus expresses as an ABSENCE. File 35 closes an eleventh
> (`brix_gridftp_allow_write`, `on` in thirty-one configs and `off` in none) and
> file 36 a twelfth of a shape the census has no column for:
> `brix_cache_store_endpoint` is ONE name declared TWICE, on the http plane and
> the stream plane, by two different setters — the corpus wrote `on` once, on
> the stream plane, and `off` nowhere, so the http declaration's custom setter
> had never run in this suite at all and the dual write it exists to perform had
> never happened.

### Tranche 1 — five `tests/test_audit15_*.py` files, 25 tests

The top of the ranked backlog, plus the parse-tier sweep of the long tail:

- **`test_audit15_throttle_open_files.py`** (4) — closes the §A2 open-files
  throttle: grant/refuse/release-on-close at the cap, cap spanning connections
  with async release on disconnect, stat-not-gated control, and the
  undeclared-zone parse refusal from `server_conf_merge_security.c:177`.
- **`test_audit15_read_only.py`** (3) — closes §A2 `brix_read_only`: WebDAV
  writes 403 with disk-state-unchanged proof, root:// write-open refused with
  `kXR_fsReadOnly` while read-open still works, and the override of an explicit
  `brix_allow_write on` is the configuration under test.
- **`test_audit15_guard_knobs.py`** (6) — closes the §A1 httpguard signature
  engine: all four knobs composed live (custom signature bounce with configured
  status, built-in set disabled with a defaults-on control instance, narrowed
  method grammar) plus parse rejects for a typoed method and an off-menu
  bounce status.
- **`test_audit15_webdav_macaroon_rotation.py`** (3) — closes the §A1
  `brix_webdav_macaroon_secret_old` plane-parity hole: current accepted, old
  accepted via the grace retry, any third secret rejected.
- **`test_audit15_zero_directive_parse.py`** (9) — first coverage, at the
  `nginx -t` tier, for the rest of the §A1/§A3/§A4 long tail: two combined
  accept configs (one stream server, one WebDAV location — every swept
  directive at once) plus rejects for `brix_signing_policy`,
  `brix_pmark_domain`, `brix_zip_cd_max_bytes`, the webdav token clock-skew
  bound, the undeclared `brix_webdav_revoke_cache` zone, a lax-permission
  `brix_backend_sss_keytab` (the setter validates mode *and* line grammar at
  parse), and `brix_webdav_redirect_scheme`. Parse-tier only — the live
  behavior of these knobs (SSI/CTA, TPC lifetime kill-switches, WT staging,
  introspection, dashboard auth) stays open below.

### Tranche 2 — same day pm, six `tests/test_audit15b_*.py` files, 19 tests

The §B pairwise matrix rows feasible without live externals, plus two §A
residuals that only needed their own fixture design:

- **`test_audit15b_virtual_redirector.py`** (3) — closes §A2
  `brix_virtual_redirector` live mode: the flag's only runtime consumer is
  `protocol_role_flags()` (src/protocols/root/session/protocol.c), and the
  tests pin exactly that — `kXR_protocol` advertises
  `kXR_isManager|kXR_attrVirtRdr` with the flag on, a control twin keeps the
  bits clear, and (no `brix_manager_map`) opens still serve locally.
- **`test_audit15b_guard_webdav_tpc.py`** (4) — closes §B1.5 (guard ×
  WebDAV TPC) by **pinning a discovered product limitation**: the pair is
  incompatible by construction. Request-time `method_to_op`
  (src/net/httpguard/guard_http_req.c) maps COPY/MOVE to `GUARD_OP_UNKNOWN`,
  the xrdhttp profile enforces grammar, so every WebDAV-TPC verb is
  grammar-bounced (403 + `signal=grammar` in the audit log) — and the escape
  hatch does not exist: config-time `method_name_to_op`
  (src/net/httpguard/module.c) also lacks COPY/MOVE, so
  `brix_guard_valid_method COPY` fails `nginx -t`. A guarded WebDAV endpoint
  cannot be a TPC party today; these tests pin current behavior and flag the
  gap as **defect candidate #3** (add COPY/MOVE to both tables or document
  the exclusion).
- **`test_audit15b_readonly_tpc_dst.py`** (3) — closes §B1.6 (readonly ×
  native-TPC destination): the security-negative proves the write gate
  (`brix_open_mode_guard`, fires before TPC opaque parsing) kills the pull at
  the dest-open with `kXR_fsReadOnly` and nothing on disk, the refusal leaves
  the connection serviceable, and the byte-identical open is granted on a
  writable twin (which needs a main-context `thread_pool` — a granted TPC
  dest-open refuses with "TPC pull requires brix_thread_pool" otherwise).
- **`test_audit15b_substreams_tls.py`** (3) — closes §B1.3 (substreams ×
  TLS): over an in-band-upgraded TLS session, a bound secondary
  (`kXR_bind` with the login sessid) reads a primary's handle byte-exact,
  cannot open files of its own (security-negative), and its disconnect leaves
  the primary session live.
- **`test_audit15b_webdav_token_config.py`** (3) — closes the §A1
  `brix_webdav_token_config` plane-parity hole with a live TokenForge issuer
  registry: registered-issuer capability token → 200, same-key
  unregistered-issuer token → rejected, anonymous → rejected.
- **`test_audit15b_srr_cache.py`** (3) — closes §B3.15 (SRR × cache): one
  process runs a read-through cache plane and the SRR endpoint whose single
  share IS the cache store; the fill lands, the document is schema-coherent
  for the cache share, and it stays sane after cache activity.

### Tranche 3 — same day, five `tests/test_audit15c_*.py` files, 25 tests

The "deferred, heavier harness" items that turned out to need only local mocks:

- **`test_audit15c_webdav_introspection.py`** (5) — closes §A2 WebDAV token
  introspection live (`brix_webdav_token_introspect_loc/_ttl/_fail_open`,
  `brix_webdav_revoke_cache`): a colocated nginx mock IdP answers
  `{"active": false}` for one exact token. Active bearer passes, revoked is
  403 twice with the second refusal served from the revoke cache (error.log
  "revocation cache hit" pin), no-bearer skips introspection entirely, and a
  dead introspector refuses/admits per `_fail_open`. Template trap worth
  keeping: the introspection subrequest only counts as complete when the
  internal location `proxy_pass`es (completion requires `r->upstream`).
- **`test_audit15c_dashboard_users.py`** (7) — closes §A2 dashboard
  users-file auth (`brix_dashboard_users`, `_cookie_path`, `_session_ttl` and
  the two setter parse-negatives): crypt(3) SHA-512 branch (hash via
  `openssl passwd -6`; Python 3.13 dropped `crypt`) and legacy-plaintext
  branch both log in and open the authed JSON API on a non-default
  cookie_path; wrong password / unknown user get no cookie; a bit-flipped
  HMAC cookie is refused (expiry is pinned by tamper, not sleep — WSL clock);
  malformed users line and the users+password conflict die at `nginx -t`
  (the conflict emerg names whichever directive comes second).
- **`test_audit15c_tpc_token_exchange.py`** (5) — closes §A2 native-TPC
  outbound RFC 8693 token exchange, live against a capturing Python token
  endpoint, full raw-wire rendezvous (source read-open registers `tpc.key` +
  `tpc.dst`, dest write-open with `tpc.token_mode=token-exchange`, sync-arm
  then sync-pull, kXR_waitresp/kXR_attn unwrap). Good endpoint completes the
  pull byte-exact; dead endpoint fails closed (`token exchange failed`, no
  committed dest); a non-JSON token response fails with `kXR_AuthFailed`
  (3030) while proving the endpoint WAS reached. **Defect candidates #1 and
  #2**, both pinned live and both present in the twin
  (`src/tpc/outbound/tpc_token_exchange.c` AND
  `src/protocols/webdav/tpc_cred_exchange.c`):
  1. the argv builder passes `-d <staged-file>` **without the `@` prefix**,
     so the IdP receives the literal `/dev/shm/brix-creds…` staging PATH as
     the POST body — the RFC 8693 `grant_type/subject_token` form never goes
     on the wire (the WebDAV twin's own comment says "for curl --data
     @file");
  2. client credentials go out as three argv words (`"-u", id, secret`):
     curl takes `-u id` with an **empty password** and treats the secret as
     an extra URL — `Authorization: Basic b64("id:")` reaches the IdP with
     the secret absent, the secret string leaks into URL/DNS resolution, and
     because curl exits with the LAST transfer's status the exchange still
     "succeeds". Fix is `@` on `-d` and a single `-u id:secret` argument;
     both pins are written to be inverted then.
- **`test_audit15c_ssi_knobs.py`** (4) — closes §A2 SSI knobs
  (`brix_ssi_cta_journal`, `brix_ssi_cta_executor`, `brix_ssi_request_max`,
  `brix_ssi_response_max`): an archive submit under `executor test` succeeds
  and leaves a non-empty journal; on a caps instance (32/16) a 100-byte
  request bounces with "SSI request too large", a 24-byte echo trips the
  response cap, and an in-cap echo round-trips on the same instance.
- **`test_audit15c_zip_cd_caps.py`** (4) — closes §A2
  `brix_zip_cd_max_bytes` + `brix_webdav_zip_cd_max_bytes` (zip_kernel.c
  bomb guard): a 4-member zip (CD > 64 B) is refused by the capped stream
  listener and capped WebDAV location while uncapped twins serve the member
  byte-exact.

Harness footprint of the three tranches: ledger `tests/fleet_ports_shared_phase5.py`
30548–30577, ladder `tests/port_ladder.py` shared width 534→541→551→564,
templates `nginx_guard_knobs.conf`, `nginx_lc_webdav_macaroon_rotation.conf`,
`nginx_lc_webdav_token_config.conf`, `nginx_srr_cache.conf`,
`nginx_audit15c_introspect.conf`, `nginx_audit15c_dash_users.conf`,
`nginx_audit15c_tpcx.conf`, `nginx_audit15c_zipcaps.conf`. Template-authoring
trap (cost one red run): placeholder substitution is textual and hits
comments too — a multi-line value named in a template comment expands there
and leaks directives into main context.

### Tranche 4 — same day, three `tests/test_audit15d_*.py` files, 13 tests

The tranche-3 reclassification pattern repeated: three residuals filed under
"live externals / blocked" turned out to be locally drivable, and two of them
exposed defect candidates #4 and #5.

- **`test_audit15d_tls_require_tpc.py`** (5) — closes §B1.4
  (tls_require×TPC): test_tls_require.py exercised the login/session/data
  masks and ADVERTISED the tpc bit, but no test had ever presented a
  TPC-role open to a tpc-masked server — the gate in
  `src/protocols/root/read/open_tpc.c` (`brix_tls_gate_refused(...,
  BRIX_TLSREQ_TPC, ...)`) had zero execution. Both roles are now driven:
  cleartext dest-open (tpc.src opaque) and source-arm read-open
  (tpc.key/tpc.dst) bounce kXR_TLSRequired "requires TLS for TPC"; plain
  opens/reads on the SAME masked cleartext session proceed (the
  capability-scoped grain); after the in-protocol TLS upgrade both TPC-role
  opens grant; a no-mask control grants them on cleartext. Reuses
  `nginx_tls_require.conf` (its AUTH_LINES slot carries the TPC knobs; the
  template gained a main-context `thread_pool default` because the pull
  machinery insists on one at prepare time).
- **`test_audit15d_inherit_parent_group.py`** (4) — closes §A2
  `brix_inherit_parent_group` ("custom setter" was no blocker) and found
  **defect candidate #4**: the policy has two consumers, and only one works.
  File create applies it UNGATED on the fresh fd
  (`open_resolved_file_finalize.c`) — a create under the rule prefix is
  chowned to the parent's supplementary gid with file-grain group bits
  (proven against a no-setgid parent, so the kernel can't take credit). But
  kXR_mkdir (`src/protocols/root/write/mkdir.c`) gates the application on
  `brix_vfs_backend_resolve(root_canon) == NULL`, written when a registered
  VFS backend implied a catalog namespace — and phase-68's census
  registration (`vfs_backend_config.c`) now registers EVERY posix export
  (explicit `posix:` and the bare-export default), so the gate never passes
  and directories NEVER inherit; the recursive branch is no better
  (`sd_posix_ns.c` passes NULL rules to the mkpath walker). Same directive,
  same server: files chowned, directories not. Pinned to be inverted when
  the gate keys on backend KIND. Plus the path-scoping negative and the
  relative-rule-path parse refusal. Skips without a supplementary group.
- **`test_audit15d_checksum_stage.py`** (4) — closes the local half of
  §B2.11 (checksum_on_write×stage) and found **defect candidate #5**: the
  ingest checksum does not survive a write-through stage flush. Front
  (WebDAV, `brix_stage on` + `brix_stage_flush sync`, backend = colocated
  WebDAV origin; new `nginx_audit15d_ckstage.conf`): the PUT lands
  byte-exact on the origin and the sync flush drains the spool, but the
  origin copy has an EMPTY xattr list — no `user.XrdCks.adler32` — while
  the identical PUT against a plain posix export persists it
  (test_checksum_on_write.py). The setxattr is attempted (op:"xattr" in
  brix_access_json on the logical export path) but the flush carries bytes
  only and the stage move deletes the spool copy: total loss, not
  relocation. Pinned to invert when the flush propagates the checksum.
  Plus the no-directive control (proving flushes aren't broken generally)
  and a clean 404 through the tier. Harness note: the wire path keeps the
  location prefix, and the flush's origin PUT will NOT create a missing
  parent collection — the origin needs pre-created `/ck` `/plain` dirs or
  every PUT dies 500 "stage move: dest commit failed (EIO)".

Tranche-4 harness footprint: ledger 30578–30583, ladder shared width
564→570, template `nginx_audit15d_ckstage.conf` (+ the `thread_pool` line in
`nginx_tls_require.conf`; its own suite re-verified green).

### Tranche 5 — same day, six `tests/test_audit15e_*.py` files, 26 tests

The tier and cluster crosses — §B2.12, §B2.13, §B2.14, the §B2.11 S3
residual, the §B3.15 cms residual and §B3.16 — all of which had been filed as
"needs a live external" and none of which did. Three more defect candidates
(#6, #7, #8), two of them the same root cause.

- **`test_audit15e_backend_async_tiers.py`** (5) — closes §B2.12
  (backend_async × cache/stage tiers) and found **defect candidate #6**: the
  async backend-op queue cannot delete through a tier. The drain executes
  UNLINK/RMDIR via `brix_vfs_unlink_path`/`brix_vfs_rmdir_path`
  (`src/fs/vfs/vfs_walk.c:319-325` → `brix_unlink_confined_canon()`) —
  posix-confined primitives on the *logical* export path that never consult
  the VFS backend registry — while RENAME alone resolves the driver via
  `brix_vfs_backend_resolve` (`src/fs/xfer/backend_async_queue.c:174`). On a
  tiered/remote export the queued DELETE ENOENTs and WebDAV renders 404
  (`src/protocols/webdav/namespace.c:282-293`) for an object that GETs fine
  before and after and survives untouched on the origin. Pinned in both tier
  shapes (cache and stage), with the sharpest formulation as a pair: async
  MOVE renames *through* correctly on the same location where async DELETE
  404s. Two controls make it a statement about the queue, not the backend —
  the same DELETE on a tiered location with `brix_backend_async off`, and on
  a bare remote export, both return 204 — plus the write-gate negative
  (403 before anything is enqueued). New `nginx_audit15e_async_tiers.conf`.
- **`test_audit15e_uring_tiers.py`** (5, **skipped in this build**) — writes
  §B2.13 (io_uring × cache spool / × passthrough / × staged writer). Both
  halves of the row are covered on one ring-forced stream front (cache
  spool-serve after the origin object is destroyed; a 300 KiB object above
  `brix_cache_max_object` served store-then-serve with no durable spool copy)
  plus the phase-70 whole-object staged writer, with the write-refusal and
  bad-writev-framing negatives. `brix_io_uring on` fail-fasts at boot and the
  "io_uring disk-I/O backend active" NOTICE is waited for, so a silent
  fallback can never pass. **This binary has no liburing**, so all five skip
  on the same needles `test_io_uring_runtime.py` uses ("compiled WITHOUT it"
  / "io_uring is unavailable") — the row is closed *pending a ring-enabled
  build*, not verified. The rest of the template was validated independently
  (`nginx -t` on the rendered config with the two `brix_io_uring` lines
  stripped: rc=0), so the skip hides no config error. New
  `nginx_audit15e_uring_tiers.conf`. **Tranche 9 built the ring and ran it:
  4 passed, 1 failed** — the staged-writer arm is defect candidate #29, and the
  ring is not the cause. Recipe and analysis in tranche 9.
- **`test_audit15e_passthrough_crosses.py`** (3) — closes §B2.14
  (passthrough × stage, passthrough × read_only). Geometry as
  `test_cache_passthrough_planes.py` (`cache_max_object` 4096 /
  `passthrough_max` 1 MiB): on a location that ALSO runs a sync-flush stage
  tier the read geometry is unchanged — 1000 B admitted and cached, 50 KiB
  served with no spool copy, 2 MiB above both caps refused 502 — and a PUT
  through the same hybrid location stages and flushes to the origin
  byte-exact. On a read-only export the passthrough read is unimpaired while
  PUT and DELETE both 403 and the origin object is untouched. No defect: the
  pure-read passthrough path composes with both. New `nginx_audit15e_pt.conf`.
- **`test_audit15e_checksum_s3.py`** (4) — closes the §B2.11 S3 residual and
  found **defect candidate #7**, the same root cause as #6 one layer up:
  `webdav_put_persist_checksums` (`src/protocols/webdav/put_body.c:50-85`)
  re-opens the committed object with `brix_vfs_open_fd(..., root_canon, path,
  O_RDONLY, 0)` — a posix-confined open on the logical path. Over an s3://
  backend no such file exists, the helper returns early, and because it is
  best-effort the PUT still answers 201: the operator-requested adler32 is
  never computed. The landed object carries only the `crc64nvme` the S3
  origin plane records for itself, and no object anywhere in the store
  carries the requested digest (a loss, not a relocation). The /px/ control —
  the *same* directive over a posix export in the *same* server — persists
  `user.XrdCks.adler32` correctly, which makes #7 a statement about the
  backend rather than the directive. Also **defect candidate #8**, found
  while stabilising the file: `webdav_lock_xattr_read`
  (`src/protocols/webdav/prop_xattr.c:238-258`) tolerates every "this backend
  has no xattrs" errno (ENODATA/ENOATTR/ENOENT/ENOTSUP/EOPNOTSUPP/ENOSYS/
  EACCES/EPERM) by declining the advisory probe — but not EIO, which is what
  the remote driver reports, so the PUT is refused 500 (`getxattr lock on "/"
  failed (5: Input/output error)`). It is sticky per worker, so a run sees a
  mix of 201s and 500s; a second face of the same instability appears with an
  nginx `thread_pool` declared, where the PUT takes the aio path
  (`webdav_put_aio_thread`), commits the object and never answers at all
  (attribution proven 4:1 by adding/removing the pool — hence the template
  declares none). Rather than assert a hang, #8 is pinned as a
  characterisation + fail-closed invariant: twelve sequential PUTs, every
  non-2xx is a 500 carrying the EIO signature in `error.log`, every refused
  PUT leaves NO object behind, and at least one write must land. New
  `nginx_audit15e_cks3.conf`.
- **`test_audit15e_srr_cms.py`** (4) — closes the §B3.15 cms residual (the
  cache half landed in tranche 2). A manager instance
  (`nginx_cms_state_server.conf`) plus a data node that both registers with
  it and serves the SRR document over HTTP, so the report is demonstrably
  made BY a mesh member: every case first waits on the member's own
  registration line (`CMS registered with … after N ms (K connect attempt(s),
  profile)`). The document is checked against the member's export
  (`implementation`, share name/path/vos, capacity sums, the endpoint's own
  root:// URL carrying the node's port), stays coherent across mesh + data
  activity (totals stable, timestamp advances, membership still live), and an
  unknown path on the report port is a clean 404. New
  `nginx_audit15e_srrcms.conf`.
- **`test_audit15e_cms_active_member.py`** (5) — closes §B3.16 (cms ×
  proxy_fwd, cms × tpc_outbound). Every cms×* unit in the suite joined nodes
  backed by a plain posix export or by nothing at all (`return ""`); here two
  members with real data roles join one out-of-process manager out of one
  master — a read-only proxy over `root://` and a writable native-TPC
  destination — alongside a TPC source and an origin deliberately kept OUT of
  the mesh so "how many nodes registered" is an exact assertion (the
  registration line is emitted once per node under `ever_logged_in`, and the
  count is asserted `== 2`: the identity gate neither collapses the two
  server blocks nor lets extra workers register duplicates). The proxy member
  serves the origin's bytes over the raw root wire while joined and keeps no
  copy; a native TPC pull lands byte-exact in the destination member's export
  and the membership survives the transfer; a pull whose rendezvous key was
  never armed on the source fails closed with nothing in the export; and a
  write-open on the read-only proxy member is refused without reaching the
  origin behind it. New `nginx_audit15e_cmsact.conf`.

Tranche-5 harness footprint: ledger 30584–30600 (eight entries, including
two `nginx_cms_state_server.conf` managers), ladder shared width 570→587, six
new templates. Harness notes worth keeping: the wire path keeps the location
prefix, so every location needs its parent directory pre-created on the
origin AND its own `brix_export` (tiers are registered keyed by canonical
export root); colocated origin hops need `worker_processes` ≥ 2 (4 for the
s3 and cms-mesh chains, where one request occupies two workers); instance
logs are wiped at teardown, so a test that reads `error.log` must read it
from `Path(ep.prefix)/"logs"` inside the test body; and every export picks up
a `.nginx-xrootd-ckp-recovery.lock`, so "the export is empty" assertions must
exclude dotfiles.

### Tranche 6 — same day, nine `tests/test_audit15f_*.py` files, 72 tests

(70 in the nine new files, plus 2 added to tranche 3's exchange file.)
The tail: the §A2/§B1 rows still filed as "needs a live external or a
multi-cred lab", and the last of the appendix. Same reclassification as
tranches 3–5 — **every one of them was locally drivable** — and nine more
defect candidates (#9–#17). One shared helper module,
`tests/_test_audit15f_helpers.py` (capturing TLS mock source, localhost cert
minting, HTTP drives), keeps the TPC files from re-implementing a mock apiece.

- **`test_audit15f_webdav_tpc_tuning.py`** (9) — closes the §A2 WebDAV
  HTTP-TPC tuning surface: seven directives in `directives_tpc.h`
  (`brix_webdav_tpc_marker_interval`, `_max_streams`, `_low_speed_bytes`,
  `_low_speed_secs`, `_token_client_id`, `_token_client_secret`, `_curl`) had
  zero occurrences anywhere in the tree. Every knob is asserted on the
  **source's** wire (a capturing TLS mock records method/path/Range/
  Authorization), not on the destination's return code. **Defect candidate
  #9**: `brix_webdav_tpc_marker_interval` arms only by accident —
  `webdav_tpc_marker_start()` bare-NULL-checks `conf->common.thread_pool`
  (tpc_marker_start.c:308), and postconfig resolves that field only for a
  SERVER-level `brix_webdav on` (postconfig.c:299-317), which the directive's
  location-only type makes impossible; every other offload site instead calls
  `brix_shared_thread_pool()`, which resolves by name and caches back onto the
  loc-conf (shared_conf.h:534, written for exactly this hazard). So markers
  stay disarmed until an unrelated threaded request warms the same loc-conf —
  both halves pinned (cold location declines to 201, warmed location streams
  markers). **Defect candidate #10**: `brix_webdav_tpc_curl` is
  config-validated (regular file, X_OK, config_merge.c:499) and then never
  used — the only fork/exec'd curl in the WebDAV TPC path hardcodes
  `argv[0] = "curl"` through `brix_subprocess_capture`, whose `execvp`
  PATH-resolves it, so an operator's chosen binary is silently ignored (pinned
  with a recording wrapper that always fails: the COPY still succeeds and the
  wrapper's log stays empty). Plus the WebDAV twin of tranche 3's #2 argv
  defect. New `nginx_audit15f_tpctune.conf`.
- **`test_audit15f_tpc_cred_forward.py`** (4) — closes §A2
  `brix_webdav_tpc_credential_forward` (zero occurrences in the tree). The
  toggle decides whose identity the pull leg uses: on, the caller's raw JWT is
  appended as `Authorization: Bearer` (tpc_copy.c:259); off, the leg is
  anonymous. Off is a **credential-containment** boundary, so it is asserted
  negatively on the source's wire log rather than on a status code. Every
  location authenticates for real (`brix_webdav_auth required` +
  `brix_webdav_token_config`) because `rctx->bearer_token` is set only by
  `webdav_verify_bearer_token` (auth_token.c:332) — under `auth none` both
  settings look identical, which is the trap the file avoids. Also: an
  explicit `TransferHeaderAuthorization` is never overridden, and an
  unauthenticated COPY never reaches the source at all. New
  `nginx_audit15f_credfwd.conf`.
- **`test_audit15f_host_auth_crosses.py`** (10) — closes §B1.9 (host auth ×
  {tls, cache, stage, tpc, cms}, all zero: `brix_auth host` paired only with
  authdb). Host auth is socket trust — the peer's reverse-DNS name against
  `brix_host_allow` — so each cross asks whether some other subsystem's
  plumbing can carry a session past that allowlist. One instance carries every
  plane behind the SAME allowlist plus an out-of-process CMS manager, and every
  drive is raw wire (handshake → protocol → login → auth with credtype "host",
  sec_host.c:50) because the point is what the server decides. TLS upgrade,
  cache fill, staged write, native TPC pull and mesh join all succeed for an
  allowed peer and are refused `kXR_NotAuthorized` for one outside it; a TLS
  session that never sends kXR_auth is gated out (the dispatcher gates on
  auth_done, not logged_in). One fail-closed pin: the destination's pull leg
  speaks only ztn/gsi, so it cannot satisfy a host-auth SOURCE. New
  `nginx_audit15f_hostx.conf`.
- **`test_audit15f_sigver_crosses.py`** (9) — closes §B1.1 (sigver × native
  TPC) and §B1.2 (sigver × substreams). Only a GSI session ever arms a signing
  key, so the reachable half is the POLICY applied to a session that CANNOT
  sign: `brix_security_level` picks the covered opcodes,
  `brix_signing_required` decides refuse-vs-accept-unsigned. **Defect
  candidate #15**: `kXR_sync` — the TPC control op the audit named — is NOT in
  the level-2 (`standard`) set, so the arm/start syncs go unprotected unless a
  site raises to `intense`. The rest: a required-signing destination refuses
  the tpc.dst open while kXR_stat still answers (the gate follows the opcode
  table); with the flag off the pull completes UNSIGNED and says so once per
  connection; a required-signing SOURCE refuses the tpc.src arm so the
  rendezvous never forms; `kXR_bind` is exempt, so a secondary attaches to a
  required-signing plane but every op it sends is refused — the policy is not
  lost across the bind, and a forged sessid is still refused. New
  `nginx_audit15f_sigver.conf`.
- **`test_audit15f_cache_admission_and_staging.py`** (10) — closes the
  appendix residuals `brix_cache_allow_prefix`, `brix_cache_index_cache`,
  `brix_cache_wt_stage_backend`, `brix_cache_wt_stage_block_size` (configured
  nowhere). A cache DECLINE is not an error — the open falls through to the
  source — so every admission assertion is a pair (the client's bytes AND the
  store), which is what makes the finding visible. **Defect candidate #12**:
  the whitelist is a BYTE prefix (`sd_cache_has_prefix()` is an `ngx_strncmp`),
  so `/admitted` also admits the sibling tree `/admittedsecrets` — an operator
  scoping a cache to one directory silently caches every directory whose name
  starts with the same bytes. **Defect candidate #13**: both stage-backend
  config refusals disappear when `brix_cache` is off, because
  `brix_server_validate_cache()` returns early — the staging tree is accepted
  unvalidated and unregistered. **Defect candidate #14**:
  `brix_cache_wt_stage()` has no callers, so the instance those two directives
  build is never consumed.
  Plus the bounded index cache proven to be serving store hits (origin stopped,
  admitted objects still answer, a never-admitted one fails). New
  `nginx_audit15f_cacheadm.conf`.
- **`test_audit15f_cluster_tuning.py`** (8) — closes the appendix's
  manager-side tuning (`brix_cms_load_weight`,
  `brix_dashboard_cluster_stale_after`, `brix_cms_server_tcp_keepalive`,
  `brix_cms_server_tcp_user_timeout`). `brix_cms_load_weight` is a process
  global (`brix_srv_set_load_weight`), so the two arms of the weight cross are
  two nginx processes; fake Python data nodes register over the real CMS wire
  and kXR_locate reads the verdict off the root:// face. **Defect candidate
  #16**: a LOAD heartbeat ZEROES the node's registered free space — the emitter
  writes a bare `[2-byte len][6 load bytes]` blob while the parser walks it as
  a tagged scalar, so `cms_srv_parse_load_free_mb` always returns 0. Plus: the
  two anonymous dashboard faces read the SAME registry through different
  staleness windows (the same live node is fresh through 90s and stale through
  1ms in the same second), the anonymous cluster view redacts host and omits
  port/paths/vnid/stage, and the manager's ACCEPTED socket carries a kernel
  keepalive timer only with the flag on. New `nginx_audit15f_clustertune.conf`.
- **`test_audit15f_cms_node_legs.py`** (7) — closes the node-side half
  (`brix_cms_perf_interval`, `brix_cms_send_timeout`, `brix_cms_tcp_keepalive`).
  Everything the node talks to is in-test Python: a StubManager that records
  every CMS frame, or a **SYN black hole** (a listener whose accept queue is
  already full, so a dial neither completes nor is refused) — the only shape
  that lets a connect deadline expire. A one-shot external load feed goes stale
  after 2× `brix_cms_perf_interval` and the /proc meter takes back over, while
  the same feed at the default 30s is still fresh in the same window; a feed
  line over the 1000 bound is rejected outright and an in-range one clamps to
  100 (a garbled monitor can neither lie about nor wrap the advertised load);
  `brix_cms_send_timeout 400ms` bounds the dial into the black hole so
  `brix_cms_connect_failures_total` climbs while the default 10s leaves it at
  zero. New `nginx_audit15f_cmsnode.conf`.
- **`test_audit15f_macaroon_issue_policy.py`** (7) — closes the appendix's
  `brix_webdav_macaroon_location` and `brix_webdav_macaroon_max_validity`.
  Both are loc-conf, so one server with two locations is the whole cross, and
  every assertion reads the ISSUED token rather than the JSON envelope (a
  macaroon is `[4-hex len]<label> <value>\n` packets under base64url, so the
  `location` packet and the `before:` caveat are plain bytes once decoded).
  The configured location is stamped verbatim and the request's Host never
  appears; the default face derives `scheme://Host`; an absent `validity` is
  issued at the configured maximum (the knob is the default as well as the
  ceiling); a requested PT1H is CLAMPED to 120s while the default face honours
  the same hour in full. One security note: the stamped location is
  **advisory** — only `brix_webdav_token_issuer` pins validation (validate.c),
  so a site cannot mistake it for a fence. **Defect candidate #17**, found by
  this file: a macaroon issued with a SUBTREE `path:` caveat authorises
  NOTHING. `macaroon_apply_path_to_scope` (macaroon_caveats.c:117-160) measures
  the caveat against the token's own root scope `"/"` as a 1-byte prefix and
  then requires `caveat_path[1]` to be `/` or NUL; for `/tight` that byte is
  `t`, so neither the narrow nor the already-narrower branch matches and the
  scope is revoked as DISJOINT (`read=write=create=modify=0`, scopes=0 → 403).
  Confining a delegation to a subtree is the entire point of the dCache
  `caveats[]` API, so the feature is unusable — but it fails closed, so it is a
  broken feature and not a hole. New `nginx_audit15f_macpolicy.conf`.
- **`test_audit15f_acc_group_resolution.py`** (6) — closes the **last two
  names in the 95-directive appendix**, `brix_acc_pgo` and
  `brix_acc_gidretran`, both previously assumed to need a fixture-user lab.
  `brix_auth unix` is the way in: the client simply declares a name
  (loopback-gated, auth.c), so the test authenticates as the account it runs
  as and the acc engine resolves that account's REAL Unix gidlist through NSS
  — which is the input both knobs act on. The authdb grants one path per
  group, so a decision is one kXR_open. Both knobs are process globals, so each
  arm is its own nginx process. By default the primary-group AND
  supplementary-group rules both grant; `brix_acc_pgo on` drops every
  supplementary group while keeping the primary; `brix_acc_gidretran <supp
  gid>` drops exactly that rule, and retranning the PRIMARY gid drops the
  primary rule instead (the skip list is keyed on the gid, not on
  "supplementary") — which is what separates the two knobs. One fail-OPEN
  characterisation: a non-numeric `brix_acc_gidretran` is parsed best-effort at
  runtime (XrdAcc parity) and `nginx -t` accepts it, so a typo skips nothing
  and every group rule keeps granting. Every denial is asserted as errcode
  **3010** (`xrdacc denied`) and never a bare 4003, with a 3011 (`file not
  found`) control, so no arm can pass by reading an absent file. Notes: the acc
  engine is built ONLY under `brix_authdb_format xrdacc` (`brix_acc_init_server`
  returns early for the native format — the first probe denied every `g` rule
  for this reason), and the file skips when the account has no supplementary
  group. New `nginx_audit15f_accgroups.conf`.
- **`test_audit15c_tpc_token_exchange.py`** (+2, tranche 3's file) — closes
  the appendix's `brix_tpc_outbound_scope` on the fifth destination instance.
  A configured scope still exchanges and pulls byte-exact, and then **defect
  candidate #11**: the scope is carried into the staged form body (launch.c →
  `t->token_scope`, `tpc_token_exchange.c` interpolates `&scope=%s`) and dies
  with that body — a consequence of #1 (`-d` without `@`), pinned separately
  because being on the wire is the directive's whole observable contract. A
  site that narrows its exchanged token narrows nothing.

Tranche-6 harness footprint: ledger 30601–30633 (33 allocations across 12
entries), ladder shared width 587→620, nine new templates plus
`tests/_test_audit15f_helpers.py`. Harness notes worth keeping: a directive
that lands in a **process global** (`brix_cms_load_weight`, `brix_acc_pgo`,
`brix_acc_gidretran`) cannot be crossed with two server blocks — the
function-scoped `lifecycle` fixture gives a fresh process per `reason`, which
is the mechanism; a **SYN black hole** (full accept queue) is the only local
shape that expires a connect deadline; and instance directories are wiped at
teardown, so a failing arm has to be reproduced by rendering the template into
a scratchpad and running `objs/nginx -c` by hand. One flake found by running
the whole set together and fixed: the dashboard staleness verdict is
`heartbeat_age_ms > stale_after_ms`, so a 1 ms window is NOT stale during the
millisecond the entry is created — the cross polls for the flip instead of
reading once.

Still open, deliberately: §B2.13's verification (written, but gated on a
liburing-enabled build), the TPC lifetime kill-switches and dashboard
session-TTL expiry (blocked on the WSL clock-backwards issue), the three §B1
rows that need a real delegated identity rather than a mock (§B1.7 authdb ×
delegation / × TPC, §B1.8 krb5 × TLS, §B1.10 macaroon × VOMS), §B3.17
(cvmfs×gridftp, listed for completeness only), and §C. **All of these except
§B2.13 are closed by tranche 8**; §B2.13 was gated on the build, which is an
environment fact rather than a coverage gap — **tranche 9 lifted the gate**, ran
the row, and turned it into defect candidates #29–#31. The clock-backwards
blocker turned out not to apply — the dashboard cookie is a signed timestamp,
so age is a parameter, not a wait.
Two named residuals were documented rather than tested here:
`brix_cms_tcp_user_timeout` / `brix_cms_server_tcp_user_timeout`
(TCP_USER_TIMEOUT is not reported back by any local API the test can read, and
provoking it needs a black-holed connection), and the wire-visible arm of
`brix_tpc_outbound_scope`, which is blocked by defect #11 itself. **Tranche 9
closed the client-leg knob**: a black-holed *connect* — unlike a black-holed
established connection — is reproducible from userspace, and TCP_USER_TIMEOUT
bounds the SYN sequence.

### Tranche 7 — same day, seven `tests/test_audit15g_*.py` files, 41 tests

§C — the rows carried unchanged from the 2026-08-04 pass, which every earlier
tranche had left alone because each one needs a fault injected into a transfer
that is already in flight rather than a configuration crossed with another:

- **`test_audit15g_reload_during_fill.py`** (5) — closes §C "reload during a
  cache fill". A paced Python origin holds the fill open across an `nginx -s
  reload`, so the retiring worker is asked to finish a transfer whose bytes are
  still arriving. **DEFECT CANDIDATE #19**: the reload destroys the retiring
  worker's kXR sessions — the graceful-shutdown path closes connections that
  have an in-flight request, where HTTP's own retiring worker drains.
- **`test_audit15g_unlink_during_transfer.py`** (7) — closes §C "unlink during
  an active transfer", on two planes: a plain posix export (the exported file
  is removed) and a read-cache tier over a root:// origin (the CACHED COPY is
  removed while the origin still holds the truth). Every assertion checks the
  byte count as well as the status, because a short read reported as a complete
  one is the failure that has no client-side symptom. The security negative is
  the PATH SWAP: replacing the path mid-transfer must not change which bytes
  the open handle delivers.
- **`test_audit15g_evict_during_read.py`** (6) — closes §C "eviction during an
  active read". The watermark reaper is the only one that can be aimed
  (`brix_cache_reap_interval` + a high mark = a purge a second), so it is what
  drives the mid-read cases. **DEFECT CANDIDATE #18**: that directive does NOT
  pace the cold/dirty reaper — `brix_cache_reap_handler` re-arms at a
  compiled-in `BRIX_CACHE_REAP_INTERVAL_MS` (3600000), so a site setting
  `brix_cache_cold_max_age 300` gets one sweep an hour whatever it configures.
- **`test_audit15g_sd_http_deadline.py`** (5) — closes §C "sd_http stall". The
  four origin misbehaviours that look identical from outside — 404, connection
  refused, accepted-then-silent, and short body — are pinned to four distinct
  client-visible outcomes, with kXR_NotFound reserved for a real 404 (a client
  told a file does not exist is entitled to act on it destructively). The
  deadline itself can only be measured, not configured: `timeout_ms` defaults
  to `BRIX_SD_HTTP_DEFAULT_TIMEOUT_MS` and no directive reaches it, and the
  three fast-fail curl bounds are left at libcurl's defaults (off).
- **`test_audit15g_tpc_crosses.py`** (9) — closes §C "TPC × cache_store" and
  "TPC × non-posix backend", plus the §B1.7 "authdb × TPC" row. Seven planes in
  one instance, one pull driver aimed by port. **DEFECT CANDIDATE #21**: a
  native TPC destination writes straight to the local filesystem under the
  export root whatever the backend is — `tpc_open_dst_logical`
  (`tpc/engine/launch_prepare.c:355-369`) opens with `brix_vfs_open_fd_at`, the
  raw-fd posix-only door, and the pull thread writes to that bare fd. Measured:
  on a cache-tiered destination the pull reports ok and the tier then answers
  kXR_NotFound for it; on an `http://`-backed destination the origin receives
  zero requests and the client is still told the transfer completed. Also
  pinned, as a rule rather than a defect: a TPC destination open is AOP_CREATE,
  which is `i|r|w`, so the `rlw` an operator would naturally write to permit an
  incoming transfer is REFUSED — the rule has to be `irw`.
- **`test_audit15g_authdb_load_failure.py`** (5) — the tail of §B1.7: what
  happens when the authdb does not parse, which every existing acc test avoids
  by handing the server a valid one. **DEFECT CANDIDATE #20**: a malformed
  `brix_authdb` passes `nginx -t` (the authdb is built per-worker from
  init_process, which `-t` never runs), then every worker exits 2 and cannot be
  respawned while the MASTER keeps the listening sockets — so the plane accepts
  TCP and answers nothing, and a port-probing health check calls it healthy.
  The refresh arm is the counter-example that makes that a defect rather than a
  policy: the same file arriving through the 1-second re-read timer is
  discarded and the last good tables keep enforcing, asserted from both sides
  (the granted path stays granted, the denied path stays denied).
- **`test_audit15g_verify_strict.py`** (4) — closes §C "`--verify` strict
  mode", deterministically and without the fault proxy the 08-04 pass needed.
  Two pins of the same fail-open verdict policy: an unparseable `--cksum` type
  is a usage error, a usage error is UNVERIFIED, and UNVERIFIED is
  warn-and-clear — rc 0 with the file kept; and a stdio destination returns OK
  outright, so `xrdcp --verify src - | consumer` carries a verification flag
  that cannot do anything. Both are indistinguishable from a real verification
  at the only place an automated caller looks. The controls that make that a
  statement about the verdict rather than about checksums: a matching digest
  reports whose it matched, and a definitely-WRONG one exits non-zero AND drops
  the destination.

Cost: 8 new ledger entries (`lc-audit15g-{fill,mtorigin,unlink,evict,sdhttp,
tpcx,badacc,verify}` and their extra planes), ladder shared width 620→640, six
new templates plus `tests/_test_audit15g_helpers.py` (a paced/faulty Python
http origin, an incrementally-read kXR handle, and `wait_until`). Harness notes
worth keeping: an extras key that collides with a REGISTERED SPEC NAME is
silently overwritten by that spec's port, because `_endpoint_template_values()`
merges `{SPECNAME}_PORT` for every registered spec after the instance's own
extras — there is a spec called `authdb`, which is why the tpcx plane's key is
`ACC_PORT`; an xrdacc authdb takes ONE record per identity with repeated
`<path> <privs>` pairs, and a second `u *` line is a duplicate-rule parse
failure; the refresh timer compares mtimes at second resolution, so an edit
must be stamped onto a strictly different second (fixed dates, not `now +
delta` — two writes a fraction of a second apart truncate to the same second);
and `lifecycle.start` runs `nginx -t` before it launches, which is precisely
what makes defect #20 measurable from a test that gets as far as its own body.

One environmental trap cost a bisect and is worth repeating here: a pytest
session's LOCAL-mode teardown `rmtree`s `TEST_ROOT` (`/tmp/xrd-test`), and
`TMPDIR`/basetemp live inside it, so a second session **finishing** deletes a
long run's `tmp_path` trees underneath its live workers. The symptom is a
server reporting ENOENT for files the test just wrote, and a backend that
should never be reached suddenly being reached — while every one of the same
files passes solo and in every pair. Run long sweeps with `--basetemp` pointing
somewhere outside `/tmp/xrd-test`.

Still open after this tranche: the §C rows that were thought to need live
externals or a real delegated identity — TPC × sss (live), TPC × TLS × GSI, and
the WebDAV GSI/delegation *push* leg — plus everything listed as still open
under tranche 6 above. **All of them are closed by tranche 8**, and the premise
turned out to be wrong in every case: see below.

### Tranche 8 — 2026-08-16, ten `tests/test_audit15h_*.py` files, 90 tests

Everything the first seven tranches recorded as "still open" — every row, with
no residual. Three of them had been carried since the 2026-08-04 audit on the
stated grounds that the suite could not stand up the infrastructure; each was
re-examined rather than re-deferred, and in each case the blocker was a
misreading of what the row required:

- **`test_audit15h_tpc_lifetime.py`** (6) — closes the §A2 TPC lifetime
  kill-switches, `brix_tpc_max_transfer_secs` and `brix_tpc_transfer_max_age`.
  The wall-clock cap is untestable against a well-behaved transfer, which is
  why it stayed at zero: it needs a source that keeps delivering bytes far too
  slowly, resetting the 60 s per-recv `TPC_IO_TIMEOUT_SEC` on every read.
  `brix-fault-proxy --rate` in front of an ordinary source produces exactly
  that, so the link never goes idle and only the cap can end it — with the
  identical paced pull *completing* on an uncapped plane as the attribution
  control, and the killed transfer's destination object proven unpublished.
  **DEFECT CANDIDATE #22**: `brix_tpc_transfer_max_age` cannot reclaim an
  abandoned slot until the 1024-entry registry is completely full. The reap runs
  from one place — `brix_tpc_registry_add` after failing to find a free slot
  (`tpc/common/registry.c:290-303`) — and the function written for a timer,
  `brix_tpc_registry_reap_stale()` (its own comment says "intended for a coarse
  timer", `registry.c:218-224`), **has no callers anywhere in the tree**. A
  worker that dies between the pull sync that creates a row (`launch.c:392`) and
  the completion callback that removes it (`done.c:59`) leaks that row forever,
  and the dashboard and metrics report it as an active transfer.
- **`test_audit15h_dashboard_session_ttl.py`** (8) — closes the §A1
  `brix_dashboard_session_ttl` hole. It was blocked on the WSL
  clock-backwards issue only because the obvious test is "log in, wait out the
  TTL": the cookie is `HMAC.<ts>` / `HMAC.<ts>.<user>` keyed on the configured
  password (`dashboard_auth_creds.c:167-191`), so a test that knows the password
  can **mint** a cookie at any age and make the wait a parameter. Two things
  keep that honest: the first case proves a mint at the server's own `now` is
  byte-identical to the product's login cookie, and "now" is read off the
  *server*, out of a real login cookie's timestamp field, never off the test
  host's clock — so nothing here depends on the two clocks agreeing.
- **`test_audit15h_krb5_tls.py`** (9) — closes §B1.8. Every krb5 test in the
  tree runs its acceptor on a plain socket, so nothing asserted that a ticket
  still authenticates after the in-protocol upgrade, nor that a krb5 listener
  can be stopped from doing the AP-REQ in the clear. The missing half was never
  the realm (`kdc_helpers.up()` already provisions a throwaway MIT KDC) but the
  PKI: this file mints a CA and a host cert whose SANs cover `localhost`, so the
  service principal and the verified TLS name are the same host and neither half
  has to be relaxed. Three planes over one realm and one keytab — TLS, cleartext
  and `brix_tls_require all` — hold the line that encryption is not identity.
- **`test_audit15h_tls_upgrade_abort.py`** (6) — **DEFECT CANDIDATE #23**, found
  while wiring the row above. Three frames from an unauthenticated peer (hello,
  `kXR_protocol` with `kXR_ableTLS`, close) crash the worker with SIGSEGV.
  `brix_recv_process_frame` sees `ctx->tls_pending` and calls `brix_start_tls`
  (`recv_process.c:286`); with the peer gone `ngx_ssl_handshake` fails, so
  `brix_start_tls` finalizes the session (`tls.c:75-78`), destroying the pool
  and `ctx` — and the recv loop dereferences the freed `ctx` on the very next
  statement (`recv.c:262`). The guard that would have prevented it is present
  and correct, one line too late. It is a remote pre-auth DoS against every
  session sharing that worker, and it reproduces on a `brix_auth gsi` listener
  with no credential at all. **Fixed in the tree as of 2026-08-16**: `recv.c`
  now returns on `BRIX_RECV_STEP_RETURN` before `brix_shutdown_hold_sync()`
  (`recv.c:261-265`), and the six tests are the regression guard for the fix
  rather than a pin on a live crash.
- **`test_audit15h_authdb_delegation.py`** (10) — closes §B1.7's authdb ×
  delegation. Every `u` rule the suite had ever written was `u *`, so no test
  had asked **which** DN a proxy login is authorized as. The product keys on the
  stable EEC subject rather than the per-mint RFC 3820 leaf
  (`brix_gsi_extract_eec_dn`, `gsi_verify.c:163`), which is the behaviour an
  operator's rule file depends on; this file asserts it from both sides.
  **DEFECT CANDIDATE #24**: the identity that is *counted* is not the identity
  that is *authorized* — `brix_gsi_complete_auth` hands the EEC DN to
  authorization and, four lines later, the proxy leaf to the metrics/session
  identity, so a site's per-user accounting fragments on every re-delegation.
- **`test_audit15h_macaroon_voms.py`** (12) — closes §B1.10. Every macaroon file
  in the tree authenticates its own issuance request with another macaroon: a
  closed loop that never exercises `mac_authorize`'s other caller
  (`macaroon_endpoint.c:156` returns early when `!ctx->token_auth`), which is
  the caller a real site has — an X.509 proxy and a VO attribute certificate,
  no token to start from. **DEFECT CANDIDATE #25**: WebDAV authorizes the proxy
  **leaf** (`webdav_finish_verified_cert`, `auth_cert.c:433`) while root://
  authorizes the **EEC** (`auth.c:81`), against the same `brix_authdb` file —
  so the rule that works on one plane fails on the other, and `access.c:275`'s
  stated "read parity with root://" is broken at the identity.
- **`test_audit15h_tpc_gsi_tls.py`** (11) — closes the §C row *TPC × TLS × GSI*,
  which needed no external at all. The rendezvous key lives in one process-wide
  SHM table with a flat namespace (`src/tpc/engine/key_registry.c`), so the
  source can carry an anonymous ARM face beside its authenticated ones: the
  client registers the key there, the destination consumes it on the face that
  demands both TLS and GSI. That split is the correct isolation rather than a
  workaround — the arm is the client's leg, the credential under test is the
  destination's. Five destinations (`good`/`notls`/`nocred`/`rogueca`/`noca`)
  make every refusal attributable, and every negative asserts twice: the pull
  errors **and** the destination file was never committed.
  **DEFECT CANDIDATE #26**: the outbound GSI leg never verifies the source's
  certificate. `tpc_gsi_verify_server_cert` (`gsi_outbound_exchange.c:82-126`)
  is guarded on `conf->gsi_store`, but `brix_configure_gsi`
  (`auth/gsi/config.c:359-398`) returns early unless the *listener's own*
  `brix_auth` is GSI/BOTH or a protbind rule names GSI — and a TPC destination
  is `brix_auth none`, so `gsi_store` is NULL. The `rogueca` and `noca` arms are
  the measurement.
- **`test_audit15h_tpc_sss.py`** (7) — closes the §C row *TPC × sss (live)* by
  first getting the row right. `grep -r sss src/tpc/` is empty and
  `gsi_outbound_finish.c` selects only `ztn` and `gsi`, so "TPC × sss" cannot
  mean an outbound sss credential: it is the client-facing sss legs plus the
  capability boundary. A destination holding the *same* shared secret as the
  source still cannot pull from it, and the refusal must name a credential that
  would actually work — which it does, by naming
  `brix_tpc_outbound_bearer_file` and `brix_certificate`. Driven from pure
  Python (`_test_sss_helpers.py` mints the keytab, the BF32 credential and the
  `kXR_auth` frame), so it needs no built client.
- **`test_audit15h_webdav_gsi_push.py`** (10) — closes the §C row *WebDAV
  GSI/delegation push leg*. The push leg itself was already covered ten times
  over; what had never existed was a peer that could **say who dialled it**.
  Adding a `log_format` carrying `$ssl_client_s_dn`, plus a destination that
  *mandates* a CA-verified client certificate, turns "which identity did the
  push use" into an assertion. **DEFECT CANDIDATE #27**: credential forwarding
  is silently pull-only. `webdav_tpc_run_curl_push` (`tpc_curl.c:401-413`) hands
  `NULL, NULL` to the client-cred slot and `webdav_tpc_handle_push`
  (`tpc_push.c:277`) calls neither `webdav_tpc_apply_user_proxy` nor
  `webdav_tpc_forward_user_bearer`, both of which the pull path calls
  (`tpc.c:393`, `tpc.c:408`). So a push runs under the source host's **service**
  identity whoever asked for it, `brix_webdav_tpc_credential_forward` (default
  on) is inert on that leg, and `X-Brix-Delegate-Proxy` is still parsed and
  security-checked on a push and then discarded. One user, one proxy, one
  header, two directions against the same DN-logging peer: the pull arrives as
  the user, the push as the service.
- **`test_audit15h_cvmfs_gridftp.py`** (11) — closes §B3.17, the last
  proto×proto pair, by putting an `http{}` CVMFS Stratum-0 handler and two
  `stream{}` GridFTP faces in one worker over **one export root** — which is the
  realistic deployment (bytes in over FTP, bytes out over http) and the only
  arrangement in which the planes can disagree. They do. **DEFECT CANDIDATE
  #28**: the http plane classifies before it opens — `brix_cvmfs_gate`
  (`gate.c:478-489`) rejects any URI that is "not a CVMFS traffic shape" with
  403 before any path resolution — so `keys/<fqrn>.masterkey`, the repository's
  private signing key that `repo mkfs` puts inside the Stratum-0 root, is
  structurally unreachable over http; `brix_gridftp_export` confines the tree
  and nothing else, and hands the same file to an anonymous RETR on the
  read-only face. Nothing warns at parse time and nothing documents a split-root
  requirement. The counter-argument is recorded with the finding: exporting a
  directory over FTP exports everything in it. What makes this different is that
  these two modules are *designed* to be co-hosted on one tree and one of them
  carries an explicit "these bytes never leave" rule the other silently does not
  honour. The file also pins the bound on the hazard honestly — a writable face
  can rewrite a CAS object and the origin serves the new bytes unverified
  (content addressing is the *client's* check), and `repo fsck --data` is what
  catches it.

Two notes for whoever runs this next.

`OpenSSL 3.x turns an IP-shaped verification name into an iPAddress-SAN check`:
`SSL_set1_host()` routes an IP literal to `X509_VERIFY_PARAM_set1_ip_asc()`,
which has **no CN fallback**, so a host certificate without an `IP:` SAN fails
with `X509_V_ERR_IP_ADDRESS_MISMATCH` even when its CN matches. The same applies
to curl against an IP-literal URL with `CURLOPT_SSL_VERIFYHOST 2`. Every host
cert minted in this tranche carries `IP:<host>,DNS:localhost`.

The lifecycle port ladder had drifted: the audit tranches grew
`LIFECYCLE_SHARED_WIDTH` from 534 to 679 but only carried 103 of those 145 slots
through to the lanes below it, so the shared band had been overlapping the
exclusive band by 42 since tranche 7. `test_fleet_ports.py`'s band check caught
it; `port_ladder.py` is now repacked as a running sum of the widths above each
offset, which is the rule that should have been applied all along.

### Tranche 9 — 2026-08-16, the deferred rows and the unranked sections, 3 files + 3 tests, 34 tests

Tranche 8 left the ranked backlog empty. What remained was everything the
document had deferred *by decision* rather than by rank: the io_uring row that
had never executed, the two `tcp_user_timeout` knobs filed as unobservable, and
§D/§E — the two sections that make claims about the tree and had nothing
checking them. All four are now closed or sharpened.

**§B2.13 finally ran, and it fails.** The row was written in tranche 5 and
skipped for three tranches because the test binary has no liburing. The unblock
is a side-build, not a reconfigure of the shared tree (`/tmp/nginx-1.28.3` is
used by every session and by the whole fleet):

```
cp -a /tmp/nginx-1.28.3 <scratch>/uring-build
cd <scratch>/uring-build
BRIX_ENABLE_IO_URING=1 ./configure --with-stream --with-stream_ssl_module \
    --with-http_ssl_module --with-http_dav_module --with-threads \
    --add-module=$REPO --with-cc-opt='-O0 -g' --with-ld-opt='-O0 -g'
make -j$(nproc)
TEST_NGINX_BIN=<scratch>/uring-build/objs/nginx \
    PYTHONPATH=tests pytest tests/test_audit15e_uring_tiers.py -v
```

`./config:193-210` double-gates the ring on `BRIX_ENABLE_IO_URING` at configure
time **and** `pkg-config --atleast-version=2.2 liburing`; this host has 2.12 and
`kernel.io_uring_disabled=0`. Result: **4 passed, 1 failed** — the cache-spool
and passthrough arms are green, the staged-writer arm is not. `kXR_writev` on a
handle the phase-70 whole-object staged writer has just opened for WRITE is
refused `kXR_FileNotOpen` while a plain `kXR_write` on that same handle
succeeds. `test_io_uring_runtime.py` + `test_uring_direct.py` under the same
binary are 5 passed / 1 skipped, so the ring's writev works on a plain export.

- **`test_audit15i_staged_writev.py`** (7) + `nginx_audit15i_stagewritev.conf` —
  the isolation arm: the same topology with **no `brix_io_uring` anywhere**,
  plus a bare posix front as the universality control. It reproduces
  identically, so the finding belongs to `kXR_writev`, not to io_uring.
  - **DEFECT CANDIDATE #29** — `writev_validate_handles`
    (`write/writev.c:136-169`) admits a handle only when
    `ctx->files[idx].fd >= 0`. A descriptor-less tier is exactly what the
    staged writer produces: an `http://` backend advertises no RANDOM_WRITE, so
    a WRITE open accumulates into `brix_stage_dir` and commits one PUT at
    close — there is no local fd to hold. `kXR_writev` is therefore
    unreachable on every such tier, while `kXR_write` works.
  - **DEFECT CANDIDATE #30** — the refusal is not terminal.
    `brix_send_error()` (`response/basic.c:65-96`) ends
    `return brix_queue_response(...)`, i.e. **NGX_OK**, so the caller treats a
    rejected request as handled and the connection continues: one request, two
    responses. The control that makes this a defect rather than house style is
    three lines earlier in the same function — the framing guard answers
    exactly once and drops the link.
  - **DEFECT CANDIDATE #31** — because the rejection is discarded, an
    out-of-range handle index survives it. `BRIX_MAX_FILES` is 16
    (`core/types/tunables.h:197`) and `fhandle[0]` is a byte, so slots 16..255
    index up to 239 entries past the array; the `.fd` read out of that memory
    is what the VFS write then receives. Remotely reachable with one byte. The
    test asserts the refusal and worker survival only, and says why: the
    post-refusal wire behaviour varies run to run (8/8 deterministic second
    frames for in-range slots, 1/6 for `0xff`) because it is unowned memory,
    and a test demanding either answer would be asserting garbage.

**`brix_cms_tcp_user_timeout` is no longer unobservable** (3 tests appended to
`test_audit15f_cms_node_legs.py`). The deferral said no local API reports
TCP_USER_TIMEOUT back — true, `ss(8)` does not print it and there is no
cross-process getsockopt — but the observable is behavioural. TCP_USER_TIMEOUT
bounds a SYN-retransmit sequence, and it does so **even when set after the
non-blocking connect has been issued**, which is precisely where
`connect.c:476` applies it (measured on this host: abort at 3.00 s with the
option, still pending at 20 s without). Hold `brix_cms_send_timeout` at 30 s,
set the knob to 2 s, dial the file's existing SYN black hole, and the only
thing that can end the dial is the kernel:
`brix_cms_connect_failures_total` climbs to ≥2 inside 25 s while the control
arm — same deadline, no knob — is still at zero after 10 s.

Its sibling `brix_cms_server_tcp_user_timeout` **stays deferred, with a sharper
reason**: the accept leg needs unacked outbound data or keepalive probing
against a peer whose kernel has stopped answering, and no local userspace peer
can be made to stop answering (a closed socket RSTs; a SIGSTOPped process still
ACKs from kernel context). It needs a netns with a DROP rule (`unshare -rn`) or
a two-host lab — not another fake node.

- **`test_audit15i_plane_pins.py`** (14) + `nginx_audit15i_cvmfs_write.conf` —
  turns §D's eight dismissals into guards. Every dismissal is a claim about the
  config surface, and it holds only while the construction does; the day
  `brix_io_uring` gains an http twin, §D is quietly wrong and the pair it
  dismissed becomes an untested cross. Parse-tier throughout (render into
  `tmp_path`, run `nginx -t`; no boot, no port, no tracked config touched):
  `brix_auth` refuses both two schemes in one directive and two directives in
  one server; `brix_io_uring`/`brix_data_substreams` are refused on the http
  plane and `brix_webdav_checksum_on_write`/`brix_srr` on the stream plane,
  each with the "directive is not allowed here" diagnostic and a same-value
  control on its own plane; `brix_io_uring on` fails loudly on a ringless build
  naming the rebuild flag (the §B2.13 blocker, as an assertion) while `auto`
  parses anywhere.
  - The **cvmfs dismissal was right for a stronger reason than §D gives**.
    §D cites the read_only force-clear; the actual first-line guard is
    `brix_cvmfs_reject_unsupported` (`cvmfs_module_build.c:97`), which makes
    `brix_allow_write on` in a cvmfs location a hard `nginx -t` EMERG. Staging
    is refused the same way.
  - **DEFECT CANDIDATE #32** (low severity, fail-safe direction) — the two
    guards are ordered so the softer disarms the louder.
    `ngx_http_brix_cvmfs_merge_loc_conf` runs `cvmfs_merge_preamble` (→
    `ngx_http_brix_shared_merge` → `brix_shared_apply_read_only`, zeroing
    allow_write) **before** `cvmfs_merge_cache` → `brix_cvmfs_reject_unsupported`,
    which then sees `allow_write == 0` and stays quiet. So `brix_allow_write on`
    alone is a fatal config error while `brix_allow_write on; brix_read_only
    on;` parses clean — the explicit write grant becomes exactly the "silent
    no-op" the guard's own comment (`cvmfs_module_build.c:94-96`) says it exists
    to prevent. Writes are refused either way; what is lost is the operator's
    error message.
- **`test_audit15i_tier_macro_surface.py`** (10) — closes §E's growth risk.
  §E worked the tier-macro hole around by hand for one measurement; a hand
  workaround does not survive the next directive. Three standing properties
  now: the factory inventory is **closed** (any `#define X(pfx, …)` whose body
  pastes `ngx_string(pfx "…")` must be one of the two known families, and no
  other construct anywhere pastes a directive name together); the hole's shape
  is pinned to the byte (**17 of the 20** generated names have no
  `ngx_string("brix_…")` literal in `src/` — the other 3 are the async triple,
  which the stream plane also declares by hand at `root/stream/module.c:476`);
  and what the hole hides is **live** surface, proven by parsing two of the
  invisible names on both planes. Two further guards: the hand-maintained
  name list in the `http_common.c` call-site comment must still match the macro
  it documents, and all 20 must appear somewhere under `tests/`.
  - **DEFECT CANDIDATE #33** — the hole has already cost documentation.
    `docs/03-configuration/directives.md` names 174 brix directives and misses
    7 of the 20 the macros generate: `brix_cache_cold_store`,
    `brix_cache_global_cas`, `brix_cache_passthrough`,
    `brix_cache_passthrough_max` and the whole `brix_backend_async` triple.
    The 13 that *are* documented are all names a literal scan would have found
    by some other mention; the missing seven are exactly the ones that only
    ever existed as macro expansions. The set is pinned, so documenting one
    fails the test, and so does shipping a new tier directive undocumented.
  - Doc nit, not filed as a defect: `tier_directives.h:9` still says the macro
    "expands to the twelve ngx_command_t initializers". It is 17.

Ledger/ladder: `lc-audit15i-stagewv` (30693 + ORIGIN_PORT 30694 + POSIX_PORT
30695) in `fleet_ports_shared_phase5.py`; `LIFECYCLE_SHARED_WIDTH` 679 → 682
with every offset below it repacked as the running sum. The two new §D/§E files
need no ports at all. Guards green: `test_fleet_ports.py`,
`test_fleet_port_uniqueness.py`, `test_server_registry_lint.py` (32),
`check_template_refs.py`, `check_file_size.py`.

### Tranche 10 — 2026-08-16, the residual and the re-measure, 2 files, 59 tests

Tranche 9 closed every ranked row and left exactly one thing open: a residual
the document had deferred to the environment. Closing it took the environment
the caveat asked for. Then the same §Method that produced §A was re-run against
the tree as it stands, because a *measurement* decays in a way a *list* does
not — and it returned seven names the 08-15 pass never saw.

**The residual is closed: `brix_cms_server_tcp_user_timeout` fires.** The
appendix caveat was right about what the knob needs — "a peer whose kernel stops
answering" — and wrong that it needs a second host. `tests/test_audit15j_cms_server_uto.py`
+ `tests/_test_audit15j_netns_uto_helpers.py` (15) build that peer inside one
`podman unshare unshare -n -m` namespace: manager and node on `lo`, an `nft`
DROP installed on the node's port *after* the session is established, so the
node's kernel goes silent while the process stays alive and the socket stays
open. That is the exact condition the knob exists for and the only one that
distinguishes it from a userspace watchdog. Four arms:

| arm | `..._tcp_user_timeout` | node kernel | result |
|---|---|---|---|
| `kernel` | 3s | DROPped mid-session | torn down at **3.41 s**, `ETIMEDOUT` |
| `control` | unset | DROPped mid-session | still up at the horizon |
| `healthy` | 3s | answering | still up at the horizon (no false positive) |
| `bareint` | 3s, no `nft` | answering | parses and runs; the arity/plane control |

Every arm pins `brix_cms_server_idle_timeout 600s` and
`brix_cms_server_interval 1` so the only thing that can end the session inside
the measurement window is the kernel timer. `control` is what makes the 3.41 s
mean something: same DROP, same traffic, no directive, no teardown. **The §A
appendix now has no caveats left.**

**The §A measurement re-run: 524 → 555 directives, seven at zero coverage.**
§Method steps 1+2, unchanged, against today's tree: the surface has grown by 31
names since 08-15 and the corpus by ~100 files. Seven directives appeared in no
test, lab, chart, or deploy artifact — and in no `docs/03-configuration/directives.md`
row either:

`brix_backend_token_audience_ok` · `brix_backend_token_exchange_client_id` ·
`brix_backend_token_exchange_client_secret` · `brix_backend_passthrough_persist` ·
`brix_idmap_cache_ttl` · `brix_idmap_forbidden_users` ·
`brix_impersonation_broker_user`

`tests/test_audit15j_zero_coverage_stragglers.py` (44) covers all seven at the
parse tier the appendix used — own-plane control, far-plane
`"directive is not allowed here"`, arity, duplicate, and value rejection — and
then applies **§Method step 4**, the supportability check ("the directive/config
field has a runtime consumer, not dead config"). Step 4 fails twice, and the
first failure is a security control that has never been able to work.

- **DEFECT CANDIDATE #34 (security, fail-open) — the backend audience gate
  cannot be turned on.** `brix_backend_token_audience_ok` decides which origin a
  bearer captured at the front door may be replayed to verbatim (phase-70 §5.2 /
  P90-70.9). It is declared in **one** place, `http_common.c:153`, writing
  `ngx_http_brix_common_conf_t.common.backend_token_aud`. Protocol modules do
  not declare it; they receive unified values through
  `brix_http_common_adopt()` → `brix_shared_adopt_unified()`, which copies its
  53 fields **one at a time** — and `backend_token_aud` is not one of them. So
  the value lands in the common module's conf and stays there;
  `brix_proto_deleg_gate_bearer()` reads the protocol conf's copy
  (`deleg_wire.c:63`), which is still NULL, and `brix_token_backend_aud_ok()`
  maps NULL to "no gate configured — passthrough unrestricted"
  (`aud_match.c:45`). The gate is a permanent no-op. That is verbatim the
  failure `aud_match.c`'s own header says it was written to end — "the directive
  was parsed but never enforced — a silent fail-open" — reintroduced one config
  layer up, in the adopt list.
  - Proven **live**, because a missing adopt has no diagnostic: one cleartext
    WebDAV export (`nginx_audit15j_audgate.conf`) with two locations differing
    *only* in whether the directive is present. A token audienced for the
    gateway and nothing else — precisely what the gate exists to stop — reads
    **200 from both**, and the refusal line (`aud_match.c:85`, INFO, with the
    export at `error_log info`) never appears. The control that stops that
    silence from meaning "the token path is broken" is the front-door audience
    pin on the *same* export, which rejects a wrong-`aud` token with **401**:
    same claim, same request, enforced at the front door and inert at the back.
  - **Four more fields have the same adopt gap** — `backend_sss_keytab`,
    `backend_sts_flavor`, `seccomp`, `verify_write` — but each is *also*
    declared in the stream plane's own tables, so for those the gap costs the
    http plane only (`brix_verify_write on` in a WebDAV location cannot reach
    the field `put_setup.c:347` reads). `backend_token_aud` is the only one with
    no second declaration anywhere: unreachable on both planes. The pin is
    written as a **class guard** — parse `brix_http_common_commands[]` for every
    `common.*` offset and diff it against the `BRIX_ADOPT_*` lines — so a sixth
    omission fails the day it is added, not the day someone notices.
  - **`verify_write`'s half of that prediction is now measured** (tranche 16,
    file 8 §C): three WebDAV locations differing only in `brix_verify_write`
    on/off/absent, against an `http://` origin that flips the first byte of what
    it stored, all answer PUT 204 and hand the corrupted body back — and the
    origin sees `HEAD` then `PUT` and is never re-read, so no read-back verify
    happens on any arm. That is the first behavioural evidence for any member of
    this class; `test_audit15j_zero_coverage_stragglers.py` remains its owner and
    file 8 pins that ownership rather than minting a number of its own.
- **DEFECT CANDIDATE #35 (dead config) — `brix_backend_passthrough_persist` has
  no runtime reader.** It parses, merges and adopts, and every mention in
  `src/ shared/ client/` is plumbing: command entry, struct field, unset init,
  merge, `BRIX_ADOPT_VAL`. The documented behaviour (spilling a captured full
  proxy into the async stage journal owner dir, phase-70 §5.1) is not
  implemented. Same shape as #14.
- **Not a defect, pinned as a fact:** the three impersonation knobs write a
  *process-global* settings block (`lifecycle.c:42`; the file's own header says
  "there is at most one broker per nginx instance") through setters that discard
  `conf` entirely (`(void) conf;`, `lifecycle.c:101/125`) — while their command
  entries advertise `NGX_STREAM_SRV_CONF`. The observable tell is that a
  duplicate parses clean where every `ngx_conf_set_*_slot` directive would say
  "directive is duplicate". Two stream servers cannot hold different values;
  the test says so, and notices if that ever changes.

Re-running §Method steps 1+2 after this file lands returns **zero** zero-coverage
directives across all 555.

Ledger/ladder: `lc-audit15j-audgate` (30696) in `fleet_ports_shared_phase5.py`;
`LIFECYCLE_SHARED_WIDTH` 682 → 683 with every offset below it repacked as the
running sum (`PORT_COUNT` 1962 → 1963). The netns file needs no ledger port —
it binds inside its own namespace. Guards green: `test_fleet_ports.py`,
`test_no_hardcoded_hosts.py`, `check_template_refs.py`, `check_ports_doc.py`,
`check_file_size.py`.

### Tranche 11 — 2026-08-16, §Method step 3 re-run at the granularity it declared, 1 file, 42 tests

Tranche 10 re-ran §Method **steps 1+2** (the directive surface) and found the
list had decayed. Step 3 — the pairwise co-occurrence matrix — was not re-run.
Re-running it does not just find new gaps; it finds that some of the old
**non-gaps were an artefact of the unit**, which is a different and worse class
of error than a stale list.

§E says so itself, and stops one sentence short:

> Unit granularity is per-file; a pair counts as co-tested even if the two
> features sit in different server blocks of one conf. Zero counts are
> therefore *conservative* — every zero really is a zero.

True, and the corollary is not drawn: **the non-zero counts are not
conservative.** Step 3's declared semantics are "one server instance runs both
features at once". Scored per file, a pair reads "covered" the moment its two
markers appear anywhere in one `.conf` — including in two `server {}` blocks
that never share a request, a listener, or a merge.

**Measured both ways over the same corpus: 1784 file units vs 2467 server
blocks, and 24 pairs are scored co-tested per file that no single server block
in the tree runs.** Two method details decide that number and both were got
wrong first:

- Block granularity brace-matches `server { … }` after stripping
  `{PLACEHOLDER}` tokens — templates otherwise unbalance the count — and a
  fragment file with no `server` block falls back to the whole file, so the
  figure is generous rather than alarmist.
- **A block's markers must include the `http {}` / `stream {}` context around
  it.** nginx inherits srv- and loc-scope directives declared outside a server
  block into every server block in the file, so reading only the block body
  invents gaps: `brix_cache on` at http level really *is* co-resident with a
  posix backend declared in a location below it. The first cut ignored
  inheritance and reported **45** pairs; modelling it removes **21** of them as
  artefacts of the measurement, `store:posix × store:stage` (6 files) at the
  head. 24 is the number that survives.

The survivors are headed by one cluster — the S3 plane's security options,
eight of the 24 — which is also the cluster where the answer matters most,
because CLAUDE.md INVARIANT 6 ("S3 SigV4 ≠ WLCG token auth") makes "what
happens when the wrong plane's security directive is written on an S3 export?"
a question with a security answer:

| pair | files | blocks |
|---|---|---|
| `auth:token × proto:s3` | 11 | 0 |
| `auth:macaroon × proto:s3` · `proto:dashboard × xfer:tpc_webdav` | 3 | 0 |
| `auth:macaroon × auth:s3sigv4` · `auth:s3sigv4 × sec:readonly` · `auth:s3sigv4 × store:cksum_w` · `proto:s3 × sec:readonly` · `proto:s3 × store:cksum_w` | 1 | 0 |

**Caveat on the method, not on the finding.** This document never enumerates
step 3's marker set, so the 39 markers used here are *reconstructed*, and each
regex was checked to fire on a named file before it was trusted. The
re-measurement is therefore evidence that the granularity artefact exists and
where it concentrates — not a byte-faithful replay of the 08-15 matrix. That is
also why the inheritance correction above is reported rather than quietly
applied: a co-occurrence matrix is a *program*, and this one was wrong on its
first run in the direction that flatters the person writing tests. Everything
below was confirmed against the source and against a running server; no pair is
called a gap on the matrix's word alone.

`tests/configs/nginx_audit15k_s3cores.conf` is the missing server block: one
cleartext listener, seven locations — control, read-only in both directive
orders, the four wrong-plane WebDAV directives, `brix_s3_token`, the XrdAcc
tier, and the dashboard face. `tests/test_audit15k_s3_coresidency.py` (42) is
what it answers. Three of the four security options behave three different
ways.

- **`brix_read_only` is wired on this plane, and order-independent.** A signed
  PUT and DELETE both read 403 `AccessDenied` "Write access is disabled."
  whether the directive is written before or after `brix_allow_write on` —
  `brix_shared_apply_read_only()` runs at the *end* of the merge and forces
  `allow_write = 0`, so the four gate sites (`handler_object_route.c:152,202,239`,
  `handler.c:171`) never see the grant. The two orders are compared to each
  other, not just asserted separately: a merge-order dependency here would be a
  security bug that reads like a typo.
- **DEFECT CANDIDATE #36 (security, silent no-op) — four WebDAV security
  directives parse inside an `brix_s3 on` location and enforce nothing.**
  `brix_webdav_auth required` (with `_token_jwks` / `_issuer` / `_audience`),
  `brix_webdav_macaroon_secret`, `brix_webdav_checksum_on_write` and
  `brix_webdav_tpc` are all `NGX_HTTP_LOC_CONF`, so nginx accepts them anywhere;
  all four write into `ngx_http_brix_webdav_loc_conf_t`
  (`module_commands.c:221/287/354/433`) and **no S3 translation unit references
  that type or that module at all**. The operator writes "auth required" on an
  S3 export, gets no warning at parse, at merge or at request time, and the
  export is authenticated by the access key alone. Proven live per directive:
  the `auth required` arm serves a signed GET **and** a signed PUT with no
  token; the `adler32` arm writes an object whose xattr set is byte-identical
  to the control arm that configures no checksum at all (the S3 plane picks its
  own digest per request, `checksum.c:46/55`, default crc64nvme).
  - **Fail-closed, not fail-open**, and the tests say so with controls rather
    than leaving it implied: a bearer alone is refused on that arm exactly as on
    `/plain/`, the macaroon-mint POST gets the S3 gate's 403, and the TPC `COPY`
    gets 405 from the S3 dispatcher. The cost is not a bypass — it is that a
    config which reads as defence in depth has none of the second layer, and
    `brix_s3_token on`, which would have provided it, is silently not what was
    written.
  - The structural pin is the durable half: a guard that fails the day
    `src/protocols/s3/` gains a reference to the WebDAV loc-conf, plus one
    assertion per directive anchored on its `ngx_command_t` initializer, so a
    rename fails loudly instead of passing vacuously.
- **DEFECT CANDIDATE #37 (security, unusable control) — the S3 XrdAcc principal
  is always empty, so per-access-key rules can never match.** `s3_acc_check()`
  takes the name from `brix_identity_dn_cstr(id)` (`handler.c:87`, whose comment
  claims "S3 access key (or subject)"), while the SigV4 verifier stores the key
  id with `brix_identity_set_subject(…, comp->akid, BRIX_AUTHN_S3KEY)`
  (`auth_sigv4_verify.c:313`) — and that setter writes `id->subject` only
  (`identity.c:249-263`). Every signed request is authorized as an anonymous
  principal. With an authdb carrying both rule shapes, `u * /acc/pub rl` grants
  the read and `u AKIAAUDIT15K /acc/keyed rl` denies it, on a request signed by
  exactly that key and verified; the audit line reads `xrootd authz: @<host>
  deny read "/acc/keyed/seed.txt"` with nothing before the `@`. Fail-closed and
  unusable: an operator restricting one key to one prefix gets a deny-all
  export, with an audit trail that names no one.
- **DEFECT CANDIDATE #38 (dead branch) — the INVARIANT 6 "both credentials
  present" rejection cannot fire.** `s3_sigv4_bearer_intercept()`
  (`auth_sigv4_verify.c:158`) derives `has_bearer` and `has_sigv4` from the
  *same* `get_header(r, "authorization")` value, so its 400 needs one header
  that begins with both `Bearer ` and `AWS4`. The reachable shape of that
  conflict is a **presigned** URL — whose credentials live in the query string,
  `X-Amz-Signature` being the presence test (`auth_sigv4_parse.c:301`) —
  carrying a Bearer header: a request with a valid token and a deliberately
  bogus `X-Amz-Signature` is served **200**, the signature material never
  examined and the conflict never reported.
- **Not a defect, pinned as a fact:** the dashboard's route table is
  URI-absolute (`module_dispatch.c:76-85`), so its co-residency with S3 is
  prefix-sensitive — mounted at `/brix` it answers beside six exports that all
  refuse unsigned requests, without inheriting their signature gate and without
  accepting a signature as a login; mounted anywhere else it 404s, which would
  read as a co-residency failure and is not one.

**Re-running step 3 with the file in place: 24 → 16.** All eight of the S3
cluster close and no new pair opens. The remaining 16 at the end of this
tranche — tranche 12 below takes the http-plane eight of them:
`proto:gridftp × store:posix` (4) ·
`store:passthru × store:posix` (3) · `proto:srr × store:posix` (3) ·
`proto:tap_proxy ×` {`sec:tls`, `proto:webdav`} (2 each) ·
`proto:dashboard ×` {`store:httpbe`, `store:cache`} (2 each) ·
`proto:cvmfs × proto:dashboard` (2) · `store:httpbe × xfer:cms` ·
`proto:tap_proxy × sec:readonly` · `proto:srr × store:cache` ·
`proto:s3 × proto:tap_proxy` · `proto:gridftp × xfer:cms` ·
`proto:gridftp × proto:root` · `proto:cvmfs × store:posix` ·
`auth:authdb × store:httpbe` (1 each). They are *not* the same claim as a §B
row: each was recorded as covered by the 08-15 pass and is covered only
per-file, so each needs a server block before it can be called tested — and
each needs the triage this tranche's own first cut earned, since a two-block
topology can be the *correct* design (a tap proxy in front of an origin) rather
than a gap.

Ledger/ladder: `lc-audit15k-s3cores` (30698) in `fleet_ports_shared_phase5.py`;
`LIFECYCLE_SHARED_WIDTH` 684 → 685 with every offset below it repacked as the
running sum (`PORT_COUNT` 1964 → 1965). Guards green: `test_fleet_ports.py`,
`test_no_hardcoded_hosts.py`, `test_fleet_declares.py`, `check_template_refs.py`,
`check_ports_doc.py`, `check_file_size.py`.

### Tranche 12 — 2026-08-16, the other eight of the 16: the http-plane storage element in one block, 1 file, 38 tests

The S3 cluster was the half of the backlog where the answer was a security
answer. The http-plane cluster is the half where the answer is an *operations*
answer, and it is the more embarrassing omission of the two, because the eight
pairs together describe the single most ordinary deployment this product has:
**a listener that serves its data, reports on itself, and carries an admin
face.**

    proto:srr × store:posix · proto:srr × store:cache · proto:cvmfs × store:posix
    proto:cvmfs × proto:dashboard · proto:dashboard × store:cache
    proto:dashboard × store:httpbe · store:passthru × store:posix
    auth:authdb × store:httpbe

Nothing exotic is missing here. What was missing is that the SRR document, the
cache tiers it reports on, and the dashboard that reads their counters had
never been in the same `server {}` — so every one of those three components was
only ever asked about a *fixture*, never about the server it was mounted in.
Three of the six defects below exist precisely in that seam and could not have
been seen any other way: a report about a neighbouring tier, a panel about a
neighbouring tier, and an authdb about a neighbouring tier are all things that
look right until the neighbour is yourself.

`tests/configs/nginx_audit15l_httpcores.conf` is that deployment. One subject
block on `{PORT}` carries the SRR document (two shares: the posix export and
the cache store below it), `/posix/` over a local posix backend, `/cache/` and
`/pt/` over a **remote** origin — the second server block in the same nginx,
which is what makes `store:httpbe` real rather than declared — `/acl/` over
that same origin behind XrdAcc, and `/brix`. A second subject block on
`{CVMFS_PORT}` carries the CVMFS face over a posix repo with its own cache
store, its own SRR document and its own dashboard.

Two structural facts shape the file and both are pinned rather than assumed:

- **One brix protocol per listen port.** `brix_http_proto_exclusive_check()`
  (`proto_exclusive.c:265`) aggregates the protocol mask of *every* server bound
  to a port and fails `nginx -t` if more than one bit is set. So
  `proto:cvmfs × proto:webdav` is not a coverage gap but a design rule, and the
  CVMFS face needs its own listener. The guard-negatives assert the rejection,
  assert that the dashboard is exempt (it is not in the protocol registry), and
  assert that the check aggregates across blocks rather than within one — all
  three against a `tmp_path` copy, never the tracked config.
- **Per-location `brix_export` is what separates two cache tiers in one
  server.** The tier is registered in the VFS backend registry keyed by the
  canonical export root
  (`vfs_backend_config.c::brix_vfs_backend_config_cache_store`), so `/cache/`
  and `/pt/` sharing a root would share one tier — `/cache/` would silently
  inherit passthrough and the control for #40 would evaporate. One test buys the
  same object through both prefixes and reads the two stores' key sets.

Splitting the matrix's own unit also has a self-referential trap, and this
tranche walked into it: a *file* that mixes CVMFS with SRR and with an authdb
scores those pairs co-tested at file granularity, so writing this file created
two fresh gaps (`proto:cvmfs × proto:srr`, `auth:authdb × proto:cvmfs`) at the
moment it closed eight. The re-run after the first draft showed 10, not 8. Both
are carried inside the CVMFS block itself — the second SRR document and an
authdb on `/cvmfs/` — and the second of them is #44.

- **DEFECT CANDIDATE #39 (reporting, over-statement) — the SRR site capacity
  double counts shares that share a filesystem.** `srr_share_usage()` statvfs's
  each configured share path and `srr_emit_capacity()` sums the results
  (`builder.c:350`) with no `st_dev` dedup. The deployment in this file — a
  posix export and a cache store on one disk, which is the ordinary small-site
  shape — reports `storagecapacity.online.totalsize` as **exactly 2×** the
  filesystem: measured ratio 2.00 against `statvfs`, with both shares resolving
  to one `st_dev`. Every share is individually correct, which is why this
  survives review; the total is what WLCG accounting reads.
- **DEFECT CANDIDATE #40 (availability) — on an HTTP backend a cache-admission
  decline is fatal to the request.** `brix_http_fill_resolve_waiter()` maps
  `NGX_DECLINED` to `NGX_HTTP_BAD_GATEWAY` (`http_cache_fill_worker.c:104`), so
  an object that exists at the origin, is readable, and is merely larger than
  `brix_cache_max_object` answers **502** — unreachable through this server. The
  same policy word on a `root://` backend does the opposite: `sd_cache_open_
  common()` falls through to the source and serves the bytes, pinned already by
  `test_audit15f_cache_admission_and_staging.py` ("a decline is not a failure").
  The control is one directive away in the same config: `/pt/` serves the
  identical object 200. So a cap intended to bound the **store** silently bounds
  the **export**, and the recovery is off by default and capped separately.
- **DEFECT CANDIDATE #41 (security, detection without enforcement) — a tampered
  CVMFS CAS object is served with 200 while the fill path quarantines it.**
  `brix_cache_verify_cvmfs_cas()` (`verify.c:264`) does the right check — the
  served bytes do not sha1 to the 40-hex name — and logs `cvmfs-cas verify
  FAILED … object was quarantined, client will retry` with `signal=cvmfs_tamper`.
  But verification is a **fill-time** filter, not a serve-time gate: on a
  posix-backed repo the read is answered from the source, so the client already
  holds the bytes the verifier just rejected, and the diagnostic's "client will
  retry" is false. The test asserts both halves — the detection *and* the
  delivery — so a fix flips one assertion and leaves the other standing.
- **DEFECT CANDIDATE #42 (observability, blind panel) — the dashboard's cache
  telemetry is root-protocol-only.** `srv->cache_enabled` is assigned in exactly
  one place in the tree, `protocols/root/connection/handler.c:333`. No HTTP-plane
  unit sets it, and both `dashboard_fill_cache()` and the Prometheus cache
  families (`stream_cache.c:83/118/152/195`) gate on it. With two WebDAV cache
  tiers in the same block actively filling, evicting and being read, the panel
  reports `cache.enabled=false` with an empty `listeners` array — no occupancy,
  no eviction counters — while the storage census two keys away lists those very
  tiers. This is the pair `proto:dashboard × store:cache` in one sentence, and it
  is why the pair mattered: the panel was only ever pointed at a root listener.
- **DEFECT CANDIDATE #43 (security, directive that does nothing) —
  `brix_dashboard_anonymous on` is a no-op unless a credential is also
  configured.** `ngx_http_brix_dashboard_check_auth()` returns `NGX_OK` for every
  request when no password or users file is set (`auth.c:232`, "No password
  configured — dashboard accessible without auth"), so `redact` stays 0 and the
  unauthenticated caller receives the full admin payload — export roots, listen
  ports, origin host and port — with the payload's own `anonymous` flag reading
  **false**. An operator writes the directive to *downgrade* anonymous viewers to
  the redacted tier and gets the opposite, with nothing at parse time to say so.
- **DEFECT CANDIDATE #44 (security, silent no-op) — `brix_authdb` on a CVMFS
  export is parsed and never consulted.** `src/protocols/cvmfs/` contains no
  reference to the acc tier at all: the gate is called by the root plane
  (`open_request_resolve.c`, `mv.c`, `locate.c`, …), by gridftp
  (`ftp_ev_path.c:115`), by WebDAV (`module_acc_directives.c`) and by S3
  (`s3_acc_check`) — and by nothing under `protocols/cvmfs/`. The same authdb
  file that denies `/acl/priv` on the other listener denies nothing here: every
  repo path is uncovered by any rule, which is XrdAcc for *deny*, and every one
  is served 200 with no audit line. Unlike #36 this is not fail-closed behind a
  second gate — CVMFS is anonymous by default — so an operator who restricts a
  repo with path rules gets no restriction whatsoever, and `nginx -t` is silent.
  A structural test walks `src/protocols/cvmfs/` for any authz call site so the
  pin fails the day one appears.

Three findings are recorded as **facts, not defects**, because each one reads
like a bug from inside a single listener:

- The dashboard's storage census is **process-wide** — it reads the VFS backend
  registry, not the server block — so the CVMFS listener's admin face lists the
  WebDAV block's exports. Documented scope, but a reader of one listener's
  dashboard should know it, and only a two-block config can show it.
- The cvmfs panel's `enabled` is **inferred from traffic**, not from config
  (`api_cvmfs.c:163`): a freshly started CVMFS listener reports `false` until it
  answers one request. The test asserts idle-`false` then request-`true`, which
  is the exact opposite shape to #42 and worth contrasting on the page.
- `proto:cvmfs × proto:webdav` is the design rule above, closed with a rejected
  config rather than left as an omission.

**Re-running step 3 with the file in place: 16 → 8.** All eight of the
http-plane cluster close, and the two pairs the file itself created close with
them. The remaining 8 fall into exactly two clusters:
`proto:gridftp × store:posix` (4 files) ·
`proto:tap_proxy ×` {`sec:tls`, `proto:webdav`} (2 each) ·
`store:httpbe × xfer:cms` · `proto:tap_proxy × sec:readonly` ·
`proto:s3 × proto:tap_proxy` · `proto:gridftp × xfer:cms` ·
`proto:gridftp × proto:root` (1 each). Both clusters need the triage tranche 11
demanded before any of them is called a gap: a tap proxy in front of an origin
is a *two-block topology by design*, and the gridftp four may be the same shape
— the question to answer first is whether a single listener can serve gridftp
and root at all, not whether some file already mentions both.

**Corrected in tranche 13: the real remainder was 6, not 8.** Two of the pairs
listed above cannot exist — `proto:tap_proxy × proto:webdav` and
`proto:s3 × proto:tap_proxy` — because `brix_tap_proxy` is
`NGX_STREAM_SRV_CONF`-only while `brix_webdav` and `brix_s3` are http-only. The
matrix script had `proto:tap_proxy` on the wrong plane, so it paired the proxy
with two protocols it can never be written beside. The fix is in the script's
plane table; the correction is recorded here rather than applied silently, and
tranche 13 pins the plane split from both directions with `nginx -t`.

Also settled in this tranche: **DEFECT CANDIDATE #23 is fixed in the tree.**
`recv.c:261-265` now returns on `BRIX_RECV_STEP_RETURN` before
`brix_shutdown_hold_sync()`, so abandoning an armed in-protocol TLS upgrade no
longer touches the freed connection. `test_audit15h_tls_upgrade_abort.py` keeps
its six tests and changes role — from a pin on a live UAF to the regression
guard for the fix — and its header now says so.

Ledger/ladder: `lc-audit15l-httpcores` (30699, extras `ORIGIN_PORT` 30700 and
`CVMFS_PORT` 30701) in `fleet_ports_shared_phase5.py`; `LIFECYCLE_SHARED_WIDTH`
685 → 688 with every offset below it repacked as the running sum (`PORT_COUNT`
1965 → 1968). Guards green: `test_fleet_ports.py`, `test_no_hardcoded_hosts.py`,
`test_fleet_declares.py`, `check_template_refs.py`, `check_ports_doc.py`.

### Tranche 13 — 2026-08-16, the last six, all stream-plane: 1 file, 34 tests

**First, the measurement.** Tranche 12 ended by naming 8 pairs; the real number
was 6. `proto:tap_proxy` was scored on the http plane by the matrix script, so
it was paired with `proto:webdav` and `proto:s3` — combinations that cannot be
written, because `brix_tap_proxy` is `NGX_STREAM_SRV_CONF`-only and both of the
others are http-only. That is the second time this pass's own instrument has
been the finding (tranche 11's inheritance bug was the first), and it is
recorded the same way: corrected in the open, with two `nginx -t`
guard-negatives that make the plane split a test rather than a claim —
`brix_webdav` inside `stream {}` and `brix_tap_proxy` inside a `location {}`
are both refused by name.

What genuinely survived is entirely stream-plane, and unlike the two http
clusters it is not one deployment but two questions asked six ways:

    proto:tap_proxy × sec:tls · proto:tap_proxy × sec:readonly
    proto:gridftp × store:posix · proto:gridftp × proto:root
    proto:gridftp × xfer:cms · store:httpbe × xfer:cms

`tests/configs/nginx_audit15m_streamcores.conf` runs all six in ONE nginx —
seven server blocks, six stream and one http: a writable posix origin; the tap
proxy that fronts it carrying a TLS identity, a read-only policy AND a remote
storage backend; a gridftp door carrying root-plane storage and a CMS client
leg; the mirrored block that writes the same two protocol directives the other
way round; an http-backed root data server that is also a cluster member; and
the manager's two faces (`brix_manager_mode` on a root listener,
`brix_cms_server` on its own port, because that directive replaces the stream
handler for its whole block).

The tranche-11 triage question — *is this pair a gap or a two-block topology by
design?* — has a different answer here than the S3 cluster's. Every one of the
six is writable in a single block, `nginx -t` accepts all six, and the server
starts. That is the finding: **the stream plane accepts co-residency it cannot
honour, and says nothing.**

- **DEFECT CANDIDATE #45 (configuration, silent shadowing) — two brix protocols
  on one stream listen port are accepted and resolved by declaration order.**
  The http plane refuses that shape by name:
  `brix_http_proto_exclusive_check()` (`proto_exclusive.c:265`) aggregates the
  protocol mask of every server on a port and fails `nginx -t` with "one brix
  protocol per port". The stream plane has no equivalent. Three modules assign
  `cscf->handler` from their own directive setter —
  `core/config/server_conf.c:365` (root), `protocols/gridftp/ftp_module.c:54`
  (gridftp), `net/cms/server_module.c:126` (cms) — and nothing arbitrates, so
  the LAST directive written owns the port and the loser vanishes: no
  diagnostic at parse time, none at runtime, and no clue in the config. The
  file runs both orders side by side. `brix_root on` then `brix_gridftp on`
  greets with "220 BriX GridFTP Gateway ready" and the root export on that port
  answers *nothing* — an xrootd handshake sent to it is eaten by the FTP
  command parser and times out. Reverse the two lines and the same eight
  directives produce a root data server with no door at all. An operator
  reading either block would say the listener serves both.
- **DEFECT CANDIDATE #46 (security, fail-OPEN) — `brix_read_only on` is not
  enforced on a tap-proxy listener.** `brix_shared_apply_read_only()` forces
  `allow_write` off so that "EVERY existing write gate … rejects writes at the
  protocol edge" (`shared_conf.h:135-144`), and the startup banner duly
  announces `root:// endpoint ready — export "/" (read-only)`. But the proxy
  diversion runs first: `if (conf->proxy.enable && ctx->login.auth_done) return
  brix_proxy_dispatch(...)` (`dispatch.c:94`) hands the opcode to the upstream
  before `brix_dispatch_require_write()` (`dispatch_write.c:159` →
  `policy.c:188`) is ever reached. Through the read-only proxy an open-new
  succeeds, the write lands on the origin's disk, `mkdir` creates the
  directory, and `rm` **deletes the origin's file** — every one of them kXR_ok,
  and the proxy's own tap log records the mutation crossing the listener that
  was supposed to stop it. The control is in the same nginx: the mirrored block
  carries `brix_allow_write on; brix_read_only on;` on storage it serves
  itself, and refuses all three with "this is a read-only server". A site that
  fronts a writable origin with a "read-only" proxy — the standard shape for a
  read-only cache in front of a writable SE — is publishing a delete-capable
  endpoint.
- **DEFECT CANDIDATE #47 (clustering, protocol mismatch) — a gridftp door that
  carries a CMS client leg is registered as a data server, and the manager
  redirects xrootd clients to it.** The door logs `cmsd role: this node is a
  client (listen :<door port>)` and joins like any other member; from then on
  every `kXR_dirlist`, `kXR_open` and `kXR_locate` the manager receives for the
  namespace that door registered comes back kXR_redirect naming that port — 24
  of 24 answers once the two members hold disjoint namespaces. The client that
  obeys the redirect is greeted with "220 BriX GridFTP Gateway ready" and can do
  nothing with it. Nothing at parse time or at join time asks whether the
  advertised endpoint speaks the protocol the cluster redirects — and because
  manager mode never serves data itself, there is no fallback that would mask
  it. The control sits beside it in the same cluster: a path in the *other*
  member's namespace is placed on that member, every time. Selection is doing
  its job; the registration is what is wrong.

Five answers that are facts rather than defects, pinned so they cannot drift:

- **The gridftp namespace is disjoint, not overlaid.** A door reads
  `brix_gridftp_export` and ignores the `brix_storage_backend` written beside
  it: the decoy tree the root plane points at is invisible over FTP
  (`MLST /decoy.txt` → 550) while the door's own file lists fine, and neither a
  relative nor an absolute climb reaches the sibling directory.
- **A remote `brix_storage_backend` on a proxy listener is inert for the same
  reason** — the diversion precedes storage, so the very object the http-backed
  member serves with kXR_ok is "No such file or directory" through the proxy.
  That is also the pair this file created by existing
  (`proto:tap_proxy × store:httpbe`, the self-referential trap tranche 12 hit),
  carried inside the proxy block rather than left as a fresh gap.
- **`brix_tls` arms the upgrade without demanding it.** The same proxy port
  serves a TLSv1.3 session (flags `0xc4300201`, login and reads forwarded) and a
  client that advertises no TLS at all — but a client that advertises
  kXR_ableTLS and then speaks cleartext is refused, so the advertisement is a
  commitment. Without that pair of arms the TLS test would have proven only
  that the port was a TLS port.
- **`brix_cms_paths /` makes a member a candidate for every path**, by design
  and not by prefix arithmetic: `srv_path_matches()` (`registry_select.c:28`)
  short-circuits a bare `/` token to `return 1` before the directory-boundary
  logic below it runs. Two members where one holds `/` are therefore both
  eligible for the other's subtree, and the winner is whatever the three-tier
  load ladder picks — which is why this file gives each member a namespace of
  its own. Worth knowing when reading a cluster test that "usually" places
  correctly: with `/` in the registry, placement is a scheduling outcome, not a
  routing one. (Cost of learning it the slow way: one test that passed against
  an ephemeral-port probe 20 times and then failed on the ledger run.)
- One asymmetry worth knowing: the proxy's own namespace *is* validated where
  the module owns it (`brix_tap_proxy_upstream_tls` with no CA is refused at
  parse time as "MITM-able"), and `brix_tls` with no certificate and
  `brix_gridftp` with no export are both refused too — but
  `brix_tap_proxy on` with no upstream at all parses and starts. The
  destination is the one part of a proxy nothing checks; pinned as a fact.

**Re-running step 3 with the file in place: 6 → 0.** The block-granularity
matrix is empty: 2483 server blocks, no pair scored co-tested per file that
lacks a block running it. **§Method step 3 — the backlog this pass generated
about itself — is closed**, and with it the whole document.

Ledger/ladder: `lc-audit15m-streamcores` (30702, extras `ORIGIN_PORT` 30703,
`GRIDFTP_PORT` 30704, `HTTPBE_PORT` 30705, `MGR_PORT` 30706, `CMS_PORT` 30707,
`HTTP_ORIGIN_PORT` 30708, `SHADOW_PORT` 30709) in
`fleet_ports_shared_phase5.py`; `LIFECYCLE_SHARED_WIDTH` 688 → 696 with every
offset below it repacked as the running sum (`PORT_COUNT` 1968 → 1976). Guards
green: `test_fleet_ports.py`, `test_no_hardcoded_hosts.py`,
`test_fleet_declares.py`, `check_template_refs.py`, `check_ports_doc.py`.

### Tranche 14 — 2026-08-17, §Method step 2 re-run: 5 files, 104 tests

**First, the measurement — for the third time it is the instrument that is the
finding.** Tranche 13 closed everything steps 1 and 3 could still see, so this
tranche sharpens **step 2**. Step 2 scored a directive covered when its name
occurred anywhere in the test/deploy corpus. That is a search, not a claim: a
directive that merely sits inside a `.conf` some test launches is "covered" by
`nginx -t` proving it parses and merges, while nothing anywhere asserts what it
*does*. Re-asked as **"is there a test whose verdict changes when this
directive's value changes?"**, the shortlist ran **30 → 26 → 13**: 30 names
re-measured, 26 that occur in the corpus at all (step 2 called every one of them
covered), and **13 with no assertion whose outcome moves with them.**

Three of the 13 did not survive contact with the C, and are recorded here rather
than re-tested — the sharpened question has to be asked of the *reader*, not of
the directive, and for these three a reader already exists:

- **`brix_s3_token_audience`** — `test_wlcg_token_conformance_s3.py::
  test_s3_04_wrong_audience_reject` and `test_audit15k_s3_coresidency.py::
  test_a_wrong_audience_bearer_is_refused` both fail if the directive stops
  being honoured. Covered in effect.
- **`brix_s3_token_jwks`** — same two tests: they mint against the JWKS the
  directive names, so a leg that ignored it could not verify them at all. Its
  *config-time* refusals were untested, and those are in tranche-14 file 3.
- **`brix_dashboard_stalled_threshold`** — `test_dashboard.py::
  TestDashboardThrottledState` runs against a face configured 1s/3s with a 45s
  budget; neither the throttled nor the stalled state is reachable on the 60s
  default, so its verdict already moves. Its *neighbour*
  `brix_dashboard_idle_threshold` had no reader at all, which is what file 4
  takes.

The five files, against what remained (`brix_s3_token_jwks` returns for its
config-time half, which no reader anywhere provoked):

- **`test_audit15n_webdav_cors.py`** (21) — `brix_webdav_cors_origin`,
  `_credentials`, `_max_age` and `brix_webdav_redirect_window` on one listener,
  because they interact: CORS headers are emitted in the ACCESS phase
  (`access.c:426`) and the redirect is built in the CONTENT phase
  (`dispatch.c:579`), so a 307 inherits whatever the access phase already put in
  `headers_out` — the difference between a redirect a browser can follow and one
  `fetch()` rejects before it ever sees the `Location`. No file in the tree had
  run the two together.
- **`test_audit15o_cms_windows.py`** (16) — `brix_cms_locate_timeout`,
  `brix_cms_state_fanout`, `brix_cms_fanout_window`, `brix_metadata_only`.
- **`test_audit15p_s3_token.py`** (23) — `brix_s3_token_clock_skew`, plus the
  two config-time refusals of `brix_s3_token_jwks`.
- **`test_audit15q_dashboard_thresholds.py`** (21) —
  `brix_dashboard_idle_threshold`, the limits echo, and the cross-field
  invariant at `dashboard/module.c:203`.
- **`test_audit15r_webdav_tpc_cadir.py`** (23) — `brix_webdav_tpc_cadir`, the
  last survivor.

**How you observe a duration directive without a stopwatch** is the method
question this tranche had to answer four separate times, and the answer was
never a clock:

- *CMS windows* — two managers identical but for the three values, and every
  timing assertion is the DIFFERENCE between them. A host slow enough to stretch
  the fast manager stretches the slow one too.
- *S3 clock skew* — the deadline is written into the token, so one minted token
  handed to four locations that differ only in the skew collects four verdicts
  at one instant.
- *Dashboard bands* — the transfer table is process-wide SHM, so four dashboard
  faces read the SAME slot and disagree. **The disagreement is the
  measurement**: no elapsed time is asserted anywhere, and every assertion
  recomputes the expected state from the `idle_ms` in the very response being
  asserted, so a slow host moves the band without breaking the test.
- *TPC trust anchor* — not a duration, but the same shape: the source's
  certificate is self-signed, so the COPY's return code collapses onto one
  question, and the two CA directories are minted with the SAME subject, so the
  wrong one is a hash HIT that fails to verify rather than a lookup miss — which
  is what distinguishes "the directive was honoured and rejected the chain" from
  "the directive was ignored".

Three defect candidates:

- **DEFECT CANDIDATE #48 (security, config that disarms the same-origin
  policy) — `brix_webdav_cors_origin *` together with
  `brix_webdav_cors_credentials on` is accepted by `nginx -t`** and grants every
  origin on the internet credentialed cross-origin access to the export.
  `cors_emit_allow_origin()` (`cors.c:72`) keeps the letter of the CORS rule —
  with credentials on it never emits the literal `*`, it echoes the request
  origin — and that echo is exactly what makes the pair dangerous: a literal `*`
  is INERT for a credentialed request (browsers refuse it), whereas the echo is
  honoured. The safe-looking spelling is the one browsers reject and the
  reflected one is the one they obey. Two unrelated origins are shown both being
  admitted with `Access-Control-Allow-Credentials: true`. The fix is a
  parse-time refusal of the pair, not a change to the emitter — the emitter is
  correct.
- **DEFECT CANDIDATE #49 (clustering, livelock) — the CMS parent-locate forward
  is write-only.** `ngx_brix_cms_send_locate()` (`net/cms/send.c:431`) emits a
  `CMS_RR_LOCATE` (= 2) frame to the configured parent; the receiving opcode
  table `cms_srv_frame_routes[]` (`net/cms/server_recv_frame.c:288-306`) has no
  row for it. The frame lands in `cms_srv_frame_unknown()`, which recognises the
  opcode BY NAME from the manager routing table and drops it with an
  `ngx_log_debug2` line — invisible on any build without `--with-debug`. The
  consequence is not an error but a livelock: every registry-missing locate on a
  server configured with `brix_cms_manager` parks the client for the full
  `brix_cms_locate_timeout`, answers `kXR_wait 5` and caches nothing, so the
  retry does the same thing forever. A hierarchy never resolves upward, and on a
  stock build it never says so.
- **DEFECT CANDIDATE #50 (configuration, an unbounded security-relevant
  window) — `brix_s3_token_clock_skew` accepts any value its two plane twins
  refuse.** `brix_token_clock_skew` (`core/config/server_conf_merge_security.c:
  154`) and `brix_webdav_token_clock_skew` (`webdav/config_merge.c:164`) both
  fail `nginx -t` with "must be >= 0 and <= 300" outside that range. The S3
  spelling is a bare `ngx_conf_set_num_slot` with a `NULL` post handler
  (`s3/module.c:410-415`) and `s3_merge_token()` (`s3/module_merge.c`) merges it
  with no bound at all, so `brix_s3_token_clock_skew 1800` starts and a token
  25 minutes dead is served 200. Negative values are still refused, but only by
  `ngx_atoi` ("invalid number"), so the hole is the upper half. Pinned twice
  over — live, by serving a long-expired token, and at the source, by a regex on
  the `ngx_command_t` entry plus a `"300" not in body` check on the merge.

Facts pinned rather than defects, in the two files that found none:

- **The dashboard's `idle_ms` and `avg_bps` survive anonymous redaction**
  (`api_transfers.c:114-124` hides path, client, identity, VO and worker pid but
  not `id`, `state`, `idle_ms` or `avg_bps`), which is what makes an anonymous
  face a usable instrument at all. The dashboard route table is URI-ABSOLUTE
  (`module_dispatch.c:76-85`), so a face must be mounted at `/brix/` — four
  faces means four server blocks, not four locations.
- **The stalled/throttled split is `avg_bps`, not time.** `dashboard_state_name()`
  (`api.c:38-58`) reaches the same branch for both and picks on `moving`; a
  held-open handle sits in `stalled` because its rate is 0.
- **The cross-field invariant fires on defaults too.** `brix_dashboard_idle_
  threshold 90s` written ALONE is refused, because the unwritten stalled default
  of 60s is what inverts the pair — the check runs after the merge and for every
  location regardless of `brix_dashboard on`.
- **`CURLOPT_CAPATH` and `CURLOPT_CAINFO` are two anchor sources OR-ed, not an
  override pair** (`tpc_curl_setup.c:190-195` sets both unconditionally): a
  location handed the WRONG directory and the RIGHT `cafile` still serves, so an
  operator adding a `cadir` cannot lose an anchor they already had.
- **The TPC `cadir` fallback carries the operator's value, not a default store.**
  `tpc_config.c:130` fills `tpc_cadir` from `brix_webdav_cadir` only when the TPC
  spelling is unset; both halves are pinned (the same inheritance with the wrong
  directory refuses), and a location carrying both uses the TPC one.
- **A `cadir` that passes every config-time check can still trust nobody.** An
  existing, readable, searchable but EMPTY directory boots and refuses every
  pull — validation proves the path is usable, never that it holds an anchor.
- **The TPC path check is unreachable for inherited values.**
  `webdav_validate_tpc_paths` applies exactly the kind and access mode
  (`WEBDAV_PATH_DIRECTORY`, `R_OK | X_OK`, `config_merge.c:504`) that
  `webdav_validate_ca_paths` has already applied to `brix_webdav_cadir`
  (`:376`), and the general check runs first and unconditionally (`:535` before
  `:538`) — so an operator's typo is always named where they wrote it, and the
  TPC check fires only for an explicitly written directive. Its own gate is the
  asymmetry: `webdav_validate_tpc_paths` early-returns on `!conf->tpc`
  (`:495`), so a nonexistent anchor staged with `brix_webdav_tpc off` is
  accepted silently and it is the later `on` that fails the reload.

**Re-running the sharpened step 2 with the five files in place: 13 → 0.** Every
directive that occurred only inside a launched template now has an assertion
whose verdict moves with it.

Ledger/ladder: `lc-audit15n-cors` (30710, extras `MEMBER_PORT` 30711,
`CMS_PORT` 30712), `lc-audit15o-cmswindows` (30713, extras `SLOW_PORT` 30714, `CMS_PORT`
30715, `META_PORT` 30716), `lc-audit15p-s3token` (30717),
`lc-audit15q-dashbands` (30718, extras `MID_PORT` 30719, `SLOW_PORT` 30720,
`DEF_PORT` 30721, `ROOT_PORT` 30722) and `lc-audit15r-tpccadir` (30723, extra
`MOCK_PORT` 30724) in `fleet_ports_shared_phase5.py`; `LIFECYCLE_SHARED_WIDTH`
696 → 711 in five steps, one per file, with every offset below it repacked as
the running sum (`PORT_COUNT` 1976 → 1991). Guards green: `test_fleet_ports.py`,
`test_fleet_declares.py`, `test_no_hardcoded_hosts.py`, `check_ports_doc.py`,
`check_template_refs.py`.

### Tranche 15 — 2026-08-17, §Method steps 1–2 re-run at VALUE granularity: 9 files, 435 tests

**For the fourth time it is the instrument that is the finding, and this time
the flaw is in steps 1 AND 2 at once.** Both steps count directive *names*.
Tranche 14 sharpened step 2 from "does the name appear?" to "does a test's
verdict change when the value changes?" and closed the last thirteen names. Both
questions — the original and the sharpened one — share a blind spot no tranche
had ever measured: **for an enum-valued directive they are answered by ONE of
its tokens.** Write `brix_authdb_audit all` once, or assert on it once, and the
directive is scored covered forever, however many other values the table holds.

Re-running step 1 per **(directive, value) pair** over the 36 `ngx_conf_enum_t`
tables in `src/` gives **93 pairs, of which 48 are written somewhere in the
coverage corpus and 45 are written nowhere at all.** Netting off the pairs
written through a template placeholder rather than as a literal —
`brix_webdav_signing_policy`'s on/off/require and `brix_webdav_crl_mode`'s
off/try/require are driven by `wlcg_fleet.WlcgInstance`, `brix_cache_verify`'s
three by `test_cache_verify_require`, `brix_seccomp audit` by
`test_seccomp_enforce` — leaves a real backlog of about two dozen. The nine
files below take all of it.

Two structural facts fell out of the count before a single test was written, and
both are why the count has to be per-token:

- **The unwritten tokens are not a random sample.** They cluster at the two ends
  of every table: the token that turns the feature OFF (file 8) and the token
  that restates the merge DEFAULT (file 9). Both are unwritten for the same
  understandable reason — an operator who wants either one writes nothing — and
  "writing the token" and "not writing the directive" are two configurations
  that nothing in the suite had ever checked are the same one. Checking that
  produced five of this tranche's thirteen defect candidates.
- **A token count cannot be taken off the spellings.** `ngx_conf_set_enum_slot`
  compares with `ngx_strcasecmp` after testing `name.len`, so `AWS` and `aws`
  are one pair and a prefix is refused; the hand-written `brix_seccomp` setter
  matches case-insensitively too. Pairs are therefore counted off the enum table
  and nowhere else, pinned by `test_the_token_is_case_insensitive` in file 9.

The nine files, each named for the directive whose table it exhausts:

- **`test_audit15s_authdb_audit.py`** (48) — `brix_authdb_audit`
  `none`/`deny`/`grant`/`all`. Eight WebDAV locations on ONE listener, read out
  of the ONE error log a single worker writes. The four tokens are the four
  subsets of a two-bit mask, so the table is a truth table; `grant` in
  particular is a **silent-deny** configuration.
- **`test_audit15t_cms_role.py`** (39) — `brix_cms_role`
  `server`/`manager`/`supervisor`/`peer`/`proxy`/`auto`. The only file in the
  tranche that cannot fold onto one listener: the role's whole observable is the
  login Mode word one node sends its manager, so six nodes, one per arm.
- **`test_audit15u_crl_mode.py`** (34) — `brix_crl_mode` `off`/`try`/`require`,
  plus the arm no name-level test could reach: `try` with no `brix_crl`, which
  arms nothing.
- **`test_audit15v_signing_policy.py`** (38) — `brix_signing_policy`
  `off`/`on`/`require` over one hashed CA directory with three anchors.
- **`test_audit15w_security_level.py`** (34) — `brix_security_level`, whose two
  never-written tokens (`none`, `compatible`) are exactly the two that switch
  enforcement off.
- **`test_audit15x_backend_delegation.py`** (61) — `brix_backend_delegation`,
  three of six tokens never written (`delegate`, `mint`, `auto`), against a
  capturing origin that records the `Authorization` header of every backend leg.
- **`test_audit15y_cvmfs_origin_policy.py`** (50) — the CVMFS origin-policy trio
  (`brix_cvmfs_origin_http_version`, `brix_cvmfs_fill_retry_policy`,
  `brix_cvmfs_geo_answer`), measured with TWO cvmfs locations in one process.
- **`test_audit15z_disable_tokens.py`** (68) — the five never-written tokens
  that turn a feature OFF: `brix_cns off`, `brix_gsi_signed_dh off`,
  `brix_io_uring off`, `brix_min_sec_level none`, `brix_seccomp off`.
- **`test_audit15aa_default_tokens.py`** (63) — the five never-written tokens
  that RESTATE the merge default: `brix_backend_s3_sts_flavor aws`,
  `brix_health_check_type ping`, `brix_ssi_cta_executor prod`,
  `brix_webdav_checksum_xattr_format text`, `brix_webdav_redirect_scheme http`.

**How you measure a token whose whole claim is that it changes nothing** is the
method question this tranche had to answer nine times, and the answer was
always the same shape: **co-residency plus a control.**

- *A token that disables* is measured against the directive being ABSENT, in the
  same process, on a second server — never against the feature being on. The
  enabling token appears only as a control, to prove the "off" observation is a
  signal and not a constant (file 8).
- *A token that restates the default* has no first-order observable at all, so
  it is measured against a SIBLING writing the other token, in one worker. Where
  the directive is honest the two are independent; where it is not, one decides
  for both — and that is the entire finding (file 9).
- *A process-global masquerading as per-location* needs a control that is
  honestly per-location in the same file, same request. `brix_cvmfs_geo_answer`
  plays that part for the other two CVMFS enums; `brix_webdav_redirect_scheme`,
  merged twelve lines below `brix_webdav_checksum_xattr_format` in the SAME
  function and read from `conf->` at request time, plays it for the checksum
  format. Without the honest neighbour the finding is house style; with it, it
  is a defect.
- *A shared trust store* is the instrument, not a convenience: files 3 and 4 put
  five and four listeners over ONE hashed CA directory precisely so that a
  verdict difference cannot be explained by a path difference — which is also
  what proves the config-parse store cache is keyed on the mode.
- *A dead endpoint* gets a ledger slot (`DEAD_PORT`, file 7) and is never bound.
  Reserving a port for something that must not answer is the only way to stop
  another suite from making it answer.

**One harness defect, found because this tranche flaked and would not stop.**
Roughly half the nine-file runs lost a `test_audit15y` case to a dead connection.
It was not the test: the instance was being **SIGTERMed from outside its own
pytest session**, because three reapers decided which processes a `TEST_ROOT`
owns by testing whether the root was a *substring* of the cmdline — so
`/tmp/xrd-test` (and the shared markers `/tmp/xrd`, `/tmp/hsproto`) owned every
`/tmp/xrd-test-<suffix>` lane on the box, and cleaning one lane SIGTERMed all of
them. Ownership is now a whole path (`fleet_orphans.owns`, used by the reaper,
`operator_build.brutal_teardown` and `run_suite_unprivileged`), pinned by four
tests in `tests/test_fleet_teardown_orphans.py`. Full account:
`docs/09-developer-guide/history-testing-and-incidents.md` §10. It is recorded
here rather than as a defect candidate because it is a defect in the harness, not
in the server — but it is the reason the tranche-15 timing above is trustworthy.

Thirteen defect candidates — the tranche's whole reason for existing, since
twelve of the thirteen are reachable only by writing a token nobody writes:

- **DEFECT CANDIDATE #51 (observability, the audit trail says a refused
  mutation landed) — `cms_frame_forward()` derives its cmsd-action audit line
  from `rc == NGX_OK`** (`net/cms/recv_frame.c:380-386`), but the failure path
  returns `ngx_brix_cms_send_error()`'s value, which is `NGX_OK` whenever the
  `kYR_error` frame was DELIVERED (`send.c:32-50`). A forwarded namespace op
  that was refused — a path escaping the export root, say — is recorded as
  `result=ok detail=manager-forwarded namespace op executed on this node`. The
  audit trail cannot distinguish a mutation that landed from one that was
  rejected.
- **DEFECT CANDIDATE #52 (security, the revocation warning is keyed on the wrong
  input) — two configurations accept revoked certificates and the startup
  warning fires for exactly one of them.** `postconfiguration.c:89-96` emits its
  "REVOKED certificates will be ACCEPTED" NOTE under `xcf->crl.len == 0` alone,
  never looking at `crl_mode`. A server carrying `brix_crl
  /etc/grid-security/certificates;` **and** `brix_crl_mode off;` loads every CRL
  on the host, enforces none of them, and starts in silence — while the operator
  who merely forgot `brix_crl` is told. The warning is keyed on the presence of
  a CRL *source*, not on whether revocation is *enforced*.
- **DEFECT CANDIDATE #53 (operability, a fatal config error reported at
  `[warn]`) — `brix_signing_policy require` with a bundle-FILE trust anchor
  fails `nginx -t` with no `[emerg]` line and no `file:line`**
  (`store_policy_store.c:232`), unlike every other brix config refusal. An
  operator grepping for the level nginx itself uses for fatal config errors
  finds nothing; the only explanation on offer is a warning that reads like
  advice.
- **DEFECT CANDIDATE #54 (operability, the remediation advice contradicts the
  verdict) — the unsignable-session WARN ends with a fixed sentence whatever the
  flag it advises about is set to** (`sigver.c:182-188`): it states the requests
  ARE refused and then tells the operator to turn on the switch that refused
  them. Only the "requests are %s" clause is conditional; the advice is
  unconditional.
- **DEFECT CANDIDATE #55 (security, a fail-closed flag that can never close) —
  `brix_security_level none` (or `compatible`) together with
  `brix_signing_required on` is a configuration that can never do anything.**
  The flag is read only on the path that levels 0 and 1 return before reaching
  (`sigver.c:211-224`). `nginx -t` accepts the pair without a word and nothing
  is logged at run time either — the once-per-session WARN lives inside the
  branch that never executes. An operator who set the fail-closed flag and left
  the level at its default has no signing enforcement and no way to discover
  that from the server. Both halves pinned.
- **DEFECT CANDIDATE #56 (security, the caller's credential is bound and then
  dropped) — `brix_backend_delegation delegate`, `mint` and `auto` capture the
  caller's bearer, run the audience gate, bind it onto the VFS ctx — and then
  `vfs_cred_live_bag` handles only two of the six modes** (`fs/vfs/vfs_cred.c:
  119-132`), so the bag is never opened and the request proceeds on the service
  credential. Three sub-findings, each pinned separately: **(a)** nothing warns
  at parse time and the run-time INFO line is the same one a non-delegating
  export writes; **(b)** `mint` neither arms minting nor is required for it —
  `vfs_cred_maybe_mint` never reads the mode, minting is armed solely by
  `brix_storage_credential_mint_ca`, measured both ways; **(c)** the
  mode-labelled counter cannot see any of it, because `brix_cred_deleg_total` is
  emitted only from the live-bag path and a successful mint, so a `delegate`
  export that drops the credential moves `brix_cred_select_fallback_total`,
  which carries no mode label at all. `docs/10-reference/backend-delegation.md`
  is honest about `delegate` and over-claims the other two: measured `auto` is
  the WORST available, not the best — it drops a bearer that `passthrough`
  forwards to the same origin on the same request.
- **DEFECT CANDIDATE #57 (correctness, a location-level directive that is not
  per-location) — `brix_cvmfs_origin_http_version` is merged into a process-wide
  global once per cvmfs location** (`cvmfs_module_merge.c:264`), so the last
  location merged decides for the whole worker. Three silent consequences, all
  measured: **(a)** a location's own value is discarded whenever another cvmfs
  location merges after it, even when the value it wrote is the one that works;
  **(b)** a location that never mentions the directive is not neutral — its
  `NGX_CONF_UNSET_UINT` merges to 0 and is written to the global like any other
  value, so adding a second unrelated repository export with no opinion at all
  reverts the first one's policy; **(c)** the reverse is the row an operator
  will actually hit — adding a repository that needs `2-direct` forces every
  OTHER repository onto h2c prior knowledge, and against an HTTP/1.x origin one
  of them stops serving. **The export that broke is not the export that was
  edited.** Nothing is said at parse time and the trace line reports the version
  negotiated, never the one the location asked for.
- **DEFECT CANDIDATE #58 (correctness, a pin that does not pin) —
  `brix_cvmfs_fill_retry_policy force-primary` does not pin the origin.**
  `sd_http.h:100-104` documents "never fails over to an alternate"; measured
  over a DEAD|LIVE set the read succeeds *from the alternate*. sd_http keeps
  its half of the contract and reports EIO; the fill layer retries with backoff,
  by the second attempt the cvmfs RTT ranker has re-preferred the live endpoint,
  so "the rank-preferred endpoint" is now the alternate. The operator asked for
  the primary and got the alternate's bytes, three seconds and three error lines
  later — strictly slower and strictly noisier than the failover they turned
  off. And because the merge at `:271` has **no `else`**, `failover` cannot
  restore the default: a location writing `failover` behaves as `force-primary`
  as soon as any OTHER location writes `force-primary`. That is #57's shape on a
  second directive, with the extra property that **no ordering of the config can
  undo it** — `sd_http_force_primary_set` has exactly one caller in the tree and
  it passes 1.
- **DEFECT CANDIDATE #59 (configuration, a duplicate guard that depends on
  order) — `brix_seccomp`'s hand-written setter cannot tell "unset" from
  "off".** Its guard is `if (*field != NGX_CONF_UNSET_UINT && *field !=
  BRIX_SECCOMP_OFF) return "is duplicate"` (`seccomp.c:57`), and
  `BRIX_SECCOMP_OFF` is 0. Measured with `nginx -t`: `off; off;` accepted,
  `off; audit;` accepted (global := audit), `audit; audit;` refused,
  `audit; off;` refused. **The same two lines are a fatal config error in one
  order and a valid configuration in the other.** The control is exact —
  `brix_min_sec_level none` is also value 0 and also the merged default, and
  doubling it IS refused, because the stock enum slot tests against
  `NGX_CONF_UNSET_UINT`, which is what "unset" actually means.
- **DEFECT CANDIDATE #60 (dead config, a merged field nothing reads) —
  `ngx_stream_brix_srv_conf_t.seccomp` is initialised, merged, addressed by two
  directive tables and written by the setter, and read by nothing in `src/`.**
  The merge is dead: its result cannot reach any decision. `brix_seccomp` is
  declared `NGX_STREAM_SRV_CONF|BRIX_HTTP_ALL_CONF|NGX_CONF_TAKE1` — per-server
  — but is in fact a process-global directive. It is at least documented at the
  declaration ("also bumps the process-global strictest"), but the documentation
  says the field is *also* used, and it is not.
- **DEFECT CANDIDATE #61 (documentation, a default that was flipped in one place
  of four) — `brix_io_uring`'s documented default is stale.** The default was
  deliberately flipped `auto -> off` (fix `-9` in
  `docs/09-developer-guide/postmortem-origin-credential-shadowing.md`, kept as
  "correct hardening"), and the merge carries the reasoning. The flip did not
  reach `src/protocols/root/stream/directives_cache.h` (the directive's own
  comment), the data-plane comparison prose, or that file's feature table
  "Default" column. The reference an operator reads says io_uring is
  best-effort-on out of the box when it is off — and the `on`-without-liburing
  error even recommends `auto` "to allow silent fallback", reinforcing the wrong
  model. Pinned as a contradiction, not as a wish.
- **DEFECT CANDIDATE #62 (correctness, a merged value thrown away) —
  `brix_webdav_checksum_xattr_format` is declared `MAIN|SRV|LOC` and merged with
  a real `ngx_conf_merge_uint_value`, and then `config_merge.c:107` throws the
  result into a process-global through an `if` with no `else`** — so the global
  only ever moves AWAY from `text` and **`text` cannot be restored by any
  configuration.** Measured in one process: `/txt/` (writes `text`) and `/bin/`
  (writes `xrdcks`) produce byte-identical binary `XrdCksData` xattrs for the
  same payload, while a separate-process control writing `text` produces the
  text record `'5bf5127c 1786941171 563566789 2048'`. Ordering does not rescue
  it — `text` never calls the setter in either order —
  `brix_integrity_set_xattr_format()` itself accepts `BRIX_CKS_FMT_TEXT` and
  only the caller is guarded never to pass it, and nothing else in `src/` reads
  `conf->checksum_xattr_format`. The honest neighbour twelve lines below
  (`brix_webdav_redirect_scheme`, three locations, three verdicts) is what makes
  this a defect rather than a house style.
- **DEFECT CANDIDATE #63 (durability, a storage-control surface fabricates a
  tape guarantee) — `brix_ssi_cta_executor` is a per-server directive pushed
  into a per-worker global on EVERY SSI open** (`ssi.c:97` calls
  `brix_ssi_cta_configure()` unconditionally), while `g_cta_use_prod` is read at
  COMPLETION (`cta_service.c:52`). Both directions measured: a `prod` open turns
  a `test` face's in-flight archive into `ERR_CTA`; and — the one that matters —
  **a `test` open makes the `prod` face answer `CTA_RSP_SUCCESS`, "writing to
  tape", for an archive that never touched tape.** Any client that can open the
  sibling listener can trigger it. `brix_ssi_cta_journal` rides the same
  push-on-open path.

Facts pinned rather than defects, in the files that found none and alongside the
ones that did:

- **`brix_authdb_audit` does exactly what its four values say.** The token
  selects the SUBSET of decisions that reach the log and nothing else: all eight
  locations answer 200 on the granted path and 403 on the refused one, so a
  location logging nothing enforces exactly as hard as one logging both. The
  merge default is `none`, not `all` — an export that turns the xrdacc engine on
  without naming a level gets **no authorization trail**, which nothing in the
  corpus established because every template writes the directive. The op field
  is real (`read`/`create`/`delete`/`readdir` by method) and the untrusted path
  is sanitised to one line per decision whatever the client sends.
- **OPTIONS is exempt from the acc tier by design.**
  `access_options_preflight()` short-circuits with `NGX_OK` before
  `webdav_acc_check()` runs, so an OPTIONS on a path the authdb grants nothing
  on answers 200 and writes no audit line even under `all`. That is the CORS
  preflight contract; it is pinned in both
  directions so that wiring acc into OPTIONS — or removing the now-unreachable
  `BRIX_AOP_ANY` arm — is a visible change.
- **Every `brix_cms_role` token produces a distinct, exact Mode word, and the
  directive being absent produces the same wire as an explicit `auto`.** `peer`
  is the only token that withholds `kYR_server` (a peer cluster's contact point
  must never be registered as ordinary serving capacity) and `proxy` sets
  `kYR_proxy` ON TOP OF `kYR_server`. The two planes are independent: `auto` +
  `brix_manager_mode` and `supervisor` emit the SAME Mode word `0x0A` and are
  nonetheless different nodes — the first dispatches a forwarded `kYR_mkdir` to
  its own executor, the second relays it down its tier. A reader inferring the
  dispatch class from the wire would get that backwards.
- **`brix_manager_mode` has no export.** It makes
  `brix_server_has_runtime_export()` false, so `root_canon` stays empty and the
  export rootfd is never opened — the gate and the storage leg are therefore
  read as two separate observables rather than one inferred from the other.
- **`try` and `require` differ on exactly one input, and so do `off` and `on`.**
  Only the `require` × no-CRL-issuer cell separates the two enforcing CRL modes,
  and only the `off` and disarmed-`try` cells accept a certificate the CA has
  revoked. Same shape for signing policy: only `require` × no-policy-file
  separates the enforcing tokens, and the `off` × out-of-namespace cell is the
  security negative — a CA told to sign only `/OU=inside/*` signs an
  `/OU=outside` subject and the login succeeds.
- **The signing-policy proxy exemption is load-bearing.** A policy naming ONE
  literal subject with no trailing wildcard accepts a proxy whose DN is that
  subject plus `/CN=<serial>` under BOTH `on` and `require`. Had the walk not
  skipped proxy links, `require` would refuse every proxy login on earth, since
  a proxy's issuer is an EEC and never has a policy file of its own.
- **`compatible` is advertised but by construction requires nothing.**
  `brix_gsi_sigver_required()` answers 0 for EVERY opcode at level <= 1, so the
  advertised `seclvl` byte and the enforced opcode set are two different facts;
  `kXR_secOData` appears iff the level is >= 4.
- **`brix_min_sec_level`, `brix_gsi_signed_dh`, `brix_cns` and `brix_io_uring`
  are honestly per-server** — two listeners in one process disagree — which is
  precisely what makes `brix_seccomp` in the same file a finding rather than a
  house pattern.
- **The two STS flavour enum tables must stay identical.** `brix_backend_s3_sts_
  flavor` is declared on both planes off two separate `ngx_conf_enum_t` tables;
  a sync guard fails if they diverge, and a second guard keeps `deleg_wire.c`'s
  unreachable post-merge `NGX_CONF_UNSET_UINT` fallback agreeing with the merge
  default.

**Re-running step 1 at value granularity with the nine files in place: 45 → 0
never-written pairs.** Three arms are recorded as gaps rather than closed, all
for the same reason — the observable needs infrastructure the tranche's shape
cannot stand up, and in each case the pair is covered at the static and parse
tiers:

- **`brix_cns off` has no runtime arm.** Emitting a name-space record needs a
  CMS manager and a write path, and the off/silence pair is not separable from
  the merged-default fact file 8 already pins statically.
- **`brix_health_check_type ping` has no wire-level split.** The probe's
  `kXR_ping` and `kXR_stat` paths are distinguished at the source and by the
  merge default; nothing in the tranche observes the two opcodes on the wire.
- **`brix_backend_s3_sts_flavor aws` has no live endpoint.** The `minio` dialect
  has a live lab (phase-70); the `aws` token is measured at the parse, merge and
  table-sync tiers only.

Ledger/ladder: `lc-audit15s-auditmodes` (30725); six single-port role nodes
`lc-audit15t-role-{auto,automgr,absent,peer,proxy,server}` (30726–30731), whose
manager peer is an in-process Python socket on a `free_port`, not a ledger port;
`lc-audit15u-crlmode` (30732, extras `TRY_PORT` 30733, `REQ_PORT` 30734,
`DEF_PORT` 30735, `NOCRL_PORT` 30736); `lc-audit15v-sigpolicy` (30737, extras
`ON_PORT` 30738, `REQ_PORT` 30739, `DEF_PORT` 30740); `lc-audit15w-seclevel`
(30741, extras `CMP_PORT` 30742, `STD_PORT` 30743, `INT_PORT` 30744, `PED_PORT`
30745, `DEF_PORT` 30746); `lc-audit15x-deleg` (30747, extra `ORIGIN_PORT`
30748); `lc-audit15y-cvpolicy` (30749, extras `MOCK_PORT` 30750 and `DEAD_PORT`
30751, reserved and never bound); `lc-audit15z-disable` (30752, extras
`SECOND_PORT` 30753, `GSI_PORT` 30754); and file 9's pair
`lc-audit15aa-default` (30755, extras `MEMBER_PORT` 30756, `CMS_PORT` 30757,
`SSI_PORT` 30758, `SSI2_PORT` 30759) with `lc-audit15aa-clean` (30760) — two
instances because a control for a process-global cannot share a process with its
case. All in `fleet_ports_shared_phase5.py`; `LIFECYCLE_SHARED_WIDTH` **711 →
747** in nine steps, one per file (711 → 712 → 718 → 723 → 727 → 733 → 735 →
738 → 741 → 747), with every offset below it repacked as the running sum
(`PORT_COUNT` 1991 → **2027**). Guards green: `test_fleet_ports.py`,
`test_fleet_declares.py`, `test_no_hardcoded_hosts.py`, `check_ports_doc.py`,
`check_template_refs.py`, `check_file_size.py`, plus `test_reload.py` and
`test_cms_sss_keytab.py` as repack sanity runs from two of the moved bands.

### Tranche 16 — 2026-08-17, the same re-run over `ngx_conf_set_flag_slot`: 36 files so far, 3,213 tests

**Tranche 15's correction was right and too narrow.** It re-ran steps 1 and 2
per *(directive, value)* over the enum tables, on the grounds that a name is
answered by one of its tokens. A flag has tokens too — exactly two — and one of
them answers the name just as completely. `ngx_conf_set_flag_slot` is the setter
behind **128 directives**, so the surface is **256 pairs**: 138 written
literally in the coverage corpus, 12 more reaching a config only through a
`{PLACEHOLDER}`, and **106 written nowhere in any form**, over 99 directives.

The interesting residue is not the 106. It is the **seven directives where BOTH
arms are unwritten** — `brix_backend_passthrough_persist`,
`brix_cvmfs_origin_reuse_conn`, `brix_http_query_token`, `brix_krb5_ip_check`,
`brix_ocsp_enable`, `brix_ocsp_soft_fail`, `brix_ocsp_stapling` — because a
directive with one arm unwritten is a coverage gap, while a directive with both
arms unwritten is a branch **nothing has ever entered**. Three of the seven are
the OCSP cluster, and the first two files take it; files 3, 4 and 5 take the next
three, one on the WebDAV plane and two on the root:// one. File 6 closes the
seventh — `brix_backend_passthrough_persist`, whose two arms can only be a
parse-tier row because it has no reader — and then starts on the 92 directives
with exactly ONE unwritten arm, taking the five S3 location flags whose
**`off` was never written anywhere**; file 7 takes the next six, the whole SciTags
packet-marking group, where three of the six **default to `on`** and the
never-written arm is therefore the only route to half the feature; and file 8
takes six more that are a group for a stronger reason still — they are six
consecutive entries in **one** command table (`brix_http_common_commands`),
behind one setter, one merge and one adopt list, which is also where one of them
turns out to die. File 9 takes nine at once, the CVMFS resilience flags, which
are a group by feature rather than by table; and file 10 the five
node-capability flags of `root/stream/directives_caps.h`, where the arm nobody
had written turns out — in one case — to be the arm that puts a **config-time
check back**. Files 11, 12 and 13 then take a whole header rather than a feature:
**every** arm-gap in `root/stream/directives_cms.h`, which holds twelve of them —
eleven `off` arms and, in the two keepalive flags that merge to `on`, two
never-written explicit `on`s. Twelve rather than thirteen: the thirteenth flag,
`brix_cms_state_relay`, has no literal arm in the corpus either, but it reaches
`nginx_cms_wire_super.conf` through a `{STATE_RELAY}` placeholder that
`_test_cms_wire_pup_conformance_helpers_b.py` fills with **both** tokens, and
both are read behaviourally (`test_state_relay_round_trip` against
`test_state_relay_default_off_is_silent`) — so it is covered and the grep is what
was wrong, which is the same step-2 lesson tranche 14 was built on. The split
into three files is the xdist groups the live tiers borrow, not the subject.
File 14 crosses back to the http plane for the five location-scoped flags of
`protocols/webdav/module_commands.c` — a group by *declaration shape* rather than
by table position or by feature: `NGX_HTTP_LOC_CONF | NGX_CONF_FLAG` and nothing
else, so a location is their only legal context on either plane, and the only
parent value their merge can ever read is another location's. That is what makes
`brix_webdav off` more than a spelling of absence — inside an enabled parent it is
the only way to disable a child — and it is where the tranche's third
never-written explicit **`on`** turns up, in the one of the five that merges to 1.
File 15 stays in the same table and takes the three arm-gaps whose declaration is
*wider* — `brix_webdav_zip_access`, `brix_webdav_require_digest` and
`brix_webdav_dig`, all three `MAIN|SRV|LOC` — where the extra scopes change what
the missing arm even is: with a merge to 0, `off` in a bare location is the merge
default under another name, so the arm worth writing is the **per-location
opt-out** under a server that wrote `on`, and the corpus had never written any of
the three at server scope in either arm. File 16 closes the table's last arm-gap,
`brix_webdav_proxy_certs`, which had to be a file of its own because its only
observable is a client-certificate verification verdict: the flag's whole effect
is `X509_VERIFY_PARAM_set_flags(…, X509_V_FLAG_ALLOW_PROXY_CERTS)` on a
listener's SSL context, so the arms cannot share a socket the way file 15's
vhosts did — verify parameters are in place before the ClientHello, let alone
before a `Host` header — and each arm buys a port. Asking a directive declared
`SRV|LOC` the same per-location question files 14 and 15 asked is what turns the
last row of the table into the tranche's twenty-seventh finding: the location
placement the declaration invites is **inert in both directions**, and the
config-time banner advertises the acceptance the socket refuses.
File 17 leaves the WebDAV module for the stream plane's authorization block and
takes the three acc-engine flags declared side by side in one header —
`brix_acc_pgo`, `brix_acc_resolve_hosts`, `brix_acc_encoding`, identical in
shape and all merging to 0. They are the tranche's first subjects the corpus
configures **only from test sources and prose**: no rendered template writes any
of the three, so the census that found their gap had to widen past `configs/`,
and the closure is written in the test file rather than in a template because
these flags are what the tests VARY. Two existing files sit on the same ground
and stop one step short — `test_acc_residual.py` covers `resolve_hosts on` and
`encoding on`, `test_audit15f_acc_group_resolution.py` covers `pgo on`, and all
three name their control arm "off" while writing **absence**. Asking the same
per-server question file 16 asked, of a header where three flags answer it the
same way, is what turns the file into the tranche's twenty-eighth finding: two
of the three are read per server on every consultation, and the third is a
process global that the last engine-carrying server in configuration order sets
for every server in the worker — reachable, because the http plane builds its acc
tables lazily, by a single anonymous request that is itself refused.
File 18 stays twelve lines further down the same header and takes the two CSI
integrity flags, `brix_csi_require` and `brix_csi_trust_fs`, whose `off` arm the
corpus had never written either — and where the missing arm is not a spelling of
the default but the only way to ask a question the suite had never asked: what
an acceptor does with a file whose at-rest record is in a **known** state. Three
states answer both flags between them (tagged and intact, tagged with the data
damaged underneath, and no record at all), which is why the four acceptors share
ONE export: the subject lives on disk, so four exports would make every
difference a difference of files. That the two flags really are per-server —
four verdicts about one file out of one worker — is the control file 17's #92
failed, and it is what lets the two findings be about the code rather than about
the harness. Both are: `require on` is silently inert under `trust_fs on`,
because the test that enforces it is nested inside the branch the other flag
skips; and when the engine does catch at-rest corruption the client is told
kXR_IOError, through a job flag that is set, documented as the mechanism for
saying kXR_ChkSumErr, and read nowhere.
File 19 goes back up the same header, to the last arm-gap left in it:
`brix_krb5_delegate`, where `on` reaches two configs and `off` reaches none. It
is the tranche's clearest case that an unwritten arm is not a spelling of the
default. The written arm is not a capture switch — at the line it branches at
the AP-REQ has already been verified, so what `on` adds is a REQUIREMENT (a
second round, and a *forwardable* ticket, which `kinit` does not issue by
default), and the arm nobody wrote is the only spelling that takes the
requirement away again. Nothing in the corpus could ask what it costs, because
nothing had a plane to compare against: the existing e2e file drives one armed
listener with the clean-room client and covers the non-forwardable refusal, but
one plane cannot say what `off` restores, that absence IS `off`, or that the
flag is read per server. Three acceptors in one worker, one realm and one
keytab, with the STOCK client throughout and the ticket as the only variable,
gives the six-cell table — and, once the arm's cost is visible, two findings
about it.
File 21 closes the family the tranche opened with. `brix_ocsp_require_nonce` is
the last flag left whose BOTH arms reach no config — and it is a harder case
than the seven above, because it is not simply absent from the corpus: it
reaches one, through the `{TLS_DIRECTIVES}` placeholder of
`nginx_upstream_tls_verify.conf`, where `test_ocsp_require_nonce.py` pushes both
tokens through an `nginx -t`. That is a PARSE gate. No server has ever started
with the flag set, so the branch at `ocsp_request.c:224-230` had never executed,
and the file that owns it says why in its own docstring — the same sentence file
1 quoted before building the responder it asked for. Four GSI acceptors in one
worker take the four policies, and THREE responders take the three answers,
because a responder's nonce behaviour is fixed at startup while the responder a
login reaches is minted into the credential's AIA: behaviour and certificate
have to be bound at PKI time or the table acquires an ordering dependency. What
the four planes are for is the composition — this tranche has twice found a
fail-closed flag rendered inert by a performance flag layered over it (#93), so
the fourth plane asks whether `brix_ocsp_soft_fail on` swallows a deny the
replay guard raised. It does not; but the reason is incidental rather than
designed, and the same shared return code that saves it is what makes the
tranche's thirty-fourth finding.
File 22 takes the densest single file in the census. `directives_tpc.h` holds
SEVEN `ngx_conf_set_flag_slot` flags with an arm written nowhere in `tests/`
`conf/` `client/` `k8s-tests/`, and it is the same arm every time: the one that
opens the gate — `brix_tpc_allow_local off`, `brix_tpc_source_guard off`,
`brix_require_pgwrite off`, `brix_tpc_outbound_tls off`,
`brix_tpc_require_source_size off`, `brix_tpc_delegate off`, and the default-on
`brix_tpc_outbound_passthrough on`. Twenty-odd configs write
`brix_tpc_allow_local on`; not one writes `off`. The sharpest case is
`nginx_root_require_pgwrite.conf`, which carries a plane whose own comment says
the directive is "deliberately omitted (default off)" and tests the permissive
behaviour there — so the OFF BEHAVIOUR is covered while the OFF TOKEN is not,
and the equivalence of the two is an assumption the corpus states in a comment
and never measures. Six acceptors in one worker over one export take the seven
arms, their armed counterparts, and their absence; three of the seven exist only
mid-transfer, on the destination's own pull leg, and are reachable because that
leg tags its requests by streamid (1 protocol/login, 2 open/close, 3 read,
4 stat, 5 query), so the file subclasses `test_tpc_pull_integrity.py`'s splice to
answer tag 4 and tag 1 untruthfully and leave the rest alone. Nothing here goes
through xrdcp: every pull is driven on the raw wire, which forced the file to
implement the half of native TPC no test had ever driven — the INITIATING
client's open of the source with `tpc.key`+`tpc.dst`, which is what registers the
key `brix_tpc_key_consume` later spends (`open_tpc.c:165`, single-use, so every
transfer mints its own). Without it a destination's pull is refused
"TPC authorization missing or expired" and no gate downstream is ever reached,
which is why the three mid-transfer arms had stayed unmeasured. What the seven
arms buy, measured rather than read off the merge, is below — and one of them
turns out not to be the operator's to give away.
File 23 asks the same question of the WebDAV plane's own TPC header. Four flags
of `protocols/webdav/directives_tpc.h` have an arm written nowhere —
`brix_webdav_tpc_allow_local off`, `_allow_private off`, `_source_guard off`,
and the shipping default `_credential_forward on` — and the four are one subject
rather than four, because between them they decide the only question an egress
control asks: which authorities may this destination DIAL, and whose credential
does it carry there. Every one of them is `NGX_HTTP_LOC_CONF`, which is what
lets the file spend TWO ledger ports on THIRTEEN planes: one listener, thirteen
locations, and a single capturing TLS mock that is source, sink and witness at
once — it answers the pull, sinks the push, and records which credential
travelled, which is the only observable a refusal that fires BEFORE any outbound
leg can have. The planes come in twins throughout (written `off` beside the
omission, armed beside disarmed) so that no verdict is attributable to anything
but the token, and the file's two hardest measurements are shapes rather than
codes: the same address-range refusal on the marker path is a 202 whose body
ends in `failure` (#100), and a `source_allow` allowlist with its guard off is a
policy that permits what it does not name and says nothing about it (#101). The
credential flag is what binds the four together — with forwarding on and the
naming guard off, the only party choosing where the caller's own bearer token
goes is the caller.
File 24 finishes the header the tranche started in, `root/stream/directives_security.h`,
whose last four arm-gaps are the four flags the corpus writes most and disarms
never: `brix_tls off` (63 configs write `on`), `brix_ztn_cleartext off` (18),
`brix_zip_access off` (8) and `brix_zip_force_scratch off` (2). All four merge
to 0, which is the whole reason the cells are worth entering rather than a
reason to skip them — every existing test of the four says "off" in its prose
and writes ABSENCE in its config, so the equality of the written token and the
omission is a claim the corpus leans on everywhere and had measured nowhere. All
four are `NGX_STREAM_SRV_CONF` with no MAIN arm, so a `server {}` is the
smallest thing that can hold a value: twelve listeners in one worker over one
export, three per flag (the written `off`, the omission, the armed control), and
the equality holds twelve times out of twelve. What entering the arms turns up
is mostly shape rather than fault — `brix_zip_access off` does not refuse a
member request, it stops reading the opaque, so the client that asked for one
member is handed the whole archive under `kXR_ok`; `brix_tls off` beside a
configured certificate is the only way to separate the flag from the material in
an AND the code writes as one line — with two exceptions. `brix_ztn_cleartext`
is enforced TWICE and only the first gate had ever been reached, because a
token-only cleartext listener is refused at login before the second can fire;
these planes say `brix_auth both`, the login survives losing ztn, and the
credential gate at `auth/gsi/auth.c:222` answers for the first time in the
corpus. And `brix_zip_force_scratch off` beside a CONFIGURED stage dir is a cell
no config had held, because the existing off arm omits the stage dir too — which
is what turns a directive that does nothing into a directive that does nothing
silently (#102).

File 25 leaves that header for `root/stream/directives_net.h`, whose one
security-relevant arm-gap is `brix_upstream_tls_verify`: the corpus writes `off`
twice and `on` never, so the flag that decides whether the outbound redirector
authenticates the server it is about to re-send a login to had never been armed
by a test. The reason is on the record — `test_upstream_tls_verify.py` says in
its own docstring that the branch is "not drivable as a live negative from this
suite" and asserts the properties against the source instead. It is drivable.
What was missing was not a plane but a PEER: the fleet's `gotorls` stub
(`upstream_protocol_stubs.py`) sends the kXR_gotoTLS flag and closes, one frame
short of the handshake the flag is about, so nothing in the corpus had ever
watched the leg finish an outbound TLS handshake, let alone fail one. A stub
that goes the rest of the way — bootstrap, gotoTLS, a certificate the test
chose, and then a redirect for whatever arrives over the encrypted side — turns
each of eight planes into a trust decision with a wire outcome: a redirect that
reached the client, or a refusal, and in the refusals whether the login frame
ever left the process. Two of the eight do not answer the way the code says they
will. `brix_upstream_tls_verify off` does not disable verification: the
belt-and-braces gate in `net/upstream/tls.c` calls itself "harmless (X509_V_OK)
when verification is off", but with no CA the peer's chain is validated against
a trust store nobody populated, so the leg aborts every connection AFTER a
completed handshake, and the opt-out the config-time EMERG advertises does not
exist (#103). And the pinned name falls back to the upstream host as spelled,
through `X509_VERIFY_PARAM_set1_host`, which matches DNS names only — so the
same peer, the same certificate and the same CA are accepted when the upstream
is written as a name and refused when it is written as an address literal, even
though the certificate carries the matching IP SAN (#104).
File 26 takes the WebDAV half of the same clustering header,
`webdav/directives_net.h`, whose two mirror arm-gaps are both on the security
side of the flag: `brix_mirror_strip_auth` is written `on` and never `off`, and
`brix_mirror_log_diverge` is never written at all. The `off` arm is the one that
forwards the client's `Authorization` header, verbatim, to a second host the
client never addressed and cannot see, and it does exactly that — a 900-character
bearer arrives whole, so the shadow leg is a full credential replay and not a
truncated echo of one; a configured `brix_mirror_token` replaces that credential
rather than joining it, and the shadow receives exactly one identity either way.
The other flag cannot be measured, and that is the finding. The primary's status
is stamped in the LOG phase and read in the shadow subrequest's finalize, but a
background subrequest holds the main request open until it completes, so the
finalize always runs first and always reads a zero — the divergence is never
declared, the NOTICE the flag gates is unreachable, and
`brix_mirror_divergence_total{surface="http"}` is frozen at zero while
`brix_mirror_requests_total` counts the very replay that disagreed (#105). What
made that provable rather than arguable was bringing two shadows: the fleet's
shared `mirror-shadow` mock answers one status, and a divergence is a mismatch
of status CLASS between primary and shadow, so it takes an upstream that agrees
and one that never does to produce one on demand.
File 27 closes the header's last arm-gap, and this one the corpus had already
claimed in prose: `test_webdav_redirect_ds.py` lists "off-path — with the
feature off the manager serves locally (no 307)" in its own docstring, and no
config anywhere writes `brix_webdav_redirect_dataserver off` — its single
manager location writes `on`, as do three others. The claim is the kind that
looks safe and is not, because `webdav_redirect_dataserver`
(`webdav/redirect.c:195-213`) declines for FOUR different reasons — the flag
off, a method outside GET/HEAD/PUT, a `brixrdr.mac` already in the query, and a
registry with no node to select — and all four are the same 200 on the wire.
Attributing one of them to the directive means holding the other three still, so
the file puts five locations one directive apart under one `listen` on ONE
instance, carries the CMS registry on that instance's own stream faces, and
registers a data node before it asserts anything: without the node the armed arm
declines too and the A/B would compare two silences. What the off arm buys is
then measurable rather than assumed — the same URI is 307 under `/on/` and 200
with its own bytes under `/off/`, a PUT the armed location refuses to store
lands in the export at the disarmed one, and the recording server the `Location`
points at hears nothing at all. The unwritten arm and the written `off` produce
responses that compare equal — status, body and header names — which is the
merge default measured rather than read off `config_merge.c`. Two things the
arm-gap was hiding turn up on the way. The accepting half of §6.1 is not behind
this flag at all: `webdav_redirect_signed_auth` is gated on `brix_http_secretkey`
alone (`webdav/access_auth.c:376-386`), so a location that emits no handoffs
still honours them, and file 27 serves a file to a client whose only credential
is a manager-minted MAC at a location whose redirect arm is off — which is the
intended topology (a data server never sets the manager's flag) and is worth
stating, because the flag's name suggests a single §6.1 switch and it is only
half of one. And the loop guard is client-controlled: it fires on the PRESENCE
of `brixrdr.mac`, while the verification that would refuse a forged one is gated
on the key, so on an armed manager with no key configured — a documented
arrangement, since the identity is signed only "when a shared key is configured"
— any client can append the parameter and be served locally by the manager it
was supposed to be redirected away from (#106).
File 28 leaves the storage planes for the monitoring one and takes the two
arm-gaps of `src/observability/dashboard/module.c` together, because between
them they are the whole of what the dashboard exposes and to whom:
`brix_admin_require_both`, which combines the two factors the admin WRITE API
authenticates with, and `brix_dashboard_vfs_browse`, which decides whether the
UI may read stored user data at all. They also share a shape that decides the
layout: both endpoints live at a FIXED uri matched against `r->uri`
(`dashboard/module_dispatch.c`), and `brix_admin_require_both` is
`NGX_HTTP_LOC_CONF` alone, so a plane here cannot be a path — it is a
`server_name` vhost, and fourteen of them share one `listen` on one ledger port.
The combiner (`dashboard/api_admin.c:196`) computes two independent predicates,
the peer inside `brix_admin_allow` and a constant-time bearer compare against
`brix_admin_secret`, and the armed arm ANDs them while the never-written arm ORs
them — which is a distinction only visible when one factor passes and the other
fails, and the corpus had no such plane: `nginx_admin_api.conf`, the suite's only
admin config, configures a secret and no allowlist. RFC 5737 TEST-NET-1 supplies
the missing shape (an allowlist that is configured and can never match), and the
verdict is read off 403 against 405 rather than 403 against 200: `cluster/servers`
is a POST route, so a GET that clears the gate is refused by the method check one
line later, which makes every combiner cell a read — one POST spends the write
once, to prove the 405 really is downstream of the gate. What the arm buys is
then measurable: the same uncredentialed request that the `on` plane refuses is
served by the `off` plane on the allowlist alone, a correct bearer from outside
the allowlist is refused by `on` and admitted by `off`, and the unwritten
directive answers identically to the written `off` across all three request
shapes. It also buys the finding, which is what the AND does when only one
factor is configured: nothing. An unconfigured factor is not a required one, so
`require_both on` with an allowlist and no secret is byte-identical to
`require_both off`, and the two arms cannot be told apart by any request (#108).
The browser flag is the table's only `MAIN|SRV|LOC` directive, which changes
what its missing arm even is — as in file 15, `off` in a bare location is the
merge default under another name, so the arm worth writing is the per-location
opt-out under a server that wrote `on`, and it works: the location 404s while
the silent sibling under the same server serves the census, the listing and the
bytes. The second finding is at the other end of that feature. `vfs_browse.c`'s
own header says the endpoints are "Always admin-auth … never the anonymous tier:
this surface exposes stored user data", and the call it makes is
`ngx_http_brix_dashboard_check_auth`, which returns `NGX_OK` before it looks at
the request when no password and no user list are configured — so a dashboard
with the browser armed and no password hands the export census, a directory
listing and the file's bytes to any client that can reach the location, and file
28 measures exactly that against a plane whose only difference from a 401 is the
password directive (#107).
File 29 goes back to the storage plane for the table's largest arm-gap:
`brix_manager_mode`, written `on` by six configs and `off` by none. The other
never-`off` flags in this tranche add a behaviour to a node; this one takes one
away. `brix_server_has_runtime_export()` (`core/config/runtime_server.c:25-29`)
opens with `!manager_mode` and gates `brix_server_setup_export()` (`:190`), so a
manager's `brix_storage_backend` is never turned into an export — the directive
whose value the operator is most likely to check twice is inert on exactly the
node that redirects. That is invisible to a client, which is being sent
somewhere else, so the file needs a second instrument: the dashboard's VFS
census reports every registered export by canonical root, and six distinct data
trees make "this block registered an export" a fact readable from outside the
process. Over the wire the arms are unambiguous — the manager redirects to the
data node that registered with its CMS listener, for a file its own tree HAS,
while `off` and absent serve their own bytes and answer a missing file with a
local refusal rather than a deferral — and the census supplies what the wire
cannot: the manager's root is not in it. The finding is one layer up, in how a
block becomes a manager without saying so. `brix_cms_server on` derives manager
mode for its own block and its comment promises the operator can always override
that with an explicit `brix_manager_mode off` in the same block; the derivation
writes the flag slot directly, and `ngx_conf_set_flag_slot` refuses a second
write, so the override is accepted before `brix_cms_server on` and is an
`[emerg] "brix_manager_mode" directive is duplicate` after it — the order an
operator writing an override would naturally choose, refused with a message that
names a directive appearing once in the file and never mentions the one that
wrote it first (#109). The order that does load is worth reading too: three
lines that name a backend produce a block with no export, banner reading
`export "/"`, and one NOTICE that is word-for-word the one a bare
`brix_cms_server on` listener with nothing to lose receives.
File 30 takes the tranche's last two one-arm gaps, and they are the two that
looked least worth the trip: `brix_webdav_open_file_cache_errors`, written `on`
once and `off` never, and `brix_webdav_open_file_cache_events`, written `off`
once and `on` never. The single place either had ever appeared is one parse-only
cell in `test_audit15_zero_directive_parse.py:99-103`. Neither flag can have a
second arm that means anything, because the family they belong to is never read:
`brix_webdav_open_file_cache` is not a stub — its setter
(`webdav/module_directives.c:262-311`) parses `max=`/`inactive=`/`off`, refuses a
missing `max` and a duplicate, and on success calls `ngx_open_file_cache_init()`,
taking a real `ngx_open_file_cache_t` out of the config pool — and then nothing
consults it. No translation unit under `src/`, `shared/` or `client/` calls
`ngx_open_cached_file()`, and inside `webdav/` the five fields
(`webdav_loc_conf.h:200-204`) appear only in the command table, `config.c`'s
`NGX_CONF_UNSET` init, and the merge. The allocation is the last event in the
cache's life (#110). Proving that takes probes a WORKING cache would fail rather
than probes that pass either way, which is the whole method of the file: with
`max=1024 inactive=1h`, `valid 1h` and `min_uses 1` configured, a live cache
would still be holding a file that was replaced by rename, one truncated in
place, one deleted, and a 404 that a create has since answered — and every one
of those is served correctly on the next request, off four locations that share
one export and differ only by which directives of the family they carry. Eight
locations on one ledger port is the geometry, because the WebDAV resolver maps
the full request URI under the export root, so a URI prefix is already a
disjoint subtree. The last three locations are why the file is not only about
the cache: `brix_backend_passthrough_persist` is not a new gap — file 6 wrote
both its arms at parse level and its inertness is already #35 — but every cell
that pins #35 asks `nginx -t`, and a grep for a reader is not a measurement.
Three live locations one directive apart answer identically, which is #35 read
off a running server for the first time. The parse tier carries what the
behavioural tier cannot: thirteen distinct diagnostics, including that `off`
wins from ANY position in the argument list — the deliberate contrast with file
29's #109, where the same family of setters refuses the second write — and that
the four satellite knobs are accepted beside a cache that was never declared,
and beside one explicitly turned `off`. And the file's quietest cell is the one
that makes #110 a silent failure rather than a documented no-op: eight locations
carrying the two families produce not one log line, at any level, that names
either.
File 31 leaves the flag census's own list and goes after the three gates of the
GridFTP gateway, which the census had scored as covered and which were not:
`brix_gridftp_verify_write`, `brix_gridftp_require_allo_size` and
`brix_gridftp_gsi` each have an armed arm in the corpus and a control arm that
is rendered as ABSENCE while being named "off" — `test_gridftp_allo_truncation.py`
writes `extra = "brix_gridftp_require_allo_size on;" if require else ""` and
calls the result `gw_lenient`. Writing the three missing tokens is cheap and the
equality holds; what the geometry needed to make it hold *for the right reason*
is the interesting part, and it is one line of config. All three flags are
`NGX_STREAM_SRV_CONF`, so a plane is a `listen`, and eight gateways run in one
process over one shared export: five write planes (both disarming tokens, neither
token, both armed, and the two crosses) and three GSI planes that all carry the
SAME certificate, key and CA — because `ftp_module_merge.c:142` only builds a
GSI context when `enable && gsi`, so a `gsi off` plane WITHOUT the material is
not a disarmed gateway, it is a gateway that was never asked. With the planes
built that way, four of the tranche's findings fall out of the crosses rather
than out of the arms. The plane with `verify_write on` and `require_allo_size
off` accepts a truncated upload with 226 while its mirror refuses it 550 — no
number, because `ftp_gateway.h:39-45` is honest that the flag is a
storage-persistence check and not a wire check, but the two names point the other
way and the measurement is worth having. `verify_write on` is then switched off,
per transfer, by any client-chosen `REST > 0` (#112), measured as a positive: a
100-byte file surviving a 20-byte "verified" write is only possible if the
verifier never ran, since it would have compared 20 against 100 and unlinked the
object. A `require_allo_size` refusal leaves the rejected bytes under the final
name, readable, `SIZE`-able and RETR-able, and over-long by 1000 bytes in the
over-delivery case (#113) — the disarmed planes leave a byte-identical file for a
226, so the whole difference the flag buys is the reply code. And the GSI planes
answer the question the earlier §D note had waved away as a detector artifact
("GSI and control-channel TLS are intrinsic to the gsiftp protocol"): the
operator doc's own "production form" gateway, `brix_gridftp_gsi on` with a host
certificate, answers `230 Login successful` to `USER anonymous` and any password
at all, and serves a full read-write session, because `ev_grp_login` sets
`authed` on any PASS without consulting the flag and no directive anywhere
requires the security layer (#111). Arming GSI adds a mechanism; it removes
nothing. The fourth finding is the one the file tripped over while proving the
third: `REST 10` is answered `350 Restart position accepted (10ld)`, because
`%lld` is handed to `ngx_vslprintf`, which implements `%L` and not `%lld` — three
more sites do the same into the log (#114).
File 32 finds the same shape one protocol over, in `protocols/oci`, and this
time the corpus states the missing arm out loud: `tests/oci/registry_lane.py`'s
`registry_spec(anonymous=False)` sets `"ANON_LINES": ""`, so every cell of the
D4.5 authorization suite names a control arm that has never been written. The
literal token `brix_oci_registry_allow_anonymous off` does not occur anywhere in
the tree, and neither does `brix_oci_mirror_insecure off` — that one is `on` in
`configs/oci_mirror.conf` (which calls itself "the ONE place in the tree that
does") and in `oci_compose.conf`, and absent everywhere else. Both merge to 0,
both equalities hold, and both cost one line to write; what the geometry needed
was seven registry fronts in one process, because the flag that opens a registry
is not the only way into one. The load-time gate
(`oci_merge.c:203-212`) refuses `brix_oci_registry on` unless the config names
an issuer table, states the anonymous intent, or `oci_ssl_verifies_client(cf)` —
and that helper is `sslcf->verify != 0`, which `on`, `optional` and
`optional_no_ca` all satisfy. So the file builds four cleartext planes (open,
the written `off`, its omission, and the composition no lane has built) and three
TLS planes that differ by nothing but `ssl_verify_client`, and four of its six
findings fall out of the two planes the corpus never builds rather than out of
the arms. The composed plane — an issuer table BESIDE `allow_anonymous on`, which
`configs/oci_registry.conf` has always permitted, its two slots being
independent — admits a bearer the issuer table REJECTED, because
`oci_authz_bearer()` returns `NGX_DECLINED` for "no issuer accepted this token"
and for "no token was sent" alike, and the anonymous branch is what catches it
(#115). Five forged pushes produce five `JWT signature verification failed`
lines, **zero** `signal=authfail` guard-audit lines, and a complete pullable
image on disk: the token layer sees the attack, the jail keyed on the audit
trail does not, and the operator's own logs are where the two halves sit one
above the other. The third route through the load gate is worth what its
weakest mode is worth: under `optional_no_ca` a **self-signed** client
certificate is an authenticated pusher and publishes an image nobody signed for
(#116), and the file bounds that precisely — `on` and `optional` refuse the
identical certificate with a 400 before brix's authz runs at all, which is to
say the module's TLS identity branch is safe only where nginx was already going
to be. The remaining three are what building the planes made cheap to see: every
refusal the module emits is audited `op=write`, refused `GET`s and `HEAD`s
included, while `GUARD_OP_READ` exists and is never used (#117); the
`WWW-Authenticate` challenge the module's own comment calls "part of the
contract, not decoration" drops the port it is listening on and names a
`/v2/token` endpoint that answers 404 `NAME_UNKNOWN` (#118); and `principal`,
which `brix_oci_registry_authz()` fills and its only caller discards, means no
log names who pushed — the string "anonymous" that the anonymous branch's comment
says "the access log distinguishes" occurs zero times in anything the instance
writes, and the pusher's `sub` reaches the log only from `brix_token`'s own
`[info]` line (#119). The mirror flag needed no runtime plane at all, which is
the sixth: `up->insecure` (`oci_merge.c:312`) is the only field the merged value
reaches and nothing reads it again, so once the upstream is `https://` the flag
has no effect in either arm (#120) and its whole subject is `nginx -t`.

File 33 takes the same shape to the WAF, and finds that the pair of flags there
is asymmetric in a way that hid both of its arms. `brix_guard` is `on` in eleven
configs and `off` in none — every "the guard is not running" control the corpus
has is an absence — while `brix_guard_default_signatures` is `off` in exactly one
config and `on` in none, because `on` is the merge default and writing it would
say what the merge already said. So for one flag the unwritten arm is the
securing one and for the other it is the permissive one, and neither had been
typed. The equalities hold: the written `off` and its omission answer a
seven-probe sweep cell for cell, and `default_signatures on` written out differs
from the merge default in exactly the one cell that carries an operator's own
signature. What the eight faces found is around the arms rather than in them.
An enabled guard with no profile and the built-ins off is, on the wire, the
disabled guard — `guard_ruleset_load_profile("")` allows every op and clears
`enforce_grammar` — and it still writes audit lines, so the only telemetry
httpguard has says the WAF is running while a scanner sweep passes it entirely
(#122); a misspelt profile name reaches the identical state and `nginx -t` says
nothing. The arm the corpus does write does not merely admit the built-in
probes, it audits them as ordinary missing files: `signal=notfound op=read
status=404`, the same line `/missing.txt` produces, in the log that is the
module's only signal since it publishes no metric (#121). The built-in
signatures are counted against the operator's own budget, so the ceiling is 51
and the diagnostic says 64 (#123). A disabled location's ruleset is never built
and therefore never validated, which makes `nginx -t` green on the config with
no protection and red on the one-line change that adds it — while
`bounce_status`, checked four lines earlier in the same function, is validated
under both arms (#124). And the one thing the never-written `off` can do that
absence cannot — carve a hole in a server-level guard — carves it out of the
audit trail as well (#125).

**How the subject was picked, which is worth more than the subject.** The
tranche's own census is a corpus grep for `<name> on;` / `<name> off;`, and by
file 33 it had drifted wrong in BOTH directions. It over-reports, because a
template slot is not a literal: `brix_opaque_strict {STRICT}`,
`brix_unix_trust_remote {TRUST_REMOTE}` and `brix_cms_state_relay {STATE_RELAY}`
are each filled with both tokens by the tests that render them, and each looked
like a gap. And it under-reports, because this tranche's own files write their
arms programmatically — `_flag("brix_cvmfs_bundle", "off")` in file 16i, an
f-string in file 32 — so work already delivered is invisible to it. The
re-derived instrument splits `src/**` on `ngx_string("brix_…")` and keeps only
entries whose next 300 characters reach `ngx_conf_set_flag_slot`, greps the
corpus with a value pattern that cannot match prose, and then cross-checks every
residue name against the tranche's own files by name rather than by token. It
puts the surface at **130 genuine flag directives**, of which **27** still look
incomplete and **14** genuinely are once the tranche's own programmatic arms are
credited: `brix_backend_async`, `brix_cache`, `brix_cache_store_endpoint`,
`brix_cvmfs_shared_cache`, `brix_data_substreams`, `brix_frm`,
`brix_frm_async_recall`, `brix_guard`, `brix_guard_default_signatures`,
`brix_health_check`, `brix_io_uring_admin`, `brix_io_uring_restrict`,
`brix_ssi` and `brix_webdav_storage_staging`. File 33 takes the two httpguard
names; the other twelve are the tranche's remaining list.
What entering those branches
for the first time found is below, and none of it is a coverage finding.

- **`test_audit16a_ocsp_flags.py`** (47) — `brix_ocsp_enable` on/off and
  `brix_ocsp_soft_fail` on/off, on FOUR GSI listeners in one process (off;
  on+soft on; on+soft off; on with soft_fail absent, which pins the merge
  default) over ONE trust store, against a **controllable OCSP responder the
  suite did not have** (`tests/lib/ocsp_responder.py`: `--entry
  CERT,ISSUER,VERDICT`, `--omit-nonce`, `--stale`, and a `/ctl/log` control
  plane that reports which certificate was actually asked about). Five
  credentials — good, revoked, unknown, an AIA nobody answers, and one with no
  AIA at all — give a 4×5 verdict matrix, and every cell is asserted.
- **`test_audit16b_ocsp_stapling.py`** (17) — `brix_ocsp_stapling` on/off, whose
  observable is a TLS handshake rather than a login verdict: three `brix_tls on`
  listeners in one process, probed with `status_request` set, plus the control
  that does not ask.
- **`test_audit16c_query_token.py`** (37) — `brix_http_query_token` on/off, the
  URL-borne bearer transport RFC 6750 §2.3 tells you not to use. Three WebDAV
  locations (on, off, absent) on ONE http listener sharing ONE access log,
  because the finding is not the verdict — it is what the log carries when the
  verdict is a refusal, and two processes writing two logs could not be compared
  line for line.
- **`test_audit16d_origin_reuse.py`** (33) — `brix_cvmfs_origin_reuse_conn`
  on/off, whose entire effect is `CURLOPT_FORBID_REUSE` + `CURLOPT_FRESH_CONNECT`
  and is therefore invisible from the listener: same status, same bytes, same log
  lines both ways. It is visible at the **origin**, as how many TCP connections a
  batch of fills costs, so the file reads it off a mock Stratum-1 started
  `--keepalive` and counts accepts. One warm-up fetch first, to take the origin
  selection and the RTT ranker's own per-thread connection out of the reading:
  after it the two arms are **0 accepts and one-per-request**, with no constant
  to explain away.
- **`test_audit16e_krb5_ip_check.py`** (40) — `brix_krb5_ip_check` on/off, the
  krb5 AP-REQ source-IP check. Three stream acceptors in one process off ONE
  realm, ONE principal and ONE keytab (on, off, and the directive unwritten),
  and the variable is the client's **source address**: an in-process TCP relay
  accepts on loopback and connects onward binding `127.0.0.2`, which is the only
  way to make the address the server sees differ from the address the ticket was
  issued for — the stock client cannot source-bind, and a second host is not
  available to a unit test. Getting a ticket that names an address at all takes
  `noaddresses = false` **and** `extra_addresses = 127.0.0.1` in the client's
  profile; without the second the KDC refuses the very next TGS-REQ, which
  arrives over loopback, and no service ticket is ever minted. With the
  instrument in place the table is unambiguous: matching address → login, from
  `127.0.0.2` → refused with `Incorrect net address` on the `on` plane and
  admitted on the other two. Three verdicts for one AP-REQ in one worker is also
  the statement that this flag really is per-server, which is the contrast the
  previous file's subject failed.
- **`test_audit16f_s3_location_flags.py`** (112) — the five S3 flags whose `off`
  arm was never written: `brix_s3_verify_chunk_signatures`,
  `brix_s3_allow_unsigned_session_token`, `brix_s3_token`, `brix_s3_list_cache`
  and `brix_s3_zip_access`, each on three arms (on, off, absent). Sixteen
  locations on ONE listener, which is forced rather than chosen — `s3_parse_uri()`
  reads the bucket out of the first URI segment, so an arm needs its own bucket
  and a location prefix spelling it, and locations are free where listeners cost
  a ledger slot. Every arm carries the same key, the same secret and the same
  region, so a verdict that differs between two of them cannot be explained by
  anything but the flag. The measured table: a forged per-chunk signature is
  refused on the `on` arm and stored on the other two, while a forged *request*
  signature is refused on all three — the flag narrows the chunk chain, not
  authentication; an unsigned `X-Amz-Security-Token` is `InvalidRequest` where
  the transport is enabled and `AccessDenied` where it is not, which is an
  earlier question being asked rather than the same one answered twice, and no
  arm refuses a request that carries no token at all; `brix_s3_token on` makes
  the location token-**only**, so the flag decides *who* refuses an anonymous
  request rather than whether one is refused; the listing cache is stale rather
  than wrong, keyed on the export root's own mtime, so a write into a
  subdirectory is invisible while a write into the root brings the hidden key
  back with it; and `?xrdcl.unzip=` is a member selector on one arm and an inert
  signed query parameter on the other two — refusing a traversing member name
  where it is armed, and never parsing one where it is not. §G is the parse tier
  for all five (values, arity, duplicates, and all four illegal placements: they
  are `NGX_HTTP_LOC_CONF` and nothing else), §H the six placements of
  `brix_backend_passthrough_persist`, which is where the seventh
  both-arms-unwritten directive ends.
- **`test_audit16g_pmark_flags.py`** (178) — the six SciTags packet-marking flags
  whose `off` arm was never written: `brix_pmark`, `brix_pmark_firefly`,
  `brix_pmark_flowlabel`, `brix_pmark_scitag_cgi`, `brix_pmark_firefly_origin`
  and `brix_pmark_http_plain`. Three of the six **default to `on`**, which makes
  the never-written arm the only way to reach the disabled behaviour at all —
  an untested half of a feature rather than an untested spelling of a default.
  Eighteen arms collapse onto thirteen locations on ONE listener, because the
  reference arm writes only the master switch and `http_plain` and is therefore
  simultaneously the `absent` arm of the other four; the listener is bound a
  second time on `[::1]` where the host has an IPv6 loopback, since the in-band
  technique refuses an AF_INET or v4-mapped peer before it reaches the kernel.
  The measured table, in the order the flags gate each other: the master switch
  off produces **no datagram and no counter at all** — not even
  `map_unresolved_total`, because the mapping is never consulted — and a client's
  `?scitag.flow=` cannot re-enable it from the wire; `brix_pmark_firefly off`
  stops the out-of-band report and leaves the **in-band flow label running**,
  which is the only configuration in which the two SciTags techniques can be told
  apart, and it is also #72 below; `brix_pmark_scitag_cgi off` refuses the
  client's flow-id and reports the site's own mapping instead (the arm that stops
  a tenant labelling its traffic as another activity), while an out-of-range
  `70000` is ignored rather than fatal on both arms; `brix_pmark_http_plain off`
  leaves a plain GET unmarked but **still marks a COPY**, because TPC is marked
  whatever the flag says (`webdav/dispatch.c:108-112`), so an operator who reads
  the flag as "packet marking off" is wrong; `brix_pmark_firefly_origin on` sends
  every datagram a second time to the client's own address at the fixed port
  10514, and #73 is that the copy is invisible; and the flow-label pair is
  asserted inside one worker over IPv6, with the IPv4 leg, the poisoned probe
  (#74) and the 32-label ceiling (#75) as three separate mechanisms. §G is the
  parse tier for all six on **both** planes the X-macro reaches — `NGX_HTTP_LOC_
  CONF` at `webdav/directives_zones.h:75` and `NGX_STREAM_SRV_CONF` at
  `root/stream/directives_pmark.h:10` — with values, arity, duplicates, four
  illegal placements, the case-insensitivity of `ngx_conf_set_flag_slot` (which
  is what makes the audit's step-2 grep sound), and the documented firefly-only
  root:// recipe pinned as a whole; §H pins the six merge defaults, the X-macro's
  two instantiations and the four source mechanisms the findings name.
- **`test_audit16h_shared_http_flags.py`** (241) — the six shared-http flags
  whose `off` arm was never written: `brix_read_only`, `brix_compress`,
  `brix_session_log`, `brix_verify_write`, `brix_strict_security` and
  `brix_backend_krb5_forwardable`. They are one group because they are six
  consecutive entries in `brix_http_common_commands`
  (`http_common.c:230-311`), all `BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG` into
  `common.*`, so each has **three** legal placements and inheritance is half of
  what a value means — which is why the config is one listener with **five
  `server_name` vhosts** and twenty-two WebDAV locations: a server-level arm
  needs a whole `server{}`, and another `server_name` on the same `listen` is a
  `server{}` that costs no ledger port. Nothing else is shared: each flag is
  measured against its own face. `brix_read_only` as the WebDAV write-method
  table (§A), where `off` is byte-identical to absent, a bare `off` over no grant
  stays 403 — `off` is not a write grant — and a server-level lock reaches a
  child while a child can take it back; `brix_compress` on the wire with raw
  bodies (§D), where a 1410-byte body compresses to 80 and switches to chunked,
  a 100-byte one does not (`BRIX_COMPRESS_MIN_SIZE` 256), `gzip;q=0` is honoured
  as a refusal, and the server's own preference picks zstd out of
  `gzip,deflate,br,zstd`; `brix_session_log` as records in one http-level brix
  access log (§E), attributed by object name because the log batches on a ~1 s
  timer, with `brix_access_log off` as the second way to reach zero records and
  the never-created file named `off` asserted absent; `brix_verify_write`
  against an origin that flips the first byte of what it stored (§C); and
  `brix_strict_security` at parse time only, as `nginx -t`'s verdict on three
  already-insecure subjects × {absent, off, on} × {location, server, http} — 18
  cells accept with `[warn]`, 9 refuse with `[emerg]`, same sentence plus
  `(refused: brix_strict_security on)`. §G is the parse matrix for all six:
  accepted in `location{}`, `server{}` and `http{}`, refused in the main
  context, and — measured, not assumed — **four of the six are also
  stream-declared** while `brix_compress` and `brix_strict_security` are
  http-only, every refusal reading `directive is not allowed here` and never
  `unknown directive`. §H pins the eleven source facts the findings rest on,
  including that `brix_http_common_merge_loc_conf` calls
  `brix_shared_adopt_unified` and nothing else.
- **`test_audit16i_cvmfs_resilience_flags.py`** (184) — the nine CVMFS
  resilience flags with no exercised `off` arm: `brix_cvmfs_bundle`, `_dict`,
  `_delta`, `_scrub`, `_learn`, `_swarm`, `_unified_origin`, `_trace` and
  `brix_scvmfs`. Seven had the token nowhere in `tests/` or `k8s-tests/`; `_trace`
  and `_unified_origin` had it in exactly one place each, a `_SINGLE_SHOT` row in
  `test_cvmfs_conformance_srv_config.py` that feeds a duplicate-**rejection**
  negative (no merge runs) and a load-only inventory (nothing is read) — see the
  method note. All nine merge to 0, so `off` and absent produce the same
  merged value and every reading is the observable the flag owns rather than a
  value comparison — which is why each of §A–§H reads its flag under
  **three** arms (`on`, written-`off`, absent) and the third is the control that
  says whether writing the token changed anything at all. The scopes are
  **not** uniform, and that was measured rather than read off the header: five
  are per-location (`bundle`, `dict`, `delta`, `unified_origin`, `scvmfs`),
  three register a service per **export** (`scrub`, `learn`, `swarm`) and one
  writes a process-wide latch (`trace`) — so every arm is a separate nginx
  **instance** on one ledger port, because two arms in one worker measure
  whichever merged last. §A the batch-fetch endpoint (a POST want-list answered
  as a `BXB1` frame, versus 405 twice over and a traversal want-list that is
  never parsed); §B the dictionary endpoint at both spellings (`current` and a
  40-hex id a client could already know) with the trainer proven silent on the
  closed arms; §C the delta encoder, where both closed arms answer **200** and
  the reading is the headers plus a byte-exact body, because an unlabelled short
  body would be worse than a refusal; §D the scrub, as a corrupted cached object
  evicted or served; §E the prefetch learner, trained down keep-alive
  connections and read at the **origin's** request log, because turning a
  prefetcher off has to stop the requests and not just the cache writes; §F the
  swarm roster, whose seed ring is written on every arm so the difference is the
  flag and not the peers; §G the unified-origin proxy face, where `on` serves a
  client-named **dead** authority from the location's own backend and all three
  arms refuse an authority outside `brix_cvmfs_upstream_allow`; §H the
  secure-CVMFS layer on a cleartext listener, where the arm decides the fate of
  every request including the manifest. §I is the inheritance matrix — seven
  flags × {child `off`, child bare} — and then `trace` on its own, because it is
  the one flag whose two faces disagree. §J is two cvmfs cache locations, which
  are one export. §K is the parse tier: the nine × two arms × three scopes, the
  three cross-checks the `off` arm **skips**, and the two-export silence. Four
  findings, three of them numbered.

- **`test_audit16j_root_caps_flags.py`** (134) — the five node-capability flags
  in `root/stream/directives_caps.h` whose `off` arm is written nowhere:
  `brix_metadata_only`, `brix_supervisor`, `brix_virtual_redirector`,
  `brix_collapse_redir` and `brix_recover_writes`. All five are
  `NGX_STREAM_SRV_CONF|NGX_CONF_FLAG` into `caps.*` and all five merge to 0
  (`conf_structs.h:537-548`), so `off` and absent are the same merged value and
  no reading here can be a value comparison — each arm is read as the observable
  its flag owns, and §A measures the equality every other section's `absent`
  control silently rests on: the whole 32-bit flags word of an all-five-`off`
  server against the reference's, then per-flag attribution of the bit each one
  owns. `test_protocol_flags.py` already owns the bit table, so this file borrows
  its `_get_protocol_flags` rather than restating it. **Ten stream servers in one
  process**, which is also the statement that the scope really is per-server —
  ten verdicts out of one worker — and two things in the config are deliberately
  *not* per-server: the manager registry and the collapse-redir cache are
  process-global (`brix_srv_select_or_blacklisted` and
  `brix_redir_cache_insert/lookup` take no conf), so the two collapse arms share
  one cache and are driven with different paths, their per-server gate being
  `conf->caps.collapse_redir` at the call site. §B isolates `brix_supervisor`
  from `brix_manager_mode` for the first time — the suite's only other supervisor
  writes both, and manager_mode alone already makes
  `brix_server_has_runtime_export()` false — over a `brix_storage_backend` the
  server asks for by path: the file is there, the tree is byte-identical to REF's,
  and the open fails, while the log names REF's export and never names the one it
  dropped. §C is the write-recovery journal and is #83. §D is
  `brix_virtual_redirector off` on a static-map node, which advertises the role it
  denies (#85), with the map-less server as the bound that keeps it a defect in
  the disjunct rather than in the flag. §E is the only reading in the suite that
  shows the collapse cache being *used*: a CMS listener plus a data node
  registering into it on a 2 s heartbeat, then the same path twice on each arm —
  `registry` then `redir-cache` where the flag is on, `registry` twice where it is
  off, both arms redirecting to the same data server, so a client cannot tell them
  apart and the flag changes only where the answer came from. §E's second class is
  #84. §F is `brix_metadata_only`'s other conjunct
  (`caps.metadata_only && manager_map == NULL`, `open_request.c:69`): with a map
  the refusal is skipped and the node redirects, while `kXR_attrMeta` is set from
  the flag alone — so a client is told "metadata only" by a node that will send it
  to data. §G is the two spellings of supervisor, which nothing in `src/` links:
  `brix_cms_role supervisor` neither advertises `kXR_attrSuper` nor costs the node
  its export, and the pair is asserted in one statement so the halves cannot
  drift. §H is the parse tier — both arms in a stream server, the
  case-insensitivity of `ngx_conf_set_flag_slot`, five bad values, arity,
  duplicates, and all four illegal placements (they are `NGX_STREAM_SRV_CONF` and
  nothing else, every refusal reading `is not allowed here` and never `unknown
  directive`) — and then the two cross-check classes that carry #86 and the
  `brix_server_guard_remote_authz` triple. Four findings, all four numbered.

- **`test_audit16k_cms_select_flag_arms.py`** (61) — the five cluster-selection
  flags of `root/stream/directives_cms.h` whose `off` arm is written nowhere:
  `brix_cms_affinity`, `brix_cms_locate_multi`, `brix_cms_fanout`,
  `brix_cms_stage_select` and `brix_cms_dfs`. All five merge to 0, so `off` is the
  same merged value as absent and every reading is the observable the arm owns.
  **No new config and no new ledger slot**: the parse tier is file 10's scaffold
  and the live tier is the parity wave's two-faced manager, driven by `FakeNode`s
  whose utilisation is chosen so that the metric and the path hash disagree by
  construction. §B reads the four arms whose `off` has a wire face — one redirect
  and no `Sr` list for `locate_multi off`; the utilisation pick surviving
  `stage_select off`; six polls that never redirect for `dfs off`, the cluster
  still probed with `CMS_RR_STATE` (pinning kXR_NotFound instead would be testing
  the negative cache, which `test_cms_parity_wave.py` owns, and without
  `brix_cms_emptylife` there is no negative entry to pin); and a single redirect
  with `CMS_RR_RM` forwarded to **neither** node for `fanout off`. §C is the
  finding: `affinity` and `locate_multi` are merged two lines apart in the same
  block and read at opposite scopes, so the identical disagreement between two
  servers resolves per-connection for one and process-wide for the other (#87),
  with the sibling-disagreement pair asserted both ways round and the documented
  path hash re-implemented in Python as a bucket→port bijection check.
- **`test_audit16l_relay_flag_arms.py`** (55) — the five relay/transport flags
  from the same header: `brix_tap_proxy`, `brix_tap_proxy_upstream_tls`,
  `brix_tap_proxy_upstream_tls_verify`, `brix_tcp_keepalive` and
  `brix_cms_tcp_keepalive`. Three have no written `off`; the last two merge to
  **1**, so there the never-written arm is the explicit `on` — a spelling a merge
  reading the wrong field would leave inert while `nginx -t` stayed happy. Again
  no new config: the TLS parse tier reuses `test_upstream_tls_verify.py`'s
  template, whose slot is a whole directive block, through the registry-free
  `nginx_t` (no ledger port, nothing started). The measured table:
  `brix_tap_proxy off` with the upstream line left in place still advertises
  **kXR_attrProxy** (#88), while the same `off` without the upstream clears it —
  one line moves the bit and it is not the flag; the whole fail-closed
  upstream-TLS audit is gated `proxy.enable && proxy.upstream_tls`
  (`runtime_server_tls.c:62`), so **either** flag's `off` arm silences the
  `[emerg]` that §B1's A-1 row exists to raise, and an explicit `verify on` is the
  only silent spelling (with a CA) yet still fails closed without one; and both
  keepalive arms are read off the kernel with `ss -tno`, where the reading had to
  be polled rather than sampled — ss prints only the *nearest* pending timer, so
  an unacknowledged segment shows `timer:(on,181ms,0)` and the keepalive timer
  queued behind it is not displayed at all, which is exactly the state a test that
  has just completed a handshake looks at. Both arms poll the same window, so a
  masked timer cannot make the negative pass.
- **`test_audit16m_guard_stream_arm.py`** (14) — `brix_guard_stream off`, the
  twelfth and last arm-gap in `directives_cms.h`, and the one whose subsystem is
  a security control. `test_stream_guard.py` already runs an unguarded relay, but
  it builds it by writing **no** directive, and the two routes to "disabled" carry
  different values: `relay.c:367` compares `relay_guard_enable == 1`, where absent
  is NGX_CONF_UNSET (-1) and a written `off` is 0. A comparison relaxed to `!= 0`
  would enable the guard for the unwritten case every other config in the tree
  takes, and nothing would see it — so the reading is a truth table on one probe:
  the `on` relay drops and logs `signal=notroot`, the `off` relay classifies
  nothing yet still carries a genuine kXR handshake, and the same instance
  reconfigured to the absent spelling behaves identically. Three relay slots exist
  on the ledger and all three were already in use, so the off-versus-absent
  comparison is `reconfigure()` + `restart()` in place — one port, one log, and
  nothing but the token under test differing between the halves.
- **`test_audit16n_webdav_module_flag_arms.py`** (115) — the five
  location-scoped flags of `protocols/webdav/module_commands.c` whose `off` arm is
  written nowhere: `brix_webdav` itself (:49), `brix_webdav_upload_resume` (:270),
  `brix_webdav_tape_rest` (:294), `brix_delegation_endpoint` (:303) and
  `brix_webdav_cors_credentials` (:377). They are one file because they share a
  declaration shape — `NGX_HTTP_LOC_CONF | NGX_CONF_FLAG` and nothing else, one
  setter, one merge — and need no TLS, no token, no stage registry and no second
  port to read: **one** http listener carries twenty locations across five
  `server_name` vhosts, and the vhosts exist only because two of the five gate an
  *absolute* URI prefix rather than the location they are written in, and a URI
  space holds exactly one arm per server. Four merge to 0 and
  `upload_resume` merges to **1** — so on that one the arm the corpus writes is
  the redundant one and `off` is the only spelling that turns the feature off at
  all, which is why every resumable-upload test in the tree had measured a value
  it did not need to write and nobody had measured the value that does something.
  For `brix_webdav` the merge is against the **parent location**, and since the
  flag is legal in no scope above a location a nested location is the only place
  that parent can be non-zero: inside a parent that wrote `on`, absent inherits
  `on` and only `off` disables the child — the one case in the file where the two
  spellings are not interchangeable, and unreachable without writing the arm.
  §A reads the switch as a method table rather than one verb, because
  `!common.enable` returns `NGX_DECLINED` from both the access-phase handler and
  the content handler (`access.c:416`, `dispatch.c:485`), so the location does not
  answer 403 — it stops being a WebDAV location and nginx's own static handler
  answers instead (GET 404, PUT/PROPFIND 405), with the security negative that the
  fall-through must not hand over the object that really is on disk. §B is one
  Content-Range PUT per arm: `on` stages the chunk, publishes nothing and returns
  200 + `X-Upload-Offset`, and refuses a non-contiguous start with 409 + the real
  offset; `off` never consults the header, so the same request is a whole-object
  PUT — and against a seeded ten-byte object the range is neither honoured nor
  rejected but ignored, replacing the object with the five-byte chunk. A client
  resuming an interrupted upload into a location whose operator wrote
  `brix_webdav_upload_resume off` destroys what it was resuming. §C and §D are
  the two absolute-prefix flags, read on both of the delegation flag's URI forms,
  with a fourth vhost carrying `tape_rest on` beside `delegation_endpoint off` so
  each verdict is attributable to its own flag and not to the vhost. §C's `off`
  arm answers **405**, measured rather than predicted and the sharper reading for
  it: a 404 would have been ambiguous between "the router declined this endpoint"
  and "the router never ran", while 405 can only come from the method table of a
  location that handled the request itself — POST is not a method a WebDAV export
  implements. §E reads the CORS flag twice over, because it is consulted twice:
  once to emit `Access-Control-Allow-Credentials` and once to decide whether a
  `*` allowlist entry may be answered with the literal `*` (`cors.c:68-71`), so
  over a wildcard the arm changes a *value* and over a concrete allowlist only a
  header — both pairs are measured, and the combination CORS forbids is asserted
  absent on all five arms. §J's parse tier adds the gate the `off` arm opens:
  `webdav_validate_webdav_enabled` returns `NGX_CONF_OK` without validating
  *anything* when the flag is zero, so a location whose `brix_export` names a
  directory that does not exist is refused under `on` and accepted **in silence**
  under `off` and when absent. One finding, #89, plus the namespace-shadowing
  observation below.
- **`test_audit16o_webdav_scoped_flag_arms.py`** (244) — the three remaining
  `module_commands.c` arm-gaps that are declared wider than a location:
  `brix_webdav_zip_access` (:405), `brix_webdav_require_digest` (:440) and
  `brix_webdav_dig` (:454), each
  `NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG`
  with `ngx_conf_set_flag_slot`, `NGX_HTTP_LOC_CONF_OFFSET` and a merge to 0
  (`config_merge.c:99`, `:112`, `:111`). The two extra scopes are the whole
  subject, because they are what makes an interesting `off` exist at all: in a
  location with nothing above it, `off` and absent are the same configuration and
  writing the token proves only that the parser takes it. What the corpus had
  never configured — for any of the three, in either arm, anywhere — is a value at
  **server** scope, and therefore the one thing absence cannot express: `on` in
  the `server{}` with `off` in one location beneath it, the per-location opt-out
  from an otherwise-enabled server. The file writes both halves of that ladder for
  all three flags (`/inherit/` writes nothing and inherits, `/opt-out/` writes
  `off`) *and* keeps the bare arms, because both readings are true at once and
  only the pair distinguishes them. One http listener carries eleven locations
  across **seven** `server_name` vhosts; the vhost count is set by
  `brix_webdav_dig`, which gates the absolute prefix `/.well-known/dig/`, so its
  four arms — server `on`, server `on` + prefix-location `off`, server `off`, and
  fully provisioned with the flag never written — cannot be adjacent locations in
  one server. §A reads `zip_access` on the **bytes** and not the status: both arms
  answer 200 for `GET a.zip?xrdcl.unzip=m.txt`, one with the 16-byte member and
  one with the 124-byte archive, because `get_zip_member_serve` declines before it
  looks at the query string (`get.c:158-160`) — which also means the `off` arm
  cannot refuse an escaping member name, and the five escapes that are 400 on the
  `on` arm (including the percent-encoded form, since `brix_zip_http_member_arg`
  unescapes before validating, `zip_http.c:61-65`) are all 200-with-the-archive on
  the `off` arm. §B is a nineteen-row header matrix over `require_digest`, and its
  shape is the finding: the flag is consulted at exactly **one** place, the
  `WEBDAV_DIGEST_NONE` arm (`put_body_digest.c:264-265`), so a digest that is
  asserted and wrong is 400 on **both** arms while every form the server cannot
  read — no header, unknown algorithm, empty value, no `=` — is 400 on `on` and
  201 on `off`. A deployment that leaves the flag off has not disabled integrity
  checking, only the requirement to assert one. §C reads `dig` on **which file
  answered**: the export is seeded with a real object under the reserved prefix
  whose bytes differ from the dig export's file of the same name, so the same URI
  and the same token yield the diagnostics endpoint's bytes on the `on` arm and
  the operator's object on all three `off` arms — with the two boundary rows that
  bound what the flag captures (the prefix itself declines on both arms,
  `dig.c:164-169`, and an unknown export name is 404 on both arms for two
  unrelated reasons, recorded as a row carrying no information). §D reuses file
  14's parse scaffold, which takes no position on which slot accepts, and asserts
  all three arms legal in `LOC_KNOBS`, `SRV_KNOBS` and `HTTP_KNOBS` — the third
  scope is read at parse tier only, since a value in `http{}` is the top of the
  merge chain for every server and cannot coexist with the bare arms. Two
  findings, #90 and the authorization-regime observation below.
- **`test_audit16p_proxy_certs.py`** (83) — the table's last arm-gap,
  `brix_webdav_proxy_certs` (`module_commands.c:228`):
  `NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG` with
  `ngx_conf_set_flag_slot`, `NGX_HTTP_LOC_CONF_OFFSET`, a merge to 0
  (`config_merge.c:85`) and an `NGX_CONF_UNSET` initialiser (`config.c:128`). The
  corpus writes `on` in **88** places and, before this file's template, `off` in
  **none** — and none of the 88 is read for a verdict, because the flag's entire
  effect is one OpenSSL call made once per `server{}` at postconfiguration:
  `X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(sslcf->ssl.ctx),
  X509_V_FLAG_ALLOW_PROXY_CERTS)` (`postconfig.c:247-253`). So the only
  observable is whether an RFC 3820 proxy chain gets through the handshake, and
  the arms cannot be vhosts on one listener the way file 15's were: an SSL_CTX
  belongs to a listening server and its verify parameters are set before the
  ClientHello. Three TLS listeners in one process, one per arm — server-scope
  `on`, server-scope `off`, and `on` written inside a `location{}` — are probed
  with four client credentials from `x509forge` (an RFC 3820 proxy, a legacy
  pre-RFC-3820 proxy, the plain EEC that issued both, and no certificate at all),
  giving a 3×4 grid in which **every** cell is asserted. §A is the grid: the armed
  listener serves the seeded bytes to the proxy chain, the `off` listener refuses
  it with `40:proxy certificates not allowed`, and the EEC row is 200 on all
  three arms — the attribution control that stops the proxy row being read as
  "TLS works here and not there". §B bounds what `on` admits: the legacy proxy
  (no `proxyCertInfo`, `CN=proxy` appended) is refused on every arm and for a
  *different* reason, `32:key usage does not include certificate signing`, so the
  flag admits RFC 3820 proxies and not "proxies"; the two credentials are pinned
  as differing only by that extension and as sharing an issuer. §C measures `off`
  against **absent** on one socket by emptying the directive in place and
  restarting — two routes to a clear flag that carry different values (0 from the
  merge, `NGX_CONF_UNSET` from the initialiser) and must reach the same verdict —
  and asserts the other two listeners are untouched by that restart. §D is the
  finding, #91. §E is the config-time census that disagrees with it, one
  `endpoint ready` block per location in configuration order. §F is the parse
  tier on file 14's scaffold: both arms legal in `SRV_KNOBS` and `LOC_KNOBS`,
  refused in `http{}`, in `stream{}` and at main scope with *directive is not
  allowed here* and never *unknown directive*, plus values, arity, duplicates,
  and the row that is the defect's parse-tier face — a server `on` with a
  location `off` beneath it parses clean and silently. §G pins the declaration,
  the setter, the merge, the initialiser, the 88-place census, and the sibling
  `brix_ssl_client_capath` (`module_commands.c:239`), declared in the same two
  scopes and read from the same server-level `wdcf` four lines below the flag —
  which is what makes #91 a property of the hook rather than of one directive.
  One finding, #91, and one harness lesson worth carrying: `x509forge`'s
  `not_before_days`/`not_after_days` are absolute offsets from a **frozen epoch**
  (`_EPOCH = 2026-01-01`), not from now, so a credential minted "7 days out" is
  already expired and is refused with `10:certificate has expired` before any
  proxy policy is consulted — which would have made §A's rows read exactly like
  §B's.

- **`test_audit16q_acc_engine_flag_arms.py`** (88) — the three acc-engine flags
  declared side by side in `src/protocols/root/stream/directives_auth.h`:
  `brix_acc_pgo` (:188), `brix_acc_resolve_hosts` (:202), `brix_acc_encoding`
  (:216), all `NGX_STREAM_SRV_CONF | NGX_CONF_FLAG` over `ngx_conf_set_flag_slot`
  and all merging to 0 (`server_conf_merge_security.c:70-72`). The census that
  found the gap had to leave `configs/` to find it: **no rendered template writes
  any of the three**, so the arms live only in test sources and prose, and the
  three files that reach this ground each stop one arm short —
  `test_acc_residual.py` writes `resolve_hosts on`/`encoding on`,
  `test_audit15f_acc_group_resolution.py` writes `pgo on`, and all three spell
  their control arm as **absence**, never as `off`. §A–§C are the six arms, each
  read through the verdict of a real `kXR_open` against an authdb whose rules are
  written so that exactly one flag can move each row: `pgo on` withdraws the
  supplementary-group grant (`g-supp` GRANTED → 3010), `resolve_hosts on` turns a
  reverse-DNS host rule from 3010 into GRANTED, and `encoding on` **swaps** which
  directory the rule `/a%20b` covers — both candidate paths are seeded, so no
  verdict can be a missing file. §D is the finding, #92: the same per-server
  question file 16 asked, asked of a header whose three flags answer it two
  different ways. §E is the finding's remote face — a single anonymous HTTP GET,
  itself refused 403, installs the process globals through the http plane's lazy
  table build (`auth/authz/acc/config.c:209-217`). §F is the parse tier on file
  14's scaffold across both planes: legal in `server{}` under `stream{}`, refused
  at main scope and in `http{}`, arity and value and duplicate rows — including
  the two planes' divergent invalid-value messages and the divergence that the
  stream plane refuses a duplicate while the http twin (`webdav`
  `module_commands.c:103,:111,:119` → `brix_acc_http_set_flag`) accepts the second
  silently. §G pins the six declarations, the two setters, the merge line, and the
  corpus census that is the gap's evidence. One finding, #92.

- **`test_audit16r_csi_flag_arms.py`** (82) — the two CSI integrity flags of the
  same header, `brix_csi_require` (:331) and `brix_csi_trust_fs` (:338), both
  `NGX_STREAM_SRV_CONF | NGX_CONF_FLAG` into `csi.*` and both merging to 0
  (`conf_structs.h:551-558`) under a master switch that merges to **1** — which
  is why the corpus wrote `on` for each of them and `off` for neither. **Four
  root:// acceptors over ONE export in one worker**, because both flags are read
  out of the per-server conf on every `kXR_open`
  (`read/open_resolved_file_finalize.c:68-88`) and the subject is what a given
  acceptor does with a file whose at-rest record is in a state the test chose:
  the payload is exactly three whole 4 KiB blocks, so the coverage rule is a
  property the file picks rather than one it trips over. §A is `trust_fs`, whose
  `on` arm is not a tuning knob but a change of failure mode — the acceptor
  serves the flipped byte, byte-for-byte, with `kXR_ok`, while the written-`off`
  and absent arms both refuse — and the same trusting acceptor **still writes**
  records for everyone else to verify, which is what separates it from
  `brix_csi off` (measured: that one records nothing). §B is `require` against a
  file with no record: refused `3019 integrity record missing`, distinguishable
  from a missing file (3011) and from an authorization refusal, and gating
  **reads only** — the open-for-write that creates the record it demands is
  granted, which is the only route an untagged export has into compliance. §C is
  #93 and §D is #94. §E is the coverage rule, measured rather than inferred: a
  read straddling the granule covers no whole block, so `csi_verify.c:47-53`
  verifies nothing and serves the byte the record knows is wrong — under
  `trust_fs off`, the arm an operator writes to be sure. §F is the parse tier —
  both arms at the declared scope in silence, every other placement refused by
  name, values, case, arity, duplicates, and the `brix_csi off` plus written-arm
  pair that parses just as silently. §G pins the declarations, the
  `NGX_CONF_UNSET`/merge pair that makes `off` and absent one value by two
  routes, the fact that these two names exist on the **stream plane only** (no
  http twin, so a WebDAV export cannot ask for either behaviour), the single
  reader of both fields, and the corpus census — including why
  `cmdscripts/gsi_trust_live.py`, which writes three `on` arms behind a
  built-`xrdcp` gate and spells its control as absence, is not a duplicate of
  this file. Two findings, #93 and #94.
- **`test_audit16s_krb5_delegate_arms.py`** (67) — `brix_krb5_delegate` on/off
  (`directives_auth.h:398`, `NGX_STREAM_SRV_CONF | NGX_CONF_FLAG`, merged to 0),
  the header's last arm-gap and the one where the unwritten arm is furthest from
  a spelling of the default. **Three stream acceptors over ONE realm, ONE
  principal, ONE keytab and ONE export in one worker** (on, off, and the
  directive unwritten), and the variable is the client's TICKET: the cache every
  other krb5 test uses, and one taken with `kinit -f`. Every verdict is the
  **stock `xrdfs`** — upstream's client, not this repo's — so the six-cell table
  says nothing that depends on the clean-room implementation: a forwardable
  ticket logs in everywhere and costs exactly **one `kXR_authmore`** on the armed
  plane and none on the other two, while a stock ticket is served by `off` and by
  absence and **refused** by `on` with `Unable to get forwarded credentials`. The
  round counts are read off an in-process relay that parses response headers and
  forwards every byte unchanged, so a relayed login is byte-for-byte the login
  the client would have made directly. Round-count and capture-marker evidence
  keep the refusal attributable to the arm rather than to the KDC: the challenge
  goes out in both cases, and the acceptor logs `krb5 delegation captured
  forwarded TGT for "alice"` only when round 2 comes back. §F is #95 and §G is
  #96. The parse tier reuses file 5's scaffold (`nginx_audit16eparse.conf`)
  rather than adding a near-identical copy — both arms at the declared scope,
  case-insensitivity, every other placement refused by name, and the
  plausible-synonym negatives where `0` is the dangerous direction because it
  reads as off and is not. §J pins the declaration, the merge default, the two
  sites in `src/` that touch the field, the MEMORY-then-FILE order of the
  capture, and the corpus census that found the gap — including why
  `test_krb5_delegation_e2e.py` and `test_krb5_delegate_load.py`, which write
  `on` and only `on`, are not duplicates. Two findings, #95 and #96.
- **`test_audit16t_compress_flag_arms.py`** (33) — `brix_read_compress` and
  `brix_write_compress` on/off (`directives_security.h:142,153`, both
  `NGX_STREAM_SRV_CONF | NGX_CONF_FLAG`, both merged to 0), the tranche's first
  PAIR of flags rather than a single one, and the clearest case yet of a large
  suite that cannot ask its own question: there are **nineteen
  `test_compression_*.py` files** and every one of them runs against the harness
  anon server, whose `nginx_shared.conf` writes both arms `on` — so the whole
  suite shares one configuration of the subject and none of it can say what
  `off` restores. The closest anything came,
  `test_compression_root_adversarial.py::test_qconfig_cmpread_advertises_codecs`,
  names the disabled form `cmpread=0` only to **skip** when it sees it, and
  `cmpwrite` had no capability coverage at all. **Four root:// acceptors over ONE
  export in one worker** — `on/on`, `off/off`, the pair unwritten, and a MIXED
  `read on, write off` — where the fourth is the point: both flags are read
  through one expression, `enabled = is_write ? conf->write_compress :
  conf->read_compress` (`read/open_request_opaque.c:71`), so a single shared bit
  or two transposed slot offsets would satisfy every both-on and both-off case
  and is visible ONLY where the directions disagree. Three observables per
  plane, none of them redundant: the advertised capability
  (`xrdfs query config cmpread|cmpwrite`, shelling out to the same client the
  existing file uses so a difference between the two can only be the plane), the
  negotiation result in the `kXR_open` reply (`cpsize == BRIX_INLINE_CMP_MAGIC`
  plus the codec ordinal in `cptype`), and the bytes themselves — a gzip frame
  that inflates to the plaintext on the armed plane, the plaintext itself on the
  disabled one. Absence is measured to equal `off` on both directions rather
  than read off `server_conf_merge_security.c:310-311`. The fail-soft contract
  gets its own section, on the ARMED plane so the refusal is attributable to the
  codec lookup and not to the flag: an unknown codec, an empty value and no
  opaque at all each degrade to plaintext with the open still `kXR_ok`, which is
  correct for an extension stock peers must never notice — and the file states
  plainly that it is not arguing with that, only measuring its consequence,
  which is that on a disabled plane "compression was refused" and "compression
  was never asked for" are byte-identical replies. §G pins the two flag-slot
  declarations, the merge defaults, the ternary, its `BRIX_CODEC_IDENTITY`
  return, the literal `"cmpread=0\n"` / `"cmpwrite=0\n"` the emitters spell, and
  that each emitter reads its own field and not the other's. One finding, #97.
- **`test_audit16u_ocsp_nonce.py`** (43) — `brix_ocsp_require_nonce` on/off
  (`conf_structs.h:30`, merged to 0 at `:533`), the last flag of the OCSP family
  and the only subject in the tranche whose gap needed the census's THIRD
  category to describe: both arms are unwritten literally, and the one place the
  directive reaches a config is a `{TLS_DIRECTIVES}` placeholder feeding
  `nginx -t`. A parse gate is not an execution, so `ocsp_request.c:224-230` — the
  CWE-294 replay guard — had never run. **Four GSI acceptors and THREE
  responders**, which is forced rather than chosen: the responder a login talks
  to comes from the leaf's `authorityInfoAccess` (`X509_get1_ocsp(leaf)`,
  `ocsp.c:143`), so the config cannot pick it and the certificate must, while a
  responder's nonce behaviour is an argv switch fixed at startup — one responder
  per behaviour is the only binding that leaves plane and answer independent.
  Four credentials cross all four planes for a 4×4 table: `echoed` (the
  control), `nonceless` (`--omit-nonce`, the subject), `mismatch` (a new
  `--wrong-nonce`, a deterministic bit flip rather than a random value so the
  negative has no passing day), and one with no AIA at all — the shape
  `xrdgsiproxy` actually mints, which is here the soft-fail control. The measured
  reading: the armed plane refuses a GOOD answer that omits the nonce **while the
  responder's own request log shows it answered GOOD**, the `off` plane admits
  the identical response with a warning, absence measures equal to `off` rather
  than being read off the merge, and a MISMATCHED nonce denies on all four —
  which is the boundary that says the flag's scope is "missing", not "checked at
  all", and the observable proof that `off` still SENDS a nonce (a mismatch is
  undetectable otherwise). The fourth plane answers the composition: `soft_fail
  on` admits the credential nobody vouched for and still refuses the replay case,
  so the two planes differ in exactly one cell of the four. §H pins why —
  `check_ocsp_response` returns -1 for a nonce deny and `ocsp_check_urls` returns
  on -1 immediately as the verdict it documents as never overridden — so a
  refactor that gives the deny its own code has to choose deliberately which side
  of `soft_fail` it lands on. One finding, #98.
- **`test_audit16v_tpc_off_arms.py`** (53) — the SEVEN
  `src/protocols/root/stream/directives_tpc.h` flags whose disarming arm the
  corpus never spelled, on **six acceptors in one worker over one export**:
  ARMED (every guard in the arm the corpus already writes), DISARMED (the seven
  unwritten tokens), ABSENT (none of the seven written, so the merge defaults
  answer), PULLING (disarmed but `allow_local on`, the destination of every live
  transfer), ORDERING (naming gate armed, address gate closed — the only plane
  where both would refuse, so its message says which ran first) and OVERRIDE (an
  explicit `brix_tpc_delegate off` beside a GSI tap proxy). Four arms are decided
  before a byte moves — `brix_tpc_source_guard` (`launch_prepare.c:284`, a string
  match run before any resolution), `brix_tpc_allow_local` (`:303`, whose refusal
  prints the merged values it decided on), `brix_require_pgwrite`
  (`write.c:232`, `kXR_Unsupported` for a data-carrying cleartext `kXR_write`)
  and `brix_tpc_delegate` — and three exist only mid-transfer on the
  destination's pull leg: `brix_tpc_require_source_size` (`source_stream.c:318`),
  `brix_tpc_outbound_tls` (`bootstrap.c:87`) and the default-on
  `brix_tpc_outbound_passthrough` (`launch_prepare.c:440`). The three are
  measured by subclassing `test_tpc_pull_integrity.py`'s splice and answering ONE
  streamid tag untruthfully — tag 4 with a `kXR_stat` body whose size token is
  not numeric (a source that answers and declines to declare a size, which is the
  case the gate exists for), tag 1 with `kXR_gotoTLS` set in the protocol reply —
  leaving every other tag alone, so each refusal is attributable to one flag.
  Every pull is driven on the raw wire rather than through xrdcp, which meant
  implementing the half of native TPC no test had driven: the initiating client's
  `kXR_open` of the SOURCE carrying `tpc.key`+`tpc.dst`, the registration
  (`open_tpc.c:165`) that the destination's `tpc.org` open later consumes — keys
  are single-use, so each transfer mints its own. ORDERING is the file's control
  for its own claims: five planes answer one URL with four distinct verdicts out
  of one worker, which is what makes every other result a fact about the flag
  rather than about the harness. Absence is measured to equal the disarming token
  on all four defaults-off flags instead of being read off the merge. One
  finding, #99, and it is the only arm here the operator does not actually own.
- **`test_audit16w_webdav_tpc_egress_off_arms.py`** (30) — the four
  `src/protocols/webdav/directives_tpc.h` flags that decide where an HTTP-TPC
  destination may DIAL, on **thirteen locations over ONE listener** — every
  directive in the subject is `NGX_HTTP_LOC_CONF`, so one server carries the
  whole cross and the planes cannot drift apart on anything but the knob under
  test, and one capturing TLS mock is source, sink and witness: it answers the
  pull, sinks the push, and records which credential (if any) travelled, which
  is the only observable for a refusal that must happen BEFORE any outbound
  leg. `brix_webdav_tpc_allow_local off` and `_allow_private off` are both
  answered by `tpc_thread_ssrf_preflight()` (`tpc_thread.c:136-171`, called
  `:339`) INSIDE the transfer thread, so each is measured as a 403 whose
  `"HTTP-TPC SSRF check blocked"` line the request thread has not yet written
  when the response returns — the file polls for it — and the private arm is
  pinned to a verdict rather than a failed dial by an elapsed bound (under 2 s
  against a configured `brix_webdav_tpc_timeout 3` at an unroutable
  `10.255.255.1`). The written `off` is measured to equal the omission on both,
  the merge defaults being 0 and 1. The same gate on the **marker** path is a
  second file: with `brix_webdav_tpc_marker_interval 1` the response commits as
  202 before the preflight — which is a private copy of it, in
  `tpc_marker_start.c:44-68` — runs, so the identical refusal surfaces only as a
  `failure\r\n` trailer at the end of a chunked body (`tpc_marker.c:239`), and
  the file asserts both shapes side by side (#100). `brix_webdav_tpc_source_guard
  off` is measured with `brix_webdav_tpc_source_allow` WRITTEN beside it: a
  disarmed guard permits a host its own allowlist does not name and audits
  nothing (#101), the omission again equalling the written `off`. ORDERING is
  the file's control for its own claims — one plane arms the naming allowlist
  (`webdav_tpc_source_guard()`, `tpc.c:244`, called `:372` on the request
  thread) with the address gate also closed, and its refusal carries the
  `signal=tpc_egress` audit line and NOT the preflight's, so the two controls
  are ordered by evidence rather than by reading. Last, the shipping default
  `brix_webdav_tpc_credential_forward on`: two locations authenticate for real
  (`brix_webdav_auth required` + `brix_webdav_token_config`, because
  `rctx->bearer_token` is set only by `webdav_verify_bearer_token`), and the
  caller's own minted token is observed arriving at an authority **no directive
  of that plane names** — the client chose it — which is what makes the naming
  guard, and not the token, the control that contains a credential: the guarded
  twin refuses the identical COPY, the source records nothing, and the token
  appears nowhere in the audit line. A COPY carries `Credential:` throughout,
  because `dispatch.c:297-302` classifies a `Destination:`-only COPY as an
  ordinary LOCAL copy that dials nothing — without it every egress assertion in
  the file would pass vacuously. Two findings, #100 and #101, both about what an
  operator can see rather than what the gate does.
- **`test_audit16x_stream_security_off_arms.py`** (32) — the last four arm-gaps
  in `src/protocols/root/stream/directives_security.h`: `brix_tls off` (63
  configs write `on`, none writes `off`), `brix_ztn_cleartext off` (18/0),
  `brix_zip_access off` (8/0) and `brix_zip_force_scratch off` (2/0), on
  **twelve listeners in one worker over one export**. Every one is
  `NGX_STREAM_SRV_CONF` with no MAIN arm, so a `server {}` is the smallest thing
  that can hold a value and each flag costs three of them — the written `off`,
  the omission, and the armed control — and the twelve answers coming out of one
  worker are themselves the per-server-independence proof. All four merge to 0
  (`server_conf_merge_security.c:249/251/312/316`), so each unwritten token
  spells the compiled default; the file measures that the token and the omission
  agree before attributing anything to either, twelve times, and they do.
  `brix_zip_access off` is the shape worth writing down: the flag gates one
  branch of the read-open resolver (`read/open_request_resolve.c:264`), so with
  it off the `?xrdcl.unzip=` opaque is never inspected and the client that asked
  for one 31-byte member is handed the whole 288-byte archive under `kXR_ok` —
  a missing member is not `kXR_NotFound` (`zip_member.c:345`) there but the
  archive, and the member-name traversal check (`open_extract_zip_member`,
  `open_request_opaque.c:166-170`, `kXR_ArgInvalid`) does not run at all,
  because nothing is resolving a member name. Both are asserted armed and
  disarmed side by side. `brix_ztn_cleartext off` is enforced TWICE and only the
  first gate had ever been reached: the login parms drop the ztn block
  (`session/login.c:323-325`), and a client that sends a ztn credential ANYWAY
  is refused `kXR_TLSRequired` at `auth/gsi/auth.c:222`. A token-only cleartext
  listener never gets there — with ztn withheld the login has nothing left to
  advertise and is refused outright, which is the cell `test_tls_require.py`
  already owns — so these planes say `brix_auth both`, the login succeeds on
  gsi, and the second gate answers for the first time in the corpus; the same
  token authenticates on the opt-in plane and a forged one is still
  `kXR_NotAuthorized` there, so the refusal is about the transport and the
  opt-in is not a bypass. `brix_tls off` is measured WITH the certificate and
  key configured on all three planes, which is the only arrangement that
  separates the two halves of `conf->tls && conf->tls_ctx != NULL && the client
  asked` (`session/protocol.c:65-66`): the armed plane answers `haveTLS|gotoTLS`
  and completes a real upgrade, the disarmed one answers neither bit while still
  serving cleartext, and a `kXR_wantTLS` client is refused
  `kXR_TLSRequired` "TLS required by client but not configured on this server"
  — the one place an off arm here produces an error rather than a silence.
  `brix_zip_force_scratch off` is the cell nothing had ever configured: the
  existing off arm omits the stage dir as well, so "the flag is off" and "there
  is no stage dir" — the two exits of `zip_stage_archive_maybe`
  (`zip/zip_member.c:302-307`) — had never been told apart. The observable is
  the `zip: archive staged to scratch (%O bytes)` INFO line and nothing else,
  because `xvfs_stage_fd` (`vfs_core.c`) mkstemps and immediately unlinks: an
  EMPTY stage directory is what both arms leave behind, which the file asserts
  so a change that stops unlinking is caught here rather than by a full disk.
  One finding, #102.
- **`test_audit16y_upstream_tls_verify_live.py`** (32) — the one arm-gap in
  `src/protocols/root/stream/directives_net.h` that decides a trust question:
  `brix_upstream_tls_verify` (2 configs write `off`, none writes `on`), driven
  live for the first time. The subject is not a new plane but a new PEER:
  `_test_audit16y_helpers.GotoTlsUpstream` answers the bootstrap, demands
  kXR_gotoTLS, presents a certificate the test minted, and — if the leg gets
  that far — reads the re-login and the forwarded client request off the
  encrypted side and answers with a `kXR_redirect` the client can see. That
  makes every verdict a wire fact: eight `stream {}` planes in one worker over
  one export, because the CA, the pinned name and the flag are all
  `NGX_STREAM_SRV_CONF` and a trust decision has no smaller unit than a
  `listen`, plus three stub upstreams, one per certificate, because which
  certificate a leg meets is fixed by which port it dials. The armed arm and the
  omission leave IDENTICAL traces (the merge default is 1, and the file asserts
  the two traces are equal rather than reading the merge), and the good plane's
  trace is the whole sequence: `handshake`, `protocol`, a CLEARTEXT
  `kXR_login` — `brix_upstream_build_bootstrap` (`net/upstream/bootstrap.c`)
  pre-sends all three frames in one write, which the stub must drain or TLS
  reads the login as the ClientHello — then `tls-established`, a SECOND login
  over TLS, the client's `kXR_open` forwarded, and the redirect back. A peer no
  configured CA signs is refused by OpenSSL itself (`SSL_do_handshake() failed
  … certificate verify failed`, client sees `kXR_ServerError` "upstream: TLS
  handshake failed") and the stub records that neither the login nor the
  client's request ever reached it. Chain and host are separated by a peer whose
  chain DOES validate under its own CA but whose certificate names another host:
  armed it is refused, and with `verify off` the identical peer receives the
  leg's login — which is what the config-time WARN's "UNVERIFIED … MITM-able"
  actually buys, measured rather than quoted. Two findings, #103 and #104, both
  of them cells that only an armed plane could reach.
- **`test_audit16z_webdav_mirror_arms.py`** (31) — the two mirror arm-gaps in
  `src/protocols/webdav/directives_net.h`: `brix_mirror_strip_auth` (written
  `on`, never `off`) and `brix_mirror_log_diverge` (never written). Seven
  `location` blocks one directive apart under ONE `listen`, because all three
  mirror controls are `NGX_HTTP_LOC_CONF` and a per-location flag needs no
  `listen` of its own, plus a `/metrics` location so the detector's own account
  of itself can be read next to its log. Two recording shadows
  (`_test_audit16z_helpers.RecordingShadow`), and there have to be two: the
  fleet's shared `mirror-shadow` answers one status and its capture is global
  session state, so a divergence — a mismatch of status CLASS — cannot be
  produced against it. The opt-out is measured, not quoted: the client's
  `Authorization` arrives at the shadow byte-for-byte, exactly once, a
  900-character bearer is not truncated, and no credential is invented when the
  client sent none; `brix_mirror_token` replaces the forwarded credential
  instead of joining it, so the second host is never offered two identities. The
  omission and a written `on` produce header blocks that compare EQUAL, which is
  the merge default measured rather than read. And the divergence flag has no
  observable arm at all: armed, unwritten, and armed-against-an-agreeing-shadow
  are indistinguishable, while `brix_mirror_requests_total` moves for the replay
  that disagreed — which is what makes it a dead detector rather than a leg that
  never ran. One finding, #105.
- **`test_audit16aa_webdav_redirect_arms.py`** (32) — the last arm-gap in
  `src/protocols/webdav/directives_net.h`, and the one the corpus had already
  claimed: `brix_webdav_redirect_dataserver off`, written by no config anywhere
  while `test_webdav_redirect_ds.py`'s docstring lists the off-path among its
  cases. Five locations one directive apart — `on`, `off`, unwritten, `off`
  with auth required, and `on` with no shared key — under one `listen`, on one
  instance whose stream faces are the manager (`brix_manager_mode on`) and the
  CMS server the registry is fed through, because the four producers of DECLINED
  in `rdr_eligible` are indistinguishable on the wire and only a populated
  registry separates "the flag is off" from "there was nowhere to send it".
  `_test_audit16aa_helpers.CmsNode` registers that node and answers the
  heartbeat for the file's lifetime; the fixture asserts registration before the
  first cell, so an unregistered node fails as itself rather than as a wrong
  verdict about the directive. `_test_audit16z_helpers.RecordingShadow` listens
  where `brix_webdav_redirect_port` points, which turns "the handoff went
  somewhere" into bytes this process received: following the `Location` reaches
  it, the four `brixrdr.*` parameters survive the trip, and the MAC recomputes
  from the shared key under the documented canon
  (`HMAC-SHA256(key, METHOD\npath\nexp\nusr\nvo)`) rather than being compared
  to itself. The off arm is measured on both sides — the same URI is 307 under
  `/on/` and 200 with its own bytes under `/off/`, a PUT that the armed location
  refuses to store lands in the export at the disarmed one, and the recording
  server hears nothing — and the unwritten arm's responses compare EQUAL to the
  written `off`'s in status, body and header names. Two cells belong to the half
  of §6.1 that accepts rather than emits: with the redirect arm off and
  `brix_webdav_auth required`, a valid signed CGI is served and a tampered,
  expired, foreign-key or path-replayed one is 403, fail-closed. One finding,
  #106, plus one observation that gets no number.
- **`test_audit16ab_admin_factor_arms.py`** (37) — the two arm-gaps of
  `src/observability/dashboard/module.c`, taken as one subject because between
  them they are the whole of what the dashboard exposes and to whom.
  `brix_admin_require_both` is written `on` in no config and `off` in none
  either; `brix_dashboard_vfs_browse` is written `on` and never `off`. Both
  endpoints are at fixed URIs and the combiner directive is `NGX_HTTP_LOC_CONF`
  alone, so the fourteen planes are `server_name` vhosts on ONE `listen` and one
  ledger port — the cheapest geometry in the tranche, and the only one available.
  Ten of them are the combiner: both factors configured and both satisfiable
  (`on`, `off`, unwritten), both configured with the allowlist pointed at RFC
  5737 TEST-NET-1 so it can never match (`on`, `off`), the allowlist alone
  (`on`, `off`), the secret alone (`on`, `off`), and neither. The verdict is read
  off 403 against 405 rather than 403 against 200, because `cluster/servers` is a
  POST route and the method check runs after the auth gate — every combiner cell
  is therefore a GET and side-effect-free, with one POST spending the write once
  to show the 405 is genuinely post-auth and one more showing the 403 is
  pre-body. The AND arm refuses an allowlisted peer with no bearer and with a
  wrong one; the OR arm admits both, and admits the correct bearer that the AND
  arm refuses for arriving from outside TEST-NET-1; the unwritten directive and
  the written `off` compare equal across all three request shapes; and with no
  factor configured every caller is refused, the real secret included, so the
  write API is closed rather than open. With ONE factor configured the two arms
  become indistinguishable — the finding, #108 — and a prefix of the secret and
  an empty bearer are both refused, which pins the length gate ahead of
  `CRYPTO_memcmp`. The other four planes are the browser: a location that takes
  its server's `on` away 404s while its silent sibling serves the census, the
  listing (the seeded file's type and exact size, the subdirectory as a dir) and
  a byte-exact download; the per-location opt-out and the bare-location `off`
  answer identically, which is the merge default measured; a missing cookie and
  a cookie forged under the wrong password are 401, a `..` path is 400, and the
  disabled plane 404s the unauthenticated caller too, which is the feature gate
  standing ahead of the auth check. The fourth plane arms the browser on a
  dashboard with no password, and gets the census and the file's bytes with no
  credential at all — #107.
- **`test_audit16ac_manager_mode_arms.py`** (57) — `brix_manager_mode`, the last
  never-`off` flag of the root/stream command table and the one with the largest
  blast radius: six configs write it `on`, none writes `off`, and the flag does
  not add a behaviour, it deletes one.
  `brix_server_has_runtime_export()` (`core/config/runtime_server.c:25-29`) has
  `!manager_mode` as its first conjunct and gates `brix_server_setup_export()`
  (`:190`), so a manager never turns its `brix_storage_backend` into an export at
  all; the open path is the other half, `brix_open_manager_dynamic` being entered
  only under `conf->manager_mode` (`root/read/open_manager.c:191-203`). The
  directive is `NGX_STREAM_SRV_CONF`, so a plane is a `listen` and the geometry is
  eight ports: the three arms, a CMS listener and a data node so the registry the
  manager selects out of is not empty, the auto-derivation pair, and an HTTP
  dashboard whose VFS census is the only way to read the export registry from
  outside the process. `on` answers kXR_redirect naming the registered data
  server — for a file its own tree HAS, which is what separates "the export was
  never made" from "the file was missing" — while `off` and absent serve their
  own bytes, accept a write into their own tree, refuse a missing file locally
  rather than deferring, and advertise a flags word without kXR_isManager that is
  byte-identical between them. The census is the deletion made visible: the
  manager's root is absent from it while the two unwritten arms' and the data
  node's are present. The security cells are the same statement from the other
  side — a kXR_new open on the manager creates nothing under the directory its
  inert backend named, the same request `off` does create it, and a traversal is
  refused by both — and three more say the census that carries §C is itself
  closed to an unauthenticated reader and leaks no export path in its 401. The
  parse tier carries the finding, #109: the escape hatch
  `net/cms/server_module.c:136-138` documents works only written BEFORE
  `brix_cms_server on`, and in the other order the config does not load at all.
- **`test_audit16ad_inert_config_surface.py`** (131) — the tranche's last two
  arm-gaps, `brix_webdav_open_file_cache_errors` (`on` written once) and
  `_events` (`off` written once), and what writing the missing arm turned out to
  cost: nothing, because the five-directive family they belong to is allocated
  and never consulted (#110). Eight locations on ONE ledger port — the WebDAV
  resolver maps the full request URI under the export root, so a prefix is
  already a disjoint subtree — carry four cache planes (the full family with
  both flags on, one with `_errors off`, one with `_events off`, and a control
  with not one directive of the family), three `brix_backend_passthrough_persist`
  planes, and a read-only plane carrying the full family. §A is built so every
  probe is one a live cache would FAIL: with `max=1024 inactive=1h`, `valid 1h`
  and `min_uses 1`, a file replaced by rename, one truncated in place, one
  deleted, and a 404 that a create has answered are all served correctly on the
  next request. §B and §C then say the stronger thing — with `os.utime` pinning
  mtime so ETag and Last-Modified compare, the eight-request fingerprint of each
  arm (missing GET, GET, HEAD, PROPFIND, OPTIONS, PUT, GET, DELETE) is
  byte-identical across all four cache planes and all three passthrough ones, so
  no configuration of either family is distinguishable from its absence. The
  passthrough planes are #35 measured live rather than a new finding — file 6
  wrote both arms at parse level, and every cell that pins #35 stops at
  `nginx -t`. §D reuses the 16j parse scaffold (which writes no directive of
  either family, so a duplicate case can be sure what it was shown) for thirteen
  diagnostics: the missing `max`, seven bad tokens including `MAX=8`, the
  duplicate, `off` accepted from ANY argument position — the contrast with #109
  — non-numeric `_valid`/`_min_uses`, the three illegal scopes, and the four
  satellite knobs accepted both beside no cache at all and beside one turned
  `off`. §E is the security tier and is written against the day the family gets
  a reader: the write gate still refuses PUT/DELETE/MKCOL on the read-only
  plane, a revoked permission is 403 on the next request rather than the cached
  200, a removed file is 404, and four traversal shapes — sent through
  `http.client` with `skip_host`, because `requests` resolves dot segments
  client-side and never lets them reach nginx — are refused identically on all
  five planes. §F is the silence: no log line at any level names either family.
- **`test_audit16ae_gridftp_gate_off_arms.py`** (170) — the three GridFTP gates,
  and the tranche's largest haul from one subject. `brix_gridftp_verify_write`,
  `brix_gridftp_require_allo_size` and `brix_gridftp_gsi` are all
  `NGX_STREAM_SRV_CONF` and all merge to 0, and both existing GridFTP files name
  their control arm "off" while rendering ABSENCE —
  `test_gridftp_allo_truncation.py` literally writes
  `extra = "brix_gridftp_require_allo_size on;" if require else ""` and calls the
  result `gw_lenient`. Eight gateways in one process over one shared export:
  five write planes (both disarming tokens written, neither written, both armed,
  and the two crosses) and three GSI planes carrying the SAME certificate, key
  and CA so the flag is measured apart from its material — without the PKI beside
  it, `gsi off` and "no GSI configured" are the same server, because
  `ftp_module_merge.c:142` only builds a context when `enable && gsi`. §A runs
  four ALLO shapes (short, exact, over-long, none at all) across the two
  disarmed planes and compares completion code AND committed bytes; §B does the
  same for `verify_write` over four payload sizes including zero, plus an
  overwrite. Then the compositions. §C: the plane with `verify_write on` and
  `require_allo_size off` answers **226** to a truncated upload while its mirror
  answers 550 — the flag that catches a truncation is the length one, not the one
  named for verification; no number, because `ftp_gateway.h:39-45` says plainly
  that it is a storage-persistence check and not a wire check, but worth stating
  because the two names point the other way. §D is #112, measured as a positive:
  a 100-byte file survives a `REST 10` STOR of 20 bytes with 226 and is still 100
  bytes, which is only possible if the verifier never ran — `brix_vfs_wverify_check`
  would have compared 20 against 100 and unlinked it. §E is #113: after a 550 the
  refused object keeps its final name, `SIZE` answers `213 2500`, RETR serves the
  bytes with a 226, a previous complete object is already overwritten, and the
  disarmed planes leave the identical file for a 226 — the whole difference the
  operator paid for is the reply code. §F is #111: the operator doc's §3
  "production form" gateway answers `230 Login successful` to `USER anonymous`
  and any password at all, and serves a full read-write session, because
  `ev_grp_login` sets `authed` on any PASS without consulting `gsi`. The rest of
  §F is the honest half — G_OFF and G_ABS answer identically to FEAT, three AUTH
  mechanisms, PBSZ, both PROTs and ADAT; the armed plane advertises
  `AUTH GSSAPI/PBSZ/PROT/DCAU`, answers 334, distinguishes 504 from 534 on
  `AUTH TLS`, refuses a garbage token 535 and a non-base64 one 501 and
  authenticates neither; and `PBSZ 0` draws `200` from all three, including the
  two that have just refused every AUTH with 534. §G reuses the 16j parse
  scaffold for both arms of all three flags in the one legal scope, eight values
  (with `ON`/`OFF` accepted, because `ngx_conf_set_flag_slot` matches
  case-insensitively — the contrast with the case-SENSITIVE parameter tokens file
  30 found one family away), three arities, the duplicate, four illegal
  placements each, the sibling override, and the GSI prerequisite in all four of
  its states. §H is the silence — no log line names any of the three — and §I is
  #114, the malformed `350 Restart position accepted (10ld)` that every one of
  the eight gateways emits. A no-number class beside it records what the REST
  parser does not reject: `9x`, `10abc`, `+5` and `0x10` are all accepted as
  their prefix (so a hex offset silently restarts from 0), and an out-of-range
  offset saturates to `LLONG_MAX`, is answered 350, and leaves a zero-byte object
  behind when the STOR that follows fails 550.
- **`test_audit16af_oci_security_arms.py`** (131) — the two `protocols/oci`
  flags whose securing arm no config in this tree had ever written, and what the
  load-time gate standing in front of one of them actually proves.
  `brix_oci_registry_allow_anonymous` is rendered `on` by
  `configs/oci_registry.conf`'s `ANON_LINES` slot, and the authenticating leg
  the whole D4.5 suite runs against is `registry_lane.registry_spec(...,
  anonymous=False)`, which sets that slot to `""` — the token `off` is a keyword
  argument's name and nothing else. `brix_oci_mirror_insecure` is `on` in
  `oci_mirror.conf` and `oci_compose.conf` and nowhere `off`. Seven registry
  fronts run in one process: four cleartext (open; the written `off` beside an
  issuer table; the same server with the line omitted; and both together, which
  no lane builds and `oci_registry.conf` has always permitted) and three TLS
  planes identical but for `ssl_verify_client on` / `optional` /
  `optional_no_ca` — the three modes `oci_ssl_verifies_client()`'s
  `sslcf->verify != 0` accepts as one. The template turns `access_log` ON at
  http level, which no other OCI config does, so §G's absence is the module's
  and not the fixture's. §A is the equality: eight request shapes (`POST
  blobs/uploads/`, `GET manifests`, `HEAD blobs`, `GET tags/list`, `DELETE
  manifests`, `PATCH` an unknown session, `GET referrers` and `GET /v2/`) answer
  identically on status, body and `WWW-Authenticate` across `off` and its
  omission, a scoped token publishes a pullable image on both, and the two
  stores hold the same file NAMES — which content addressing makes the strongest
  available form of "the same", since the names are the digests. §B is the open
  registry as the control (any credential or none is 202; no challenge is ever
  issued). §C is #115 and §D is #116, both above. §E is #117, three refusals —
  a `GET`, a `HEAD` and a `POST` — all audited `op=write`, with the rest of the
  audit line asserted intact so the finding is one field and not a rewrite. §F
  is #118: the realm and the `service` both drop the port, the advertised
  `/v2/token` answers 404 `NAME_UNKNOWN`, and the challenge is otherwise a
  perfectly well-formed Bearer header, which is the harder failure to notice.
  §G is #119 — the access log is asserted to EXIST first, then an authenticated
  push and an anonymous one are shown to produce the same line but for the port,
  and the pusher's `sub` is found only in `brix_token`'s own `[info]` line. §H is
  the parse tier on the shared 16j scaffold: both arms of both flags in their one
  legal scope (`NGX_HTTP_LOC_CONF`, narrower than the module's own
  `brix_oci_token_issuers`, so the merge's inheritance arm for both is
  unreachable rather than untested), the written `off` refused exactly as its
  omission is with the same diagnostic, all three ways out of the gate named in
  the refusal, six illegal values, three arities, the duplicate, four illegal
  placements each, and the mirror's http/https matrix including #120's
  inertness. Beside it, a no-number class records that `ON`, `On`, `"on"` and
  `'on'` are all accepted — `ngx_conf_set_flag_slot` matches case-insensitively
  and the parser strips quotes before the setter sees the value, so an operator
  grepping the corpus for either flag in lower case would not find the line that
  opened the registry. §I is the security-negative under #116's hole: a `..`
  that climbs out of `/v2/` is answered 404 by nginx's own normalization and
  never reaches the registry, a percent-encoded one is decoded and collapsed and
  arrives as an ordinary name — asserted on the `Location` the registry hands
  back, because a status code alone cannot tell a refusal from a rewrite — and
  a full push by the self-signed stranger under a normalizing name leaves the
  six other stores in the process byte-for-byte unchanged.
- **`test_audit16ag_guard_arms.py`** (99) — the two `net/httpguard` flags whose
  unwritten arm is the one an operator reaches for. `brix_guard` is `on` in
  eleven configs and `off` in none: every "the guard is not running" control the
  corpus has is an ABSENCE, so the two routes to `enable == 0` — an explicit `0`
  from `ngx_conf_set_flag_slot` and `ngx_conf_merge_value`'s default — had never
  been compared. `brix_guard_default_signatures` is the mirror image: `off` in
  `configs/nginx_guard_knobs.conf` and nowhere else at all, while `on` — the arm
  that carries the thirteen built-in scanner signatures, and the merge default —
  is written nowhere, so every enabling config in the tree relies on it silently.
  Eight guard fronts run in one process, one `location /` per listener because
  the guard classifies the whole `r->uri` (`guard_http_req.c:118`) and a matrix
  of sibling locations would have measured the location prefix as much as the
  arm: the written `off`; the same server with the line deleted; `on` with the
  second flag left to the merge; `on` with it written out beside an operator
  signature; the same with `off`; `on` with NO profile and no built-ins; and two
  inheritance servers writing `brix_guard` at SERVER level with one child
  location contradicting it in each direction — a shape no config in the tree
  has. Every face carries its own audit log, because
  `ngx_http_brix_guard_audit_log_slot` calls `ngx_conf_open_file` with no
  reference to `enable` and the disabled faces get a file that is created and
  never written. The sweep is seven probes wide: a file that exists, one that
  does not, one probe of each built-in signature KIND (SUFFIX `.php`, PREFIX
  `/.git`, SUBSTR `/.env` — one flag governs three code paths), the operator's
  own signature, and `PATCH`, which `method_to_op()` maps to `GUARD_OP_UNKNOWN`
  and is therefore the only clean grammar probe under `xrdhttp`, whose profile
  ALLOWS `PUT`, `DELETE` and `PROPFIND`. §A is the equality and it holds cell for
  cell, with a third face asserted DIFFERENT so the agreement is a property of
  the flag and not of a dead build. §B is what the absence-as-control gives up.
  §C is the merge default written out: the two columns differ in exactly one
  cell, the operator's own signature. §D is #121, §E is #122, §F is the
  inheritance and #125, and §G is the parse tier on the shared 16h scaffold —
  #123's budget arithmetic (51 accepted, 52 refused by a message naming 64, and
  the missing thirteen returned by `default_signatures off`, which is what proves
  the two sets share one array), #124's skipped ruleset build in four shapes
  including both inheritance directions, the `bounce_status` half that IS
  validated under `off`, three legal scopes and three refused ones for both
  flags, six illegal values, three arities and the duplicate. Beside them a
  no-number class records that a MISSPELT profile — `xrdhttps`, `XRDHTTP`,
  `webdav` — is accepted without a word, which is the second route into #122, and
  another that `ON`, `On`, `"on"` and `'off'` all parse, which is why this file's
  own census could not be a corpus grep.
- **`test_audit16ah_frm_hc_arms.py`** (66) — the three
  `NGX_STREAM_SRV_CONF | NGX_CONF_FLAG` flags of the cluster and tape planes,
  `brix_health_check`, `brix_frm` and `brix_frm_async_recall`: written `on`
  across the corpus and `off` in NOTHING, so every "the subsystem is not
  running" control the tree has is again an absence. They are one file because
  they are one merge boundary — all three merge to 0, all three gate a subsystem
  started once per worker, and two of the three gate the SAME one. §A and §D are
  the equalities and they hold: the written `off` and the deleted line produce
  the same process, cell for cell, on a plane whose companions
  (`brix_health_check_interval` and the rest, `brix_frm_queue_path`,
  `brix_frm_control_dir`, `brix_frm_stage_ttl`) are all still written, which is
  the shape an operator actually leaves behind when they turn a subsystem off
  rather than delete it. What the absence-as-control gives up is that nobody had
  ever measured the enabled arm's failure modes, and §B, §E, §F, §G and §H are
  five of them. #126: `brix_health_check on` with `interval 0` is accepted by
  `nginx -t`, starts nothing (`health_check.c:410` returns on the zero) and says
  nothing — the one configuration that is enabled and inert. #127: the manager's
  startup NOTICE formats msec with `%M` and follows it with a literal `s`, so a
  2 s interval logs `interval=2000s`. #128 is the tape plane's version of the
  same shape and the more serious one: `brix_frm on` with a queue path and NO
  `brix_frm_control_dir` passes validation — the merge's two diagnostics police
  `brix_frm_queue_path`'s presence and absoluteness — and is then cell for cell
  the disabled server, because `brix_init_server_stage_registry`
  (`process_server_init.c:129`) gates on `frm.enable && frm.control_dir.len`,
  and the field the operator was made to write is the one that does not matter.
  #129 is the other half: `brix_frm_queue_path` is demanded, validated, and read
  by no code outside its own merge; the directory is never created, opened or
  written, and under `off` even the validation is skipped, so the same absolute-
  path typo is an `emerg` on one arm and silence on the other. #130 and #131 are
  why the file runs a SECOND instance: the stage registry is a process
  singleton (`stage_request_registry.c:405`, a `static` struct behind an
  `if (reg->inited)` early return with no log), so in a process where ANY server
  block named a control dir, a sibling that named none is served by it anyway —
  its exports' LFNs land in the first block's journal and it answers QPrep for
  the first block's request ids — while a THIRD block's control dir is
  discarded in silence and the named directory stays empty. The observable
  throughout is one byte of the kXR_prepare response: `prepare_emit_stage`
  (`prepare.c:305`) returns the durable `seq.pid@host` handle when the registry
  enqueued and the legacy `"0"` when it did not. §J is the parse tier on the
  REUSED `nginx_audit16hparse.conf` scaffold — both arms of all three flags,
  six illegal values, the three-way scope refusal (`http`, `stream` main, and
  the absence of `NGX_STREAM_MAIN_CONF` on all three is #132: the parent branch
  of all three merges is unreachable, since no `prev` can ever be anything but
  `NGX_CONF_UNSET`), arities, duplicates, and both arms of every companion knob.
  One asymmetry falls out of that last group and gets no number:
  `brix_health_check_type bogus` is refused under `off` because
  `ngx_conf_set_enum_slot` runs at parse time and never consults the flag, while
  `brix_frm_queue_path` is checked by the merge and the merge is skipped — and
  the enum's diagnostic names the VALUE and not the directive, so on a server
  carrying six health-check lines the operator is told `invalid value "bogus"`
  and a line number.
- **`test_audit16ai_gridftp_write_gate.py`** (136) — `brix_gridftp_allow_write`,
  the fourth GridFTP gate and the one file 31 left behind: written `on` by
  **thirty-one** configs and `off` by none, so the tree's every read-only export
  is read-only by merge default. The two configs that mean to be one are both
  absences, and one of them says otherwise — which is #133, and is a defect
  found by reading the corpus rather than the code:
  `nginx_gridftp_metrics.conf:11` documents its `RO_PORT` gateway as
  "`brix_gridftp_allow_write off`, the security-negative path" and the block at
  `:48-52` carries no such line. The gateway is read-only anyway, so the suite
  resting on it passes, which is exactly how the mismatch survived; §K reads
  both files and states it as a measurement, with a companion cell on
  `nginx_gridftp_plain_ev_ro.conf`, which is read-only by omission too and whose
  header says so rather than claiming a line. §A is the equality across all
  seven verbs the gate governs and it holds, on the wire and on the disk: across
  four faces nothing on a disabled one reached the tree — no directory created,
  no file deleted, no rename, no mode change, no byte written. What the
  absence-as-control gave up is that nobody had measured the refusal PATH: the
  only live probe of a disabled gate anywhere in the suite was a single STOR
  (`test_gridftp_metrics.py::test_read_only_export_refuses_stor_as_forbidden`),
  one verb of seven, on the plane whose read-onliness is the omission. #134 is
  what the other six do: they refuse in total silence. A client that issues MKD,
  XMKD, DELE, RMD, XRMD, RNFR and RNTO against a read-only export moves **no**
  `brix_io_ops_total` row at all — not `forbidden`, not anything, the only
  counter that moves in the whole scrape being the login's `brix_auth_total` —
  and leaves an error log at `info` whose three new lines are all session
  lifecycle. A refused STOR does book
  `brix_io_ops_total{proto="gridftp",op="write",status="forbidden"}`, so the
  gateway can meter a refusal; six of its seven do not, and the comment above
  `ev_xfer_guards` that explains what it deliberately leaves unmetered
  ("protocol misuse … the verb never became an operation") does not cover any of
  them, because each of the six IS a requested operation with an authorization
  outcome. #135 is dead code found the same way: `brix_ftp_ev_cmd_rnto` tests
  `rnfr_set` and CONSUMES it before it tests `allow_write`, and `rnfr_set` is
  set in exactly one place — the tail of `brix_ftp_ev_cmd_rnfr`, behind the same
  gate — so on a read-only export RNTO always answers `503 RNFR required first`
  and the `550 Permission denied (read-only)` two lines below it can never be
  emitted. §F measures the reachability rather than reading it, including the
  repeated-pair shape that is the only way state from a failed pairing could
  arm one. #136 came out of asking what the gate does NOT cover: `SITE` is a
  bare `200 OK` with its argument never read (`ftp_ev_dispatch.c:259`), so
  `SITE CHMOD 000` on a read-only export is answered `200 OK` and the mode on
  disk is unchanged — nothing is bypassed, but a client is told a mutation
  succeeded on an export that refuses mutations, and `SITE EXEC` gets the same
  answer. §G pins an ordering worth keeping: the permission verdict is reached
  before the data-channel check, so a STOR with no PASV is `550` on a read-only
  face and `425` on a writable one, which is the direction that does not leak
  writability to a client that never opened a data connection. §C reads the
  merged flag off the runtime — `ftp_ev_io.c:292`'s `session start (export=…
  write=%d)` is the one place it is observable without provoking it, and it
  agrees on `write=0` for the written token and the deleted line — and gets no
  number only because the line exists and is right; that it is at `[info]`,
  which no production deployment runs, is the reason #134 bites. §J is the parse
  tier on the REUSED `nginx_audit16jparse.conf` scaffold, and #137 is its
  residue: `brix_gridftp_verify_write on` and `brix_gridftp_require_allo_size on`
  are both accepted, without a word, beside `allow_write off` — the
  inert-companion shape of #101 and #102, one merge function away from every
  fact needed to diagnose it.
- **`test_audit16aj_cache_store_endpoint_arms.py`** (281) —
  `brix_cache_store_endpoint`, and it is not a thirty-sixth flag so much as a
  different KIND of row: the one directive in the tree declared under a single
  name on BOTH planes, by two command-table entries with two different setters.
  `webdav/module_commands.c:74` is `MAIN|SRV|LOC_CONF|FLAG` behind a CUSTOM
  setter that writes `common.cache_store_endpoint` on the WebDAV loc-conf AND on
  the S3 one; `root/stream/module.c:239` is `STREAM_SRV_CONF|FLAG` behind stock
  `ngx_conf_set_flag_slot`. The corpus had written the name exactly twice, both
  `on`, both on the stream plane (`nginx_mu_sidecar_store.conf:25` and
  `cmdscripts/tier_remote.py:42`), so the **http declaration had never been
  written at all** — its custom setter had never run, and the dual write it
  exists to perform had never happened anywhere in this suite. The flag is the
  sole `allow_internal` argument of the reserved-name guard, at four call sites
  (`compat/path.c:61` for both HTTP planes, plus `open_request.c:205`,
  `stat.c:316`, `statx.c:232`), and `path.c:50-58` states its refusal contract in
  so many words: the answer is "404 (not 403) so the response does not
  distinguish an internal name from a genuinely absent one", covering "WebDAV +
  S3". §A is that contract measured on WebDAV, and it holds to the byte — the
  written `off` and the deleted line are one fingerprint across all seven
  reserved patterns, and each is byte-identical (153 bytes, one md5) to the 404
  a path that was never created gets, headers included. Four other planes do not
  keep it. #138 is the one that matters: `s3_resolve_key` (`s3/util.c:136-152`)
  reduces `brix_http_resolve_path_ex`'s 403/404/414 to a BOOLEAN and
  `handler_dispatch.c:288-305` maps the false to **403 AccessDenied**, so a
  reserved key answers 403 whether or not it exists while a plain absent key
  answers 404 NoSuchKey — the reserved-name POLICY is disclosed to a client that
  can read nothing, which is precisely the inference the 404 was chosen to
  prevent. WebDAV over the same export, the same flag and the same two keys is
  the control that makes it a defect rather than a status-code preference, and
  the armed arm answering that same absent key 404 is the control that pins it
  to the guard. #139 is the same call site's other half: the refusal books
  `brix_s3_events_total{event="access_denied"}` where the absence it is supposed
  to be indistinguishable from books `no_such_key`, measured as a delta with the
  whole eight-label family read back so "nothing else absorbed it" is a
  measurement too. #140 is a leak of the same shape one plane over and audible
  only on the wire: kXR_stat's error TEXT is `file not found` for a reserved
  name and `No such file or directory` for a genuinely absent one, both under
  3011, and the two swap when the flag does — while kXR_open, reaching the same
  guard, answers both with one string and is the control. #141 is the gap in the
  four call sites: **kXR_rm consults the flag nowhere**, so on the disarmed arm a
  client that cannot stat, open, statx or list a sidecar can still UNLINK it,
  and WebDAV's DELETE of the same name on the same export is 404 — two
  implementations of one rule disagreeing, not a deliberate read/write
  asymmetry. #142 and #143 are what the custom setter had to reimplement and
  did not: `off; on;` in one location parses clean in every http scope and the
  PERMISSIVE line wins (the `dav-dup.test` face serves reserved names), while
  the identical pair in a stream server is `"brix_cache_store_endpoint"
  directive is duplicate` — because the setter fills the slot itself and never
  reaches `ngx_conf_set_flag_slot`'s `if (*fp != NGX_CONF_UNSET)` — and its
  diagnostic drops nginx's pronoun, so one directive name has two spellings of
  one error and an operator grepping for either misses half. #144 is the hole
  the predicate's shape leaves: `brix_is_internal_name` tests the FINAL path
  component, so a reserved DIRECTORY hides only itself — `/adir.meta/` is 404 on
  the disarmed arm and `/adir.meta/inside.txt` is **200 on both arms**, root://
  stat agrees, and root:// dirlist enumerates the collection its own stat just
  refused. Nothing in the tree creates such a directory today, which is why it
  has never been reached; MKCOL on the armed arm creates one in a single
  request. #145 is three files that include `fs/path/reserved_names.h` with a
  "hide sidecars" comment and never call the predicate. §C is the merge's
  UNSET/0 distinction, which is the only reason the merge is a merge rather
  than a default and which an absence cannot express: a server-scope `on` with
  a bare child, an `off` child, and a re-asserted `on` child. §H is the
  asymmetry that is by design and worth pinning so it is not read as a
  regression — the four enumeration filters never consult the flag, so a
  sidecar can be fetched by name on the armed arm and can never be discovered by
  listing, identically on all three arms and on all three planes. §I is the
  security tier: nine spellings of one reserved name (percent-encoded dot,
  percent-encoded suffix letter, percent-encoded stem letter, `/./`, `//`,
  traversal up and back down, trailing slash, trailing `/.`) all 404 on the
  disarmed arm and all resolve to the same fifteen bytes on the armed one, an
  embedded NUL refused 400 by nginx before the guard is reached, and the
  near-miss controls that keep the guard from being read as over-broad —
  `keep.dat.CINFO` served (the comparison is `memcmp`), `keep.dat.cinf`,
  `keep.dat.cinfoX`, `keep.datxrd-tmp.1.2` and a bare `cinfo` served, and a bare
  `.cinfo`, whose whole basename is the suffix, correctly reserved. It also
  records a milder relative of #138 on the plane that otherwise keeps the
  promise: a CREATING verb whose target is reserved answers **409** — MKCOL of
  `*.meta/`, COPY with a reserved Destination — which is indistinguishable from
  "it already exists" rather than from "it does not", so the 404 rule holds for
  reads and not for creates. §J is the parse tier on the REUSED
  `nginx_audit16nparse.conf` scaffold and is where #142 and #143 are diagnosed
  rather than merely observed: four accepting scopes across the two
  declarations, two refusing ones (`http{}`'s outer level and `stream{}` main,
  both `not allowed here` and never `unknown directive`), arity and case-folding
  identical on both — everything nginx gave both setters for free matches, and
  everything the custom setter had to reimplement does not. A note on the
  fixture that cost a debugging pass and is now a test of its own: the
  `.xrd-tmp.` sidecar must be named with a LIVE pid, because the startup
  orphan-temp reaper (`config/process.c:43-72`) unlinks dead-pid temps before
  any request arrives — a temp seeded with a dead pid is 404 on the ARMED arm
  too, for a reason that has nothing to do with this directive, and §A now
  states both halves so a future reader does not read the reaper's work as the
  guard's.

  **All eight were then fixed, and the file was rewritten to pin the cure
  rather than the defect** — every paragraph above describes what the file
  MEASURED when it was written, and every class that pinned a defective answer
  now pins the corrected one with the defect kept in its docstring as the reason
  the cell exists. Two things the eight tests had not predicted came out of
  fixing them, and both are recorded against #138 and #141: an S3 DELETE of an
  absent key is 204 and not 404, so giving the reserved key the resolver's
  status alone would have left that one verb disclosing after every other was
  closed; and root:// dirlist was refusing nothing about the collection ITSELF,
  which is the same two-planes-disagree shape as #141 one opcode over. Neither
  was visible from the test file — the first came from probing the fixed binary
  face by face, the second from reading the one cell (`the hidden directory can
  still be listed`) that the #144 fix had turned into a statement about a
  DIFFERENT gap. The root-plane flag is now read at FIVE call sites, not three,
  and §K names them individually rather than counting them, so a sixth is a
  deliberate addition. §G's runtime duplicate face could not survive its own
  cure (a duplicate is now an `emerg`, so no running vhost can carry one) and
  moved to the parse tier; the vhost stays as the ordinary armed arm the pair
  used to resolve to. The predicate's widening reaches every caller in the tree,
  so the S3, WebDAV, root, dirlist-conformance, path-edge, fattr, error and
  cache families were re-run against the fixed binary — green, with the only
  failures being an unbuilt `client/bin/xrdcinfo` and three xdist-parallel
  interference cases that each pass serially.

Eighty-one defect candidates, and the first one is why the tranche exists:

- **DEFECT CANDIDATE #64 (security, pre-auth remote worker crash — FOUND AND
  FIXED IN THIS TRANCHE) — every completed OCSP round trip segfaulted the
  worker.** `ocsp_build_request()` handed the caller's `OCSP_CERTID` to
  `OCSP_request_add0_id()`, which takes ownership, while `brix_ocsp_check_cert()`
  kept using it for the rest of the AIA loop and freed it itself at
  `ocsp.c:175` — a use-after-free on a second AIA URL and a double free on every
  path that reached `OCSP_REQUEST_free()`, which is all of them, success and
  error alike. The trigger is entirely client-supplied: the responder URL comes
  from the `authorityInfoAccess` of the certificate the CLIENT presents, so any
  unauthenticated peer that offers a proxy carrying an AIA the server can reach
  kills the worker before authentication completes. It was invisible for as long
  as it was because no test had ever written `brix_ocsp_enable on` — the flag's
  both-arms-unwritten row in the table above is the defect's whole hiding place.
  **Fixed in the tree** (`ocsp_request.c`, `OCSP_CERTID_dup` so the caller's
  pointer is never transferred, which covers `brix_ocsp_staple_fetch()`'s
  identical usage as well); file 1 §G is the regression guard — four
  credentials, and after each the process must still serve a second login.
- **DEFECT CANDIDATE #65 (operability, a security control that refuses everyone)
  — `brix_ocsp_enable on` with `brix_ocsp_soft_fail off` rejects every ordinary
  GSI login.** The responder URL is read from the leaf, and the leaf on a GSI
  handshake is the *proxy*: a Globus/`xrdgsiproxy` proxy carries no AIA, no
  responder is found, no verdict exists, and the strict token refuses what it
  could not check. The configuration is not merely strict, it is undeployable
  against the credential HEP actually uses — pinned with a proxy of exactly that
  shape, plus the control showing every other plane admits it.
- **DEFECT CANDIDATE #66 (security theatre, the log says the opposite of the
  truth) — `brix_ocsp_staple_fetch()` has no caller anywhere in `src/`.** It is
  the only writer of `ocsp.staple_data`, so the buffer is NULL for the life of
  the process, `brix_ocsp_stapling_cb` can only return `SSL_TLSEXT_ERR_NOACK`,
  and no client ever receives a staple — while `tls_config.c:118-122` logs
  "brix: OCSP stapling enabled for TLS context" and three comments
  (`srv_conf_fields_cache.h:300`, `server_conf_merge_proxy_net.c:151`,
  `src/auth/crypto/README.md`) describe an `init_process`/reload hook that does
  not exist. An operator who writes the flag, greps the log and finds the NOTICE
  has been told the opposite of what is true. File 2 pins both halves — the
  empty CertificateStatus on the wire and the absent caller at the source — so
  that giving the fetch a caller trips a test rather than landing silently.
- **DEFECT CANDIDATE #67 (security, the flag that refuses a credential logs it
  instead) — `brix_http_query_token off` writes the refused URL token to BOTH
  logs, verbatim.** The redactor exists and works: `brix_http_redact_query_token()`
  (`core/http/http_headers.c:339-372`) overwrites the value length-preservingly in
  `r->args`, `r->unparsed_uri` and `r->request_line`, so `$args`,
  `$request_uri` and `$request` all come out clean. But `wt_parse_header()`
  reaches its two `wt_redact_query_token(r)` calls (`auth_token.c:299`, `:305`)
  only *after* the query fallback has been consulted, and with the flag OFF
  `webdav_bearer_from_query()` declines at `:272-274` and the function returns
  `NGX_DECLINED` at `:404-406` — above both. The arm an operator selects
  **because** they do not want tokens in URLs is the one arm that guarantees the
  token lands in the access log and the error log. File 3 §E pins both sinks.
- **DEFECT CANDIDATE #68 (security, the redaction is correct and runs too late)
  — even with the flag ON, any log line written before the token auth phase
  carries the raw request line.** Redaction happens inside that phase, so it
  cannot reach a line another phase has already written. The concrete instance
  is `[warn] brix_webdav: non-TLS connection, cannot verify GSI`
  (`protocols/webdav/auth_cert.c:481-484`), which fires once per request on a
  cleartext listener and quotes the request line in full — token included. The
  same request's access-log entry is clean, because it is written at completion,
  after the redactor ran: one request, two sinks, two answers. File 3 §E2 asserts
  the leak and the clean control side by side, so a fix that only moves the
  redactor earlier for one sink still fails.
- **DEFECT CANDIDATE #69 (correctness/operability, a location-level flag that is
  not per-location — and not even per-feature) — `brix_cvmfs_origin_reuse_conn`
  is decided for the whole worker by whichever cvmfs location merged last.** It
  is declared `NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|
  NGX_CONF_FLAG` (`protocols/cvmfs/directives_resilience.h:93-99`) and its merge
  writes a process-wide `static int g_origin_no_reuse`
  (`cvmfs_module_merge.c:270` → `s3_transport_setup.c:73`). Measured, through one
  unchanged location: **(a)** a sibling writing `on` discards this location's
  `off`; **(b)** a sibling writing *nothing* discards it too, because
  `NGX_CONF_UNSET` merges to 1 and is written to the global like a chosen value —
  so adding an unrelated repository export silently undoes the middlebox
  workaround an operator put on a different one; **(c)** the reverse costs every
  other export its keep-alive, one cold TCP connection and one cold congestion
  window per object, which is the entire cost the reuse path exists to avoid.
  **(d)** The blast radius is not confined to CVMFS: `s3o_apply_reuse()` is
  applied by the transport itself (`s3_transport_setup.c:481`) and sd_http — the
  plain `http://` storage backend, with no cvmfs in its configuration — drives
  the same `brix_s3_transport_t` vtable, so a `brix_cvmfs_*` directive in one
  location re-policies a plain HTTP tier in another, while that tier can never
  state a policy of its own (the setter's only call site is inside
  `if (conf->cvmfs.enable)`). This is #57's shape on a third directive, with the
  cross-feature leak added. Nothing is said at parse time and nothing at run
  time: file 4 asserts that an `info`-level log on the non-default arm contains
  no line naming the policy in force, so the operator has nothing to grep for.
- **DEFECT CANDIDATE #70 (observability, a security control that cannot be shown
  to have run) — `brix_krb5_ip_check on` is silently inert for the ticket a
  stock `kinit` produces.** `krb5_rd_req()` compares addresses only when the
  ticket carries any, and MIT's `noaddresses` defaults to true, so an addressless
  ticket walks past the enabled check from any address at all — measured, through
  the relay: the same credential that is refused from `127.0.0.2` when it names
  addresses is **accepted** from `127.0.0.2` when it does not. Whether the
  control does anything is therefore decided entirely in the *client's*
  `krb5.conf`, which the server operator neither writes nor sees. That much
  matches upstream `XrdSeckrb5 -ipchk` and is not a divergence. What is missing
  is any way to tell the two cases apart: the acceptor logs nothing when it binds
  an address, nothing when the ticket has none to check, and `brix_auth_total`
  counts an unchecked login exactly like a checked one — file 5 §C asserts that
  no runtime line anywhere names the check, and that the failure counter does not
  move. The one signal that exists is at config time, and it only reports what
  was *configured*: `krb5 auth configured … ip_check=on` (`auth/krb5/config.c:
  252-257`), one line per krb5 server. `src/auth/krb5/README.md:159` already
  calls the check best-effort, but with respect to address *families*, not this.
- **DEFECT CANDIDATE #71 (operability, a nested location that silently stops
  being an S3 export) — overriding any S3 flag in a child location takes the
  location out of the S3 handler entirely.** `brix_s3` is the one directive on
  this plane whose setter does more than fill a slot: `ngx_http_s3_set()`
  installs `clcf->handler = ngx_http_s3_handler` (`protocols/s3/module.c:201`).
  A handler is not inherited the way the merged loc conf is, so a child location
  written to change one flag —
  ```
  location /bucket/ {
      brix_s3 on;  brix_s3_bucket bucket;  ...
      location /bucket/sub/ { brix_s3_verify_chunk_signatures off; }
  }
  ```
  — inherits the bucket, the credentials, the storage backend and the override,
  and is then served by nginx's static handler: measured, a PUT there is **405**
  and a GET is a stock **404 with no `<Code>` in the body**, against an export
  that answers both one path segment up. Nothing diagnoses it at config time and
  nothing can — the flag slot has no view of which handler its location ended up
  with — and the surviving configuration looks complete, which is what makes it
  a trap rather than a mistake anyone would catch reading it back. It is
  standard nginx handler semantics (`proxy_pass` behaves identically) and the
  cure is one line, repeating `brix_s3 on;` inside the child; file 6 §B pins the
  pair — the same override with and without that line, one refusing the forged
  chunk its parent refuses and one accepting it — so the day the handler becomes
  inheritable, the test says so.
- **DEFECT CANDIDATE #72 (observability, a phantom backlog that grows for ever) —
  `brix_pmark_firefly off` counts every flow's start and can never count its
  end.** `brix_pmark_flow_begin` increments `brix_pmark_flows_started_total`
  unconditionally (`pmark/firefly.c:245`), while `brix_pmark_flows_ended_total` is
  incremented inside `if (flow->firefly_started && flow->pm->firefly)`
  (`firefly.c:257-259`). On a site that marks in-band only — exactly the
  configuration this tranche's never-written `off` arm selects — `started`
  climbs with every transfer and `ended` stays at zero, so `started - ended`, the
  obvious "flows in progress" expression for a dashboard, reads as an
  ever-growing pile of stuck transfers on a perfectly healthy server. Measured:
  three GETs on the `off` arm give started=3, ended=0, and nothing in the error
  log. Cure: count the end unconditionally (the flow ended either way), or stop
  counting the start when firefly is off. File 7 §B pins the asymmetry and the
  growth, so a fix inverts the test rather than passing silently.
- **DEFECT CANDIDATE #73 (observability, the one arm with a delivery risk is the
  one arm with no observability) — the origin firefly copy is neither counted nor
  error-tracked.** With `brix_pmark_firefly_origin on` each datagram is sent
  twice, once to every configured collector and once to the client's own address
  at the fixed `BRIX_PMARK_FF_PORT` 10514, but the second `sendto` is
  `(void)`-cast (`firefly.c:158-161`): measured, **four datagrams leave the box
  and `brix_pmark_firefly_sent_total` reports two**. The common case is worse than
  an undercount — the report is aimed at the peer's flowd, and a client that has
  nothing on 10514 produces no `firefly_dropped_total`, no log line and no
  difference of any kind from a client that received it. The exposition
  understates egress by exactly the factor the operator turned on. Cure: count
  and log the origin send like the collector send. File 7 §E measures both halves
  (a sink bound on 10514, then the same request with nothing bound).
- **DEFECT CANDIDATE #74 (silent loss of a REQUIRED technique) — the flow-label
  capability probe leases one fixed label EXCLusively and caches its refusal for
  the worker's life.** `brix_pmark_flowlabel_usable` leases
  `encode(BRIX_PMARK_EXP_MIN, BRIX_PMARK_ACT_MIN)` = `0x20004` toward
  `in6addr_loopback` with `flr_share = PMARK_FL_S_EXCL`
  (`pmark/flowlabel.c:86-103`), closes the socket, and stores the verdict in a
  per-worker `static int pmark_fl_usable`. A kernel flow-label entry outlives the
  socket that held it — measured on this host: still held at 6 s, free at 10 s —
  and while it exists any other exclusive lease of the same label is refused with
  `EPERM`, including the probe of a second worker, a reloaded worker, or a second
  brix on the same host. The loser runs firefly-only for its entire life with one
  NOTICE and **no metric at all**: `brix_pmark_flowlabel_failed_total` is only
  incremented by the per-flow lease (`flowlabel.c:134`), which a declined probe
  never reaches. This was observed unprompted *inside the new test file*, where
  the per-test lifecycle fixture starts a fresh nginx per test and one test's
  probe was refused by its predecessor's lingering lease. Worse, a **failed**
  lease refreshes the blocking entry (the kernel's `fl_release()` stamps
  `lastuse` on the `EPERM` path), so a server that keeps retrying keeps the
  blocker alive. Cure: a non-exclusive share — measured, `IPV6_FL_S_PROCESS`,
  `S_USER` and `S_ANY` each admit four sockets on one label where `S_EXCL` admits
  one — or no probe at all, since the per-flow lease already fails open. File 7
  §F reproduces it deterministically by holding `0x20004` itself, and pins the
  kernel's one-holder rule in a test that touches no brix code.
- **DEFECT CANDIDATE #75 (silent loss under load) — the per-flow label space is
  32 wide per (experiment, activity), and exhausting it stops the in-band
  technique with no symptom but a counter.** `pmark_flowlabel_lease` ORs five
  random bits (`BRIX_PMARK_FL_ENTROPY_MASK` = `0x000C0103`) into the structural
  label and leases the result exclusively (`flowlabel.c:123-131`), so one
  (exp, act) pair has 2⁵ distinct labels and each is held by its connection.
  Measured with 40 concurrent IPv6 flows on one activity: **22 stamped, 18
  refused** — and the refusals begin at the *second* flow rather than the 33rd,
  because the draw is random with replacement. Every refusal is fail-open, so all
  40 transfers completed; the only evidence is
  `brix_pmark_flowlabel_failed_total` climbing while the labels routers are meant
  to classify on stop arriving. The test asserts the pigeonhole bound
  (`set + failed == 40`, `set <= 32`, `failed >= 8`) rather than the sample, so it
  is exact without being a coin flip. Same cure as #74: the share is what makes a
  label scarce, not the entropy width.
- **DEFECT CANDIDATE #76 (wasted work and self-inflicted lockout on IPv4-only
  sites) — the capability probe runs before the peer-family gate.**
  `brix_pmark_flowlabel_apply` calls `brix_pmark_flowlabel_usable(log)` in the
  same condition as its `fd < 0` check (`flowlabel.c:158-160`) and only then asks
  `getpeername` what family the peer is. Every first marked request in a worker
  therefore performs the whole probe — a socket, an exclusive lease of the fixed
  label, and on refusal a NOTICE — **even over IPv4, where the result can never be
  used**. On a host where the probe succeeds that is worse than noise: the
  successful probe plants precisely the ~10-second exclusive blocker of #74, so a
  v4-only deployment manufactures the lockout it cannot benefit from. The sibling
  entry point disagrees — `brix_pmark_flowlabel_apply_addr` tests
  `dst->sa_family != AF_INET6` *before* it probes (`flowlabel.c:185-189`) — which
  is what makes this an ordering slip rather than a decision. Cure: move the probe
  below the family checks in `apply`, as `apply_addr` already has it. File 7 §F
  proves it by holding the label and driving an IPv4 GET: the NOTICE appears
  although the connection could never have been labelled, and the control on the
  `off` arm shows the flag really does stop brix touching the flow-label manager
  at all.
- **DEFECT CANDIDATE #77 (a directive with no reader on the plane that declares
  it) — `brix_backend_krb5_forwardable` is parsed on the http plane and read only
  on the stream plane.** The value is declared for all three http contexts
  (`http_common.c:230`), merged (`shared_conf.h:426`) and adopted into every
  child location (`http_common.c:438`), and the **only** reader anywhere in
  `src/`, `client/` or `shared/` is `op_path.c:548`, inside the root:// stream
  protocol's delegation SPN selection. An operator who writes it in a `location`
  under `http{}` — the placement the command table advertises — gets a config
  that parses, reloads, and does nothing, with no diagnostic at either time. The
  cure is a decision, not a patch: either the http WebDAV/S3 backend legs learn
  to honour it, or the entry loses `NGX_HTTP_*` and moves to the stream table
  where its reader lives. File 8 §F asserts the three http placements parse and
  pins the reader census by walking the tree, so the day a second reader appears
  the test fails and says which claim to retire. This is the same shape as #35
  and #34 (declared, merged, never consumed) but a strictly narrower one — the
  value *is* consumed, on the other plane.
- **DEFECT CANDIDATE #79 (a security-relevant `off` that a keep-alive connection
  ignores) — `brix_session_log off` does not silence a location reached over a
  connection whose FIRST request hit a logging location.** `brix_http_sess()`
  (`sesslog_conn.c:165-207`) looks the session record up per **connection**,
  returns the cached `record->sess` when it finds one, and only ever consults
  `conf->session_log` on the path that creates a record. Measured: one keep-alive
  connection, `/sl-on/` then `/sl-off/`, yields **one** session id and nine
  records — three of them ATTEMPT/RESULT/XFER naming the object under
  `/sl-off/`. The reverse order is clean (the `off` location logs nothing and the
  `on` location that follows opens a session of its own), which is what makes
  this a leak rather than a mis-merge: the decision belongs to whichever location
  the client happened to ask for first. For an export whose whole reason for
  `off` is that its paths are sensitive, the flag is honoured only for clients
  that open a fresh connection — and HTTP/1.1 clients do not. Cure: consult the
  location's flag on every request and suppress the record when it is off, rather
  than only when the connection begins.
- **DEFECT CANDIDATE #80 (a location-level flag that cannot be turned off, and
  the half that cannot be retracted is the half that discloses) —
  `brix_cvmfs_trace on` latches a process-wide global.** The merge
  (`cvmfs_module_merge.c:167-172`) is `ngx_conf_merge_value(conf->cvmfs.trace,
  prev->cvmfs.trace, 0); if (conf->cvmfs.trace) { brix_origin_trace_set(1); }` —
  no else — into `static int g_origin_trace_info`
  (`fs/cache/origin/s3_transport_setup.c:31-37`), read at `:208` as `level =
  g_origin_trace_info ? NGX_LOG_INFO : NGX_LOG_DEBUG`. Nothing in the tree ever
  passes 0, which file 9 §I pins by walking `src/` as well as by measuring. The
  directive has **two** faces and only one of them is retractable: the
  per-request `cvmfs-trace: client id= class= repo= path= cache= status=`
  (`handler_finalize.c:88,100`) is read off the location's own merged value and
  goes correctly silent, while `cvmfs-trace: upstream HEAD/GET <url> status=
  bytes= host= dur_ms= proto=` keeps writing at INFO. Measured in ONE config — a
  server that says `on`, a location that says `off` — as **4 upstream lines and 0
  client lines**. The upstream face is the one that matters: its lines carry the
  full origin URL, so a location that opted out is still publishing its origin
  topology into a log that may be shipped off-host, and the latch is
  process-wide, so a `trace on` on ANY cvmfs location in the config promotes the
  origin fetches of every other location — including, measured, a WebDAV
  location on a second listener that mentions no cvmfs directive at all. Same
  family as #57 and #58 (tranche 15) on a third directive; cure is the same
  one-line `else brix_origin_trace_set(0)` plus a per-request read, and the same
  caveat applies — a per-worker global cannot express a per-location value, so
  the honest fix is to plumb the location's flag to the emit site.
- **DEFECT CANDIDATE #81 (two exports silently become one, and the last one
  declared wins) — every cvmfs CACHE location in a config shares the export
  root, so a second export overwrites the first one's store AND its origin.** A
  cache node declares no `brix_cvmfs_root`, so `cvmfs_module_build.c:215-217`
  canonicalises it to `/`, and every per-export registration goes through
  `brix_vfs_backend_entry_get_or_create()`
  (`fs/vfs/vfs_backend_config.c:320-400`), which **overwrites** the entry it
  finds for that root. Two `location /cvmfs/<repo>/` blocks, each with its own
  `brix_cache_store` and its own `brix_storage_backend`, are therefore one
  export wearing two prefixes. Measured: a request through the FIRST location is
  cached under the SECOND location's store, and the first location's store stays
  empty. The blast radius is the row an operator actually hits — adding an export
  for a new repository whose Stratum-1 is not up yet takes the existing, working
  export **down**: its requests are sent to the new location's dead origin,
  retried until the client hold expires (504 at `client_hold`, 502 with a longer
  one), and the live Stratum-1 its own `brix_storage_backend` names is never
  contacted at all — asserted against the mock's own request log, which stays
  empty. Reverse the declaration order and the same config serves the first
  location's repository out of a Stratum-1 it never named. Nothing is said at
  either time: no parse diagnostic, no runtime one. That is a diagnostic gap with
  an in-file precedent — `cvmfs_module_build.c:315+` already WARNs about origin
  coordinates configured with no geo face answering, i.e. exactly this class of
  coherent-but-useless combination — so the cure is a decision plus a warning:
  either key the registrations on something that distinguishes two cache
  locations, or refuse/warn at parse time when a second cvmfs location
  canonicalises onto an export that already has a different store or origin.
- **DEFECT CANDIDATE #82 (a per-location flag that is really per-export, so a
  location's `off` does not protect its own objects) — `brix_cvmfs_scrub`,
  `_learn` and `_swarm` are registered against the export root.** Same
  mechanism as #81, and it is worth its own number because the consequence is
  not a lost setting but a flag that reads as honoured and is not:
  `cvmfs_module_build.c:281-315` registers the scrub, learn and swarm services
  keyed on `root_canon`, so a location that writes `brix_cvmfs_scrub off` has its
  cached objects checksummed and evicted by a **sibling** location's `on`.
  Measured all three ways: A-`off`/B-`on` evicts A's corrupted object,
  A-`off`/B-`off` does not (the control that proves it is the flag), and
  A-`on`/B-`off` evicts it too — declaration order is irrelevant, the export is
  shared rather than inherited. All three flags are declared
  `NGX_HTTP_MAIN_CONF|SRV_CONF|LOC_CONF`, so the language invites exactly the
  per-location reading that does not hold. Note what the parser does get right
  one scope down: two values of the same flag in ONE location are refused as
  `directive is duplicate` (§K), which is the check that is missing **across**
  locations. Cure is #81's, plus a decision about which scope these three should
  advertise.
- **DEFECT CANDIDATE #83 (integrity — a durability feature that discards one
  legitimate write and then permits the double write it exists to prevent) —
  `brix_recover_writes`' replay journal matches on `(offset, length)` alone, with
  no reconnect condition.** `brix_wrts_is_replay()`
  (`write/wrts_journal.c:78-92`) returns 1 for any write whose offset and length
  equal a journalled entry's; the write path consults it on *every* write
  (`write/write.c:120-134`, and the same gate on the vector and AIO paths at
  `write/writev_aio.c:94-95` and `core/aio/write.c:99-100`), not only on one that
  arrives after a reconnect. So the two halves of one flag are both wrong in
  opposite directions, and both were measured on a server whose only difference
  from the reference is this line. **First half:** `AAAA` at offset 0 then `BBBB`
  at offset 0, one handle, no disconnect — both writes answered `kXR_ok`, and the
  file holds `AAAA`. The client is told its write landed and it did not. The
  identical sequence against the `off` arm and the absent arm leaves `BBBB`, and
  `kXR_sync` between the two writes (which flushes the journal,
  `write/sync.c:91-94`) also leaves `BBBB` — so the protection is exactly as
  durable as a client's habit of not syncing. **Second half:** the journal is
  per-handle and zeroed on teardown
  (`connection/fd_table_teardown.c:205-208`), while the recovery a client
  actually performs is a **reopen** — so the replayed write arrives at an empty
  journal and is executed. Measured with different bytes, because two identical
  writes to a POSIX file are indistinguishable from one: write `AAAA`, close,
  reopen, write `BBBB`, and the file holds `BBBB`. The bound is asserted too — a
  2-byte write over a 4-byte one lands (`BBAA`), because the match is exact on
  both fields, which is deliberate (`wrts_journal.c:80-84` explains why
  range-coverage would be worse) and is why the defect is the equal-length case
  and not "the journal swallows overwrites". The server advertises
  `kXR_recoverWrts` throughout, which is what makes this a promise rather than an
  internal detail. Cure: gate the check on a recovery reopen and key it on
  something a replay preserves and a rewrite does not — the per-handle
  `wrts_gen` counter already exists (`core/types/file.h:229`) and is recorded but
  never compared.
- **DEFECT CANDIDATE #84 (a capability advertised by the one config shape that
  cannot implement it) — `brix_collapse_redir`'s cache is reachable only under
  `brix_manager_mode`, and the suite's only config that enables the flag has a
  static `brix_manager_map` instead.** The insert and the lookup both live inside
  `brix_open_manager_dynamic` (`root/read/open_manager.c:117` and `:164`), which
  the redirect entry point enters only when `conf->manager_mode`
  (`:196-203`); a static-map node is answered one branch further down
  (`:207-215`), which neither inserts nor reads. `tests/configs/
  nginx_collapse_redir.conf` — the only place in `tests/` or `k8s-tests/` that
  writes the directive — is exactly that shape. Measured on a server built to
  the same shape: two opens of one path, both answered `redirect`, never
  `registry` and never `redir-cache`; and on the manager-mode arm the same two
  opens give `registry` then `redir-cache`, so the instrument works. Meanwhile
  the flags word ORs in `kXR_collapseRedir` from `caps.collapse_redir` alone
  (`root/session/protocol.c:121`), with no reference to `manager_mode` — so that
  config tells every client the server collapses redirects while no code path in
  it can. The bound, stated because it caps the severity: a static map is already
  a local O(1) answer, so nothing is mis-served and no client caches anything
  wrong — what is wrong is that the feature's only recipe is inert and the
  advertisement does not know it. Cure: condition the bit on the mode that can
  honour it, and give the directive a documented manager-mode recipe. The
  premise is read off the tracked config at run time rather than asserted, so the
  pair fails the day the config gains `brix_manager_mode` and the finding retires
  itself.
- **DEFECT CANDIDATE #85 (a flag whose `off` cannot deny the role it names) —
  `brix_virtual_redirector off` on a static-map node advertises
  `kXR_attrVirtRdr` anyway.** The bit comes from
  `caps.virtual_redirector || (manager_map != NULL && cms.addr == NULL)`
  (`root/session/protocol.c:81-83`), and the second disjunct is unconditional:
  any node with a static map and no CMS parent *is* a virtual redirector as far
  as the wire is concerned. Measured — the arm nobody had written writes the flag
  `off`, carries a map, and sets the bit, together with the `kXR_isManager` the
  same expression emits — with the map-less server as the bound that keeps this a
  defect in the disjunct rather than in the flag (there, `off` reads clear). The
  reason it cannot be fixed by touching the flag alone is the general shape of
  all five directives in this file: they merge to 0
  (`conf_structs.h:537-548`), so at runtime a written `off` is
  indistinguishable from absent and the flag has no way to express "no" — a
  reader that wants to honour an explicit denial needs the `NGX_CONF_UNSET`
  tri-state to survive the merge. Cure: either that, or say in the directive's
  documentation that it can only ever add the role.
- **DEFECT CANDIDATE #86 (a flag that silently switches off another directive's
  config-time validation, so a typo'd origin URL becomes a clean start) —
  `brix_supervisor on` makes `brix_storage_backend` unvalidated.** The backend
  string is parsed only by `brix_vfs_backend_config_str()`, which is called from
  `brix_server_setup_export()` — and that function early-returns before it when
  `brix_server_has_runtime_export()` is false (`core/config/runtime_server.c:190`),
  which `caps.supervisor` alone is enough to make false (`:25-29`). Measured as a
  triple with the flag as the only variable: `brix_storage_backend
  "root://127.0.0.1:PORT/"` (one trailing slash, so the port parse fails) is
  `[emerg] brix_storage_backend: invalid remote origin host:port` with no flag
  (`fs/vfs/vfs_backend_config_s3.c:262-277`), **loads clean** with
  `brix_supervisor on`, and is refused again with `brix_supervisor off` — which
  makes the never-written arm the arm that puts a check *back*. The accepted run
  never names the backend it stopped reading, so nothing in the log connects the
  flag to the directive it disarmed. Two things sharpen it: an operator whose
  supervisor was mis-typed learns nothing until the day the flag comes off, and
  the codebase already knows how to refuse this pairing on a different axis —
  `brix_server_guard_remote_authz()` (`runtime_server.c:66-98`) turns the *same*
  remote backend plus one authorization rule into an `[emerg]` naming the mode
  the moment the flag is written, and the file asserts that triple beside this one
  (loads without the flag, refused with `on` naming `requires a runtime export`
  and `brix_export`, loads with `off`, and legal again over a posix backend). So
  the guard checks who may combine the two and nothing checks whether the value
  is even well-formed. Cure: validate the backend string unconditionally, or warn
  that it is ignored.
- **DEFECT CANDIDATE #87 (a per-server flag that is really a process-wide
  one-way latch, so one server block changes every other server's selection
  policy) — `brix_cms_affinity` cannot be turned off, by `off` or by omission,
  once any server in the file writes `on`.** The flag is merged per server like
  its neighbours — `ngx_conf_merge_value(conf->cms.affinity, prev->cms.affinity,
  0)` — and then, three lines later, `if (conf->cms.affinity) {
  brix_srv_set_affinity(1); }` (`core/config/server_conf_merge_cluster.c:227-232`)
  writes the process-global `brix_srv_affinity` (`net/manager/registry.c:16`).
  Nothing in `src/` ever calls it with 0, and the reader takes no conf at all:
  `if (brix_srv_affinity && st.n_fresh > 1) { best =
  st.fresh_cands[srv_sel_path_hash(path) % st.n_fresh]; }`
  (`net/manager/registry_select.c:392-393`) is the selection every server in the
  worker goes through. What makes it a defect rather than a documented
  process-wide knob is the line **immediately above** it:
  `conf->cms.locate_multi` is merged in the same statement pair and read as
  `if (!lc->conf->cms.locate_multi)` (`protocols/root/read/locate_manager.c:294`)
  — per connection, off the server's own conf. So two servers in one file that
  disagree get a per-server answer for one flag and a whole-process answer for
  the other, and the two are indistinguishable in the config. Measured as the
  asymmetric pair: a manager whose own arm is `off` while a **sibling** server
  block says `on` still returns the path-hash pick rather than the metric pick,
  and the same sibling disagreement over `locate_multi` resolves correctly for
  each server. The comment at the merge does say "process-wide, like the load
  weight", so the mechanism is deliberate — but the directive is declared
  `NGX_STREAM_SRV_CONF`, it accepts `off` per server, and the flag it is merged
  beside honours that scope; an operator has nothing to read the difference off.
  Cure: refuse `off` in a second server once one wrote `on` (the pattern the tree
  already uses for other set-once globals), or make the reader take the conf.
- **DEFECT CANDIDATE #88 (a capability bit that tracks the plumbing instead of
  the switch, so a disabled proxy still advertises itself as one) —
  `brix_tap_proxy off` with a `brix_tap_proxy_upstream` line left in place answers
  kXR_protocol with **kXR_attrProxy** (0x200) set.** The bit is
  `((conf->proxy.enable > 0 || conf->proxy.upstreams != NULL) ? kXR_attrProxy : 0)`
  (`protocols/root/session/protocol.c:85-86`), and the upstream setter populates
  `proxy.upstreams` with no reference to the flag at all
  (`net/proxy/directives.c:200-207`) — nor does anything refuse, warn about, or
  clear an upstream list whose proxy is switched off. Every proxy code path in the
  process is inert on that arm (`net/proxy/pool.c` and `connect_upstream.c` are
  only reached with the proxy enabled), so the advertisement is the *only*
  observable, which is why it is read from a client's point of view. Measured as a
  pair with one line as the variable: `off` **plus** the upstream sets the bit,
  `off` **alone** clears it. A client that routes on capabilities — TPC source
  selection and monitoring both do — is told this server will re-authenticate
  onward when it will not, and the operator's own switch is not what the wire
  says. Cure: OR the flag with the list rather than the list on its own, or refuse
  an upstream that no enabled proxy will ever dial. Note also that the whole
  fail-closed upstream-TLS audit is gated on the same conjunction
  (`if (xcf->proxy.enable && xcf->proxy.upstream_tls)`,
  `core/config/runtime_server_tls.c:62`), so this arm additionally silences the
  `[emerg]` that would otherwise refuse an unverified TLS hop — the config that
  advertises a proxy it will not run is also the config the TLS audit skips.
- **DEFECT CANDIDATE #89 (a reserved endpoint that is not at a place but at every
  place, because one of its two dispatchers matches the URI by suffix) — with
  `brix_delegation_endpoint on`, a `PUT` to **any** path in the export whose URI
  merely *ends* in `/.well-known/brix-delegation` is taken as a delegated-
  credential upload rather than written as a file.** The upload dispatcher
  compares the tail:

  ```c
  if (!conf->delegation_endpoint
      || r->uri.len < sizeof(delegation_path) - 1
      || ngx_memcmp(r->uri.data + r->uri.len - (sizeof(delegation_path) - 1),
                    delegation_path, sizeof(delegation_path) - 1) != 0)
  ```
  (`protocols/webdav/dispatch.c:184-190`), while its sibling — the gridsite
  `getProxyReq` form, twenty lines further down — anchors the identical string at
  the *start* of the URI (`ngx_memcmp(r->uri.data, deleg_prefix, prefix_len)`,
  `dispatch.c:203-207`). One of the two believes the endpoint lives at a fixed
  place and the other believes it lives everywhere, and that asymmetry inside one
  feature reading one flag is what makes this a defect rather than a design.
  RFC 8615 defines `/.well-known/` as a **path prefix** on an origin, so the
  suffix reading has no specification behind it either. Measured as a pair with
  one token as the variable: `PUT /de-on/deep/nested/.well-known/brix-delegation`
  is answered 401 by the credential endpoint and creates nothing, while the
  byte-identical PUT under `/de-off/` is stored as an object — with the parent
  collections seeded in advance on **both** arms, so the 401 cannot be the 409 an
  unprepared namespace produces. The consequence is a namespace an operator cannot
  reason about: any subtree a user can create a directory in becomes another
  delegation endpoint, and a client that legitimately stores a file at that name
  (a mirrored `/.well-known/` tree is the obvious case) has its body parsed as a
  proxy chain and its write silently discarded. Cure: anchor the upload form the
  way the gridsite form already is. Pinned twice — as the live pair, and as a
  source assertion on both `ngx_memcmp` calls, so fixing the dispatcher trips a
  test rather than landing silently.
- **DEFECT CANDIDATE #90 (security, integrity — one request header switches
  `brix_webdav_require_digest on` off, and also switches off verification of a
  digest the client did assert) — a PUT carrying `Content-Encoding: identity` is
  committed unverified, and its body is stored byte-for-byte.**
  `webdav_put_verify_ingest_digest()` returns before it consults the flag or the
  asserted digest:

  ```c
  ce = brix_http_find_header(r, "Content-Encoding", sizeof("Content-Encoding") - 1);
  if (ce != NULL && ce->value.len > 0) {
      return NGX_OK;
  }
  kind = webdav_digest_select(r, &alg, exp_hex, sizeof(exp_hex));
  if (kind == WEBDAV_DIGEST_BAD)  { return NGX_HTTP_BAD_REQUEST; }
  if (kind == WEBDAV_DIGEST_NONE) {
      return conf->require_digest ? NGX_HTTP_BAD_REQUEST : NGX_OK;
  }
  ```
  (`protocols/webdav/put_body_digest.c:253-266`). Skipping the check for a body
  the server is about to decode is deliberate and documented in the function's own
  comment — the digest describes the decoded bytes, and the staged fd holds the
  encoded ones. But `identity` is a **registered, available** codec
  (`core/compat/codec_core.c:65-67`, `http_token = "identity"`), so it passes
  `webdav_put_select_codec`'s 415 gate (`put_body.c:316-329`), takes no decode path
  at all, and reaches the skip as a bare verification-off switch. Measured on the
  arm that writes `brix_webdav_require_digest on`: a digest-less PUT is 400 with
  nothing stored, the same PUT plus `Content-Encoding: identity` is **201 with the
  body stored verbatim**, and `Digest: adler32=deadbeef` — 400 on *both* arms
  without the header — is likewise **201** with the header, so the second half of
  the bypass defeats verification of a digest the client asserted rather than
  merely the requirement to assert one. Two adjacent rows bound it and are pinned
  as fences: a present-but-**empty** `Content-Encoding` is 400 under
  `require_digest on` (the `ce->value.len > 0` half of the guard), and
  `Content-Encoding: deflate` over a body that is not deflate-coded is 400 on both
  arms — a codec that really decodes fails honestly. Only a no-op codec token
  bypasses, which is also the cure: gate the skip on the codec actually
  transforming the body (`put_body.c:247` already computes
  `bctx->put_codec != BRIX_CODEC_IDENTITY` for the threaded-write decision), and
  make "cannot verify" mean 400 whenever `require_digest` is set. Pinned as the
  four live rows plus a source assertion on the ordering, so a fix trips the file
  instead of landing silently.
- **DEFECT CANDIDATE #91 (security, a scope the declaration invites and the
  reader cannot honour) — `brix_webdav_proxy_certs` inside a `location{}` parses
  in silence and does nothing, in BOTH directions: `on` grants no proxy
  acceptance, and `off` under an armed server restricts none.** The scope mask is
  `NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG`
  (`module_commands.c:228`), so a per-export write is legal, and every other
  `brix_webdav_*` flag in that table is read per location. This one is read once
  per `server{}`:

  ```c
  ngx_http_conf_ctx_t             *ctx = cscf->ctx;
  ...
  wdcf = ctx->loc_conf[ngx_http_brix_webdav_module.ctx_index];   /* :237 */
  ...
  if (wdcf->proxy_certs) {
      param = SSL_CTX_get0_param(sslcf->ssl.ctx);
      if (param) {
          X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_ALLOW_PROXY_CERTS);
  ```
  (`protocols/webdav/postconfig.c:230-256`), called from
  `webdav_postconf_setup_servers` over `cmcf->servers` alone
  (`postconfig.c:347-356`) — a loop that never walks a location tree, so the
  `loc_conf` it dereferences is always the **server's**. Measured on three
  listeners in one process, with an RFC 3820 proxy chain and the plain EEC that
  issued it:

  | client credential    | server `on` | server `off` | location `on` |
  |----------------------|-------------|--------------|---------------|
  | RFC 3820 proxy chain | 200 + bytes | 400          | **400**       |
  | plain EEC            | 200 + bytes | 200 + bytes  | 200 + bytes   |

  and the location-scope listener logs the `off` arm's own refusal —
  `40:proxy certificates not allowed, please set the appropriate flag` — while
  the startup INFO census of `enabled X509_V_FLAG_ALLOW_PROXY_CERTS on SSL
  context for server …` names only the server-scope arm. The mirror is inert
  too, and that is the half that makes this a security finding rather than a
  usability one: a `location{}` writing `off` beneath a server that wrote `on`
  (the corpus's only `off`, added by this file's template) still admits the proxy
  chain, so an operator cannot carve a proxy-free export out of an armed server
  either. **The sharpening:** `webdav_log_endpoint_summary` computes its
  credential census from the **location's** own flag (`config.c:247-248`,
  `has_x509 = (cadir.len || cafile.len || conf->proxy_certs)`), so the inert
  location is the one export that announces `credentials accepted:
  x509/GSI-proxy` and earns `NOTE: x509/GSI is accepted but no CRL is configured
  — REVOKED certificates will be ACCEPTED` — a revocation warning about proxies,
  on a socket that refuses every proxy — while the `off` subtree advertises
  nothing and admits them. Config time and runtime disagree in opposite
  directions at the same two places. The cure is one line either way: narrow the
  mask to `NGX_HTTP_SRV_CONF`, which is the placement the hook can honour and the
  one the sibling `brix_ssl_client_capath`'s own comment already claims
  ("Server-level, like `brix_webdav_proxy_certs` above", `module_commands.c:239`),
  or diagnose a location-scoped write at merge time. Not a property of one
  directive: that sibling is declared in the same two scopes and read from the
  same server-level `wdcf` four lines further down the same hook, so it inherits
  the same silence. File 16 §D and §E pin what the code does today and name the
  arm each row measures, so a fix in either direction trips the file.

- **DEFECT CANDIDATE #92 (authorization, a per-server flag that is a process
  global — file 17 §D/§E).** `brix_acc_pgo` is declared
  `NGX_STREAM_SRV_CONF | NGX_CONF_FLAG` and stored per server
  (`directives_auth.h:188`, `NGX_STREAM_SRV_CONF_OFFSET`, merged to 0 at
  `server_conf_merge_security.c:70-72`), and every reader of the acc engine sees
  it as a **process global** instead. `brix_acc_build()`
  (`auth/authz/acc/config.c:40-53`) hands the server's flag to
  `brix_acc_groups_set_primary_only()`, which writes the file-static
  `acc_primary_only` (`groups.c:33/43`); `brix_acc_init_server` runs once per
  server (`process.c:235` → `process_server_init.c:438`), so **the last
  engine-carrying server in configuration order decides for every server in the
  worker**. Measured, three stream listeners in one process, one authdb, one
  identity holding a supplementary group that a rule grants:

  | A | B | C | `g-supp` on A | on B | on C |
  |---|---|---|---|---|---|
  | `pgo on` | engine, flag unwritten | — | 3010 | **3010** | — |
  | `pgo off` | `pgo on` | — | **3010** | 3010 | — |
  | `pgo off` | `pgo off` | `pgo on` | **3010** | **3010** | 3010 |
  | `pgo on` | `pgo on` | `pgo off` | **GRANTED** | **GRANTED** | GRANTED |

  Every bolded cell is a server being answered by another server's flag, in both
  directions: a server that wrote `off` withdraws grants it was configured to
  make, and a server that wrote `on` makes grants it was configured to withhold.
  The attribution is controlled rather than assumed — the two flags declared
  beside it in the same header, `brix_acc_resolve_hosts` (:202) and
  `brix_acc_encoding` (:216), are read from the server's own config on every
  consultation and measured per-server in the same three-listener process (file
  17 §D), so this is a property of `pgo`, not of the harness. **Three channels
  make it worse than a config-order surprise.** (1) The per-user gidlist cache is
  process-wide with TTL `acc_gidlifetime` (default 43200 s), so which flag a
  request sees also depends on *when* the first lookup for that user landed. (2)
  The http plane builds its acc tables **lazily**, on first request
  (`config.c:209-217`), so the globals can be installed **after** startup by a
  single anonymous HTTP GET that is itself refused 403 — file 17 §E measures a
  stream verdict flipping because of a request to a different plane that was
  denied. (3) `brix_acc_build()` installs `gidlifetime`, `nisdomain` and
  `gidretran` through the same call, so the whole family rides the same
  last-writer-wins, and `test_audit15f_acc_group_resolution.py` inherits it. The
  cure is one of two lines: carry the flag on the engine handle so each server's
  lookups read their own value, or narrow the declaration to
  `NGX_STREAM_MAIN_CONF` and diagnose a second, differing write — which is what
  the code already means. File 17 §D and §E pin today's behaviour and name the
  arm each row measures, so a fix in either direction trips the file.

- **DEFECT CANDIDATE #93 (data integrity, a fail-closed control silently
  disabled by a performance one — file 18 §C).** `brix_csi_require on` does
  nothing at all in a server that also writes `brix_csi_trust_fs on`. Both are
  plain per-server flags declared twelve lines apart
  (`directives_auth.h:331`, `:338`) with nothing to suggest an ordering, and an
  operator writing both is asking for the strict reading of each: record every
  file, refuse anything unrecorded, and skip the per-read CRC because the
  filesystem already checksums. What they get is the skip and not the refusal,
  because the `require` test is **nested inside the branch `trust_fs` turns
  off**:

  ```c
  if (conf->csi.enable && S_ISREG(st->st_mode)
      && !(conf->csi.trust_fs && !is_write))          /* :68-70  */
  {   ...
      if (!is_write && crc == BRIX_CSI_NOTAGS
          && conf->csi.require)                       /* :83-85  */
      { ... kXR_ChkSumErr, "integrity record missing"); }
  ```
  (`protocols/root/read/open_resolved_file_finalize.c`). Measured, one untagged
  file, four acceptors in one worker, one export:

  | acceptor                   | untagged read | corrupt read |
  |----------------------------|---------------|--------------|
  | `require on; trust_fs on;` | **GRANTED**   | **GRANTED**  |
  | `require on; trust_fs off;`| 3019          | 3007         |
  | `require off;`             | GRANTED       | 3007         |
  | `brix_csi off;`            | GRANTED       | GRANTED      |

  The first row is the one an operator would call the strictest configuration in
  the table, and it is indistinguishable from the last — the engine off
  entirely — on both readings. Writing the two directives in the other order
  changes nothing (measured, §C), because the nesting is in the C and not in the
  parse. **Nothing says so at any point.** `nginx -t` accepts the pair in
  silence with no advisory; the worker's startup census, which does announce the
  export, the mode and the auth scheme (`brix: root:// endpoint ready — export
  "…" (read-write), auth: none (anonymous)`), never mentions CSI at all
  (`core/config/postconfiguration.c` has no `csi` branch); and the feature's one
  metric, `brix_csi_scrub_mismatch_total`
  (`observability/metrics/stream_family.c:389-397`), counts the background scrub
  and never a read. The cure is one line either way: hoist the `require` test
  out of the `trust_fs` short-circuit so a missing record is refused whoever is
  trusting the filesystem, or diagnose the pair at merge time as the
  contradiction it is. Note the two are not redundant even after a fix —
  `trust_fs` is about verifying bytes the record already covers, `require` is
  about refusing files the record does not cover at all. File 18 §C pins today's
  behaviour, and the row asserting the grant carries the instruction to invert
  it and strike this entry when it is fixed.

- **DEFECT CANDIDATE #94 (data integrity, observability — at-rest corruption is
  reported as a disk error, through a flag that is set for exactly this and read
  nowhere — file 18 §D).** When CSI catches a page whose CRC no longer matches
  the record, the client is told **kXR_IOError (3007) "Input/output error"**,
  never kXR_ChkSumErr (3019). The distinction is the whole operational value of
  the feature: kXR_IOError says the server had trouble reading, which a
  federation client retries; kXR_ChkSumErr says *this replica's bytes are
  wrong*, which is a reason to fetch elsewhere and to quarantine. The code
  intends the second. `brix_vfs_job_t` carries a bit declared for it —
  `unsigned csi_mismatch:1; /* OUT: a page failed CSI verify (W2) */`
  (`fs/vfs/vfs_io_core.h:85`) — set on every mismatch at
  `fs/vfs/vfs_io_core.c:155`, under a comment that states the contract twice:
  "A mismatch fails the read with EIO + the csi_mismatch flag so the handler
  **maps it to kXR_ChkSumErr instead of serving corrupt data**" (`:147-148`).
  No handler does. A scan of every `.c`/`.h` in `src/` finds **one write, zero
  reads** (file 18 §D asserts exactly that), and the read path answers with a
  literal instead: `BRIX_RETURN_ERR(…, kXR_IOError, strerror(errno))`
  (`read/read_buffered.c:361`, whose own comment at `:313` says "mismatch
  surfaces here as EIO (job.csi_mismatch set)"). `kXR_ChkSumErr` does not appear
  in that file at all. The result is that **the same feature reports the weaker
  condition with the stronger code**: "no integrity record" is kXR_ChkSumErr
  (#93's table, third column), "the record says these bytes are wrong" is
  kXR_IOError — backwards, in one process, measured side by side. Nor is there
  another channel: the mismatch is invisible in the scrub metric (it counts the
  background scrub only) and the error log line is the generic I/O one, so an
  operator cannot tell a corrupt replica from a failing disk on any surface.
  The control that keeps this a finding about the mapping rather than about the
  measurement is `read/read_sendfile.c:167-180`, `&& ctx->files[idx].csi ==
  NULL`: a handle carrying an integrity engine is excluded from zero-copy, so
  every verifying read really does run through the buffered path that hard-codes
  the code. The cure is to carry the bit up — `read_buffered` already has the
  job struct in hand — and answer kXR_ChkSumErr when it is set, which is what
  both comments already say happens. File 18 §D pins the code on the wire, the
  one-write-zero-reads scan and the sendfile exclusion, each with the
  instruction to invert and strike this entry when the mapping lands.

- **DEFECT CANDIDATE #95 (observability — a login refused for the reason the
  directive exists is recorded on no operator-visible face at all — file 19
  §F).** With `brix_krb5_delegate on`, a client whose ticket is not forwardable
  is turned away *after* it has authenticated: the AP-REQ was verified, the
  principal was mapped, and the acceptor withheld the session it had already
  earned the right to grant. The client is told clearly enough — stock `xrdfs`
  says `Auth failed: Seckrb5: Unable to get forwarded credentials; KDC can't
  fulfill requested option`, and this repo's client goes one better and names the
  fix (`need a forwardable ticket: kinit -f`). The server says nothing, anywhere:

  | face                                             | completed | refused | malformed cred |
  |--------------------------------------------------|-----------|---------|----------------|
  | `brix_access_log` AUTH record                    | `OK`      | **none**| `ERR`          |
  | `brix_auth_total{…,status="ok"}`                 | +1        | **0**   | 0              |
  | `brix_auth_total{…,status="fail"}`               | 0         | **0**   | +1             |

  Measured on one plane in one run, so the third column is what makes the second
  a defect rather than a design: a refusal the acceptor itself makes is both
  logged and counted, while the refusal this directive is FOR is neither. The
  access log for the refused connection carries the LOGIN and the DISCONNECT with
  nothing between them. The cause is structural rather than a missing call —
  `brix_krb5_begin_delegation` (`auth/krb5/auth.c:422-449`) accounts for each of
  its own failures with `brix_metric_auth(…, 0)` + `brix_log_access(… "AUTH" …)`
  and then returns the CHALLENGE as a success, and nothing is left to account for
  the round that never comes back. Nor is there a config-time hint that the plane
  is armed: the startup notice prints `principal=… keytab=… ip_check=…`
  (`auth/krb5/config.c:252-257`) and no delegation word at all, so three servers
  with three different arms emit three IDENTICAL notices (file 19 §A asserts the
  three are one string). The operational shape is the bad one: an operator who
  arms delegation breaks every client whose tickets are not forwardable — which
  is the `kinit` default — and watches a flat line while they do it. The cure is
  small: account for the parked round, either at the challenge (a
  `status="pending"` or an access record naming the reason) or at connection
  close when a parked round-1 state is still parked, which the pool cleanup at
  `deleg_capture.c:163-172` already runs for exactly that state. File 19 §F pins
  today's behaviour — the silence, the unmoved counters, the logged-and-counted
  contrast, and the un-accounted success return in the C — each with the
  instruction to invert it and strike this entry when accounting lands.

- **DEFECT CANDIDATE #96 (credential placement — the captured user TGT lands in
  `/tmp`, and the documented knob for moving it cannot be set from a config file
  — file 19 §G).** Round 2 of the delegation exchange exports the client's
  forwarded credential to a FILE ccache, and `brix_krb5_deleg_mkccache`
  (`auth/krb5/deleg_capture.c:209-236`) is commented "Honors `$TMPDIR`,
  defaulting to `/tmp`". In a worker, `getenv("TMPDIR")` is NULL: nginx rebuilds
  the worker environment from its `env` directives alone, so the fallback is not
  a fallback but the only reachable behaviour unless an operator writes a
  main-scope `env TMPDIR;` — a directive belonging to nginx rather than to this
  module, which **no config in the coverage corpus, no README and no doc
  mentions** (file 19 §G asserts the census). Measured both ways on the same
  instance: rendered plain, every capture is `/tmp/brix-krb5-fwd-XXXXXX`;
  rendered with `env TMPDIR;` and the variable handed in, the same capture moves
  to the given directory. This is a siting question and not an exposure, and the
  file pins why: `mkstemp` gives 0600 and libkrb5's rewrite-by-name preserves it,
  the file is owned by the worker's uid, and the pool cleanup unlinks it at
  connection close (all three asserted). But what sits there is not an opaque
  blob — §G reads it back with `klist` and gets `Default principal:
  alice@NGINX.TEST`, `krbtgt/NGINX.TEST@NGINX.TEST`, i.e. a live, usable
  ticket-granting ticket for the logged-in user, one per concurrent delegated
  connection, in the directory most likely to be world-writable, shared with
  every other tenant of the host, and on some deployments a tmpfs sized for
  something else. The cure is a directive of this module's own —
  `brix_krb5_delegate_ccache_dir`, merged and validated like the keytab path, so
  the location is a configuration decision with a diagnostic behind it rather
  than an environment variable that silently has no effect. Failing that, the
  `$TMPDIR` sentence in the C and the delegation docs should say what actually
  reaches a worker. File 19 §G pins the default location, the mode, the owner,
  the lifetime, the `klist` readback, the relocation under `env TMPDIR;`, and the
  corpus census, so a directive landing would fail the census row first.

- **DEFECT CANDIDATE #97 (observability — inline compression is counted nowhere,
  so an operator can see that one request compressed and never how often
  compression was refused — file 20 §G).** Both directions of the inline
  compression extension emit a per-request marker: `read_compress.c:232` and
  `write_compress.c:188` each append `z=<wirebytes>` to the access record when a
  codec engaged, and file 20 asserts the marker's presence on an armed plane and
  its absence on a disabled one, for reads and for writes. What does not exist
  anywhere in `src/` is an **aggregate**: no `brix_metric_*` call names a codec
  or a compression outcome (file 20 §G asserts the census over every `.c` in the
  tree), and `src/observability` mentions compression only in an unrelated
  comment about the HTTP serve helper. The consequence is specific rather than
  cosmetic, and it compounds with the fail-soft design the same file measures.
  Compression here degrades silently by intent — a disabled direction, an
  unknown codec and an unbuilt codec all return `BRIX_CODEC_IDENTITY` and the
  open still succeeds — so a fleet that ships `brix_read_compress on` and a
  client that asks for `zstd` against a binary built without it will transfer
  every byte uncompressed forever, and nothing on any operator-visible face will
  differ from the working case except the absence of a marker on individual log
  lines that nobody greps. There is no counter to alert on, no ratio to graph,
  and the capability query answers what the server *would* do rather than what
  it *did*. The cure is small and matches what the auth plane already has in
  `brix_auth_total`: one low-cardinality counter — outcome (`engaged`,
  `identity`, `unknown-codec`, `unavailable`) crossed with direction
  (`read`/`write`), codec named only from the built-in table so the label set is
  bounded — incremented at the single site that already decides all of it,
  `open_negotiate_compress_codec`. File 20 §G pins today's state: the two marker
  sites exist, the metric census is empty, and the test carries the instruction
  to grow the instance a `METRICS_PORT` and invert the assertion when a counter
  lands.

- **DEFECT CANDIDATE #98 (observability, security-adjacent — six distinct OCSP
  refusals, a replay-guard deny among them, all reach the operator as
  `certificate is REVOKED` — file 21 §G).** `check_ocsp_response`
  (`ocsp_request.c`) has one failure code for everything short of an UNKNOWN
  verdict: an unsuccessful response status, an unparseable basic response, a
  failed signature verification, a nonce missing under
  `brix_ocsp_require_nonce`, a mismatched nonce, and a certificate the response
  does not cover are all a bare `return -1` before the status switch is ever
  reached. Its only caller, `ocsp_check_urls` (`ocsp.c:118-121`), treats -1 as
  the verdict it documents as never overridden and logs one line for all of
  them: `brix_ocsp: certificate is REVOKED ("<url>")`. File 21 proves it from
  outside rather than off the source — on the armed plane the nonce-less
  credential is refused with that line in the error log **while the responder's
  own `/ctl/log` shows it answered `good` for that exact serial** — and shows
  the conflation is not something the strict token opts into, by reproducing it
  for a mismatched nonce on the plane where the flag is `off`, which is what
  every deployment in the corpus runs. Two things follow, and the second is the
  worse one. A site alerting on the string gets paged about a certificate nobody
  revoked, most likely because its responder is misconfigured; and a site
  reading the log to CONFIRM a revocation cannot tell a real one from a
  responder that omitted a nonce, which is precisely the case an attacker
  replaying a captured response produces. The same shared code is also the only
  thing that keeps the replay guard alive under `brix_ocsp_soft_fail on` — the
  guard survives because -1 means REVOKED, not because it was exempted from the
  policy — so the cure has to move both halves together: give the policy
  refusals a distinct return (a third code, or an out-param carrying the
  reason), log the reason at the call site, and make the soft-fail loop treat
  the new code as non-overridable explicitly rather than by coincidence. File 21
  §F pins the coincidence so a refactor that separates them cannot quietly make
  the guard fail-open, and §G pins today's message so the fix inverts a test
  rather than silently passing one.

- **DEFECT CANDIDATE #99 (configuration, security-adjacent — `brix_tpc_delegate
  off` is not a value a GSI tap-proxy operator can hold, and the arm written over
  it costs an extra round on every GSI login — file 22 §I).**
  `brix_config_prepare_server` (`src/core/config/runtime_server.c:441-448`) sets
  `xcf->tpc_delegate = 1` whenever `proxy.enable && proxy.auth ==
  BRIX_PROXY_AUTH_GSI && !xcf->tpc_delegate`, logging NOTICE `brix_tap_proxy_auth
  gsi: enabling GSI proxy delegation capture`. The intent is sound — a GSI tap
  proxy that cannot present a delegated proxy upstream is useless — but it runs
  from `postconfiguration.c:131`, which is AFTER the merge, and the merge writes
  0 for BOTH spellings of off: `server_conf_merge_cluster.c:58` resolves the
  `NGX_CONF_UNSET` of `server_conf.c:219` to 0 exactly as it resolves a written
  `off`. By the time the override reads the field, "the operator declined
  delegation" and "the operator never heard of the directive" are the same
  value, so the override cannot decline to fire on the first, and the directive
  has no spelling that survives a GSI tap proxy. File 22's OVERRIDE plane writes
  `brix_tpc_delegate off` beside `brix_tap_proxy_auth gsi` and measures that the
  server runs with it on.
  What makes this more than an unhelpful default is what the flag ALSO gates.
  It is documented and named as a TPC concern, and one of its two readers is one
  (`tpc/engine/launch.c:285,307`, attaching the delegated credential to a pull);
  the other is `src/auth/gsi/auth_cert.c:324`, where `conf->tpc_delegate` gates
  an EXTRA GSI handshake round — `brix_gsi_begin_delegation` sends `kXGS_pxyreq`
  and auth completes only on `kXGC_sigpxy` — for EVERY GSI login, TPC or not,
  and a client that cannot sign a proxy is refused `kXR_NotAuthorized` with `GSI
  proxy delegation failed`. So the override does not merely re-arm a transfer
  option the site turned off: it adds a requirement to the authentication of
  every GSI client the listener has, including read-only ones that will never
  initiate a copy, on a listener whose operator wrote the token that says not to.
  The NOTICE is emitted, but cannot say where: postconfiguration runs after the
  parse, so nginx cites the LAST line of the file (`.../nginx.conf:186`) for
  every server it rewrites, and a config with several `server {}` blocks gets N
  identical notices naming none of them. File 22 measures the notice per
  configuration LOAD rather than per plane for that reason, and the fact that it
  had to is part of the finding.
  The cure is to keep the tri-state: leave `tpc_delegate` `NGX_CONF_UNSET`
  through the merge (or carry a second `explicitly_set` bit) so the override
  fires on OMISSION only and an explicit `off` is either honoured or refused at
  config time as an incompatible pair — refusing is defensible, silently
  inverting is not — and to cite the server block in the notice. File 22 §I pins
  today's behaviour on both readers, so a fix that makes the token stick inverts
  a test rather than quietly passing one.

- **DEFECT CANDIDATE #100 (observability, security-relevant — an SSRF refusal on
  the marker path reaches the client only as the last line of a 200-shaped body
  — file 23).** With `brix_webdav_tpc_marker_interval` set, a COPY is answered
  **202** and the performance-marker stream is opened
  (`webdav_tpc_marker_start()`) BEFORE the address-range preflight runs — the
  marker path carries its own copy of that check at `tpc_marker_start.c:44-68`,
  which sets `progress->result = NGX_HTTP_FORBIDDEN` on a blocked target when
  the response line has already been committed. The verdict then leaves the
  server only as the body's terminal token: `failure\r\n` instead of
  `success\r\n` (`tpc_marker.c:239`). File 23 measures both shapes on two
  locations that differ in `brix_webdav_tpc_allow_local` alone: a transfer
  refused for policy and one that completed carry the SAME status code, the same
  headers and a body that differs in its final line. This is legal
  HTTP-TPC — the marker protocol is defined that way, and the plain
  (non-marker) path does return 403 from `tpc_thread_ssrf_preflight()` — but the
  operational consequence is that a client, a mover, or a monitoring probe that
  checks `status == 202` and stops cannot distinguish "the destination refused to
  dial that authority" from "the copy succeeded", and neither can anything that
  aggregates status codes. The audit record is intact (the refusal is logged as
  `brix_webdav: HTTP-TPC SSRF blocked: <url>`), so this is a reporting gap rather
  than a containment one: nothing was dialled, and file 23 asserts that too. The
  cheap improvement is to refuse BEFORE committing the 202 — the preflight needs
  nothing the request thread does not already have, and the plain path proves the
  same verdict is reachable there — leaving the trailer for failures that only a
  running transfer can discover.
- **DEFECT CANDIDATE #101 (configuration, fail-open — a written
  `brix_webdav_tpc_source_allow` allowlist is inert, silently, whenever the guard
  flag is off or absent — file 23).** The naming allowlist is two directives:
  `brix_webdav_tpc_source_guard` (a flag, merged to **0** at
  `tpc_config.c:80`) and `brix_webdav_tpc_source_allow` (a list, merged
  independently at `:81` by its own setter, `module_directives.c:147-170`, which
  only appends). `webdav_tpc_source_guard()` returns `NGX_OK` on
  `!conf->tpc_source_guard` (`tpc.c:254-256`) before the allowlist is read at
  all, so a location that names its permitted sources and does not also write
  `on` pulls from **every** authority a client asks for, including hosts its own
  allowlist does not name. Nothing reports it: the setter accepts the list
  without comment, `nginx -t` passes, and — the half that matters for an
  operator who thinks the control is live — a transfer to an unnamed host emits
  **no** `signal=tpc_egress` audit line, because that line is written only by the
  refusal path. File 23 measures the three states side by side on locations
  carrying the identical allowlist: guard written `off`, guard omitted, guard
  `on` — the first two both complete the pull and log nothing, the third refuses
  it 403 with the audit line, which is what makes the first two attributable to
  the flag. The shape is a plausible operator mistake rather than an exotic one,
  because the allowlist is the directive that reads like the policy. The cure is
  a config-time diagnostic: a non-empty `tpc_source_allow` with the guard off is
  either a warning at merge or an outright refusal, and the same check belongs on
  the native twin (`brix_tpc_source_guard` / `brix_tpc_source_allow`), which
  merges the same way.
- **DEFECT CANDIDATE #102 (configuration, silent no-op — a configured
  `brix_zip_stage_dir` is inert, and says so nowhere, unless
  `brix_zip_force_scratch on` is written beside it — file 24).** Archive staging
  is three directives that read like one feature: the flag
  (`brix_zip_force_scratch`, merged to **0** at
  `server_conf_merge_security.c:316`), the destination (`brix_zip_stage_dir`,
  merged independently) and the cap (`brix_zip_stage_max_bytes`, merged to
  **512 MiB** at `:317`). `zip_stage_archive_maybe`
  (`zip/zip_member.c:302-307`) returns `NGX_OK` — read the archive in place —
  on `!conf->zip_force_scratch || sdir == NULL || sdir[0] == '\0' ||
  ast->st_size > maxb`, one condition, four ways to lose, and only the taken
  path logs anything: `zip: archive staged to scratch (%O bytes)` at INFO on
  success, nothing at any level on any of the three skips. So an operator who
  sets a stage dir to confine archive reads to scratch — and does not also write
  the flag, which is the directive that does not read like the policy — gets the
  old behaviour, no warning from `nginx -t`, no runtime line, and an empty stage
  directory that looks exactly like a working one, because the staged copy is
  unlinked the instant it is made (`xvfs_stage_fd`, `vfs_core.c`) and BOTH arms
  leave the directory empty. File 24 measures the three states side by side on
  planes carrying the identical stage dir: flag written `off`, flag omitted,
  flag `on` — the first two serve identical member bytes and log nothing, the
  third serves the same bytes and logs the staging line, which is what makes the
  first two attributable to the flag. The same silence covers the size cap: an
  archive over `brix_zip_stage_max_bytes` falls back to the in-place read with
  no diagnostic, so a stage dir that worked yesterday stops working on a bigger
  archive without saying so — that third exit is read off the code rather than
  measured here, since it needs a plane whose cap is smaller than its archive.
  Same cure as #101, and the same shape: a non-empty `zip_stage_dir` with the
  flag off is a warning at merge, and the cap skip is a line at WARN rather than
  silence.

- **DEFECT CANDIDATE #103 (configuration, an opt-out that does not opt out —
  `brix_upstream_tls_verify off` still refuses every peer whose chain does not
  validate, so the escape hatch the config-time EMERG advertises cannot be used
  — file 25).** Peer verification on the outbound redirector leg is enforced in
  two places, by design: the CTX build sets `SSL_VERIFY_PEER` plus
  `X509_VERIFY_PARAM_set1_host` when a CA is configured
  (`runtime_server_tls.c:116-165`), and the handshake-done callback re-checks
  `SSL_get_verify_result()` before the re-login (`net/upstream/tls.c`). The
  second gate is unconditional, and its comment says why that is safe —
  "Harmless (X509_V_OK) when verification is off" — which is true only when a
  chain the default trust store accepts is on the other end. With
  `brix_upstream_tls on; brix_upstream_tls_verify off;` and no CA, which is
  precisely the configuration the EMERG names as the way out ("set the CA, or
  brix_upstream_tls_verify off to opt out"), no trust store was ever populated,
  so `SSL_get_verify_result()` returns a self-signed / no-local-issuer error for
  any private peer and the leg aborts with "upstream: TLS peer verification
  failed" — AFTER a completed handshake, which is how file 25 tells this refusal
  apart from the armed one: the stub records `tls-established` and then never
  receives a login. The direction of the failure is safe; the contract is not.
  An operator following the error message reaches a TLS upstream that cannot
  work at all, and the only configuration that does work is the one the message
  offers as the alternative. Cure is a choice, not a patch: either the callback
  honours the flag (skip the verify-result gate when verification was
  deliberately disabled, keeping it as belt-and-braces for the armed case), or
  the EMERG and the `off` arm stop advertising an exit that leads nowhere and
  say a CA is mandatory. Either way the arm should not parse into a leg that
  refuses everything in silence at config time.
- **DEFECT CANDIDATE #104 (configuration/usability — an upstream spelled as an
  address literal can never be verified, whatever its certificate says — file
  25).** The pinned name is `brix_upstream_tls_name` when written and the
  upstream host AS SPELLED otherwise (`runtime_server_tls.c:136-139`), and it is
  pinned through `X509_VERIFY_PARAM_set1_host`, which matches DNS names — an
  address literal handed to it is compared against dNSName SANs and the CN, never
  against the certificate's iPAddress SAN (that is `X509_VERIFY_PARAM_set1_ip`).
  So `brix_upstream 10.0.0.5:1094` with verification armed fails its handshake
  against a certificate minted for exactly that address. File 25 measures the
  A/B that makes this a defect rather than a misconfiguration: ONE stub, ONE
  certificate carrying both `DNS:localhost` and the loopback IP SAN, ONE CA, and
  two planes that differ only in how the upstream is written — the DNS spelling
  completes the upgrade and returns the stub's redirect, the literal is refused
  with `certificate verify failed`. Addresses are a normal way to write an
  upstream in this codebase (the fleet's own `brix_upstream` rows are literals),
  and the failure gives the operator no hint that the SPELLING is the problem,
  which makes `brix_upstream_tls_verify off` — see #103, where it does not work
  either — the obvious next thing to try. Cure: pin through
  `X509_VERIFY_PARAM_set1_ip_asc` when the host parses as an address, or refuse
  the combination at config time with a message naming
  `brix_upstream_tls_name`.
- **DEFECT CANDIDATE #105 (correctness/observability — the HTTP mirror's
  divergence detector can never fire, so `brix_mirror_log_diverge` has no
  observable arm and `brix_mirror_divergence_total{surface="http"}` is frozen at
  zero — file 26).** The detector compares the shadow's status class with the
  primary's inside `mirror_finalize_request`
  (`net/mirror/http_mirror_request.c:452-464`) and guards itself with
  `pctx->primary_status != 0`. That field has exactly one writer,
  `brix_http_mirror_log_handler` (`net/mirror/http_mirror.c:307-323`), which runs
  in the LOG phase of the MAIN request — and a background mirror subrequest holds
  the main request open until it completes (which is why the client's connection
  stays open past the body; `_test_phase24_mirror_helpers.py` documents the
  symptom without naming the cause). The finalize therefore always precedes the
  stamp and always reads zero, for every method: the divergence is never
  declared, the counter never increments, and the NOTICE the flag gates is
  unreachable code. File 26 measures the whole chain rather than the absence of a
  log line: a shadow that answers 404 to the primary's 200 for the same URI (both
  verified on the wire), `brix_mirror_requests_total{surface="http"}` moving by
  exactly one for that replay — so the finalize ran and saw the shadow's status —
  and `brix_mirror_divergence_total{surface="http"}` not moving at all; armed,
  unwritten, and armed-against-an-agreeing-shadow then produce identical output,
  which is what "no observable arm" means. The stream surface is the control and
  is not affected: it stamps its primary status inline and
  `test_phase24_mirror.py` proves its divergence counter moves. Cure: stamp the
  primary status where it is known — at the end of the content phase, or from
  `r->headers_out.status` read directly in the finalize through `r->parent` —
  rather than in a LOG handler that runs after the only reader.
- **DEFECT CANDIDATE #106 (correctness/policy bypass — the redirect loop guard
  is client-controlled, so on a keyless manager any client can opt out of being
  redirected and have the manager serve the data itself — file 27).**
  `rdr_eligible` refuses to redirect a request whose query already carries
  `brixrdr.mac` (`webdav/redirect.c:205-209`), which is right on a node that can
  VERIFY that CGI: a request arriving with a handoff has been redirected once
  already, and bouncing it again is the loop the guard exists to stop. But the
  guard tests presence, while the verification that would refuse a forged one is
  gated on `brix_http_secretkey` being configured — `webdav_redirect_signed_auth`
  returns `NGX_DECLINED` outright when there is no key
  (`webdav/redirect.c:396-402`), by design, "a key-less server cannot verify
  anything". On a manager configured `brix_webdav_redirect_dataserver on` with
  no key — a documented arrangement, since the docs sign the identity only "when
  a shared key is configured" — the two halves disagree: the guard fires on a
  parameter anyone can type, nothing verifies it, and the location's ordinary
  policy serves the file locally. File 27 measures exactly that: a GET to the
  keyless armed location returns 307, and the SAME GET with a stranger's CGI
  appended returns 200 and the file's bytes from the manager. Where a key is
  configured the identical request is 403 (fail-closed on the expiry or the MAC),
  so the exposure is precisely the keyless arm — the one the corpus had never
  written. It is not an authentication bypass: the manager still applies its own
  auth. What it defeats is the redirect itself — load distribution, and any
  policy that lives on the data server rather than on the manager — at the
  client's choice and with no log line saying so. Cure: skip the guard when no
  key is configured (an unsigned handoff cannot be recognised, so there is
  nothing to loop on), or have the access phase record that a handoff verified
  and consult that flag in `rdr_eligible` instead of the raw query.

- **DEFECT CANDIDATE #107 (security — a dashboard with no password serves the
  VFS export browser, and the file's bytes, to anyone who can reach the
  location — file 28).** `vfs_browse.c`'s own header states the rule the code
  does not keep: "Always admin-auth (ngx_http_brix_dashboard_check_auth) — never
  the anonymous tier: this surface exposes stored user data". The call is real
  (`vfs_browse.c:69`), but `ngx_http_brix_dashboard_check_auth` opens with
  `if (conf->password.len == 0 && !dashboard_users_enabled(conf)) return NGX_OK;`
  (`dashboard/auth.c:233`) — a passwordless dashboard authenticates nobody,
  which is a defensible rule for a read-only status UI and is not the rule this
  surface needs. `brix_dashboard on; brix_dashboard_vfs_browse on;` with no
  `brix_dashboard_password` and no user list therefore answers an anonymous
  `GET /brix/api/v1/vfs` with the export census, `/vfs/files?export=&path=` with
  a directory listing of the LOGICAL namespace of any registered export, and
  `/vfs/download?export=&path=` with the file. File 28 measures all three on a
  plane that differs from a 401 plane by the password directive and nothing
  else: same flag, same endpoint, same anonymous request, `(401, 200)`. The
  browser reads through `brix_vfs_*` with `allow_write=0` and re-confines every
  open to the export root, so this is disclosure and not traversal or
  corruption — but the disclosure is of user data through an export whose own
  location may require a token, since the browser answers on the dashboard
  location's terms rather than the export's. Cure: give this surface its own
  gate — refuse (404, matching the disabled arm, or 403) when the dashboard has
  no credential configured at all — rather than inheriting the status UI's
  "passwordless means public". The three cells invert the day it is fixed.
- **DEFECT CANDIDATE #108 (correctness/policy — `brix_admin_require_both on` is
  inert, and silent, whenever only one factor is configured — file 28).**
  `admin_auth_combine` (`dashboard/api_admin.c:196`) ANDs the factors that are
  CONFIGURED, not the two the directive names: with `require_both` on it demands
  every configured factor, with it off either configured factor is enough, and
  with neither configured the API is closed. That is a sensible reading of the
  flag and it means the armed arm does nothing at all on a config with one
  factor — file 28 puts `brix_admin_allow` alone under `on` and under `off` and
  gets identical answers to all three request shapes, and the same for
  `brix_admin_secret` alone (403 / 200-class / 403 on both arms). It is the
  pattern of #101 and #102 one more time — a configured control that is inert
  and says nothing about it — and it has a specific operational shape: the
  natural mitigation after an incident is "we set `brix_admin_require_both on`",
  and if the allowlist is later dropped from the config, or was never merged
  into the location it was written above, the remaining factor authenticates
  alone with no warning at config time and no line at any log level. The suite
  had never entered the combiner at all, since its only admin config
  (`nginx_admin_api.conf`) configures a secret and no allowlist — which is
  exactly the arrangement in which the flag has no effect. Cure: warn at config
  time when `brix_admin_require_both on` is merged with fewer than two
  configured factors, or make the armed arm mean what it says and refuse to
  start.
- **DEFECT CANDIDATE #109 (usability/correctness — the documented override for
  the CMS auto-derivation is order-dependent, and in the order an operator
  writes it the config does not load — file 29).** `brix_cms_server on` derives
  manager mode for its own block (`net/cms/server_module.c:127-146`) and the
  comment there promises an escape hatch: "An explicit `brix_manager_mode off`
  in the same block still wins: only flip the flag while it is UNSET so the
  operator can always override the auto-derivation." The derivation implements
  itself by assigning `bcf->manager_mode = 1` — the same slot
  `ngx_conf_set_flag_slot` refuses to write twice — so the override wins only
  when the parser reaches it FIRST:

  ```
  brix_manager_mode off;   brix_cms_server on;     -> loads, export kept
  brix_cms_server on;      brix_manager_mode off;  -> nginx: [emerg]
                                                     "brix_manager_mode"
                                                     directive is duplicate
  ```

  The failing order is the one the escape hatch invites: an override is a
  reaction to the derivation, so it goes after the line that caused it. The
  diagnostic names a directive that appears exactly once in the file, never
  mentions `brix_cms_server`, and arrives after the derivation's own NOTICE has
  already been logged — and the refusal is positional rather than semantic, since
  `brix_manager_mode on` after `brix_cms_server on` is refused identically
  (file 29 §E measures all four orders plus the control that a block with no
  `brix_cms_server` accepts the flag in either position). Cure: have the
  derivation record its intent in a separate field that the merge consults, or
  hold it to post-configuration where the written value is already known, so the
  directive stays writable in either order. **The half that gets no number:** in
  the accepted order the same three lines — `brix_root on;
  brix_storage_backend posix:/data; brix_cms_server on;` — produce a block with
  no export at all, whose startup banner reads `export "/"`, whose directory is
  absent from the VFS census, and whose only diagnostic is
  "auto-enabling manager mode for this block" — word for word the notice a bare
  `brix_cms_server on` listener with no backend to lose gets. That is the
  documented consequence of manager mode rather than a defect, but the
  derivation cannot tell the two blocks apart and says nothing about the backend
  it has just made inert.

- **DEFECT CANDIDATE #110 (usability/correctness — the WebDAV open-file-cache
  family parses, validates, merges and ALLOCATES, and is then never consulted —
  file 30).** Five directives —
  `brix_webdav_open_file_cache`, `_valid`, `_min_uses`, `_errors`, `_events` —
  are accepted at location, server and http scope, and one of them does real
  work at configuration time: the setter at
  `protocols/webdav/module_directives.c:262-311` parses `max=` and `inactive=`,
  refuses a missing `max`, refuses a duplicate, honours `off` from any argument
  position, and on success calls `ngx_open_file_cache_init()`, so an
  `ngx_open_file_cache_t` is allocated out of the config pool and stored on the
  location conf. Four more directives fill the four fields beside it
  (`webdav_loc_conf.h:200-204`) and `config_merge.c:147-156` merges all five
  with stock nginx's defaults (NULL, 60, 1, 0, 0). Nothing reads any of it.
  **No translation unit under `src/`, `shared/` or `client/` calls
  `ngx_open_cached_file()`**, and within `webdav/` the five fields appear only in
  the command table (`module_commands.c:482-515`), the `NGX_CONF_UNSET` init
  (`config.c:153-157`) and that merge. The allocation is the last event in the
  cache's life.

  What makes it a defect rather than a shrug is that the directive ANSWERS.
  `nginx -t` accepts

  ```
  brix_webdav_open_file_cache max=100000 inactive=60s;
  brix_webdav_open_file_cache_errors on;
  ```

  and reports the file good, so an operator who reached for the standard nginx
  answer to "my export stats the same file thousands of times a second" is told
  it is configured, gets no diagnostic at any log level (file 30 §F), and has no
  way to observe that nothing changed — the next move is to raise `max`.
  `_errors on` is the sharper half: in stock nginx it caches ENOENT and EACCES
  for `valid` seconds, which is a real change in what a client is told about a
  file that has just been created, deleted, or had its permissions revoked.
  Here it changes nothing, which is safe today and is exactly the surface a
  future implementation would land on with no test watching either side. File 30
  measures the inertness rather than inferring it: with `max=1024 inactive=1h`,
  `valid 1h` and `min_uses 1` configured, a live cache would still be holding
  every one of a file replaced by rename (new inode), a file truncated in place
  (same inode, stale `st_size`), a deleted file, and a 404 that a create has
  since answered — and all four are served correctly on the next request, on
  four planes that differ only by which directives of the family they carry.
  The eight-request fingerprint of the configured planes is byte-for-byte the
  fingerprint of the plane that writes none of them.

  Cure: either wire the family or delete it, and the choice is not obvious —
  invariant 12 puts raw data syscalls in `src/fs/backend/`, so an fd cache keyed
  on a filesystem path may be the wrong shape for a VFS-seam export entirely.
  What is not defensible is the middle state, where the configuration is
  accepted, allocated and silent. The cheapest honest fix is the diagnostic: a
  `[warn]` at configuration time saying the export does not use an open-file
  cache would turn a silent no-op into a documented one and cost nothing.
  **The same shape, one directive wide, is already #35**
  (`brix_backend_passthrough_persist`: command table `http_common.c:239`, init
  `shared_conf.h:100`, merge `:428-429`, adopt macro `:441`, no reader) — file 30
  carries three live planes of it too, which is the first time #35 has been
  measured against a running server rather than an `nginx -t` and a grep; all
  three answer identically. Two inert families one audit apart is the argument
  for a guard: nothing in CI notices a directive that is parsed, merged and
  never read.

- **DEFECT CANDIDATE #111 (security — `brix_gridftp_gsi on` OFFERS the security
  layer and never REQUIRES it; the operator doc's "production form" gateway
  takes anonymous cleartext logins — file 31).** `docs/05-operations/gridftp.md`
  §3 presents a config as "The production form: an RFC 2228 GSI control channel
  authenticated by an X.509 (proxy) certificate": `brix_gridftp_gsi on` beside a
  host certificate, key and trusted-CA directory, with `brix_gridftp_allow_write
  on`. File 31 stands exactly that gateway up and, without a certificate, a
  proxy, or any `AUTH` command at all, sends `USER anonymous` / `PASS
  x@example.org` and is answered **`230 Login successful`** — then `PWD`, a
  full-size STOR, and a byte-identical RETR. Any password is accepted, including
  the empty string. The cause is three lines: `ev_grp_login`
  (`protocols/gridftp/ev/ftp_ev_dispatch.c:226-233`) sets `fc->authed = 1` on any
  `PASS` and never consults `fc->conf->gsi`; the flag's whole effect is at
  `ftp_ev_sec.c:121` and in the FEAT list, both of which only ADD a mechanism.
  Nothing in the gridftp command table (`ftp_module.c:208-341`) requires the
  security layer, and the one directive that could —
  `brix_gridftp_require_vo` — is a per-PATH ACL evaluated after resolution
  (`ftp_ev_path.c:117-125`) whose callee returns early allow-all when no rule
  covers the path, so §3's example, which has no VO rules, has no gate at all.
  File 31 measures the equality that sizes the finding: for a client that simply
  never sends `AUTH`, all three GSI planes — `on`, `off`, and the directive
  omitted — are the same server. Arming GSI adds a mechanism; it removes nothing.
  This also overturns a §D note from an earlier pass: "gridftp × brix_auth/tls
  markers — GSI and control-channel TLS are intrinsic to the gsiftp protocol"
  reads the zeros as detector artifacts, but a GSI plane is not a GSI-only plane,
  and the gap was real. What still holds is the confinement: invariant 4's
  `resolve_path` is upstream of authentication, so the anonymous session cannot
  escape the export (file 31 asserts four escape shapes). Cure: either a
  `brix_gridftp_require_gsi`-style gate, or `gsi on` refusing `PASS` outright,
  or — cheapest and least surprising — a startup `[warn]` and a doc sentence
  saying §3's gateway is also an anonymous FTP server.

- **DEFECT CANDIDATE #112 (security/correctness — a client-chosen `REST` turns
  the operator's `brix_gridftp_verify_write` off, per transfer, silently — file
  31).** `protocols/gridftp/ev/ftp_ev_xfer.c:374`:

  ```c
  *verify = (fc->conf->verify_write && *start == 0);
  ```

  `*start` is the REST offset the CLIENT sent, so the operator's directive is
  ANDed with a value under the peer's control. `REST 1` in front of every STOR
  is a complete opt-out of the integrity check on a server configured to require
  it, with no log line and no change to any reply the client can see. File 31
  measures it as a POSITIVE rather than as an absence — a cell asserting "no
  verification happened" by asserting nothing went wrong would pass under any
  implementation. The probe is built so a verifier that HAD run would have
  destroyed the evidence: `brix_vfs_wverify_check` (`fs/vfs/vfs_wverify.c`)
  compares the accumulator's whole-object CRC and its total length against the
  reopened file (`if (total != brix_vfs_file_size(rfh)) return NGX_ERROR;`) and
  a mismatch unlinks the object and fails the transfer. After `REST 10` and 20
  delivered bytes onto a 100-byte file, the accumulator holds 20 and the file
  holds 100 — and the transfer answers **226** with the file still 100 bytes.
  The control is `REST 0`, which satisfies `*start == 0`, runs the verifier, and
  performs an ordinary truncating STOR down to 20 bytes; without it, "the file
  was unchanged" could be read as "REST always no-ops". The armed plane, the
  plane with `verify_write off`, and the plane that never wrote the line are
  indistinguishable under `REST 10`. The intent behind the line is legible — a
  resume writes a fragment and the whole-object CRC cannot be computed from it —
  but the outcome is that the peer decides whether the server verifies. Cure:
  verify the written EXTENT rather than the whole object, or refuse a resumed
  STOR when `verify_write` is on, or at minimum log the downgrade.

- **DEFECT CANDIDATE #113 (correctness — a `require_allo_size` refusal leaves the
  rejected object on disk, complete-looking and readable — file 31).**
  `ftp_gateway.h:57-64` states the flag's contract as "a STOR preceded by
  `ALLO <size>` must deliver exactly `<size>` bytes or it fails 550 (never a
  truncated object committed as complete)". The 550 arrives; the object does not
  go away. After a refused short upload the name holds the 2500 delivered bytes,
  `SIZE` answers `213 2500`, and RETR serves them with a `226` — the same three
  answers a complete 2500-byte file would draw. Nothing marks it partial. The
  over-long case is worse: the object left behind is 5000 bytes, LONGER than the
  `ALLO 4000` the refusal was based on. And a refused STOR onto a name that
  already held a complete object has already overwritten it, so a client
  re-uploading a file it already has, truncated mid-flight, ends with the
  fragment and a 550 rather than with what was there. The prefix is left
  deliberately — the same doc comment says so, for a REST-resume, which is a
  defensible choice — but a resume story needs a way to tell a resumable prefix
  from a complete file and there is none: no `.part` name, no marker, no
  extended attribute, and (per #112) a resume is exactly the case where the
  integrity check does not run. File 31's sharpest cell is the comparison: the
  disarmed planes leave a byte-identical file and answer 226, so the entire
  difference the operator bought is the reply code. Cure: unlink on refusal, or
  commit under a partial name, or record the declared size so a resume can be
  validated against it.

- **DEFECT CANDIDATE #114 (correctness, one of them wire-visible — `%ll`
  conversions handed to nginx's own formatter, which has no `%lld` — file 31).**
  `ngx_vslprintf` implements `%L` (int64) and `%O` (off_t); `%lld`/`%llu` are
  not in its table, so `%l` consumes the argument and the remaining `d`/`u`
  characters are emitted literally. Four sites:
  `protocols/gridftp/ev/ftp_ev_dispatch.c:173`,
  `protocols/root/session/signing.c:43` (`%llu` × 2, the sigver replay WARN),
  `protocols/root/query/set.c:78` (`%llu` × 3, the `cms.space` INFO) and
  `fs/cache/directives.c:231` (the config-time cache-admission NOTICE). The
  first is on the wire and file 31 measures it on all eight of its gateways:
  `REST 10` is answered **`350 Restart position accepted (10ld)`**. The values
  are correct on LP64, which is why it has survived — a client that parses the
  number and ignores the tail is unharmed — but the reply is malformed FTP, and
  on an ILP32 or LLP64 target `%l` would consume the wrong width and the values
  would be wrong too. Cure: `%L` with an `int64_t` cast at all four sites.
  **Not a defect, recorded beside it:** the REST parser
  (`ftp_ev_dispatch.c:168-171`) checks `endp == arg` and `off < 0` but neither
  trailing bytes nor `ERANGE`, so `9x`, `10abc`, `+5`, `-0.5` and `0x10` are all
  accepted as their numeric prefix — a client that wrote a hex offset is told
  `350` and silently restarts from 0 — and an out-of-range offset saturates to
  `LLONG_MAX`, draws a `350`, and leaves a zero-byte object behind when the STOR
  that follows fails 550. Every observed outcome is a refusal or a correct
  prefix, so no number; it is written down so a future change to those three
  lines is a change to a measured behaviour.
- **DEFECT CANDIDATE #115 (security, an authentication layer that admits what it
  just rejected — an OCI registry naming an issuer table AND
  `brix_oci_registry_allow_anonymous on` publishes a forged bearer's image, and
  the audit trail stays clean — file 32).** `oci_authz_bearer()`
  (`oci_authz.c:135,175`) returns `NGX_DECLINED` when no bearer was presented
  and `NGX_DECLINED` when every configured issuer REFUSED the one that was.
  `brix_oci_registry_authz()` (`:183-236`) treats the two identically: it falls
  through to `lcf->registry_anon` and admits. On a location carrying both
  directives — a composition `configs/oci_registry.conf` has always permitted,
  its `ANON_LINES` and `ISSUER_LINES` slots being independent, and which no lane
  builds — the token plane is therefore decorative: a token whose signature does
  not verify starts an upload with 202, seals blobs 201, and publishes a complete
  manifest that pulls back byte-identical. The forged token is not weak and the
  issuer table is not broken; the file bounds it by sending the same token at the
  two authenticating planes, which both answer 401. What makes it worth a number
  rather than a note is the second half: the error log carries the
  `brix_token: JWT signature verification failed` line for every attempt, and the
  guard audit carries **nothing** — no `signal=authfail`, because nothing was
  refused — so a `[brix-oci-push]` fail2ban jail keyed on that signal sees a
  quiet registry while credentials it rejected publish through it. Cure: make
  "a token was presented and refused" distinguishable from "no token was
  presented" — an `NGX_ABORT`/`NGX_ERROR` return that `brix_oci_registry_authz()`
  denies on before it reaches the anonymous branch — or refuse the composition at
  load, since an issuer table beside an open door cannot mean anything an
  operator wanted.
- **DEFECT CANDIDATE #116 (security, a load-time gate satisfied by a mode that
  validates nothing — `ssl_verify_client optional_no_ca` makes a self-signed
  client certificate an authenticated pusher — file 32).**
  `oci_ssl_verifies_client()` (`oci_merge.c:141-152`) is `sslcf->verify != 0`,
  and its comment reads "`ssl_verify_client on` (and `optional`, whose result the
  request path checks) means the peer carries a certificate this server's CA
  chain accepted". `optional_no_ca` is the third non-zero mode and the comment
  does not mention it: it asks the client for a certificate and validates nothing
  about it. So a registry naming no issuer table and no anonymity directive
  LOADS, and `brix_oci_registry_authz()`'s TLS branch (`oci_authz.c:206-220`),
  which asks only that `ngx_ssl_get_subject_dn` succeed, then admits a
  certificate the client issued and signed for itself — 202 on the upload, 201
  on the seal, and a complete image published and pulled back under a subject
  chaining to nothing. The bound is what makes it precise: `on` and `optional`
  both answer the identical certificate with a 400 `SSL certificate error`
  before brix's authz runs at all, and all three modes admit the tree's own
  CA-signed user certificate, so the module's TLS identity branch is correct
  exactly where nginx was already going to refuse for it. Cure: read the mode
  rather than the flag — accept `on` and `optional`, refuse `optional_no_ca` at
  load with the same message the gate already has, since a registry whose
  authenticated context is "any certificate at all" is the unauthenticated push
  registry that message exists to prevent.
- **DEFECT CANDIDATE #117 (observability, a refused pull is audited as a refused
  push — file 32).** `oci_challenge()` and `oci_deny()` (`oci_authz.c:97,111`)
  pass `GUARD_OP_WRITE` unconditionally, and so does the read-only refusal at
  `:195`. `GUARD_OP_READ` exists (`guard.h:21`) and the OCI module never emits
  it. Measured on three refusals at the same plane — a `GET manifests`, a `HEAD
  blobs` and a `POST blobs/uploads/` — every audit line reads `op=write`, so an
  enumeration sweep across a private registry and a push attempt are one event
  to the operator and to any jail keyed on the field. Everything else in the
  line is right (`proto=oci`, `signal=authfail`, the status and the exact path),
  which is why this is one field and not an emitter to rewrite. Cure: pass
  `GUARD_OP_READ` when the request method is `GET`/`HEAD`, which the challenge
  path already has in `r->method`.
- **DEFECT CANDIDATE #118 (interoperability, a `WWW-Authenticate` challenge no
  client can follow — the realm drops the port and names an endpoint that does
  not exist — file 32).** `oci_authz.c:85-88` builds the realm from
  `r->headers_in.server`, which nginx parses out of the `Host` header WITHOUT
  the port, so a registry on any port but 80 advertises
  `Bearer realm="http://<host>/v2/token",service="<host>"` — both fields wrong
  for every non-default listener, including every one in the test fleet. And
  `/v2/token` is not implemented: following the realm, port corrected, reaches
  the registry's own name grammar and answers 404 `NAME_UNKNOWN`. The header is
  otherwise a syntactically perfect Bearer challenge, which is why it has
  survived — it parses, and it parses to the wrong place. The module says the
  stakes itself: "`podman login` only works against a registry that answers an
  unauthenticated request with a challenge it can follow, so the header is part
  of the contract, not decoration". Cure: build the realm from `$http_host`
  (port included) and from the scheme the request actually arrived on, and
  either implement the token endpoint or advertise the issuer the registry
  really accepts.
- **DEFECT CANDIDATE #119 (observability, the registry records who pushed
  nowhere — `principal` is filled and dropped, and the "anonymous" identity the
  code's own comment promises never reaches a log — file 32).**
  `brix_oci_registry_authz()` fills a caller-supplied `principal`, and its only
  caller (`oci_registry.c:290,318`) declares `char principal[256]` on the stack,
  passes it in, and never reads it back. The anonymous branch's comment
  (`oci_authz.c:222-224`) says the identity is "Recorded as such in the identity
  so the access log distinguishes 'nobody authenticated' from 'somebody did, and
  it was anonymous'". Measured against an instance with `access_log` deliberately
  ON — which no other OCI config in the tree has — neither half happens: the
  string "anonymous" occurs **zero** times in anything the instance writes, and a
  manifest `PUT` that a scoped token authorised is the same access-log line as
  one nobody authorised. The pusher's `sub` survives only where `brix_token`'s own
  validation `[info]` line put it, with no mention of what the subject was then
  allowed to do. So a registry that has been pushed to cannot answer "by whom"
  from its logs, in either arm of the flag. Cure: carry the principal into a
  variable the log format can name (`$brix_oci_principal`), which is what the
  out-parameter was plainly written for.
- **DEFECT CANDIDATE #120 (correctness, a flag whose name promises a TLS laxity
  it does not deliver — `brix_oci_mirror_insecure` reaches one field and nothing
  reads it — file 32).** The merged value is copied once, to
  `up->insecure` (`oci_merge.c:312`), and that field is read nowhere in the tree.
  The flag's entire effect is therefore the cleartext permit in
  `oci_reject_mirror()` (`:117`): it decides whether an `http://` upstream base
  is allowed at load, and nothing after. Measured as the black-box shadow of the
  dead field: with an `https://` upstream, `on`, `off` and the omission are one
  configuration — all three load, none draws a diagnostic. The name reads as
  "this mirror tolerates a bad certificate", which it does not: an upstream with
  an untrusted chain fails the same way under every arm. Not exploitable, and
  recorded because the field is live in the struct and an operator (or a future
  patch) reading the name would expect the peer verification the flag has never
  had. Cure: delete the carrier, or make the name true — one or the other, since
  the two surfaces disagree today.
- **DEFECT CANDIDATE #121 (observability, the one arm the corpus writes turns
  the WAF's only telemetry into 404 noise — `brix_guard_default_signatures off`
  audits a scanner probe as an ordinary miss — file 33).** That the arm ADMITS
  the built-in probes is known and tested (tranche 15). What no test had read is
  what the audit log then says about them: `/probe.php`, `/.git/config` and
  `/x/.env` are each logged `signal=notfound op=read status=404`, which is
  character for character the line `/missing.txt` produces. Every field but
  `path` agrees, and `path` is the field a scanner grep cannot key on — the
  next probe is a different one. httpguard publishes **no metric** (there is no
  guard family anywhere in `observability/`), so that log is the only place a
  sweep could ever have been counted, and in this arm it counts nothing. The
  enabled control on the same instance does distinguish them: `signature`
  against `notfound`, one request apart. The arm is not wrong to admit the
  probes — an operator may have good reason — but an admitted probe and a
  mistyped filename are different events, and the guard classified them
  correctly and then wrote the same word for both. Cure: keep the signature
  match in the outcome signal when the rule is disabled (a `signal=admitted`
  alongside the reason), or at minimum log the probe at its own level so a
  fail2ban filter can key on something.
- **DEFECT CANDIDATE #122 (security, a guard that is enabled, reports enabled,
  and cannot bounce anything — an empty profile is a permissive ruleset, and a
  MISSPELT one reaches the same state in silence — file 33).**
  `brix_guard on;` with `brix_guard_default_signatures off;` and no
  `brix_guard_profile` hands `guard_ruleset_load_profile()` an empty string,
  which falls to its unknown-profile branch (`guard_ruleset.c:180-188`): every
  op allowed, `enforce_grammar` cleared. With the built-ins off as well the
  ruleset holds no signature, no prefix and no grammar — nothing that can
  produce a bounce. Measured on the wire, that instance's seven-probe column is
  **cell for cell** the column of the instance that turned the guard OFF. It
  is not silent, though, which is what makes it dangerous rather than merely
  useless: it writes five audit lines for the same sweep, so the only signal an
  operator has says the WAF is running. The single tell is `proto=http` where a
  rule-bearing face writes `proto=xrdhttp` — a field about the profile, not
  about rules, in a line that otherwise looks healthy. The same state is one
  typo away from any working config: `xrdhttps`, `XRDHTTP` and `webdav` are all
  accepted by `nginx -t` without a diagnostic, and each silently downgrades the
  guard to signatures-only. Cure: refuse an unknown non-empty profile at config
  time (the three names are a closed set), and warn — or refuse — when an
  enabled guard's built ruleset holds no rule of any kind.
- **DEFECT CANDIDATE #123 (usability, the signature budget is spent by
  signatures the operator did not write, and the diagnostic names a number they
  cannot reach — file 33).** `guard_ruleset_add_default_signatures()` fills the
  same fixed array (`guard.h:94`, `GUARD_MAX_SIGS` 64) that
  `brix_guard_signature` fills, with thirteen built-ins. Under the merge default
  the operator's ceiling is therefore **51** — and the 52nd line is refused by
  `brix_guard_signature: more than 64 signatures` (`module.c:262`, which formats
  `GUARD_MAX_SIGS`). The number in the message is not the number in force, the
  number in force appears in no config, no diagnostic and no document, and it
  MOVES when an unrelated flag is written: with `default_signatures off` exactly
  64 are accepted and the 65th is refused. Measured in both arms and in both
  inheritance directions, since the second flag inherits from `http`/`server`
  and the budget is how that inheritance is observable at all. Cure: count the
  operator's signatures separately in the diagnostic ("N of 51 available; 13 are
  built-in — see brix_guard_default_signatures"), which needs no change to the
  array.
- **DEFECT CANDIDATE #124 (correctness, `nginx -t` is green on the config with
  no guard and red on the change that adds one — a disabled guard's ruleset is
  never validated, while its bounce status is — file 33).**
  `ngx_http_brix_guard_merge_loc_conf()` validates `bounce_status` and then
  returns early on `!conf->enable` (`module.c:380-389`), so
  `ngx_http_brix_guard_build_ruleset()` never runs for a disabled location and
  nothing it would have checked is checked. A location naming **192**
  signatures — three times the cap — passes `nginx -t` clean, with no
  diagnostic at all, as long as `brix_guard off` is in it or inherited; flip
  that one word to `on` and the identical config is refused. The failure
  therefore lands on the deploy that turns protection ON, which is the worst
  moment to discover it and the one an operator is least likely to have
  rehearsed. Four shapes were measured: the flag written `off` in the location,
  inherited `off` from the server, a child that opts out of a server-wide `on`,
  and the enabled control that fails. The asymmetry is four lines wide inside
  one function — `bounce_status` is refused under both arms, because its check
  sits before the early return — so nothing in the config or the diagnostics
  tells an operator which of the guard's knobs are checked when it is off. Cure:
  build (and discard) the ruleset for disabled locations too, or validate the
  arrays independently of `enable`.
- **DEFECT CANDIDATE #125 (security, a location that opts out of a server-wide
  guard opts out of its telemetry as well — the carve-out leaves no trace in the
  log the parent named — file 33).** `brix_guard off` in a child location is the
  only way to carve a hole in a server-level guard, and it is a complete one: on
  the face where `server { brix_guard on; … }` covers everything, `/quiet/`
  admits `.env`, `.git/config` and `.php` — and the parent's audit log, which
  the child inherits by pointer (`module.c:371-373`) and which is open and named
  in a config the operator can read, gains **not one line** about any of them.
  The log handler self-disables on `lcf->enable` exactly as the access handler
  does, so the carve-out is invisible in the one place an operator would look
  for it. A WAF with a documented exception is normal; a WAF whose exception
  cannot be seen in its own audit trail is how an exception outlives the reason
  for it. Cure: audit passes through a disabled child at least once per
  configuration reload, or emit the carve-out at config time so it appears in
  the error log the operator already reads.
- **DEFECT CANDIDATE #126 (operability, the one configuration that is enabled
  and inert — `brix_health_check on` with `brix_health_check_interval 0` starts
  nothing and says nothing — file 34).** `brix_hc_manager_start`
  (`health_check.c:410`) returns at once on
  `if (!conf->hc.enabled || conf->hc.interval_ms == 0)`, and the two arms of
  that `||` are not equivalent to an operator: one of them was asked for. The
  config passes `nginx -t`, the worker starts, the `interval 0` server is cell
  for cell the `brix_health_check off` server — no manager NOTICE, no probe, no
  timer — and the error log carries not one word distinguishing "you turned it
  off" from "you turned it on and gave it an interval that means never". A
  zeroed interval reaches production the ordinary way, as a templating default
  or a units mistake, and the cluster then blacklists nothing for the life of
  the process. Cure: refuse `interval 0` under an enabled flag at config time,
  or log a WARN naming the interval when the manager declines to start.
- **DEFECT CANDIDATE #127 (operability, the startup NOTICE misreports its own
  units by three orders of magnitude — file 34).** `brix_hc_manager_start` logs
  `"brix: health check manager started (interval=%Ms timeout=%Ms scan=%Ms)"`.
  `%M` is nginx's `ngx_msec_t` specifier and prints the raw milliseconds; the
  `s` that follows each is a literal in the format string, not a unit the
  formatter supplies. A server configured `brix_health_check_interval 2s`
  therefore announces `interval=2000s`, and the one line an operator has to
  confirm what the health-check plane actually parsed tells them it will probe
  every half hour. Pinned against a face whose interval is 2 s and timeout 1 s.
  Cure: drop the literal `s`, or divide.
- **DEFECT CANDIDATE #128 (operability, `brix_frm on` without a control dir
  loads clean and is the disabled server — and the validation polices the field
  that does not matter — file 34).** `brix_frm_conf_merge`
  (`tape_stage_conf.c:78-88`) refuses an enabled FRM that named no
  `brix_frm_queue_path` and refuses a relative one, so an operator who writes
  `brix_frm on;` is told exactly one thing they must add. Having added it, the
  config loads — and `brix_init_server_stage_registry`
  (`process_server_init.c:129-146`) gates the registry on
  `xcf->frm.enable && xcf->frm.control_dir.len > 0`, a field nothing asked for.
  The result is a server that reports `brix_frm on` in its own config, passes
  `nginx -t`, and answers `kXR_prepare` with the legacy `"0"` handle exactly as
  the `off` server does: no journal, no durable request id, no `kXR_QPrep`
  lookup, and no log line at any level saying the subsystem declined to start.
  Cure: make the load-time check demand what the runtime actually gates on.
- **DEFECT CANDIDATE #129 (operability, `brix_frm_queue_path` is required,
  validated for absoluteness, and read by nothing — file 34).** The directive is
  mandatory under an enabled flag and its value must be absolute; a grep across
  `src/` finds it in its own directive table, its init, its merge and that
  validation, and in no consumer. The directory is never created, opened,
  written or scanned. Two consequences follow, and the second is the one that
  bites: the operator is made to supply a path whose only effect is to satisfy
  the check that demands it, and because the whole validation block sits under
  `if (conf->enable)`, the identical relative-path typo is a config-refusing
  `emerg` on one arm of the flag and completely silent on the other — so a
  config that was `off` and correct-looking becomes `emerg` the day someone
  flips it on. Cure: wire the path to the queue it names, or delete the
  directive and its validation.
- **DEFECT CANDIDATE #130 (security/correctness, a stream server that named no
  control dir is served by a SIBLING's stage registry — its LFNs land in the
  other block's journal and it answers QPrep for the other block's request ids
  — file 34).** `brix_stage_registry_init` (`stage_request_registry.c:405`)
  writes into a `static brix_stage_registry_t` singleton, and every consumer
  reaches it through the same accessor rather than through the server config
  that created it. In a process where any one server block carries
  `brix_frm on` WITH a control dir, a second block carrying `brix_frm on`
  without one is not registryless: it enqueues, it is handed a durable
  `seq.pid@host` handle, its exports' logical file names are written into the
  first block's journal file, and `qprep_resolve_src` (`prepare_qprep.c:145`)
  resolves a request id minted on the FIRST listener when asked on the SECOND.
  Two stream fronts in one nginx are the ordinary way to run two VOs or two
  tiers on one host; this makes the tape-stage journal and the QPrep namespace
  process-global while the configuration that appears to scope them is
  per-server. Pinned both directions — the bleed face's own path appearing in
  the neighbour's journal, and a cross-face QPrep answering `kXR_ok` where the
  registryless control answers `kXR_ArgInvalid`. Cure: key the registry by
  server config, or refuse the second enabled block outright.
- **DEFECT CANDIDATE #131 (operability, every control dir after the first is
  discarded in silence and the named directory stays empty — file 34).**
  `brix_stage_registry_init` returns at `:412` on `if (reg->inited)` with no
  log at any level. `brix_init_one_server` runs for every enabled server block,
  so in a process with two blocks that each name their own
  `brix_frm_control_dir`, whichever the parser reached first owns the singleton
  and the second directory is never touched: it is created by the operator,
  named in a config that loads clean, reported nowhere as unused, and remains
  empty for the life of the process while that server's stage requests are
  journalled somewhere else entirely. This is #130's other face and the reason
  #130 is hard to notice — the evidence an operator would look for is in a
  directory they did not configure. Cure: WARN, naming both directories, when a
  second block's control dir is dropped.
- **DEFECT CANDIDATE #132 (correctness, the inheritance all three merges spell
  out cannot happen — no `NGX_STREAM_MAIN_CONF` bit — file 34).**
  `brix_merge_srv_healthcheck` (`server_conf_merge_cluster.c:154`) and
  `brix_frm_conf_merge` (`tape_stage_conf.c:47,56`) both call
  `ngx_conf_merge_value(conf->x, prev->x, 0)`, whose first branch takes the
  parent's value when the child left `NGX_CONF_UNSET`. All three directives are
  declared `NGX_STREAM_SRV_CONF | NGX_CONF_FLAG` in `directives_net.h` with no
  main-context bit, so `stream { brix_frm on; }` is refused by the parser with
  "directive is not allowed here", `prev` is permanently `NGX_CONF_UNSET`, and
  the parent branch of all three merges is dead code. The cost is not a wrong
  answer, it is a wrong expectation: the merge reads as though a stream-wide
  default were settable, three of these flags would be natural to set that way,
  and a reader auditing the tape plane's defaults from the merge alone would
  conclude something the parser will not let them write. Cure: add the bit and
  the main-conf allocation, or drop the merge to a plain default so the code
  says what it does.

- **DEFECT CANDIDATE #133 (documentation, the tree's one config that claims to
  write the disarming token does not write it — file 35).**
  `configs/nginx_gridftp_metrics.conf:11` documents its `RO_PORT` gateway as
  "`brix_gridftp_allow_write off`, the security-negative path: a STOR refused by
  the read-only gate must still book a `forbidden` row". The server block at
  `:48-52` carries `brix_gridftp` and `brix_gridftp_export` and nothing else.
  The gateway is read-only regardless — the merge default is 0
  (`ftp_module_merge.c:159`) — so `test_gridftp_metrics.py` passes and the
  mismatch was invisible; it matters because this is the ONLY place in the
  corpus where a reader would find the token, and the file it points them at
  does not contain it. Anyone auditing "which of our gateways are read-only?"
  by grepping the configs gets one hit, in a comment, on a block that does not
  carry it. Cure: write the line the header describes, which costs nothing and
  makes the block say what it is. Guarded from both directions in §K, which
  fails the moment the token is written and the moment the header stops
  claiming it.

- **DEFECT CANDIDATE #134 (observability/security, six of the seven verbs the
  write gate governs refuse in total silence — file 35).** A client that issues
  MKD, XMKD, DELE, RMD, XRMD, RNFR and RNTO against a read-only export is
  refused seven times, and afterwards **no `brix_io_ops_total` row has moved at
  all** — not `forbidden`, not under another op name, not anything; the only
  counter that changed in the whole `{proto="gridftp"}` plane is
  `brix_auth_total{method="none",status="ok"}`, from the login. The error log,
  at `info`, gained three lines, and all three are session lifecycle: connect,
  `gateway session start`, `gateway session end`. Not one names a refusal, at
  any level. `ev_xfer_guards` (`ftp_ev_xfer.c:333`) DOES meter its verdict — a
  refused STOR or APPE books
  `brix_io_ops_total{proto="gridftp",op="write",status="forbidden"}` — so the
  gateway is perfectly capable of recording an authorization outcome, and its
  own comment gives a good reason for what it leaves out ("protocol misuse …
  the verb never became an operation") which applies to none of the six. The
  practical shape: an operator watching the metrics plane sees two increments
  out of nine refusals when a client sweeps a read-only export for a writable
  path, and an incident responder reading the log afterwards finds no record
  that the attempt happened at all. Cure: call `brix_ftp_ev_metric_refused` from
  `ftp_ev_ns_mutate`, `brix_ftp_ev_cmd_rnfr` and `brix_ftp_ev_cmd_rnto`, and
  emit the access-log line on the refusal path — the success path already does
  (`brix_access_json` with `"status":"ok"`), so the asymmetry is one call site
  each way. §D and §E measure both halves, including the control that makes the
  silence a finding: a successful MKD on the armed face logs `"op":"mkdir"`.

- **DEFECT CANDIDATE #135 (correctness, RNTO's permission check is unreachable
  — file 35).** `brix_ftp_ev_cmd_rnto` (`ftp_ev_cmd.c:425-435`) tests
  `fc->rnfr_set` first and consumes it — `fc->rnfr_set = 0;` with the comment
  "single-shot pairing" — and only then tests `fc->conf->allow_write`.
  `rnfr_set` is assigned 1 in exactly one place, the tail of
  `brix_ftp_ev_cmd_rnfr`, which is itself behind the same gate. On a read-only
  export the pairing therefore can never be armed, RNTO always answers `503
  RNFR required first`, and the `550 Permission denied (read-only)` below it is
  dead. The cost is a reader's: `brix_ftp_ev_cmd_rnto` looks defence-in-depth
  and is not, and a future change that made RNFR reachable without the gate — a
  resume path, a second setter, a config reload rebinding `fc->conf` — would be
  relying on a line that has never once executed. Cure: hoist the `allow_write`
  test above the `rnfr_set` test, which costs nothing, makes the refusal the
  truthful one, and makes the check live. §F measures the reachability across
  three dialogue shapes rather than reading it, with the armed face as the
  control that shows the pairing itself works.

- **DEFECT CANDIDATE #136 (correctness, `SITE` answers `200 OK` to every
  subcommand including ones it does not implement — file 35).**
  `ev_grp_session` (`ftp_ev_dispatch.c:259`) is a bare `return
  brix_ftp_ev_reply(fc, "200 OK\r\n")` with the argument never read. So `SITE
  CHMOD 000 /seed.txt` against a **read-only** export is answered `200 OK` and
  the file's mode on disk is unchanged — the gate is not bypassed, nothing
  happens, and the client is told the mutation succeeded. `SITE UMASK`, `SITE
  HELP` and `SITE EXEC` get the same answer, which is worse than a refusal in
  the last case: `SITE EXEC` is the classic wu-ftpd remote-execution verb and a
  scanner reading `200 OK` will record the server as supporting it. `SITE` is
  not advertised in FEAT, so nothing is promised, but nothing forces a client
  to consult FEAT either. Cure: `502 Command not implemented` for every
  subcommand the gateway does not implement, which is all of them today. §H
  measures the reply and the unchanged mode on both faces.

- **DEFECT CANDIDATE #137 (operability, an integrity knob is accepted, in
  silence, on a gateway that can never write — file 35).**
  `brix_gridftp_verify_write on` and `brix_gridftp_require_allo_size on` both
  parse clean and draw no diagnostic beside `brix_gridftp_allow_write off`, in
  either order, singly or together. Both knobs' entire subject is a write that
  the same server has just been configured to refuse, so the composition can
  only be a mistake — most plausibly a gateway that was writable, was made
  read-only, and kept its verify settings, leaving an operator with a config
  that reads as though uploads were being checksummed. This is the
  inert-companion shape of #101 and #102 on a third plane, and the merge is one
  function away from every fact needed to diagnose it: all four flags are
  merged in `brix_ftp_merge_srv_conf` within six lines of each other
  (`ftp_module_merge.c:159-164`). Cure: a `[warn]` naming both directives, in
  the merge, in the same place #101's and #102's belong. §I measures the
  inertness on the wire — the `verify_write` face answers every gated verb
  exactly as the two plain disabled faces do — and §J the silent acceptance at
  parse time, with the control that a MALFORMED companion is still refused by
  name, so the gap is about meaning and not about parsing.
- **DEFECT CANDIDATE #138 (security, the S3 plane discloses the reserved-name
  policy the resolver is written to hide — file 36, FOUND AND FIXED IN THIS
  TRANCHE).** `compat/path.c:50-58` does not merely return 404 for a name
  matching `brix_is_internal_name`, it says why: "404 (not 403) so the response
  does not distinguish an internal name from a genuinely absent one", and it
  says the rule "Covers WebDAV + S3 (both route client URIs through here)".
  WebDAV keeps it exactly — the refusal for a reserved name that exists, a
  reserved name that does not, and a plain name that does not are one
  fingerprint, 153 bytes and one md5, headers included. S3 cannot express it.
  `s3_resolve_key` (`s3/util.c:136-152`) ends `return
  brix_http_resolve_path_ex(...) == 0 ? 1 : 0`, collapsing the resolver's three
  distinct refusals — 403 escape, 404 internal name, 414 overflow — into one
  bit, and `s3_resolve_object_key` (`handler_dispatch.c:288-305`) maps the
  false to `NGX_HTTP_FORBIDDEN` / `AccessDenied`. So on a bucket with the flag
  off or absent, `GET ghost.cinfo` — a key that exists nowhere — is **403
  AccessDenied** while `GET ghost.dat` is **404 NoSuchKey**, and a client with
  no read access at all learns from the status alone that the NAME is reserved.
  That is the inference the 404 was chosen to prevent, and it is available to
  any unauthenticated probe that can reach the endpoint. The armed arm answers
  the same absent key 404, which pins the disclosure to the guard rather than
  to the storage layer. Cure: return the resolver's status rather than a
  boolean — `s3_resolve_key` already has it and throws it away; 414 wants
  distinguishing from 403 for the same reason. §D measures all four faces, with
  WebDAV over the same export as the control. **Fixed in the tree.**
  `s3_resolve_key_ex()` returns the resolver's status, `s3_resolve_key()` is
  kept as the boolean wrapper derived from it, and one new
  `s3_resolve_key_error()` maps status → (HTTP status, S3 code, message, metric
  event) in a single place. The four call sites that each resolved a key on
  their own — the object router, COPY's source leg, POST-form and the
  DeleteObjects batch — all go through it, because a fix at one of them would
  have left the other three answering 403 for a name the resolver called
  absent. **A status is not the whole answer, and that is the part the tests
  did not predict:** S3 DELETE of an absent key is 204, not 404, so routing the
  reserved key to a 404 would have left single-object DELETE disclosing after
  every other verb was closed — found by probing the fixed binary, not by a
  test. `s3_dispatch_object_absent()` (`handler_object_route.c`) now takes the
  whole answer: it re-runs the write gate and hands DELETE to
  `s3_delete_respond(r, ENOENT)`, so the shape matches and not merely the
  number. DeleteObjects reports `<Deleted>` for a reserved key and touches
  nothing, which is what it does for an absent one. The COPY leg needed one
  more step than the other three: threading the mapped answer through
  `s3_handle_copy_object` took it to CCN 16 and `check_complexity` refused it,
  so the source resolve moved into `s3_copy_resolve_source()` — a reserved
  source now leaves by the same door an absent one does (404 `NoSuchKey`, event
  `no_such_key`, byte-identical message) and only a genuine escape is
  `AccessDenied`. `test_s3_b.py` covers the three arms — `test_copy_object`,
  `test_copy_object_missing_source`, `test_copy_object_path_traversal` — and
  they pass against the rebuilt binary, as does the whole S3 family
  (27 files, 275 passed, 1 skipped).
- **DEFECT CANDIDATE #139 (observability, the reserved-name refusal is booked
  against the wrong event — file 36, FOUND AND FIXED IN THIS TRANCHE).** The
  same call site that chooses the 403 chooses the counter:
  `BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_ACCESS_DENIED])` at
  `handler_dispatch.c:300`. `brix_s3_events_total` carries a fixed eight-value
  `event` label (`metrics/s3.c:52-64`), `no_such_key` among them, and the
  request that a reserved-name refusal is supposed to be indistinguishable from
  books exactly that. So an operator watching the family sees an authorization
  failure where the resolver specified an absence, and because both land in one
  series with the same label set the two cannot be separated after the fact —
  invariant 8 rules out fixing this with a label. It travels with #138 and is
  cured by the same change. §E measures it as a delta and reads the whole
  family back, so "no other event absorbed it" is a measurement too. **Fixed in
  the tree** with #138: the event travels in the same mapped triple, so the
  refusal is booked against `no_such_key` and the two arms of the flag are no
  longer distinguishable in the metric either.
- **DEFECT CANDIDATE #140 (security, kXR_stat's refusal TEXT is a policy oracle
  — file 36, FOUND AND FIXED IN THIS TRANCHE).** On the root plane both
  refusals carry errnum 3011, which is where a reader would stop. The strings
  differ: a reserved name is `file not found` and a genuinely absent one is `No
  such file or directory`, and the two SWAP when the flag does — so `stat
  /ghost.cinfo`, a path that exists nowhere, tells the client the name is
  reserved on the disarmed arm and reports an ordinary absence on the armed
  one. kXR_open reaches the same guard (`open_request.c:205`) and answers both
  cases `file not found`; it is the control that makes this kXR_stat's own leak
  rather than a property of the guard. Cure: one string for both paths in
  `stat.c`, the one open already uses. §F measures all four combinations plus
  the open control. **Fixed in the tree** in `stat.c` and `statx.c` — both now
  answer `strerror(ENOENT)`, the text the miss they must be indistinguishable
  from carries. statx needed it too: it refuses the whole batch on one reserved
  member, so a fix confined to kXR_stat would only have moved the oracle to the
  batching verb. `open_request.c` is untouched and stays the control.
- **DEFECT CANDIDATE #141 (security, unlink is not gated and the two planes
  disagree — file 36, FOUND AND FIXED IN THIS TRANCHE).** The flag is read at
  exactly three root-plane call sites — `open_request.c:205`, `stat.c:316`,
  `statx.c:232` — and the unlink path is not among them. On the disarmed arm a
  client is told a sidecar does not exist by every reading verb it has (stat
  3011, open 3011, statx fails the whole batch, dirlist omits it) and kXR_rm on
  that same name returns `kXR_ok` and the file is gone. WebDAV's DELETE of the
  same name on the same export, through the same flag, is 404 and the file
  survives — so this is two implementations of one rule disagreeing rather than
  a deliberate decision to gate reads and not writes. The exposure is bounded
  by needing the exact name, but the names are a fixed lexical set and the
  objects are a cache's own metadata: unlinking a `.cinfo` beside a live data
  file is exactly the collision the guard's own comment says it exists to
  prevent ("never created … would collide with the cache's own sidecar
  naming"). Cure: the guard belongs on the unlink path, and the same question
  is worth asking of every other opcode that takes a path. §F is the
  measurement and the WebDAV control; a genuinely absent reserved name still
  reports 3011, so the path is not lenient, it simply never consults the flag.
  **Fixed in the tree**, and the "same question is worth asking of every other
  opcode" half is what decided where: the guard went into
  `brix_path_resolve_beneath` (`root/path/op_path.c`), the shared resolve core
  for rm, rmdir, mkdir, chmod, truncate, readlink, fattr and kXR_mv, so all of
  them inherit it at once and none can drift from its neighbour. It returns
  `NGX_DECLINED` — the gate's own "well-formed but missing" — so the refusal
  leaves by the same door a genuine miss does and the caller's error text
  cannot tell the two apart. **The count of call sites went from three to five,
  not four:** the fifth is `root/dirlist/handler.c`, where the same
  two-planes-disagree shape was still open on the collection ITSELF — WebDAV
  PROPFIND 404s `/adir.meta/` while root:// dirlist enumerated it. That guard
  is about the collection being NAMED; the per-entry filter that hides reserved
  MEMBERS is unconditional on every arm and is deliberately left alone.
- **DEFECT CANDIDATE #142 (correctness, one directive name accepts a duplicate
  on one plane and refuses it on the other, landing on the permissive arm —
  file 36, FOUND AND FIXED IN THIS TRANCHE).** `ngx_conf_set_flag_slot` opens
  with `if (*fp != NGX_CONF_UNSET) { return "is duplicate"; }`, which the
  stream declaration gets for free. The http declaration's custom setter
  (`webdav/module_acc_directives.c:59-82`) reads the token, writes
  `wc->common.cache_store_endpoint` and `sc->common.cache_store_endpoint`
  directly, and never tests the slot — so `brix_cache_store_endpoint off;`
  followed by `brix_cache_store_endpoint on;` in one location parses clean, in
  every http scope, in either order, and the SECOND line wins. Written as `off;
  on;` — the order a config acquires when a restriction is added above an
  existing line — the restriction is silently discarded and the reserved-name
  guard stays disarmed on both the WebDAV and the S3 loc-conf. The same pair in
  a stream server is a hard `emerg`. Cure: the `NGX_CONF_UNSET` test the stock
  setter performs, before the two writes. §G measures which line wins on the
  wire (the `dav-dup.test` face serves reserved names) and §J shows the parse
  asymmetry across all three http scopes against the stream control. **Fixed in
  the tree** — the setter tests both slots it is about to write, before the
  token parse, and returns nginx's own `"is duplicate"`. Testing both matters:
  reading one would leave the other reachable from a location the first module
  does not create. **The fix invalidated its own test face:** the duplicate is
  now a hard `emerg`, so a RUNNING vhost cannot carry it and the `dav-dup.test`
  location was rewritten to the single line the pair resolved to. The
  measurement moved to the parse tier (§G's first two cells and §J's matrix),
  which is where it belonged. §J also gained the negative the fix needs —
  http/server/location each own a loc-conf, so a restatement one scope down is
  not a duplicate and the three-scope composition must still parse. The twelve
  lines the check added also moved `module_acc_directives.c`'s two frozen
  duplication-backlog entries, so those two keys were shifted by hand rather
  than by `--regen`, which would have absorbed 86 unrelated blocks from other
  uncommitted work in the tree. A third key retired for real: backlog entry 419
  paired this setter with the ktls one, and the duplicate check is enough to
  tell them apart.
- **DEFECT CANDIDATE #143 (operability, one directive name, two spellings of
  one diagnostic — file 36, FOUND AND FIXED IN THIS TRANCHE).** nginx's own
  text is `invalid value "%s" in "%s" directive, it must be "on" or "off"`; the
  custom setter's is the same sentence with the pronoun dropped — `…directive,
  must be "on" or "off"`. So `brix_cache_store_endpoint maybe` produces one
  message in `http{}` and a different one in `stream{}`, for one directive, and
  an operator or a log scraper matching either string misses half its
  occurrences. Trivial to cure and worth curing because the setter exists only
  to perform the dual write; everything else it reimplements is a place to
  drift. §J pins both texts exactly, in both directions. **Fixed in the tree**
  — the custom setter now emits nginx's sentence verbatim, pronoun included,
  and §J asserts one wording across both declarations.
- **DEFECT CANDIDATE #144 (security, a reserved DIRECTORY hides only itself —
  file 36, FOUND AND FIXED IN THIS TRANCHE).** `brix_is_internal_name`
  (`fs/path/reserved_names.h`) matches suffixes and infixes against the FINAL
  path component, which is right for the sidecars it was written for and wrong
  for a directory. With the flag off, `GET /adir.meta/` is 404 and `PROPFIND
  /adir.meta/` is 404 — and `GET /adir.meta/inside.txt` is **200**, because the
  final component of that path is `inside.txt`. root:// agrees: `stat
  /adir.meta` is 3011 and `stat /adir.meta/inside.txt` succeeds, and root://
  dirlist enumerates the collection its own stat just refused, since the
  enumeration filters never consult the flag either. The result is a subtree
  the disarmed arm believes it is hiding and serves in full to anyone who names
  a member. Nothing in the tree creates such a directory today, which is why
  the hole has never been reached — and it is one request away: MKCOL of
  `*.meta/` on an armed endpoint creates one, after which the same export read
  through a disarmed one is in exactly this state. Cure: test every component,
  or state in the header that the predicate is defined on leaf names only and
  refuse a reserved component anywhere in the path. §I measures both planes
  plus a plain-directory control. **Fixed in the tree** —
  `brix_is_internal_name` walks every component. **The infix test had to be
  rewritten to do it, which is the part worth recording:** a component is a
  SLICE of the caller's path and carries no NUL of its own, so the `strstr()`
  the leaf-only version used would have run past its end into the next
  component. `brix_name_has_infix()` is the bounded `memcmp` loop that replaces
  it, and §K asserts `strstr(` no longer appears in the header's code at all.
  Every caller of the predicate — both HTTP planes, every root-plane guard, the
  four enumeration filters — inherited the widening at once, so the S3, WebDAV,
  root, dirlist-conformance, path-edge and cache families were re-run to show
  nothing legitimate was swallowed by it. They were re-run again on 08-20
  against the canonically rebuilt tree, after the last fix landed: the
  dirlist/path-edge/error and sidecar families 291 passed 1 xfailed, the
  fattr/openflags/WebDAV families 537 passed 9 xfailed, and the S3 family as
  above, alongside the four cross-plane files that also copy objects
  (`metrics_vfs_ops`, `cross_protocol_access_logging`, `cns_http`,
  `cachemx_ops_grid`) at 49 passed. 1152 passed, 1 skipped and 10 xfailed over
  54 files with the eight fixes in, and no arm of the widening reaching a name
  that is not reserved.
- **DEFECT CANDIDATE #145 (hygiene, three includes of a predicate nothing calls
  — file 36, FOUND AND FIXED IN THIS TRANCHE).**
  `protocols/root/dirlist/handler.c:15`,
  `protocols/root/read/open_request_resolve.c:11` and
  `protocols/root/read/stat_manager.c:7` each carry `#include
  "fs/path/reserved_names.h"` with a trailing comment naming
  `brix_is_internal_name` and saying "hide sidecars". None of the three calls
  it. Each of the three sits beside a file that does, so the reading is not
  "this file forgot to filter" but "the filtering moved and the include did
  not" — dead intent that reads, to the next person auditing the guard, as
  coverage. It is how a reviewer would conclude the dirlist path is filtered by
  the same rule the read path is, which §H shows it is not (dirlist filters
  unconditionally and ignores the flag). Cure: delete the three includes.
  **Fixed in the tree**, and #141 is why this one is not merely hygiene: two of
  the three stale includes sat on paths the guard was actually missing from, so
  the dead intent had been reading as coverage for exactly the gap it hid. Two
  were deleted; `dirlist/handler.c`'s became real when #141's fifth call site
  landed there. §K's cell was generalised from those three files to a scan of
  all of `src/`, so the next stale include is a failure and not a discovery.

**The browser's header comment names URIs that no longer exist, and that gets no
number.** `vfs_browse.c`'s WHAT block documents
`GET /xrootd/api/v1/vfs`, `/xrootd/api/v1/vfs/files` and
`/xrootd/api/v1/vfs/download`; the dispatcher matches `/brix/api/v1/vfs…`
(`dashboard/module_dispatch.c:101-103`), which is what file 28 drives and what
answers. It is pre-rebrand residue in a comment and
nothing is mis-served, but it is worth writing down here because this header is
also where the security rule for the surface is stated, and #107 is what happens
when a reader trusts it.

**The flag names half of §6.1, and that gets no number.**
`brix_webdav_redirect_dataserver` arms the EMITTING half only; the accepting
half — `webdav_redirect_signed_auth`, which verifies a `brixrdr.*` CGI and adopts
the identity it carries — is called first from `access_authenticate`
(`webdav/access_auth.c:376-386`) and is gated on `brix_http_secretkey` alone.
File 27 asserts it: at a location with the redirect arm explicitly OFF and
`brix_webdav_auth required`, a valid signed CGI is served the file and a
tampered one is 403. That is the intended topology rather than a defect — a data
server never sets the manager's flag, and the docs say the key "counts as a
credential verifier for `brix_webdav_auth required`" — but it is worth writing
down, because the arms census reads a flag's name as the feature's switch and
here it is half of one: configuring the shared key at a location is what makes
that location honour identities minted elsewhere, and turning the redirect flag
off does not take it back.

**`brix_zip_access off` answers a member request with the whole archive, and
that gets no number.** With the flag off the resolver never looks at
`?xrdcl.unzip=` (`read/open_request_resolve.c:264`), so the open falls through to
the ordinary whole-file path: file 24 measures a client asking for a 31-byte
member and receiving the 288-byte archive under `kXR_ok`, a nonexistent member
receiving the archive rather than `kXR_NotFound`, and a `../../etc/passwd`
member name receiving the archive rather than the `kXR_ArgInvalid` the armed arm
gives it. It reads like a silent substitution and it is not a defect, for two
reasons that are worth stating so the next reader does not re-open it: stock
XrdCl does `xrdcl.unzip` CLIENT-side — it reads the central directory and the
member bytes itself, which is exactly why the server path needed its own test
file to begin with — so the archive is the response that client is asking for
and the opaque is advisory; and nothing crosses an authorization boundary,
because the bytes returned are the bytes of the archive the same client is
already entitled to read at that URI. The residue is a naming one: the member
name is validated only where a member is actually resolved, which is the armed
arm, so the traversal refusal is a property of the feature rather than of the
export — worth knowing before someone cites it as a path-traversal control.

**The outbound leg pre-sends a cleartext `kXR_login` to a peer it has not
authenticated, and that gets no number.** `brix_upstream_build_bootstrap`
(`net/upstream/bootstrap.c`) packs handshake, `kXR_protocol` and `kXR_login`
into one write, so the login is on the wire before the server's kXR_gotoTLS
answer has been read, let alone its certificate checked; file 25 records it on
every plane, including the ones whose handshake is about to be refused, and the
stub has to drain that frame or TLS reads it as the ClientHello. It is not a
credential leak: the pre-sent login carries the connector's fixed anonymous
identity — username `xrd`, the worker pid, `kXR_ver005` — and nothing else, and
the credential the leg may later be asked for travels in `kXR_auth` after the
upgrade, which is why the re-login over TLS exists at all ("the server discards
the plaintext login that was pre-sent"). What it does disclose to an
unauthenticated peer is that the dialler is a brix worker and which pid it is,
which is worth knowing when reasoning about the leg but is not a finding.

**An enabled prefix flag captures part of the export namespace with no
config-time diagnostic — recorded as an observation, not a defect.**
`brix_webdav_tape_rest on` makes `/api/v1/` the Tape REST router's and
`brix_delegation_endpoint on` makes `/.well-known/brix-delegation/` the delegation
endpoint's, for every request in the location — *including* requests for objects
that really are on disk under those paths. File 14 measures it with one file per
prefix, seeded under the export root and reachable through the vhost whose flag is
off and not through the one whose flag is on: `GET /api/v1/plain.txt` answers 200
with its bytes on the `off` arm and 404 `{"detail":"unknown endpoint"}` on the
`on` arm, and `GET /.well-known/brix-delegation/request` answers 200 with its
bytes on all three disabled arms and 401 on the enabled one. It is an observation
rather than a defect because both prefixes are fixed by the protocols they
implement — WLCG Tape REST v1 and RFC 8615 — and shadowing is the only way to
serve them at all; what is missing is the advisory, since the export root is known
at merge time and could be probed for a colliding subtree the way
`brix_assert_dir_outside_export` already probes the stage and cache directories.
The `off` arm is the only way to see the capture at all, which is the reason it
took a value-granularity re-run to notice.

**And the mirror of it: `brix_webdav_dig off` does not remove a feature from a URI
subtree, it moves that subtree to a different authorization regime — also an
observation, not a defect.** With the flag on, everything under
`/.well-known/dig/` is governed by dig's own fail-closed allow-file: an anonymous
or unlisted principal is refused 403 (`dig/dig.c:58-113`, `:255-283`) and no
method but GET/HEAD is answered at all (405 from `dig_precheck`, `dig.c:170-172`).
With it off — including by the per-location opt-out under a server that wrote `on`
— the same subtree is governed by whatever the export's own policy is. File 15
measures that with `brix_webdav_auth optional`, where the anonymous request dig
refused is answered **200** with the operator's shadow object, and a `PUT` under
the reserved prefix that was 405-with-nothing-written becomes **201 and lands in
the export**. The export is the operator's and those bytes are theirs to publish,
so nothing here is wrong; what is worth recording is that the two regimes are not
comparable, so the flag is not a feature switch layered *on top of* the export's
authorization and turning it off is not a reduction in what the server does at
that URI. The absent spelling behaves identically to the written `off`, which
means every deployment that has never heard of the directive is already in the
second regime — and that is exactly the configuration nothing in the tree had
measured, because measuring it needs the seeded shadow object to have something
to answer *with*.

**DEFECT CANDIDATE #78 was withdrawn on measurement, twice, and is recorded as
an observation instead.** The first framing — that a child location's
`brix_read_only off` cannot undo a lock its server wrote — was measured against a
throwaway prototype that had no server-level `brix_allow_write`, so the 403 it
saw was a missing grant and not a stuck lock. Against the real template the
child's `off` is honoured (`/ri-off/` answers 201/204), for a mechanism worth
knowing: `brix_http_common_merge_loc_conf` calls **only**
`brix_shared_adopt_unified`, a fill-if-unset adopt with no defaults and no
`apply_read_only`, so the child inherits the server's `allow_write` *before*
`brix_shared_apply_read_only` runs for that child and finds `read_only 0`. The
residue is a diagnostic one: the config-time NOTICE says *"the export is
read-only; all write operations are rejected at the protocol edge (overrides
allow_write)"* — absolute language for a value whose scope is one server — and
nothing retracts it per location. That did not survive as a defect either,
because the endpoint-ready NOTICE discloses the truth one line per location: a
census of the twenty-two shows **14 posix `(read-only)` and 5 posix
`(read-write)`**, plus the 3 origin-backed arms whose export is the origin's
root, and the opted-out children are in the second list. §A asserts
both halves — the single absolute sentence, and the per-location census — so a
change to either has to be deliberate. The number is left unused rather than
recycled, because two revisions of the audit cite it.

**`brix_verify_write` gets no number, and that is the finding.** All three arms —
`on`, `off`, absent — answer PUT 204 and hand back a body the origin corrupted
after storing it, and the origin sees `HEAD` then `PUT` during the write and is
never re-read. The gate cannot fire because `brix_shared_adopt_unified()` omits
`verify_write` from its adopt list, so the location's value never reaches the
merged conf `put_setup.c:347` reads. That is **DEFECT #34's family** — a
common-module directive parsed but never adopted — already owned and enumerated
by `test_audit15j_zero_coverage_stragglers.py:306`, whose `known` set names
`verify_write` alongside `backend_token_aud`, `backend_sss_keytab`,
`backend_sts_flavor` and `seccomp`. File 8 §C contributes the first
**behavioural** evidence for any member of that set — until now the family was
pinned by reading the adopt list — and pins 15j as the owner so the two files
cannot drift apart.

**`brix_cvmfs_bundle off` has a diagnostic that names it and no way to write
it.** `cvmfs_reject()` (`gate.c:97-102`) logs a `cause="…"` span at WARN and
returns a bare status, so every refusal vocabulary in this area is an operator
reading and not a wire one — which is the right design, and which is also what
makes this inversion a real defect instead of a cosmetic one, because the log is
the only audience the sentence ever had. `cvmfs_gate_method()`
(`gate.c:295-307`) runs **before** `cvmfs_gate_route()` (`gate.c:503`) and its
carve-out is `if (!(lcf->cvmfs.bundle && r->method == NGX_HTTP_POST && …))
return cvmfs_reject(r, NGX_HTTP_NOT_ALLOWED, "method not allowed")`. So the
POST a batch-fetch client actually sends is refused with the generic sentence,
and `"bundle endpoint disabled (brix_cvmfs_bundle off)"` (`gate.c:426-439`) is
reachable only by GET or HEAD — the two methods the endpoint refuses as
`"bundle endpoint is POST-only"` even when the flag is **on**. Every method
therefore logs the sentence written for the other one, and an operator debugging
a broken batch fetch is never told which directive to flip. File 9 §A pins both
halves plus the `on`-arm control, so the day the method gate learns to consult
the class first, the pair fails and says so. No number because nothing is
mis-served and no state is wrong — the cure is to route before refusing the
method, or to name the flag in the method refusal when the class is BUNDLE.

**Turned off, the three reserved endpoint names under a cvmfs prefix refuse in
three different vocabularies at two statuses, and the third one is right for the
wrong reason.** `bundle` and `dict` both 403 with a cause naming their directive;
the swarm roster 403s with `"path is not a CVMFS traffic shape"`, which names
neither the flag nor the feature. That is not an oversight in the message but a
consequence of the mechanism: `brix_cvmfs_swarm off` does not disable the roster,
it never **registers** it, so `cvmfs_gate_meta()` does not intercept the path and
classification rejects it exactly as it would a typo. Worth writing down because
the operator symptom — a silent ring — is the one case where the log says nothing
about the subsystem that is off, and because it is the shape any future
"registered only when enabled" endpoint will inherit.

**`brix_scvmfs` is the one flag of the nine that is location-only, and the
asymmetry is invisible until a reload fails.** The other eight are
`NGX_HTTP_MAIN_CONF|SRV_CONF|LOC_CONF` (`directives_resilience.h`) and file 9 §K
parses all eight in all three scopes on both arms — 48 accepting cells.
`brix_scvmfs` is `NGX_HTTP_LOC_CONF` alone: written at `server{}` or `http{}` it
is refused with `"brix_scvmfs" directive is not allowed here`, on **both** arms.
So the obvious way to make a whole server's exports secure — a site-wide default
beside the eight flags that accept one — is a config that does not load, and the
obvious way to turn the layer off site-wide is too. Measured, not read off the
header, and pinned as a pair so a widened scope has to be deliberate. No number:
a directive may legitimately be location-only. The finding is that it sits in a
group of nine that is otherwise uniform and is documented alongside them.

Method notes this tranche adds to tranche 15's list:

- **A verdict the server must FETCH needs an instrument that can be told what to
  say.** Every revocation test in the suite until now used a CRL, which is a
  file; OCSP is a conversation, and asserting on it means owning the other end.
  The responder is therefore a fixture with a control plane, and the assertion
  that closes the attribution question — *which* certificate is being asked
  about — is read from the responder's log, not inferred from the verdict.
- **Reserve the unreachable endpoint.** `DEAD_PORT` is a ledger slot nothing
  binds, because "the responder did not answer" is one of the two arms
  `brix_ocsp_soft_fail` decides between and a port left to chance is a port some
  other suite eventually answers on. Same move as tranche 15's file 7.
- **A both-arms-unwritten flag is a crash surface, not a coverage number.** The
  first time file 1 wrote `on`, the worker died on every cell of the matrix, at
  a regular ~99 s per test — the client's timeout, not the server's latency.
  Reading that cadence as slowness rather than as a crash would have cost the
  finding; the error log said `exited on signal 11` and the matrix was a
  segfault reproducer that happened to be written as a test.
- **Do not hand pyOpenSSL a socket carrying a `settimeout()`.** `settimeout()`
  makes the fd non-blocking and runs the wait in Python, which the stdlib `ssl`
  module knows and pyOpenSSL does not, so `do_handshake()` raises
  `WantReadError` against a server behaving perfectly. File 2 hands OpenSSL a
  blocking fd and moves the bound into the kernel (`SO_RCVTIMEO`/`SO_SNDTIMEO`),
  which keeps the timeout without the false failure.
- **An unexpected failure is a second finding, not a threshold to loosen.** File
  3's ON arm was expected to keep the token out of the error log and did not.
  Weakening the assertion would have buried #68; splitting it into its own class,
  with the same request's clean access log as the control, is what turned one
  failure into a distinct defect with a distinct fix.
- **Warm up, do not subtract.** File 4's instrument counts connections at the
  origin, and a cold instance spends some on things that are not fills (origin
  selection, the RTT ranker's own per-thread curl handle). Measured cold the arms
  read 2 and N+1, and that `+1` would have to be written down as a constant
  nothing explains. One warm-up fetch before the reset makes them **0 and N** —
  the same fact with no magic number in it, and a reading that stays true if the
  worker ever grows a third thread that talks to the origin.
- **A flag whose only effect is on the wire needs the other end to be the
  instrument.** Nothing the listener emits distinguishes
  `brix_cvmfs_origin_reuse_conn`'s arms — same status, same bytes, same log. The
  mock Stratum-1 already counted accepts (`/ctl/connections`); what it needed was
  `--keepalive`, because against its default HTTP/1.0 face both arms read as one
  connection per request and the directive would have looked inert.
- **When the variable is the client's own address, move the client, not the
  server.** File 5's subject compares the peer address against the ticket, and
  nothing in the stock client, the harness or the config language can change
  where a connection appears to come from. An in-process relay that binds a
  second loopback address as its **source** does it in nine lines, needs no
  privileges, no second host and no netns, and — because krb5 has no channel
  binding — relays an AP-REQ that is byte-for-byte the one a direct client would
  have sent. The same instrument fits any check whose input is `c->addr_text`.
- **Provision the credential the check consumes, not the credential the suite
  has.** `kdc_helpers` mints an addressless ticket, which is correct for every
  other krb5 test and useless for this one: against it both arms of the flag
  behave identically. File 5 writes its own profile (`noaddresses = false` plus
  `extra_addresses`) and then **asserts the ticket's address list** with
  `klist -a -n` before using it — the pair is only a pair if the credential
  really names one address and not the other, and that is a property of MIT's
  address enumeration rather than of anything in this tree.
- **A silent arm is a finding when the loud arm is a security control.** The
  addressless case in file 5 is not a bug in the C — `krb5_rd_req()` is doing
  what the protocol says. It is a defect in what an operator can know, and the
  way to pin it is to assert the *absence*: no runtime line names the check, and
  the failure counter does not move. That kind of assertion goes stale in the
  right direction — the day someone adds the missing log line, the test fails and
  says which claim to retire.
- **Sign what the server canonicalises, not what the client sent.** File 6's
  first two query-bearing rows — `?list-type=2` and `?xrdcl.unzip=` — returned
  403 against a signer that emitted an empty canonical-query line, and the
  natural reading is "the feature refuses me". The server sorts the parameters
  and percent-encodes name and value before hashing
  (`auth_sigv4_verify_crypto.c:222`, `build_canonical_qs`), so a signer that
  skips that step fails every request with a query string, for a reason that has
  nothing to do with the directive under test. Any file that drives a query
  through SigV4 needs those five lines; there is no shared signer in the suite,
  and the house pattern is a per-file one.
- **Measure the whole table before writing the first assertion.** Every row of
  file 6's arm × probe matrix was driven live in a scratch instance first, which
  is what turned three surprises into findings instead of into failing tests
  with plausible explanations: the nested 405 (#71), the fact that the OFF arms
  still refuse a forged *request* signature, and the list cache's mtime key.
  Writing the file first would have produced assertions that encode a guess and
  then get relaxed until they pass.
- **A cache keyed on an mtime needs the clock to have moved.** File 6's
  invalidation case writes into the export root to bump the key, but `st_mtime`
  is whole seconds here: a directory written twice inside one second keeps one
  mtime, and the test would have been a coin flip. Parking until the root's
  mtime falls strictly behind the wall clock costs at most a second and makes
  the case deterministic. It is the same reason `worker_processes 1` is in the
  config, one level up: the cache is per worker, so a
  second worker would answer the repeat listing cold and the ON arm would read
  like the OFF arm about half the time.
- **Do not poll for a resource whose failed acquisition renews the lock.** The
  first attempt to find out how long a kernel flow-label entry lingers was a 4 Hz
  loop, and it never saw the label free — because a refused `IPV6_FLOWLABEL_MGR`
  lease stamps `lastuse` on the blocking entry, so the measurement was extending
  what it was measuring. Sparse single attempts separated by long sleeps gave the
  answer in three tries (busy at 6 s, free at 10 s, free at 15 s). File 7 keeps
  that shape everywhere it waits: `_settle_for_a_clean_probe()` is a flat sleep
  with a comment saying why it must not be a poll, and the one retry in
  `_hold_the_probe_label()` is deliberately a single retry after a full settle.
  The same trap has a cousin in Python: a prototype that printed its progress
  produced no output at all and looked hung, because `print()` block-buffers to a
  pipe — `flush=True`, or `python3 -u`, before concluding anything about a
  measurement harness that prints nothing.
- **A test file can reproduce the defect it is testing for, between its own
  tests.** #74 surfaced not from the poison test written for it but from a test in
  a different section failing on a stray log line: the per-test lifecycle fixture
  gives every test a fresh nginx, every fresh nginx probes the one fixed label,
  and one test's probe was refused by its predecessor's lingering lease. Two
  consequences worth generalising — an assertion that a log is *clean* should name
  the lines it forbids (`_origin_diagnostics`) rather than grep for a word as
  broad as "firefly", and an assertion that depends on a capability probe must
  either wait the capability out or be written as a disjunction with the log line
  that says the probe was refused.
- **When a positive fails, check the primitive before the plumbing.** Six parse
  negatives asserting that `ON` is rejected failed, and the cause was the
  primitive rather than the test: `ngx_conf_set_flag_slot` compares with
  `ngx_strcasecmp`, so `ON`, `OFF`, `On` and `oFf` are all legal while `1`, `0`,
  `yes` and `true` are all errors. That is now pinned as a positive of its own,
  because the audit's step-2 measurement is a grep: had the comparison been
  case-sensitive, a corpus that wrote `OFF` would have been scored as never
  writing the off arm and this file would rest on a miscount. Re-running the
  step-2 grep case-insensitively found exactly one off arm in the corpus, and it
  is in documentation — `docs/10-reference/comparison/deployment-reference.md:411`
  offers `brix_pmark_flowlabel off` as the "Firefly-only parity with stock
  XRootD" root:// recipe — so the configuration the reference manual advertises
  had no test on either plane. §G now parses that recipe as a whole and not only
  as four independent directives.
- **An arm is a location when the conf it selects is per-location.** File 6 landed
  on one listener because an S3 arm needs its own bucket; file 7 lands on one
  listener for a different reason — `brix_pmark_conf_t` is `NGX_HTTP_LOC_CONF`, so
  an arm costs a `location {}` and not a `listen`. Eighteen arms then collapse
  onto thirteen, because the arm that writes only the master switch is
  simultaneously the `absent` arm of every flag it does not write, and that is a
  property to exploit deliberately (and document in the config header) rather
  than a shortcut. Binding the same port a second time on `[::1]` is the same
  economy one level down: the flow-label technique only exists over real IPv6, and
  a second `listen` in the same server is not a second ledger slot.
- **Measure against the template you are going to ship, not a prototype of it.**
  #78 was written up as a defect, twice, off a scratch config that differed from
  the real one in a single line — no server-level `brix_allow_write` — and the
  403 that difference produced was read as an inheritance failure. The prototype
  is the right tool for *finding* the table; the assertions have to be re-measured
  against the exact rendered `.conf` the test will launch, because the config IS
  the experiment's other half. Two revisions of this audit cite a number that
  never survived that step.
- **When a flag's scope is a `server`, the cheap server is a `server_name`.** All
  six of file 8's flags are legal in `http{}`, `server{}` and `location{}`, so
  half of what a value means is what a child can take back from it — and a
  server-level arm needs a whole `server{}`. Another `server_name` on the *same*
  `listen`, selected with a `Host:` header, is a whole `server{}` for the price of
  a dict lookup in the test: five vhosts, twenty-two locations, **one** ledger
  port. It only works because every vhost carries the same backend over the same
  seeded tree, which is what makes a verdict that differs between two of them the
  flag and nothing else.
- **A per-connection cache needs a per-connection instrument.** #79 is invisible
  to any client that opens a fresh connection per request, which is every other
  file in this suite (`requests` without a `Session`, one URL at a time). Driving
  two locations down **one** keep-alive connection, in both orders, is four lines
  and it is the whole finding: the flag's verdict turns out to depend on which
  location the connection *started* on. Any conf value consulted only where a
  cached per-connection object is created is exposed the same way, and the order
  reversal is what separates a leak from a mis-merge.
- **Read the raw body, or every compression arm looks identical.** `requests`
  gunzips transparently, so an `on` arm and an `off` arm both hand back the same
  1410 bytes and the same `len()`. The negotiation is only visible through
  `urllib3` with `decode_content=False` — which is also the only way to see that
  the compressed answer switches to chunked and drops `Content-Length`, and to
  assert that gzip decodes byte-exact to what was seeded rather than merely that a
  header was set.
- **Beware the confounder that makes the subject unreachable.** §C's origin has to
  be asked twice for the read-back verify to have anything to verify, and a
  writable whole-object `http://` backend with no stage tier is silently given a
  brix-managed store under `/tmp` (`runtime_server_backend.c:256-267`) — after
  which the read-back comes off local disk and the origin's lie never surfaces.
  `brix_stage off` on those three locations is not tidiness; without it the
  section measures the wrong storage.
- **One brix protocol per port survives into the parse tier.** §B's subject
  started as extra directives inside the scaffold's existing `/probe/` server and
  collided with it (`brix_s3` beside `brix_webdav` on one listen is refused before
  the subject is reached), which produced a 26-cell table with one anomalous row
  that looked like a finding. Rendering the subject as its **own** `server{}` at
  `http{}` level gave a uniform 27 cells. Two placeholder ports cover all three
  servers in that scaffold, because `nginx -t` accepts an http server and a stream
  server on the same port — measured in both orders, not assumed.
- **A pin on a C symbol must match the definition, not the forward declaration.**
  The §H assertion that `brix_http_common_merge_loc_conf` calls only
  `brix_shared_adopt_unified` located the function with
  `index("brix_http_common_merge_loc_conf(ngx_conf_t")` and found the prototype,
  200 lines above the body, so it read the wrong window and failed. Anchoring on
  `"static char *\nbrix_http_common_merge_loc_conf("` — the return type sits on
  its own line only at the definition, which is the house style the coding
  standard requires — is the fix, and it is worth a comment saying why, because
  the naive anchor looks correct.
- **When `off` and absent merge to the same value, the third arm is the whole
  method.** All nine of file 9's flags merge to 0, so a value comparison is
  impossible and the only readable question is what the feature *does*. That is
  answerable — but a two-arm table (`on` versus `off`) would prove nothing,
  because a silent `off` arm is indistinguishable from a config where the flag
  never reached the location, from a corpus with nothing to find, and from an
  instrument that is not looking. Every section therefore reads **three** arms and
  writes every support directive on all of them: the seed ring on a `swarm off`
  location, the scrub interval on a `scrub off` one, the allowlist and the bounds
  on all three `unified_origin` arms. A closed arm that also dropped its support
  directive would be a two-directive change and the reading would no longer belong
  to the flag.
- **Verify the scope you are about to organise the file around.** File 9's plan
  assumed the nine flags were per-location, because all nine are declared for
  `location{}` and eight for all three http scopes. Three of them are actually
  registered per **export** and one writes a process-wide latch, which is not
  visible in the command table at all — it is visible in
  `cvmfs_module_build.c:281-315` and `cvmfs_module_merge.c:167-172`. That
  discovery is #81/#82 and it also dictates the harness: one nginx **instance**
  per arm rather than one location per arm, ~46 restarts on a single ledger port.
  A file that had put two arms in one worker would have measured whichever merged
  last and called it inheritance.
- **A refusal vocabulary is a log reading, not a wire reading.** Seven
  assertions in file 9 were first written against `response.text` and failed
  against nginx's stock 403 page. `cvmfs_reject()` writes `cause="…"` to the
  error log and returns a bare status — correctly, a cache must not narrate its
  configuration to a stranger. The house helper is therefore a
  `cause="([^"]*)"` extractor scoped to `cvmfs-reject:` lines, and the negatives
  ("the refusal does not name the feature") have to be written against the
  extracted causes rather than against the transcript, which contains the tmp
  prefix and hence the words `on` and `off`.
- **When a bound and a retry ladder disagree, assert the destination, not the
  status.** #81's blast-radius case was measured at 502 in the prototype and
  answered 504 in the shipped template, because the fill's retry ladder outlives
  the default client hold and the status is simply whichever bound expires first.
  Widening the assertion to `in (502, 504)` would have been a threshold loosened
  to pass; the fix is to assert the thing the finding is actually about — the
  request went to the OTHER location's origin, and the live origin this location
  names was never contacted, which the mock's own request log states without
  ambiguity. Bounding both `origin_connect_timeout` and `client_hold` then turns a
  30-second case into a 5-second one, and the bounds must be written identically
  in both locations because `origin_connect_timeout` reaches a process-wide
  setter.
- **A latch is pinned twice: once by behaviour and once by census.** A runtime
  test can only say the trace latch did not clear in the orders it tried. Walking
  `src/` for `brix_origin_trace_set(` and asserting that no call site passes 0 —
  while also asserting the setter still *has* call sites, so the pin fails loudly
  if the symbol is renamed rather than passing vacuously — says the stronger
  thing. Same instrument as tranche 15's #58 census.
- **Step 2's grep cannot tell a value that is exercised from a value that is
  merely spelled, and re-reading the hit is the only way to know.** Re-running the
  sweep for file 9's nine found **seven** with no `off` arm anywhere in
  `tests/` or `k8s-tests/`, and two — `brix_cvmfs_trace off` and
  `brix_cvmfs_unified_origin off` — with exactly one hit each, the same one: a row
  in `test_cvmfs_conformance_srv_config.py`'s `_SINGLE_SHOT` table (`:63`, `:74`).
  That table feeds two tests, and neither is coverage of the value.
  `test_duplicate_directive_rejected` asserts `nginx -t` **refuses** the second
  occurrence, so no merge ever runs; `test_full_inventory_single_config_loads`
  renders every row into one config and asserts only that it loads. Nothing reads
  a behaviour, and in the `trace` case the inventory writes `off` with no `on`
  anywhere in the same config — which is exactly why the process-wide latch (#80)
  survived a suite that already spelled the token. So the honest score for the
  group is "seven never written, two written where writing them cannot fail", and
  the general rule is that a step-2 hit is a pointer to a row to read, not a
  coverage claim. The inverse blind spot is worth the same caution: a directive
  written through a template placeholder or composed from a parametrised fragment
  is invisible to the grep entirely.

Ledger/ladder: `lc-audit16a-ocsp` (30761, extras `ON_PORT` 30762, `HARD_PORT`
30763, `DEF_PORT` 30764, `RESP_PORT` 30765 for the responder and `DEAD_PORT`
30766, reserved and never bound); `lc-audit16b-staple` (30767, extras `ON_PORT`
30768, `DEF_PORT` 30769); `lc-audit16c-qtoken` (30770, one listener — the three
arms are three locations sharing one access log); `lc-audit16d-reuse` (30771,
extra `MOCK_PORT` 30772 for the keep-alive origin); `lc-audit16e-ipcheck` (30773,
extras `OFF_PORT` 30774, `ABSENT_PORT` 30775, `RELAY_PORT` 30776 — bound by the
test's own relay, never by nginx — and `METRICS_PORT` 30777);
`lc-audit16f-s3flags` (30778, ONE slot for sixteen locations and the `/metrics`
face, all on one listener); `lc-audit16g-pmark` (30779, ONE slot for thirteen
locations and `/metrics`, and the same port bound a second time on `[::1]` where
the host has an IPv6 loopback — the firefly collector is an in-process UDP sink on
an ephemeral port, the documented exemption `test_pmark.py` already takes, and the
origin report is fixed at 10514 inside `pmark.h:40`, so neither is a ledger slot);
`lc-audit16h-shared` (30780, extra `ORIGIN_PORT` 30781 for the origin that lies on
read-back — ONE slot for five vhosts and twenty-two locations, since a
`server_name` is a whole `server{}` and not a whole listener);
`lc-audit16i-cvmfs` (30782, extras `MOCK_PORT` 30783 for the live mock Stratum-1
every fill comes from and `DEAD_PORT` 30784, reserved and never bound — it is
three things at once: the unreachable authority §G aims the proxy face at, the
dead half of §F's seed ring, and the not-yet-deployed Stratum-1 of §J's second
export. ONE nginx slot for **~46 instances**, because the arms cannot share a
worker: three of the nine flags register per export, one latches
process-wide, and `brix_cvmfs_origin_connect_timeout` — needed to bound two
sections — is a process-wide setter too); and `lc-audit16j-caps` (30785, extras `OFF_PORT`
30786, `SUPER_PORT` 30787, `WRTS_PORT` 30788, `MAP_PORT` 30789, `COLLON_PORT`
30790, `COLLOFF_PORT` 30791, `CMS_PORT` 30792, `DS_PORT` 30793 and `ROLE_PORT`
30794 — ten ports for ten stream servers, but ONE instance, which is the point:
`caps.*` is srv_conf, so ten verdicts out of one worker is also the reading that
the scope is per-server).
`LIFECYCLE_SHARED_WIDTH`
**747 → 781** in ten steps (747 → 753 → 756 → 757 → 759 → 764 → 765 → 766 → 768 → 771 → 781), and every
offset below it repacked as the running sum (`LIFECYCLE_EXCLUSIVE_OFFSET`
925 → 959, `PORT_COUNT` 2027 → **2061**) — the first two width bumps landed without the
repack and the band check caught the 9-port overlap, which is the same lesson the
08-16 note above records. Guards green: `test_fleet_ports.py`,
`test_fleet_declares.py`, `test_no_hardcoded_hosts.py`, `check_ports_doc.py`,
`check_template_refs.py`, plus `test_reload.py` and `test_cms_sss_keytab.py` as
repack sanity runs from two of the moved bands, and `test_fleet_port_uniqueness.py`,
`test_conftest_fleet_lifecycle.py`, `check_file_size.py`, `check_doc_paths.py` and
`check_todo_fixme.py` for file 6, and all eleven of those plus `check_doc_links.py`
again for file 7, and all twelve again for file 8 plus `check_duplication.py` and
`check_readme_coverage.py`, and all fourteen again for file 9, and all fourteen
again for file 10. Measured on 08-17:
**47 passed in
4 min 10 s**, **17 passed in 4 s**, **37 passed in 6 s**, **33 passed in
24 s**, **40 passed in 10 s**, **112 passed in 12 s**, **178 passed in
2 min 33 s**, **241 passed in 36 s**, **184 passed in 10 min 27 s** and
**134 passed in 1 min 16 s**, one
process each — file 8 re-run from a
second ladder band as the repack sanity check (**241 passed in 44 s**). File 9 is
the tranche's slowest by a factor of four for a structural reason and not a fixable
one: ~46 nginx starts, and five sections have to wait on a background service (a
scrub cursor, a prefetch, a swarm gossip interval) rather than on a response. Its
parse tier is 118 of the 184 cases and runs in **12 s**, which is the tier to
re-run while iterating. File 7's
two and a half minutes are almost
entirely the four flat settle waits #74 forces on it; without them the flow-label
positives would have to be disjunctions, and the file would assert less in less
time. File 10 splits the same way for the opposite reason — 96 of its 134 cases
are the parse tier plus the two `nginx -t` cross-checks and run in **7 s**, while
the 38 live cases cost the rest, because §E has to wait for a data node to
register with a CMS listener on a 2 s heartbeat before the collapse cache has a
registry to be a cache *of*.

**No both-arms-unwritten directive is left.** All seven are closed: six
behaviourally, and `brix_backend_passthrough_persist` at parse level only,
because it has no reader anywhere in `src/`, `client/` or `shared/` and is
already pinned as DEFECT #35 by `test_audit15j_zero_coverage_stragglers.py` —
writing its value is the whole of what can be asserted about it. That leaves the
directives with exactly ONE unwritten arm, and the arithmetic is worth stating
because the earlier note rounded it: 106 unwritten pairs over 99 directives is
7 × 2 + 92 × 1, so **92** directives have one arm unwritten, not 99. File 6
closes five of them, file 7 six more — all six pmark flags, which are one
feature and one X-macro, and so are worth taking as a group rather than five at a
time — and file 8 another six, the shared-http block of
`brix_http_common_commands`, which is a group in the strongest sense available:
one table, one setter, one merge, one adopt list. File 9 closes nine, the CVMFS
resilience group, which is a group by feature rather than by table: nine
directives across `directives_resilience.h` and `directives_secure.h` whose `off`
arm is the same question — what does this cache stop doing — asked of nine
different faces. File 10 closes five, the node-capability block of
`root/stream/directives_caps.h`, which is a group in file 8's sense — five
consecutive `NGX_CONF_FLAG` entries in one table, behind one merge — and which
answers the tranche's question in the sharpest form it has taken yet: one of the
five `off` arms is the only way to get a config-time check on a *different*
directive (#86). That is 31 of the 92, and 14 + 31 = **45 pairs closed of the
106**, leaving **61 open** as the rest of this tranche. Two of file 9's nine were
scored as unwritten by a grep that found the token and did not read the row it was
in (see the method note); they are counted as closed here because what file 9
writes is the first exercise of either, and the arithmetic above is unaffected —
they were in the 106 already.

## Method

1. **Directive surface.** Every `ngx_command_t` entry across `src/**/*.{c,h}`
   (command tables live in headers too — `directives_*.h` on both planes), plus
   the two prefix-pasting macro families in
   `src/core/config/tier_directives.h` (`BRIX_TIER_DIRECTIVES` — 17 cache/stage
   directives, expanded for the http common module and the stream plane — and
   `BRIX_BACKEND_ASYNC_DIRECTIVES` — 3). Literal-string scans miss the macro
   names entirely; a first extraction returned 507, the true surface is
   **524 distinct directive names**.
2. **Coverage corpus.** 2,946 files under `tests/`, `k8s-tests/`, `deploy/`,
   `contrib/`, `docker/`, `examples/` (`.conf .py .tmpl .template .yaml .yml
   .sh`). A directive is "covered" if its name appears anywhere in that corpus.
   **Corrected by tranche 14 (2026-08-17):** that is a search, not a claim. A
   name that occurs only inside a `.conf` some test launches is covered by
   `nginx -t` proving it parses and merges, and by nothing else. The right
   question is *"is there a test whose verdict changes when this directive's
   value changes?"*, which is what the re-run asked; it returned 13 directives
   this step as originally written had scored covered. All 13 are closed — see
   tranche 14.
   **Corrected again by tranche 15 (2026-08-17), and this correction applies to
   step 1 as well:** both steps count directive NAMES, and for an enum-valued
   directive a name is answered by ONE of its tokens. Re-run per *(directive,
   value)* pair over the 36 `ngx_conf_enum_t` tables in `src/`, the surface is
   **93 pairs**, of which 48 are written in the corpus and **45 are written
   nowhere**. The next pass must count pairs, and it must count them **off the
   enum table, never off the spellings found in configs**: `ngx_conf_set_enum_
   slot` compares with `ngx_strcasecmp` after testing `name.len`, so `AWS` and
   `aws` are the same pair and a prefix is refused, and the hand-written
   `brix_seccomp` setter matches case-insensitively too (pinned by
   `test_audit15aa_default_tokens.py::test_the_token_is_case_insensitive`). All
   45 are closed bar three arms recorded as gaps — see tranche 15.
   **Corrected a third time by tranche 16 (2026-08-17), same correction, wider
   surface:** an enum table is not the only place a name outruns its values. A
   *flag* has exactly two, and one token answers the name just as completely.
   Re-run per *(directive, value)* over the **128 `ngx_conf_set_flag_slot`
   directives** in `src/`, the surface is **256 pairs**: 138 are written
   literally somewhere in the corpus, 12 more only ever reach a config through
   an interpolated `{PLACEHOLDER}`, and **106 are written nowhere in any form**,
   spread over 99 directives. Seven directives have BOTH arms unwritten —
   `brix_backend_passthrough_persist`, `brix_cvmfs_origin_reuse_conn`,
   `brix_http_query_token`, `brix_krb5_ip_check`, `brix_ocsp_enable`,
   `brix_ocsp_soft_fail`, `brix_ocsp_stapling` — which is the sharpest form of
   the miscount: not one arm untested but a directive whose branch nothing has
   ever entered. Count flags off the setter, not off the configs: like the enum
   setter, `ngx_conf_set_flag_slot` tests `len` and then `ngx_strcasecmp`, so
   `On` is the same pair as `on` and `1`/`true`/`yes` are not pairs at all
   (pinned by `test_audit16a_ocsp_flags.py` §F). Tranche 16 is closing these —
   see below.
3. **Pairwise matrix.** 1,089 config units (446 `tests/**/*.conf` + 643 python
   files containing config text, fleet spec catalogues included), classified by
   45 feature markers (protocol / auth scheme / security option / storage-tier
   option / transfer-plane option). A pair is "co-tested" only when one unit
   carries both markers — the right semantics for "one server instance runs
   both features at once".
4. **Supportability check.** Every headline finding was verified against the
   source: the directive/config field has a runtime consumer (not dead config),
   and the combination is not rejected at merge/validation time. Pairs that are
   illegal, plane-inapplicable, or by-design exclusions are listed in §D so the
   next audit does not re-derive them.

## A. Zero-coverage directives — 95 of 524

95 directives appear in **no** test, lab, chart, or deploy artifact anywhere in
the repository. Full list in the appendix; ranked clusters:

### A1. Security-relevant (highest priority)

| Cluster | Directives | Wiring evidence |
|---|---|---|
| httpguard signature engine | `brix_guard_signature`, `brix_guard_default_signatures`, `brix_guard_valid_method`, `brix_guard_bounce_status` | `src/net/httpguard/module.c` parses signatures and narrows the method grammar per location; the custom-signature language and method-narrowing have zero tests while the base `brix_guard on` path has 11 units |
| WebDAV token introspection | `brix_webdav_token_introspect_url`, `brix_webdav_token_introspect_ttl`, `brix_webdav_revoke_cache` | remote introspection is an auth-decision path — an introspection bug is an auth bypass; never exercised |
| WebDAV secret rotation | `brix_webdav_macaroon_secret_old`, `brix_webdav_token_config`, `brix_webdav_token_clock_skew` | genuine plane-parity holes: the stream twins (`brix_macaroon_secret_old`, `brix_token_config`, clock-skew) are tested, the WebDAV twins never — these are separately named, separately parsed directives |
| WebDAV client-cert chain depth | `brix_webdav_verify_depth` | consumed in `src/protocols/webdav/delegation.c:235` chain verification; depth-limit bypass/lockout behavior untested |
| Dashboard hardening | `brix_dashboard_users`, `brix_dashboard_session_ttl`, `brix_dashboard_cookie_path`, `brix_dashboard_cluster_stale_after` | dashboard auth/session controls untested — closed by tranches 3 and 6, and `brix_dashboard_session_ttl`'s *expiry* by tranche 8 (`test_audit15h_dashboard_session_ttl.py`: the cookie is an HMAC over `<ts>`, so a test that knows the password mints one at any age instead of waiting) |
| tap-proxy TLS/audit | `brix_tap_proxy_audit_log`, `brix_tap_proxy_login_user`, `brix_tap_proxy_upstream_tls_name` | upstream TLS name pinning + audit trail untested |
| Stream signing policy | `brix_signing_policy` | the *other* sigver directives (`brix_security_level`, `brix_min_sec_level`, `brix_signing_required`) landed with tests 08-05; the policy selector did not |
| Misc | `brix_mirror_token`, `brix_csi_block`, `brix_session_log`, `brix_backend_sss_keytab`, `brix_backend_s3_sts_role` | `brix_backend_sss_keytab` is the *outbound* sss identity toward a backend — the credential-forwarding suites exercised other mechanisms, never this one |

### A2. Whole features with zero tests

- **`brix_virtual_redirector`** — feeds the capability bits advertised in the
  root:// login response (`src/protocols/root/session/protocol.c:81`). A whole
  operating mode, never configured by any test.
- **`brix_throttle_zone` + `brix_throttle_max_open_files`** — the open-files
  throttle (`src/net/ratelimit/throttle_compat.c`, open-inc/dec on the SHM
  leaky-bucket zone; validated at merge in `server_conf_merge_security.c:177`).
  Distinct from the *bandwidth* throttle (`brix_throttle_bandwidth_*`), which
  phase-92 tested. The open-files sibling has zero tests.
- **`brix_read_only`** — http-plane global RO flag; on cvmfs it force-clears
  `allow_write` (`cvmfs_module_merge.c:106`). Distinct from
  `brix_allow_write off` (which is tested). Never set anywhere.
- **TPC outbound OAuth2 client-credentials flow** —
  `brix_tpc_outbound_client_id/_client_secret/_scope/_token_endpoint`: the
  entire acquire-a-token-then-push flow is untested (only
  `brix_tpc_outbound_bearer_file`/`_tls`/`_passthrough` are exercised).
- **TPC lifetime enforcement** — `brix_tpc_max_transfer_secs`,
  `brix_tpc_transfer_max_age`: the kill-switches for runaway/stale transfers.
  **Closed by tranche 8** (`test_audit15h_tpc_lifetime.py`): the wall-clock cap
  needs a source paced below it rather than an idle one, and the reaper is
  DEFECT #22 — it only runs when the 1024-entry registry is completely full.
- **WebDAV TPC tuning surface** — `brix_webdav_tpc_credential_forward`,
  `_curl`, `_low_speed_bytes`, `_low_speed_secs`, `_marker_interval`,
  `_max_streams`, `_token_client_id`, `_token_client_secret`. Note
  `credential_forward`: the credential-forwarding *suites* exist but drive
  forwarding through other planes; this directive itself never appears — its
  default-path behavior is what's actually covered.
- **WT staging policy** — `brix_cache_wt_stage_backend`,
  `brix_cache_wt_stage_block_size`, `brix_wt_allow_prefix`,
  `brix_wt_deny_prefix`: write-through staging to an *alternate* backend and
  the prefix allow/deny policy.
- **SSI/CTA integration** — `brix_ssi_cta_executor`, `brix_ssi_cta_journal`,
  `brix_ssi_request_max`, `brix_ssi_response_max` (4 of 4 directives).
- **io_uring guard rails** — `brix_io_uring_panic_file`,
  `brix_io_uring_restrict` (the base `brix_io_uring on` is tested).
- **WebDAV fd-cache tuning** — all five `brix_webdav_open_file_cache*`.
  **Closed by tranche 16 file 30**, which is also where the zero coverage turns
  out to have been the least of it: the family parses, merges and allocates and
  is then never read (#110).

### A3. Resource-bound / DoS caps (zero-tested limits)

`brix_zip_cd_max_bytes` (stream) · `brix_webdav_zip_cd_max_bytes` ·
`brix_s3_zip_cd_max_bytes` · `brix_zip_stage_max_bytes` — the ZIP
central-directory bounds on all three planes; these are DoS caps, and no test
proves an oversized CD is refused. Also `brix_s3_mpu_max_age` (MPU GC),
`brix_cache_lock_timeout`, `brix_webdav_lock_timeout`, `brix_scan_max_files`,
`brix_ckscan_depth`, `brix_ckscan_max_files`, `brix_cache_allow_prefix`,
`brix_cache_index_cache` (the one tier-macro directive with zero units).

### A4. Tuning knobs (lower priority, still zero)

CMS: `brix_cms_fxhold`, `_load_weight`, `_perf_interval`, `_send_timeout`,
`_vnid`, `_tcp_keepalive`, `_tcp_user_timeout`, `brix_cms_server_tcp_keepalive`,
`brix_cms_server_tcp_user_timeout`, `brix_manager_stale_after` ·
acc: `brix_acc_gidlifetime`, `_gidretran`, `_nisdomain`, `_pgo`, `_spacechar` ·
pmark: `brix_pmark_domain`, `_firefly`, `_firefly_origin`, `_flowlabel` (base
`brix_pmark` is tested; the four knobs are not, on any plane) ·
misc: `brix_s3_token_clock_skew`, `brix_srr_id`, `brix_tcp_congestion`,
`brix_inherit_parent_group`, `brix_webdav_redirect_scheme`.

## B. Untested pairwise combinations (verified supported)

Each pair below has **zero** co-occurrence across all 1,089 config units, both
features individually appear in ≥3 units, and the combination was verified
legal and wired.

### B1. Security interactions

1. **sigver × TPC (native)** — request signing enforced while delegated TPC
   runs. The TPC control ops (`tpc.src`/`tpc.dst` opens, sync/close) are
   exactly the mutating ops signing exists to protect; no test signs them.
2. **sigver × substreams** — `kXR_bind`-attached data paths under
   `brix_signing_required`. The signing sequence-number window is
   per-connection; whether a bound path shares or restarts the window is
   untested correctness- and security-relevant behavior.
3. **substreams × TLS** — a bound data path arriving on a TLS listener.
   `src/protocols/root/session/bind.c` contains no TLS handling (termination
   happens at accept), which *should* make this work for free — no test proves
   it, including the pgwrite/CRC path over a TLS-bound substream.
4. **tls_require × TPC** — a TPC transfer where one leg demands the in-band
   TLS upgrade. Does the internal TPC client honor `kXR_tlsRequired`? Zero
   units. (tls_require lives in exactly 3 units, all dedicated to itself.)
5. **guard × WebDAV TPC** — httpguard filtering the COPY method. Pairs with
   the zero-covered `brix_guard_valid_method`: whether a guard-narrowed
   location still admits COPY/MOVE for TPC is untested in both directions.
6. **readonly × TPC (native, destination)** — `brix_allow_write off` on a TPC
   *destination* must refuse the pull cleanly. The security-negative is
   untested (webdav twin has exactly 1 unit, `nginx_webdav_tpc.conf`).
7. **authdb × delegation / authdb × TPC** — authorization-db rules evaluated
   against a *delegated* identity rather than the connecting one. Zero units
   combine them. **Closed**: × TPC by tranche 7
   (`test_audit15g_tpc_crosses.py`), × delegation by tranche 8
   (`test_audit15h_authdb_delegation.py`) — every `u` rule in the tree was
   `u *`, so nothing had ever asked *which* DN a proxy login is authorized
   as. It is the EEC subject, not the per-mint proxy leaf. DEFECT #24.
8. **krb5 × TLS** — `brix_auth krb5` on a TLS listener: zero. krb5 is also
   never combined with TPC, stage, or any non-posix backend (its only pairings
   are authdb, cache-origin, delegation — one unit each).
   **Closed by tranche 8** (`test_audit15h_krb5_tls.py`): the missing half was
   the PKI, not the realm. Wiring it surfaced DEFECT #23 — abandoning an armed
   in-protocol TLS upgrade was a use-after-free that killed the worker; fixed
   in the tree 2026-08-16, and that file is now the regression guard.
9. **host auth × anything** — `brix_auth host` pairs only with authdb; host
   auth × {tls, cache, stage, tpc, cms} are all zero. Host-based trust plus
   TLS (the classic "verify the reverse-DNS matches the cert" interaction) is
   untested.
10. **macaroon × voms / macaroon × delegation** — macaroon minting for an
    identity established via VOMS/proxy chain: zero units.
    **Closed by tranche 8** (`test_audit15h_macaroon_voms.py`): every macaroon
    file authenticated its issuance request with another macaroon, so
    `mac_authorize`'s non-token caller had never run. DEFECT #25 — WebDAV
    authorizes the proxy leaf where root:// authorizes the EEC, off one
    `brix_authdb`.

### B2. Integrity / durability interactions

11. **checksum_on_write × stage** (WebDAV) — a PUT checksummed at ingest, then
    flushed asynchronously by the WT tier: no test proves the checksum
    survives (or is re-verified at) the flush. Same for
    **checksum_on_write × S3 backend** and **× io_uring** (all zero).
12. **async backend queue × cache/stage tiers** — `brix_backend_async on`
    co-resident with `brix_cache_store`/`brix_stage`: both subsystems mutate
    backend namespace with different durability windows; zero units combine
    them (async_be pairs with *no* storage feature at all).
13. **io_uring × stage / × passthrough** — the uring read path under
    write-through staging or a passthrough spool fill: zero.
14. **passthrough × stage / passthrough × readonly** — passthrough spool on an
    instance that also runs a write tier, or on a read-only instance: zero.

### B3. Cluster / reporting interactions

15. **SRR × cache / SRR × cms** — the storage-resource report built by
    `src/protocols/srr/builder.c` (statvfs per share) on a cache-tier member
    or a cms cluster member: SRR appears only in 3 standalone units. What the
    report claims about a cache instance's capacity is untested.
16. **cms × tpc_outbound / cms × proxy_fwd** — a cluster data-server that also
    initiates outbound TPC, or forwards: zero.
17. **cvmfs × gridftp** — the only proto×proto pair with zero co-residence
    (every other protocol pair is co-tested somewhere, including via the
    multiproto configs). Low value, listed for completeness.
    **Closed by tranche 8** (`test_audit15h_cvmfs_gridftp.py`), and it was not
    low value: standing both planes on one export root — the realistic
    Stratum-0-plus-GridFTP deployment — showed the two disagree about what is
    publishable. The http plane rejects anything that is not a CVMFS traffic
    shape before it resolves a path; the stream plane confines the tree and
    nothing else, and serves the repository's master signing key to an
    anonymous RETR. DEFECT #28.

## C. Previously known and still open (from the 08-04 audit — not re-counted)

Confirmed still-zero by this pass's matrix, already on record: TPC × sss
(live), TPC × non-posix backends, TPC × cache_store, TPC × TLS × GSI, WebDAV
GSI/delegation *push* leg, the three mid-transfer resilience legs (reload
during cache-fill, unlink during active transfer, eviction during active
read), `--verify` strict mode, sd_http 180 s stall.

**Closed by tranche 7** (2026-08-15), leaving only the rows that need a live
external service or a real delegated identity:

| §C row | closed by | outcome |
| --- | --- | --- |
| reload during cache-fill | `test_audit15g_reload_during_fill.py` | DEFECT #19 |
| unlink during active transfer | `test_audit15g_unlink_during_transfer.py` | as designed |
| eviction during active read | `test_audit15g_evict_during_read.py` | DEFECT #18 |
| sd_http 180 s stall | `test_audit15g_sd_http_deadline.py` | as designed |
| TPC × cache_store | `test_audit15g_tpc_crosses.py` | DEFECT #21 |
| TPC × non-posix backends | `test_audit15g_tpc_crosses.py` | DEFECT #21 |
| `--verify` strict mode | `test_audit15g_verify_strict.py` | fail-open, pinned |

**Closed by tranche 8** (2026-08-16) — the last three rows, none of which
actually needed infrastructure the suite cannot stand up. The "needs a live
external" verdict had been carried unexamined from the 08-04 audit; each row
was re-read against the source before being re-deferred, and each dissolved:

| §C row | closed by | why it was thought to be blocked | outcome |
| --- | --- | --- | --- |
| TPC × TLS × GSI | `test_audit15h_tpc_gsi_tls.py` | assumed to need a built `xrdcp` and two hosts | the rendezvous key is one process-wide SHM table, so an anonymous ARM face beside the authenticated ones drives it from sockets — DEFECT #26 |
| TPC × sss (live) | `test_audit15h_tpc_sss.py` | assumed to mean an outbound sss credential | there is no sss anywhere under `src/tpc/`; the row is the client-facing legs plus the capability boundary, and the refusal must name a credential that works — as designed |
| WebDAV GSI/delegation *push* leg | `test_audit15h_webdav_gsi_push.py` | assumed to need a real remote peer | the leg was already covered; what was missing was a peer that logs `$ssl_client_s_dn` and one that mandates a client cert — DEFECT #27 |

§C is now **closed in full**. §B1.7's "authdb × TPC" is closed by the same
tpc_crosses file, the authdb *load-failure* tail it exposed is closed by
`test_audit15g_authdb_load_failure.py` (DEFECT #20), and §B1.7's remaining
half — authdb × *delegation* — is closed by
`test_audit15h_authdb_delegation.py` (DEFECT #24).

## D. Dismissed pairs — checked and not gaps

**Guarded since tranche 9** (`tests/test_audit15i_plane_pins.py`, 14 tests). A
dismissal is a claim about the config surface, and it is only durable while the
construction holds — every item below is now an `nginx -t` assertion that fails
if the construction changes. One correction the guards produced: the cvmfs item
is right for a stronger reason than given, and the read_only path it *does* cite
turns out to disarm the stronger guard (defect candidate #32).

- **auth × auth on one server** — `brix_auth` is `NGX_CONF_TAKE1`
  (`directives_auth.h:12`): one scheme per stream server block. Same-unit
  scheme pairs are unsupported by construction (mixed-auth *clusters* are
  covered by the chaos mixed-auth helpers).
- **cvmfs × auth/write features** — cvmfs is designed anonymous read-only;
  the merge even force-clears `allow_write` under `read_only`. *Corrected in
  tranche 9:* the first-line guard is stronger than the force-clear —
  `brix_cvmfs_reject_unsupported` (`cvmfs_module_build.c:97`) makes
  `brix_allow_write on` in a cvmfs location a hard `nginx -t` EMERG, and
  refuses staging the same way. The force-clear runs *earlier* and therefore
  silences that EMERG whenever `brix_read_only on` is also present — defect
  candidate #32.
- **gridftp × brix_auth/tls markers** — GSI and control-channel TLS are
  intrinsic to the gsiftp protocol, not expressed through these directives;
  the zeros are detector artifacts, not gaps. **Overturned by tranche 16 file
  31.** The reading assumed a GSI plane is a GSI-only plane. It is not:
  `brix_gridftp_gsi on` adds `AUTH GSSAPI` to the FEAT list and takes nothing
  away, so the doc's "production form" gateway still accepts an anonymous
  cleartext `USER`/`PASS` and serves a full read-write session (#111). The row
  was a real gap in the strongest sense — the pair nobody wrote is the pair that
  would have found it.
- **webdav × sigver/substreams** — kXR wire-protocol features; no WebDAV twin
  exists (nothing to test).
- **root × checksum_on_write** — `brix_webdav_checksum_on_write` is
  WebDAV-only; there is deliberately no stream twin (stream uses on-demand
  `kXR_chksum`). Worth noting as a *parity decision*, not a coverage gap.
- **checksum_on_write × io_uring** (listed under §B2.11) — plane-vacuous, for
  the reason above plus its mirror: `brix_io_uring` is declared only on the
  stream plane (`src/protocols/root/stream/directives_cache.h:198`). One
  directive is http-only and the other stream-only, so no location can carry
  both. Tranche 5 (2026-08-15). The other two thirds of that row — × stage
  (tranche 4) and × S3 backend (tranche 5) — are real and are closed.
- **tls_require × implicit-TLS listener** — vacuous (the connection is already
  TLS before the handshake).
- **root × srr / root × proxy_fwd** — http-plane features; artifact of marker
  granularity.

## E. Method notes for the next pass

- **The tier-macro hole:** literal `ngx_string("brix_...")` scans miss every
  directive born from `BRIX_TIER_DIRECTIVES` / `BRIX_BACKEND_ASYNC_DIRECTIVES`
  (prefix string-pasting). Any future surface extraction must expand those
  macros or read `tier_directives.h` by hand. This is also a growth risk: a
  new macro family silently hides new directives from name-based guards.
  **Guarded since tranche 9** (`tests/test_audit15i_tier_macro_surface.py`, 10
  tests): the factory inventory is closed, the hole's shape is pinned (17 of
  the 20 generated names have no literal declaration anywhere in `src/`), the
  hidden surface is proven live on both planes, and the expansion now lives in
  one place a new family's author is forced to visit. The risk had already
  materialised once — 7 of the 20 are absent from
  `docs/03-configuration/directives.md` (defect candidate #33).
- Fleet registry confs (`/tmp/xrd-test/registry/*/conf/nginx.conf`) were not
  running during this pass; the checked-in specs and configs they are
  generated from were used instead, which is the durable ground truth anyway.
- Unit granularity is per-file; a pair counts as co-tested even if the two
  features sit in different server blocks of one conf. Zero counts are
  therefore *conservative* — every zero really is a zero.
  **Re-measured in tranche 11, and the unstated corollary is the expensive
  half: the NON-zero counts are not conservative.** Run per server block
  (2467 blocks vs 1784 file units), 24 pairs this pass scored as co-tested turn
  out to have their two markers in blocks that never share a request — which is
  not step 3's declared semantics ("one server instance runs both features at
  once"). Eight are closed by
  `tests/configs/nginx_audit15k_s3cores.conf` + `tests/test_audit15k_s3_coresidency.py`
  (42 tests, defect candidates #36–#38); the other 16 are listed in tranche 11
  and are open. **Any future pass must count pairs per server block**, and any
  claim of the form "feature A and feature B are tested together" must name the
  block, not the file.
- **A block-granularity matrix must model inheritance.** Directives declared in
  the `http {}` / `stream {}` context above a server block apply inside it, so
  a matrix that reads only block bodies reports pairs as split that nginx
  merges. Tranche 11's first cut did exactly that and invented 21 gaps out of
  45. Attribute the surrounding context to every block in the file.

## Appendix — the 95 zero-coverage directives

**Closed 2026-08-15 (tranche 6).** Re-running the §Method measurement over the
same corpus, **all 95 now appear** — 32 in a `.conf` template, 63 in a config
built inline by a test (the bulk of those in
`test_audit15_zero_directive_parse.py`, which is parse-tier by design). The
last two to fall were `brix_acc_pgo` and `brix_acc_gidretran`, both of which
had been filed as needing a fixture-user lab and needed only `brix_auth unix`
plus the account the suite already runs as. Two names carried a caveat rather
than a behavioural test — `brix_cms_tcp_user_timeout` and
`brix_cms_server_tcp_user_timeout` were set and parsed but were filed as having
no local observable. **Tranche 9 closed the client leg:** the caveat had
conflated readback with observability, and the three tests appended to
`tests/test_audit15f_cms_node_legs.py` observe the knob behaviourally by
black-holing the *connect* under a 30 s `brix_cms_send_timeout`, leaving the
kernel as the only thing that can end the dial. **Tranche 10 closed the last one:**
`brix_cms_server_tcp_user_timeout` guards an already-established inbound
session, so making it fire needs a peer whose kernel stops answering — and
`tests/test_audit15j_cms_server_uto.py` builds exactly that inside one
`podman unshare unshare -n -m` namespace (`nft` DROP on the node's port after
the session is up). It tears down at 3.41 s with `ETIMEDOUT`; the
no-directive control, same DROP, does not. **No name in this appendix carries a
caveat any more.**

Re-running the §Method measurement on 2026-08-16 against the grown tree put the
surface at **555** directives and returned **seven** further names with zero
coverage — a different list from this one, closed by tranche 10 and recorded
there, not appended here: this appendix is the 08-15 measurement and is left as
measured.

brix_acc_gidlifetime · brix_acc_gidretran · brix_acc_nisdomain · brix_acc_pgo ·
brix_acc_spacechar · brix_backend_s3_sts_role · brix_backend_sss_keytab ·
brix_cache_allow_prefix · brix_cache_index_cache · brix_cache_lock_timeout ·
brix_cache_wt_stage_backend · brix_cache_wt_stage_block_size ·
brix_ckscan_depth · brix_ckscan_max_files · brix_cms_fxhold ·
brix_cms_load_weight · brix_cms_perf_interval · brix_cms_send_timeout ·
brix_cms_server_tcp_keepalive · brix_cms_server_tcp_user_timeout ·
brix_cms_tcp_keepalive · brix_cms_tcp_user_timeout · brix_cms_vnid ·
brix_csi_block · brix_dashboard_cluster_stale_after ·
brix_dashboard_cookie_path · brix_dashboard_session_ttl · brix_dashboard_users ·
brix_guard_bounce_status · brix_guard_default_signatures ·
brix_guard_signature · brix_guard_valid_method · brix_inherit_parent_group ·
brix_io_uring_panic_file · brix_io_uring_restrict · brix_manager_stale_after ·
brix_mirror_token · brix_pmark_domain · brix_pmark_firefly ·
brix_pmark_firefly_origin · brix_pmark_flowlabel · brix_read_only ·
brix_s3_mpu_max_age · brix_s3_token_clock_skew · brix_s3_zip_cd_max_bytes ·
brix_scan_max_files · brix_session_log · brix_signing_policy · brix_srr_id ·
brix_ssi_cta_executor · brix_ssi_cta_journal · brix_ssi_request_max ·
brix_ssi_response_max · brix_tap_proxy_audit_log · brix_tap_proxy_login_user ·
brix_tap_proxy_upstream_tls_name · brix_tcp_congestion ·
brix_throttle_max_open_files · brix_throttle_zone · brix_tpc_max_transfer_secs ·
brix_tpc_outbound_client_id · brix_tpc_outbound_client_secret ·
brix_tpc_outbound_scope · brix_tpc_outbound_token_endpoint ·
brix_tpc_transfer_max_age · brix_virtual_redirector · brix_webdav_lock_timeout ·
brix_webdav_macaroon_location · brix_webdav_macaroon_max_validity ·
brix_webdav_macaroon_secret_old · brix_webdav_open_file_cache ·
brix_webdav_open_file_cache_errors · brix_webdav_open_file_cache_events ·
brix_webdav_open_file_cache_min_uses · brix_webdav_open_file_cache_valid ·
brix_webdav_redirect_scheme · brix_webdav_revoke_cache ·
brix_webdav_token_clock_skew · brix_webdav_token_config ·
brix_webdav_token_introspect_ttl · brix_webdav_token_introspect_url ·
brix_webdav_tpc_credential_forward · brix_webdav_tpc_curl ·
brix_webdav_tpc_low_speed_bytes · brix_webdav_tpc_low_speed_secs ·
brix_webdav_tpc_marker_interval · brix_webdav_tpc_max_streams ·
brix_webdav_tpc_token_client_id · brix_webdav_tpc_token_client_secret ·
brix_webdav_verify_depth · brix_webdav_zip_cd_max_bytes · brix_wt_allow_prefix ·
brix_wt_deny_prefix · brix_zip_cd_max_bytes · brix_zip_stage_max_bytes
