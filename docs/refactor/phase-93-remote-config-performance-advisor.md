# Phase 93 — Remote config & performance advisor: scrape → classify → recommend for remote XRootD endpoints

**Status:** **LANDED (client slices S1–S5), 2026-08-03.** Originally drafted as a
DESIGN / PROPOSAL; the client-side advisor (S1–S5) is now implemented, built
clean, and tested. S6 (server-side authoritative read surface) remains deferred /
opt-in. It scopes expanding the existing `xrddiag` diagnostic family so a remote
operator can point the client at a remote XRootD server (data server,
redirector/manager, or protocol gateway), have it scrape every fact reachable
over the wire, and receive a classified verdict plus a concrete remedy for each
detected misconfiguration or performance fault.

> **As-built (2026-08-03).** Implemented inline, unprivileged. New TU
> `client/apps/diag/diag_doctor_audit.c` (424 lines) holds the value-predicates,
> the Qconfig/Qspace scrape, the single-endpoint config/capacity/perf rules, the
> `--all-servers` fan-out, and the fleet cross-cluster diff. Edited:
> `diag_internal.h` (`doctor_cfg` block + `diag_args` fields + prototypes),
> `xrddiag.c` (`--config-audit`/`--all-servers`/`--cap-threshold` opts + a
> `capacity`/`kXR_NoSpace` DX_RULES row + usage), `diag_doctor.c` (scrape/rules
> wired into `doctor_one`; config block into text+JSON renderers; fan-out entry),
> `diag_doctor_proto.c` (`cns-stat-drift` + ghost/stale split in `doctor_cms`).
> **Deviations from this plan, corrected as-built:**
> 1. **Build governance (§8.1 was wrong):** the client TU is registered **only**
>    in `client/Makefile` (`xrddiag_OBJS`), **not** the repo-root `./config` —
>    verified `./config` references no client `.c` at all (it is server-module
>    only). The committed `client/Makefile` was additionally found to be missing
>    the existing `diag_*` split-sibling objects from `xrddiag_OBJS` (a fresh
>    `make xrddiag` could not link); restored alongside the new object.
> 2. **Probe-id length:** `dx_finding.probe` is `char[16]`, so the fleet-balance
>    finding id is **`cap-imbalance`** (13 ch), not the over-long
>    `capacity-imbalance` (18 ch, silently truncated by `dx_record`).
> **Extension (2026-08-03) — mesh diagram (`--map`).** New TU
> `client/apps/diag/diag_doctor_graph.c` (181 lines) renders the topology the
> fan-out already discovers over the wire (`eps[0]`=manager, `eps[1..]`=CMS-located
> data servers) as a picture: `--map` draws an ASCII tree above the normal report;
> `--map-format dot` emits a standalone Graphviz digraph (pipe to `dot -Tpng`);
> `--map-format mermaid` emits a standalone Mermaid `graph TD` — both graph-only
> (no report noise) with node fill/class coloured by the per-node health verdict.
> Pure formatting over the scraped `doctor_ep[]` — **no new wire, no connection.**
> `--map` implies the config scrape (so role/version/capacity labels populate) and
> routes through the fan-out path. PII-free beyond the cluster-member authorities
> that *are* the topology (no path, token, or credential; host label capped at 72
> chars). Wiring: `diag_args.{map,map_format}` + prototypes in `diag_internal.h`;
> `--map`/`--map-format` `DX_OPTS` rows + usage in `xrddiag.c`; scrape-gate +
> fan-out render + routing in `diag_doctor.c`; object in `client/Makefile`.
> **Tests (all green):** `client/apps/diag/diag_doctor_graph_unittest.c` +
> `tests/test_doctor_graph_unit.py` (format classifier + all three renderers over
> a synthetic mesh, incl. skipped-node styling, stub-include, fast tier), and 4
> e2e cases in `tests/test_config_audit.py` (§5: ASCII tree, DOT graph-only,
> Mermaid graph-only, PII guard across all three formats).
>
> **Extension (2026-08-03) — mesh latency (`--latency`) + IPv6 skip.** New TU
> `client/apps/diag/diag_doctor_latency.c` (221 lines). `--latency` (with
> `--latency-count N`, default 5) times a **bi-directional round-trip** against
> every reachable mesh node over the two XRootD control planes — the data-server
> plane (`kXR_stat "/"`) and the CMS redirect plane (`kXR_locate "/"`, the query
> the CMSD answers) — reporting min/avg/max ms per plane; comparing the two
> surfaces an overloaded manager/CMSD vs a healthy DS. Each sample is a full
> request→reply, so the figure is round-trip (out and back) by construction. Pure
> composition of the public `brix_stat`/`brix_locate` API timed with
> `CLOCK_MONOTONIC` — **no new wire**; informational (never changes the worst
> verdict); rendered as a text table (ASCII/report mode) or a per-endpoint
> `"latency"` JSON object; suppressed under a graph-only `--map-format dot|mermaid`.
> **IPv6 skip:** `doctor_have_ipv6()` (a connected-UDP route probe, no packet sent)
> + `doctor_host_ipv6_only()` (getaddrinfo AAAA-only) let `doctor_fanout` mark an
> IPv6-only located server **SKIPPED** — not a red connect failure — when the
> local host has no IPv6 route, so the mesh verdict reflects the fleet, not our
> vantage. New `doctor_ep` fields `skipped` + `doctor_lat lat`; renderers
> (ASCII/DOT/Mermaid/text/JSON) show a distinct SKIP token / `lightskyblue` fill /
> dashed `skip` class. Wiring: `diag_args.{latency,latency_count}` + prototypes in
> `diag_internal.h`; `--latency`/`--latency-count` `DX_OPTS` + usage in `xrddiag.c`;
> probe/render/skip-report/JSON + fan-out routing in `diag_doctor.c`; object in
> `client/Makefile`. **Verified live** against `root://eospublic.cern.ch:1094//eos`
> with an LHCb VOMS proxy: manager RTT xrootd 32.0/32.3/32.8 ms · cms 32.2/32.9/34.6
> ms, and the IPv6-only FST rendered SKIP instead of a false DOWN. **Tests (all
> green):** `diag_doctor_latency_unittest.c` + `tests/test_doctor_latency_unit.py`
> (render/JSON emitters, IPv6-only classifier, probe unreachable branch,
> stub-include) and 4 e2e cases in `tests/test_config_audit.py` §6 (latency table,
> latency JSON, off-by-default, PII guard).
>
> **Extension (2026-08-03) — CMS-plane node classification (map redesign).** The
> map no longer flattens the fleet to "manager + servers" from the opaque Qconfig
> `role`. The kXR_locate answer itself types every node: each token is
> `<type><access>host:port` — type `S`/`s` = data server, `M`/`m` = subordinate
> manager (redirector), lowercase = pending (queued/staging); access `r`/`w` =
> read-only / read-write. New static `doctor_locate_classify()` (in
> `diag_doctor_audit.c`) parses that into a `doctor_cmsloc {role, pending, write,
> reported}` carried on every `doctor_ep` — **including nodes we can never connect
> to inbound** (IPv6-only, firewalled). That is the answer to "if inbound access
> isn't allowed, query the host over CMSD": the locate reply *is* the CMSD
> talking, so a SKIP holder is now typed `data server, read-only` instead of a
> blank. The root is typed `redirector` when it located other hosts (fixing EOS's
> `role=none`). Renderers distinguish kinds: ASCII prints `redirector` /
> `data server rw|ro [pending]`; DOT gives redirectors `box3d` vs servers `box`;
> Mermaid gives redirectors a hexagon `{{…}}` vs servers a rectangle `[…]`; the
> text report adds a `cms:` line and the SKIP line names the CMS verdict; JSON
> gains a per-endpoint `"cms":{reported,role,access,pending}` object. Pure parse +
> format over the existing locate — **no new wire**. **Verified live** against
> `root://eospublic.cern.ch:1094//eos`: root rendered `redirector`, the IPv6-only
> FST rendered `data server ro` + SKIP. **Tests (all green):** classifier unit
> (`diag_doctor_audit_unittest.c::test_locate_classify` — `S/s/M/m`, `r/w`,
> bracketed IPv6, malformed), renderer unit (`diag_doctor_graph_unittest.c`
> redirector/server/access/pending + shape/hexagon) and 2 e2e in
> `tests/test_config_audit.py` §5 (`test_map_ascii_tree` role detection,
> `test_map_cms_roles_json` structural `cms` object).
>
> **Extension (2026-08-03) — EOS dialect for `--map` (speak EOS to find the FST
> farm).** The XRootD mesh (kXR_locate / CMSD) is *structurally blind* to an EOS
> FST farm: an EOS MGM answers `kXR_locate` for **any** path with itself plus the
> aggregate space report, revealing the storage nodes only at open/redirect time
> (confirmed live against eospublic — locate returns the MGM + 5.15 PB aggregate,
> never an FST). To draw the real cluster, `--map` now speaks EOS's own
> out-of-band command channel: the client opens the magic path `/proc/{user,admin}/`
> with the command in the CGI opaque and reads the reply envelope
> `mgm.proc.stdout=…&mgm.proc.stderr=…&mgm.proc.retc=N`. New TU
> `client/apps/diag/diag_doctor_eos.c` (393 ln): `/proc/user/?mgm.cmd=version`
> **detects** the MGM (`EOS_INSTANCE` / `EOS_SERVER_VERSION` banner), then
> `/proc/admin/?mgm.cmd=fs&mgm.subcmd=ls&mgm.outformat=m` **enumerates** the FSTs,
> replacing the locate-blind self-node with the real farm (`arr[1..]`, each an
> `doctor_ep` typed `DOC_EOS_FST` with host, geotag, booted/active, configstatus
> and capacity). `fs ls` is admin-gated: an identity without admin rights (e.g.
> one nginx maps to `nobody`) fails the `/proc/admin/` **open** with
> NotAuthorized — *recognised*, not unknown — so the MGM is marked `gated` and the
> map degrades gracefully to the detection banner. The transport
> (`doctor_eos_proc` open+grow-read+close; proc replies stat as size 0 so the read
> loops to EOF) and `doctor_eos_map` orchestrator are the **only** wire code;
> every parser — `doctor_eos_stdout` (envelope span), `doctor_eos_kv` (exact
> token-boundary key match, so `host` never matches inside `hostport`),
> `doctor_eos_retc`, `doctor_eos_parse_version`, `doctor_eos_parse_fs`
> (`fs ls -m` monitoring format → FST endpoints) — is pure over a caller buffer.
> Renderers: the ASCII/DOT/Mermaid map gains an `EOS <instance> v<ver>` token on
> the MGM and `EOS FST rw|ro` / `geo=…` on each FST (health from the MGM's
> booted/active flags via `map_health`, since an FST is never inbound-probed — it
> is not falsely rendered gray/DOWN); the text report adds an `eos:` line
> (`doctor_eos_report_mgm` / `_report_fst`) and JSON a per-endpoint `"eos":{…}`
> object (`doctor_eos_emit_json`). Wired into `doctor_fanout`
> (`diag_doctor_audit.c`, tail) behind `--map` — a non-EOS mesh is untouched.
> **Verified live** against `root://eospublic.cern.ch:1094//eos` with the LHCb
> proxy: map shows `redirector … EOS eospublic v5.3.36`, report shows
> `eos: EOS MGM eospublic v5.3.36 (FST inventory admin-gated — not enumerable with
> this identity)`. **Tests (all green):** `diag_doctor_eos_unittest.c` +
> `tests/test_doctor_eos_unit.py` (stub-include; the pure parsers over the genuine
> eospublic version envelope + a constructed `fs ls -m` fixture — three FSTs
> exercising green/yellow/red health — plus all three renderers and the
> `doctor_eos_map` early guard), and a `test_config_audit.py` §5 e2e
> (`test_map_non_eos_untouched`: a stock server emits no `eos:` line / no `eos`
> JSON object). Build: object in `client/Makefile` `xrddiag_OBJS`; the audit
> unit stubs `doctor_eos_map` (the fan-out now calls it).
>
> **Extension (2026-08-03) — unprivileged FST discovery via `fileinfo` replica
> sampling.** The `fs ls` enumeration above is admin-gated, so under an ordinary VO
> proxy (eospublic maps ours to `nobody`) the map degraded to just the MGM banner —
> the FST farm stayed invisible to exactly the identity most operators actually
> hold. EOS's **user**-plane `fileinfo` command closes that gap: `fileinfo <path>`
> works for any reader and prints the FSTs holding *that file's* replicas. So when
> the `/proc/admin/` `fs ls` open returns NotAuthorized, `doctor_eos_map` now falls
> back to `doctor_eos_discover_fileinfo` (new TU
> `client/apps/diag/diag_doctor_eos_fileinfo.c`): a bounded DFS from the map target
> (`brix_dirlist`, budgets `EOS_WALK_DIRS`/`_FILES`/`_FSTS`/`_STACK` = 24/16/32/48)
> samples files, issues `fileinfo` per file over the same `doctor_eos_proc`
> transport, and **unions the distinct FSTs** their replica tables name into
> `arr[1..]` (deduped by host via `eos_fst_present`). Wire discovery, not
> inventory — nodes are honestly tagged `sampled` and rendered **"via fileinfo
> replica sampling"** (text/JSON) / carried in the map legend as *partial* coverage,
> never as a complete farm listing. The MGM route **ignores the `-m` monitoring
> flag** on `fileinfo` and always returns a human box-drawing table, so the parser
> (`doctor_eos_parse_fileinfo`) is table-structural, not key=value: strip ANSI CSI
> escapes (`eos_strip_ansi` — the `active` cell is a coloured `online`), whitespace-
> tokenise, and accept a row as a replica when it is `≥9` tokens with `tok[0]`/`tok[1]`
> all-digits and `tok[2]` alphabetic (`eos_is_replica_row`); `eos_fill_rep` lifts
> host/geotag/configstatus/booted/active, and `eos_add_fst` materialises a
> `DOC_EOS_FST` `doctor_ep` (port defaults to 1095 — `fileinfo` omits it; write from
> `configstatus` containing `rw`). Everything but the walk/transport is pure over a
> caller buffer; `doctor_eos_url_path` (pure) extracts the walk root from the map
> URL. **Verified live** against `root://eospublic.cern.ch:1094//eos/opendata/lhcb`
> with the LHCb proxy: 30 FSTs discovered (full geotags, all GREEN), report
> `eos: EOS MGM eospublic v5.3.36 (29 FSTs via fileinfo replica sampling — partial,
> admin fs ls gated)`, JSON `"gated":true,"sampled":true`. **Tests (all green):**
> new `diag_doctor_eos_fileinfo_unittest.c` + `tests/test_doctor_eos_fileinfo_unit.py`
> (stub-include; `url_path` cases, `parse_fileinfo` over a **genuine** eospublic
> `fileinfo` table, and an end-to-end faked-wire walk of a two-level tree with
> overlapping replica sets proving dedup — union A∪B = 3 distinct), extended
> `diag_doctor_eos_unittest.c` (sampled branch of `_report_mgm`/`_report_fst`/
> `_emit_json`), and `test_config_audit.py` `test_map_non_eos_untouched` now also
> asserts a stock server emits no `"fileinfo replica sampling"` text. Build: object
> after `diag_doctor_eos.o` in `client/Makefile` `xrddiag_OBJS`; both new functions
> refactored to ≤15 CCN (lizard `-C 15` clean) and the file is 347 ln (≤600 cap).
>
> **Live cross-site validation (2026-08-03) — GOCDB-sourced production endpoints.**
> Ran `remote-doctor --map` with the LHCb VOMS proxy against production XRootD
> storage discovered from the EGI GOCDB PI
> (`get_service?sitename=…`) for two UK GridPP Tier-2 sites plus the LHCb-gated CERN
> EOS instance:
>
> | Target (GOCDB) | Server | Result |
> |---|---|---|
> | `root://eoslhcb.cern.ch:1094//eos/lhcb` | EOS MGM v5.3.36 | ✅ **login OK, 25 nodes** — 24 FSTs via `fileinfo` replica sampling (admin `fs ls` gated for our nobody-map), full geotags, all GREEN. Second independent live proof of the S5p fallback, on an instance that **requires** LHCb creds. |
> | `root://cephc02.gla.scotgrid.ac.uk:1094//cephfs/ops/` (Glasgow, CephFS/XRootD) | XRootD (host cert: UK e-Science CA 2B) | ✅ **GSI now authenticates** (`[ok] auth authenticated`) after the client fix below; remaining `[3010] permission denied` on the path is site authz, identical to what stock `xrdfs` returns. |
> | `root://xgate.hec.lancs.ac.uk:1094//cephfs/grid/ops` (Lancaster, CephFS/XRootD) | XRootD (host cert: UK e-Science CA 2B) | ✅ **GSI now authenticates** after the fix; residual `NotAuthorized` on the path matches stock `xrdfs`'s `[3010] permission denied`. |
>
> **Root-caused and FIXED (GSI client, `client/lib/auth/sec/sec_gsi.c`).** All four
> servers advertise the *identical* gsi capability `v:10600,c:ssl`; they differ only
> in the `ca:` hint = the CA chain of the **server's own host certificate** — CERN
> (`5168735f.0|4339b4bc.0`, accepted) vs UK e-Science CA 2B
> (`530f7122.0|ffc3d59b.0`, **two hashes for one CA**). The bug: `gsi_first` echoed
> the server-advertised `ca:` verbatim into the round-1 certreq's
> `kXRS_issuer_hash` bucket. That bucket must instead name the CA that issued **our
> own** proxy EEC, because a stock `XrdSecgsi` server uses it as the anchor for
> prepending the issuing CA before verifying the *client's* round-2 `kXGC_cert`
> chain. When the server's host-cert CA ≠ our proxy's CA (every UK e-Science site),
> the wrong anchor makes the stock server reject the chain as *"chain is
> inconsistent"*. CERN worked only by luck — its EOS host cert shares the CERN Grid
> CA with our proxy, so the echoed `ca:` happened to equal the correct hash. **Fix:**
> new helper `gsi_client_issuer_hash()` reads the terminal (EEC) cert from our proxy
> PEM and computes `X509_NAME_hash{,_ex}` + `X509_NAME_hash_old` of *its issuer*,
> emitting the stock two-hash `<new>.0|<old>.0` form; `gsi_first` sends that instead
> of `ca`, falling back to the echoed `ca` only when no proxy is readable. Verified
> **live**: Glasgow + Lancaster now authenticate, CERN eospublic/eoslhcb unchanged
> (no regression). Regression-guarded by `TestForeignCaHostCert` in
> `tests/test_gsi_handshake.py`, which reproduces the exact `chain is inconsistent:
> kXGC_cert` failure against a **stock** XRootD server whose host cert is signed by a
> CA distinct from the proxy's (our own lenient server never consumes the hint, so it
> cannot reproduce it); reverting the one-line fix flips
> `test_native_auth_foreign_ca_host` red while the stock-client oracle stays green.
> Tracked in memory `phase93_glasgow_lancaster_gsi_interop.md`.
>
> **Extension (2026-08-03) — VOMS attribute-certificate FQAN decoder fix.** The
> credential dump (`xrddiag doctor`/`remote-doctor`, shared `credinfo.c`) narrates
> a GSI proxy's VOMS FQANs. The previous `voms_scan()` blind-ASCII-scanned the
> whole AC extension for `/…`-runs, which mislabelled the AC's `[0] policyAuthority`
> server URI (`lhcb://voms-lhcb-auth.cern.ch:4430`) and the AC's **embedded signer
> certificate's** CRL / AIA / OCSP distribution-point URIs (`http://cafiles…`,
> `ldap:///CN=…`, `http://ocsp.cern.ch/ocsp`) as FQANs, and over-read each string
> into the following DER tag byte — the `…Capability=NULL0`, `…:4430B` junk. The
> parser is now a bounded DER/TLV walk: new `der_tlv()` (short + long-form length
> reader), `voms_is_fqan()` (one leading `/`, printable, no `:`/`?`/`%`, not `//`),
> `voms_dup()`, and recursive `voms_emit_values()`. It locates each **VOMS FQAN
> attribute** by its OID `1.3.6.1.4.1.8005.100.100.4` (DER value
> `2B 06 01 04 01 BE 45 64 64 04` — note: the *attribute* `.100.100.4`, distinct
> from the AC *extension* OID `.100.100.5`), descends SET → IetfAttrSyntax, and
> prints only its `OCTET STRING` (tag `0x04`) `values` at exact length — skipping
> the `[0] policyAuthority` (`0xA0`, the URI) and descending an optional `values`
> `SEQUENCE OF` wrapper. Search is bounded to the attribute's SET, so it never
> wanders into the signer cert. FQANs are DER `OCTET STRING`s, **not** `IA5String`.
> **Verified live** against `root://eospublic.cern.ch:1094//eos` with the LHCb
> proxy: output is now exactly `/lhcb/Role=user/Capability=NULL` and
> `/lhcb/Role=NULL/Capability=NULL`, with none of the URI / junk noise.
> `credinfo.c` is now 598/600 lines — at the file-size cap, so any further edit
> must split it. **Tests (all green):** `credinfo_voms_unittest.c` stub-includes
> the real `credinfo.c` and links `libbrix.a`, driving `voms_scan` over
> `voms_ac_fixture.h` — a genuine 3015-byte LHCb-proxy AC — asserting exactly two
> FQAN lines and the absence of every URI/junk substring, plus `der_tlv` /
> `voms_is_fqan` micro-cases and degenerate (NULL / zero-len / truncated-SET)
> inputs; wrapper `tests/test_credinfo_voms_unit.py` (skips if `libbrix.a` unbuilt).
>
> **Extension (2026-08-03) — TPC source-host egress guard (SSRF Layer 2), native
> + WebDAV.** Third leg of the "read-only deep-recon / egress self-test / guard"
> ask. A TPC pull is an SSRF primitive — the *destination* dials the source — so
> a new **source-host NAMING allowlist** now gates it, ahead of the pre-existing
> address-range gate (`_tpc_allow_local`/`_private`) and ahead of any socket.
> Pure verdict core `brix_tpc_source_guard_check()` in
> `src/tpc/common/egress_guard.c` (host = exact or leading-`.` domain suffix,
> case-insensitive, bare apex excluded from a `.suffix` rule) is **shared by both
> planes** so they cannot drift:
> - **native `root://`**: enforced in `tpc_prepare_check_preconditions()`
>   (`src/tpc/engine/launch_prepare.c`); refuses `kXR_NotAuthorized` +
>   `TPC source host not permitted: <host>`. Directives
>   `brix_tpc_source_guard on|off` / `brix_tpc_source_allow <host> […]` on the
>   stream server (`src/protocols/root/stream/`), the latter via a **custom
>   multi-arg setter** `brix_tpc_conf_source_allow` — the stock
>   `ngx_conf_set_str_array_slot` keeps only the first token, silently dropping
>   the rest of an allowlist (the same footgun that bit `brix_cvmfs_upstream_allow`).
> - **WebDAV `COPY`**: enforced in `webdav_tpc_source_guard()`
>   (`src/protocols/webdav/tpc.c`), *after* the Source-URL https validation but
>   *before* credential delegation / curl; refuses `403`. Directives
>   `brix_webdav_tpc_source_guard` / `brix_webdav_tpc_source_allow` (loc-conf;
>   fields added to `webdav_loc_conf.h`, create/merge in `tpc_config.c`, custom
>   setter `webdav_conf_tpc_source_allow` in `module_directives.c`).
> Both refusals emit a `signal=tpc_egress` guard-audit line (new fail2ban jail
> `[xrootd-guard-tpc_egress]`, filter `xrootd-guard-tpc_egress.conf`, maxretry 3)
> and bump the label-less `brix_stream_tpc_egress_refused_total` metric
> (INVARIANT 8). New guard reason `GUARD_R_TPCEGRESS` → `"tpc_egress"`.
> **Build gotchas hit:** `.inc` command-table files are not tracked build deps
> (must `touch` the `.c` that `#include`s them); adding fields to
> `webdav_loc_conf.h` needs *all* webdav `*.o` deleted or the stale objects skew
> field offsets (surfaced as a spurious `brix_webdav_pwd_file path "storage.read"`
> — `storage.read` being the default `tpc_cred.token_scope` bleeding through).
> **Tests (all green):** offline `src/tpc/common/egress_guard_unittest.c`
> (`tests/test_tpc_egress_guard_unit.py`) + guard-core `guard_test.c`
> (`test_cmd_guard_core.py`, asserts the new reason string); native online
> `tests/test_tpc_source_egress_guard.py` (6 — refuse RFC-1918/sibling-TLD/bare-
> apex, allow IP/suffix fall-through, guard-off control on `tpc-ssrf-default`);
> WebDAV online `tests/test_webdav_tpc_source_egress_guard.py` (5 — same matrix
> over cleartext `COPY`, asserting on the `signal=tpc_egress` audit line because
> a fell-through host can still 403 later at the DNS/range stage); fail2ban
> `tests/test_fail2ban_regex.py` (`tpc_egress` case; filter is `proto=\S+` so the
> one root-plane sample also proves webdav-plane capture). New fleet role
> `webdav-tpc-source-guard:11219` (`nginx_webdav_tpc_source_guard.conf`,
> `WEBDAV_TPC_SRC_GUARD_PORT`). Guards clean: config/client-build coverage, VFS
> seam, `bash -n config`, lizard CCN ≤ 15 / files < 600. SSRF two-layer model
> written up in `docs/04-protocols/http-tpc-reference.md` §4 and
> `docs/07-security/hostile-network-lessons.md`.
>
> **Tests (all green):** `client/apps/diag/diag_doctor_audit_unittest.c` +
> `tests/test_doctor_audit_unit.py` (pure predicates + record-emitting rules,
> stub-include, fast tier), and `tests/test_config_audit.py` (10 e2e cases:
> scrape block, sitename WARN, `--cap-threshold` capacity WARN, fan-out
> cross-cluster `config-role`, PII guard, read-only). Ledger port
> `lc-cfgaudit-anon:30459` added to `tests/fleet_lifecycle_ports.py`.

**Motivation (verbatim ask):** *"can the xrddiag tool(s) be expanded to check
remote settings and/or recommend fix(es) [for] problem(s) in remote XRootD
server configurations? I want the remote diag tools to be able to scrape
everything they can to determine if there is a problem/misconfiguration or bad
performance on a remote host and to advise what action to take."*

**Key finding:** ~70–80% of this already exists. The detect→advise engine
(`DX_RULES[]` + `dx_record()` + `doctor_print_diagnosis()`), the multi-protocol
probe batteries, the CMS locate/redirect probe, the `Qconfig`/`Qspace`/`/metrics`
scrape, and the throughput/latency benches are all shipped. This phase is
mostly **consolidation** (one orchestrator over scattered tools), **rule
extension** (new `DX_RULES` rows over facts already scraped), and a **new
consistency-check class** unlocked by the phase-6x cms/cns code. Exactly one
capability — authoritative introspection of the CMS registry and CNS inventory —
has **no remote read surface today** and is called out as a deferred, opt-in
server-side slice (§7).

> **House-rule note.** Every symbol, struct field, signature and `file:line`
> anchor below was verified against the working tree on 2026-08-03. Where a rule
> or check already exists (several `cms-*`/`locate` records do), the phase
> *upgrades* it rather than re-adding it — those cases are marked **(exists →
> extend)**.

---

## 1. Why this phase exists

The capability the ask describes is real but **scattered across ~6 tools**, each
scraping one slice of the remote server and none producing a single "is this
server correctly configured and performing?" verdict:

| Tool | File(s) | Scrapes remotely | Advises? |
|---|---|---|---|
| `remote-doctor` | `diag_doctor.c` · `diag_doctor_probe.c` · `diag_doctor_proto.c` | connect/TLS/auth/namespace/read/checksum/locate/load; multi-protocol root/http/davs/s3/**cms** | **yes** — rules engine |
| `xrd doctor` | `xrd_doctor.c` · `xrd_doctor_json.c` · `xrd.c` | `kXR_Qconfig` capability matrix, host-cert validity, clock skew, functional battery | partial |
| `qstats` | `xrdqstats.c` (`brix_qstats_main`) | raw `kXR_QStats` / `Qconfig` / `Qspace` | no (dumps text) |
| `topology` / `xrdmapc` | `diag_topology.c` · `xrdmapc.c` | `kXR_locate` holders, redirect convergence, `Qspace` free/total | flags ghost / no-holder |
| `status` / `watch` | `diag_watch.c` · `diag_misc.c` | Prometheus `/metrics` + SLA probe | flags shedding |
| `bench` / `metabench` | `diag_bench.c` · `diag_metabench.c` | throughput knee, TTFB, MB/s, metadata ops/sec p50/p95/p99 | reports numbers |

(All under `client/apps/diag/`.)

### 1.1 The advice spine already exists

The advisor already has a working spine — this phase widens what feeds it, it
does not build a new engine:

- **The rule table** — `DX_RULES[]` at `xrddiag.c:15`, 18 rows today, each a
  `dx_rule { const char *probe; int kxr; int sev; const char *cause; const char
  *remedy; }` (`diag_internal.h:121`).
- **The matcher** — `dx_record_status()` (`xrddiag.c:136`) scans `DX_RULES`
  top-to-bottom for the first row whose `probe` matches (or is `NULL` wildcard)
  and whose `kxr` matches (or is `DX_ANY`), else a conservative generic
  fallback. It **never echoes `st->msg`** (wire text may carry a path → PII).
- **The recorder** — `dx_record()` (`xrddiag.c:112`) appends a `dx_finding` to
  `doctor_ep.dx[DOC_MAXDX]` and escalates `doctor_ep.status`
  (`GREEN<YELLOW<RED`). `DOC_MAXDX == 20` (`diag_internal.h:60`).
- **The renderers** — `doctor_print_diagnosis()` (`diag_doctor.c:327`) for text
  (`[FAIL] probe cause` + `→ remedy`), `doctor_emit_json()`
  (`diag_doctor.c:279`) for the `{"probe","verdict","kxr","cause","remedy"}`
  array.
- **The orchestrator** — `do_remote_doctor()` (`diag_doctor.c:433`) loops over
  `a->urls[0..nurls)`, dispatches each by scheme via `doctor_dispatch()`
  (`diag_doctor.c:349`), then runs `doctor_cross()` (`diag_doctor.c:258`) for
  the cross-endpoint transfer-path diff.

**Net of this phase:** promote that spine from a per-endpoint *failure*
classifier into a whole-endpoint (and, for a manager, whole-federation)
*configuration and performance* auditor.

---

## 2. The remote scrape surface (what is knowable over the wire)

Verified against the current tree. A remote client can already pull, **with no
server-side change**:

### 2.1 Advertised configuration — `kXR_Qconfig`

Wire call: `brix_query(c, kXR_Qconfig, "<key>", reply, sizeof(reply), &st)`
(`brix_ops.h:425`). The server answers one value-line per key. Supported keys
(server side `brix_qconfig_table[]`, `src/protocols/root/query/config.c:347`):

```
chksum · readv · readv_ior_max · readv_iov_max · tpc · tpcdlg ·
cmpread · cmpwrite · xrdfs.ext · version · bind_max · pio_max · role · fattr
```

plus `sitename` and `pgread`, already probed by `xrd doctor`
(`XRD_CAP_KEYS[]`, `client/apps/diag/xrd.c:18` — currently
`{"chksum","readv","tpc","tpcdlg","xrdfs.ext","version","role","sitename","pgread"}`).
An **unknown** key echoes the key name verbatim (reference `do_Qconf` default,
`config.c` dispatch) — so *absence of support* is detectable (echo == key), and
present keys parse as `key=value` or a bare value-line (`xrd_doctor.c:427` strips
at `'='` or `'\n'`).

This is the **configuration face** — enough to spot a large class of
misconfigurations from advertised settings alone.

### 2.2 Capacity — `kXR_Qspace` / `kXR_QFSinfo`

`brix_query(c, kXR_Qspace, "<path>", …)` returns `oss.*` total/free/used
(`src/protocols/root/query/space.c`). `xrdmapc.c:78` already parses it;
`brix_statvfs()` (`brix_ops.h`) is the higher-level wrapper. The Qspace arg is
`rpCheck`'d server-side — an empty/relative path is rejected (reference parity),
so pass an absolute path.

### 2.3 Topology — `kXR_locate` + redirect

`brix_locate(c, path, out, outsz, &st)` (`brix_ops.h:429`) returns a
space-separated token list; a holder token begins with `'S'` (see the counting
loop at `diag_doctor_probe.c:285` and `diag_doctor_proto.c:~415`). Redirect
convergence is confirmed by a follow-through `brix_stat()` through the manager
(`doctor_cms`, `diag_doctor_proto.c:433`).

### 2.4 Transport facts — netfacts / TCP_INFO

`brix_netdiag_facts(c, &e->nf)` fills `brix_netfacts` (`brix_net.h:515`):

```c
typedef struct {
    double   tcp_ms, tls_ms, auth_ms, total_ms;  /* connect-phase deltas */
    int      family;        /* AF_INET / AF_INET6 / 0 */
    uint32_t flow_label;
    int      have_tcpinfo;  /* 1 ⇒ rtt/retrans valid */
    uint32_t rtt_us, rttvar_us, retrans;
} brix_netfacts;
```

Captured in `doctor_one_session_facts()` (`diag_doctor.c:91`) along with
`e->caps = c->server_flags`, `e->gototls = (server_flags & kXR_gotoTLS)`,
`e->tls_active`/`tls_ver`/`tls_cipher` via `brix_tls_info()`, and `e->auth` from
`c->diag.chosen_auth`. The no-silent-downgrade check ("gotoTLS advertised but
session is cleartext" → `DOC_RED`) already fires here.

### 2.5 Runtime health — Prometheus `/metrics`

`doctor_metrics()` (`diag_doctor_probe.c:132`) does a cleartext
`brix_http_get(host, port, "/metrics", …)` and sets `e->shedding` when any line
matching `kXR_wait|_wait_|budget|shed` has a nonzero trailing counter. The
manager-mesh counters are emitted at `src/observability/metrics/stream.c:289+`:

```
brix_cms_read_timeouts_total · brix_cms_login_timeouts_total ·
brix_cms_idle_closes_total · brix_cms_cap_rejections_total ·
brix_cms_frame_yields_total
```

### 2.6 Performance — active benches

`bench` (throughput knee: single vs. N streams, `diag_bench.c`), `metabench`
(metadata storm ops/sec + p50/p95/p99, `diag_metabench.c`), plus per-endpoint
`e->ttfb_ms`/`e->mbps`/`e->xfer_bytes` from `doctor_xfer()`
(`diag_doctor_probe.c:90`) over a target resolved by `resolve_target()`
(`diag_topology.c`).

### 2.7 Scrape-surface summary table

| Source | Wire primitive | Existing caller | Held on `doctor_ep` |
|---|---|---|---|
| Config keys | `brix_query(kXR_Qconfig)` | `xrd_probe_caps` (`xrd_doctor.c:412`) | *(not yet — §5.2 adds `cfg`)* |
| Capacity | `brix_query(kXR_Qspace)` / `brix_statvfs` | `xrdmapc.c:78` | *(not yet — §5.2)* |
| Holders | `brix_locate` | `doctor_diagnose` (`probe.c:281`) | `holders`, `ghost` |
| Transport | `brix_netdiag_facts` | `doctor_one_session_facts` | `nf`, `tls_*`, `caps`, `gototls`, `auth` |
| Load/mesh | `brix_http_get("/metrics")` | `doctor_metrics` | `metrics_http`, `shedding` |
| Throughput | `doctor_xfer` | `doctor_one_xfer_probe` | `ttfb_ms`, `mbps`, `xfer_bytes` |
| Consistency | `brix_stat` (mgr vs DS) | `doctor_cms` (redirect only) | *(not yet — §5.4)* |

---

## 3. What the cms/cns code unlocks (new consistency-check class)

The phase-6x CNS (Composite Name Space) manager keeps a `path→{size, mtime,
server}` inventory and answers `kXR_stat` for any federation file **locally**,
without redirecting (`src/net/cms/cns.h`; `cns.c:176 brix_cns_stat`). Emit
coverage is add/del/mkdir/rmdir (`src/net/cms/cns_emit.h`,
`brix_cns_emit(conf, op, resolved, size, mtime)`). CMS registry is prefix-based
routing (which server exports which subtree). Together these enable checks
previously **impossible to run remotely**:

1. **Manager-stat vs. data-server-stat divergence.** `brix_stat` a path via the
   redirector (CNS answers locally) and via the DS it locates to; compare
   `brix_statinfo.size` and `.mtime` (`brix_net.h:159`). A mismatch ⇒ stale /
   unconverged inventory (a `brix_cns_emit` was lost, or a mutation bypassed the
   CNS seam). `brix_statinfo` carries `size`/`mtime` always and
   `mode`/`owner`/`group`/`ctime`/`atime` when `have_ext` (long stat form).
2. **Locate-vs-hold agreement.** The manager claims a holder (`'S'` token from
   `brix_locate`); confirm the DS actually serves it. `doctor_ep.ghost` becomes
   cross-checkable against CNS rather than inferred **(exists → extend)**.
3. **Registry routing sanity.** CMS prefix routing says server X exports
   `/subtree`; verify X answers and no second server also claims it.
4. **Mesh health.** The `brix_cms_*` `/metrics` counters (§2.5) directly expose
   manager-link timeouts, login failures, cap rejections.

So cms/cns turns the tools from "is this **one endpoint** healthy?" into "is this
**federation** internally consistent?"

---

## 4. The hard ceiling (two structural limits, stated honestly)

1. **No remote read surface for the CMS registry or CNS inventory.**
   `brix_cns_stat()` is server-internal (it backs the stat handler); there is
   **no** `kXR_query cms`/`cns` verb and **no** `/metrics` gauge for
   `cns_entries` / `cms_registered_servers` / per-subtree exporters. A remote
   tool observes cluster/namespace state only **indirectly** (locate/stat/
   redirect behaviour), never authoritatively. Closing this is the one
   server-side slice (§7, deferred/opt-in).

2. **The server's actual config file is never remotely readable** (nginx `.conf`
   / xrootd `.cf` are not on the wire, by design). Configuration is **inferred**
   from advertised capabilities + observed symptoms; it cannot be diffed against
   the operator's source text unless the operator chooses to expose it. Every
   finding must be phrased "advertised/observed behaviour indicates X", never
   "your config line Y is wrong."

These bound the ambition: the advisor detects **symptoms and advertised
settings**, plus (with §7) authoritative membership — not raw config text.

---

## 5. Proposed architecture

**Do not build a new tool.** Add one orchestrator entry point, extend the
`doctor_ep` fact set, and feed everything through the existing rules engine.

### 5.1 CLI surface — a flag, not a new subcommand

Add `--config-audit` as a `DXO_FLAG` row in `DX_OPTS[]` (`xrddiag.c:257+`,
`offsetof(diag_args, config_audit)`), plus the field on `diag_args`
(`diag_internal.h:25`). It composes with existing flags:

```
xrddiag remote-doctor --config-audit [--all-servers] [--json] \
        [--allow-write] [--auth-suite] [--no-verify-tls] \
        [--metrics-port N] <url> [url2 ...]
```

- No flag → today's behaviour unchanged (pure back-compat; `config_audit == 0`).
- `--config-audit` → after the existing per-endpoint battery, run the new
  config/capacity/perf scrape (§5.2) and its rules (§6).
- `--all-servers` → for a **manager** endpoint, fan out to every located DS and
  diff (§5.3). Ignored for a plain DS.

Keep `remote-doctor`'s existing gates: write/stage probes stay behind
`--allow-write` + (`dx_is_loopback` OR `--i-am-authorized`)
(`diag_doctor_probe.c:297`); the auth suite stays behind `--auth-suite`. A
config audit **must be safe to run against a production endpoint you do not
own** — reads only, unless the operator explicitly opts into mutation.

### 5.2 New fact block on `doctor_ep`

Extend `doctor_ep` (`diag_internal.h:94`) with a config-scrape sub-struct
(pointer-free, PII-free — only advertised scalars, never a path):

```c
typedef struct {
    int      scraped;                 /* 1 = the Qconfig/Qspace scrape ran   */
    char     version[48];             /* kXR_Qconfig "version"               */
    char     role[24];                /* "manager"/"server"/"meta"/...       */
    char     sitename[64];            /* "" if unset                         */
    int      tpc, tpcdlg;             /* 0/1 advertised                      */
    int      have_adler32, have_crc32c; /* parsed from "chksum" list         */
    int      bind_max, pio_max;       /* parallelism caps (-1 = absent)      */
    int      readv_iov_max, readv_ior_max;
    int      pgread;                  /* per-page CRC read supported         */
    int64_t  space_total, space_free; /* kXR_Qspace bytes (-1 = not pulled)  */
} doctor_cfg;
```

and add `doctor_cfg cfg;` plus (for §5.4) `int64_t mgr_stat_size; long
mgr_stat_mtime; int mgr_stat_have;` to hold the manager-side stat for the
cross-DS comparison. `DOC_MAXDX` (20) already bounds findings; the new rules add
≤10 records, within budget.

**New scrape function** (new TU, see §5.6):

```c
/* Populate e->cfg from a live root:// connection. Best-effort: a key the
 * server does not answer leaves its field at the "absent" sentinel. PII-free. */
void doctor_scrape_config(brix_conn *c, doctor_ep *e);
```

It calls `brix_query(kXR_Qconfig, key)` for each key in a local table (superset
of `XRD_CAP_KEYS`, adding `bind_max`, `pio_max`, `readv_iov_max`,
`readv_ior_max`, `cmpread`, `cmpwrite`, `fattr`), parses each value-line with the
same `'='`/`'\n'` split as `xrd_doctor.c:427`, then one `brix_query(kXR_Qspace,
"/")` (or the resolved target's directory) for capacity. Wire it into
`doctor_one()` right after `doctor_one_session_facts()` (`diag_doctor.c:197`),
gated on `a->config_audit`.

### 5.3 N-node manager fan-out (extend `doctor_cross`, don't replace)

Today `do_remote_doctor` probes each **user-supplied** URL independently and
`doctor_cross` (`diag_doctor.c:258`) diffs *adjacent* pairs of them. For
`--all-servers` against a manager we add a **discovery** step that turns one
manager URL into N endpoints:

```
doctor_fanout(a, manager_url, eps[], &n):
  1. connect to manager; brix_locate(path or "/") → holder token list
  2. for each 'S'-token (a data-server authority), parse host:port
  3. cap at N ≤ 8 (eps[] is doctor_ep[8] in do_remote_doctor:435 — raise to
     a heap array or a documented cap; see §5.6 sizing note)
  4. doctor_one() each DS (full battery + doctor_scrape_config)
  5. return the manager as eps[0], the DSs as eps[1..n)
```

Then a new `doctor_cross_cluster(eps, n, out)` (sibling of `doctor_cross`)
computes **fleet-level** diffs over the whole set rather than adjacent pairs:

- **version skew** — any `eps[i].cfg.version != eps[0].cfg.version`.
- **role consistency** — exactly one manager; every other node reports a
  server/data role, none a second manager.
- **capacity balance** — `free%` per DS vs. the fleet mean; flag outliers.
- **cap uniformity** — `bind_max`/`pio_max` identical across DSs (a lone
  low-cap DS bottlenecks parallel reads).

The existing `cross_diff_pair` TLS-downgrade / auth-fallback / family-asymmetry
checks (`diag_doctor.c:227`) still run for the user-path case; the two are
complementary (`doctor_cross` = *transfer path*, `doctor_cross_cluster` =
*fleet uniformity*).

### 5.4 cms/cns cross-stat consistency (extends `doctor_cms`)

`doctor_cms` (`diag_doctor_proto.c:371`) already does connect → locate →
redirect-stat. Add, after its redirect stat succeeds, a **divergence** check:

```
after brix_stat(&mgr_conn, path, &si_mgr) succeeds:
  save si_mgr.size / si_mgr.mtime into e->mgr_stat_*
  for the located DS (from the same locate token list):
    connect DS directly; brix_stat(&ds_conn, path, &si_ds)
    if si_ds.size != si_mgr.size || abs(si_ds.mtime - si_mgr.mtime) > SKEW:
        dx_record("cns-stat-drift", DX_WARN, 0,
          "manager (CNS) metadata disagrees with the data server",
          "check the DS emit path / manager inventory convergence")
```

This is the concrete realisation of §3(1). The `ghost` case (§3(2)) already
records `cms-redirect` FAIL when the redirect does not resolve to a live DS
(`diag_doctor_proto.c:440`) — the extension is to *distinguish* a dead DS from a
stale registry entry using the direct-DS connect result (**exists → extend**).

### 5.5 Rendering — reuse both paths

Text and JSON both already walk `e->dx[]` (`doctor_print_diagnosis`,
`doctor_emit_json`). New findings appear automatically. Additions:

- `remote_doctor_report_ep()` (`diag_doctor.c:375`) grows a `--config-audit`
  block for `DXP_ROOT`/`DXP_CMS`: one line summarising `e->cfg` (version, role,
  sitename, tpc, caps) plus a capacity line when `space_total >= 0`.
- `doctor_emit_json()` (`diag_doctor.c:279`) grows a `"config"` object mirroring
  `doctor_cfg`, and (for fan-out) a `"cluster"` object with the skew/role/
  balance verdicts. Field values are scalars → the existing `fjson_str` escaping
  covers the two strings (`version`, `sitename`, `role`).

### 5.6 Constraints carried from the existing design

- **PII-free** (`diag_doctor.c` header invariant): never echo `st->msg`; only
  classified `cause`/`remedy` + advertised scalars. `doctor_cfg` deliberately
  holds **no path**.
- **Read-only by default**; mutation gated as §5.1.
- **Loopback semantics** preserved (`dx_is_loopback`, exact-match only,
  `xrddiag.c:170`).
- **libXrdCl-free**, pure libbrix — no new dependency.
- **Endpoint array sizing.** `do_remote_doctor` uses `doctor_ep eps[8]`
  (`diag_doctor.c:435`) and the URL cap is 8 (`diag_args.urls[8]`,
  `diag_internal.h:43`). Fan-out to a large fleet needs either a documented
  `N ≤ 8` DS cap (with a `log()`-style "truncated to 8 of M servers" note — no
  silent cap) or a heap `doctor_ep *` array in the fan-out path. Recommendation:
  heap array in `doctor_fanout`, keep the 8-slot stack array for the
  user-supplied-URL path.

---

## 6. Concrete `DX_RULES` / check catalogue

Two mechanisms:
- **Code-keyed rows** — add to `DX_RULES[]` (`xrddiag.c:15`); fire via
  `dx_record_status(e, probe, &st)` when a probe returns that kXR code.
- **Computed checks** — a predicate over `e->cfg` / `e->nf` / fleet, then a
  direct `dx_record(e, &(dx_note){...})`. These are the majority here because
  config/perf faults are *values*, not error codes.

### 6.1 From `Qconfig` (computed; zero server change)

| Probe id | Predicate | Sev | cause → remedy |
|---|---|---|---|
| `config-tpc` | `!cfg.tpc || !cfg.tpcdlg` and peer participates in TPC | WARN | third-party copy unavailable → enable `tpc` (and delegation) if this endpoint takes part in TPC |
| `config-chksum` | `!cfg.have_adler32 && !cfg.have_crc32c` | WARN | no common checksum algorithm advertised → add adler32/crc32c so clients can verify integrity |
| `config-role` | fleet: ≠1 manager, or a DS advertising `role=manager` | FAIL | server role misconfiguration → correct the role directive on the offending node |
| `config-version` | fleet: `cfg.version` differs across DSs | WARN | mixed-version cluster → align server versions to avoid parity gaps |
| `config-parallel` | `cfg.bind_max < 4` or `cfg.readv_iov_max` below client need | WARN | server-side parallelism capped → raise `bind_max`/`readv` limits if clients need more streams |
| `config-sitename` | `cfg.sitename[0] == '\0'` | WARN | sitename unset → set `sitename` for monitoring/attribution |
| `config-pgread` | `!cfg.pgread` while integrity mode expected | INFO/WARN | per-page CRC read unsupported → informational; enable pgread for end-to-end page integrity |

### 6.2 From `Qspace` / capacity (computed)

| Probe id | Predicate | Sev | cause → remedy |
|---|---|---|---|
| `capacity-low` | `space_free * 100 / space_total < THRESH` (default 5%, flag-tunable) | WARN | export nearly full → free space or add capacity before writes fail with `kXR_NoSpace` |
| `capacity-imbalance` | fleet: a DS's `free%` deviates > K·σ from the mean | WARN | unbalanced cluster → rebalance data or check a stuck/degraded DS |

### 6.3 From netfacts / `/metrics` (computed + code-keyed)

| Probe id | Predicate / trigger | Sev | cause → remedy |
|---|---|---|---|
| `perf-retrans` | `nf.have_tcpinfo && nf.retrans > 0` **(exists → promote from `doc_issue` to `dx_record`)** | WARN | TCP retransmits on the path → check the network path, MTU, NIC offloads |
| `perf-throughput` | `have_xfer && xfer_bytes ≥ 4MiB && nf.rtt_us < 5000 && mbps < 5.0` **(exists → promote, `diag_doctor.c:157`)** | WARN | low throughput at low RTT → check window sizing / stream count / server load (cwnd/BDP) |
| `perf-shedding` | `e->shedding` (set by `doctor_metrics`) **(exists → promote)** | WARN | server throttling (`kXR_wait`/budget) → reduce concurrency or scale the server |
| `mesh-timeouts` | `/metrics` `brix_cms_read_timeouts_total`/`_login_timeouts_total` nonzero & rising | WARN | sick manager mesh → check the manager link and its load |
| `read`/`write` codes | `kXR_Overloaded`/`kXR_NoMemory`/`kXR_NoSpace` **(exists in `DX_RULES`)** | as-is | already classified — no change |

> Note the `perf-*` rows already exist as `doc_issue()` yellow lines
> (`doctor_one_load_signals`, `diag_doctor.c:147`). The phase **promotes** them
> into `dx_record` findings so they carry a `remedy` and appear in the JSON
> `diagnosis[]`, not just the free-text `issues[]`. This is a small, high-value
> consolidation — same detection, now actionable + machine-readable.

### 6.4 From cms/cns (consistency — §3)

| Probe id | Trigger | Sev | cause → remedy |
|---|---|---|---|
| `cns-stat-drift` | mgr `brix_stat` size/mtime ≠ DS `brix_stat` (§5.4) | WARN | stale CNS inventory → check the DS emit path / manager convergence |
| `cms-ghost` | located holder present but DS connect/stat fails | FAIL | ghost registration → remove the stale CMS registry entry / restart the DS |
| `cms-noholder` | manager locates no server for an existing path **(exists, `diag_doctor_proto.c:416`)** | FAIL | unregistered replica → register the DS / check the CMS registry |
| `cms-redirect` | redirect resolves but file absent / dead DS **(exists, `:433`)** | WARN/FAIL | as-is → extend to split dead-DS vs. stale-entry via direct connect |

### 6.5 A `DX_RULES` row, verbatim shape

For the code-keyed additions, a new row is one array entry (matches the existing
style at `xrddiag.c:15`):

```c
/* capacity — code-keyed fallbacks (computed checks handle the value cases) */
{ "capacity", kXR_NoSpace, DX_FAIL,
  "export filesystem is full",
  "free disk space on the server export or add capacity" },
```

Computed checks do not go in `DX_RULES`; they call `dx_record` directly at the
scrape site, e.g.:

```c
if (e->cfg.space_total > 0 &&
    e->cfg.space_free * 100 / e->cfg.space_total < a->cap_threshold_pct) {
    dx_record(e, &(dx_note){ "capacity", DX_WARN, 0,
        "export nearly full",
        "free space or add capacity before writes fail with kXR_NoSpace" });
}
```

---

## 7. Deferred / opt-in: authoritative CMS/CNS read surface (server-side)

The §4(1) ceiling — no remote way to read cluster membership or inventory size —
is the single item requiring a **server-side** change, deliberately **out of
scope for the client slices above** and gated behind operator opt-in. Two
candidate shapes (pick one when the phase reaches it):

- **A `/metrics` gauge set** (lowest-risk, reuses the existing scrape path in
  `doctor_metrics`): emit `brix_cns_entries` and `brix_cms_registered_servers`
  (and low-cardinality per-role counts) alongside the existing `brix_cms_*`
  counters at `src/observability/metrics/stream.c:289`. **Must** honour metrics
  INVARIANT 8 (low-cardinality labels) — counts only, never per-path or
  per-hostname labels.
- **A read-only `kXR_query` diagnostics subtype** returning a *bounded summary*
  (counts, not the namespace). Must run auth (READ) and never leak the namespace
  to an anonymous client. Would slot beside the existing query dispatch
  (`src/protocols/root/query/dispatch.c:51`).

Either turns "infer from behaviour" into "scrape authoritatively." Neither is
required for §5–§6 to deliver value; both are follow-on and separately reviewed.

---

## 8. Work breakdown (slices)

Ordered by value-per-line; each independently landable and separately tested.

| Slice | Scope | New/edited files | Depends on | Size | Status |
|---|---|---|---|---|---|
| **S1** | `--config-audit` flag (`diag_args` field + `DX_OPTS` row + usage line); `doctor_cfg` struct; wire `doctor_scrape_config` into `doctor_one`; report block | `diag_internal.h`, `xrddiag.c`, new `diag_doctor_audit.c` | — | M | ✅ LANDED |
| **S2** | §6.1 Qconfig computed rules + parse `chksum` list into `have_adler32/crc32c` | `diag_doctor_audit.c` | S1 | S | ✅ LANDED |
| **S3** | §6.2 capacity (Qspace scrape + rules) and §6.3 **promotion** of the existing `doc_issue` perf/shedding signals to `dx_record` | `diag_doctor_audit.c`, `diag_doctor.c` | S1 | S | ✅ LANDED |
| **S4** | `doctor_fanout` (manager → N DS via `brix_locate`) + `doctor_cross_cluster` (version/role/balance); `--all-servers` flag; heap `doctor_ep` array | `diag_doctor_audit.c`, `do_remote_doctor` | S1 | M | ✅ LANDED |
| **S5** | §5.4 `cns-stat-drift` + ghost/stale split in `doctor_cms` | `diag_doctor_proto.c` | S4 | M | ✅ LANDED |
| **S5m** | **mesh diagram** — `--map`/`--map-format ascii\|dot\|mermaid` renders the fan-out topology as an ASCII tree / Graphviz digraph / Mermaid graph, coloured by per-node health | new `diag_doctor_graph.c`, `diag_internal.h`, `xrddiag.c`, `diag_doctor.c`, `client/Makefile` | S4 | S | ✅ LANDED |
| **S5o** | **EOS dialect for `--map`** — detect an EOS MGM via the `/proc/user/?mgm.cmd=version` banner and enumerate the FST farm via `/proc/admin/?mgm.cmd=fs&mgm.subcmd=ls&mgm.outformat=m` (admin-gated → graceful degrade); FST nodes rendered in ASCII/DOT/Mermaid/text/JSON | new `diag_doctor_eos.c`, `diag_internal.h`, `diag_doctor_audit.c`, `diag_doctor_graph.c`, `diag_doctor.c`, `client/Makefile` | S5m + S5n | M | ✅ LANDED |
| **S5p** | **unprivileged FST discovery** — when `fs ls` (S5o) is NotAuthorized, fall back to the user-plane `fileinfo` command: a bounded DFS samples files under the map target and unions the distinct FSTs their replica tables name (honestly tagged `sampled` / "via fileinfo replica sampling", partial coverage) | new `diag_doctor_eos_fileinfo.c`, `diag_internal.h`, `diag_doctor_eos.c`, `diag_doctor_graph.c`, `client/Makefile` | S5o | M | ✅ LANDED |
| **S6** | *(deferred, opt-in)* server-side read surface (§7) | `src/observability/metrics/stream.c` **or** `src/protocols/root/query/` | — | M–L, server change, separate review | ⏸ DEFERRED |

S1–S3 are pure client-side, zero server change, and deliver the "scrape a remote
host → advise" ask on their own. S4–S5 add the federation view. S6 is the only
server-touching, opt-in slice.

### 8.1 Build governance

`diag_doctor.c` is 465 lines, `diag_doctor_probe.c` 313, `diag_doctor_proto.c`
446 — all under the **600-line file-size guard**, but with limited headroom. The
orchestrator + fan-out + cluster diff land in a **new TU `diag_doctor_audit.c`**,
not grown into `diag_doctor.c`. Register it:

1. **Corrected as-built:** add `apps/diag/diag_doctor_audit.o` to `xrddiag_OBJS`
   in **`client/Makefile`** — the client build's single source of truth (every
   `.c` listed, no wildcards). The repo-root `./config` is **server-module only**
   and references no client `.c`; the earlier instruction to add it there was
   wrong. (While here, the committed `xrddiag_OBJS` was missing the existing
   `diag_check_probe`/`diag_doctor_probe`/`diag_doctor_proto`/`diag_authsuite`
   split siblings and could not link — restored.)
2. Add the new function prototypes to `diag_internal.h` (the split contract).
3. `make -C client xrddiag` — incremental; no `./configure` re-run (client build
   is independent of the nginx module source list).
4. The `*_unittest.c` (`diag_doctor_audit_unittest.c`) is **not** listed in the
   Makefile — it is standalone-built by its pytest wrapper, per repo convention
   (cf. `cns_inventory_unittest.c`).

---

## 9. Test plan (per repo 3-tests-per-change discipline)

Every rule/probe added lands with **success + error + security-negative**
coverage. Use the `fleet_specs` registry launcher (`RegistryLauncher`, pure
Python) for server fixtures; run `PYTHONPATH=tests pytest tests/<file>.py -v`.

### 9.1 Fixture matrix

| Rule | Success fixture | Detection fixture | Security-negative assertion |
|---|---|---|---|
| `config-tpc` | fleet DS with `tpc` enabled → no `config-tpc` finding | fleet DS with TPC disabled → `config-tpc` WARN + exact remedy substring | audit performs **no** write/TPC op (assert DS logs show read-only) |
| `config-chksum` | server advertising adler32 → clean | server with empty `chksum` → `config-chksum` WARN | — |
| `capacity-low` | export with free space → clean | mock/`Qspace`-stubbed low-free server → `capacity-low` WARN | audit issues no write to "confirm" fullness |
| `config-version`/`config-role`/`balance` | uniform 2-DS fleet → clean cluster verdict | version-skewed / dual-manager fleet → `config-version`/`config-role` finding | fan-out connects read-only to each DS; no mutation |
| `cns-stat-drift` | converged mgr+DS → clean | DS mutated with CNS emit suppressed → `cns-stat-drift` WARN | mgr+DS stat only; no write |
| `cms-ghost` | live DS → `cms-redirect` OK | registry entry for a downed DS → `cms-ghost` FAIL | — |
| PII guard (all) | — | any finding whose server `st->msg` contains a marker path | assert the rendered text/JSON **never** contains the marker (only `cause`/`remedy`) |

### 9.2 Topology notes

- CNS/CMS consistency tests need a **manager + ≥1 DS** topology. Per `cns.h`,
  the per-worker-vs-SHM fallback means a single-worker manager gives a
  deterministic inventory — pin `worker_processes 1` (or register a `brix_cns
  zone` for the multi-worker path) for the drift fixture.
- Fan-out (`--all-servers`) needs the manager's `brix_locate` to return real DS
  authorities — reuse the phase-61 CMS parity fleet fixtures (fixed-port,
  serial) noted in the CMS test memory.

### 9.3 Unit-testable pure pieces (no server)

C-unit the value predicates the way `src/net/cms/cns_inventory_unittest.c` unit
tests the inventory. **As-built:** `client/apps/diag/diag_doctor_audit_unittest.c`
(stub-include harness — `#include "diag_doctor_audit.c"` with trivial stubs for
the ~dozen wire/render externs, `dx_record` stubbed to a recorder so emitted
findings are asserted by probe id), run by `tests/test_doctor_audit_unit.py`:

- `chksum`-list parse → `have_adler32`/`have_crc32c` (synthetic value-lines, incl. NULL).
- capacity free-% predicate incl. clamp/unknown; `--cap-threshold` selection.
- version-skew / manager-role-count reducers over a synthetic fleet array.
- `doctor_audit_rules` fires config-chksum/tpc/sitename/parallel/capacity-low on
  bad config and stays silent on healthy config.
- `doctor_cross_cluster` records config-version / config-role / `cap-imbalance`.

**As-built addition (2026-08-03) — the `--json` assembler.** Every per-endpoint
sub-object above (`config`, `latency`, `recon`, `eos`) is emitted by its own TU
and writes its **own leading comma**, so the document's validity depends entirely
on where `doctor_emit_json` calls it. `doctor_eos_emit_json` was being called
*after* the `}` that closes the endpoint object, which put `"eos"` between two
elements of the `endpoints` array — unparseable JSON for any EOS-bearing
endpoint, and invisible to every substring assertion in
`tests/test_config_audit.py` (which only ever exercised the non-EOS path,
asserting `"eos" not in ep`). Fixed, and pinned by
`client/apps/diag/diag_doctor_json_unittest.c` + `tests/test_doctor_json_unit.py`
(stub-include; the four sub-emitters are stubbed to their documented
`,"name":{…}`-or-nothing contract):

- The C harness asserts each sub-object's **nesting depth** equals that of the
  endpoint's own keys. Depth, not substring order, is the assertion that
  discriminates the two placements — both produce text containing `},{"protocol"`.
- The Python driver parses the harness's printed document with a real JSON parser
  and asserts `eos` is a member of its endpoint.
- A **mutation case** recompiles the TU with the call moved back after the brace
  (the mutated copy shadows the real one because `#include "diag_doctor_json.c"`
  resolves from the includer's directory) and requires both halves to fail —
  without it, a green parse would not prove the placement is what makes it green.
- Security-negative: an `issues[]` string carrying `"` and `\` (server-supplied
  error text lands there) must come back through the parser byte-identical.

These need no fleet and run in the fast tier. The e2e side lives in
`tests/test_config_audit.py` (self-hosted anon export, lifecycle harness).

---

## 10. Invariants & guards to honour

- **File-size ≤ 600 lines** — new orchestrator/fan-out in `diag_doctor_audit.c`,
  not grown into `diag_doctor.c` (§8.1). The phase's type growth eventually took
  `diag_internal.h` to 617 lines; the doctor endpoint model (`doctor_ep` and every
  sub-record it aggregates — `doctor_cfg`/`doctor_lat`/`doctor_recon`/
  `doctor_cmsloc`/`doctor_eos`/`doctor_eos_rep`) now lives in
  `client/apps/diag/diag_doctor_types.h`, included from `diag_internal.h` after
  `dx_finding`/`DOC_*` so no translation unit had to change.
- **Metrics INVARIANT 8** (low-cardinality labels) binds the §7 gauges — counts,
  never per-path/per-host labels.
- **PII-free rendering** — `doctor_cfg` holds no path; renderers echo only
  `cause`/`remedy` + advertised scalars; `st->msg` is never printed (`dx_record_status`).
- **No `goto`; early-return; use existing HELPERS** — reuse `dx_record`,
  `dx_record_status`, `brix_query`, `brix_locate`, `brix_stat`, `brix_statvfs`,
  `doctor_metrics`, `doctor_cross`; do not reimplement framing/auth/scrape.
- **VFS INVARIANT 12** is not in play (client-side, no storage syscalls).
- **Gated mutation** — write/stage/auth-forge stay behind
  `--allow-write`/`--auth-suite` + loopback/`--i-am-authorized` (unchanged from
  `doctor_diagnose`, `diag_doctor_probe.c:297`).

---

## 11. Out of scope

- Editing the remote server's config (the tool *advises*, never mutates a remote
  endpoint's configuration).
- Reading the remote config file text (§4(2) — structurally impossible on the
  wire).
- Any write/stage/auth-forge probe by default (gated behind existing flags).
- Root-only / privileged local probes (the tool stays unprivileged-runnable,
  consistent with the rest of the client family).
- The S6 server-side read surface is *planned but deferred* — not part of the
  client deliverable and separately reviewed.

---

## 12. Summary

The ask is ~70–80% already implemented. The detect→advise rules engine
(`DX_RULES` + `dx_record` + `dx_record_status` + `doctor_print_diagnosis`/
`doctor_emit_json`), the multi-protocol batteries, the cms locate/redirect probe
(`doctor_cms`), and the `Qconfig`/`Qspace`/`/metrics`/bench scrape all ship
today. This phase (a) adds a `--config-audit` orchestrator flag and a
`doctor_cfg` fact block, (b) adds config/capacity/performance rules over facts
already scraped — **promoting** several existing `doc_issue` signals into
actionable `dx_record` findings — and (c) uses the cms/cns code for a new
federation-consistency class (fleet-uniformity fan-out + `cns-stat-drift`). The
only capability unreachable without a server-side, opt-in change is authoritative
CMS-registry / CNS-inventory introspection (§7); everything else is client-side
and scrapeable now.

---

**Deliverable file:** `docs/refactor/phase-93-remote-config-performance-advisor.md`
**Predecessors:** `docs/refactor/phase-92-open-work-audit.md` (register), the
`remote-doctor` machinery in `docs/refactor/phase-38-file-size-unix-modularity.md`
(the split that produced `diag_doctor*.c`).
