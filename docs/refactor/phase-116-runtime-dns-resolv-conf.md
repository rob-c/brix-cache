# Phase 116 — Runtime DNS: resolv.conf-driven resolution and start-safe hostnames

**Status:** IMPLEMENTED (spec 2026-09-05; W1–W6 landed 2026-09-06). Every
work item below is ticked with the amendment that item needed; the phase is
pinned by 108 tests in twelve `tests/test_phase116_*.py` suites and by
`tools/ci/check_dns_seam.py`, which admits no waiver and carries no backlog.
**Source:** operator requirement of 2026-09-05 — "use the brix module to cover
the DNS gap between nginx open-source and nginx Plus: every name nginx sees is
resolved dynamically at runtime from the `resolv.conf` exposed to the server,
and no hostname may stop nginx starting because DNS is unavailable at that
moment"
**Depends on:** Phase 22 (health checks), Phase 23 (dynamic upstreams, CLOSED),
Phase 106 (nginx-native integration surface, W7 dynamic-load conformance),
Phase 109 (thread-offload conventions), Phase 110 (monitoring vocabulary)
**Touches:** new `src/net/dns/`; `src/net/cms/config.c`;
`src/net/mirror/{http,stream}_mirror_config.c`; `src/net/upstream/{directives,start}.c`;
`src/core/config/helpers.c`; `src/protocols/webdav/proxy_pool.c`;
`src/core/compat/net_target*.{c,h}`; every runtime `getaddrinfo()` site listed
in Appendix A; `tools/ci/check_dns_seam.py` (new)
**Trigger:** W1 starts; W3 is the item that satisfies the operator requirement
and is the minimum close

## Outcome — what landed, and where it diverged from this spec

The code is in `src/net/dns/` (see its `README.md` for the file map), with one
client-side seam in `client/lib/net/resolve.c`. Sixteen amendments to the plan,
each of them a narrowing or a hardening:

1. **`path=` must be absolute — but symlinks are deliberately followed.** The
   absolute-path half was planned as a security negative and kept exactly: a
   relative path (or an empty one) is a configuration error, the one
   DNS-adjacent fatal left, and it is the operator's own line, not a DNS
   result. The `O_NOFOLLOW` half of the plan was **dropped, and the spec text
   below is corrected accordingly**: on every systemd host `/etc/resolv.conf`
   *is* a symlink (to `../run/systemd/resolve/stub-resolv.conf` or
   `.../resolv.conf`), so refusing to follow one would silently degrade the
   default deployment to "cannot read → nameserver 127.0.0.1" and drop the
   search list with it — the phase's own failure mode, self-inflicted.
   `resolv_conf.c:452` therefore uses a plain `fopen()`, and the choice is
   pinned by test rather than by comment: a link is read through to its
   target's *contents*, while a dangling link, a link to a directory and a
   self-referential loop each degrade to the documented warning and still
   start (the directory case needed the loader fix in amendment 11 — `fopen`
   succeeds on a directory) (`test_phase116_resolv_conf_parser.py`, four cases). Reading a file
   the operator named is not a privilege boundary: nginx has already read the
   config that names it.
2. **`nameserver` accepts address literals only**, plus the BriX extension
   `ip:port` / `[v6]:port`. A `%scope` suffix is parsed and dropped:
   `ngx_resolver` cannot bind a scope id, so honouring it would be a lie.
3. **`options rotate` is parsed and recorded, but is a no-op.** The spec's
   W2.2 plan (one `ngx_resolver_t` per rotation order, picked round-robin) buys
   nothing here: brix rotates across the *answer* set per connect (W5.3), and
   `ngx_resolver` already fails over between nameservers. Keeping the flag
   parsed means an operator's file is never rejected for it.
4. **`options` beyond `ndots`/`timeout`/`attempts`/`rotate` are ignored**
   (`single-request`, `use-vc`, `trust-ad`, `no-reload`, `sortlist`, anything
   unknown) rather than mapped, with the glibc clamps applied to the three that
   are honoured: `ndots ≤ 15`, `timeout ≤ 30`, `attempts ≤ 5`, at most three
   nameservers and six search elements.
5. **The CI guard is stricter than planned.** W4.4 specified a
   `/* dns-seam-allow: … */` marker and a shrinking `dns_seam_backlog.txt`.
   Neither exists: every call site in `src/`, `client/` and `shared/` was
   converted in this phase, so the guard bans the symbols outright — there is
   nothing to grandfather and no marker to abuse. It also covers what the spec
   did not: `getnameinfo`, `res_*query`/`res_*search`, `<netdb.h>`,
   `CURLOPT_FOLLOWLOCATION`, and the companion rules (`ngx_parse_url` ⇒
   `no_resolve = 1`; `CURLOPT_URL` ⇒ an address pin).
6. **Reverse (PTR) resolution was in no work item and had to be done** —
   `reverse.c`, `reverse_cache.c` and the accept/login prefetch (called W7 in
   the source headers). XrdAcc `h` rules, protbind hostname templates, `host`
   auth and the TPC origin id were resolving the peer's FQDN inline on the
   event loop; I-DNS-1 covers them too, so they now read a bounded,
   address-keyed cache and never wait.
7. **A thread-pool → event-loop bridge was needed** (`resolve_bridge.c`).
   W4.3 assumed thread-pool sites could simply keep libc. They can, but then
   they see a different world from the async path (a different cache, and none
   of the `brix_resolver` policy). The bridge lets a blocking caller use the
   worker's own resolver and fall back to libc only when there is no loop to
   ask — which is also what keeps `/etc/hosts` working for those sites.
8. **The client was pulled in scope.** The original non-goal ("client-side
   resolution is out of scope") did not survive the operator's instruction to
   fix *all* of the code before closing: `client/lib/net/resolve.c` is now the
   single client seam, with a bounded positive-only cache, and the guard scans
   `client/` and `shared/` exactly as it scans `src/`.
9. **W5.4 (SRV) was not taken** — it was explicitly a stretch item, and
   `service=` has no consumer in the tree. **W6 closed as decision B**
   (reload from the deployment's own file watcher): no live lab showed an
   outage window that a worker-side re-stat would close, and the file is
   re-read on every parse, so `nginx -s reload` is the whole story.

10. **The reverse path needed a config-time backend, and the stream gate was
    reading the wrong slot.** Two defects found after W7 landed, both fixed
    here and pinned by `test_phase116_reverse_no_resolver.py`:

    * A configuration that declares neither a `brix_resolver` nor a
      `thread_pool` had *no* reverse backend at all —
      `ngx_thread_pool_get(cycle, "default")` declines when no pool was named
      anywhere, `brix_dns_reverse()` failed with "no resolver and no thread
      pool available", the failure was negative-cached for `negative_ttl`, and
      every consumer degraded to the numeric peer. `brix_acc_resolve_hosts on`
      therefore stopped granting `h` rules on such a configuration — a real
      regression against the pre-phase behaviour, where the same lookup was a
      blocking `getnameinfo()` that answered (and stalled the worker, which is
      why it had to go). `brix_dns_backend_prepare()` in `directive.c` now
      registers the default pool at merge time — the same
      `ngx_thread_pool_add(cf, NULL)` pattern `brix_conf_set_resolver()` and
      `brix_dns_target_register()` already use — from
      `brix_http_common_merge_loc_conf()` and `brix_merge_srv_security()`,
      i.e. only for a server that actually consults the peer name
      (`acc.resolve_hosts`, a protbind host template, `brix_auth host`). A
      sync `getnameinfo()` fallback was rejected: that is the event-loop stall
      invariant 13 exists to remove. A resolver-only PTR path was rejected
      too: it cannot see `/etc/hosts`, which is exactly what `h localhost`
      needs.
    * `conn_peer_name_needed()` read `sconf->common.protbind`, but the stream
      `brix_protbind` directive writes `sconf->protbind` (every other stream
      consumer — `login.c`, `protocol.c`, `gsi/auth.c` — uses the srv slot),
      so a stream protbind host template never armed the accept-time
      prefetch. Fixed to the srv slot.
    * The same hole exists on the **forward** path, and the audit that found
      the reverse one was widened to close it rather than leave a backlog.
      `brix_dns_resolve()` (`resolve.c:462`) refuses with the identical "no
      resolver and no thread pool available" when a name reaches it from a
      configuration that registered no DNS target. Five callers resolve a name
      outside `brix_dns_target_register()`; three were exposed. `brix_pmark`'s
      firefly destination (`observability/pmark/mapping.c:211`, set by
      `brix_pmark_set_firefly_dest`), `brix_proxy_upstream`
      (`net/proxy/connect_upstream.c:141`, set by
      `brix_conf_set_proxy_upstream`) and the WebDAV dynamic proxy pool
      (`protocols/webdav/proxy_pool.c:267`) each now call
      `brix_dns_backend_prepare(cf)` from their own config-time entry. The
      other two are safe for reasons worth recording: the CMS health-check
      target goes through `brix_dns_target_register()` (`net/cms/config.c:57`),
      and TPC is already pool-dependent. Both `*_sync()` flavours fall back to
      libc unconditionally, so neither can hit this failure.
    * A finding, not a fix, from that sweep: `brix_proxy_pool_configure()` has
      **no caller** in `src/` — the `brix_webdav_proxy_dynamic` directive named
      in `proxy_pool.h:4` survives only in that comment, so the shared zone is
      never declared and `brix_proxy_pool_add()` (the admin REST route
      `dashboard/api_admin_proxy.c:157`) always answers `proxy_pool_disabled`.
      The whole dynamic pool, resolution included, is inert. The prepare call
      went inside `brix_proxy_pool_configure()` itself rather than at a call
      site, so whoever wires the directive back gets the DNS backend with it;
      re-arming the pool is out of phase-116's scope and is recorded here so
      the next reader does not mistake the inert path for a DNS defect.

11. **The closing coverage sweep found three gaps of its own**, each now
    closed and pinned rather than noted. The operator's instruction was that
    every feature, discovery, bug and compat layer this phase produced ends up
    explicitly tested, so the sweep was run as a census, not as a reading.

    * **The bridge shipped unobservable and untested.**
      `brix_dns_bridge_stats()` (amendment 7) had exactly one property worth
      knowing at runtime — how often a blocking caller crossed into the
      worker's resolver, and how often that crossing timed out — and no
      caller anywhere in `src/`: a dead export. It is now emitted by
      `dns_metrics_emit_bridge()` (`net/dns/metrics.c:126`) as
      `brix_dns_bridge_requests_total` / `brix_dns_bridge_timeouts_total`,
      both process-global counters with no labels (I-DNS-4). The crossing
      itself had no test, because no *live* configuration reached it without
      client traffic: the reachable blocking callers are all request-driven.
      `tests/configs/nginx_lc_p116_dns_bridge.conf` drives it from the one
      caller that is not — the cvmfs origin RTT probe
      (`brix_cvmfs_origin_select rtt`), whose timer fires on a thread within
      500 ms of `init_process` — against a `.lab.test` origin name that libc
      cannot resolve, which makes "the probe dialled the stub's sink" proof
      that the worker's policy answered and not a libc detour. The negative
      (NXDOMAIN: crossing still counted, no dial, server keeps serving) and
      the security negative (an off-path forged answer with the wrong query
      id never reaches the probe) are in the same suite.
    * **Three resolver classes the guard could not see.** A caller can leave
      the seam without naming any banned symbol, by asking libcurl or a second
      resolver library to do the lookup. `check_dns_seam.py` now bans
      `CURLOPT_CONNECT_TO`, `CURLOPT_DOH_URL`, `CURLOPT_DNS_SERVERS` and
      `CURLOPT_DNS_INTERFACE` ("libcurl alternate resolver") and
      `ares_getaddrinfo(`/`ares_gethostbyname(` ("c-ares resolver"), and
      requires the same address pin for `CURLOPT_PROXY` that `CURLOPT_URL`
      already required — libcurl resolves the proxy host itself, so an
      unpinned proxy is the whole seam bypassed one level down. The one
      standing allowance, `BIO_new_connect()`'s `host:port` string in
      `src/auth/crypto/ocsp_transport.c`, is a single-file `frozenset` whose
      value is already numeric (`ocsp_request.c` resolves through
      `brix_dns_resolve_sync()` and formats with `ngx_sock_ntop()`); the test
      asserts both the frozenset's contents and that a second file using
      `BIO_new_connect` is flagged.
    * **An unreadable path defaulted silently.** Writing the symlink cases
      for amendment 1 surfaced a fourth: `fopen()` *succeeds* on a directory,
      so `brix_resolver auto path=/some/dir` read zero bytes, kept glibc's
      127.0.0.1 default and warned about nothing — the operator's own path
      was unusable and the log said so nowhere. `brix_resolv_conf_load()` now
      treats "opened, but the first read failed" (`n == 0 && ferror(fp)`) as
      an unreadable file and returns -1, which routes it to the existing
      "cannot read … using the libc defaults" warning; a genuinely empty
      regular file still reads 0 bytes with no error and still defaults
      silently, which is what glibc does. Both halves are asserted in the C
      unit (`resolv_conf_unittest.c`, `test_unreadable_content`) and the
      directory case is one of the three live symlink negatives.

    * **A shipped directive with no test.** The census of the http and stream
      command tables against the phase-116 test corpus — every
      `brix_dns_*`/`brix_resolver` directive must be named by a
      `tests/test_phase116_*.py` or a `tests/configs/nginx_lc_p116_*.conf` —
      immediately caught `brix_dns_status_zone`, which labels a target's row
      in `brix_dns_targets` and had no parse test, no live test and no
      mention. It now has all three (accepted in both planes, malformed
      refused, and the label appearing in the target row, defaulting to the
      empty string, and never reaching a metric label). The census is itself
      a test (`test_phase116_discoveries_and_compat.py`), so the next
      directive added without coverage reddens the suite; the same file
      censuses the metric families, pins the resolv.conf load site to the
      config-time directive (decision B), pins both arms of the
      `NGX_THREADS`/no-threads bridge, and pins the caller set of
      `brix_dns_backend_prepare()` and the inert WebDAV proxy pool from
      amendment 10.

12. **The failure-driven address advance was wired to the wrong site, and
    then thrown away by the refresh it scheduled.** Writing
    the W5.3 negative — a two-address record whose *first* address has nothing
    listening — showed the CMS client never reaching the live member at all
    inside 45 s, on a record that had been resolved for the whole run. There
    were two independent causes.

    The first is where the advance was signalled. `brix_dns_target_note_failure()`
    was called from exactly one place in the CMS client: the branch where
    `ngx_event_connect_peer()` itself fails (`src/net/cms/connect.c:464`). That
    is the one surface a refused dial on loopback never takes — the connect
    goes `EINPROGRESS` and the `ECONNREFUSED` arrives on the read/write side,
    which is precisely what `ngx_brix_cms_disconnect()`'s own comment already
    said about the failure *counter* ("a refused dial can surface on any of
    three of them … funnels through this teardown exactly once"). The DNS
    signal now leaves from that same funnel, under the same "never became a
    link" condition that increments `brix_cms_connect_failures_total`, and
    skips a `kYR_try`-retargeted dial because that address did not come from
    this target's answer set. The connect-time call site stays: a synchronous
    failure never builds a connection, so it never reaches the teardown.

    The second is in the answer-apply path.
    `dns_target_on_success()` (`src/net/dns/targets.c`) restarted the rotation
    on every answer (`t->rr = 0; dns_target_publish(t, 0)`), and a refused dial
    schedules an *early* refresh (`brix_dns_target_note_failure`), so the
    advance the failure had just made was undone by the refresh it had just
    scheduled: even once the advance was signalled from the right place, the
    node was dragged back onto the dead member on the next refresh, over and
    over, for as long as that member stayed in the record. A consumer that dials the
    published address — the CMS client — is the one that feels it; the ones
    that call `brix_dns_target_next()` per connect (`brix_upstream`, the stream
    mirror) rotate past it on their own. The fix keeps the published address
    across a re-resolution when the new answer still contains it
    (`dns_target_carry_index()`), and starts `rr` *past* it so the next
    rotation hands out a different member rather than repeating the one in use;
    a record that genuinely changed still starts at index 0. Both directions
    are pinned live: `test_a_dead_first_address_is_left_for_the_second`
    (`test_phase116_reresolve.py`) bounds `brix_cms_connect_failures_total` at
    two — before the fix the live member was never dialled at all and the
    counter kept climbing — and
    `test_successive_dials_rotate_through_the_answer_set`
    (`test_phase116_upstream_async_resolve.py`) pins the per-connect rotation
    that the same cursor change could have broken. Both halves are pinned
    structurally as well, in `test_phase116_discoveries_and_compat.py`, so a
    revert reddens in a pure run with no lane and no binary.

13. **The pin's own build sites — a link regression the tree had no guard for.**
    Giving the libcurl address pin its own translation unit
    (`client/apps/fs/brixcvmfs_curl_pin.c`, the file that keeps I-DNS-1 true for
    the cvmfs client) broke every *hand-written* rebuild of the brixcvmfs
    driver. `client/Makefile` and one `tests/cmdscripts` list learned the new
    member; the other sites did not, and each died at link — first on
    `cvmfs_curl_perform_pinned`, then, once the pin was named, one TU further
    down on `brix_resolve`, `brix_resolve_ntop` and `brix_netpref_family`,
    because the pin resolves every name through the client seam
    (`client/lib/net/resolve.c`, `netpref.c`). The affected sites are the
    driver-unit pair (`cvmfs_driver_units.py` and `cvmfs_driver_units_part2.py`,
    which *rebinds* `BRIXCVMFS_DRIVER_SRCS` rather than extending it), the
    `cvmfs_live_ext` family, the `brixcvmfs_live` family,
    `tap_proxy_live_part2.py` (which links `client/libbrix.a`, so it owed the
    split member and not the seam) and `tests/c/cvmfs_url_rewrite_test.c`, which
    `#include`s the transport and therefore had to *stub* the pin rather than
    link it. None of this is DNS behaviour; all of it is the cost of the seam,
    and it is recorded here because the seam is what made the pin a separate
    file.

    `tools/ci/check_client_build_coverage.py` could not have caught any of it:
    it compared ONE concatenated list of sources against the Makefile, so a
    single complete site made every other site look complete. It now judges each
    site alone and by symbol: it follows `_load_continuation()` composition (a
    shard is part of its loader's gcc line), honours a shard that rebinds the
    loader's list (a rebinding shadows, it does not extend), reads a `.c` unit's
    own stubs as definitions, treats `client/libbrix.a` as supplying the library
    half but never the app-side split, and walks one hop out of the split into
    `client/lib/net` so the seam a split TU calls is part of what a site owes.
    References are call-shaped and comment-free — the transport names
    `brix_resolve()` twice in prose and calls it never, and a word-match reading
    demanded the seam at sites that never compile the pin.

    The four new cases in `tests/test_source_guards.py` are the pin:
    `test_a_site_that_stops_at_the_split_misses_the_seam_below_it` is the
    second stage of the real failure reduced to a fixture,
    `test_a_site_that_names_the_seam_passes` is its positive,
    `test_an_archive_supplies_the_library_but_never_the_split` holds the
    `tap_proxy_live_part2.py` case, and
    `test_a_symbol_named_only_in_a_comment_is_not_a_call` holds the transport's
    prose mention. `test_a_shard_that_rebinds_the_loaders_list_is_judged_on_its_own`
    covers `cvmfs_driver_units_part2.py`. The live proof is the whole file
    `tests/test_cvmfs_driver_units.py` (10 passed), which is where the link
    error surfaced.

14. **The pinned transfer loop was the one blocking libcurl site nothing
    bounded.** `tests/test_blocking_curl_bounded.py` states a phase-106 W5
    security invariant: a blocking `curl_easy_perform()` with no timeout is an
    unbounded stall, so a black-holed endpoint is a denial of service. It reads
    each source that performs, plus any `*setup*.c` beside it, and asks for a
    timeout option. `src/net/dns/curl_pin.c` had none — the loop this phase
    added performs on a handle it did *not* create and re-performs once per
    redirect hop, and it relied entirely on its callers having bounded that
    handle first. Both real callers (the two pelican transfers) do, so nothing
    hung in practice; the defect is that neither the audit nor the next caller
    could tell. Even for a caller that does set `CURLOPT_TIMEOUT`, the bound was
    per *hop*, so a chain of N redirects cost N times the caller's ceiling.

    The loop now owns a **total** budget. `brix_dns_curl_transfer_t` gains
    `timeout_ms`; `curl_pin_bound()` sets `CURLOPT_TIMEOUT_MS`,
    `CURLOPT_CONNECTTIMEOUT_MS` and `CURLOPT_NOSIGNAL` on every hop with what is
    *left* of it, and an exhausted budget returns `CURLE_OPERATION_TIMEDOUT`
    rather than starting another hop — libcurl reads a 0 timeout as "no
    timeout", so the loop must never hand it one. The budget is spent down with
    `CURLINFO_TOTAL_TIME_T`, libcurl's own clock: `ngx_current_msec` is updated
    by the event loop and does not advance on a thread-pool thread, which is
    exactly where this code runs, so a loop that measured with it would see no
    time pass and the total budget would silently become per-hop again. A caller
    that names no budget gets `BRIX_DNS_CURL_TIMEOUT_MS_DEFAULT` (60 s, the S3
    origin's own fallback ceiling); `brix_pelican_xfer_init()` names 30 s, one
    ceiling for the whole chain instead of one per hop.

    `tests/c/curl_pin_budget_test.c` drives the real loop against three local
    endpoints — a listener that completes the handshake from its backlog and
    never answers, a server that redirects once into that black hole after
    burning most of the budget, and a server that answers at once — with the DNS
    half stubbed (every URL has an IP-literal host, and the
    `brix_dns_resolve_sync()` stub fails the run if it is ever reached). Both
    negatives were verified by building the unit against a deliberately broken
    copy: with the per-hop options removed the transfer never returns (the
    unit's `alarm()` watchdog names it), and with the budget not spent down the
    two hops take 1,602 ms of a 1,000 ms budget. The arm where the caller names
    no budget at all is a second build with
    `-DBRIX_DNS_CURL_TIMEOUT_MS_DEFAULT=400`, so proving the fallback costs a
    second rather than a minute; the shipped 60 s value is pinned separately in
    `tests/test_phase116_curl_pin_budget.py`, which also holds the caller census
    — a new caller of `brix_dns_curl_perform_pinned()` must join it rather than
    inherit the default unnoticed.

15. **The guard had a backlog after all — one written in file extensions.**
    The operator's closing instruction was to drill until the seam was correct
    and complete rather than leave any client or plugin code outside it, and
    the drill-down found the one place a bypass could still have landed
    unseen: `check_dns_seam.py` walked its three trees filtering
    `path.suffix in (".c", ".h")`. `client/apps/ceph/` holds six C++ sources —
    `xrdceph_striper_engine.cpp`, `xrdceph_striper_migrate.cpp`,
    `xrdceph_striper_estimate.cpp`, `xrdceph_cephfs_to_striper.cpp`,
    `xrdceph_striper_internal.hpp` and `pymigrate/shim/rados_manifest_shim.cpp`
    — of which `client/Makefile:587-601` compiles four into the two
    `xrdceph_striper_migrate` / `xrdceph_cephfs_to_striper` programs the RPM
    ships (`packaging/rpm/nginx-mod-brix-cache.spec:413-414`) and `:812-813`
    installs the fifth as the `pymigrate` shim. They are shipped client code
    that the one-DNS-path guarantee did not cover. They are
    clean today, so this is a hole and not a defect: the guard's file count
    goes 2,437 → 2,443 and stays green.

    **The same hole had a second axis**, found by asking the question the
    other way round — not "which suffixes does it read" but "which trees does
    it walk". `SCAN_DIRS` was `("src", "client", "shared")`, and
    `tools/pblock-fsck/` is a standalone consistency oracle in C with its own
    install target (`tools/pblock-fsck/Makefile:14-15`). Shipped code, outside
    the guard, for the same reason and with the same consequence. It is clean
    too — libc, `dirent` and sqlite3, no `netdb.h` and no socket at all — but
    a resolver landing there would never have been seen.

    So the guard now walks `("src", "client", "shared", "tools")` over
    `SOURCE_SUFFIXES` naming every compiled suffix, and what is left outside
    is test C only (`tests/`, `k8s-tests/`, `brixtest/`), which uses libc
    deliberately. Real-tree file count 2,437 → 2,447, still green.

    Five tests hold both axes. Two are negatives — a planted `getaddrinfo`
    must be flagged in each of the five C++ suffixes, and in
    `tools/pblock-fsck/pblock-fsck.c`. Two are censuses that make the next
    gap a red rather than a silence: no tracked suffix under the scanned
    trees may be one the guard neither scans nor names non-source, and **no
    tracked C or C++ file anywhere in the repository** may sit outside both
    `SCAN_DIRS` and the declared test trees — so a new shipped tool in a new
    directory has to be judged, not discovered. The fifth is the live proof
    that the six real ceph files are in `_source_files(REPO)`.

    Two smaller findings from the same sweep are pinned beside it. The
    `ngx_parse_url` companion rule is judged **per file**, so one
    `no_resolve = 1` satisfies a file however many times it parses a URL; all
    six call sites are 1:1 today and a test now says so, which makes a second
    call in an already-compliant file a red rather than the guard's one blind
    spot. And amendment 9's SRV half was the only non-goal in this phase left
    unpinned while its sibling (W6 decision B) was pinned; the marker census
    over `src/net/dns/` and the client seam closes that asymmetry.

    Everything else the sweep checked was already whole. All 1,192 sources
    named by `./config` and `client/Makefile` sit inside the scanned trees
    with a scanned suffix; there is no direct `ngx_resolve_*` outside the
    seam, no CURLU or `curl_multi` bypass, and the two unpinned `CURLOPT_URL`
    mentions are comments. The non-C axis is clean as well: no Python or
    shell under any shipped tree calls `socket.getaddrinfo`,
    `socket.gethostby*`, `getent hosts`, `resolvectl`, `dig`, `host` or
    `nslookup` — the only two `socket.create_connection()` calls
    (`tools/diag/storm_ab_bench.py:99`, `utils/xrd_proxy.py:48`) both name
    `127.0.0.1`, and the `pymigrate` plugin names no resolver at all.
    `CMakeLists.txt` compiles no source outside these trees.

16. **The backoff pin sampled a value that is honestly zero.** The one red
    left after the fifteen suites went green was this phase's own test, and
    intermittently: `test_dead_target_retries_back_off` failed about one run in
    seven with `assert 0 < 0`, never in the backoff assertions themselves but
    in the sampler's per-sample guard `_assert_retry_armed`, which required
    `0 < next_retry_ms <= max`. The row carried `failures: 3` when it fired, so
    the mechanism under test was working; what the guard had encoded was that a
    failed target *always* has a retry pending. It does not. Between the timer
    firing and the next retry being armed there is a short window in which no
    retry IS pending because one is in flight, and `next_retry_ms` reports 0 —
    truthfully. A 50 ms poll over a four-second window lands in it now and
    then. **This is a test defect, not a product one**, and the distinction
    matters: the fix must not weaken the guard into vacuity. So the bound check
    stays per sample (`0 <= next_retry_ms <= max`, still catching a retry
    scheduled past `brix_dns_retry`'s cap) and the *armed-ness* check moves up
    to `_sample_retries`, which now asserts over the whole window that a
    positive `next_retry_ms` was observed at least once. A genuinely stuck
    target reads 0 on every sample and still reddens — verified directly
    against three synthetic rows: all-zero rejected, over-cap rejected,
    alternating zero/armed accepted. 10/10 isolated runs after the fix, then
    160/160 across all fifteen suites.

17. **The whole-repo C census found its first stray: a site checksum
    plugin.** The fail-fast lane of 2026-09-07 (run 46) reddened on
    `test_every_tracked_c_file_is_scanned_or_is_test_code` the first time it
    reached the census after `contrib/checksum-plugins/brix_cks_fnv1a64.c`
    was tracked (20:06). `contrib/` was outside `SCAN_DIRS`, and a checksum
    plugin is a shared object the worker `dlopen()`s
    (`contrib/checksum-plugins/README.md`), so a resolver in one runs inside
    the server process — the same bypass as in `src/`. Judged, as the census
    demands: the guard now walks `("src", "client", "shared", "tools",
    "contrib")`; the plugin is clean (no `netdb.h`, no socket), so the
    real-tree count goes 2,456 → 2,457 and stays green. Three pins: a
    planted `getaddrinfo` under the plugin tree is flagged, a bare
    `#include <netdb.h>` there is flagged by the header rule alone, and the
    live proof that every tracked C file under `contrib/checksum-plugins/`
    is in `_source_files(REPO)`. The census did what amendment 15 built it
    for — a red, not a silence.

## Goal

Two properties, both enforced by tests and a CI guard:

1. **Every hostname nginx or brix sees is resolved at runtime, from the
   `resolv.conf` the process can read, with the search list, `ndots` and
   timeouts that file declares.** One directive, `brix_resolver auto;`, seeds
   nginx's own asynchronous resolver from that file so stock nginx features
   that need a `resolver` (`proxy_pass` with a variable, upstream
   `server ... resolve`) work with no nameserver copied into `nginx.conf`.
2. **No DNS condition prevents `nginx -t` or startup.** A brix directive
   naming a host is syntax-checked at configuration time and address-resolved
   later, with retry and backoff. NXDOMAIN, SERVFAIL, a timeout, or an empty
   `resolv.conf` at start produces a warning, a metric and a dashboard row,
   never a refused configuration.

The design keeps invariant 8 (low-cardinality metric labels), the SSRF policy
in `src/core/compat/net_target.c` on every resolved address, and the
event-loop rule already documented at `src/core/compat/net_target.h:12`
(no blocking `getaddrinfo()` on the event loop).

## Problem — measured 2026-09-05 against `main` @ `6b78de61a`, nginx 1.28.3

### What nginx open-source already has, and what it still lacks

nginx 1.27.3 moved the Plus-only `resolve` parameter of the upstream `server`
directive and the `resolver` directive inside `upstream {}` into open source;
both are present in the 1.28.3 tree brix builds against
(`/tmp/nginx-1.28.3/src/http/ngx_http_upstream.c:6357` and `:6504`,
`src/stream/ngx_stream_upstream.c:545` and `:702`). This phase does not
reimplement them. What neither open-source nor Plus provides, and what brix
supplies here:

| Gap | nginx OSS 1.28 | nginx Plus | Phase 116 |
|---|---|---|---|
| Resolver seeded from `/etc/resolv.conf` | no — `resolver` needs literal nameserver addresses; the string `resolv.conf` appears nowhere under `src/` | no | **W1** |
| `search` / `domain` / `ndots` semantics | no — `ngx_resolver` queries the name as given | no | **W2** |
| A hostname in a module directive that does not fail startup on DNS error | only for `server ... resolve` inside a zoned upstream | same | **W3** (every brix directive) |
| One re-resolving, TTL-honouring, SSRF-checked lookup path for module code | n/a | n/a | **W4/W5** |
| Live re-read of `resolv.conf` without reload | no | no | **W6** (gated) |

### What brix does today

**Configuration-time resolution that is fatal.** Four brix directives call
`ngx_parse_url()` at parse time and turn a DNS failure into
`NGX_CONF_ERROR`, so `nginx -t` fails and the master refuses to start:

| Directive | Site | Behaviour on DNS failure |
|---|---|---|
| `brix_cms_manager` | `src/net/cms/config.c:41-58` | `EMERG "could not resolve"` → start refused |
| `brix_mirror_url` (HTTP) | `src/net/mirror/http_mirror_config.c:130` | `EMERG "cannot resolve"` → start refused |
| `brix_mirror_url` (stream) | `src/net/mirror/stream_mirror_config.c:68` | `EMERG "cannot resolve"` → start refused |
| `brix_conf_parse_addr()` helper | `src/core/config/helpers.c:99` | `EMERG` → `NULL`; **no caller remains in `src/`** (declared at `src/core/config/config.h:40`) |

`brix_upstream` (`src/net/upstream/directives.c:125-145`) is the one site
already tolerant: it warns and falls back to a per-request `getaddrinfo()`,
which the file's own header admits "may block" the event loop
(`src/net/upstream/start.c:12`). Tolerant, but by breaking the other rule.

**Runtime resolution is scattered and uncached.** Fourteen sites call
`getaddrinfo()` directly (Appendix A). Each resolves on every use, none
honours TTL, none re-resolves on a connect failure with a fresh answer, and
two run on the event loop. libc reads `resolv.conf` for them, so these sites
already see the search list — but the asynchronous path nginx itself uses does
not, so a name that resolves from a worker thread can fail from a `proxy_pass`
variable in the same process.

**The dashboard config classifier** lists `resolver`/`resolver_timeout` as
stock nginx directives (`src/observability/dashboard/config_download_classify.c:117`);
no brix directive today declares any DNS policy.

**Test estate.** 53 fleet configs use `brix_cms_manager` or `brix_mirror_url`;
none uses `resolver`. Every one of them names a literal address, which is why
the fatal path has never been exercised in CI. There is no DNS stub server in
`tests/brixtest/`.

## Design

### Directive surface

```
brix_resolver auto [path=/etc/resolv.conf] [valid=<time>] [min_ttl=<time>]
                   [max_ttl=<time>] [negative_ttl=<time>]
                   [ipv4=on|off] [ipv6=on|off] [search=on|off];
brix_resolver off;
brix_dns_retry  <initial> <max>;        # default 1s 30s, exponential
brix_dns_status_zone <name>;            # optional; dashboard rows
```

Contexts: `http`, `server`, `location`; `stream`, `server`. Registered through
the four HTTP protocol modules' shared command tables and the stream module the
way `tools/ci/check_directive_registry.py` already censuses; names go into
`docs/03-configuration/directives.md`.

`brix_resolver auto` **fills, never overrides**: it installs the file-derived
`ngx_resolver_t` into `ngx_http_core_loc_conf_t.resolver`
(`/tmp/nginx-1.28.3/src/http/ngx_http_core_module.h:379`),
`ngx_stream_core_srv_conf_t.resolver` (`src/stream/ngx_stream.h:164`) and
each `ngx_http_upstream_srv_conf_t.resolver` / stream equivalent
(`ngx_http_upstream.h:142`, `ngx_stream_upstream.h:89`) only where the operator
wrote no `resolver` of their own. Core's merge creates a dummy resolver when
none is set (`ngx_http_core_module.c:3874-3889`); brix's merge runs after
core's by module order and replaces exactly that dummy. An explicit `resolver`
anywhere in scope wins unchanged.

### W1 — `resolv.conf` reader and resolver seeding

- [x] **W1.1 Parser** `src/net/dns/resolv_conf.c` (+ `.h`): reads `path`
  (default `/etc/resolv.conf`), accepts `nameserver` (IPv4, IPv6 with and
  without `%scope`, optional `#port`), `search`, `domain` (older synonym,
  last one wins as in glibc), `options ndots:N timeout:N attempts:N rotate`, and ignores
  `single-request`, `single-request-reopen`, `use-vc`, `trust-ad`,
  `no-reload`, `sortlist` and every unknown keyword.
  **Landed with amendments 2 and 4:** `nameserver` takes an address literal
  only (plus the BriX `ip:port` / `[v6]:port` extension), a `%scope` suffix is
  parsed and dropped, and `rotate` is recorded but inert.
  Clamps: `ndots ≤ 15`, `timeout ≤ 30`, `attempts ≤ 5`, 3 nameservers,
  6 search elements. Honours the
  `LOCALDOMAIN` and `RES_OPTIONS` environment overrides glibc honours. An
  empty or absent file yields glibc's default: nameserver `127.0.0.1`,
  `ndots:1`, `timeout:5`, `attempts:2`. Maximum three nameservers and six
  search elements, as glibc clamps them.
- [x] **W1.2 Resolver construction.** The parsed nameservers become the
  argument vector of `ngx_resolver_create()` (`ngx_resolver.c:133`), which is
  the only way nginx allows an `ngx_resolver_t` to be built; `valid=`,
  `ipv4=`, `ipv6=` pass straight through. `timeout:N` maps onto
  `resolver_timeout` where the operator left it unset; `attempts:N` and
  `rotate` are implemented in W2's driver because `ngx_resolver` retries each
  nameserver in order with a fixed policy.
- [x] **W1.3 Merge-time seeding** into the four resolver slots above, with a
  `notice` log line per slot that names the file, the nameserver count and
  the search list once per reload. `nginx -t` prints the same line.
- [x] **W1.4 Reload semantics.** The file is re-read on every configuration
  parse (`nginx -s reload`, `-t`). Nothing else in W1 runs after `init_process`.
- Verification: success — `brix_resolver auto` with a three-nameserver,
  two-search-element file drives `proxy_pass http://$upstream_name` and
  `server name.svc resolve` with no `resolver` line; error — a file with no
  `nameserver` at all starts with the loopback default and a `warn`, and a
  `nameserver` line that is not an address is skipped with a `warn`, never
  fatal; security negative — `path=` must be absolute, a relative or empty
  path is a configuration error (that one is fatal by design: it is the
  operator's line, not DNS) while a *symlink* is followed on purpose (see
  amendment 1: systemd's `/etc/resolv.conf` is one, and an unreadable target
  is a warning, never a refusal), and no
  byte of the file ever reaches a shell, an environment or a log line
  unescaped (a `nameserver 1.2.3.4 $(id)` line logs the literal bytes through
  `%V`).

### W2 — Search list, `ndots`, attempts and rotation

`ngx_resolver` resolves the literal name it is handed. glibc's rules live in
one brix driver so every caller gets them identically:

- [x] **W2.1 Candidate list.** For a query name: a trailing dot means absolute
  only. Otherwise, if the name contains at least `ndots` dots, try it
  absolute first then each search suffix; if fewer, try each search suffix
  in order then absolute. `search=off` disables expansion for operators who
  want nginx's literal behaviour.
- [x] **W2.2 Driver** `src/net/dns/resolve.c`: `brix_dns_resolve(ctx)` walks
  the candidate list as a chain of `ngx_resolve_start()` /
  `ngx_resolve_name()` contexts on the event loop, stopping at the first
  answer with addresses; NXDOMAIN on a candidate advances, SERVFAIL or
  timeout counts one attempt, and after `attempts` exhausted per candidate
  the whole query reports failure with the last rcode. **Landed without the `rotate` machinery** (amendment 3): the flag is parsed
  and ignored, because `ngx_resolver` already fails over between nameservers
  and W5.3 rotates across the answer set per connect.
- [x] **W2.3 Answer shaping.** Results carry every A/AAAA address, the minimum
  TTL of the answer set clamped to `[min_ttl, max_ttl]`, and the family
  filtered by the caller's `brix_af_policy_t` (`src/core/compat/af_policy.h`).
- Verification: success — `ndots:5` with search `ns.svc.cluster.local
  svc.cluster.local cluster.local` resolves `manager` via the first suffix
  and `manager.ns.svc.cluster.local.` absolutely with exactly one query;
  error — a suffix whose nameserver returns SERVFAIL is retried `attempts`
  times then skipped, and the query still succeeds on the next suffix;
  security negative — an answer obtained through search-list expansion is
  still passed through `brix_net_target_check_addr()` before any connect, so
  a search domain that resolves `metadata` to `169.254.169.254` is refused by
  the same `allow_local`/`allow_private` policy as a literal would be.

### W3 — Start-safe hostnames in every brix directive (the operator requirement)

- [x] **W3.1 Parse-only at configuration time.** Each site in the "fatal"
  table above keeps its syntax checks (scheme, brackets, port present, port
  in range, host is a valid DNS label sequence or literal address) and stores
  the host as text plus a `brix_dns_target_t` handle instead of a resolved
  `ngx_addr_t`. A literal IP is resolved immediately, as today, because no
  DNS is involved. A syntactically invalid host stays fatal.
- [x] **W3.2 First resolution at `init_process`,** asynchronously via W2, with
  `brix_dns_retry` backoff until the first answer; connection attempts that
  arrive before an answer fail fast with the existing per-site error
  (`kXR_NotFound`-class for CMS, mirror target skipped, upstream 502/redirect
  refused) and a rate-limited `warn`. The master never blocks on DNS.
- [x] **W3.3 Sites.** `brix_cms_manager` (`src/net/cms/config.c`);
  `brix_mirror_url` HTTP and stream; `brix_upstream` (delete the blocking
  per-request fallback in `src/net/upstream/start.c`, replace with the W4
  cache); `brix_proxy_pool` admin API (`src/protocols/webdav/proxy_pool.c:140`
  accepts an unresolved backend into the SHM table with `resolving` state,
  draining semantics unchanged); `brix_pmark_firefly_origin`
  (`src/observability/pmark/mapping.c:152`); `brix_health_check` peers
  (`src/net/manager/health_check.c:175`). `brix_conf_parse_addr()` is deleted
  unless a caller is found — the grep on 2026-09-05 found none.
- [x] **W3.4 Dashboard and metrics.** Unresolved targets appear in the
  dashboard snapshot as `{directive, host, state, last_error, next_retry}`
  rows (names are fine there; they are not metric labels), and in
  `brix_dns_targets{state="resolved|resolving|failed"}` as a gauge with no
  host label (invariant 8).
- Verification: success — a config naming an NXDOMAIN manager, mirror,
  upstream and firefly host passes `nginx -t`, the master starts, and the
  moment the test DNS stub starts answering every target reaches
  `resolved` within one retry interval without a reload; error — while a
  target is unresolved a client open through that path gets the documented
  per-protocol error (not a hang, not a 5xx storm: one `warn` per
  `brix_dns_retry` interval); security negative — a server started with DNS
  down and later resolved does not lose any auth gate: an anonymous write
  through the now-resolved upstream is refused by the typed VFS policy with
  `EROFS`/`EACCES` exactly as when DNS was up (Phase 105 invariant carried
  through deferred initialisation).

### W4 — One lookup path: cache, negative cache, thread flavour, CI seam

- [x] **W4.1 Per-worker cache** keyed by `(name, family policy)` holding the
  W2 answer, TTL-expiring, bounded (`brix_dns_cache_max`, default 4096
  entries, LRU). `ngx_resolver` keeps its own cache of raw records; brix's
  cache holds the post-search, post-policy shaped answer so callers never
  redo expansion.
- [x] **W4.2 Negative cache** with `negative_ttl` (default 5 s) so a storm of
  opens against a dead name does not become a storm of queries.
- [x] **W4.3 Blocking flavour for thread-pool sites.** `brix_dns_resolve_sync()`
  serves from the cache under a read lock and otherwise calls `getaddrinfo()`
  exactly as those sites do today (libc already honours `resolv.conf`
  there), then stores the shaped answer. Thread-pool sites in Appendix A
  switch to it; the two event-loop sites switch to the asynchronous W2 call.
- [x] **W4.4 Guard** `tools/ci/check_dns_seam.py`, modelled on
  `check_vfs_seam.py`: **landed stricter than specified** (amendment 5): there is no
  `dns-seam-allow` marker and no backlog file, because every site in Appendix A
  was converted. The forward symbols (`getaddrinfo`, `gethostbyname*`,
  `gethostbyaddr*`, `res_*query`, `res_*search`) are allowed only in
  `src/net/dns/resolve_thread.c` and `client/lib/net/resolve.c`, `getnameinfo`
  only in `src/net/dns/reverse.c`, `<netdb.h>` only in those three;
  `ngx_inet_resolve_host` and `CURLOPT_FOLLOWLOCATION` are banned outright;
  and two companion rules apply per file — `ngx_parse_url(` ⇒ `no_resolve = 1`,
  `CURLOPT_URL` ⇒ an address pin. `--root <dir>` scans a copy, which is how
  the guard's own negatives run without touching the real tree.
- Verification: success — 10k opens against one name produce one query per
  TTL window; error — a name that flips from resolvable to NXDOMAIN is served
  from cache until TTL, then negative-cached for `negative_ttl`, and the
  metric `brix_dns_lookups_total{result="nxdomain"}` counts one query per
  negative window, not per open; security negative — the cache is keyed by
  the family policy, so a caller that demands `inet` can never be handed a
  cached `inet6` answer from a permissive caller, and a TPC source whose
  cached address changes between the `brix_net_target_check_dns_pin()`
  preflight and the connect is re-checked against the SSRF policy on the
  address actually connected (the DNS-rebinding pin in
  `src/core/compat/net_target.h:109` stays authoritative).

### W5 — Re-resolution and endpoint refresh for long-lived targets

- [x] **W5.1 TTL-driven refresh** for CMS managers, mirror targets, `brix_upstream`,
  health-check peers and cache origins: a per-worker timer re-resolves on
  expiry and swaps the address set atomically; live connections are not
  torn down, new connections use the new set.
- [x] **W5.2 Failure-driven refresh:** `ECONNREFUSED`, `EHOSTUNREACH`,
  `ENETUNREACH` or a connect timeout on a target marks its entry stale and
  forces a re-resolve before the next attempt, with the `brix_dns_retry`
  backoff so a dead target does not query on every connect.
- [x] **W5.3 Multi-address use:** round-robin across the answer set per
  connect (the CMS manager list and the health checker already iterate
  peers; this iterates addresses within a peer), family order from
  `af_policy`.
- [ ] **W5.4 SRV (`service=`) — NOT TAKEN.** `ngx_resolver` supports SRV via
  `ctx->service`, and exposing `brix_cms_manager _xrootd._tcp.example.org
  service=xrootd` remains possible, but it was a stretch item with no consumer
  in the tree. Recorded as a non-goal, not as open work.
- Verification: success — changing the stub's answer for a manager name is
  picked up within one TTL with zero dropped in-flight sessions; error — a
  manager whose address goes dark is re-resolved, and if the new answer is
  the same dead address the backoff caps at `brix_dns_retry <max>`;
  security negative — a shortened TTL cannot be used to spin the resolver:
  `min_ttl` clamps every answer, so a 0-TTL response costs one query per
  `min_ttl`, never one per connect.

### W6 — Live `resolv.conf` tracking without reload (decision-gated)

kubelet, NetworkManager and `systemd-resolved` rewrite the file without
signalling nginx; glibc ≥ 2.26 re-reads on mtime change. `ngx_resolver_t` is
built from `ngx_conf_t` and its nameserver connections are fixed at creation,
so a runtime rebuild means constructing a resolver outside configuration
parsing. Options, decided by a measurement and recorded here before code:

- **A.** Per-worker timer stats the file every `reload=<time>`; on change,
  build a new `ngx_resolver_t` from a synthetic `ngx_conf_t` over the cycle
  pool and swap the pointer in the brix driver only (nginx core slots keep the
  reload-time resolver). Cheap, worker-local, does not help `proxy_pass $var`.
- **B.** Document `nginx -s reload` from the deployment's own file watcher
  (the Phase 115 W1 compose/helm stacks carry an inotify sidecar recipe).
  Zero new C.
- **C.** Both.

Default recommendation is B now, A only if a live lab shows a real outage
window between a `resolv.conf` rewrite and the next reload.

## Invariants this phase adds

- **I-DNS-1** No `getaddrinfo()`, `gethostbyname()` or `ngx_inet_resolve_host()`
  runs on the event loop; guard `check_dns_seam.py`.
- **I-DNS-2** No brix directive fails configuration parsing on a DNS result.
  A hostname's only configuration-time checks are syntactic. Pinned by the W3
  success test running `nginx -t` with the DNS stub down.
- **I-DNS-3** Every address obtained through brix DNS passes
  `brix_net_target_check_addr()` before a connect, regardless of how the name
  was expanded or cached.
- **I-DNS-4** Hostnames never become metric labels; they appear only in
  dashboard rows and logs.
- **I-DNS-5** `brix_resolver auto` fills unset resolver slots only; an
  operator's explicit `resolver` is never replaced.

## Non-goals

- Reimplementing upstream `server ... resolve` or `resolver` in `upstream {}`:
  open-source nginx ≥ 1.27.3 has them; brix only seeds their resolver.
- A DNS-over-TLS or DNS-over-HTTPS client; `use-vc` (TCP) is passed to
  `ngx_resolver` only where it already supports TCP fallback.
- `/etc/hosts` and NSS: the asynchronous path is pure DNS. Sites that need
  `/etc/hosts` semantics are thread-pool sites, and they reach libc through
  `resolve_thread.c` when the bridge declines; the difference is documented in
  the directive reference.
- mDNS, LLMNR, `nsswitch.conf` ordering.
- SRV records (W5.4): specified as a stretch item, not taken — no consumer.
- A worker-side `resolv.conf` re-stat (W6 option A): not taken; W6 closed as
  decision B, `nginx -s reload` driven by the deployment's own file watcher.

**No longer a non-goal.** The spec listed client-side (`client/`) resolution as
out of scope. The operator's instruction of 2026-09-05 — fix all of the code in
the clients and plugins before closing — overrode that, so `client/` and
`shared/` are in scope, hold one seam (`client/lib/net/resolve.c`), and are
scanned by the guard.

## Test plan — as delivered

`tests/dns_stub.py` (not `tests/brixtest/`, which holds no server stubs): a
pure-Python UDP+TCP DNS responder with a programmable zone (A, AAAA, CNAME,
PTR), per-name TTL and rcode, a query counter, and start/stop/answer-swap
controls. Every suite writes its own `resolv.conf` into `tmp_path` and passes
`path=`, so no test ever reads the host's `/etc/resolv.conf` or reaches a real
nameserver.

| suite | tests | covers | lane |
|---|---|---|---|
| `test_phase116_resolv_conf_parser.py` | 28 | W1 parser, via the C unittest (`resolv_conf_unittest.c`) and its negatives, plus the four symlink cases behind amendment 1 and the unreadable-path loader fix (amendment 11) | pure |
| `test_phase116_search_ndots.py` | 4 | W2 candidate order and query counts | `lc-p116-dns` |
| `test_phase116_start_safe_hostnames.py` | 13 | W3: `nginx -t` and start with every hostname dead, convergence once the stub answers, the auth negative, and `brix_dns_status_zone` in both planes (amendment 11) | `lc-p116-dns` |
| `test_phase116_dns_cache_and_seam.py` | 39 | W4 cache/negative cache + the guard's own positive and negatives, incl. the three resolver classes added in amendment 11, the live I-DNS-4 label census, and amendment 15's two axes — C++ and `tools/` negatives, the tracked-suffix and whole-repo C censuses, and the live proof that the shipped `client/apps/ceph` C++ apps are scanned; amendment 17: `contrib/` negatives (planted resolver, bare `netdb.h`) and the live proof that the shipped checksum plugins are scanned | `lc-p116-dns` |
| `test_phase116_cache_bound.py` | 3 | `brix_dns_cache_max` on both caches, incl. the peer-filled reverse cache negative | `lc-p116-dns-rev` |
| `test_phase116_reresolve.py` | 5 | W5.1 answer swap, dead-target backoff, `min_ttl` clamp, and W5.3's failure-driven advance surviving the refresh it schedules (amendment 12) | `lc-p116-dns` |
| `test_phase116_upstream_async_resolve.py` | 4 | `brix_upstream` dials asynchronously; no event-loop resolve; successive dials rotate the answer set (amendment 12) | `lc-p116-dns-upstream` |
| `test_phase116_mirror_failure_reresolve.py` | 4 | W5.2 failure-driven re-resolve on the stream mirror | `lc-p116-dns-mirror` |
| `test_phase116_reverse_dns.py` | 5 | the PTR driver, cache and prefetch (amendment 6) | `lc-p116-dns-rev` |
| `test_phase116_reverse_no_resolver.py` | 11 | amendment 10: an `h` rule decided with no `brix_resolver` and no `thread_pool`, the two merge call sites, the stream protbind slot, and the three forward callers that resolve outside the target registry, and the file-order case where the operator declares the pool later | `lc-p116-dns-rev` |
| `test_phase116_client_resolve.py` | 6 | the client seam and its cache (amendment 8) | pure |
| `test_phase116_recent_phases_nonregression.py` | 19 | phases 105–115 and the 2.0 readiness audit did not revert: pin suites re-run as subprocesses (the two ladder-shape audits pinned to the canonical `TEST_PORT_START` so a second concurrent lane is not read as a regression), removed directives still removed, the three seam/gate guards still green | pure |
| `test_phase116_bridge_sync_path.py` | 3 | amendment 11: a thread-pool caller (the cvmfs RTT origin probe) resolves through the worker's policy, the counters move, the failure is the policy's answer and not a libc detour, and an off-path forgery never reaches the probe | `lc-p116-dns-bridge` |
| `test_phase116_discoveries_and_compat.py` | 11 | amendment 11: the directive and metric-family censuses over this corpus, the resolv.conf load site (decision B), both bridge arms, and the amendment-10 caller set incl. the inert WebDAV pool; amendment 12: both halves pinned structurally so a revert reddens without a lane; amendment 15: the `ngx_parse_url` 1:1 ratio and the SRV non-goal | pure |
| `tests/test_source_guards.py` | 25 | amendment 13: `check_client_build_coverage` judged per site and by symbol — the split member, the seam one hop below it, `_load_continuation` composition, a shard that rebinds the loader's list, a `.c` unit's own stubs, `client/libbrix.a` supplying only the library half, and a comment-only mention that is not a call | pure |
| `test_phase116_curl_pin_budget.py` | 8 | amendment 14: the pinned transfer loop driven for real against a black hole, a 302 into it and a prompt answer (C unit, both arms), the shipped 60 s default, the per-hop bound, the exhausted-budget return, libcurl's clock, and the caller census | pure |

160 tests in the fifteen `test_phase116_*` suites, plus the 25 in
`tests/test_source_guards.py` that hold amendment 13 (four of them written
for it) and the whole of `tests/test_cvmfs_driver_units.py` (10) as its live
proof. Each live suite carries `pytest.mark.xdist_group` for its lane
because the stub is a fixed-port family; the five lanes are independent, so
they can run concurrently on one host but must not share a `TEST_ROOT`.

Run form (a private lane, no shared fleet — pick a `TEST_PORT_START` that no
other session owns; a lane reserves `TOTAL_PORT_COUNT` = 18,711 ports):

```
TEST_ROOT=/tmp/xrd-p116 TEST_PORT_START=42000 TEST_SKIP_SERVER_SETUP=1 \
  python3 -m pytest -p no:cacheprovider -q tests/test_phase116_search_ndots.py
```

The four pure suites (`resolv_conf_parser`, `client_resolve`,
`recent_phases_nonregression`, `discoveries_and_compat`) need no lane:
`PYTHONPATH=tests python3 -m pytest --noconftest -q
tests/test_phase116_discoveries_and_compat.py`. They import stdlib only, so a
broken port ladder in another session cannot silently deselect them.

## Close-out

W1–W6 are closed, each with the tests named in the table above. I-DNS-1 …
I-DNS-5 are all guarded: I-DNS-1 and the seam by `check_dns_seam.py` plus the
guard's own negatives, I-DNS-2 by the start-safe suite (`nginx -t` green with
the stub down), I-DNS-3 by the SSRF re-check negatives, I-DNS-4 by the metric
census in the cache/seam suite, I-DNS-5 by the "explicit resolver wins"
positive. W5.4 and W6 option A were not taken and are recorded as non-goals
above, not as open work — and both are now *pinned* as non-goals, so taking
one silently reddens the census suite (amendment 15).

Every amendment is covered by name: 1 by the parser suite's symlink cases, 2–4
by the parser negatives, 5 by the guard's own positives and negatives, 6 by the
reverse suites, 7 and 11 by the bridge suite and the census suite, 8 by the
client suite, 9 by the SRV non-goal pin in
`test_phase116_discoveries_and_compat.py` (a non-goal is testable: the
assertion is that it stayed one, exactly as W6 decision B is pinned), 10 by
`test_phase116_reverse_no_resolver.py`, 12 by the dead-first-address negative
in `test_phase116_reresolve.py` together with the rotation positive in
`test_phase116_upstream_async_resolve.py`, 13 by the four seam cases in
`tests/test_source_guards.py` and, live, by `tests/test_cvmfs_driver_units.py`,
14 by `test_phase116_curl_pin_budget.py` together with the named-site row
this phase added to `tests/test_blocking_curl_bounded.py`, 16 by the repaired
sampler in `test_phase116_reresolve.py` itself, whose window-wide armed-ness
assertion is what a stuck target now trips, 17 by the three `contrib/` pins
in `test_phase116_dns_cache_and_seam.py` beside the census that found the
plugin. The two censuses in
`test_phase116_discoveries_and_compat.py` are the standing guard against this
list going stale: a new DNS directive or metric family that no phase-116 test
or template names reddens the suite.

One operational dependency remains outside this phase: the `lc-p116-dns-bridge`
lane needs a fixed-port slot in the shared lifecycle ledger before the bridge
suite can start (`launcher/harness.py` raises for a lifecycle spec with neither
a fixed port nor a ledger entry). It is a one-line width change owned by the
ports files, not by this phase; it landed as
`fleet_ports_shared_phase5_rest_c.py:57` while this phase was in flight.

One harness fix belongs to the same wave: `DnsStub.start()` bound its UDP and
TCP sockets on a port chosen by `free_port()`, and lost the race often enough
to red a live suite roughly one run in ten (`OSError: [Errno 98]` on the TCP
half, after the UDP half had bound). It now retries with a freshly picked port
unless the caller named one explicitly. That failure had been masking a real
test bug underneath it — `test_status_zone_labels_the_target_rows_and_defaults_to_empty`
called `lifecycle.start()` twice under one name, which the registry refuses;
the second config is now a `reconfigure()` + `restart()` of the same
instance. `TcpSink` had the same race for the same reason and now owns its
port: constructed without one it picks (and re-picks) its own, so the callers
read `sink.port` instead of passing a `free_port()` result in. A port the
caller *does* pin — the second address of a two-address record, which must
share the first's port — still raises on a collision, because there the
collision is the finding.

Remaining: nothing in this phase. The `00-overview.md` active-phase row reads
IMPLEMENTED; this file stays in Phase 111 §7.4 as a work record, beside the
other recently created phase records (112–115), rather than moving to §7.2.

## Appendix A — resolution sites in `src/`, `client/` and `shared/`

Surveyed 2026-09-05 (the "Was" column, line numbers as of `6b78de61a`);
"Now" is the state after this phase. Every row is enforced by
`tools/ci/check_dns_seam.py`, which fails on any new occurrence of the banned
symbols anywhere outside the three seam files.

| # | Site | Context | Was | Now |
|---|---|---|---|---|
| 1 | `src/net/cms/config.c` | config | fatal on DNS | `no_resolve = 1` + `brix_dns_target_register()`; resolved per worker |
| 2 | `src/net/mirror/http_mirror_config.c` | config | fatal | same, target on the mirror entry |
| 3 | `src/net/mirror/stream_mirror_config.c` | config | fatal | same; failure-driven re-resolve added (W5.2) |
| 4 | `src/core/config/helpers.c` | config | fatal; believed caller-less | kept, not deleted — `brix_conf_upstream_directive()` calls it for `brix_http_handoff` / `brix_transparent_proxy`; it now parses only and registers a target |
| 5 | `src/net/upstream/directives.c` | config | warn, then per-request blocking | registers a target; the blocking fallback is gone |
| 6 | `src/net/upstream/start.c` | **event loop** | blocking `getaddrinfo` | `brix_dns_target_next()`, round-robin; `NGX_DECLINED` while unresolved |
| 7 | `src/net/proxy/connect_upstream.c` | **event loop** | blocking | async `brix_dns_resolve()` under the block's policy |
| 8 | `src/protocols/webdav/proxy_pool.c` | admin API (event loop) | `ngx_parse_url` resolved inline | `no_resolve = 1`, then async `brix_dns_resolve()`; entry enters the SHM table `resolving` |
| 9 | `src/observability/pmark/mapping.c` | config/runtime | blocking | async `brix_dns_resolve()` from a cycle-pool request |
| 10 | `src/net/manager/health_check.c` | health check | blocking, no cache | async `brix_dns_resolve()` |
| 11 | `src/fs/cache/origin_connection.c` | thread pool | blocking | `brix_dns_resolve_sync()`, every answer tried |
| 12 | `src/tpc/outbound/connect.c` | thread pool | blocking | `brix_dns_resolve_sync()`; per-candidate SSRF check kept |
| 13 | `src/protocols/root/connection/netconnect.h` | header helper | blocking | resolves through the driver: async on the loop, `_sync` on a thread |
| 14 | `src/fs/backend/gsiftp/gftp_control.c` | thread pool | blocking | `brix_dns_resolve_sync()` under the export's policy |
| 15 | `src/fs/backend/gsiftp/gftp_data.c` | thread pool, literal peer | blocking | `brix_dns_parse_literal()` — a PASV peer is numeric by protocol, so no resolver is involved and no waiver is needed |
| 16 | `src/protocols/cvmfs/origin_probe.c` | thread pool | blocking | `brix_dns_resolve_sync()` |
| 17 | `src/protocols/cvmfs/swarm_gossip.c` | thread pool | blocking | `brix_dns_resolve_sync()` |
| 18 | `src/protocols/webdav/tpc_thread.c`, `tpc_curl_setup.c` | TPC thread pool | libcurl resolved for itself | addresses pinned with `CURLOPT_RESOLVE` via `curl_pin.c`; `CURLOPT_FOLLOWLOCATION` banned tree-wide |
| 19 | `src/core/compat/net_target_dns.c` | thread-only checkers | blocking by contract | the driver's `_sync` flavour + `brix_dns_cache_probe()` for the loop-side probe |

Added by this phase, beyond the 2026-09-05 survey:

| Site | Was | Now |
|---|---|---|
| XrdAcc `h` rules, protbind hostname templates, `host` auth, TPC origin id | inline PTR on the event loop | `brix_dns_reverse_cached()` against the address-keyed cache, warmed by the accept/login prefetch |
| `client/` and `shared/` (cvmfs client, diag tools, `client/lib/net/sock.c`) | libc per call | one seam, `client/lib/net/resolve.c`, with a bounded cache |

Sites 6 and 7 were the two event-loop violations; sites 1–4 were the
start-time failures the operator requirement targeted. All six are closed.
