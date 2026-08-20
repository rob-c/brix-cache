# Test-fleet ports registry

**Source of truth:** [`tests/fleet_ports.py`](../../tests/fleet_ports.py), backed
by the port ladder, packs
all central allocations into 1,151 contiguous lane-relative slots. Set
`TEST_PORT_START`; the tables below retain the **original development ports**
only as provenance. The named constants live in
[`tests/settings.py`](../../tests/settings.py). Secondary allocators:
[`tests/cms_mesh_lib.py`](../../tests/cms_mesh_lib.py) (21610–21749),
[`tests/hybrid_mesh_lib.py`](../../tests/hybrid_mesh_lib.py) (11300–11330),
and the declarative fleet catalogue [`tests/fleet_specs.py`](../../tests/fleet_specs.py)
(launch orchestration). `tools/ci/check_ports_doc.sh` fails CI when a
settings.py port constant is missing from this page.

First stop when a test fails with a connection error: find the port here,
then `ss -tlnp | grep <port>` to see whether that instance is actually up
(`python3 -m cmdscripts.manage_test_servers start-all`, run from `tests/`,
brings up the fleet).

## Primary nginx fleet (shared multi-protocol instance)

| Port | Constant | Protocol | Auth | Purpose |
|---|---|---|---|---|
| 11094 | NGINX_ANON_PORT | root | anon | main anonymous entry point (resume ON) |
| 11095 | NGINX_GSI_PORT | root | GSI | x509/proxy-cert auth |
| 11096 | NGINX_GSI_TLS_PORT | roots | GSI+TLS | GSI with TLS encryption |
| 11097 | NGINX_TOKEN_PORT | root | token | WLCG bearer token auth |
| 11118 | NGINX_ANON_RESUME_OFF_PORT | root | anon | anonymous with upload-resume OFF |
| 11119 | NGINX_TOKEN_STRICT_PORT | root | token | zero clock-skew enforcement (`brix_token_clock_skew=0`) |
| 8443 | NGINX_WEBDAV_PORT | davs | none | WebDAV over HTTPS, no client auth |
| 8444 | NGINX_WEBDAV_GSI_TLS_PORT | davs | GSI | WebDAV HTTPS with x509 auth |
| 8080 | NGINX_HTTP_WEBDAV_PORT | http | anon | WebDAV over plain HTTP |
| 9001 | NGINX_S3_PORT | s3 | SigV4/anon | S3 API endpoint |
| 9002 | NGINX_S3_TOKEN_PORT | s3 | token | S3 with bearer-token enforcement (`brix_s3_token=on`) |
| 9100 | NGINX_METRICS_PORT | http | none | Prometheus `/metrics` |

## WLCG token conformance (dedicated enforcing instances)

| Port | Constant | Protocol | Auth | Purpose |
|---|---|---|---|---|
| 11250 | NGINX_TOKEN_MULTIKEY_PORT | root | token | multi-key JWKS (`jwks_multi.json`) + multi-issuer |
| 11251 | NGINX_TOKEN_REGISTRY_PORT | root | token | issuer registry (`scitokens.cfg`) enforcement |
| 8446 | NGINX_WEBDAV_TOKEN_PORT | davs | token | WebDAV bearer-token-only |
| 11115 | NGINX_JWKS_REFRESH_PORT | root | token | JWKS periodic-refresh behavior |

## Reference (stock XRootD) comparison fleet

| Port | Constant | Protocol | Auth | Purpose |
|---|---|---|---|---|
| 11098 | REF_BRIX_PORT | root | anon | stock xrootd baseline (cross-backend tests) |
| 11099 | REF_BRIX_GSI_PORT | root | GSI | stock xrootd GSI (separate data dir) |
| 11100 | REF_BRIX_GSI_SHARED_PORT | root | GSI | stock xrootd GSI on the shared data root |
| 11112 | XRDHTTP_ROOT_PORT | root | anon | XrdHttp reference daemon, root:// side |
| 11113 | XRDHTTP_HTTP_PORT / XRDHTTP_HTTPS_PORT | http(s) | anon | XrdHttp reference HTTP(S) (davs conformance) |
| 12988 | XRDHTTP_DIGEST_PORT | http | anon | XrdHttp cleartext + RFC-3230 digest |

## Kerberos tier (skipped cleanly without MIT KDC tooling)

| Port | Constant | Protocol | Auth | Purpose |
|---|---|---|---|---|
| 11116 | NGINX_KRB5_PORT | root | krb5 | dedicated krb5 instance (isolated from main fleet) |
| 11117 | KRB5_KDC_PORT | kdc | — | MIT KDC listener (`kdc_helpers.py`) |

## CRL / PKI validation

| Port | Constant | Protocol | Auth | Purpose |
|---|---|---|---|---|
| 11104 | CRL_PORT | davs | x509 | CRL-file validation |
| 11105 | WEBDAV_CRL_PORT | davs | x509 | WebDAV with CRL checking |
| 11106 | CRL_DIR_PORT | davs | x509 | CRL-directory validation |
| 11107 | WEBDAV_DIR_PORT | davs | x509 | WebDAV dir listing with CRL |
| 11108 | CRL_RELOAD_PORT | davs | x509 | reloadable CRL (`TEST_CRL_RELOAD_INTERVAL`) |
| 11109 | CRL_RELOAD_HTTP_PORT | http | none | HTTP stub serving the CRL for reload tests |

## TPC & SSRF policy

| Port | Constant | Protocol | Auth | Purpose |
|---|---|---|---|---|
| 11110 | ROOT_TPC_NGINX_PORT | root | anon | native-TPC nginx node |
| 11111 | ROOT_TPC_REF_PORT | root | anon | native-TPC stock-xrootd peer |
| 11180 | TPC_SSRF_DEFAULT_PORT | root | anon | SSRF default policy |
| 11181 | TPC_SSRF_ALLOW_LOCAL_PORT | root | anon | SSRF allow-local policy |
| 11182 | TPC_SSRF_DENY_PRIVATE_PORT | root | anon | SSRF deny-private policy |
| 11218 | TPC_SRC_GUARD_PORT | root | anon | TPC source-host naming allowlist (SSRF Layer 2) |
| 11219 | WEBDAV_TPC_SRC_GUARD_PORT | http | none | WebDAV COPY source-host naming allowlist (SSRF Layer 2) |
| 18450 | WEBDAV_TPC_SOURCE_REQUIRED_PORT | davs | cert | HTTP-TPC source, client cert required |
| 18451 | WEBDAV_TPC_SOURCE_OPEN_PORT | davs | none | HTTP-TPC source, open |
| 18452 | WEBDAV_TPC_DEST_CAFILE_PORT | davs | — | HTTP-TPC dest, cafile validation |
| 18453 | WEBDAV_TPC_DEST_CADIR_PORT | davs | — | HTTP-TPC dest, cadir validation |
| 18454 | WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT | davs | — | HTTP-TPC dest without service cert |
| 18455 | WEBDAV_TPC_DEST_DISABLED_PORT | davs | — | HTTP-TPC dest with TPC disabled |
| 18456 | WEBDAV_TPC_DEST_READONLY_PORT | davs | — | HTTP-TPC dest read-only |

## Upstream-proxy tier (nginx proxy ↔ real xrootd backends)

| nginx | backend | Constants | Scenario |
|---|---|---|---|
| 11120 | 12120 | UPSTREAM_REDIRECT_NGINX_PORT / UPSTREAM_REDIRECT_BACKEND_PORT | kXR_redirect passthrough |
| 11121 | 12121 | UPSTREAM_WAIT_NGINX_PORT / UPSTREAM_WAIT_BACKEND_PORT | kXR_wait handling |
| 11122 | 12122 | UPSTREAM_WAITRESP_NGINX_PORT / UPSTREAM_WAITRESP_BACKEND_PORT | kXR_waitresp handling |
| 11123 | 12123 | UPSTREAM_ERROR_NGINX_PORT / UPSTREAM_ERROR_BACKEND_PORT | upstream error sequences |
| 11124 | 12124 | UPSTREAM_AUTH_NGINX_PORT / UPSTREAM_AUTH_BACKEND_PORT | token-auth forwarding |
| 11125 | 12125 | UPSTREAM_AUTH_NOFILE_NGINX_PORT / UPSTREAM_AUTH_NOFILE_BACKEND_PORT | token auth, no authfile |
| 11126 | 12126 | UPSTREAM_GOTORLS_NOTLS_NGINX_PORT / UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT | gotoTLS-without-TLS negative |
| 11137 | — | REAL_REDIRECT_NGINX_PORT | proxy to a real redirecting xrootd |

## Protocol stub backends (deterministic wire sequences)

Python socket listeners emitting scripted XRootD responses; each has an
nginx proxy in front.

| nginx | stub | Constants | Emits |
|---|---|---|---|
| 11130 | 13120 | STUB_REDIRECT_NGINX_PORT / STUB_REDIRECT_BACKEND_PORT | kXR_redirect |
| 11131 | 13121 | STUB_WAIT_NGINX_PORT / STUB_WAIT_BACKEND_PORT | kXR_wait |
| 11132 | 13122 | STUB_WAITRESP_NGINX_PORT / STUB_WAITRESP_BACKEND_PORT | kXR_waitresp |
| 11133 | 13123 | STUB_ERROR_NGINX_PORT / STUB_ERROR_BACKEND_PORT | kXR_error |
| 11134 | 13124 | STUB_AUTH_NGINX_PORT / STUB_AUTH_BACKEND_PORT | kXR_authmore |
| 11135 | 13125 | STUB_AUTH_NOFILE_NGINX_PORT / STUB_AUTH_NOFILE_BACKEND_PORT | kXR_authmore (nofile) |
| 11136 | 13126 | STUB_GOTORLS_NGINX_PORT / STUB_GOTORLS_BACKEND_PORT | kXR_gotoTLS |

## Cluster / CMS topologies

| Port | Constant | Role |
|---|---|---|
| 11160 | CLUSTER_REDIR_PORT | basic cluster redirector |
| 11161 | CLUSTER_CMS_PORT | basic cluster CMS |
| 11162 | CLUSTER_DS_PORT | basic cluster data server |
| 11163 | CHAOS_TIER3_PORT | chaos mesh tier-3 origin |
| 11164 | CHAOS_TIER2_PORT | chaos mesh tier-2 cache |
| 11165 | CHAOS_TIER1_PORT | chaos mesh tier-1 proxy |
| 11166 | CHAOS_DISCOVERY_REDIR_PORT | chaos discovery redirector |
| 11167 | CHAOS_DISCOVERY_CMS_PORT | chaos discovery CMS manager |
| 11168 | CHAOS_DISCOVERY_DS_PORT | chaos discovery data server |
| 11169 / 11170 / 11171 | CLUSTER_MP_REDIR_PORT / CLUSTER_MP_DS_PORT / CLUSTER_MP_CMS_PORT | multi-path cluster |
| 11172 / 11173 / 11174 / 11175 | CLUSTER_MS_REDIR_PORT / CLUSTER_MS_DS1_PORT / CLUSTER_MS_DS2_PORT / CLUSTER_MS_CMS_PORT | multi-server cluster |
| 11176 / 11177 / 11178 | CLUSTER_MW_PORT / CLUSTER_MW_CMS_PORT / CLUSTER_MW_REDIR_PORT | multi-worker cluster |
| 11185 / 11186 | CLUSTER_3T_META_PORT / CLUSTER_3T_META_CMS_PORT | 3-tier meta redirector |
| 11187 / 11188 / 11189 | CLUSTER_3T_SUB_PORT / CLUSTER_3T_SUB_CMS_PORT / CLUSTER_3T_SELF_PORT | 3-tier intermediate manager |
| 11190 | CLUSTER_3T_LEAF_PORT | 3-tier leaf data server |
| 11194 / 12601 | CLUSTER_SELECT_PORT / CLUSTER_SELECT_CMS_PORT | kYR_select parent lookup |
| 11195 / 11196 / 12608 | CLUSTER_SLOTS_REDIR_PORT / CLUSTER_SLOTS_METRICS_PORT / CLUSTER_SLOTS_CMS_PORT | full-registry (slots) cluster |
| 12602–12605 | CLUSTER_SLOTS_DS1_PORT / CLUSTER_SLOTS_DS2_PORT / CLUSTER_SLOTS_DS3_PORT / CLUSTER_SLOTS_DS4_PORT | slots cluster data servers |
| 11197 / 12606 | CLUSTER_TRY_PORT / CLUSTER_TRY_CMS_PORT | kYR_try parent lookup |
| 11198 / 11199 / 12607 | CLUSTER_ESC_SUB_PORT / CLUSTER_ESC_LEAF_PORT / CLUSTER_ESC_CMS_PORT | kYR_esc escalation cluster |
| 12399 / 12400 / 12500 | CMS_TEST_REDIR_PORT / CMS_TEST_CMS_PORT / CMS_TEST_NGINX_PORT | CMS heartbeat test trio |
| 29000 | CLUSTER_SELECT_REDIRECT_PORT | phantom DS advertised by select responses |
| 29001 / 29002 | CLUSTER_TRY_FIRST_PORT / CLUSTER_TRY_SECOND_PORT | phantom DSs advertised by try responses |
| 29010 / 29011 / 29012 | CLUSTER_GONE_DS_PORT / CLUSTER_GONE_DS_PORT_A / CLUSTER_GONE_DS_PORT_B | phantom DSs for kYR_gone (no listener) |

## Feature-dedicated instances

| Port | Constant | Protocol | Purpose |
|---|---|---|---|
| 11101 | MANAGER_PORT | root | manager-mode nginx |
| 11102 | READONLY_PORT | root | read-only instance |
| 11103 | VO_PORT | root | VO ACL enforcement |
| 8445 | NGINX_DASHBOARD_PORT | http | dashboard/admin API |
| 11114 | AUTHDB_PORT | root | authdb permission rules |
| 11183 / 11184 | S3_PRESIGNED_PORT / S3_PRESIGNED_STS_PORT | s3 | presigned URLs (/+STS) |
| 11191 / 11192 | SECURITY_LEVEL_STANDARD_PORT / SECURITY_LEVEL_PEDANTIC_PORT | root | signing security levels |
| 11193 / 12501 | PROXY_NGINX_PORT / PROXY_UPSTREAM_PORT | root | proxy mode + upstream |
| 11200 | CACHE_ONLY_PORT | root | read-through cache node |
| 11201 / 11202 | WT_SYNC_PORT / WT_ASYNC_PORT | root | write-through sync/async |
| 11203 / 19999 | PROXY_DEAD_NGINX_PORT / PROXY_DEAD_UPSTREAM_PORT | root | dead-upstream negative test (19999 never listens) |
| 11204 / 11205 | PREPARE_CMD_PORT / PREPARE_NOCMD_PORT | root | kXR_prepare with/without staging command |
| 11206 / 11207 | META_ONLY_PORT / SUPERVISOR_PORT | root | protocol capability flags |
| 11208 / 11209 | VIRTUAL_REDIR_PORT / COLLAPSE_REDIR_PORT | root | static manager_map / collapse redirect cache |
| 11210–11212 | HA_HAPROXY_PORT / HA_NGINX1_PORT / HA_NGINX2_PORT | root | HA failover (haproxy VIP + two nodes) |
| 11213 | PROXY_PURE_NGINX_PROXY_PORT | root | pure nginx→nginx proxy stack |
| 11214 | PROXY_BRIDGE_BRIX_PORT | root | PSS bridge xrootd (proxy matrix) |
| 11215 | CREDENTIAL_BRIDGE_PORT | root | GSI proxy → bearer-token translator |
| 11216 / 11217 | READONLY_HTTP_DAV_PORT / READONLY_HTTP_S3_PORT | davs/s3 | read-only multi-protocol node |
| 18444 / 18445 | WEBDAV_AUTH_CACHE_MANUAL_PORT / WEBDAV_AUTH_CACHE_NGINX_PORT | davs | auth-cache behavior |
| 18457 | NGINX_HTTP_CACHE_PORT | http | HTTP read-through cache |
| 18458 | NGINX_WEBDAV_VOMS_PORT | davs | VOMS attribute extraction |
| 12980 | OPEN_FLAGS_LIFECYCLE_NGINX_PORT | root | open-flags lifecycle (migrated dedicated) |
| 13210 | WEBDAV_DELLOCK_PORT | davs | DELETE/lock security (migrated dedicated) |
| 22014 | WEBDAV_UNLOCK_OWNERSHIP_PORT | davs | LOCK/UNLOCK xattr-backed locks |
| 22017 | S3_MPU_PORT | s3 | multipart upload-part-copy traversal |
| 12960 / 12961 | COMPRESS_WEBDAV_PORT / COMPRESS_S3_PORT | davs/s3 | dedicated compression instance (`nginx_compress.conf`; tests attach and seed `data-compress`) |
| 21196 / 21198 / 21199 | ZIP_ROOT_PORT / ZIP_WEBDAV_PORT / ZIP_S3_PORT | root/davs/s3 | ZIP virtual-file conformance endpoints |
| 21200 | INTEROP_OUR_PORT | root | "our server" half of the official-interop conformance pair (`nginx_interop.conf`; `official_interop_lib.start_pair` attaches) |
| 21201 | INTEROP_OFF_PORT | root | stock-xrootd "official" half of the interop pair (exports `data-interop-off`) |

## IPv6 tier (all on `[::1]`, skipped when IPv6 unavailable)

| Port | Constant | Protocol |
|---|---|---|
| 11240 | IPV6_STREAM_PORT | root |
| 11241 / 11242 / 11247 | IPV6_MGR_PORT / IPV6_MGR_CMS_PORT / IPV6_MGR_HTTP_PORT | manager + CMS + dashboard |
| 11243 | IPV6_WEBDAV_PORT | davs |
| 11244 | IPV6_S3_PORT | s3 |
| 11245 / 11246 | IPV6_UPSTREAM_PORT / IPV6_PROXY_PORT | davs origin + proxy |

## Registry-managed Python mock singletons (mocks band 32000+)

Former in-process `ThreadingHTTPServer` stubs, now standalone `proc` fleet specs on
fixed ports (`tests/lib/*_server.py`, registered by `fleet_specs`) so every test reaches
ONE declared mock instead of spawning its own. The band sits BELOW the OS ephemeral-port
floor (32768) so a client socket can never transiently steal a mock's fixed listen.

| Port | Constant | Purpose |
|---|---|---|
| 32001 | GUARD_STUB_PORT | Hit-counter + mutable reply-status guard backend (`test_xrdhttp_guard.py`, `test_arc_guard.py`); `/__introspect` + `/__reset` control API |
| 32002 | STATIC_ORIGIN_PORT | Stateless `ORIGIN-OK` backend for admin-API URL-validation coverage (`test_phase23_admin_api.py`); no introspection |
| 32003 | MIRROR_SHADOW_PORT | Hit-recording mirror shadow upstream (`test_phase24_mirror.py`): records path/headers/method + write bodies behind a control API |
| 32004 | INTROSPECT_IDP_PORT | Mock RFC 7662 token-introspection endpoint (`test_phase21_proxy_filter.py`): `revoked` in token → active:false, else active:true |

## Launcher-level overrides (not fixed ports)

| Constant | Default | What |
|---|---|---|
| TEST_PORT_START | `10000` | Number immediately below the first port in the 1,151-slot central ladder. A base of 10000 allocates 10001..11151; the next lane must start at 11151 or later. |

## Fixed bands outside settings.py

| Band | Owner | What |
|---|---|---|
| 21610–21749 | `tests/cms_mesh_lib.py` | 18 self-contained CMS mesh topologies (real xrootd ↔ nginx interop: managers, pools, write-through pairs, failover, tri-protocol) |
| 21900–21959 | `tests/lib/tpc_fwd.sh` + `tests/run_tpc_fwd_{webdav,root}.sh` | TPC credential-forwarding suite (proves a user's GSI proxy / WLCG token is delegated through a third-party COPY so the SOURCE authenticates the end user). WebDAV flavor 21900–21929, native root:// flavor 21930–21959; each driver allocates a monotonic source/dest port pair per cell from its base (`FWD_PORT_BASE`). Reuses the OIDC discovery server on 21999. Self-contained, non-persistent; per-cell pidfile-scoped teardown; `fuser -k` cleanup. Disjoint from the normal-access forwarding matrix (21960–21999) |
| 11300–11330 | `tests/hybrid_mesh_lib.py` | 2-tier hybrid mesh: tier-1 nginx redirector + S3/WebDAV front doors → tier-2 xrootd hierarchy (env-overridable `HYBRID_*_PORT`) |
| 12831–12904 | `tests/run_cvmfs_*.sh` | ad-hoc cvmfs suite ports (reverse/select/holdopen/keepalive/upstream-metrics/scvmfs), fixed per script, non-persistent |
| 13100–13727 | `tests/cvmfs/conformance_common.py` `PORT_BLOCKS` | cvmfs conformance corpus: one 20-port block per test file (mock origins base+0..9, nginx base+10..19), then the `matrix_port()` sub-range (48 ports) just past the blocks. Canonical bases only — the whole map is tiled by a per-session offset (lock-port claim) so concurrent sessions never collide. Newest blocks: `srv_scvmfs_x509` 13520, `srv_scvmfs_voms` 13540, `srv_stratum0` 13560, `srv_s0_scvmfs` 13580 (phase-96 S13/S14), `srv_s0_quickstart` 13600 (the shipped-binary runbook lane behind `docs/05-operations/cvmfs-stratum0.md`), `srv_smoke` 13620, `srv_ingest` 13640 (phase-104 D8.4 `ingest image` mock registry), `srv_ingest_oracle` 13660 (phase-104 D10 composition). Adding a block entry grows the tile span — safe for new sessions, never rebases a running one |
| 21960–21999 | `tests/lib/fwd_matrix.sh` + `tests/run_fwd_{brix_xrootd,xrootd_brix,brix_brix}.sh` | credential-forwarding matrix suite. Each driver allocates a monotonic pair of front/backend ports per cell from its base (A=21960, B=21970, C=21980; env `FWD_PORT_BASE`). Self-contained, non-persistent; per-cell pidfile-scoped teardown. Reserved contiguous block, disjoint from all above |
| 14100–14119 | `tests/oci/mirror_lane.py` | phase-104 D0–D3 OCI pull-through mirror lanes: mock registries at base+0..9, brix nginx fronts at base+10..19 — `classify` 14100/14110, `authdance` 14101–14103/14111 (evil realm and CDN twin bind second/third loopback addresses; 14102 on the third address doubles as the D15.11 off-domain token listener — the same mock process, a second bind, which is what makes an allowlisted realm testable), `cachepolicy` 14104/14112. Non-persistent lifecycle instances, one cache store per test |
| 14120–14121 | `tests/test_oci_mirror_podman_pull.py` | phase-104 D3.3 podman oracle lane: mock registry 14120, brix nginx front 14121 (one at a time — every mirror fixture is function-scoped so "cold" means cold). Needs podman specifically (docker cannot be told to trust a cleartext registry per invocation); the opt-in DockerHub leg reuses 14121 with `oci_mirror_live.conf`. Non-persistent lifecycle instances |
| 14150–14157 | `tests/test_oci_registry_push.py`, `tests/test_oci_registry_referrers.py`, `tests/test_oci_registry_gc.py`, `tests/test_oci_registry_gc_background.py` | phase-104 D4 local registry push surface: anonymous front 14150, the token-authenticating front 14151, the capped-blob front 14152, the read-only front 14153; the D15.1 referrers lane brings up its own front at 14154, and the D15.3 `brixoci gc` lane a further one at 14155 (it pushes through the registry so the store it sweeps is a real one). The D15.5 background-sweep lane adds two more: 14156 for the timer-armed store, 14157 for the grace-window leg, which needs a second store because its cadence and grace differ. No mocks — this surface IS the registry. Non-persistent lifecycle instances, one store per test |
| 14140–14145 | `tests/test_oci_brixoci_copy.py` | phase-104 `oci_registry` mock sextet for the `brixoci` CLI: plain+push 14140, basic-auth 14141, evil-realm 14142, blob-redirect 14143, CDN twin 14144 (binds a second loopback host), and the D15.2 IPv6-literal front at 14145 (the one mock bound to `[::1]`, so it claims the port on a different address family). Non-persistent, module-scoped fixture |
| 14160–14162 | `tests/test_rpm_mirror_dnf.py` | phase-104 D11 RPM/dnf pull-through mirror: mirror 14160 (stock nginx rendering `deploy/rpm-mirror/nginx.conf.example`), `python3 -m http.server` upstream 14161, second mirror 14162 with the `repomd.xml` TTL cut to 1 s so expiry is observable inside a test. Non-persistent, module-scoped |
| 14170–14176 | `tests/test_rpm_mirror_native.py` | phase-104 D15.9 native RPM mirror (`brix_rpm_mirror`, the C surface that replaces the D11 config recipe): mock repository origin 14170 (`tests/rpm/mock_repo.py`, with a `/ctl/fault` plane that tampers, 404s, 503s or hangs a chosen path), the canonical front 14171, and 14172 — the same front with `brix_rpm_metadata_ttl 1s` so a repomd refetch is observable inside a test while the digest-named metadata beside it must still be fetched exactly once. The D15.10 warm-prefetch rows bring up a further front at 14176 — the same template with `brix_rpm_prefetch on`, on its own port because its whole assertion is about requests the mirror makes that no client asked for. Non-persistent lifecycle instances, one cache store per test. 14173–14175 are claimed but never bound: the refusal rows (wrong verify mode, cleartext upstream without the opt-in) and the shipped `deploy/rpm-mirror/brix.conf.example` are run through `nginx -t` only |
| 14200–14212 | `tests/test_oci_compose_secure.py` | phase-104 D14 composition lane: mock upstream registry 14200, the public full-stack front 14201 (mirror + local registry + Stratum-0 from ONE template), the consuming site's union front 14202, and the gated twin 14203 — the same template as 14201 with the scvmfs x509 lines added, which is the D14 claim made executable. 14210–14212 are claimed but never bound: the shipped `deploy/oci-mirror/*.conf.example` recipes are rendered onto them and run through `nginx -t` only. Non-persistent, module-scoped `LifecycleHarness` |
