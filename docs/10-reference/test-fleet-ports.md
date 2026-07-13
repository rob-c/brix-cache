# Test-fleet ports registry

**Source of truth:** [`tests/settings.py`](../../tests/settings.py) — every
constant below is env-overridable (`TEST_<NAME>`). Secondary allocators:
[`tests/cms_mesh_lib.py`](../../tests/cms_mesh_lib.py) (21610–21749),
[`tests/hybrid_mesh_lib.py`](../../tests/hybrid_mesh_lib.py) (11300–11330),
`tests/lib/dedicated.sh` (launch orchestration), `tests/run_cvmfs_*.sh`
(ad-hoc 12831–12904). `tools/ci/check_ports_doc.sh` fails CI when a
settings.py port constant is missing from this page.

First stop when a test fails with a connection error: find the port here,
then `ss -tlnp | grep <port>` to see whether that instance is actually up
(`tests/manage_test_servers.sh start-all` brings up the fleet).

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

## IPv6 tier (all on `[::1]`, skipped when IPv6 unavailable)

| Port | Constant | Protocol |
|---|---|---|
| 11240 | IPV6_STREAM_PORT | root |
| 11241 / 11242 / 11247 | IPV6_MGR_PORT / IPV6_MGR_CMS_PORT / IPV6_MGR_HTTP_PORT | manager + CMS + dashboard |
| 11243 | IPV6_WEBDAV_PORT | davs |
| 11244 | IPV6_S3_PORT | s3 |
| 11245 / 11246 | IPV6_UPSTREAM_PORT / IPV6_PROXY_PORT | davs origin + proxy |

## Fixed bands outside settings.py

| Band | Owner | What |
|---|---|---|
| 21610–21749 | `tests/cms_mesh_lib.py` | 18 self-contained CMS mesh topologies (real xrootd ↔ nginx interop: managers, pools, write-through pairs, failover, tri-protocol) |
| 21900–21959 | `tests/lib/tpc_fwd.sh` + `tests/run_tpc_fwd_{webdav,root}.sh` | TPC credential-forwarding suite (proves a user's GSI proxy / WLCG token is delegated through a third-party COPY so the SOURCE authenticates the end user). WebDAV flavor 21900–21929, native root:// flavor 21930–21959; each driver allocates a monotonic source/dest port pair per cell from its base (`FWD_PORT_BASE`). Reuses the OIDC discovery server on 21999. Self-contained, non-persistent; per-cell pidfile-scoped teardown; `fuser -k` cleanup. Disjoint from the normal-access forwarding matrix (21960–21999) |
| 11300–11330 | `tests/hybrid_mesh_lib.py` | 2-tier hybrid mesh: tier-1 nginx redirector + S3/WebDAV front doors → tier-2 xrootd hierarchy (env-overridable `HYBRID_*_PORT`) |
| 12831–12904 | `tests/run_cvmfs_*.sh` | ad-hoc cvmfs suite ports (reverse/select/holdopen/keepalive/upstream-metrics/scvmfs), fixed per script, non-persistent |
| 21960–21999 | `tests/lib/fwd_matrix.sh` + `tests/run_fwd_{brix_xrootd,xrootd_brix,brix_brix}.sh` | credential-forwarding matrix suite. Each driver allocates a monotonic pair of front/backend ports per cell from its base (A=21960, B=21970, C=21980; env `FWD_PORT_BASE`). Self-contained, non-persistent; per-cell pidfile-scoped teardown. Reserved contiguous block, disjoint from all above |
