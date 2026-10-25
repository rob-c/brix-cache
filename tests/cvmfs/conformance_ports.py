"""Pure CVMFS port catalogue shared by the consumer and the global ledger."""

BLOCK_WIDTH = 20
MATRIX_WIDTH = 48
CANONICAL_ORDER = (
    "srv_gate", "srv_manifest", "srv_cas", "srv_http", "srv_proxy", "srv_geo",
    "srv_resilience", "srv_config", "srv_verify", "srv_authz",
    "fuse_cache", "fuse_catalog", "fuse_manifest_parse", "fuse_posix", "fuse_read",
    "fuse_refresh_failover", "fuse_trust", "fuse_whitelist", "fuse_pin",
    "srv_bundle", "srv_dict", "srv_scvmfs_x509", "srv_scvmfs_voms", "srv_stratum0",
    "srv_s0_scvmfs", "srv_s0_quickstart", "srv_smoke",
    "srv_ingest", "srv_ingest_oracle",
)
CONFORMANCE_WIDTH = len(CANONICAL_ORDER) * BLOCK_WIDTH + MATRIX_WIDTH
