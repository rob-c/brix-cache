# `tests/lib/` — sourced helper libraries for `manage_test_servers.sh`

Phase-38 split of the 1868-line `tests/manage_test_servers.sh` monolith. The main
script keeps only the global-config block + the dispatch `case`; every function
definition lives here, grouped by concern and **`source`d** (not executed) by the
main script. Sourced files run in the parent shell, so they share its global
config vars (`TEST_ROOT`, `NGINX_*`, `REF_*`, …); function-definition order across
the libs is irrelevant since all are sourced before the dispatch runs.

Behavior-identical refactor — verified end-to-end (`force-stop`→`start-all`→tests
pass→`stop`). See [docs/refactor/phase-38-file-size-unix-modularity.md](../../docs/refactor/phase-38-file-size-unix-modularity.md).

| Lib | Responsibility |
|---|---|
| `util.sh` | Generic helpers: `usage`, `have_cmd`, `find_xrd_sec_lib`, `find_xrd_library`, `pids_on_port`, `kill_pid_list`, `wait_ready_xrdfs`. |
| `pki.sh` | `regenerate_pki` (CA/cert/proxy/VOMS) + `substitute_config` (nginx.conf templating). |
| `nginx.sh` | nginx lifecycle: `start_nginx`/`stop_nginx`/`force_stop_nginx`, `start_dedicated_nginx`, `start_ha_nginx`/`stop_haproxy`, `status_nginx`. |
| `refxrootd.sh` | Reference XRootD: `write_*_ref_cfg`, `start_extra_ref_{gsi,anon}`, `start_root_tpc_ref`, `start_pss_bridge_ref`, `start_ref`/`stop_ref`/`force_stop_ref`, `status_ref`. |
| `xrdhttp.sh` | XrdHttp reference server: `start_xrdhttp`/`stop_xrdhttp`/`force_stop_xrdhttp`/`status_xrdhttp`. |
| `dedicated.sh` | The dedicated-instance + mesh orchestration: `start_all_dedicated`/`stop_all_dedicated`, `start_cms_mesh`/`stop_cms_mesh`, `start_krb5_tier`/`stop_krb5_tier`. |
