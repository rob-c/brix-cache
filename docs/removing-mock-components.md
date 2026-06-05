# Removing Mock Components from Test Infrastructure

Status: implemented.

The manager-mode and upstream wait tests no longer start Python socket
simulators. The affected scenarios now use real `nginx-xrootd` instances:
CMS-server-only listeners, child managers, parent CMS managers, and data
servers that register through the CMS protocol.

## What Changed

| Former mock | Replacement |
|---|---|
| `tests/test_manager_mode.py` CMS select server | Real child manager asks a real parent CMS server; one registered data server produces `kYR_select`. |
| `tests/test_manager_mode.py` CMS try server | Real parent CMS server has two registered data servers and returns `kYR_try`. |
| `tests/test_a_upstream_redirect.py` silent CMS stub | Real CMS-server-only nginx instance on the wait CMS port; no matching `/data` registration, so backend locate requests time out naturally. |
| `tests/test_manager_mode.py` kYR_gone data-server socket | Real data-server nginx instances register path tokens; deleting the exact registered directory sends `kYR_gone`. |
| Multi-worker CMS listener | Real CMS-server-only nginx instance; tests count established local CMS connections. |

## Supporting Product Hooks

The test-suite removal required real product behavior that the mocks had been
standing in for:

- CMS server handles incoming `CMS_RR_LOCATE` and replies with `kYR_select` or
  `kYR_try` using the shared manager registry.
- Manager registry exposes ordered multi-match selection for `kYR_try`.
- Data-server namespace removal sends `kYR_gone` to its CMS manager after a
  successful `kXR_rm` or `kXR_rmdir`.

## Test Infrastructure

New live-server configs:

- `tests/configs/nginx_cms_server.conf`
- `tests/configs/nginx_cluster_parent_lookup.conf`

Updated orchestration in `tests/manage_test_servers.sh` starts:

- upstream wait CMS server on `12128`
- multi-worker CMS server on `11141`
- select parent CMS plus real data server on `11149` / `14410`
- try parent CMS plus two real data servers on `11158` / `14411` / `14412`
- escalation parent CMS plus real leaf data server on `11162` / `11163`
- isolated kYR_gone redirector/CMS/data-server fleet on `14403` / `14404` /
  `14400`-`14402`

## Validation

Run these from the repository root:

```bash
python3 -m py_compile tests/test_manager_mode.py tests/test_a_upstream_redirect.py tests/settings.py
bash -n tests/manage_test_servers.sh
make -C /tmp/nginx-1.28.3 -j$(nproc)
PYTHONPATH=tests pytest tests/test_manager_mode.py -v
PYTHONPATH=tests pytest tests/test_a_upstream_redirect.py -v
```

The final two pytest commands require permission to bind the local nginx/xrootd
test ports.
