# Developer & Contributor Guide for k8s-tests

This document is for developers who want to modify, extend, or debug the Kubernetes testing infrastructure.

## 1. Directory Architecture

The framework is designed to be modular. If you want to change a specific part, here is where to look:

| Component | Location | Responsibility |
|---|---|---|
| **CLI Entrypoint** | `xrd-k8s` | The main tool users interact with. It delegates to scripts. |
| **Logic Scripts** | `scripts/` | Bash scripts that handle cluster, build, and deploy logic. |
| **Server Helm** | `server-helm/` | Templates for the `nginx-xrootd` server nodes. Edit this to change `nginx.conf` structure. |
| **Infra Helm** | `test-infra-helm/` | Templates for cert-manager, PKI, and network policies. |
| **Dockerfiles** | `Dockerfiles/` | Build definitions for RPMs and all container images. |
| **PKI Logic** | `pki-scripts/` | Python and Bash scripts for CA, VOMS, and JWT key generation. |
| **Test Logic** | `test-runner/` | The Python `pytest` environment and result aggregator. |
| **Raw Manifests** | `k8s-manifests/` | Pre-baked YAML for specialized environments like the `lab`. |

---

## 2. Common Development Tasks

### How to add a new nginx directive to the test cluster
1.  Open `server-helm/templates/configmap.yaml`.
2.  Add your directive to the `nginx.conf` data block.
3.  If it needs to be configurable, add a variable to `server-helm/values.yaml` and reference it in the template using `{{ .Values.your_variable }}`.
4.  Redeploy using `./xrd-k8s deploy servers`.

### How to add a new test case
1.  Add your Python test file to the `tests/` directory at the project root (not inside `k8s-tests`).
2.  The `test-runner` automatically picks up files from the root `tests/` directory when it runs in K8s.
3.  To run just your new test in the cluster:
    ```bash
    ./xrd-k8s test -- --test-patterns your_new_test.py
    ```

### How to debug a failing build
-   Check the RPM builder logs:
    ```bash
    docker build -t test-build -f k8s-tests/Dockerfiles/rpm-builder/Dockerfile .
    ```
-   The RPM build happens inside the container using `rpmbuild`. If it fails, the error usually relates to missing dependencies in the `spec` file or compilation errors in the C code.

---

## 3. The Test Runner (`test-runner/`)

The test runner is a specialized pod that executes `pytest`. 
-   **Discovery**: It uses `run_tests.py` to find server IPs via K8s DNS (e.g., `svc-nginx-data.xrootd-lab.svc.cluster.local`).
-   **Aggregation**: After tests finish, `aggregate_results.py` merges XML reports into a single JSON summary.
-   **Custom Pytest Args**: You can pass any `pytest` argument through the CLI:
    ```bash
    ./xrd-k8s test --extra-args "-k test_my_feature -vv"
    ```

---

## 4. PKI and Security Testing
The `test-infra-helm` chart sets up a restricted environment.
-   **Network Policies**: By default, pods cannot talk to each other unless explicitly allowed in `test-infra-helm/templates/network-policy.yaml`.
-   **Certs**: `cert-manager` is used to issue certificates. If you need to test certificate rotation, you can delete the K8s secrets, and cert-manager will recreate them.

---

## 5. Coding Standards
-   **Scripts**: Use `set -euo pipefail` in all Bash scripts.
-   **Templates**: Keep Helm templates readable. Use `_helpers.tpl` for complex logic.
-   **Images**: Always use AlmaLinux 9 as the base to ensure consistency with production HEP environments.
