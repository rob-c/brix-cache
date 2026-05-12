# K8s Testing Pipeline for nginx-xrootd

## Architecture Overview

This directory contains infrastructure for building, deploying, and testing nginx-xrootd at scale on Kubernetes (minikube or Kind). It supports:

- **RPM-first delivery**: Build the module as an RPM from `packaging/rpm/nginx-mod-xrootd.spec`, then bake it into container images
- **Multi-node K8s clusters**: Deploy server nodes across multiple worker nodes for realistic load distribution and TPC testing
- **Full PKI stack**: Automated x509 CA, host certificates, proxy certificate generation, VOMS attributes, and CRL publication — managed via cert-manager + custom automation scripts
- **Dynamic JWT key generation (no Keycloak)**: On-demand RSA-2048 keypair generation at test cluster startup. Keys are stored in a Kubernetes Secret/ConfigMap and mounted into server pods via the `xrootd_token_jwks` directive. No persistent OAuth provider required.
- **Network isolation**: Network policies enforce traffic flow restrictions between test profiles
- **Resource governance**: ResourceQuotas and LimitRanges prevent a single profile from consuming all cluster resources
- **Pod Security Standards**: Namespace-level PSS enforcement prevents privileged containers
- **Parallel test execution**: pytest runs inside Kubernetes Jobs with result aggregation via `aggregate_results.py`

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    CI/CD Pipeline                            │
│                                                              │
│  build-rpm → build-images → deploy-dev → run-tests          │
│  (Alma9)      (GHCR push)     (Helm upgrade)   (pytest Job)  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Kubernetes Cluster                         │
│                                                              │
│  ┌──────────────────┐  ┌────────────────┐  ┌───────────────┐ │
│  │ cert-manager     │  │ JWT Key Gen    │  │ Prometheus    │ │
│  │ (CA/ClusterIssuer)│  │ Job (RSA-2048) │  │ ServiceMonitor│ │
│  └──────────────────┘  └────────────────┘  └───────────────┘ │
│           │                │                                    │
│           │          Stores in K8s Secret/ConfigMap            │
│           │                ↓                                   │
│  ┌────────▼────────────────▼───────────────────────────────┐  │
│  │              nginx-xrootd Server Nodes (N replicas)     │  │
│  │  Pod-N-0 :1094 | :1095 | :8443 | :9100                   │  │
│  │  Pod-N-1 :1094 | :1095 | :8443 | :9100                   │  │
│  └──────────────┬──────────────────────────────────────────┘  │
│                 │ Service (ClusterIP)                          │
│                 ▼                                              │
│  ┌─────────────────────────────────────────────────┐          │
│  │              Test Runner Job (pytest)            │          │
│  │         aggregate_results.py → summary.json      │          │
│  └─────────────────────────────────────────────────┘          │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐                           │
│  │ Network     │  │ Resource    │                           │
│  │ Policies    │  │ Quotas      │                           │
│  └─────────────┘  └─────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
k8s-tests/
├── README.md                     # This file — architecture overview
├── Makefile                      # Unified entry point: build, deploy, test, teardown
│
├── .github/workflows/            # CI pipeline (RPM → images → deploy → TEST)
│   └── build.yaml                # Includes post-deploy integration tests
│
├── Dockerfiles/                  # Container images for all components
│   ├── rpm-builder/Dockerfile    # AlmaLinux 9 + mock — builds the RPM
│   ├── server/Dockerfile         # nginx-xrootd server (RPM-installed)
│   ├── client/Dockerfile         # XRootD client tools (xrdcp, xrdfs)
│   └── test-runner/Dockerfile    # pytest + XRootD Python client + aggregate_results.py
│
├── scripts/                      # Utility scripts
│   ├── setup-minikube.sh         # Bootstrap minikube or Kind cluster (auto-detect)
│   └── teardown-cluster.sh       # Clean up namespace and cluster resources
│
├── server-helm/                  # Helm chart for nginx-xrootd server deployment
│   ├── Chart.yaml
│   ├── values.yaml               # Default configuration
│   ├── values.dev.yaml           # Development profile (minikube, 1-3 nodes)
│   ├── values.prod.yaml          # Production profile (multi-node)
│   └── templates/                # Kubernetes manifests
│       ├── _helpers.tpl
│       ├── deployment.yaml       # N replicas based on server.nodeCount
│       ├── service.yaml          # XRootD (headless), WebDAV, Metrics services
│       ├── configmap.yaml        # nginx.conf + module configs (incl. token auth)
│       ├── secret.yaml           # TLS certs, tokens
│       └── pvc.yaml              # Persistent volume for shared data
│
├── test-infra-helm/              # Helm chart for PKI/test infrastructure
│   ├── Chart.yaml
│   ├── values.yaml               # Includes jwtKeys section (no Keycloak)
│   └── templates/
│       ├── _helpers.tpl
│       ├── namespace.yaml        # Namespace with PSS labels (restricted)
│       ├── network-policy.yaml   # Traffic isolation between profiles
│       ├── resource-quota.yaml   # CPU/memory/pod limits per namespace
│       ├── cert-manager-ca.yaml  # CA via cert-manager ClusterIssuer
│       ├── server-certificate.yaml  # Server TLS signed by CA
│       ├── crl.yaml              # CRL distribution point
│       └── jwt-keys.yaml         # JWT key generation Job + Secret/ConfigMap
│
├── k8s-manifests/                # Direct Kubernetes manifests (non-Helm alternative)
│   ├── namespace.yaml            # Test namespaces with PSS labels
│   ├── network-policy.yaml       # Traffic isolation (incl. default-deny)
│   ├── resource-quota.yaml       # Resource limits + PSS labels
│   └── deployment-server.yaml    # Server deployment without Helm
│
├── pki-scripts/                  # PKI automation for K8s environments
│   ├── generate-ca.sh            # Generate root CA (cert-manager compatible CSR)
│   ├── generate-server-cert.sh   # Sign server certificates with CA
│   ├── generate-proxy-certs.sh   # Generate user proxy certificates
│   ├── setup-voms-attributes.sh  # Create VOMS attributes for ACL testing
│   ├── manage-crl.sh             # CRL generation and rotation
│   └── generate-jwt-keys.py      # Dynamic RSA-2048 JWT keypair generator
│
├── test-runner/                  # pytest execution in K8s Jobs
│   ├── Dockerfile                # Container with pytest + XRootD client libraries
│   ├── run_tests.py              # Entry point — discovers endpoints, runs pytest
│   ├── conftest.py               # pytest fixtures for K8s-aware testing
│   ├── aggregate_results.py      # Collect and summarize parallel test results
│   └── values.test.yaml          # Test configuration overlay (URLs, auth mode)
│
└── PLAN.md                       # Architectural plan with phase breakdown
```

## Key Design Decisions

### 1. RPM-First Pipeline
The existing `packaging/rpm/nginx-mod-xrootd.spec` is the single source of truth. CI builds the RPM in an AlmaLinux 9 container, then server Dockerfiles install it on a minimal nginx base image. This ensures parity between local development and K8s deployment.

### 2. cert-manager for PKI
cert-manager's `Certificate` resources automate certificate lifecycle management (renewal, rotation). The CA is established once per namespace via a `ClusterIssuer`. Static fallback secrets exist via `secret.yaml` templates.

### 3. Dynamic JWT Key Generation (No Keycloak)
**This replaced the previous Keycloak-based approach.** On test cluster startup, a Kubernetes Job generates an RSA-2048 keypair using Python's cryptography library:
1. **Key generation**: RSA-2048 private/public key pair created in-memory
2. **JWKS export**: Public key exported as JWKS (JSON Web Key Set) format for nginx-xrootd `xrootd_token_jwks` directive
3. **Secret storage**: Both keys stored in a Kubernetes Secret; public key also exported as ConfigMap
4. **Server pod mounting**: The jwks.json is mounted into server pods at `/etc/nginx/jwks/jwks.json`

**Advantages over Keycloak:**
- No persistent OAuth provider to manage or scale
- Keys are regenerated fresh for every test run — no stale/expired tokens
- Simpler deployment footprint (one Job + Secret vs. StatefulSet + PostgreSQL)
- Fully ephemeral — keys exist only for the duration of the test profile

### 4. Namespace Isolation & Security
Each test profile runs in its own Kubernetes namespace with:
- **Network policies**: Restrict ingress to server ports (1094, 1095, 8443) from test profiles only; default-deny for server pods
- **ResourceQuotas**: Limit CPU/memory/pods per namespace (8/32Gi cpu/mem, 50 pods max)
- **LimitRanges**: Set default container resource boundaries (500m/512Mi limits)
- **Pod Security Standards**: Enforce `restricted` policy — no privileged containers

### 5. Test Result Aggregation
The `aggregate_results.py` script collects pytest-junit XML from parallel Jobs via two modes:
- **Local**: Results stored in shared PVC/emptyDir volume
- **S3**: Results pushed to S3-compatible storage (Minio in CI)

### 6. Cluster Type: Kind vs Minikube

| Factor | Kind | Minikube |
|---|---|---|
| Multi-node setup | `--nodes` flag, native Docker containers | Requires VM addons |
| Port exposure | `extraPortMappings`, direct host mapping | Driver-dependent complexity |
| Disk I/O | Container-level (near-native) | VM overhead |
| TPC testing | Full networking stack available | Single-node focus limits scope |
| Teardown speed | Immediate container removal | VM cleanup required |

The `scripts/setup-minikube.sh` script auto-detects which tool is installed. To force a specific type:

```bash
# Use Kind (recommended for production parity)
k8s-tests/scripts/setup-minikube.sh 3 4 8192 kind

# Use Minikube (faster local iteration)
k8s-tests/scripts/setup-minikube.sh 3 4 8192 minikube
```

## Quick Start — Local Development

```bash
# Prerequisites: docker, kubectl, helm, kind or minikube installed

# 1. Build images locally
make build-images IMAGE_TAG=dev

# 2. Bootstrap cluster (auto-detect Kind vs Minikube, creates 3-node cluster)
make cluster-start CLUSTER_TYPE=minikube NODE_COUNT=2

# 3. Deploy test infrastructure (PKI + cert-manager + JWT key generation)
helm upgrade --install cert-manager jetstack/cert-manager \
    --namespace cert-manager --create-namespace --set crds.enabled=true || true
helm upgrade --install test-infra ./test-infra-helm \
    --namespace k8s-tests-dev --create-namespace

# 4. Deploy nginx-xrootd servers with GSI auth (or token: add --set jwtKeys.jwksJson=...)
helm upgrade --install xrootd-servers ./server-helm \
    --namespace k8s-tests-dev \
    -f ./server-helm/values.dev.yaml \
    --set auth.mode=gsi

# 5. Run tests with result aggregation
make test AUTH_MODE=gsi NAMESPACE=k8s-tests-dev CLUSTER_TYPE=minikube
```

### Token Auth Quick Start (Dynamic JWT Keys)

For token-based authentication testing without Keycloak:

```bash
# Generate pre-signed JWKS file for static deployment
python3 k8s-tests/pki-scripts/generate-jwt-keys.py \
    --mode-jwks --output-jwks=/tmp/jwks.json

# Deploy with JWT key mounted via ConfigMap
helm upgrade --install xrootd-servers ./server-helm \
    --namespace k8s-tests-dev \
    -f ./server-helm/values.dev.yaml \
    --set auth.mode=token \
    --set-file jwtKeys.jwksJson=/tmp/jwks.json

# Run tests with token auth mode
make test AUTH_MODE=token NAMESPACE=k8s-tests-dev CLUSTER_TYPE=minikube
```

### Token Auth Dynamic Job Mode (Recommended)

For automatic JWT key generation at cluster startup:

```bash
# Deploy infra — the jwt-keys.yaml template includes a Helm hook Job
helm upgrade --install test-infra ./test-infra-helm \
    --namespace k8s-tests-dev --create-namespace

# The JWT key generation Job runs automatically as part of test-infra deployment.
# Wait for it to complete:
kubectl wait --for=condition=complete job/jwt-key-generation \
    -n k8s-tests-dev --timeout=120s

# Deploy servers with token auth — they will mount the generated jwks.json
helm upgrade --install xrootd-servers ./server-helm \
    --namespace k8s-tests-dev \
    -f ./server-helm/values.dev.yaml \
    --set auth.mode=token
```

## Test Profiles

| Profile | Nodes | Auth Mode | PKI | Token | Use Case |
|---|---|---|---|---|---|
| `dev` | 1 | none/anonymous | static certs | disabled | Local iteration, fast feedback |
| `dev-gsi` | 2-3 | gsi/x509 | cert-manager CA | disabled | Minikube PKI testing |
| `staging` | 3+ | token/bearer | cert-manager CA | Dynamic JWT | Pre-production validation |
| `perf` | 5+ | any | cert-manager CA | optional | Throughput benchmarking |

## Troubleshooting

| Symptom | Fix |
|---|---|
| Server pods fail to start with "JWKS file not found" | Verify jwt-keys Job completed: `kubectl get jobs -n k8s-tests-dev` |
| Token auth tests failing with signature verification errors | Regenerate keys: `python3 pki-scripts/generate-jwt-keys.py --mode-both ...` |
| GSI tests fail "certificate expired" | Redo PKI generation with fresh certificates |
| `Address already in use` on ports 1094/8443 | Kill existing processes or switch to Kind (different port mapping) |
| Test runner can't discover endpoints | Check NodePort mappings: `kubectl get svc -n k8s-tests-dev` |
| JWT key generation Job stuck | Increase timeout: `--set jwtKeys.image=python:3.12-slim --set job.activeDeadlineSeconds=180` |
| PSS restriction blocking pods | Verify pod security context matches restricted policy (no privilege escalation) |

## Extending

To add a new deployment profile, create `server-helm/values.<name>.yaml` and optionally override specific Helm template variables. The test runner automatically picks up new profiles from the values file naming convention.

For dynamic JWT key customization, modify `test-infra-helm/values.yaml` jwtKeys section:
```yaml
jwtKeys:
  image: python:3.12-slim          # Python container for key generation
  keyId: test-key-1                # JWKS kid identifier
  tokenExpiryDays: 1               # JWT TTL in days
```
