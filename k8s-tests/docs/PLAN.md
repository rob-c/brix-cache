# K8s Testing Pipeline — Plan for Large-Scale nginx-xrootd Testing

## Executive Summary

This document outlines a production-grade Kubernetes-based testing infrastructure for nginx-xrootd, supporting multi-node deployments with full x509/CA/VOMS/CRL/Token authentication at scale. The plan builds on existing `k8s-tests/` scaffolding while addressing critical gaps identified through codebase analysis.

---

## Current State Assessment

### ✅ What Exists (Leverage)
| Component | Location | Status |
|---|---|---|
| RPM spec file | `packaging/rpm/nginx-mod-xrootd.spec` | Production-ready for EL9/EPEL |
| RPM builder Dockerfile | `k8s-tests/Dockerfiles/rpm-builder/` | CI-integrated, builds from git archive |
| 4 Container images | `k8s-tests/Dockerfiles/{rpm-builder,server,client,test-runner}` | Pushed to GHCR in CI |
| Helm charts | `k8s-tests/server-helm/`, `test-infra-helm/` | Basic scaffolding present |
| K8s manifests (raw) | `k8s-tests/k8s-manifests/` | Deployment, service, configmap, namespace |
| CI pipeline | `k8s-tests/.github/workflows/build.yaml` | Builds RPM → images → deploy-dev |
| PKI scripts | `k8s-tests/pki-scripts/` | CA, server cert, proxy certs, CRL, VOMS |
| Test runner | `k8s-tests/test-runner/run_tests.py`, `conftest.py` | pytest entrypoint with K8s fixtures |

### ❌ Critical Gaps (Must Address)
1. **Helm charts incomplete** — Templates exist but `_helpers.tpl`, service definitions, and configmap are skeleton/placeholder code
2. **CI pipeline missing test execution** — Builds/deploy happens but no automated test run against deployed servers
3. **No network policies** — Test pods have no isolation; cross-namespace traffic is unrestricted
4. **No resource quotas** — Multi-tenant test runs can starve each other without limits
5. **Token auth not integrated** — WLCG/JWT testing requires an OIDC provider (Keycloak/Dex) but none exists in K8s manifests
6. **No test result aggregation** — Parallel pytest Jobs produce scattered results with no collection mechanism
7. **Minikube local registry missing** — Images pull from GHCR; local dev should use `minikube-image-registry`
8. **RPM spec references upstream tarball** — The spec uses GitHub tags for source, not the local repo tree

---

## Architecture Blueprint

```
┌─────────────────────────────────────────────────────────────────────┐
│                         GITHUB CI                                    │
│                                                                      │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                       │
│  │ build-rpm│───▶│build-imgs│───▶│ deploy   │                       │
│  │(Alma9)   │    │(GHCR push)│    │(Helm upg)│                       │
│  └──────────┘    └──────────┘    └──────────┘                       │
│         │              │               │                            │
│         ▼              ▼               ▼                            │
├─────────────────────────────────────────────────────────────────────┤
│                    KUBERNETES CLUSTER                                │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   Namespace: k8s-tests-{profile}              │   │
│  │                                                               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │   │
│  │  │ cert-manager │  │  Keycloak   │  │ Prometheus  │           │   │
│  │  │ Cluster      │  │ (OIDC/JWT)  │  │ Operator    │           │   │
│  │  │ Issuer/CA    │  │             │  │             │           │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘           │   │
│  │         │              │               │                       │   │
│  │  ┌──────▼─────────────────────────────────────────────────┐    │   │
│  │  │              nginx-xrootd Server Nodes (N replicas)     │    │   │
│  │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                │    │   │
│  │  │  │ Pod-N-0 │  │ Pod-N-1 │  │ Pod-N-2 │ ...             │    │   │
│  │  │  │ :1094   │  │ :1095   │  │ :8443   │                │    │   │
│  │  │  │ :8443   │  │ :9100   │  │ ...     │                │    │   │
│  │  │  └─────────┘  └─────────┘  └─────────┘                │    │   │
│  │  └──────────────┬────────────────────────────────────────┘    │   │
│  │                 │ Service (ClusterIP)                          │   │
│  │                 ▼                                              │   │
│  │  ┌─────────────────────────────────────────────────┐          │   │
│  │  │              Test Runner Job (pytest)            │          │   │
│  │  │         Collects results → S3/GCS/Minio         │          │   │
│  │  └─────────────────────────────────────────────────┘          │   │
│  │                                                               │   │
│  │  ┌─────────────┐  ┌─────────────┐                           │   │
│  │  │  Network     │  │ Resource    │                           │   │
│  │  │  Policies    │  │ Quotas      │                           │   │
│  │  └─────────────┘  └─────────────┘                           │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   Ingress / Load Balancer                     │   │
│  │              (for external access during testing)             │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Fix Existing Foundation (Week 1-2)

### 1.1 Complete Helm Charts

**server-helm/templates/_helpers.tpl** — Must implement all `include` references used in deployment.yaml:
```yaml
{{- define "xrootd.fullname" -}}
{{- printf "%s-%s" .Release.Name "xrootd" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "xrootd.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "xrootd.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/component: server
{{- end }}
```

**server-helm/templates/service.yaml** — Already exists but needs ClusterIP + NodePort options for minikube:
```yaml
# XRootD stream service (TCP, headless for stable DNS)
apiVersion: v1
kind: Service
metadata:
  name: {{ include "xrootd.fullname" $ }}-xrootd
spec:
  type: ClusterIP
  clusterIP: None  # Headless for Pod-per-node addressing
  ports:
    - name: xrootd
      port: {{ $.Values.ports.xrootd }}
      targetPort: {{ $.Values.ports.xrootd }}
      protocol: TCP
    - name: roots
      port: {{ $.Values.ports.roots }}
      targetPort: {{ $.Values.ports.roots }}
  selector:
    app.kubernetes.io/name: {{ .Chart.Name }}
    app.kubernetes.io/component: server

# WebDAV HTTP service (LoadBalancer for external access)
apiVersion: v1
kind: Service
metadata:
  name: {{ include "xrootd.fullname" $ }}-webdav
spec:
  type: NodePort  # Minikube-friendly; LoadBalancer in prod
  ports:
    - port: {{ $.Values.ports.webdav }}
      targetPort: {{ $.Values.ports.webdav }}
      nodePort: {{ $.Values.ports.webdavNodePort | default 32443 }}
      protocol: TCP
  selector:
    app.kubernetes.io/name: {{ .Chart.Name }}
    app.kubernetes.io/component: server
```

**server-helm/templates/configmap.yaml** — nginx.conf generation with templated paths/certs:
- Must inject PKI mount paths from `secret.yaml`/`configMap`
- Must support auth mode switching (none/gsi/token) via template conditionals

### 1.2 Fix RPM Spec for Local Builds

The current spec references upstream tarballs (`%global version 0.1.0`). Replace with:
```spec
# Use local source tree instead of GitHub archive
Source0: nginx-xrootd-%{version}.tar.gz

# Or use git archive in RPM builder Dockerfile (already done there)
# This allows building without network access to GitHub
```

### 1.3 Add Minikube Image Registry Support

Update `Makefile` to push images to minikube's local registry:
```makefile
minikube-image-registry:
	@minikube image build -t $(IMAGE):$(TAG) ./k8s-tests/Dockerfiles/$(COMPONENT)
	@minikube image tag $(IMAGE):$(TAG) localhost:5000/$(IMAGE):$(TAG)

deploy-minikube: minikube-image-registry
	helm upgrade --install xrootd-servers ./server-helm \
		--namespace k8s-tests-dev \
		-f server-helm/values.dev.yaml \
		--set image.repository=localhost:5000/nginx-xrootd-server \
		--set image.tag=$(TAG) \
		--set image.pullPolicy=Never
```

---

## Phase 2: Security & Isolation (Week 3-4)

### 2.1 Network Policies

**k8s-tests/k8s-manifests/network-policy.yaml** — Restrict traffic flow:
```yaml
# Allow test-runner pods to reach server pods on specific ports only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-test-to-server
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: server
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              k8s-tests/profile: test
          podSelector: {}
      ports:
        - port: 1094   # root://
        - port: 1095   # roots://
        - port: 8443   # davs://
        - port: 9100   # metrics (optional, for debugging)
---
# Deny cross-namespace traffic by default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-cross-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

### 2.2 Resource Quotas & LimitRanges

**k8s-tests/k8s-manifests/resource-quota.yaml**:
```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: test-profile-quota
spec:
  hard:
    requests.cpu: "8"
    requests.memory: 16Gi
    limits.cpu: "16"
    limits.memory: 32Gi
    pods: "50"
    services: "20"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: pod-limits
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 512Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
```

### 2.3 Pod Security Standards (PSS)

**k8s-tests/k8s-manifests/pod-security.yaml**:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: k8s-tests-dev
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

---

## Phase 3: Authentication Infrastructure (Week 5-6)

### 3.1 Keycloak Deployment for Token Auth

**k8s-tests/test-infra-helm/templates/keycloak.yaml**:
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: keycloak
spec:
  serviceName: keycloak-headless
  replicas: 1
  template:
    spec:
      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak:24.0
          args: ["start-dev"]
          env:
            - name: KC_DB
              value: postgresql
            - name: KC_DB_URL_HOST
              value: keycloak-db
            - name: KEYCLOAK_ADMIN
              value: admin
            - name: KEYCLOAK_ADMIN_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: keycloak-credentials
                  key: admin-password
          ports:
            - containerPort: 8080
              name: http
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
spec:
  type: ClusterIP
  ports:
    - port: 8080
      targetPort: 8080
```

### 3.2 WLCG Token Configuration

Create a Keycloak realm with WLCG-compatible token structure:
- Realm: `wlcg`
- Client: `nginx-xrootd-token-verifier`
- Mappers: `sub`, `wlcg.groups`, `preferred_username`

**k8s-tests/test-infra-helm/templates/keycloak-realm.yaml**:
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: keycloak-init
spec:
  template:
    spec:
      containers:
        - name: init
          image: curlimages/curl:latest
          command: ["/bin/sh", "-c"]
          args:
            - |
              # Wait for Keycloak to be ready
              until curl -s http://keycloak:8080/health; do sleep 2; done
              # Create realm via Admin REST API
              curl -X POST http://admin:password@keycloak:8080/admin/realms \
                -H "Content-Type: application/json" \
                -d '{"realm": "wlcg", "enabled": true}'
      restartPolicy: Never
```

### 3.3 Token JWKS Endpoint Integration

Update nginx-xrootd server config to fetch JWKS from Keycloak:
```nginx
# In configmap.yaml template
xrootd_token_jwks_url http://keycloak:8080/realms/wlcg/protocol/openid-connect/certs;
xrootd_token_audience nginx-xrootd-test-clients;
```

---

## Phase 4: Test Execution & Results Aggregation (Week 7-8)

### 4.1 Parallel Test Job with Result Collection

**k8s-tests/k8s-manifests/job-test-run-aggregated.yaml**:
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: test-runner-aggregated
spec:
  template:
    spec:
      containers:
        - name: pytest
          image: ghcr.io/HEP-x/nginx-xrootd-test-runner:latest
          command: ["/usr/local/bin/python", "/app/run_tests.py"]
          args:
            - "--tests"
            - "test_file_api.py test_query.py test_write.py"
            - "--namespace"
            - "{{ .Release.Namespace }}"
            - "--result-bucket"
            - "k8s-test-results"  # S3-compatible storage for results
          env:
            - name: TEST_NGINX_URL
              value: "root://xrootd-server.xrootd-service:1094"
            - name: TEST_DAVS_URL
              value: "davs://webdav-server.webdav-service:8443"
      restartPolicy: Never
  backoffLimit: 2
```

### 4.2 Result Aggregation Sidecar/Post-Job

**k8s-tests/test-runner/aggregate_results.py**:
```python
"""Collect pytest results from multiple parallel jobs and generate summary."""
import boto3
from datetime import datetime
import json

def fetch_results(bucket_name, prefix):
    """Fetch all XML result files from S3-compatible storage."""
    s3 = boto3.client('s3')
    objects = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    
    results = []
    for obj in objects.get('Contents', []):
        if obj['Key'].endswith('.xml'):
            response = s3.get_object(Bucket=bucket_name, Key=obj['Key'])
            # Parse pytest-junit XML
            results.append(parse_junit_xml(response['Body'].read()))
    
    return aggregate(results)

def summarize(summary):
    """Generate human-readable test summary."""
    total = sum(1 for r in summary.values() if r['passed'] > 0 or r['failed'] > 0)
    passed = sum(r['passed'] for r in summary.values())
    failed = sum(r['failed'] for r in summary.values())
    
    return {
        'total_tests': total,
        'passed': passed,
        'failed': failed,
        'duration_seconds': max(r.get('duration', 0) for r in summary.values()),
        'timestamp': datetime.utcnow().isoformat()
    }
```

### 4.3 CI Integration — Run Tests After Deploy

Update `k8s-tests/.github/workflows/build.yaml`:
```yaml
jobs:
  # ... existing build-rpm, build-images jobs ...
  
  test-k8s-dev:
    name: Run K8s Integration Tests
    needs: [build-images]
    runs-on: ubuntu-latest
    if: ${{ github.event_name == 'push' }}
    steps:
      - uses: actions/checkout@v4
      
      - name: Start minikube
        run: |
          minikube start --nodes=3 --cpus=4 --memory=8192
          
      - name: Deploy test infrastructure
        run: |
          helm repo add jetstack https://charts.jetstack.io
          helm install cert-manager jetstack/cert-manager \
            --namespace cert-manager \
            --create-namespace \
            --set crds.enabled=true
          
          # Push images to local registry
          for img in server client test-runner; do
            docker build -t localhost:5000/nginx-xrootd-$img:${GITHUB_SHA} \
              ./k8s-tests/Dockerfiles/$img
            minikube image load localhost:5000/nginx-xrootd-$img:${GITHUB_SHA}
          done
          
      - name: Deploy servers
        run: |
          helm upgrade --install xrootd-servers ./server-helm \
            --namespace k8s-tests-dev \
            --create-namespace \
            -f server-helm/values.dev.yaml \
            --set image.repository=localhost:5000/nginx-xrootd-server \
            --set image.tag=${GITHUB_SHA} \
            --set image.pullPolicy=Never \
            --set auth.mode=gsi
        
      - name: Wait for servers ready
        run: kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=server \
             --namespace=k8s-tests-dev --timeout=300s
          
      - name: Run tests
        run: |
          helm upgrade --install test-job ./test-infra-helm \
            --namespace k8s-tests-dev \
            --set job.image=localhost:5000/nginx-xrootd-test-runner:${GITHUB_SHA} \
            --set job.authMode=gsi
          
          # Wait for test completion and collect results
          kubectl logs -l app.kubernetes.io/component=test-runner \
            --namespace=k8s-tests-dev --tail=-1
```

---

## Phase 5: Observability & Teardown (Week 9-10)

### 5.1 Prometheus Metrics Scraping

**k8s-tests/k8s-manifests/prometheus-scrape.yaml**:
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: nginx-xrootd-metrics
spec:
  selector:
    matchLabels:
      app.kubernetes.io/component: server
  endpoints:
    - port: metrics
      path: /metrics
      interval: 15s
```

### 5.2 Automated Teardown (Cleanup)

**k8s-tests/Makefile** — Add teardown target:
```makefile
teardown-%:
	# Clean up namespace and all resources
	helm uninstall xrootd-servers --namespace $(PROFILE) || true
	helm uninstall test-infra --namespace $(PROFILE) || true
	kubectl delete namespace $(PROFILE) --wait --timeout=120s || true
	minikube image rm localhost:5000/nginx-xrootd-* 2>/dev/null || true

teardown-all: teardown-dev teardown-staging teardown-perf
```

### 5.3 Minikube Multi-Node Setup Script

**k8s-tests/scripts/setup-minikube.sh**:
```bash
#!/usr/bin/env bash
set -euo pipefail

NODES="${1:-3}"
CPUS="${2:-4}"
MEMORY="${3:-8192}"

echo "Starting minikube with ${NODES} nodes, ${CPUS} CPUs, ${MEMORY}Mi memory each"

minikube stop 2>/dev/null || true
minikube delete --all 2>/dev/null || true

minikube start \
    --nodes="${NODES}" \
    --cpus="${CPUS}" \
    --memory="${MEMORY}000" \
    --driver=docker \
    --kubernetes-version=v1.28.3

# Enable ingress addon for external access
minikube addons enable ingress
minikube addons enable metrics-server

echo "Cluster ready. Nodes:"
kubectl get nodes -o wide
```

---

## Directory Structure After Implementation

```
k8s-tests/
├── README.md                         # Updated with full architecture docs
├── Makefile                          # build, deploy, test, teardown targets
│
├── .github/workflows/
│   ├── build.yaml                    # CI: RPM → images → deploy → TEST (NEW)
│   └── cleanup.yaml                  # Periodic namespace cleanup cron (NEW)
│
├── Dockerfiles/
│   ├── rpm-builder/Dockerfile        # Existing — no changes needed
│   ├── server/Dockerfile             # Update: add metrics-sidecar init container
│   ├── client/Dockerfile             # Add Keycloak CLI for token generation
│   └── test-runner/Dockerfile        # Add aggregate_results.py, boto3
│
├── server-helm/                      # Complete Helm chart
│   ├── Chart.yaml
│   ├── values.yaml                   # Production defaults
│   ├── values.dev.yaml               # Minikube profile (1 node, anonymous)
│   ├── values.prod.yaml              # Multi-node production profile
│   └── templates/
│       ├── _helpers.tpl              # FIX: Complete helper definitions
│       ├── deployment.yaml           # Existing — verify templating works
│       ├── service.yaml              # FIX: Add ClusterIP + NodePort services
│       ├── configmap.yaml            # FIX: Complete nginx.conf template
│       ├── secret.yaml               # TLS cert injection from cert-manager
│       └── pvc.yaml                  # Shared data volume for cross-node TPC
│
├── test-infra-helm/                  # PKI + Keycloak + observability
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/
│       ├── _helpers.tpl
│       ├── cert-manager-ca.yaml      # Existing CA via cert-manager ClusterIssuer
│       ├── server-certificate.yaml   # Server TLS signed by CA
│       ├── crl.yaml                  # CRL ConfigMap + distribution endpoint
│       ├── voms-server.yaml          # VOMSdir as PersistentVolumeClaim
│       ├── keycloak.yaml             # NEW: Keycloak StatefulSet + Service
│       ├── keycloak-realm.yaml       # NEW: Realm initialization Job
│       └── prometheus-scrape.yaml    # NEW: ServiceMonitor for metrics
│
├── k8s-manifests/                    # Raw manifests (non-Helm alternative)
│   ├── namespace.yaml                # With PSS labels
│   ├── network-policy.yaml           # NEW: Traffic isolation
│   ├── resource-quota.yaml           # NEW: Resource limits
│   ├── deployment-server.yaml        # Update with pod anti-affinity
│   ├── service-xrootd.yaml           # Headless for stable DNS
│   ├── service-webdav.yaml           # NodePort/LoadBalancer
│   └── job-test-run.yaml             # Add result collection args
│
├── pki-scripts/                      # Existing scripts — verify completeness
│   ├── generate-ca.sh
│   ├── generate-server-cert.sh
│   ├── generate-proxy-certs.sh
│   ├── setup-voms-attributes.sh
│   └── manage-crl.sh
│
├── test-runner/
│   ├── Dockerfile                    # Add aggregate_results.py dependencies
│   ├── run_tests.py                  # Existing entrypoint
│   ├── conftest.py                   # K8s-aware fixtures (verify completeness)
│   ├── values.test.yaml              # Test config overlay
│   └── aggregate_results.py          # NEW: Result collection & summarization
│
├── scripts/                          # Utility scripts
│   ├── setup-minikube.sh             # NEW: Multi-node minikube bootstrap
│   └── teardown-cluster.sh           # NEW: Full cluster cleanup
│
└── docs/
    └── deployment-guide.md           # Step-by-step instructions (update)
```

---

## Deployment Profiles

| Profile | Nodes | Auth | PKI | Token | Use Case |
|---|---|---|---|---|---|
| `dev` | 1 | none/anonymous | static certs | disabled | Local iteration |
| `dev-gsi` | 2-3 | gsi/x509 | cert-manager CA | disabled | Minikube PKI testing |
| `staging` | 3+ | token/bearer | cert-manager CA | Keycloak | Pre-prod validation |
| `perf` | 5+ | any | cert-manager CA | optional | Throughput benchmarking |

---

## Verification Checklist

Before considering this pipeline production-ready:

- [ ] RPM builds successfully in CI without network access to GitHub (local source)
- [ ] Server pods start, nginx passes `-t` config validation on first boot
- [ ] cert-manager issues TLS certificates within 60 seconds of deployment
- [ ] Network policies enforce ingress restrictions (test with `kubectl port-forward`)
- [ ] Resource quotas prevent a single test profile from consuming all cluster resources
- [ ] Keycloak realm initializes and serves JWKS endpoint before server pods start
- [ ] Test runner Job completes, collects results from S3-compatible storage
- [ ] Makefile `teardown-dev` cleans up all namespace resources within 30 seconds
- [ ] Minikube multi-node setup script provisions cluster with 3 nodes in under 5 minutes

---

## Risk Assessment

| Risk | Mitigation |
|---|---|
| cert-manager Certificate CRDs not available on older K8s versions | Fallback to static mounted secrets via init container |
| Minikube Docker driver doesn't support multi-node well enough for TPC testing | Switch to `podman` or `kvm2` drivers; document requirements |
| Keycloak startup race condition with server pods | Use Helm `initContainers` with readiness checks, or Job-based realm initialization |
| GHCR rate limiting during CI image builds | Add layer caching with BuildKit; use GitHub Actions cache for Docker layers |
| Test flakes due to K8s resource contention | Implement test retries with exponential backoff in `conftest.py`; add resource quotas |

---

## Summary

This plan transforms the existing `k8s-tests/` skeleton into a production-grade testing pipeline. The key insight is that **most infrastructure already exists** — what's needed is completing the Helm templates, adding security isolation (network policies + quotas), integrating Keycloak for token auth, and wiring test execution into CI with result aggregation.

The phased approach ensures each component is validated before moving to the next phase, reducing integration risk.
