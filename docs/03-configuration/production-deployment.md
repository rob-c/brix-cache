# Production Deployment Guide

Step-by-step instructions for deploying gnuBall in production — covering systemd service setup, resource limits, log rotation, and the Kubernetes testing pipeline.

## Prerequisites

### Software Requirements

| Tool | Minimum Version | Purpose |
|---|---|---|
| Docker | 20.10+ | Build container images, Kind/minikube driver |
| Helm | 3.12+ | Deploy Helm charts (server-helm, test-infra) |
| kubectl | 1.28+ | Kubernetes CLI for cluster management |
| minikube OR kind | Latest stable | Local K8s cluster runtime |

### Required Addons (Kind only — auto-enabled by setup-cluster.sh)

- Ingress controller (`kind` creates with `ingress-nginx`)
- Metrics server (for HPA and monitoring)

## Step 1: Bootstrap the Cluster

Choose your cluster type based on use case:

**Kind (recommended for production parity):**
```bash
cd k8s-tests
bash scripts/setup-cluster.sh 3 4 8192 kind 120s
export KUBECONFIG="$(kind get kubeconfig --name nginx-xrootd-test)"
```

**Minikube (faster local iteration):**
```bash
bash scripts/setup-cluster.sh 3 4 8192 minikube 120s
```

Verify cluster is ready:
```bash
kubectl get nodes -o wide
# Expected output: 3 Ready nodes with external IPs
```

## Step 2: Install cert-manager (PKI)

cert-manager provides automated TLS certificate issuance for server pods:

```bash
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager \
    --namespace cert-manager \
    --create-namespace \
    --set crds.enabled=true
```

Wait for cert-manager to become ready:
```bash
kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=cert-manager \
    --namespace cert-manager --timeout=120s
```

## Step 3: Deploy Test Infrastructure (PKI + Keycloak)

This deploys the CA, certificates, and Keycloak for token auth testing:

```bash
helm upgrade --install test-infra ./test-infra-helm \
    --namespace k8s-tests-dev \
    --create-namespace \
    -f ./test-infra-helm/values.yaml
```

Wait for Keycloak realm initialization Job to complete:
```bash
kubectl wait --for=condition=complete job/keycloak-realm-init \
    --namespace=k8s-tests-dev --timeout=120s || true
```

Verify deployment:
```bash
kubectl get pods -n k8s-tests-dev -l app.kubernetes.io/component=keycloak
# Expected: 1/1 Running pod named "keycloak-0"
```

## Step 4: Build and Load Images

**Build images locally:**
```bash
make build-images IMAGE_TAG=dev
```

**Load into Kind cluster:**
```bash
for img in server client test-runner; do
    docker image save nginx-xrootd-$img:dev | kind load docker-image --name nginx-xrootd-test -
done
```

**Load into Minikube cluster:**
```bash
for img in server client test-runner; do
    minikube image load nginx-xrootd-$img:dev
done
```

## Step 5: Deploy gnuBall Servers

**For GSI/x509 authentication testing:**
```bash
helm upgrade --install xrootd-servers ./server-helm \
    --namespace k8s-tests-dev \
    -f ./server-helm/values.dev.yaml \
    --set auth.mode=gsi \
    --set server.nodeCount=3 \
    --set image.pullPolicy=Never  # For local images
```

**For token/JWT authentication testing:**
```bash
helm upgrade --install xrootd-servers ./server-helm \
    --namespace k8s-tests-dev \
    -f ./server-helm/values.dev.yaml \
    --set auth.mode=token \
    --set server.nodeCount=3 \
    --set image.pullPolicy=Never
# The JWKS file is mounted into the pod at /etc/nginx/jwks/jwks.json by test-infra-helm,
# matching jwtKeys.configPath in server-helm/values.yaml — no Helm override is needed.
```

Wait for servers to be ready:
```bash
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=server \
    --namespace=k8s-tests-dev --timeout=300s
```

Verify services are accessible (Kind example):
```bash
# Kind uses port-forwarding via extraPortMappings
curl http://localhost:9100/metrics  # Prometheus metrics endpoint
```

## Step 6: Run Tests

**Via Makefile (recommended):**
```bash
make test AUTH_MODE=gsi NAMESPACE=k8s-tests-dev CLUSTER_TYPE=kind
```

**Manual test job deployment:**
```bash
helm upgrade --install test-job ./test-infra-helm \
    --namespace k8s-tests-dev \
    --set job.image=nginx-xrootd-test-runner:dev \
    --set job.imagePullPolicy=Never \
    --set job.authMode=gsi

# Wait for completion (up to 30 minutes)
kubectl wait --for=condition=complete job/test-job \
    --namespace=k8s-tests-dev --timeout=1800s || true
```

**Collect and aggregate results:**
```bash
mkdir -p /tmp/k8s-test-results && kubectl cp k8s-tests-dev/test-runner:/test-results/*.xml /tmp/k8s-test-results/ 2>/dev/null || true
python3 test-runner/aggregate_results.py --results-dir /tmp/k8s-test-results -o /tmp/test-summary.json
cat /tmp/test-summary.json
```

## Troubleshooting

### Pod Stuck in Pending State
```bash
kubectl describe pod <pod-name> -n k8s-tests-dev | grep -A 10 "Events:"
# Common causes: insufficient resources, PVC not bound, image pull failure
```

### Keycloak Not Ready After Deployment
The realm initialization Job waits for the `/health/ready` endpoint. If it times out:
```bash
kubectl logs job/keycloak-realm-init -n k8s-tests-dev --tail=50
# Restart if needed:
kubectl delete job keycloak-realm-init -n k8s-tests-dev && helm upgrade --install test-infra ./test-infra-helm ...
```

### Test Runner Can't Reach Server Pods
Verify DNS resolution from within the test runner pod:
```bash
kubectl exec -it $(kubectl get pods -l app.kubernetes.io/component=test-runner -n k8s-tests-dev -o jsonpath='{.items[0].metadata.name}') \
    -n k8s-tests-dev -- nslookup xrootd-servers-xrootd.k8s-tests-dev.svc.cluster.local
```

### Network Policy Blocking Test Traffic
Verify network policies are correctly applied:
```bash
kubectl get networkpolicy -n k8s-tests-dev
kubectl describe networkpolicy allow-test-to-server -n k8s-tests-dev
```

## Cleanup

**Remove namespace and cluster:**
```bash
bash scripts/teardown.sh k8s-tests-dev --all
```

**Or use Makefile targets:**
```bash
make teardown-all  # Cleans up dev, staging, perf namespaces
```
