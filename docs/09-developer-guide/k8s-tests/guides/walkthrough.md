# First-run walkthrough (copy-paste)

This is the shortest path from a clean machine to a green smoke test. All commands
run from `k8s-tests/`.

## 1. Install the tooling

```bash
# Helm 3
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
# helm-unittest (chart unit tests)
helm plugin install https://github.com/helm-unittest/helm-unittest
# python + shellcheck (pytest suite / lint)
sudo dnf install -y python3-pip ShellCheck && pip install -r pytests/requirements.txt
# kubeconform (manifest schema validation)
sudo curl -fsSLo /tmp/kc.tgz https://github.com/yannh/kubeconform/releases/download/v0.6.7/kubeconform-linux-amd64.tar.gz \
  && sudo tar -xzf /tmp/kc.tgz -C /usr/local/bin kubeconform
# yq (YAML query)
sudo curl -fsSLo /usr/local/bin/yq https://github.com/mikefarah/yq/releases/download/v4.44.3/yq_linux_amd64 \
  && sudo chmod +x /usr/local/bin/yq
```

You also need `minikube`, `kubectl`, `docker`, and `jq`. Verify everything:

```bash
./tools/require-tools.sh      # prints "All required tools present." on success
```

> **Note on minikube:** the lab pins Kubernetes to **v1.31.4**. A healthy
> `minikube` binary is ~90 MB; if `minikube version` crashes or hangs, reinstall it:
> ```bash
> curl -fsSLo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
> sudo install minikube /usr/local/bin/minikube && rm minikube
> ```

## 2. Run the lab's own unit tests (no cluster needed)

```bash
helm unittest charts/smoke charts/brix-test-lab   # chart assertions
pytest pytests/ -m 'not e2e'                    # lab + klib + config (no cluster)
```

You should see all suites pass.

## 3. Bring up the dev profile

```bash
./xrd-lab up            # minikube start --kubernetes-version=v1.31.4 --nodes=1
./xrd-lab deploy dev    # builds brix-smoke:dev into the node, installs the dev profile
```

What you should see: `minikube` reports the cluster is running, the smoke image is
built into the node, and `helm upgrade --install` waits until the pod is **Ready**.

## 4. Verify

```bash
./xrd-lab test smoke    # -> "smoke OK (200 /healthz)"
./xrd-lab status        # nodes + lab pods
```

## 5. Tear down

```bash
./xrd-lab down dev
```

## Tips

- Prefix any command with `XRD_LAB_DRY_RUN=1` to see the exact commands without
  running them — great for learning what the driver does.
- `XRD_LAB_NODES=3 ./xrd-lab up` gives a multi-node cluster (needed later for the
  one-role-per-node pinning profiles).
