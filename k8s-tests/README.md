# nginx-xrootd Kubernetes Test Lab

A portable, Helm-driven test lab that runs the project's server topologies on
**minikube** — no external container registry required, so it runs anywhere.

## Prerequisites

Run the checker; it names anything missing:

    ./tools/require-tools.sh

Install anything reported missing (helm, python3, kubeconform, yq, shellcheck;
minikube, kubectl, docker, jq). See `docs/walkthrough.md` for exact commands.
The Python tests need `pip install -r pytests/requirements.txt` (pytest +
kubernetes client).

## Quickstart (dev profile)

    ./xrd-lab up            # start minikube (pinned Kubernetes version)
    ./xrd-lab deploy dev    # build images into the cluster + install the dev profile
    ./xrd-lab test smoke    # verify the smoke Service answers /healthz with 200
    ./xrd-lab down dev      # tear the profile down

Set `XRD_LAB_DRY_RUN=1` before any command to print the exact `minikube`/`helm`/
`kubectl` commands it would run without executing them.

## How it fits together

- `charts/brix-common` — a Helm *library* chart holding every shared helper
  (labels, image reference, the one-role-per-node pinning toggle, NetworkPolicy,
  ResourceQuota). Nothing else re-implements these.
- `charts/brix-test-lab` — the umbrella chart. A **profile** is a values file in
  `charts/brix-test-lab/values/`; it turns subcharts on and configures them.
- `charts/smoke` — a minimal deployable that exercises the whole foundation
  (image build → in-cluster load → deploy → Service → `/healthz`).
- `images/smoke` — the registry-free image the `smoke` chart runs.
- `xrd-lab` — the one script you run.

## Testing the lab itself

- Chart unit tests (no cluster): `helm unittest charts/smoke charts/brix-test-lab`
- Lab + klib + config tests (no cluster): `pytest pytests/ -m 'not e2e'`
- Image + live end-to-end (needs Docker + minikube): `pytest pytests/ -m e2e`
- Manifest schema validation:
  `helm template brix-dev charts/brix-test-lab -f charts/brix-test-lab/values/values.dev.yaml | kubeconform -strict`

## What comes next

Later sub-projects add the auth-authority plane (CA/CRL/VOMS/JWKS/krb5), the
chaos-mesh topology, the main test fleet, the dedicated-scenario catalog, the
CMS/hybrid meshes, and the Ceph/FUSE backends as additional subcharts + profiles.
See `docs/superpowers/plans/2026-07-04-k8s-lab-subproject-*.md`.
