# Kubernetes Test Suite Deep Dive

This document explains the `k8s-tests/` lab from the ground up. It is written
for someone who wants to understand not only which command to run, but also how
Kubernetes decides:

- which image a container should run
- which config files, secrets, and generated artifacts a pod should see
- which Kubernetes node, or minikube VM/container, should host each pod
- how the repo's normal pytest suite is adapted to run against Kubernetes
- how Helm, minikube, Docker, Services, ConfigMaps, Secrets, Jobs, and pod
  scheduling all fit together

The current primary entrypoint is:

```bash
cd k8s-tests
./xrd-lab up
./xrd-lab deploy dev
./xrd-lab test smoke
./xrd-lab down dev
```

There is also older Makefile-oriented scaffolding in this directory. The
maintained path described here is the `xrd-lab` Python driver plus Helm profile
charts. Treat `xrd-lab` as the source of truth unless a task explicitly says to
use the older Makefile flow.

## Big Picture

The lab is a self-contained Kubernetes environment for running nginx-xrootd
topologies. It avoids an external container registry by building images locally
and loading them into minikube. Helm renders the Kubernetes objects. Kubernetes
then schedules pods, mounts configuration, exposes Services, and runs either
small scenario probes or in-cluster pytest Jobs.

At the highest level:

```text
developer shell
    |
    | ./xrd-lab up
    v
minikube cluster
    |
    | ./xrd-lab deploy <profile>
    v
local images built/loaded into minikube
    |
    v
Helm umbrella chart renders one profile
    |
    v
Kubernetes API stores Deployments, Jobs, Services, ConfigMaps, Secrets
    |
    v
scheduler chooses nodes
    |
    v
kubelet on each node starts containers and mounts config
    |
    | ./xrd-lab test <scenario>
    v
scenario probe or in-cluster pytest validates the topology
```

The important principle is that Kubernetes does not inspect this repository and
infer what to do. The chain is explicit:

```text
xrd-lab command
    -> Python plan in labtools/lab.py or labtools/lab_suite.py
    -> docker/minikube/helm/kubectl commands
    -> Helm values
    -> rendered Kubernetes Pod specs
    -> Kubernetes scheduler and kubelets
```

If you can find the image, config, volume, label, or affinity rule in the
rendered Kubernetes YAML, you can explain what the cluster will do.

## Core Kubernetes Vocabulary

This lab uses standard Kubernetes objects. The most important ones are:

- **Cluster**: The Kubernetes control plane plus worker nodes. In this lab,
  `minikube` creates it.
- **Node**: A worker machine from Kubernetes' point of view. With minikube's
  Docker driver, nodes are Docker containers acting like machines. With a VM
  driver, nodes are VMs. Either way Kubernetes sees them as nodes.
- **Pod**: The smallest scheduled unit. A pod contains one or more containers
  that share networking and volumes.
- **Container**: A process started from an image, such as `brix-server:dev`.
- **Image**: The filesystem and metadata used to start a container.
- **Deployment**: A controller that keeps a desired number of pod replicas
  running.
- **Job**: A controller that runs a pod to completion, used for bootstrap work
  and pytest runs.
- **Service**: A stable virtual IP and DNS name in front of matching pods.
- **ConfigMap**: Non-secret configuration mounted into pods or exposed as env.
- **Secret**: Secret-ish material such as private keys, mounted into pods.
- **emptyDir**: Scratch storage created when a pod starts and deleted with it.
- **hostPath**: A mount from the Kubernetes node filesystem into a pod.
- **Helm chart**: A template package that renders Kubernetes YAML.
- **Helm values**: Data passed into a chart to choose images, ports, config
  keys, enabled subcharts, auth URLs, and other settings.

Kubernetes itself only sees the rendered YAML submitted through its API. Helm is
a client-side renderer. Once Helm sends the objects to Kubernetes, Kubernetes
schedules and runs them like any other workload.

## Directory Map

The main pieces are:

```text
k8s-tests/
  xrd-lab
      Thin shell wrapper. Executes python3 -m labtools.lab.

  labtools/
      Python implementation of the driver and helper logic.
      lab.py             up/deploy/down/status/test scenario command plans
      lab_suite.py       suite and remote-suite in-cluster pytest flows
      catalog.py         dedicated-scenario catalog lint/render
      coverage.py        remote-suite classification
      sync.py            remote-suite fork synchronization
      mega_config.py     generated fleet-mega nginx config

  charts/
      brix-common/       Helm library helpers
      brix-test-lab/     umbrella chart, profile entrypoint
      smoke/             minimal smoke Deployment and Service
      topology-role/     generic one-role nginx-xrootd chart
      main-fleet/        aliases topology-role into anon/gsi/token/metrics
      auth-authority/    CA, CRL, JWKS, VOMS, KDC authority plane
      cms-mesh/          CMS manager plus data server
      chaos-mesh/        tiered cache/discovery topology
      backend-ceph/      Rook-Ceph custom resources
      fuse-client/       privileged FUSE client pod
      test-runner/       pytest Job
      client-rbac/       ServiceAccount/Role/RoleBinding for pod exec

  images/
      smoke/             tiny nginx /healthz image
      server/            real nginx-xrootd image
      client/            remote-suite client image with kubernetes client
      test-runner/       repo test-runner image
      authority/         PKI/token tooling plus static nginx distributor
      krb5-kdc/          test KDC image

  pytests/
      Tests for the lab itself. Fast tests inspect plans/rendering/helpers.
      e2e tests build images and use a real minikube cluster.

  remote-suite/
      Fork/adaptation of the repo's normal tests for in-cluster remote mode.

  scenarios/
      catalog.yaml       Dedicated one-role scenario definitions.
      schema.md          Schema for catalog entries.

  test-runner/
      Older/general runner helpers and result aggregation.

  docs/
      walkthrough.md     Copy-paste first-run walkthrough.
```

## The Main Lifecycle

### 1. Starting The Cluster

`./xrd-lab up` calls `labtools.lab.plan_up()`, which emits:

```text
minikube start --driver=<driver> --nodes=<nodes> --kubernetes-version=<version>
minikube addons enable metrics-server
```

Defaults:

```text
XRD_LAB_DRIVER=docker
XRD_LAB_NODES=1
XRD_LAB_K8S_VERSION=v1.31.4
```

Override examples:

```bash
XRD_LAB_NODES=3 ./xrd-lab up
XRD_LAB_DRIVER=podman ./xrd-lab up
XRD_LAB_K8S_VERSION=v1.31.4 ./xrd-lab up
```

What this means:

```text
host machine
  |
  +-- minikube control plane
  |
  +-- node 1  (a Kubernetes worker; Docker-driver node container by default)
  |
  +-- node 2  (only when --nodes >= 2)
  |
  +-- node 3  (only when --nodes >= 3)
```

From Kubernetes' perspective, each node is a possible place to run pods. The lab
uses the word VM loosely in some contexts because a Kubernetes node often is a
VM. With the default Docker driver, the "VM" is actually a minikube-managed
container acting as a node.

### 2. Building And Loading Images

`./xrd-lab deploy <profile>` begins with `plan_images(profile)`. That profile
decides which local images are needed.

The image build target defaults to AlmaLinux 9.  Select CentOS Stream 9 with:

```bash
XRD_LAB_OS_TARGET=centos9-stream ./xrd-lab deploy <profile>
```

The target metadata lives in `labtools/targets.py`:

```text
alma9
  base image:        almalinux:9
  smoke base image:  almalinux:9-minimal
  Ceph SIG repo:     off

centos9-stream
  base image:        quay.io/centos/centos:stream9
  smoke base image:  quay.io/centos/centos:stream9
  Ceph SIG repo:     on
  default Ceph repo: ceph-tentacle
```

Override the Ceph SIG stream with:

```bash
XRD_LAB_CEPH_SIG_RELEASE=squid ./xrd-lab test ceph-rpmbuild
```

Current image plan:

```text
profile        image tags loaded/built by xrd-lab
-------------  ----------------------------------------------------------
dev            brix-smoke:dev
gsi            brix-authority:dev
token          brix-authority:dev, brix-krb5-kdc:dev
fleet          brix-authority:dev, brix-server:dev, brix-test-runner:dev
cms            brix-server:dev
chaos          brix-server:dev
ceph           none from xrd-lab; chart uses Rook/Ceph images externally
fuse           chart expects brix-client-fuse:dev; build/load separately or
               extend plan_images before relying on this profile
```

The smoke image is special:

```text
minikube image build -t brix-smoke:dev k8s-tests/images/smoke
```

That command builds directly inside minikube's image environment.

The other lab images are built by Docker, then loaded into minikube:

```text
docker build -t brix-server:dev -f k8s-tests/images/server/Dockerfile <repo-root>
minikube image load brix-server:dev
```

This is how the lab avoids an external registry.

```text
repo Dockerfile + repo source
       |
       | docker build
       v
host Docker image store
       |
       | minikube image load
       v
minikube node image store
       |
       | kubelet starts container with imagePullPolicy: Never
       v
running container
```

For `brix-smoke:dev`, the build path is even shorter:

```text
k8s-tests/images/smoke
       |
       | minikube image build
       v
minikube node image store
       |
       | kubelet starts container with imagePullPolicy: Never
       v
running smoke container
```

### 3. Creating The Namespace

After images, `xrd-lab deploy <profile>` creates the namespace:

```text
kubectl create namespace brix-<profile>
kubectl label namespace brix-<profile> pod-security.kubernetes.io/enforce=baseline --overwrite
```

Examples:

```text
profile dev     -> namespace brix-dev
profile fleet   -> namespace brix-fleet
profile chaos   -> namespace brix-chaos
```

Most lab resources are namespaced. Deleting the namespace is therefore the final
cleanup boundary:

```text
./xrd-lab down dev
  -> helm uninstall brix-dev --namespace brix-dev
  -> kubectl delete namespace brix-dev --ignore-not-found
```

### 4. Rendering The Profile With Helm

The deployment command then runs:

```text
helm dependency build k8s-tests/charts/brix-test-lab

helm upgrade --install brix-<profile> k8s-tests/charts/brix-test-lab \
  --namespace brix-<profile> \
  --create-namespace \
  --values k8s-tests/charts/brix-test-lab/values/values.<profile>.yaml \
  --wait \
  --timeout 5m
```

The umbrella chart is `charts/brix-test-lab`. Its `Chart.yaml` declares
dependencies:

```text
brix-test-lab
  |
  +-- smoke          condition: smoke.enabled
  +-- auth-authority condition: auth-authority.enabled
  +-- chaos-mesh     condition: chaos-mesh.enabled
  +-- main-fleet     condition: main-fleet.enabled
  +-- cms-mesh       condition: cms-mesh.enabled
  +-- backend-ceph   condition: backend-ceph.enabled
  +-- fuse-client    condition: fuse-client.enabled
```

The umbrella default values turn every subchart off. A profile values file turns
on exactly the pieces needed for that profile.

```text
charts/brix-test-lab/values.yaml
  smoke.enabled: false
  auth-authority.enabled: false
  chaos-mesh.enabled: false
  main-fleet.enabled: false
  cms-mesh.enabled: false
  backend-ceph.enabled: false
  fuse-client.enabled: false

charts/brix-test-lab/values/values.dev.yaml
  smoke.enabled: true
  smoke.image.repository: brix-smoke
  smoke.image.tag: dev
  smoke.image.pullPolicy: Never

charts/brix-test-lab/values/values.fleet.yaml
  auth-authority.enabled: true
  main-fleet.enabled: true
```

That gives this flow:

```text
./xrd-lab deploy fleet
       |
       v
values.fleet.yaml
       |
       +-- auth-authority.enabled=true
       |
       +-- main-fleet.enabled=true
       |
       v
Helm renders authority Deployments/Services/Jobs
and anon/gsi/token/metrics server roles
```

Kubernetes does not know what a "profile" is. Profile is a lab concept. By the
time Kubernetes sees the request, Helm has converted the profile into ordinary
Kubernetes objects.

## How Kubernetes Knows Which Image To Launch

Kubernetes knows which image to launch because the pod template says so.

For smoke, the chart renders:

```yaml
containers:
  - name: smoke
    image: "brix-smoke:dev"
    imagePullPolicy: Never
```

For a topology role, the chart renders:

```yaml
containers:
  - name: gsi
    image: "brix-server:dev"
    imagePullPolicy: Never
```

The values come from Helm values. For topology roles, the defaults are:

```yaml
role:
  image:
    repository: brix-server
    tag: dev
    pullPolicy: Never
```

For authority:

```yaml
image:
  repository: brix-authority
  tag: dev
  pullPolicy: Never
kdcImage:
  repository: brix-krb5-kdc
  tag: dev
  pullPolicy: Never
```

For the test-runner:

```yaml
image:
  repository: brix-test-runner
  tag: dev
  pullPolicy: Never
```

The exact decision chain is:

```text
Helm values
  image.repository: brix-server
  image.tag: dev
  image.pullPolicy: Never
       |
       v
Helm template
  image: "brix-server:dev"
  imagePullPolicy: Never
       |
       v
Kubernetes API stores PodSpec
       |
       v
scheduler picks a node
       |
       v
kubelet on that node tries to start "brix-server:dev"
       |
       v
container runtime looks in local node image store
```

`imagePullPolicy: Never` is intentional. It means:

- do not contact Docker Hub, Quay, GHCR, or another registry for that image
- only run if the image already exists in the selected node's local image store
- fail with an image error if the tag was not built/loaded into minikube

That is why `plan_images(profile)` runs before Helm install.

Practical debugging:

```bash
minikube image ls | grep brix
kubectl -n brix-fleet describe pod <pod-name>
kubectl -n brix-fleet get pods -o wide
```

Common image failures:

```text
ErrImageNeverPull
  The pod has imagePullPolicy: Never, but the selected node does not have the
  requested image tag.

ImagePullBackOff
  Some chart used a pull policy that allows pulling, or an external image is
  referenced and the node cannot pull it.

Wrong tag
  The chart asks for brix-server:dev, but you loaded brix-server:pytest or
  nginx-xrootd-server:latest.
```

## How Kubernetes Knows Which Config To Load

The config path is also explicit in the pod spec. The most important chart is
`charts/topology-role`, the generic "run one nginx-xrootd role" chart.

A topology role has:

```yaml
role:
  name: gsi
  configKey: gsi
  ports:
    - { name: xrootd, port: 11095 }
  data:
    root: /data/xrootd
```

`configKey: gsi` means:

```text
charts/topology-role/configs/gsi.conf
```

The chart creates a ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: <release>-conf
data:
  nginx.conf: |
    user root;
    <rendered contents of configs/<configKey>.conf>
```

Then the Deployment mounts that ConfigMap:

```yaml
volumeMounts:
  - name: config
    mountPath: /etc/brix

volumes:
  - name: config
    configMap:
      name: <release>-conf
```

Inside the container this becomes:

```text
/etc/brix/nginx.conf
```

The server image entrypoint does:

```bash
export NGINX_CONF="${NGINX_CONF:-/etc/brix/nginx.conf}"
nginx -t -c "$NGINX_CONF"
exec nginx -c "$NGINX_CONF" -g 'daemon off;'
```

So the config path is:

```text
values.role.configKey
       |
       v
charts/topology-role/configs/<configKey>.conf
       |
       v
Helm ConfigMap data["nginx.conf"]
       |
       v
Pod volume configMap: <release>-conf
       |
       v
mountPath /etc/brix
       |
       v
/etc/brix/nginx.conf inside the container
       |
       v
server entrypoint runs nginx -c /etc/brix/nginx.conf
```

That is the full answer to "how does Kubernetes know what config to load?" It
does not know the semantic meaning of nginx config. It knows that a ConfigMap
volume should be mounted at `/etc/brix`. The container entrypoint knows to run
nginx with `/etc/brix/nginx.conf`.

## Config, Secrets, Init Containers, And Sidecars

Topology roles can also consume auth material. For example, the fleet GSI role
has:

```yaml
auth:
  caBundle: brix-fleet-ca-bundle
  hostCertSecret: brix-fleet-pki
  crlUrl: http://brix-fleet-grid-ca:8080/crl/test-user.crl.pem
```

This renders volumes and mounts:

```text
caBundle ConfigMap
  -> /etc/grid-security/certificates

hostCertSecret Secret
  -> /etc/grid-security/hostcert.pem
  -> /etc/grid-security/hostkey.pem

crlUrl
  -> init container fetches CRL into an emptyDir
  -> sidecar refreshes CRL periodically
  -> main container sees /etc/brix/crl/crl.pem
```

Token roles are similar:

```yaml
auth:
  jwksUrl: http://brix-fleet-token-issuer:8080/certs/jwks.json
```

That produces:

```text
jwksUrl
  -> init container fetches JWKS into an emptyDir
  -> sidecar refreshes JWKS periodically
  -> main container sees /etc/brix/jwks/jwks.json
```

The pattern is:

```text
authority Service
   |
   | HTTP GET from init container
   v
emptyDir volume shared by pod containers
   |
   +-- main nginx-xrootd container reads file
   |
   +-- refresh sidecar periodically rewrites file
```

Why use an `emptyDir` for CRL/JWKS instead of mounting the ConfigMap directly?
Because the topology roles are testing the production-like behavior where the
server fetches authority material over HTTP and refreshes it over time. The
authority chart still publishes some material as ConfigMaps and Secrets, but
the server roles can consume CRL/JWKS through HTTP URLs.

## The Authority Plane

`charts/auth-authority` creates the lab's test identity and auth services.

It can enable:

```text
service       purpose
------------  ------------------------------------------------------
grid-ca       Serves CA and CRL material over HTTP.
token-issuer  Serves JWKS over HTTP.
voms-service  Serves VOMS-related material when enabled.
krb5-kdc      Runs a test MIT KDC and publishes krb5 material.
bootstrap     Pre-install/pre-upgrade Job that generates PKI/tokens.
```

The bootstrap Job is a Helm hook:

```text
helm install/upgrade auth-authority
       |
       v
pre-install/pre-upgrade RBAC hook
       |
       v
pre-install/pre-upgrade bootstrap Job
       |
       +-- generate CA, host cert, user cert, proxy inputs, CRL, VOMS dir
       |
       +-- generate token signing key and JWKS
       |
       +-- kubectl apply Secret <release>-pki
       |
       +-- kubectl apply ConfigMap <release>-ca-bundle
       |
       +-- kubectl apply ConfigMap <release>-crl
       |
       +-- kubectl apply ConfigMap <release>-jwks
       |
       +-- kubectl apply ConfigMap <release>-vomsdir
       |
       v
authority Deployments mount/publish those objects
```

The bootstrap Job needs RBAC because it creates and updates ConfigMaps and
Secrets inside the namespace. The chart creates:

```text
ServiceAccount <release>-bootstrap
Role           <release>-bootstrap
RoleBinding    <release>-bootstrap
```

The CA and token issuer Deployments are plain nginx static HTTP distributors
using the `brix-authority:dev` image:

```text
<release>-grid-ca Service
  -> Deployment serving /srv/dist/crl and /srv/dist/certs on port 8080

<release>-token-issuer Service
  -> Deployment serving /srv/dist/certs/jwks.json on port 8080
```

The KDC image is separate:

```text
brix-krb5-kdc:dev
  -> runs tests/kdc_helpers.py up
  -> creates <release>-krb5 ConfigMap
  -> updates <release>-pki Secret with keytab material
```

## Services And DNS

Kubernetes Services provide stable names for pods. For a topology role:

```yaml
kind: Service
metadata:
  name: <release-name>
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: topology-role
    app.kubernetes.io/instance: <release-name>
    app.kubernetes.io/component: <role-name>
```

The Service selects pods with matching labels. The pod IP can change; the
Service name remains stable.

Inside the cluster, DNS names are:

```text
<service>.<namespace>.svc.cluster.local
```

Examples:

```text
brix-dev-smoke.brix-dev.svc.cluster.local
brix-fleet-anon.brix-fleet.svc.cluster.local
brix-fleet-grid-ca.brix-fleet.svc.cluster.local
srv.brix-remote.svc.cluster.local
```

Scenario probes usually use the short service name when running in the same
namespace:

```text
root://brix-fleet-anon:11094//file
http://brix-fleet-token-issuer:8080/certs/jwks.json
```

That works because Kubernetes injects namespace-local DNS search paths into pod
resolvers.

Service wiring diagram:

```text
client or probe pod
       |
       | root://brix-fleet-anon:11094
       v
Service brix-fleet-anon
       |
       | selector labels
       v
Pod labels:
  app.kubernetes.io/instance=brix-fleet-anon
  app.kubernetes.io/component=anon
       |
       v
container "anon" port 11094
```

## How Kubernetes Chooses A VM Or Node

Kubernetes pod placement has two stages:

```text
Kubernetes API receives a Pod
       |
       v
scheduler filters and scores available nodes
       |
       v
scheduler writes spec.nodeName
       |
       v
kubelet on that node starts the pod
```

The scheduler considers:

- node readiness
- CPU and memory requests
- taints and tolerations
- node selectors and node affinity
- pod affinity and anti-affinity
- volume constraints
- other scheduling constraints

The lab's default placement mode is portable:

```yaml
nodePinning:
  mode: off
```

When mode is `off`, the chart emits no node placement rules. Kubernetes can put
the pod on any ready node with enough capacity.

The shared helper `brix-common.nodePinning` also supports:

```yaml
nodePinning:
  mode: role
```

In `role` mode the chart emits required pod anti-affinity:

```yaml
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - topologyKey: kubernetes.io/hostname
        labelSelector:
          matchLabels:
            app.kubernetes.io/part-of: brix-test-lab
```

Meaning:

- do not schedule two pods labeled `app.kubernetes.io/part-of=brix-test-lab`
  on the same Kubernetes hostname
- `kubernetes.io/hostname` is effectively the node name topology domain
- if the cluster has enough nodes, lab roles spread one per node
- if the cluster does not have enough nodes, some pods remain `Pending`

Placement diagram:

```text
nodePinning.mode=off

  pod A ----+
            +--> scheduler can place both on node 1
  pod B ----+    if resources allow


nodePinning.mode=role

  pod A --------> node 1
  pod B --------> node 2
  pod C --------> node 3

  pod D --------> Pending if there is no fourth node
                  because required anti-affinity forbids sharing
```

This is how the lab approximates "one role per VM." It does not hard-code
specific VM names. It asks Kubernetes not to co-locate lab pods on the same
node. Kubernetes still chooses the actual node.

To see placement:

```bash
kubectl -n brix-fleet get pods -o wide
kubectl get nodes -o wide
kubectl -n brix-fleet describe pod <pod-name>
```

If a pod is pending because of placement:

```text
0/1 nodes are available: 1 node(s) didn't match pod anti-affinity rules
```

Fixes:

```bash
XRD_LAB_NODES=4 ./xrd-lab up
```

or disable role pinning in the values for that profile or chart invocation.

Special placement-related profiles:

- `fuse` mounts `/dev/fuse` from the node with `hostPath`; the selected node
  must have that device.
- `ceph` creates Rook-Ceph resources using `dataDirHostPath: /var/lib/rook`;
  storage behavior depends on node filesystem state and Rook operator setup.

## Profiles

Profiles live under:

```text
charts/brix-test-lab/values/values.<profile>.yaml
```

Current checked-in profiles:

```text
profile  main enabled charts        purpose
-------  -------------------------  -----------------------------------------
dev      smoke                      Smallest possible build/load/deploy check.

gsi      auth-authority             CA, CRL, token issuer, VOMS authority
                                     services; no server fleet.

token    auth-authority             CA, token issuer, and KDC; no server fleet.

fleet    auth-authority, main-fleet Multi-auth server fleet: anon, gsi, token,
                                     metrics.

cms      cms-mesh                   CMS manager plus data server wired by
                                     Service DNS.

chaos    chaos-mesh                 Tier3 -> tier2 -> tier1 cache path plus
                                     delayed CMS discovery pair.

ceph     backend-ceph               Rook-Ceph CephCluster, block pool, and
                                     filesystem resources. Requires Rook.

fuse     main-fleet, fuse-client    Anon fleet plus privileged FUSE client pod.
```

The image planner in `labtools/lab.py` also mentions a `full` image bucket, but
there is no checked-in `values.full.yaml` profile at the time this document was
written. Do not assume `./xrd-lab deploy full` is a first-class profile until
that values file exists.

## Chart Relationships

The chart layout is intentionally compositional.

```text
brix-test-lab umbrella
    |
    +-- smoke
    |
    +-- auth-authority
    |
    +-- main-fleet
    |      |
    |      +-- topology-role alias anon
    |      +-- topology-role alias gsi
    |      +-- topology-role alias token
    |      +-- topology-role alias metrics
    |
    +-- cms-mesh
    |      |
    |      +-- topology-role alias manager
    |      +-- topology-role alias ds
    |
    +-- chaos-mesh
    |      |
    |      +-- topology-role alias chaos-tier3
    |      +-- topology-role alias chaos-tier2
    |      +-- topology-role alias chaos-tier1
    |      +-- topology-role alias chaos-discovery-redir
    |      +-- topology-role alias chaos-discovery-ds
    |
    +-- backend-ceph
    |
    +-- fuse-client
```

Nearly all charts depend on `brix-common`, a Helm library chart. It provides:

```text
helper                         purpose
-----------------------------  ---------------------------------------------
brix-common.image              Render repository:tag from values.
brix-common.imagePullPolicy    Default to Never for registry-free minikube.
brix-common.labels             Standard labels.
brix-common.selectorLabels     Stable labels used by Service/Deployment.
brix-common.nodePinning        Optional one-role-per-node anti-affinity.
brix-common.networkPolicy      Default-deny ingress allowing lab pods.
brix-common.resourceQuota      Namespace caps for lab-sized profiles.
brix-common.fetchSidecar       CRL/JWKS refresh sidecar.
```

The label helpers are especially important because Services, pod lookup, and
remote-suite `klib.py` all rely on predictable labels.

## The Smoke Profile

The dev profile is deliberately tiny. It proves the full Kubernetes foundation
without bringing in the real server image.

```text
./xrd-lab deploy dev
    |
    +-- minikube image build -t brix-smoke:dev images/smoke
    |
    +-- namespace brix-dev
    |
    +-- helm install brix-dev with values.dev.yaml
            |
            +-- Deployment brix-dev-smoke
            |
            +-- Service brix-dev-smoke
            |
            +-- optional NetworkPolicy
```

The image is `almalinux:9-minimal` plus nginx and a small config:

```text
GET /healthz -> 200 ok
GET /        -> 200 brix smoke
```

The smoke test:

```text
./xrd-lab test smoke
    |
    +-- kubectl run temporary probe pod in brix-dev
    |
    +-- image brix-smoke:dev
    |
    +-- curl http://brix-dev-smoke.brix-dev.svc.cluster.local:8080/healthz
    |
    +-- expect HTTP 200
```

Dry run:

```bash
XRD_LAB_DRY_RUN=1 ./xrd-lab deploy dev
XRD_LAB_DRY_RUN=1 ./xrd-lab test smoke
```

## The Generic Topology Role

`charts/topology-role` is the central chart for real nginx-xrootd server pods.
It can render one server role with:

- a role name
- an image
- an nginx config selected by `configKey`
- one or more ports
- optional upstream references
- optional auth material
- optional start delay
- optional node pinning
- an `emptyDir` data root

Minimal shape:

```yaml
role:
  name: anon
  image: { repository: brix-server, tag: dev, pullPolicy: Never }
  configKey: anon
  ports:
    - { name: xrootd, port: 11094 }
  data:
    root: /data/xrootd
```

Rendered objects:

```text
ConfigMap <release>-conf
Deployment <release>
Service <release>
```

Rendered pod layout:

```text
pod <release>
  |
  +-- container <role.name>
  |     image: brix-server:dev
  |     env:
  |       NGINX_CONF=/etc/brix/nginx.conf
  |     ports:
  |       role.ports[*]
  |     mounts:
  |       /etc/brix       <- ConfigMap
  |       /data/xrootd    <- emptyDir
  |
  +-- optional init containers
  |     start-gate
  |     crl-init
  |     jwks-init
  |
  +-- optional sidecars
        crl-refresh
        jwks-refresh
```

## The Main Fleet

`charts/main-fleet` is not a new server implementation. It is a chart that uses
`topology-role` multiple times through aliases:

```text
main-fleet
  |
  +-- anon    topology-role, configKey anon,    port 11094
  +-- gsi     topology-role, configKey gsi,     port 11095
  +-- token   topology-role, configKey token,   port 11097
  +-- metrics topology-role, configKey metrics, port 9100
```

In the `fleet` profile, authority Services are expected to be named as if the
umbrella release is `brix-fleet`. That is why `values.fleet.yaml` comments that
the profile should be installed as release `brix-fleet`.

Fleet auth wiring:

```text
brix-fleet-grid-ca:8080
    |
    +-- serves /crl/test-user.crl.pem
    |
    v
gsi role init/sidecar fetches CRL

brix-fleet-token-issuer:8080
    |
    +-- serves /certs/jwks.json
    |
    v
token role init/sidecar fetches JWKS

brix-fleet-ca-bundle ConfigMap
    |
    v
gsi role /etc/grid-security/certificates

brix-fleet-pki Secret
    |
    v
gsi role /etc/grid-security/hostcert.pem and hostkey.pem
```

`./xrd-lab test fleet` currently checks:

```text
1. anon xrdcp write/read round-trip through brix-fleet-anon:11094
2. gsi pod reaches Ready, proving authority material was consumed
3. token pod reaches Ready, proving JWKS material was consumed
```

## CMS And Chaos Meshes

`cms` profile:

```text
cms-mesh
  |
  +-- manager
  |     configKey: cluster_redir
  |     ports: xrootd 1094, cms 1096
  |
  +-- ds
        configKey: cluster_ds
        port: xrootd 1094
        upstreams:
          CMS -> manager:1096
```

`./xrd-lab test cms` writes a file to the data server and polls the manager
until `xrdfs locate` sees registration.

`chaos` profile:

```text
chaos-mesh
  |
  +-- chaos-tier3
  |
  +-- chaos-tier2
  |      upstream UPSTREAM -> chaos-tier3:1094
  |
  +-- chaos-tier1
  |      upstream UPSTREAM -> chaos-tier2:1094
  |
  +-- chaos-discovery-redir
  |      ports xrootd 1094, cms 1096
  |      startGate waitSeconds: 12
  |
  +-- chaos-discovery-ds
         upstream CMS -> chaos-discovery-redir:1096
```

`./xrd-lab test chaos` checks:

```text
1. read-through cache path works through tier1 -> tier2 -> tier3
2. delayed CMS discovery eventually registers the data server
```

The `startGate` init container is intentionally simple: it sleeps before the
main container starts. That creates a deterministic delayed-start sequence for
tests that need convergence behavior.

## Dedicated Scenarios

Dedicated single-role scenarios live in:

```text
scenarios/catalog.yaml
```

Each entry names:

- a `configKey`
- one or more ports
- optional auth placeholders
- optional check type
- optional related pytest selection

Example:

```yaml
readonly:
  configKey: readonly
  ports:
    - { name: xrootd, port: 11102 }
  check: write-rejected
  tests: tests/test_readonly.py
```

The catalog renderer turns that into Helm `--set` values:

```text
role.name=readonly
role.configKey=readonly
role.ports[0].name=xrootd
role.ports[0].port=11102
```

`./xrd-lab test readonly` deploys a temporary `topology-role` release in the
`brix-dedicated` namespace, runs the known check, and uninstalls the release.

Auth placeholders are resolved per release:

```text
CA_BUNDLE  -> <release>-ca-bundle
PKI_SECRET -> <release>-pki
VOMSDIR_CM -> <release>-vomsdir
CRL_URL    -> http://<release>-grid-ca:8080/crl/test-user.crl.pem
JWKS_URL   -> http://<release>-token-issuer:8080/certs/jwks.json
```

## The In-Cluster Pytest Paths

There are two related in-cluster pytest flows in `labtools/lab_suite.py`:

```text
./xrd-lab test suite [selection] [extra]
./xrd-lab test remote-suite [selection]
```

### suite

The `suite` scenario deploys:

```text
namespace brix-suite
  |
  +-- auth-authority release "auth"
  |
  +-- topology-role release "srv"
  |     role.name=mono
  |     role.configKey=fleet-mono
  |     ports: anon, gsi, tls, token, metrics
  |
  +-- test-runner release "run"
        image brix-test-runner:dev
        mounted client PKI from auth-pki/auth-jwks
        env TEST_SERVER_HOST=srv-mono
        pytest <selection>
```

This is for running repo tests from the `brix-test-runner:dev` image against a
single multi-port server role.

### remote-suite

The `remote-suite` scenario deploys:

```text
namespace brix-remote
  |
  +-- auth-authority release "auth"
  |
  +-- client-rbac release "brix-remote"
  |     ServiceAccount brix-remote-client
  |     Role allowing pods get/list and pods/exec get/create
  |
  +-- topology-role release "srv"
  |     role.name=mega
  |     role.configKey=fleet-mega
  |     ports: anon, gsi, tls, token, webdav, webdavgtls,
  |            httpdav, crl, s3, metrics, readonly
  |
  +-- test-runner release "run"
        image brix-client:dev
        serviceAccount=brix-remote-client
        mounted client PKI from auth-pki/auth-jwks
        env TEST_SERVER_HOST=srv-mega
        env BRIX_SUITE_NS=brix-remote
        pytest <selection>
```

The `brix-client:dev` image contains:

- the adapted `remote-suite/`
- `pytest`
- xrootd clients
- `kubectl`
- Python Kubernetes client
- `client-pki-init.sh`
- real `pyxrootd` through the Python 3.9 worker path

The test-runner chart renders a Kubernetes Job:

```text
Job run-test-runner
  |
  +-- pod
        |
        +-- container pytest
              image: brix-client:dev or brix-test-runner:dev
              workingDir: /opt/brix
              command:
                mkdir -p "${TEST_ROOT:-/tmp/tr}/data"
                optional client-pki-init.sh
                pytest <selection> -m <marker> <extraArgs>
```

After the Job completes, `lab_suite.py` collects:

```text
kubectl -n <ns> logs job/run-test-runner
kubectl -n <ns> get job run-test-runner -o jsonpath={.status.succeeded}
helm uninstall <releases>
```

## How Remote-Suite Server-Side File Access Works

Some adapted tests need to inspect or mutate files on the server side. They do
that through `remote-suite/tests/klib.py`.

`klib.py` runs inside the client/test pod and uses the official Kubernetes
Python client:

```text
test code
  |
  | klib.svc_read("mega", "/data/xrootd/file")
  v
Kubernetes API in-cluster config
  |
  | list pod with label app.kubernetes.io/component=mega
  v
server pod name
  |
  | connect_get_namespaced_pod_exec
  v
exec command in container "mega"
  |
  | base64 file payload over text websocket
  v
test receives bytes
```

This requires RBAC. `charts/client-rbac` creates:

```text
ServiceAccount <release>-client
Role:
  pods      get,list
  pods/exec get,create
RoleBinding:
  binds the ServiceAccount in the same namespace
```

The `pods/exec` `get` verb matters because the Python client's websocket exec
path uses a GET-style connection. `kubectl exec` commonly needs `create`, so the
Role includes both.

Binary payloads are base64 encoded at the edge because Kubernetes exec
websockets are handled as text in this test helper. Writes use a bounded
`head -c <len>` reader so stdin does not hang waiting for a websocket EOF.

## Remote-Suite Fork And Coverage

The repo's broad test suite lives under top-level `tests/`. The Kubernetes
remote copy lives under:

```text
k8s-tests/remote-suite/tests/
```

`TEST_REGISTRY.md` tracks the file/function inventory and migration state. The
intent is a one-to-one fork of test files where possible, with explicit markers
for files that needed adaptation or should be skipped remotely.

Coverage buckets are computed by `labtools/coverage.py`:

```text
pure_remote   no marker, no obvious server-local path dependency
adapted       file starts with # brix-remote-adapted
verified_ok   file starts with # brix-remote-ok
remote_skip   file starts with # brix-remote-skip
server_local  still appears to depend on local server filesystem/process state
```

The sync helper preserves adapted files:

```text
top-level tests/
       |
       | labtools.sync.sync()
       v
k8s-tests/remote-suite/tests/
       |
       +-- unadapted files can be refreshed
       |
       +-- adapted marker files are not clobbered
```

## Official Ceph Docker Gates

The Ceph/RADOS backend still uses Docker for the live storage cluster because
the harness needs a host-network all-in-one Ceph demo container and a separate
build container with Ceph development packages.  The k8s lab exposes those
Docker gates as official scenarios so they are visible beside the Kubernetes
profiles:

```bash
./xrd-lab test ceph-docker
./xrd-lab test ceph-rpmbuild
```

`ceph-docker` is the always-runnable live Ceph backend gate:

```text
tests/ceph_harness.sh start
       |
       v
single-node Ceph demo cluster, pool xrdtest
       |
       v
docker build tests/ceph/Dockerfile.build
       |
       v
CentOS Stream 9 + Storage SIG Ceph build image
       |
       v
tests/ceph/build_in_container.sh
       |
       v
nginx built with BRIX_HAVE_CEPH inside xrd-ceph-work
       |
       +-- tests/ceph/run_sd_ceph_live.sh
       |
       +-- tests/ceph/ceph_export_smoke.sh
```

The live cluster image and the build image are intentionally different:

```text
Ceph demo image
  Purpose: run MON/MGR/OSD and provide a real RADOS pool.

CentOS Stream 9 Storage SIG build image
  Purpose: install current SIG Ceph devel/runtime packages and compile/test
           the nginx module, driver, and operator tooling against that stack.
```

`ceph-rpmbuild` is the isolated RPM build:

```text
docker build -f k8s-tests/Dockerfiles/rpm-builder/Dockerfile
       |
       +-- BRIX_OS_TARGET=centos9-stream
       +-- BRIX_ENABLE_CEPH_SIG=1
       +-- BRIX_CEPH_SIG_RELEASE=tentacle by default
       |
       v
rpmbuild -ba packaging/rpm/nginx-mod-brix-cache.spec
       |
       v
assert brix-tools RPM contains:
  /usr/bin/xrdceph_striper_migrate
  /usr/bin/xrdceph_cephfs_to_striper
  /usr/bin/xrdrados_rescue
  /usr/bin/xrdcephfs_rescue
  /usr/bin/xrdceph_migrate
  /usr/bin/xrdceph_striper_migrate.py
  /usr/bin/xrdceph_cephfs_to_striper.py
  /usr/libexec/brix/pymigrate/...
  /usr/share/man/man1/xrdceph*.1*
  /usr/share/bash-completion/completions/{xrdceph*,xrdrados_rescue}
```

Use dry-run when you want the exact command list without launching Docker:

```bash
XRD_LAB_DRY_RUN=1 ./xrd-lab test ceph-docker
XRD_LAB_DRY_RUN=1 ./xrd-lab test ceph-rpmbuild
```

## The Lab's Own Tests

The lab has its own pytest suite under `k8s-tests/pytests`.

Fast tier:

```bash
pytest pytests/ -m 'not e2e'
```

This does not require a running cluster. It tests:

- `xrd-lab` command plans as Python lists
- dry-run scenario output
- scenario catalog lint/render
- config import marker mapping
- generated `fleet-mega.conf`
- remote-suite sync and coverage classification
- `klib.py` behavior against an in-memory fake server
- OS target planning for AlmaLinux 9 and CentOS Stream 9
- official Ceph Docker/RPM command plans
- docs/tooling expectations

E2E tier:

```bash
pytest pytests/ -m e2e
```

This needs Docker and minikube. It tests:

- image build/run behavior
- smoke image `/healthz`
- server image contains nginx-xrootd and xrootd client tools
- client image contains pytest, kubectl, kubernetes client, pyxrootd path
- authority image can generate PKI/token material
- live topology deployment/probes
- generated mega config validates with `nginx -t`

Chart tests:

```bash
helm unittest charts/smoke charts/brix-test-lab
```

Schema validation example:

```bash
helm template brix-dev charts/brix-test-lab \
  -f charts/brix-test-lab/values/values.dev.yaml \
  | kubeconform -strict
```

## End-To-End Object Flow

This diagram follows a typical `fleet` deployment from command to running pods:

```text
./xrd-lab deploy fleet
    |
    +-- plan_images("fleet")
    |     |
    |     +-- docker build brix-authority:dev
    |     +-- minikube image load brix-authority:dev
    |     +-- docker build brix-server:dev
    |     +-- minikube image load brix-server:dev
    |     +-- docker build brix-test-runner:dev
    |     +-- minikube image load brix-test-runner:dev
    |
    +-- kubectl create namespace brix-fleet
    |
    +-- helm dependency build charts/brix-test-lab
    |
    +-- helm upgrade --install brix-fleet charts/brix-test-lab
          -f values/values.fleet.yaml
          |
          +-- auth-authority
          |     |
          |     +-- bootstrap RBAC
          |     +-- bootstrap Job creates pki Secret and ConfigMaps
          |     +-- grid-ca Deployment + Service
          |     +-- token-issuer Deployment + Service
          |     +-- voms-service Deployment + Service
          |
          +-- main-fleet
                |
                +-- topology-role anon
                |     +-- ConfigMap brix-fleet-anon-conf
                |     +-- Deployment brix-fleet-anon
                |     +-- Service brix-fleet-anon
                |
                +-- topology-role gsi
                |     +-- ConfigMap brix-fleet-gsi-conf
                |     +-- Deployment brix-fleet-gsi
                |     +-- Service brix-fleet-gsi
                |
                +-- topology-role token
                |
                +-- topology-role metrics
```

Kubernetes then schedules the pods:

```text
unscheduled pods in API
       |
       v
scheduler
       |
       +-- check resources
       +-- check anti-affinity if nodePinning.mode=role
       +-- check volume constraints
       |
       v
pod.spec.nodeName assigned
       |
       v
kubelet on selected node
       |
       +-- find image locally because pullPolicy Never
       +-- mount ConfigMaps, Secrets, emptyDirs
       +-- run init containers
       +-- run main containers
       +-- run sidecars
```

## Inspecting What Helm Will Submit

To see what Kubernetes will receive before it receives it:

```bash
helm dependency build charts/brix-test-lab

helm template brix-fleet charts/brix-test-lab \
  --namespace brix-fleet \
  --values charts/brix-test-lab/values/values.fleet.yaml
```

Useful filters:

```bash
helm template brix-fleet charts/brix-test-lab \
  -f charts/brix-test-lab/values/values.fleet.yaml \
  | yq 'select(.kind == "Deployment") | .metadata.name'

helm template brix-fleet charts/brix-test-lab \
  -f charts/brix-test-lab/values/values.fleet.yaml \
  | yq 'select(.kind == "ConfigMap") | .metadata.name'

helm template brix-fleet charts/brix-test-lab \
  -f charts/brix-test-lab/values/values.fleet.yaml \
  | yq 'select(.kind == "Service") | .metadata.name'
```

To inspect a live release:

```bash
helm -n brix-fleet status brix-fleet
helm -n brix-fleet get values brix-fleet
helm -n brix-fleet get manifest brix-fleet
```

## Debugging Kubernetes Decisions

### What command would xrd-lab run?

```bash
XRD_LAB_DRY_RUN=1 ./xrd-lab up
XRD_LAB_DRY_RUN=1 ./xrd-lab deploy fleet
XRD_LAB_DRY_RUN=1 ./xrd-lab test remote-suite
```

Dry-run is often the fastest way to answer "where did this value come from?"

### Did the cluster start?

```bash
kubectl get nodes -o wide
kubectl get pods -A
minikube status
```

### Which node got a pod?

```bash
kubectl -n brix-chaos get pods -o wide
kubectl -n brix-chaos describe pod <pod-name>
```

Look for:

```text
Node:
Events:
  Scheduled
  FailedScheduling
```

### Which image did Kubernetes try to run?

```bash
kubectl -n brix-fleet get pod <pod-name> \
  -o jsonpath='{.spec.containers[*].image}{"\n"}'

kubectl -n brix-fleet describe pod <pod-name>
```

Check loaded images:

```bash
minikube image ls | grep brix
```

### Which config is mounted?

```bash
kubectl -n brix-fleet get configmap
kubectl -n brix-fleet get configmap brix-fleet-gsi-conf -o yaml

kubectl -n brix-fleet exec deploy/brix-fleet-gsi -c gsi -- \
  sh -c 'ls -l /etc/brix && sed -n "1,80p" /etc/brix/nginx.conf'
```

### Did init containers fetch CRL or JWKS?

```bash
kubectl -n brix-fleet describe pod <gsi-pod>
kubectl -n brix-fleet logs <gsi-pod> -c crl-init
kubectl -n brix-fleet logs <gsi-pod> -c crl-refresh

kubectl -n brix-fleet exec <gsi-pod> -c gsi -- \
  ls -l /etc/brix/crl
```

### Did the authority bootstrap create material?

```bash
kubectl -n brix-fleet get jobs
kubectl -n brix-fleet logs job/brix-fleet-bootstrap
kubectl -n brix-fleet get secret brix-fleet-pki
kubectl -n brix-fleet get configmap brix-fleet-ca-bundle
kubectl -n brix-fleet get configmap brix-fleet-jwks
```

### Why is a Service not routing?

Check labels and selectors:

```bash
kubectl -n brix-fleet get svc brix-fleet-anon -o yaml
kubectl -n brix-fleet get pods --show-labels
kubectl -n brix-fleet get endpoints brix-fleet-anon -o yaml
```

If `endpoints` is empty, the Service selector does not match any Ready pod.

### Why did a pytest Job fail?

```bash
kubectl -n brix-remote get jobs
kubectl -n brix-remote describe job run-test-runner
kubectl -n brix-remote logs job/run-test-runner
kubectl -n brix-remote get pod -l job-name=run-test-runner -o wide
```

For remote-suite RBAC issues:

```bash
kubectl -n brix-remote auth can-i get pods/exec \
  --as system:serviceaccount:brix-remote:brix-remote-client

kubectl -n brix-remote auth can-i create pods/exec \
  --as system:serviceaccount:brix-remote:brix-remote-client
```

## Adding A New Profile

To add a new umbrella profile:

1. Create `charts/brix-test-lab/values/values.<name>.yaml`.
2. Enable the subcharts needed by the profile.
3. Set image repository/tag/pullPolicy values if they differ from defaults.
4. Add image build/load logic to `_IMAGES` in `labtools/lab.py` if the profile
   needs local images that are not already loaded.
5. Run:

```bash
XRD_LAB_DRY_RUN=1 ./xrd-lab deploy <name>
helm dependency build charts/brix-test-lab
helm template brix-<name> charts/brix-test-lab \
  -f charts/brix-test-lab/values/values.<name>.yaml
```

6. Add or update lab tests under `pytests/` if this is a first-class profile.

Remember: a profile is only real to Kubernetes after Helm values render concrete
Kubernetes objects.

## Adding A New Topology Role

If the role can be represented by `topology-role`, prefer that. Usually you need:

1. Add a config file:

```text
charts/topology-role/configs/<key>.conf
```

2. Add values through an alias chart or a catalog entry:

```yaml
role:
  name: new-role
  configKey: <key>
  ports:
    - { name: xrootd, port: 12345 }
```

3. If it belongs to a multi-role chart, add a `topology-role` alias dependency
   in that chart's `Chart.yaml`.
4. Wire `upstreams` or auth values through Helm values, not hard-coded service
   names in ad-hoc scripts.
5. Render before running:

```bash
helm template test charts/topology-role \
  --set role.name=new-role \
  --set role.configKey=<key> \
  --set role.ports[0].name=xrootd \
  --set role.ports[0].port=12345
```

## Adding A New Image

If a new chart needs a new local image:

1. Put the Dockerfile under `images/<name>/Dockerfile`.
2. Decide the canonical tag, usually `brix-<name>:dev`.
3. Add the profile/image mapping to `_IMAGES` in `labtools/lab.py`.
4. Use `imagePullPolicy: Never` for local minikube-only images.
5. Add an image test under `pytests/test_images.py` if the contents matter.

Image rule of thumb:

```text
If Kubernetes sees imagePullPolicy: Never, xrd-lab must build/load that exact
tag before Helm creates pods that reference it.
```

## Adding A New Dedicated Scenario

For a one-role scenario:

1. Add or reuse `charts/topology-role/configs/<configKey>.conf`.
2. Add an entry to `scenarios/catalog.yaml`.
3. Run the fast catalog tests:

```bash
pytest pytests/test_config.py -m 'not e2e'
```

4. Dry-run it:

```bash
XRD_LAB_DRY_RUN=1 ./xrd-lab test <scenario-name>
```

5. If possible, add a client-observable check to `labtools.lab.scenario_dedicated`.

## NetworkPolicy And ResourceQuota

`brix-common` provides optional security and resource controls.

NetworkPolicy:

```text
default-deny ingress for the selected pods
allow ingress only from pods labeled:
  app.kubernetes.io/part-of=brix-test-lab
```

ResourceQuota:

```text
requests.cpu:    8
requests.memory: 16Gi
limits.cpu:      16
limits.memory:   32Gi
pods:            50
```

The smoke profile enables NetworkPolicy and disables ResourceQuota by default.
Other profiles can opt in through their values.

## Common Failure Modes

### Pod says ErrImageNeverPull

Cause:

```text
The selected node does not have the exact image tag and the pod says
imagePullPolicy: Never.
```

Check:

```bash
minikube image ls | grep brix-server
kubectl -n <ns> describe pod <pod>
```

Fix:

```bash
./xrd-lab deploy <profile>
```

or manually build/load the missing tag.

### Pod is Pending

Likely causes:

- not enough nodes for required pod anti-affinity
- not enough CPU or memory
- missing hostPath device such as `/dev/fuse`
- storage/operator constraints for Ceph/Rook

Check:

```bash
kubectl -n <ns> describe pod <pod>
kubectl get nodes -o wide
```

### nginx container starts then exits

Likely causes:

- rendered config is invalid
- mounted auth file is missing
- configKey points at the wrong config
- expected port/upstream value was not supplied

Check:

```bash
kubectl -n <ns> logs <pod> -c <container>
kubectl -n <ns> get configmap <release>-conf -o yaml
kubectl -n <ns> exec <pod> -c <container> -- nginx -t -c /etc/brix/nginx.conf
```

### GSI/token role is not Ready

Likely causes:

- authority bootstrap failed
- CRL/JWKS URL points at the wrong release name
- init container cannot reach the authority Service
- Secret or ConfigMap name mismatch

Check:

```bash
kubectl -n <ns> get pods
kubectl -n <ns> logs job/<release>-bootstrap
kubectl -n <ns> describe pod <server-pod>
kubectl -n <ns> logs <server-pod> -c crl-init
kubectl -n <ns> logs <server-pod> -c jwks-init
```

### Service DNS fails

Check from a pod in the same namespace:

```bash
kubectl -n <ns> run dns-probe --rm -i --restart=Never \
  --image=brix-authority:dev --image-pull-policy=Never \
  --command -- bash -lc 'getent hosts <service> && curl -v http://<service>:8080/healthz'
```

If DNS resolves but traffic fails, inspect Service endpoints:

```bash
kubectl -n <ns> get endpoints <service> -o yaml
```

### Remote-suite cannot exec into server pod

Likely causes:

- `client-rbac` chart not installed
- test-runner Job uses wrong ServiceAccount
- RoleBinding subject namespace mismatch
- service/component label mismatch

Check:

```bash
kubectl -n brix-remote get sa,role,rolebinding
kubectl -n brix-remote get pods --show-labels
kubectl -n brix-remote logs job/run-test-runner
```

## Mental Model

The cleanest way to reason about the lab is:

```text
1. xrd-lab chooses a profile and exact commands.

2. The profile chooses Helm subcharts and values.

3. Helm renders ordinary Kubernetes objects.

4. Pod specs choose images, pull policies, env, ports, volumes, and placement
   rules.

5. ConfigMaps and Secrets provide files. They do not configure nginx by magic;
   they are mounted where the container entrypoint expects them.

6. Services provide stable DNS names by selecting pods with labels.

7. The scheduler chooses a node. The lab can influence placement with
   anti-affinity, but Kubernetes makes the placement decision.

8. Kubelet on the selected node starts containers from the node image store,
   mounts volumes, runs init containers, then starts main containers and
   sidecars.

9. Scenario probes and pytest Jobs validate behavior from inside the cluster.
```

When debugging, follow that same order. Most failures are visible at exactly one
of those boundaries: image not loaded, wrong Helm value, missing ConfigMap,
wrong Service selector, insufficient nodes, failed init container, or failing
pytest Job.
