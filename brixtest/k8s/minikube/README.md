# BriXTest Minikube profile

This profile exercises the normal Kubernetes engine through
`backend="minikube"` against a local
Docker-driven Minikube cluster. BriXTest creates a unique namespace, projects
server-only credentials through a Kubernetes Secret, starts the declared
server, forwards its allocated port, archives its logs, and deletes the
namespace during teardown. The live case also launches a first-class tool Pod,
injects its bearer token through `SecretKeyRef`, checks in-cluster service DNS,
and captures its result through the normal `run.tool(...)` API. It uses a
dedicated `brixtest` Minikube profile and
does not modify or delete other local profiles.

From the BriXTest project root:

```console
brixtest minikube start
brixtest minikube test
brixtest --json minikube status
```

`test` loads the digest-pinned `alpine/socat` image already named by
`cluster.json`; it does not build or import anything outside this sub-project.
It first verifies that the host, kubelet, and API server are all running and
reports the exact `start` command when the dedicated profile is not ready.
The cluster is deliberately not deleted after the test so repeated runs are
fast. `minikube delete -p brixtest` remains an explicit operator action.
