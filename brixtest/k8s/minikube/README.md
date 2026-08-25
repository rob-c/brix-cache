# BriXTest Minikube profile

This profile exercises the normal Kubernetes engine through
`backend="minikube"` against a local
Docker-driven Minikube cluster. BriXTest creates a unique namespace, projects
server-only credentials through a Kubernetes Secret, starts the declared
servers, forwards TCP and binary UDP traffic, archives their logs, and deletes the
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

`test` loads the digest-pinned `alpine/socat` server and official Python helper
runtime already named by `cluster.json`; it does not build or import anything
outside this sub-project. The Python image needs no BriXTest installation:
the framework streams its content-addressed helper bundle into the Job. The
live suite proves the helper's ServiceAccount identity/RBAC restriction,
force-cleans a deliberately hung remote test, and runs binary-safe
`service.fs` assertions through the restricted shared-volume sidecar.
It first verifies that the host, kubelet, and API server are all running and
reports the exact `start` command when the dedicated profile is not ready.
The cluster is deliberately not deleted after the test so repeated runs are
fast. `minikube delete -p brixtest` remains an explicit operator action.
