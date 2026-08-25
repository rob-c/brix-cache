"""Managed authentication services rendered inside a Kubernetes case."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Mapping

from brixtest.auth.kerberos import KerberosRealm, kdc_projection
from brixtest.auth.models import KerberosAuth
from brixtest.design import binary
from brixtest.errors import CaseRunError, SpecError
from brixtest.runtime.images import OCIImageStore
from brixtest.runtime.kubernetes_manifests import secure_secret_resource


def _plugins() -> tuple[Path, ...]:
    found = set(_kdb_plugins())
    found.update(_verto_plugins())
    if not found:
        raise SpecError(
            "Kubernetes Kerberos KDC", "KDB plugins",
            "no MIT Kerberos database plugin was found under /usr/lib or /usr/lib64",
        )
    return tuple(sorted(found))


def _kdb_plugins() -> tuple[Path, ...]:
    return tuple({
        path.resolve()
        for root in (Path("/usr/lib64"), Path("/usr/lib"))
        for pattern in ("krb5/plugins/kdb/*.so", "*/krb5/plugins/kdb/*.so")
        for path in root.glob(pattern)
        if path.is_file()
    })


def _verto_plugins() -> tuple[Path, ...]:
    candidates = (
        Path("/usr/lib64/libverto-libev.so.1"), Path("/lib64/libverto-libev.so.1"),
    )
    return tuple(path for path in candidates if path.is_file())


def _tool(name: str) -> Path:
    selected = shutil.which(name)
    if selected is None:
        raise SpecError("Kubernetes Kerberos KDC", name, "is not installed or on PATH")
    return Path(selected)


def _captured_tools(backend, recipe: KerberosAuth):
    suffix = recipe.name.replace("-", "_")
    plugins = _plugins()
    kdc = binary(
        "brixtest_kdc_%s" % suffix, _tool("krb5kdc"), libraries=plugins,
        runtime_files={str(path): path for path in plugins},
    )
    copier = binary(
        "brixtest_kdc_copy_%s" % suffix, _tool("cp"),
    )
    captured = backend.owner.binary_store.capture_all((kdc, copier))
    return captured[kdc.name], captured[copier.name]


def _image(backend, recipe: KerberosAuth):
    registry = os.environ.get("BRIXTEST_OCI_REGISTRY", "")
    if backend.owner.backend_name != "minikube" and not registry:
        raise SpecError(
            "Kubernetes Kerberos KDC", backend.owner.backend_name,
            "requires backend='minikube' or a configured BriXTest OCI registry",
        )
    kdc, copier = _captured_tools(backend, recipe)
    store = OCIImageStore(
        backend.owner, backend.context or "brixtest", registry=registry,
    )
    generated = store.build("auth-kdc-%s" % recipe.name, (kdc, copier))
    return generated, generated.paths[kdc.name], generated.paths[copier.name]


def _labels(recipe: KerberosAuth, namespace: str) -> dict[str, str]:
    return {
        "app.kubernetes.io/managed-by": "brixtest",
        "app.kubernetes.io/name": "kdc-%s" % recipe.name.replace("_", "-"),
        "brixtest.io/case": namespace,
        "brixtest.io/authority": recipe.name,
    }


def _container(recipe, image, kdc_path, port) -> dict:
    return {
        "name": "kdc", "image": image,
        "imagePullPolicy": "Never" if image.startswith("brixtest.local/") else "IfNotPresent",
        "command": [kdc_path, "-n", "-r", recipe.realm],
        "env": [
            {"name": "KRB5_CONFIG", "value": "/realm/krb5-kubernetes.conf"},
            {"name": "KRB5_KDC_PROFILE", "value": "/realm/kdc-kubernetes.conf"},
        ],
        "ports": [
            {"name": "kerberos-tcp", "containerPort": port, "protocol": "TCP"},
            {"name": "kerberos-udp", "containerPort": port, "protocol": "UDP"},
        ],
        "volumeMounts": [{"name": "realm", "mountPath": "/realm"}],
        "readinessProbe": {"tcpSocket": {"port": port}, "periodSeconds": 1},
        "securityContext": {
            "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "resources": {
            "requests": {"cpu": "10m", "memory": "32Mi"},
            "limits": {"cpu": "250m", "memory": "128Mi"},
        },
    }


def _documents(backend, recipe, realm, image, kdc_path, copy_path):
    name = "kdc-%s" % recipe.name.replace("_", "-")
    secret, items = secure_secret_resource(
        backend.namespace, kdc_projection(realm), name=name + "-seed",
    )
    for item in items:
        item["mode"] = 0o600
    labels = _labels(recipe, backend.namespace)
    port = int(realm.metadata["port"])
    pod_spec = {
        "automountServiceAccountToken": False,
        "restartPolicy": "Always",
        "initContainers": [{
            "name": "seed", "image": image,
            "imagePullPolicy": "Never" if image.startswith("brixtest.local/") else "IfNotPresent",
            "command": [copy_path, "-a", "/seed/.", "/realm/"],
            "volumeMounts": [
                {"name": "seed", "mountPath": "/seed", "readOnly": True},
                {"name": "realm", "mountPath": "/realm"},
            ],
            "securityContext": {
                "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            },
        }],
        "containers": [_container(recipe, image, kdc_path, port)],
        "volumes": [
            {"name": "seed", "secret": {"secretName": name + "-seed", "items": items}},
            {"name": "realm", "emptyDir": {}},
        ],
    }
    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": backend.namespace, "labels": labels},
        "spec": {
            "replicas": 1 if recipe.start_kdc else 0,
            "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": pod_spec},
        },
    }
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": name, "namespace": backend.namespace, "labels": labels},
        "spec": {"selector": labels, "ports": [
            {"name": "kerberos-tcp", "port": port, "targetPort": port, "protocol": "TCP"},
            {"name": "kerberos-udp", "port": port, "targetPort": port, "protocol": "UDP"},
        ]},
    }
    return name, (secret, deployment, service)


def _authority_aliases(backend, name: str) -> None:
    default = backend.environments.default
    hostname = "%s.%s.svc.%s" % (name, default.namespace, default.dns_domain)
    for target in backend.environments.targets:
        if (target.context, target.namespace) == (default.context, default.namespace):
            continue
        if target.context != default.context:
            continue
        backend._apply([{
            "apiVersion": "v1", "kind": "Service",
            "metadata": {
                "name": name, "namespace": target.namespace,
                "labels": {"brixtest.io/authority-alias": name},
            },
            "spec": {"type": "ExternalName", "externalName": hostname},
        }], context=target.context)


class KubernetesKDC:
    """Coordinate one remote deployment with its retained local authority."""

    def __init__(self, backend, item, local, resource: str, uids: Mapping[str, str]) -> None:
        self.backend = backend
        self.item = item
        self.local = local
        self.resource = resource
        self.uids = dict(uids)

    def available(self) -> bool:
        try:
            result = self.backend._run(
                "-n", self.backend.namespace, "get", "deployment/" + self.resource,
                "-o", "json", timeout=5.0,
            )
            status = json.loads(result.stdout).get("status", {})
            return bool(status.get("readyReplicas")) and self.local.available()
        except (CaseRunError, AttributeError, ValueError):
            return False

    def stop(self) -> None:
        self.backend._run(
            "-n", self.backend.namespace, "scale", "deployment/" + self.resource,
            "--replicas=0", timeout=15.0,
        )
        self.local.stop()

    def start(self) -> None:
        self.local.start()
        self.backend._run(
            "-n", self.backend.namespace, "scale", "deployment/" + self.resource,
            "--replicas=1", timeout=15.0,
        )
        self.backend._run(
            "-n", self.backend.namespace, "rollout", "status",
            "deployment/" + self.resource, "--timeout=30s", timeout=35.0,
        )

    def collect_and_delete(self) -> list[str]:
        errors = []
        self._collect(errors)
        try:
            self.backend._run(
                "-n", self.backend.namespace, "delete", "deployment/" + self.resource,
                "--ignore-not-found=true", "--wait=true", timeout=30.0,
            )
        except CaseRunError as exc:
            errors.append(str(exc))
        return errors

    def _collect(self, errors: list[str]) -> None:
        self._collect_observation(errors)
        try:
            result = self.backend._run(
                "-n", self.backend.namespace, "logs", "deployment/" + self.resource,
                "--all-containers=true", "--prefix=true", timeout=15.0,
            )
            path = self.backend.owner.root / "runtime/logs/auth" / (self.item.name + ".log")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(result.stdout)
            self.backend.owner.evidence.attach(
                path, name="auth-%s-log" % self.item.name, role="authority-log",
                description="Kubernetes Kerberos KDC output",
            )
        except CaseRunError as exc:
            errors.append(str(exc))

    def _collect_observation(self, errors: list[str]) -> None:
        try:
            pods = self.backend._run(
                "-n", self.backend.namespace, "get", "pods", "-l",
                "brixtest.io/authority=" + self.item.name, "-o", "json", timeout=15.0,
            )
            events = self.backend._run(
                "-n", self.backend.namespace, "get", "events", "-o", "json",
                timeout=15.0,
            )
            self.backend.owner.evidence.attach_json(
                "auth-%s-kubernetes.json" % self.item.name,
                {"pods": json.loads(pods.stdout), "events": json.loads(events.stdout)},
                role="authority-status",
                description="Kubernetes Kerberos status and namespace events",
            )
        except (CaseRunError, ValueError) as exc:
            errors.append(str(exc))


def _uids(backend, documents) -> dict[str, str]:
    selected = {}
    for document in documents:
        kind = str(document["kind"]).lower()
        name = str(document["metadata"]["name"])
        result = backend._run(
            "-n", backend.namespace, "get", kind, name, "-o", "json",
        )
        payload = json.loads(result.stdout)
        uid = str(payload.get("metadata", {}).get("uid", ""))
        selected[kind + "/" + name] = uid
        backend.owner.evidence.event("kubernetes-resource", {
            "api_version": document["apiVersion"], "kind": document["kind"],
            "name": name, "namespace": backend.namespace, "uid": uid,
            "owned": True, "authority": document["metadata"]["labels"].get(
                "brixtest.io/authority", "",
            ),
        })
    return selected


def start_kubernetes_auth_services(backend) -> None:
    """Create every declared Kerberos authority before dependent workloads."""
    recipes = {item.name: item for item in backend.owner.definition.auth}
    for item in backend.owner.security.auth._items.values():
        recipe = recipes[item.name]
        if not isinstance(recipe, KerberosAuth):
            continue
        local = getattr(item, "_authority_controller")
        if not isinstance(local, KerberosRealm):
            raise SpecError("Kubernetes Kerberos KDC", item.name, "has no local realm state")
        generated, kdc_path, copy_path = _image(backend, recipe)
        resource, documents = _documents(
            backend, recipe, local, generated.tag, kdc_path, copy_path,
        )
        backend._apply(documents)
        _authority_aliases(backend, resource)
        controller = KubernetesKDC(backend, item, local, resource, _uids(backend, documents))
        backend._auth_services[item.name] = controller
        object.__setattr__(item, "_authority_controller", controller)
        if recipe.start_kdc:
            backend._run(
                "-n", backend.namespace, "rollout", "status",
                "deployment/" + resource, "--timeout=60s", timeout=65.0,
            )
        backend.owner.evidence.event("authority-service", {
            "name": item.name, "kind": "kerberos", "backend": "kubernetes",
            "host": resource, "port": local.metadata["port"],
            "protocols": ["tcp", "udp"], "image": generated.tag,
        })


def close_kubernetes_auth_services(backend) -> list[str]:
    """Archive and quiesce remote authorities before namespace deletion."""
    errors = []
    for controller in reversed(tuple(backend._auth_services.values())):
        errors.extend(controller.collect_and_delete())
    backend._auth_services.clear()
    return errors


def authority_endpoints(backend) -> dict[str, int]:
    """Return declared authority ports for dependency-derived network policy."""
    return {
        name: int(controller.local.metadata["port"])
        for name, controller in backend._auth_services.items()
    }


__all__ = [
    "KubernetesKDC", "authority_endpoints", "close_kubernetes_auth_services",
    "start_kubernetes_auth_services",
]
