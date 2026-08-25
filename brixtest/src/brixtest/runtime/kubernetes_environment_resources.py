"""Create credentials and UID-safe namespaces for every case environment."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Sequence

from brixtest.errors import CaseRunError
from brixtest.runtime.kubernetes_manifests import (
    _secret_environment, secure_secret_resource,
)
from brixtest.runtime.kubernetes_ownership import write_ownership


class KubernetesEnvironmentResourcesMixin:
    """Own per-context namespaces and role-scoped Secret projections."""

    def _create_case_secrets(self) -> tuple[str, Sequence[dict]]:
        owner = self.owner
        server_files = owner.security.secure_files("server")
        client_files = owner.security.secure_files("client")
        server_name = "brixtest-secure" if server_files else ""
        server_items: Sequence[dict] = ()
        if server_files:
            _unused, server_items = secure_secret_resource(
                self.namespace, server_files, name=server_name,
            )
        self._prepare_client_secret_metadata(client_files)
        for target in self.environments.targets:
            self._create_environment_namespace(target)
            self._project_environment_secrets(
                target, server_files, server_name, server_items, client_files,
            )
        return server_name, server_items

    def _prepare_client_secret_metadata(self, client_files) -> None:
        if not client_files:
            return
        self._client_secure_secret = "brixtest-client-secure"
        _unused, self._client_secure_items = secure_secret_resource(
            self.namespace, client_files, name=self._client_secure_secret,
        )
        self._client_secret_environment.update(_secret_environment(
            client_files, self._client_secure_items,
            self.owner.security.environment("client"),
        ))

    def _create_environment_namespace(self, target) -> None:
        labels = {
            "app.kubernetes.io/managed-by": "brixtest",
            "brixtest.io/test-instance": self.test_instance,
            "brixtest.io/environment": target.name,
        }
        self._apply([{
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": target.namespace, "labels": labels},
        }], context=target.context)
        uid = self._read_namespace_uid(target.namespace, target.context)
        identity = target.context, target.namespace
        self._namespace_uids[identity] = uid
        if target.namespace == self.namespace and target.context == self.context:
            self._namespace_uid = uid
        environment = "" if identity == (self.context, self.namespace) else target.name
        record = write_ownership(
            self.owner.root, target.namespace, uid, environment=environment,
        )
        self.owner.evidence.event("kubernetes-resource", {
            "api_version": "v1", "kind": "Namespace", "name": target.namespace,
            "uid": uid, "context": target.context, "environment": target.name,
            "owned": True, "ownership_record": str(record),
        })
        self._namespace_created = True

    def _project_environment_secrets(
        self, target, server_files, server_name, server_items, client_files,
    ) -> None:
        documents = (
            self._environment_server_secret(target, server_files, server_name),
            self._environment_client_secret(target, client_files),
        )
        self._apply_environment_secrets(target, documents)

    def _environment_server_secret(self, target, files, name):
        if not files or not self.environments.has_resource(target, "server"):
            return None
        secret, _unused = secure_secret_resource(target.namespace, files, name=name)
        return secret

    def _environment_client_secret(self, target, files):
        consumes = self.environments.has_resource(
            target, "client",
        ) or self.environments.has_resource(target, "task")
        if not files or not consumes:
            return None
        secret, _unused = secure_secret_resource(
            target.namespace, files, name=self._client_secure_secret,
        )
        return secret

    def _apply_environment_secrets(self, target, candidates) -> None:
        documents = [item for item in candidates if item is not None]
        if documents:
            self._apply(documents, context=target.context)

    def _read_namespace_uid(self, namespace: str = "", context: str = "") -> str:
        selected = namespace or self.namespace
        result = self._run(
            "get", "namespace", selected, "-o", "json", context=context,
        )
        try:
            uid = json.loads(result.stdout)["metadata"]["uid"]
        except (KeyError, TypeError, ValueError) as exc:
            raise CaseRunError(
                self.owner.nodeid, "kubernetes ownership",
                "namespace %s has no readable UID" % selected,
            ) from exc
        if not isinstance(uid, str) or not uid:
            raise CaseRunError(
                self.owner.nodeid, "kubernetes ownership",
                "namespace %s returned an invalid UID" % selected,
            )
        return uid

    def _delete_environment_namespaces(self) -> list[str]:
        errors = []
        environments = getattr(self, "environments", None)
        targets = environments.targets if environments is not None else (
            SimpleNamespace(
                namespace=self.namespace, context=getattr(self, "context", ""),
            ),
        )
        for target in reversed(targets):
            error = self._delete_environment_namespace(target)
            if error:
                errors.append(error)
        if not errors:
            self._namespace_created = False
        return errors

    def _delete_environment_namespace(self, target) -> str:
        identity = target.context, target.namespace
        owned_uid = getattr(self, "_namespace_uids", {}).get(
            identity, getattr(self, "_namespace_uid", ""),
        )
        try:
            observed_uid = self._read_namespace_uid(target.namespace, target.context)
            if observed_uid != owned_uid:
                return "refusing to delete namespace %s: owned UID %s, observed UID %s" % (
                    target.namespace, owned_uid, observed_uid,
                )
            self._run(
                "delete", "namespace", target.namespace, "--wait=false",
                timeout=20.0, context=target.context,
            )
        except CaseRunError as exc:
            return str(exc)
        return ""


__all__ = ["KubernetesEnvironmentResourcesMixin"]
