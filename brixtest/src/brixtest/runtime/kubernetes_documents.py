"""Owned Kubernetes document application and workload controls."""

import json
from types import SimpleNamespace
from typing import Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.runtime.kubernetes_manifests import _resource_name


def _graph_node_label(labels: Mapping[str, object]) -> str:
    for key, prefix in (
        ("brixtest.io/workload", "server"),
        ("brixtest.io/identity", "identity"),
        ("brixtest.io/task", "task"),
        ("brixtest.io/authority", "authority"),
        ("brixtest.io/group", "group"),
    ):
        value = str(labels.get(key, ""))
        if value:
            return ("%s.%s" % (prefix, value)).replace("_", "-")[:63]
    value = str(labels.get("app.kubernetes.io/name", "case"))
    return ("resource.%s" % value).replace("_", "-")[:63]


class KubernetesDocumentMixin:
    """Apply labelled documents and control their typed server workloads."""

    def signal(self, name: str, signal_name: str) -> None:
        """Send a conventional POSIX signal to PID 1 in one server pod."""
        if signal_name not in ("TERM", "INT", "QUIT", "KILL", "HUP", "USR1", "USR2"):
            raise SpecError("Kubernetes server signal", signal_name, "has an unknown signal name")
        target = self._server_target(name)
        self._run(
            "-n", target.namespace, "exec", self._workload_resource(name),
            "-c", self._container_name(name), "--",
            "kill", "-s", signal_name, "1", timeout=15.0,
            context=target.context,
        )

    def restart(self, name: str) -> None:
        """Roll out a fresh pod from the captured immutable workload."""
        target = self._server_target(name)
        resource = self._workload_resource(name)
        self._run(
            "-n", target.namespace, "rollout", "restart", resource,
            context=target.context,
        )
        self._run(
            "-n", target.namespace, "rollout", "status", resource,
            "--timeout=60s", timeout=65.0,
            context=target.context,
        )

    def _workload_resource(self, name: str) -> str:
        kind = self._workload_kinds.get(name, "deployment")
        realized = getattr(self, "_workload_names", {}).get(name, _resource_name(name))
        return "%s/%s" % (kind, realized)

    def _workload_selector(self, name: str) -> str:
        return getattr(self, "_workload_selectors", {}).get(
            name, "app.kubernetes.io/name=%s" % _resource_name(name),
        )

    def _container_name(self, name: str) -> str:
        grouped = name in getattr(self, "_workload_selectors", {}) and (
            getattr(self, "_workload_selectors", {}).get(name, "").startswith(
                "brixtest.io/group="
            )
        )
        return _resource_name(name) if grouped else "server"

    def _server_target(self, name: str):
        environments = getattr(self, "environments", None)
        if environments is not None:
            return environments.for_server(name)
        return SimpleNamespace(
            namespace=self.namespace, context=getattr(self, "context", ""),
            name="default",
        )

    def _apply(self, documents: Sequence[dict], *, context: str = "") -> None:
        selected = self._owned_documents(documents, context)
        text = "\n---\n".join(json.dumps(item) for item in selected) + "\n"
        self._run("apply", "-f", "-", **self._apply_options(text, context))
        self._record_applied_documents(selected, context)

    def _owned_documents(self, documents, context: str) -> list[dict]:
        return [self._owned_document(item, context=context) for item in documents]

    @staticmethod
    def _apply_options(text: str, context: str) -> dict[str, str]:
        options = {"input_text": text}
        if context:
            options["context"] = context
        return options

    def _record_applied_documents(self, selected, context: str) -> None:
        for item in selected:
            self._record_applied_document(item, context=context)

    def _owned_document(self, document: Mapping[str, object], *, context: str = "") -> dict:
        selected = dict(document)
        metadata = dict(selected.get("metadata", {}))
        labels = dict(metadata.get("labels", {}))
        labels.setdefault("app.kubernetes.io/managed-by", "brixtest")
        labels.setdefault(
            "brixtest.io/test-instance", getattr(self, "test_instance", self.namespace),
        )
        labels.setdefault("brixtest.io/graph-node", _graph_node_label(labels))
        environment = self._document_environment(metadata, context)
        if environment:
            labels.setdefault("brixtest.io/environment", environment)
        metadata["labels"] = labels
        selected["metadata"] = metadata
        self._label_pod_template(selected, labels)
        return selected

    def _document_environment(self, metadata: Mapping[str, object], context: str) -> str:
        environments = getattr(self, "environments", None)
        if environments is None:
            return ""
        namespace = str(metadata.get("namespace", ""))
        return environments.name_for(context or getattr(self, "context", ""), namespace)

    @staticmethod
    def _label_pod_template(document: dict, labels: Mapping[str, object]) -> None:
        if document.get("kind") not in ("Deployment", "StatefulSet", "Job"):
            return
        spec = document.setdefault("spec", {})
        template = spec.setdefault("template", {})
        metadata = template.setdefault("metadata", {})
        pod_labels = metadata.setdefault("labels", {})
        for name in ("brixtest.io/test-instance", "brixtest.io/graph-node"):
            pod_labels.setdefault(name, labels[name])

    def _record_applied_document(
        self, document: Mapping[str, object], *, context: str = "",
    ) -> None:
        metadata = document.get("metadata", {})
        labels = metadata.get("labels", {}) if isinstance(metadata, Mapping) else {}
        self.owner.evidence.event("kubernetes-resource", {
            "api_version": document.get("apiVersion", ""),
            "kind": document.get("kind", ""),
            "name": metadata.get("name", "") if isinstance(metadata, Mapping) else "",
            "namespace": metadata.get("namespace", self.namespace)
            if isinstance(metadata, Mapping) else self.namespace,
            "graph_node": labels.get("brixtest.io/graph-node", "")
            if isinstance(labels, Mapping) else "",
            "test_instance": getattr(self, "test_instance", self.namespace),
            "environment": labels.get("brixtest.io/environment", "")
            if isinstance(labels, Mapping) else "",
            "context": context or getattr(self, "context", ""),
            "owned": True,
        })


__all__ = ["KubernetesDocumentMixin"]
