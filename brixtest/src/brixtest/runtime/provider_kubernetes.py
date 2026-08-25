"""Confined Kubernetes object operations for managed resource providers."""

from __future__ import annotations

import copy
import contextlib
import json
import re
from pathlib import Path
from typing import Mapping, Sequence

from brixtest.errors import SpecError

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
_CLUSTER_SCOPED = frozenset({
    "CustomResourceDefinition", "ClusterRole", "ClusterRoleBinding", "Namespace",
    "Node", "PersistentVolume", "StorageClass",
})


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise SpecError(field, value, "must be non-empty text")
    return value


def _name(value: object, field: str) -> str:
    selected = _text(value, field)
    if len(selected) > 253 or _NAME.fullmatch(selected) is None:
        raise SpecError(field, value, "must be a lowercase Kubernetes object name")
    return selected


def _documents(value: object) -> tuple[Mapping[str, object], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not value:
        raise SpecError("provider objects", value, "must be a non-empty document sequence")
    selected = tuple(value)
    if not all(isinstance(item, Mapping) for item in selected):
        raise SpecError("provider objects", value, "must contain object mappings")
    return selected


def _object_document(
    value: Mapping[str, object], namespace: str, owner: str, instance: str,
) -> dict:
    document = copy.deepcopy(dict(value))
    kind = _text(document.get("kind"), "provider object kind")
    _text(document.get("apiVersion"), "provider object apiVersion")
    if kind in _CLUSTER_SCOPED:
        raise SpecError("provider object kind", kind, "must be namespace-scoped")
    metadata = document.get("metadata")
    if not isinstance(metadata, Mapping):
        raise SpecError("provider object metadata", metadata, "must be a mapping")
    metadata = copy.deepcopy(dict(metadata))
    _name(metadata.get("name"), "provider object name")
    requested = metadata.get("namespace", namespace)
    if requested != namespace:
        raise SpecError("provider object namespace", requested, "must equal the owned case namespace")
    labels = metadata.get("labels", {})
    if not isinstance(labels, Mapping):
        raise SpecError("provider object labels", labels, "must be a mapping")
    metadata["namespace"] = namespace
    metadata["labels"] = {
        **dict(labels), "app.kubernetes.io/managed-by": "brixtest",
        "brixtest.dev/provider-resource": owner,
        "brixtest.dev/test-instance": instance,
    }
    document["metadata"] = metadata
    return document


def _identity(payload: object, expected: Mapping[str, str]) -> Mapping[str, str]:
    if not isinstance(payload, Mapping):
        raise SpecError("provider object response", payload, "must be a Kubernetes object")
    metadata = payload.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise SpecError("provider object response metadata", metadata, "must be a mapping")
    labels = metadata.get("labels", {})
    if expected.get("owner") and (
        not isinstance(labels, Mapping)
        or labels.get("brixtest.dev/provider-resource") != expected["owner"]
    ):
        raise SpecError("provider object ownership", labels, "does not match its provider resource")
    if expected.get("instance") and labels.get(
        "brixtest.dev/test-instance"
    ) != expected["instance"]:
        raise SpecError(
            "provider object ownership", labels,
            "does not match its BriXTest instance",
        )
    uid = _text(metadata.get("uid"), "provider object UID")
    return {**expected, "uid": uid}


class KubernetesProviderObjects:
    """Apply, inspect, and UID-guard provider-owned namespaced objects."""

    def __init__(self, backend, journal: Path) -> None:
        self._backend = backend
        self._journal = Path(journal)

    def apply(
        self, owner: str, documents: Sequence[Mapping[str, object]],
    ) -> tuple[Mapping[str, str], ...]:
        selected_owner = _name(owner, "provider resource name")
        instance = _text(
            getattr(self._backend, "_namespace_uid", ""),
            "provider test instance",
        )
        rendered = tuple(
            _object_document(
                item, self._backend.namespace, selected_owner, instance,
            )
            for item in _documents(documents)
        )
        intents = tuple(self._document_identity(item, selected_owner, instance) for item in rendered)
        self._record(intents)
        try:
            self._create(rendered)
            identities = self._capture_identities(rendered, selected_owner, instance)
        except Exception:
            self._rollback(rendered, (), selected_owner, instance)
            raise
        self._replace(intents, identities)
        for item in identities:
            self._backend.owner.evidence.event("provider-kubernetes-object", dict(item))
        return identities

    def _create(self, documents) -> None:
        payload = json.dumps({
            "apiVersion": "v1", "kind": "List", "items": list(documents),
        })
        self._backend._run(
            "-n", self._backend.namespace, "create", "-f", "-",
            input_text=payload, timeout=30.0,
        )

    def _capture_identities(
        self, documents, owner: str, instance: str,
    ) -> tuple[Mapping[str, str], ...]:
        return tuple(
            self._read_identity(document, owner, instance)
            for document in documents
        )

    def _rollback(self, documents, identities, owner: str, instance: str) -> None:
        known = {(item["kind"], item["name"]): item for item in identities}
        for document in reversed(documents):
            metadata = document["metadata"]
            identity = known.get((str(document["kind"]), str(metadata["name"])))
            if identity is None:
                with contextlib.suppress(Exception):
                    identity = self._read_identity(document, owner, instance)
            if identity is not None:
                with contextlib.suppress(Exception):
                    self.delete(identity)

    def get(self, identity: Mapping[str, str]) -> Mapping[str, object]:
        selected = self._validated_identity(identity)
        result = self._backend._run(
            "-n", selected["namespace"], "get",
            "%s/%s" % (selected["kind"], selected["name"]), "-o", "json",
        )
        payload = json.loads(result.stdout)
        actual = _identity(payload, {key: selected[key] for key in selected if key != "uid"})
        if actual["uid"] != selected["uid"]:
            raise SpecError("provider object UID", actual["uid"], "does not match owned UID")
        return payload

    def discover(
        self, kind: str, name: str, *, namespace: str = "",
    ) -> Mapping[str, object]:
        """Read one external prerequisite without claiming ownership."""
        selected_kind = _text(kind, "provider discovery kind")
        selected_name = _name(name, "provider discovery name")
        argv = []
        if namespace:
            argv.extend(("-n", _name(namespace, "provider discovery namespace")))
        argv.extend(("get", "%s/%s" % (selected_kind, selected_name), "-o", "json"))
        payload = json.loads(self._backend._run(*argv).stdout)
        if not isinstance(payload, Mapping):
            raise SpecError("provider discovery response", payload, "must be an object")
        self._backend.owner.evidence.event("provider-kubernetes-discovery", {
            "kind": selected_kind, "name": selected_name, "namespace": namespace,
            "uid": str(payload.get("metadata", {}).get("uid", "")),
        })
        return payload

    def delete(self, identity: Mapping[str, str]) -> None:
        selected = self._validated_identity(identity)
        self.get(selected)
        self._backend._run(
            "-n", selected["namespace"], "delete",
            "%s/%s" % (selected["kind"], selected["name"]),
            "--wait=false", timeout=20.0,
        )
        self._remove(selected)

    def orphans(self, owner: str = "") -> tuple[Mapping[str, str], ...]:
        """Return journalled objects that still have their exact owned UID."""
        selected_owner = _name(owner, "provider resource name") if owner else ""
        found = []
        for candidate in self._records():
            if selected_owner and candidate.get("owner") != selected_owner:
                continue
            try:
                identity = self._recover(candidate)
                self.get(identity)
            except Exception:
                continue
            found.append(identity)
        return tuple(found)

    def cleanup_orphans(self, owner: str = "") -> tuple[Mapping[str, str], ...]:
        """Delete only discoverable objects whose labels and UID still match."""
        removed = []
        for identity in self.orphans(owner):
            self.delete(identity)
            removed.append(identity)
            self._backend.owner.evidence.event(
                "provider-kubernetes-orphan-cleaned", dict(identity),
            )
        return tuple(removed)

    def observe(
        self, identity: Mapping[str, str], *, pod_selector: str = "",
    ) -> Mapping[str, object]:
        """Collect UID-correlated object, event, Pod, log, and metric evidence."""
        from brixtest.runtime.provider_observation import provider_observation

        selected = self._validated_identity(identity)
        return provider_observation(
            self._backend, selected, self.get(selected), pod_selector,
        )

    def _read_identity(
        self, document: Mapping[str, object], owner: str, instance: str,
    ) -> Mapping[str, str]:
        expected = self._document_identity(document, owner, instance)
        result = self._backend._run(
            "-n", expected["namespace"], "get",
            "%s/%s" % (expected["kind"], expected["name"]), "-o", "json",
        )
        return _identity(json.loads(result.stdout), expected)

    @staticmethod
    def _document_identity(document, owner: str, instance: str) -> Mapping[str, str]:
        metadata = document["metadata"]
        return {
            "api_version": str(document["apiVersion"]), "kind": str(document["kind"]),
            "namespace": str(metadata["namespace"]), "name": str(metadata["name"]),
            "owner": owner, "instance": instance,
        }

    def _recover(self, candidate: Mapping[str, str]) -> Mapping[str, str]:
        if candidate.get("uid"):
            return self._validated_identity(candidate)
        result = self._backend._run(
            "-n", str(candidate["namespace"]), "get",
            "%s/%s" % (candidate["kind"], candidate["name"]), "-o", "json",
        )
        identity = _identity(json.loads(result.stdout), candidate)
        self._replace((candidate,), (identity,))
        return identity

    def _validated_identity(self, value: object) -> Mapping[str, str]:
        if not isinstance(value, Mapping):
            raise SpecError("provider object identity", value, "must be a mapping")
        required = (
            "api_version", "kind", "namespace", "name", "owner", "instance", "uid",
        )
        if set(value) != set(required) or not all(isinstance(value[key], str) for key in required):
            raise SpecError("provider object identity", value, "must contain its exact typed identity")
        if value["namespace"] != self._backend.namespace:
            raise SpecError("provider object namespace", value["namespace"], "is outside the owned case namespace")
        return dict(value)

    def _records(self) -> list[Mapping[str, str]]:
        try:
            payload = json.loads(self._journal.read_text())
        except (OSError, TypeError, ValueError):
            return []
        return [item for item in payload if isinstance(item, Mapping)] \
            if isinstance(payload, list) else []

    def _write_records(self, records: Sequence[Mapping[str, str]]) -> None:
        self._journal.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._journal.with_name(".%s.tmp" % self._journal.name)
        temporary.write_text(json.dumps(list(records), indent=2, sort_keys=True) + "\n")
        temporary.replace(self._journal)

    def _record(self, identities: Sequence[Mapping[str, str]]) -> None:
        current = self._records()
        keys = {_journal_key(item) for item in identities}
        self._write_records([
            item for item in current if _journal_key(item) not in keys
        ] + [dict(item) for item in identities])

    def _replace(self, old, new) -> None:
        keys = {_journal_key(item) for item in old}
        current = [item for item in self._records() if _journal_key(item) not in keys]
        self._write_records(current + [dict(item) for item in new])

    def _remove(self, identity: Mapping[str, str]) -> None:
        key = _journal_key(identity)
        self._write_records([
            item for item in self._records() if _journal_key(item) != key
        ])


def _journal_key(value: Mapping[str, object]) -> tuple[str, str, str]:
    return str(value.get("namespace", "")), str(value.get("kind", "")), str(value.get("name", ""))


def bind_kubernetes_provider_api(context, backend) -> None:
    """Attach the backend only after side-effect-free planning has completed."""
    journal = context.root / "kubernetes-ownership.json"
    object.__setattr__(
        context, "_kubernetes_objects", KubernetesProviderObjects(backend, journal),
    )
