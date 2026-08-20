"""Retrying OpenSearch/Elasticsearch data-stream exporter and schema manager."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import random
import time
import urllib.error
import urllib.request
from typing import Iterable, Mapping

from brixtest.evidence.model import iter_entities, normalize_session
from brixtest.evidence.redaction import value as redact
from brixtest.errors import SpecError

_LOCAL_ONLY = frozenset({"replay", "run_root", "journal"})


def _remote_safe(item: object) -> object:
    if isinstance(item, Mapping):
        return {
            str(key): _remote_safe(value) for key, value in item.items()
            if str(key) not in _LOCAL_ONLY
        }
    if isinstance(item, list):
        return [_remote_safe(value) for value in item]
    if isinstance(item, tuple):
        return [_remote_safe(value) for value in item]
    return item


def _name(value: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789-_."
    if not value or any(char not in allowed for char in value):
        raise SpecError("search index", value, "must be lowercase [a-z0-9-_.]")
    return value


def documents(payload: Mapping[str, object], *, prefix: str = "brixtest") -> Iterable[dict]:
    base = _name(prefix)
    session = normalize_session(payload)
    for row in iter_entities(session):
        entity = str(row.get("entity", "unknown"))
        timestamp = row.get("timestamp") or row.get("started_at") or session.get("generated_at")
        document = redact(_remote_safe({"@timestamp": timestamp, **row}))
        identity = "\0".join(str(document.get(key, "")) for key in (
            "session_id", "case_id", "attempt_id", "entity", "ordinal", "name"
        ))
        yield {
            "index": "%s-evidence-%s" % (base, entity.replace("_", "-")),
            "id": hashlib.sha256(identity.encode()).hexdigest(),
            "document": document,
        }


def bulk_lines(payload: Mapping[str, object], *, prefix: str = "brixtest") -> Iterable[str]:
    for row in documents(payload, prefix=prefix):
        yield json.dumps({"create": {"_index": row["index"], "_id": row["id"]}})
        yield json.dumps(row["document"], sort_keys=True, default=str)


class SearchClient:
    def __init__(
        self, url: str, *, timeout: float = 30.0, retries: int = 4,
        opener=None, compress: bool = True,
    ) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.opener = opener or urllib.request.urlopen
        self.compress = compress

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        token = os.environ.get("BRIXTEST_SEARCH_BEARER_TOKEN")
        basic = os.environ.get("BRIXTEST_SEARCH_BASIC_AUTH")
        if token:
            headers["Authorization"] = "Bearer " + token
        elif basic:
            headers["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
        return headers

    def request(self, method: str, path: str, body: object = None,
                content_type: str = "application/json") -> bytes:
        data = None
        headers = self._headers()
        if body is not None:
            raw = body if isinstance(body, bytes) else json.dumps(body).encode()
            data = gzip.compress(raw) if self.compress else raw
            headers["Content-Type"] = content_type
            if self.compress:
                headers["Content-Encoding"] = "gzip"
        last = None
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(
                self.url + "/" + path.lstrip("/"), data=data, method=method, headers=headers
            )
            try:
                with self.opener(request, timeout=self.timeout) as response:
                    return response.read()
            except urllib.error.HTTPError as exc:
                last = exc
                if exc.code not in (408, 429, 500, 502, 503, 504):
                    break
            except OSError as exc:
                last = exc
            if attempt < self.retries:
                time.sleep(min(8.0, 0.25 * (2 ** attempt)) + random.random() * 0.1)
        raise SpecError("search archive", self.url, "request failed: %s" % last)

    def ensure_schema(self, prefix: str) -> None:
        name = _name(prefix)
        policy = {
            "policy": {
                "description": "BriXTest evidence retention",
                "default_state": "hot",
                "states": [{
                    "name": "hot", "actions": [{"rollover": {"min_size": "20gb", "min_index_age": "7d"}}],
                    "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "90d"}}],
                }, {"name": "delete", "actions": [{"delete": {}}], "transitions": []}],
            }
        }
        try:
            self.request("PUT", "_plugins/_ism/policies/%s-retention" % name, policy)
        except SpecError:
            pass
        template = {
            "index_patterns": [name + "-evidence-*"],
            "data_stream": {},
            "priority": 200,
            "template": {
                "settings": {
                    "index.mapping.total_fields.limit": 2000,
                    "plugins.index_state_management.policy_id": name + "-retention",
                },
                "mappings": {
                    "dynamic": True,
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "session_id": {"type": "keyword"},
                        "case_id": {"type": "keyword"},
                        "attempt_id": {"type": "keyword"},
                        "nodeid": {"type": "keyword", "ignore_above": 2048},
                        "entity": {"type": "keyword"},
                        "name": {"type": "keyword"},
                        "value": {"type": "double"},
                        "unit": {"type": "keyword"},
                    },
                },
            },
        }
        self.request("PUT", "_index_template/%s-evidence-v2" % name, template)

    def post(self, payload: Mapping[str, object], *, prefix: str = "brixtest") -> None:
        self.post_lines(bulk_lines(payload, prefix=prefix))

    def post_lines(self, lines: Iterable[str]) -> None:
        """Post a complete bulk stream and expose the first useful item errors."""
        body = ("\n".join(lines) + "\n").encode()
        response = self.request("POST", "_bulk", body, "application/x-ndjson")
        try:
            result = json.loads(response)
        except (ValueError, TypeError) as exc:
            raise SpecError("search archive", self.url, "returned invalid JSON") from exc
        if not isinstance(result, Mapping) or result.get("errors"):
            failures = []
            for item in result.get("items", []) if isinstance(result, Mapping) else []:
                operation = item.get("create", {}) if isinstance(item, Mapping) else {}
                if int(operation.get("status", 500)) >= 300:
                    failures.append(operation.get("error", operation.get("status")))
                if len(failures) == 5:
                    break
            raise SpecError("search archive", self.url,
                            "bulk service reported item errors: %s" % failures)
