"""Human-readable rendering of collected BriXTest declarations."""

from __future__ import annotations

from brixtest.planning import backend_capabilities, compile_case


def _command_names(command) -> str:
    return " ".join(
        "<binary:%s>" % part.name if hasattr(part, "name") else str(part)
        for part in command
    )


def _describe_pool(terminal, pool) -> None:
    terminal.write_line("  pool %s servers=%s consumers=%d" % (
        pool.key, ",".join(server.name for server in pool.definition.servers), len(pool.tests),
    ))


def _describe_servers(terminal, definition) -> None:
    for server in definition.servers:
        source = str(server.config.path) if server.config.path is not None \
            else "<inline:%s>" % server.config.destination
        terminal.write_line("  server %-18s scope=%-7s ports=%s config=%s command=%s" % (
            server.name, server.scope, ",".join(server.ports), source,
            _command_names(server.command),
        ))


def _describe_clients(terminal, definition) -> None:
    for client in definition.clients:
        terminal.write_line("  client %-18s command=%s" % (
            client.name, _command_names(client.command),
        ))


def _describe_artifacts(terminal, definition) -> None:
    for artifact in definition.artifacts:
        detail = "%d bytes" % artifact.size if artifact.kind == "noise" else artifact.kind
        terminal.write_line("  artifact %-16s %s" % (artifact.name, detail))


def _describe_credentials(terminal, definition) -> None:
    for credential in definition.credentials:
        terminal.write_line("  credential %-14s kind=%s targets=%s" % (
            credential.name, credential.kind, ",".join(credential.targets),
        ))


def _describe_auth(terminal, definition) -> None:
    for recipe in definition.auth:
        terminal.write_line("  auth %-20s kind=%s" % (recipe.name, recipe.kind))


def _describe_hosts(terminal, definition) -> None:
    for host in definition.hosts:
        terminal.write_line("  host %-20s %s -> %s" % (host.name, host.hostname, host.address))


def _describe_resources(terminal, definition) -> None:
    _describe_servers(terminal, definition)
    _describe_clients(terminal, definition)
    _describe_artifacts(terminal, definition)
    _describe_credentials(terminal, definition)
    _describe_auth(terminal, definition)
    _describe_hosts(terminal, definition)


def _describe_plan(terminal, definition) -> None:
    backend = "local" if definition.backend == "auto" else definition.backend
    graph = compile_case(definition, backend)
    terminal.write_line(
        "  plan schema=%d fingerprint=%s nodes=%d edges=%d" % (
            graph.schema_version, graph.fingerprint, len(graph.nodes), len(graph.edges),
        )
    )
    for node in graph.nodes:
        _describe_plan_node(terminal, node)
    for edge in graph.edges:
        terminal.write_line(
            "    edge %s -[%s]-> %s" % (edge.source, edge.relation, edge.target)
        )


def _describe_plan_node(terminal, node) -> None:
    kind = {"client": "executor", "server": "launcher"}.get(node.kind, "backend")
    available = backend_capabilities(node.backend, kind)
    missing = sorted(set(node.requires) - available)
    suffix = " missing=" + ",".join(missing) if missing else ""
    terminal.write_line(
        "    node %-28s backend=%-10s requires=%s%s" % (
            node.id, node.backend, ",".join(node.requires) or "none", suffix,
        )
    )


def _describe_case(terminal, item, definition) -> None:
    terminal.write_line("\n%s" % item.nodeid)
    terminal.write_line(
        "  backend=%s isolation=%s timeout=%.1fs keep=%s attempts=%d+%d observe=%s" % (
            definition.backend, definition.isolation.kind, definition.timeout,
            definition.keep, definition.warmup, definition.trials,
            ",".join(item.name for item in definition.observe) or "none",
        )
    )
    _describe_resources(terminal, definition)
    _describe_plan(terminal, definition)


def _managed_items(session, definition_for):
    declared = ((item, definition_for(item)) for item in session.items)
    return [(item, definition) for item, definition in declared if definition is not None]


def _derived_pools(managed):
    from brixtest.topology.model import derive

    return derive([(item.nodeid, definition) for item, definition in managed])


def _write_pools(terminal, pools) -> None:
    for pool in pools:
        _describe_pool(terminal, pool)


def _write_cases(terminal, managed) -> None:
    for item, definition in managed:
        _describe_case(terminal, item, definition)


def describe(session, definition_for) -> None:
    terminal = session.config.pluginmanager.get_plugin("terminalreporter")
    if terminal is None:
        return
    managed = _managed_items(session, definition_for)
    terminal.write_line("BriXTest designs: %d" % len(managed))
    pools = _derived_pools(managed)
    terminal.write_line("Derived shared server pools: %d" % len(pools))
    _write_pools(terminal, pools)
    _write_cases(terminal, managed)
