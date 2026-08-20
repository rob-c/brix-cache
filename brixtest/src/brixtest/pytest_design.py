"""Human-readable rendering of collected BriXTest declarations."""

from __future__ import annotations


def _command_names(command) -> str:
    return " ".join(
        "<binary:%s>" % part.name if hasattr(part, "name") else str(part)
        for part in command
    )


def describe(session, definition_for) -> None:
    terminal = session.config.pluginmanager.get_plugin("terminalreporter")
    if terminal is None:
        return
    managed = [(item, definition_for(item)) for item in session.items]
    managed = [(item, definition) for item, definition in managed if definition is not None]
    terminal.write_line("BriXTest designs: %d" % len(managed))
    from brixtest.topology.model import derive
    pools = derive([(item.nodeid, definition) for item, definition in managed])
    terminal.write_line("Derived shared server pools: %d" % len(pools))
    for pool in pools:
        terminal.write_line(
            "  pool %s servers=%s consumers=%d" % (
                pool.key, ",".join(server.name for server in pool.definition.servers),
                len(pool.tests),
            )
        )
    for item, definition in managed:
        terminal.write_line("\n%s" % item.nodeid)
        terminal.write_line(
            "  backend=%s isolation=%s timeout=%.1fs keep=%s attempts=%d+%d observe=%s" % (
                definition.backend, definition.isolation.kind,
                definition.timeout, definition.keep, definition.warmup,
                definition.trials, ",".join(item.name for item in definition.observe) or "none",
            )
        )
        for server in definition.servers:
            config_source = (
                str(server.config.path) if server.config.path is not None
                else "<inline:%s>" % server.config.destination
            )
            terminal.write_line(
                "  server %-18s scope=%-7s ports=%s config=%s command=%s" % (
                    server.name, server.scope, ",".join(server.ports), config_source,
                    _command_names(server.command),
                )
            )
        for client in definition.clients:
            terminal.write_line(
                "  client %-18s command=%s" % (client.name, _command_names(client.command))
            )
        for artifact in definition.artifacts:
            detail = "%d bytes" % artifact.size if artifact.kind == "noise" else artifact.kind
            terminal.write_line("  artifact %-16s %s" % (artifact.name, detail))
        for credential in definition.credentials:
            terminal.write_line(
                "  credential %-14s kind=%s targets=%s" % (
                    credential.name, credential.kind, ",".join(credential.targets),
                )
            )
        for recipe in definition.auth:
            terminal.write_line("  auth %-20s kind=%s" % (recipe.name, recipe.kind))
        for host in definition.hosts:
            terminal.write_line(
                "  host %-20s %s -> %s" % (host.name, host.hostname, host.address)
            )
