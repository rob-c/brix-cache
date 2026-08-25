"""Authentication authority, material, consumer, and redaction graph contracts."""

from brixtest import (
    case, client, kerberos_auth, server, server_config, tls_auth, token_auth,
    voms_auth,
)
from brixtest.planning import compile_case


def _definition(*recipes):
    origin = server("origin", command=("true",), config=server_config("ready=true\n"))
    request = client("request", command=("true",))

    @case(servers=(origin,), clients=(request,), auth=recipes, observe=())
    def selected(run):
        pass

    return selected.__brixtest_case__


def test_auth_graph_models_role_scoped_material_and_consumers():
    graph = compile_case(_definition(
        token_auth("tokens", algorithm="ES256", managed=True), tls_auth("pki"),
        voms_auth("grid"), kerberos_auth("realm", start_kdc=False),
    ))

    server_material = graph.node("authority-material:tokens:server")
    assert server_material.attributes["material"] == ("public-key", "jwks", "discovery")
    assert graph.node("authority-material:tokens:test").attributes["consumers"] == (
        "test-helper",
    )
    edges = {(edge.source, edge.target, edge.relation) for edge in graph.edges}
    assert ("authority:tokens", server_material.id, "issues") in edges
    assert (server_material.id, "server:origin", "consumes") in edges
    assert ("authority:pki", "authority-material:pki:client", "revokes") in edges


def test_auth_graph_records_restart_refresh_policy_without_materializing():
    recipe = token_auth(
        "tokens", algorithm="ES256", managed=True, rotate_on_restart=True,
    )
    graph = compile_case(_definition(recipe))
    material = graph.node("authority-material:tokens:server")

    assert material.attributes["refresh"] == "authority-restart"
    assert any(edge.relation == "refreshes" for edge in graph.edges)


def test_auth_graph_never_contains_secret_or_password_values():
    definition = _definition(
        token_auth("tokens", secret="graph-secret"),
        kerberos_auth("realm", password="user-secret", master_password="master-secret"),
    )
    encoded = str(compile_case(definition).as_dict())

    assert "graph-secret" not in encoded
    assert "user-secret" not in encoded
    assert "master-secret" not in encoded
