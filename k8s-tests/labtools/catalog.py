"""catalog — lint scenarios/catalog.yaml and render a scenario to helm --set args.

Was tools/catalog-lint.sh + tools/scenario-render.sh (yq/sed). Pure functions;
the CLI mirrors the old scripts' stdout/exit for the bash wrappers.
"""
import sys
from pathlib import Path

import yaml

from . import CONFIG_DIR

# auth placeholder token -> template resolved per (release, scenario name)
_AUTH = {
    "SCENARIO_SVC": "{rel}-{name}",
    "CA_BUNDLE":    "{rel}-ca-bundle",
    "PKI_SECRET":   "{rel}-pki",
    "VOMSDIR_CM":   "{rel}-vomsdir",
    "CRL_URL":      "http://{rel}-grid-ca:8080/crl/test-user.crl.pem",
    "JWKS_URL":     "http://{rel}-token-issuer:8080/certs/jwks.json",
}


def scenarios(catalog):
    return yaml.safe_load(Path(catalog).read_text())["scenarios"]


def _missing_config_problem(name, key, config_dir):
    if not (Path(config_dir) / f"{key}.conf").exists():
        return [f"MISSING CONFIG: scenario {name!r} -> {key}.conf"]
    return []


def _duplicate_port_problem(name, scenario):
    ports = [entry["port"] for entry in scenario.get("ports", [])]
    duplicates = sorted(port for port in set(ports) if ports.count(port) > 1)
    if duplicates:
        return [f"DUP PORT: scenario {name!r} repeats {duplicates}"]
    return []


def _scenario_problems(name, scenario, config_dir):
    key = scenario["configKey"]
    return (_missing_config_problem(name, key, config_dir)
            + _duplicate_port_problem(name, scenario))


def lint(catalog, config_dir=CONFIG_DIR):
    """Return a list of problems; empty list means the catalog is clean."""
    problems = []
    for name, scenario in scenarios(catalog).items():
        problems.extend(_scenario_problems(name, scenario, config_dir))
    return problems


def render(catalog, name, release):
    """Return the helm ``--set`` values (as 'key=value' strings) for a scenario."""
    scn = scenarios(catalog)[name]
    out = [f"role.name={name}", f"role.configKey={scn['configKey']}"]
    for i, p in enumerate(scn.get("ports", [])):
        out += [f"role.ports[{i}].name={p['name']}", f"role.ports[{i}].port={p['port']}"]
    for k, raw in scn.get("auth", {}).items():
        v = raw
        for tok, repl in _AUTH.items():
            v = v.replace(tok, repl.format(rel=release, name=name))
        out.append(f"role.auth.{k}={v}")
    return out


def _render_command(argv):
    _, catalog, name, release, *_ = argv
    for value in render(catalog, name, release):
        print(f"--set {value}")
    return 0


def _lint_command(argv):
    catalog = argv[1] if argv and argv[0] == "lint" else argv[0]
    problems = lint(catalog)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print("catalog OK")
    return 0


def main(argv):
    if argv and argv[0] == "render":
        return _render_command(argv)
    return _lint_command(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
