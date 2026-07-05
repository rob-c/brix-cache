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


def lint(catalog, config_dir=CONFIG_DIR):
    """Return a list of problems; empty list means the catalog is clean."""
    problems = []
    for name, scn in scenarios(catalog).items():
        key = scn["configKey"]
        if not (Path(config_dir) / f"{key}.conf").exists():
            problems.append(f"MISSING CONFIG: scenario {name!r} -> {key}.conf")
        ports = [p["port"] for p in scn.get("ports", [])]
        dups = sorted({p for p in ports if ports.count(p) > 1})
        if dups:
            problems.append(f"DUP PORT: scenario {name!r} repeats {dups}")
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


def main(argv):
    if argv and argv[0] == "render":
        _, catalog, name, release, *_ = argv
        for kv in render(catalog, name, release):
            print(f"--set {kv}")
        return 0
    catalog = argv[1] if argv and argv[0] == "lint" else argv[0]
    problems = lint(catalog)
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 1
    print("catalog OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
