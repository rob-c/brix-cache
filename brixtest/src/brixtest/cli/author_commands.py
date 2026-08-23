"""Project scaffolding, design discovery, and API-browser commands."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from itertools import groupby
from pathlib import Path

from brixtest.errors import SpecError
from brixtest.introspection import api_contract

_PROJECT_ENV = "BRIXTEST_PROJECT"

def _basic_test_source() -> str:
    return (
        "import sys\n\n"
        "from brixtest import case, execution, tool\n\n"
        "PYTHON = tool(\"python\", execution=execution(\n"
        "    sys.executable, \"-c\", \"print('hello from BriXTest')\",\n"
        "))\n\n\n"
        "@case(PYTHON)\n"
        "def test_new_feature(run):\n"
        "    result = run.tool(PYTHON).run()\n"
        "    assert result.stdout.strip() == \"hello from BriXTest\"\n"
    )


def _nginx_config_source() -> str:
    return (
        "pid {workspace}/nginx.pid;\nerror_log /dev/stderr notice;\nevents {}\n"
        "http {\n    access_log /dev/stdout;\n    server {\n"
        "        listen {host}:{port};\n"
        "        location / { return 200 'hello from BriXTest\\n'; }\n    }\n}\n"
    )


def _nginx_test_source() -> str:
    return (
        "import sys\nfrom pathlib import Path\n\n"
        "from brixtest import (\n"
        "    binary, case, config_ref, execution, http_endpoint, http_probe,\n"
        "    server, server_ref, template_config, tool,\n)\n\n"
        "HERE = Path(__file__).parent\nNGINX = binary(\"nginx\", \"nginx\")\n"
        "ORIGIN = server(\n    \"origin\", binary=NGINX,\n"
        "    args=[\"-p\", \"{workspace}\", \"-c\", config_ref(\"nginx.conf\"), "
        "\"-g\", \"daemon off;\"],\n"
        "    config=template_config(HERE / \"configs/nginx.conf.in\", "
        "destination=\"nginx.conf\"),\n"
        "    endpoints=[http_endpoint()], probe=http_probe(),\n)\n"
        "HTTP = tool(\"http\", execution=execution(\n    sys.executable, \"-c\",\n"
        "    \"import sys,urllib.request;print(urllib.request.urlopen(sys.argv[1]).read().decode(),"
        "end='')\",\n    server_ref(ORIGIN, role=\"http\"),\n))\n\n\n"
        "@case(ORIGIN, HTTP)\ndef test_nginx_serves_a_page(run):\n"
        "    assert run.tool(HTTP).run().stdout == \"hello from BriXTest\\n\"\n"
    )


def _new_test_files(destination: Path, nginx: bool) -> dict[Path, str]:
    if not nginx:
        return {destination: _basic_test_source()}
    config = destination.parent / "configs" / "nginx.conf.in"
    return {config: _nginx_config_source(), destination: _nginx_test_source()}


def _new_test_destination(args) -> Path:
    project = Path(args.project or os.environ.get(_PROJECT_ENV, ".")).resolve()
    destination = Path(args.path)
    destination = destination if destination.is_absolute() else project / destination
    if destination.suffix != ".py":
        raise SpecError("new test path", str(destination), "must end in .py")
    return destination


def _write_new_test_files(files: dict[Path, str]) -> None:
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def _cmd_new(args) -> int:
    destination = _new_test_destination(args)
    files = _new_test_files(destination, args.nginx)
    existing = [path for path in files if path.exists()]
    if existing and not args.force:
        raise SpecError(
            "new test", ", ".join(str(path) for path in existing),
            "already exists; pass --force to replace generated files",
        )
    _write_new_test_files(files)
    print("created %s" % destination)
    if args.nginx:
        print("created %s" % (destination.parent / "configs" / "nginx.conf.in"))
    return 0


def _cmd_design(args) -> int:
    project = args.project or os.environ.get(_PROJECT_ENV, "")
    paths = list(args.paths or ["tests"])
    argv = [
        sys.executable, "-m", "pytest", "-p", "brixtest.pytest_plugin", *paths,
        "--collect-only", "--brixtest-describe", "-q",
    ]
    return subprocess.call(argv, cwd=project or None)


def _api_json(contract, symbols, args) -> dict:
    payload = dict(contract)
    payload["symbols"] = symbols
    if not (args.group or args.name):
        return payload
    visible = {symbol["name"] for symbol in symbols}
    payload["groups"] = _visible_groups(contract["groups"], visible)
    return payload


def _visible_groups(groups, visible: set[str]) -> dict[str, list[str]]:
    selected = {}
    for group, names in groups.items():
        matches = [name for name in names if name in visible]
        if matches:
            selected[group] = matches
    return selected


def _api_symbol_lines(contract, symbols) -> list[str]:
    lines = ["BriXTest %s public API (schema %s)" % (
        contract["version"], contract["schema_version"],
    )]
    order = {name: index for index, name in enumerate(contract["groups"])}
    ordered = sorted(symbols, key=lambda row: (order[row["group"]], row["name"]))
    for group, rows in groupby(ordered, key=lambda row: row["group"]):
        lines.extend(("", group + ":"))
        for symbol in rows:
            lines.extend(_api_symbol_entry(symbol))
    return lines


def _api_symbol_entry(symbol) -> list[str]:
    name = symbol["name"]
    if symbol["kind"] in ("function", "class"):
        name += "(" + ", ".join(symbol["call_shape"]) + ")"
    lines = ["  %-38s %-8s %s" % (name, symbol["kind"], symbol["module"])]
    if symbol["attributes"]:
        lines.append("    attributes: " + ", ".join(symbol["attributes"]))
    if symbol["members"]:
        lines.append("    members: " + ", ".join(_api_members(symbol)))
    return lines


def _api_members(symbol) -> list[str]:
    properties = set(symbol["properties"])
    return [
        _api_member(symbol, member, member in properties)
        for member in symbol["members"]
    ]


def _api_member(symbol, member: str, is_property: bool) -> str:
    if is_property:
        return member + " [property]"
    return member + "(" + ", ".join(symbol["member_call_shapes"][member]) + ")"


def _pytest_api_lines(contract) -> tuple[str, ...]:
    surface = contract["pytest"]
    return (
        "", "pytest:", "  fixtures: " + ", ".join(surface["fixtures"]),
        "  markers:  " + ", ".join(surface["markers"]),
        "  ini:      " + ", ".join(surface["ini"]),
        "  hooks:    " + ", ".join(surface["hooks"]),
        "  options:  %d public --brixtest-* options" % len(surface["options"]),
    )


def _cmd_api(args) -> int:
    contract = api_contract()
    symbols = [symbol for symbol in contract["symbols"] if _symbol_selected(symbol, args)]
    if _api_selection_missing(args, symbols):
        _print_missing_symbol(args.name)
        return 2
    return _write_api(contract, symbols, args)


def _api_selection_missing(args, symbols) -> bool:
    return bool(args.name) and not symbols


def _print_missing_symbol(name: str) -> None:
    print(
        "brixtest: no public API symbol named %r; use `brixtest api` to list names"
        % name,
        file=sys.stderr,
    )


def _write_api(contract, symbols, args) -> int:
    if args.json:
        print(json.dumps(_api_json(contract, symbols, args), indent=2, sort_keys=True))
        return 0
    lines = _api_symbol_lines(contract, symbols)
    if not (args.name or args.group):
        lines.extend(_pytest_api_lines(contract))
    for line in lines:
        print(line)
    return 0


def _symbol_selected(symbol, args) -> bool:
    if args.group and symbol["group"] != args.group:
        return False
    return not args.name or symbol["name"] == args.name
