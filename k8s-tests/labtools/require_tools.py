"""require_tools — which of the lab's required CLIs are missing from PATH.
Was tools/require-tools.sh.
"""
import os
import shutil
import sys

DEFAULT = "minikube kubectl docker helm python3 kubeconform yq jq shellcheck".split()


def missing(tools=None):
    """Return the subset of ``tools`` (default: the lab set) not found on PATH."""
    return [t for t in (tools or DEFAULT) if shutil.which(t) is None]


def main(argv):
    tools = os.environ.get("REQUIRE_TOOLS_LIST")
    tools = tools.split() if tools else DEFAULT
    gone = missing(tools)
    for t in gone:
        print(f"MISSING: {t}", file=sys.stderr)
    if gone:
        print("One or more required tools are missing. See k8s-tests/README.md.",
              file=sys.stderr)
        return 1
    print("All required tools present.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
