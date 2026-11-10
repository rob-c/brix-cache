"""Reuse only a healthy Minikube profile matching the requested lab settings."""
import json


def _json_result(run, command):
    result = run(command, check=False, capture=True)
    if result.returncode:
        return {}
    try:
        value = json.loads(result.stdout)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _matches(profile, name, driver, nodes, version):
    config = profile.get("Config", {})
    return (profile.get("Name") == name
            and profile.get("ActiveKubeContext") is True
            and config.get("Driver") == driver
            and str(len(config.get("Nodes") or [])) == nodes
            and config.get("KubernetesConfig", {}).get("KubernetesVersion") == version)


def reusable_cluster(run, driver, nodes, version):
    """A failed health probe falls back to the normal start/repair command."""
    health = _json_result(run, ["minikube", "status", "--output=json"])
    expected = {"Host": "Running", "Kubelet": "Running",
                "APIServer": "Running", "Kubeconfig": "Configured"}
    if not health.get("Name") or any(health.get(k) != v for k, v in expected.items()):
        return False
    profiles = _json_result(run, ["minikube", "profile", "list", "--output=json"])
    return any(_matches(profile, health["Name"], driver, nodes, version)
               for profile in profiles.get("valid", []))
