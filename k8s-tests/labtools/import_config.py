"""import_config — map a repo dedicated config's sed markers to the lab's Helm
expressions / mount paths, and report any marker left unmapped.

Was tools/import-config.sh (sed). Order matters: '{BIND_HOST}:' before '{BIND_HOST}'.
"""
import re
import sys
from pathlib import Path

from . import CONFIG_DIR

MARKERS = {
    "{BIND_HOST}:": "",
    "{BIND_HOST}":  "0.0.0.0",
    "{PORT}":       "{{ (index .Values.role.ports 0).port }}",
    "{DATA_DIR}":   "{{ .Values.role.data.root }}",
    "{LOG_DIR}":    "/var/log/brix",
    "{TMP_DIR}":    "/tmp",
    "{SERVER_CERT}": "/etc/grid-security/hostcert.pem",
    "{SERVER_KEY}":  "/etc/grid-security/hostkey.pem",
    "{CA_CERT}":     "/etc/grid-security/certificates/ca.pem",
    "{CA_DIR}":      "/etc/grid-security/certificates",
    "{VOMSDIR}":     "/etc/grid-security/vomsdir",
    "{CRL_PATH}":    "/etc/brix/crl/crl.pem",
}


def convert(text):
    """Apply the marker substitutions and return the transformed config text."""
    for marker, repl in MARKERS.items():
        text = text.replace(marker, repl)
    return text


def unmapped(text):
    """Return the sorted-unique {MARKER}s the transform did not handle."""
    return sorted(set(re.findall(r"\{[A-Z_0-9]+\}", text)))


def import_config(src, key, config_dir=CONFIG_DIR):
    """Convert ``src`` into ``<config_dir>/<key>.conf``; return unmapped markers."""
    dest = Path(config_dir) / f"{key}.conf"
    out = convert(Path(src).read_text())
    dest.write_text(out)
    return unmapped(out)


def main(argv):
    src, key = argv[0], argv[1]
    if not Path(src).is_file():
        print(f"no such config: {src}", file=sys.stderr)
        return 1
    left = import_config(src, key)
    if left:
        print(f"WARN: {key} has unmapped markers (manual edit needed):", file=sys.stderr)
        for m in left:
            print(f"  {m}", file=sys.stderr)
        return 2
    print(f"imported {src} -> {CONFIG_DIR / (key + '.conf')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
