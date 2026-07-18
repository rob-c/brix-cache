#!/bin/sh
# install-automount.sh — portable installer for the CVMFS-brix automount stack
# on hosts without RPM (WSL2, Ubuntu/Debian, containers). Idempotent: existing
# config files are never clobbered (cp -n); binaries/helpers are refreshed.
#
# Installs:
#   <prefix>/sbin/mount.cvmfs         mount -t cvmfs / autofs helper
#   /etc/auto.cvmfs                   autofs program map (only if autofs found)
#   /etc/auto.master.d/cvmfs.autofs   autofs master drop-in (only if autofs found)
#   /etc/cvmfs/...                    default config + master keys (cp -n)
#   systemd units                     only when systemd is the running init
#
# The umbrella daemon itself (`brixMount autofs`) ships in the brixMount
# binary; build/install that first (`make -C client bin/brixMount install-bin`).
#
# Usage: install-automount.sh [--prefix /usr/local] [--no-config] [--dry-run]
set -eu

prefix=/usr/local
do_config=1
dry=0

usage() {
    echo "usage: $0 [--prefix DIR] [--no-config] [--dry-run]" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)    [ $# -ge 2 ] || usage; prefix=$2; shift 2 ;;
        --no-config) do_config=0; shift ;;
        --dry-run)   dry=1; shift ;;
        -h|--help)   usage ;;
        *)           usage ;;
    esac
done

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

run() {
    if [ "$dry" = 1 ]; then
        echo "DRY: $*"
    else
        "$@"
    fi
}

# --- sanity checks -----------------------------------------------------------
if ! command -v fusermount3 >/dev/null 2>&1; then
    echo "WARNING: fusermount3 not found — install fuse3 (apt install fuse3 /" >&2
    echo "         dnf install fuse3) or unprivileged unmounts will fail." >&2
fi

if [ -f /etc/fuse.conf ] && ! grep -q '^[[:space:]]*user_allow_other' /etc/fuse.conf; then
    echo "NOTE: /etc/fuse.conf lacks 'user_allow_other'. The system service runs" >&2
    echo "      as root and does not need it, but per-user umbrellas with" >&2
    echo "      -o allow_other do. Enable with:" >&2
    echo "          echo user_allow_other >> /etc/fuse.conf" >&2
fi

# --- mount helper ------------------------------------------------------------
run install -d "$prefix/sbin"
run install -m755 "$here/mount.cvmfs" "$prefix/sbin/mount.cvmfs"
# mount(8) looks in /sbin only; link when installing to a different prefix.
if [ "$prefix" != "" ] && [ "$prefix/sbin" != "/sbin" ] && [ ! -e /sbin/mount.cvmfs ]; then
    run ln -s "$prefix/sbin/mount.cvmfs" /sbin/mount.cvmfs
fi

# --- autofs integration (optional; the native umbrella needs neither) --------
if command -v automount >/dev/null 2>&1; then
    run install -m755 "$here/auto.cvmfs" /etc/auto.cvmfs
    run install -d /etc/auto.master.d
    if [ ! -e /etc/auto.master.d/cvmfs.autofs ]; then
        if [ "$dry" = 1 ]; then
            echo "DRY: write /etc/auto.master.d/cvmfs.autofs"
        else
            printf '/cvmfs /etc/auto.cvmfs\n' > /etc/auto.master.d/cvmfs.autofs
        fi
    fi
    echo "autofs map installed; activate with: systemctl restart autofs"
else
    echo "autofs not present — skipping auto.master integration (the native"
    echo "umbrella 'brixMount autofs' does not need it)."
fi

# --- default config + keys ---------------------------------------------------
if [ "$do_config" = 1 ]; then
    (cd "$here/etc/cvmfs" && find . -type d) | while read -r d; do
        run install -d "/etc/cvmfs/${d#./}"
    done
    (cd "$here/etc/cvmfs" && find . -type f) | while read -r f; do
        # cp -n: never overwrite operator-edited config or rotated keys
        run cp -n "$here/etc/cvmfs/${f#./}" "/etc/cvmfs/${f#./}"
    done
    echo "config + keys installed under /etc/cvmfs (existing files untouched)"
fi

# --- runtime dirs ------------------------------------------------------------
run install -d -m755 /cvmfs
run install -d -m700 /var/lib/brixcvmfs

# --- service -----------------------------------------------------------------
if [ -d /run/systemd/system ]; then
    unitdir=/etc/systemd/system
    for u in brixcvmfs-automount.service brixcvmfs@.service; do
        src="$here/../../packaging/$u"
        [ -f "$src" ] && run install -m644 "$src" "$unitdir/$u"
    done
    run systemctl daemon-reload
    echo "enable + start with: systemctl enable --now brixcvmfs-automount"
else
    echo ""
    echo "systemd is not running (WSL2 without systemd=true?). Two options:"
    echo ""
    echo "  1. enable systemd in WSL2 — /etc/wsl.conf:"
    echo "         [boot]"
    echo "         systemd=true"
    echo "     then 'wsl --shutdown' from Windows and use systemctl as above."
    echo ""
    echo "  2. boot-command mode — /etc/wsl.conf:"
    echo "         [boot]"
    echo "         command=$prefix/sbin/brixcvmfs-automount-boot.sh"
    echo "     (installed next; runs the umbrella daemon at distro start)"
    run install -m755 "$here/brixcvmfs-automount-boot.sh" \
        "$prefix/sbin/brixcvmfs-automount-boot.sh"
fi

echo "done."
