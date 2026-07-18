#!/bin/sh
# brixcvmfs-automount-boot.sh — WSL2 [boot] command= helper: start the
# CVMFS-brix automount umbrella on /cvmfs at distro boot without systemd.
#
#   /etc/wsl.conf:
#       [boot]
#       command=/usr/local/sbin/brixcvmfs-automount-boot.sh
#
# Idempotent: exits 0 if the umbrella is already mounted. Runs as root
# (WSL boot commands do), so allow_other + idle expiry are both available.
set -u

BRIXMOUNT=${BRIXMOUNT_BIN:-brixMount}
MNT=${BRIXCVMFS_MNT:-/cvmfs}
CACHE=${BRIXCVMFS_CACHE_BASE:-/var/lib/brixcvmfs}
IDLE=${BRIXCVMFS_IDLE:-600}

command -v "$BRIXMOUNT" >/dev/null 2>&1 || {
    echo "brixcvmfs-automount-boot: $BRIXMOUNT not in PATH" >&2
    exit 1
}

# already mounted? (field 5 of mountinfo is the mountpoint)
if awk -v m="$MNT" '$5 == m { found = 1 } END { exit !found }' \
        /proc/self/mountinfo 2>/dev/null; then
    exit 0
fi

mkdir -p "$MNT" "$CACHE"
chmod 700 "$CACHE"

if [ -f /etc/fuse.conf ] && ! grep -q '^[[:space:]]*user_allow_other' /etc/fuse.conf; then
    : # root umbrella: allow_other works regardless of user_allow_other
fi

# setsid + background: [boot] command must return promptly or WSL stalls boot.
setsid "$BRIXMOUNT" autofs - "$MNT" -f \
    -o "allow_other,idle=$IDLE,cachebase=$CACHE" \
    >/var/log/brixcvmfs-automount.log 2>&1 &

exit 0
