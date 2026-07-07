#!/usr/bin/env bash
# Configure an EL-family container for the requested k8s test target.
#
# Inputs:
#   BRIX_OS_TARGET          alma9 | centos9-stream
#   BRIX_ENABLE_CEPH_SIG    0 | 1
#   BRIX_CEPH_SIG_RELEASE   tentacle | squid | reef | ...
set -euo pipefail

target="${BRIX_OS_TARGET:-alma9}"
enable_ceph_sig="${BRIX_ENABLE_CEPH_SIG:-0}"
ceph_release="${BRIX_CEPH_SIG_RELEASE:-tentacle}"

dnf -y install 'dnf-command(config-manager)' ca-certificates
dnf config-manager --set-enabled crb >/dev/null 2>&1 || true

case "$target" in
    alma9)
        dnf -y install epel-release
        ;;
    centos9-stream)
        dnf -y install epel-release
        dnf -y install epel-next-release >/dev/null 2>&1 || true
        ;;
    *)
        echo "unknown BRIX_OS_TARGET: $target" >&2
        exit 2
        ;;
esac

if [ "$enable_ceph_sig" = "1" ]; then
    repo="/etc/yum.repos.d/centos-storage-ceph-${ceph_release}.repo"
    cat > "$repo" <<EOF
[centos-storage-ceph-${ceph_release}]
name=CentOS Stream 9 Storage SIG Ceph ${ceph_release}
baseurl=https://mirror.stream.centos.org/SIGs/9-stream/storage/\$basearch/ceph-${ceph_release}/
enabled=1
gpgcheck=0
module_hotfixes=1
EOF
fi
