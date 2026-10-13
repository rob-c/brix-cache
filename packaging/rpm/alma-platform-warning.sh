#!/bin/sh
# Warn when an AlmaLinux-built BriX RPM is installed on Rocky Linux. Parse
# os-release as data rather than sourcing it because RPM scriptlets run as root.

os_release="${BRIX_OS_RELEASE_FILE:-/etc/os-release}"
test -r "$os_release" || exit 0

platform_id="$(sed -n 's/^ID=//p' "$os_release" | tr -d "\"'" | sed -n '1p')"
if test "$platform_id" = "rocky"; then
    printf '%s\n' \
        'WARNING: this BriX-Cache RPM was built for AlmaLinux.' \
        'Rocky Linux is NOT supported by BriX-Cache; continue at your own risk.' \
        'Use an AlmaLinux or CentOS Stream build target for supported EL deployments.' >&2
fi

exit 0
