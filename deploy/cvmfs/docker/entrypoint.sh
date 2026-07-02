#!/usr/bin/env bash
# deploy/cvmfs/docker/entrypoint.sh — render config, start fail2ban, run nginx.
#
# Env knobs:
#   DASH_PASSWORD   dashboard password            (default: cvmfs-demo)
#   UPSTREAM_ALLOW  space-separated Stratum-1 hosts allowed through :3128
#                   (default: the common WLCG Stratum-1 set)
#   MOCK_STRATUM1=1 start the bundled mock Stratum-1 on 127.0.0.1:8000 and
#                   allowlist 127.0.0.1 — offline demo mode (a real CVMFS
#                   client can't mount it, but every cache path is exercised)
set -eu

: "${DASH_PASSWORD:=cvmfs-demo}"
: "${UPSTREAM_ALLOW:=cvmfs-stratum-one.cern.ch cernvmfs.gridpp.rl.ac.uk cvmfs-s1bnl.opensciencegrid.org cvmfs-s1fnal.opensciencegrid.org cvmfs-s1goc.opensciencegrid.org}"

NGX=/opt/nginx-xrootd
LOGDIR=/var/log/nginx-xrootd

mkdir -p "$LOGDIR" /var/cache/nginx-cvmfs /var/cache/nginx-cvmfs-quarantine \
         /srv/scratch /run
# nginx workers run as the built-in default user (nobody)
chown -R nobody "$LOGDIR" /var/cache/nginx-cvmfs \
                /var/cache/nginx-cvmfs-quarantine /srv/scratch

if [ "${MOCK_STRATUM1:-0}" = 1 ]; then
    echo "entrypoint: starting bundled mock Stratum-1 on 127.0.0.1:8000"
    python3 /opt/demo/mock_stratum1.py --port 8000 --repo test.cern.ch \
        --objects 16 --seed 68 &
    UPSTREAM_ALLOW="$UPSTREAM_ALLOW 127.0.0.1"
fi

sed -e "s|@DASH_PASSWORD@|$DASH_PASSWORD|" \
    -e "s|@UPSTREAM_ALLOW@|$UPSTREAM_ALLOW|" \
    "$NGX/conf/nginx.conf.in" > "$NGX/conf/nginx.conf"

# fail2ban needs its logpaths to exist before it starts
touch "$LOGDIR/error.log" "$LOGDIR/guard-audit.log"

# Real bans need NET_ADMIN (docker run --cap-add=NET_ADMIN). Probe instead of
# assuming: without it, fall back to the no-op action — jails still match and
# count, so detection remains demonstrable via fail2ban-client status.
if nft add table inet f2b_probe 2>/dev/null; then
    nft delete table inet f2b_probe
    BANACTION=nftables-multiport
else
    echo "entrypoint: WARN no NET_ADMIN — fail2ban bans are log-only (dummy)"
    BANACTION=dummy
fi
mkdir -p /etc/fail2ban/jail.d
sed "s|@BANACTION@|$BANACTION|" /etc/fail2ban/jail-nginx-xrootd.local.in \
    > /etc/fail2ban/jail.d/nginx-xrootd.local

fail2ban-server -b
sleep 1
fail2ban-client status || true

"$NGX/sbin/nginx" -t
exec "$NGX/sbin/nginx" -g "daemon off;"
