#!/usr/bin/env bash
# tests/cvmfs/netem_lab.sh — impaired-network lab for CVMFS cache testing.
# Host side 10.199.0.1 (cache under test) <-> ns "cvmfslab" 10.199.0.2 (origin).
# Impairment is applied on BOTH veth ends so loss/reorder hits each direction.
set -eu
NS=cvmfslab; VH=cvmfs-h; VN=cvmfs-n; HIP=10.199.0.1; NIP=10.199.0.2

profile_args() {
    case "$1" in
        clean)   echo "" ;;
        loss)    echo "loss 3%" ;;
        reorder) echo "delay 10ms reorder 25% 50%" ;;
        corrupt) echo "corrupt 0.5%" ;;
        jitter)  echo "delay 80ms 40ms distribution normal" ;;
        site)    echo "delay 30ms 15ms loss 1% reorder 10% 50% corrupt 0.1%" ;;
        *) echo "unknown profile: $1" >&2; exit 2 ;;
    esac
}

cmd_up() {
    ip netns add "$NS"
    ip link add "$VH" type veth peer name "$VN"
    ip link set "$VN" netns "$NS"
    ip addr add "$HIP/24" dev "$VH"; ip link set "$VH" up
    ip netns exec "$NS" ip addr add "$NIP/24" dev "$VN"
    ip netns exec "$NS" ip link set "$VN" up
    ip netns exec "$NS" ip link set lo up
    echo "lab up: host $HIP <-> ns $NS $NIP"
}

cmd_profile() {
    local args; args="$(profile_args "$1")"
    tc qdisc del dev "$VH" root 2>/dev/null || true
    ip netns exec "$NS" tc qdisc del dev "$VN" root 2>/dev/null || true
    if [ -n "$args" ]; then
        # shellcheck disable=SC2086
        tc qdisc add dev "$VH" root netem $args
        # shellcheck disable=SC2086
        ip netns exec "$NS" tc qdisc add dev "$VN" root netem $args
    fi
    echo "profile: $1 ($args)"
}

cmd_down() {
    ip link del "$VH" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    echo "lab down"
}

case "${1:-}" in
    up) cmd_up ;;
    down) cmd_down ;;
    profile) cmd_profile "${2:?profile name}" ;;
    status) tc qdisc show dev "$VH" 2>/dev/null || echo "lab not up" ;;
    *) echo "usage: $0 up|down|profile <clean|loss|reorder|corrupt|jitter|site>|status" >&2
       exit 2 ;;
esac
