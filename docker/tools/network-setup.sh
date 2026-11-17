#!/usr/bin/env bash
# Creates the isolated Docker network for VeritySec tool containers and
# blocks it from reaching the host and internal address ranges.
#
# Usage: sudo docker/tools/network-setup.sh          (create network + rules)
#        sudo docker/tools/network-setup.sh --remove (delete rules + network)
#
# IMPORTANT: loopback to the host is NOT reachable from the bridge network by
# design. Tools in bridge mode cannot scan 127.0.0.1 targets; use the host
# network mode (tool_execution.network: host) for localhost work.
set -euo pipefail

NET_NAME="veritysec-tools"
SUBNET="172.30.0.0/24"
CHAIN="DOCKER-USER"
STATIC_DESTS=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 172.17.0.0/16)

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "error: must run as root (use sudo)" >&2
  exit 1
fi
command -v docker >/dev/null || { echo "error: docker not found" >&2; exit 1; }
command -v iptables >/dev/null || { echo "error: iptables not found" >&2; exit 1; }

MODE="add"
case "${1:-}" in
  "") ;;
  --remove) MODE="remove" ;;
  *) echo "usage: $0 [--remove]" >&2; exit 2 ;;
esac

# Destinations: host's own IPv4 addresses (as /32) plus the static ranges.
dests=()
while read -r ip; do
  [ -n "$ip" ] && dests+=("$ip/32")
done < <(ip -4 -o addr | awk '{print $4}' | cut -d/ -f1 | sort -u)
dests+=("${STATIC_DESTS[@]}")

if [ "$MODE" = "add" ]; then
  if docker network inspect "$NET_NAME" >/dev/null 2>&1; then
    echo "network $NET_NAME already exists"
  else
    docker network create --driver bridge --subnet "$SUBNET" "$NET_NAME"
    echo "created network $NET_NAME ($SUBNET)"
  fi
  iptables -n -L "$CHAIN" >/dev/null 2>&1 || { echo "error: chain $CHAIN missing (is Docker running?)" >&2; exit 1; }
  for d in "${dests[@]}"; do
    if iptables -C "$CHAIN" -s "$SUBNET" -d "$d" -j DROP 2>/dev/null; then
      echo "rule exists: DROP $SUBNET -> $d"
    else
      iptables -I "$CHAIN" -s "$SUBNET" -d "$d" -j DROP
      echo "added rule: DROP $SUBNET -> $d"
    fi
  done
else
  for d in "${dests[@]}"; do
    if iptables -C "$CHAIN" -s "$SUBNET" -d "$d" -j DROP 2>/dev/null; then
      iptables -D "$CHAIN" -s "$SUBNET" -d "$d" -j DROP
      echo "removed rule: DROP $SUBNET -> $d"
    fi
  done
  if docker network inspect "$NET_NAME" >/dev/null 2>&1; then
    docker network rm "$NET_NAME"
    echo "removed network $NET_NAME"
  else
    echo "network $NET_NAME not present"
  fi
fi
