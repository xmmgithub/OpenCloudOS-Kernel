#!/bin/bash
# Finalize setup

function setup_arp() {
  echo 1 > /proc/sys/net/ipv4/ip_forward
  echo 1 > /proc/sys/net/ipv4/conf/all/proxy_arp
  echo 1 > /proc/sys/net/ipv4/conf/ipvlan1/proxy_arp_pvlan
}

debug=$(cat /opt/eklet-agent/debug)

if [ "$debug" -eq 1 ]; then
  setup_arp
fi
