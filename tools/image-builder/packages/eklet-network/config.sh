#!/bin/bash
# Initialize POD Network

function mask2cdr () {
  # Assumes there's no "255." after a non-255 byte in the mask
  local x=${1##*255.}
  set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) "${x%%.*}"
  x=${1%%$3*}
  echo $(( $2 + (${#x}/4) ))
}

function remove_reserved() {
  local reserved_file='/opt/eklet-agent/reserved.file'
  [ -e ${reserved_file} ] && rm -f ${reserved_file} || true
}

function mount_cdrom() {
  mount -t iso9660 /dev/sr0 /mnt
}

function umount_cdrom() {
  umount /mnt
}

function read_sys_config() {
  local conf_file='/mnt/qcloud_action/os.conf'
  instance_id=$(awk -F "=" '/instance_id/ {print $2}' ${conf_file})
  ip_addr=$(awk -F "=" '/eth0_ip_addr/ {print $2}' ${conf_file})
  mac_addr=$(awk -F "=" '/eth0_mac_addr/ {print $2}' ${conf_file})
  netmask=$(awk -F "=" '/eth0_netmask/ {print $2}' ${conf_file})
  gateway=$(awk -F "=" '/eth0_gateway/ {print $2}' ${conf_file})
  nameservers=$(awk -F "=" '/dns_nameserver/ {print $2}' ${conf_file})

  echo -n "${ip_addr}" > /opt/eklet-agent/pod.ip
}

function read_user_data() {
  source /mnt/openstack/latest/user_data

  local debug=${DEBUG:-0}
  echo -n "${debug}" > /opt/eklet-agent/debug

  base64 -d <<< "${KUBE_CONFIG}" > /opt/eklet-agent/kubeconfig.yaml
  base64 -d <<< "${POD}" > /opt/eklet-agent/manifests/pod.yaml
}

function read_config() {
  read_sys_config
  read_user_data
}

function install_ebpf() {
  local clsact_ret
  clsact_ret=$(tc qdisc show dev eth0 |grep clsact)
  [[ -z "$clsact_ret" ]] && tc qdisc add dev eth0 clsact

  local ingress
  ingress=$(/opt/eklet-agent/bpftool prog list|grep tc_ingress|awk -F: '{print $1}')
  [[ -n $ingress ]] && echo "tc_ingress already loaded" && exit 1

  local egress
  egress=$(/opt/eklet-agent/bpftool prog list|grep tc_egress|awk -F: '{print $1}')
  [[ -n $egress ]] && echo "tc_egress already loaded. exit" && exit 1

  /opt/eklet-agent/snat "$ip_addr" "$SUBNET_RESERVED_IP" eth0 61001 65534 "$METRIC_PORT"
}

function set_nameserver() {
  local nameserver=${nameservers//\"/}
  cat << EOF > /etc/systemd/resolved.conf
[Resolve]
DNS=$nameserver
ReadEtcHosts=yes
Cache=yes
DNSOverTLS=no
DNSSEC=no
EOF
}

function set_instance() {
  echo "${instance_id}" > /etc/instance_id
}

function set_network() {
  mkdir -p "/etc/systemd/network/"
  local mask_bit
  mask_bit=$(mask2cdr "$netmask")
  cat << EOF > /etc/systemd/network/eth0.network
[Match]
Name=eth0

[Link]
MACAddress=$mac_addr

[Network]
LinkLocalAddressing=no
IPv6AcceptRA=no
DHCP=no
IPVLAN=ipvlan1
EOF

  cat << EOF > /etc/systemd/network/ipvlan1.netdev
[NetDev]
Kind=ipvlan
Name=ipvlan1

[IPVLAN]
Mode=L2
Flags=bridge
EOF

  cat << EOF > /etc/systemd/network/ipvlan1.network
[Match]
Name=ipvlan1

[Network]
LinkLocalAddressing=no
IPv6AcceptRA=no
Address=$SUBNET_RESERVED_IP/$mask_bit
Gateway=$gateway
EOF
}

function set_cni() {
  mkdir -p "/etc/cni/net.d/"
  local mask_bit
  mask_bit=$(mask2cdr "$netmask")
  cat << EOF > /etc/cni/net.d/10-containerd-net.conflist
{
  "cniVersion": "0.4.0",
  "name": "containerd-net",
  "plugins": [
    {
      "type": "ipvlan",
      "name": "main",
      "master": "eth0",
      "mode": "l2",
      "ipam": {
        "type": "static",
        "addresses": [
          {
            "address": "$ip_addr/$mask_bit",
            "gateway": "$gateway"
          }
        ],
        "routes": [
          { "dst": "0.0.0.0/0" }
        ]
      }
    }
  ]
}
EOF
}

function on_exit() {
  umount_cdrom
}

trap on_exit EXIT
remove_reserved
mount_cdrom
read_config
install_ebpf
set_nameserver
set_instance
set_network
set_cni