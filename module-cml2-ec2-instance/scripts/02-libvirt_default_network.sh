#!/bin/bash

#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

# Destroy existing default network and set up IPv4 and IPv6 to forward packets
# without using NAT

set -e
set -x

virsh net-destroy default && virsh net-undefine default || virsh net-undefine default || true

NET_DEVICE=$(ip -j route show default | jq -r .[].dev)
NET_MAC=$(ip -j link show ${NET_DEVICE} | jq -r .[].address)
# Accept ICMPv6 Router Advertisements even if forwarding is enabled.  Libvirt
# wants it.
echo 2 > /proc/sys/net/ipv6/conf/${NET_DEVICE}/accept_ra

# TODO cmm - AWS by default allocates /28s for v4 prefixes, and this cannot be
# changed.  A /28 won't be enough for all pods and libvirt doesn't support DHCP
# with multiple prefixes.  DHCPv6 with /80s are fine, but I'd like to get
# DHCPv6-PD working.  Change all this junk over to routes in a private subnet
# with a NAT gateway.

TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
IPV4_PREFIX=`curl -s -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/network/interfaces/macs/${NET_MAC}/ipv4-prefix`
IPV6_PREFIX=`curl -s -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/network/interfaces/macs/${NET_MAC}/ipv6-prefix`

# HACK cmm - Yeah, this sucks, I know.  This script should probably be Python.
IPV4_FIRST=`python3 -c "import ipaddress as i;n=i.ip_network(\"${IPV4_PREFIX}\");print(n[1])"`
IPV4_SECOND=`python3 -c "import ipaddress as i;n=i.ip_network(\"${IPV4_PREFIX}\");print(n[2])"`
IPV4_LAST=`python3 -c "import ipaddress as i;n=i.ip_network(\"${IPV4_PREFIX}\");print(n[-2])"`
IPV4_NETMASK=`python3 -c "import ipaddress as i;n=i.ip_network(\"${IPV4_PREFIX}\");print(n.netmask)"`

IPV6_FIRST=`python3 -c "import ipaddress as i;n=i.ip_network(\"${IPV6_PREFIX}\");print(n[0])"`
IPV6_SECOND=`python3 -c "import ipaddress as i;n=i.ip_network(\"${IPV6_PREFIX}\");print(n[1])"`
IPV6_LAST=`python3 -c "import ipaddress as i;n=i.ip_network(\"${IPV6_PREFIX}\");print(n[0xff])"`
IPV6_PREFIXLEN=`python3 -c "import ipaddress as i;n=i.ip_network(\"${IPV6_PREFIX}\");print(n.prefixlen)"`

virsh net-define <(cat <<EOF
<network>
  <name>default</name>
  <!-- <uuid>98739091-4ac9-4e0f-b2a5-b94b38b9cf11</uuid> -->
  <forward mode='route' dev='ens5'/>
  <bridge name='virbr0' stp='off' delay='0'/>
  <mac address='52:54:00:bb:cf:de'/>
  <ip address='${IPV4_FIRST}' netmask='${IPV4_NETMASK}'>
    <dhcp>
      <range start='${IPV4_SECOND}' end='${IPV4_LAST}'/>
    </dhcp>
  </ip>
  <ip family='ipv6' address='${IPV6_FIRST}' prefix='${IPV6_PREFIXLEN}'>
    <dhcp>
      <range start='${IPV6_SECOND}' end='${IPV6_LAST}'/>
    </dhcp>
  </ip>
</network>
EOF
)

virsh net-autostart default
virsh net-start default

set +e
set +x
