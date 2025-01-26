# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

source /provision/common.sh
source /provision/copyfile.sh
source /provision/vars.sh

if ! is_controller; then
    # Generate a unique compute UUID before installing, otherwise they're the same
    sed -i -e "s/COMPUTE_ID=\".*$/COMPUTE_ID=\"$(uuidgen)\"/" /etc/default/virl2

    systemctl stop NetworkManager
    hostnamectl set-hostname $(cloud-init query local_hostname)
    sed -i -e 's/^"hostname":.*$/"hostname": "'$(hostname -s)'"/' /etc/virl2-base-config.yml
    systemctl start NetworkManager
    cat /etc/virl2-base-config.yml

    # Fix BGP router ID, otherwise it uses the virbr0 IP, which is the same on all compute nodes
    BGP_ROUTER_ID="$(ip -j route show default | jq -r .[0].prefsrc)"
    # HACK cmm - BGP AS should be a variable
    printf "router bgp 65000\nbgp router-id ${BGP_ROUTER_ID}\nend" >> /etc/frr/frr-base.conf 
    vtysh -f /etc/frr/frr-base.conf
    vtysh -c "copy running-config startup-config"
    systemctl restart frr
else
    # Otherwise just load the base config
    vtysh -f /etc/frr/frr-base.conf
    vtysh -c "copy running-config startup-config"

    # Start routed external network (100.64.1.0/24)
    virsh net-define /provision/net-bah-external.xml
    virsh net-autostart bah-external
    virsh net-start bah-external
fi        
