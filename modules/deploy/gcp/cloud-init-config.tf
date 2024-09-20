#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2024, Cisco Systems, Inc.
# All rights reserved.
#

locals {

  cloud_init_config_write_files_template = concat([
    {
      path        = "/provision/refplat"
      owner       = "root:root"
      permissions = "0644"
      content     = jsonencode(var.options.cfg.refplat)
    },
    {
      path        = "/provision/cml.sh"
      owner       = "root:root"
      permissions = "0700"
      content     = var.options.cml
    },
    {
      path        = "/provision/common.sh"
      owner       = "root:root"
      permissions = "0700"
      content     = var.options.common
    },
    {
      path        = "/provision/copyfile.sh"
      owner       = "root:root"
      permissions = "0700"
      content     = var.options.copyfile
    },
    {
      path        = "/provision/vars.sh"
      owner       = "root:root"
      permissions = "0700"
      content     = format("%s\n%s", local.vars, var.options.extras)
    },
    {
      path        = "/provision/del.sh"
      owner       = "root:root"
      permissions = "0700"
      content     = var.options.del
    },
    {
      path        = "/provision/interface_fix.py"
      owner       = "root:root"
      permissions = "0700"
      content     = var.options.interface_fix
    },
    # Disable cloud-init network configuration.  Use systemd-networkd instead
    {
      path        = "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"
      owner       = "root:root"
      permissions = "0644"
      content = yamlencode({
        network = {
          config = "disabled"
        }
      })
    },
    # Enable mDNS
    {
      path        = "/etc/systemd/resolved.conf.d/mdns.conf"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [Resolve]
        MulticastDNS=yes
        LLMNR=no
      EOF
    },
    {
      path        = "/etc/systemd/network/20-${local.cluster_interface_name}.netdev"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [NetDev]
        Name=${local.cluster_interface_name}
        Kind=bridge
        [Bridge]
        VLANFiltering=0
      EOF
    },
    {
      path        = "/etc/systemd/network/20-${local.cluster_interface_name}.network"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [Match]
        Name=${local.cluster_interface_name}
        [BridgeVLAN]
        VLAN=1
        [Link]
        Multicast=yes
        [Network]
        MulticastDNS=yes
        LLMNR=no
        LinkLocalAddressing=ipv6
      EOF
    },
    {
      path        = "/etc/systemd/network/30-${local.cluster_vxlan_interface_name}.netdev"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [NetDev]
        Name=${local.cluster_vxlan_interface_name}
        Kind=vxlan
        [VXLAN]
        VNI=${local.cluster_vxlan_vnid}
        DestinationPort=4789
      EOF
    },
    {
      path        = "/etc/systemd/network/30-${local.cluster_vxlan_interface_name}.link"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [Match]
        OriginalName=${local.cluster_vxlan_interface_name}
        [Link]
        Name=${local.cluster_vxlan_interface_name}
      EOF
    },
    {
      path        = "/etc/systemd/network/30-${local.cluster_vxlan_interface_name}.network"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [Match]
        Name=${local.cluster_vxlan_interface_name}
        [Network]
        BindCarrier=${var.options.cfg.gcp.compute_primary_interface_name}
        Bridge=${local.cluster_interface_name}
        LLMNR=no
        [BridgeVLAN]
        VLAN=1
      EOF
    },
    # Force all interfaces unmanaged by NetworkManager
    {
      path        = "/etc/NetworkManager/conf.d/11-unmanaged.conf"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [keyfile]
        unmanaged-devices=*
      EOF
    }, ],
    [for script in var.options.cfg.app.customize : {
      path        = "/provision/${script}"
      owner       = "root:root"
      permissions = "0644"
      content     = file("${path.module}/../data/${script}")
      }
    ]
  )

  cloud_init_config_libvirt_networks = [for network_name, config in var.options.cfg.gcp.cml_custom_external_connections :
    {
      path        = "/provision/net-${network_name}.xml"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        <network>
          <name>${network_name}</name>
          <forward mode="%{if config.enable_nat}nat%{else}route%{endif}"/>
          <bridge name='${config.bridge_name}' stp='off' delay='0'/>
          <mtu size="%{if config.mtu == null}${local.cml_network_mtu}%{else}${config.mtu}%{endif}"/>
          %{if config.mac_address != null}<mac address="${config.mac_address}"/>%{endif}
          <ip address='${config.ip}' netmask='${config.netmask}'>
            <dhcp>
              <range start='${config.start}' end='${config.end}'/>
            </dhcp>
          </ip>
        </network>
      EOF
    }
  ]

  cloud_init_config_write_files_controller = concat(local.cloud_init_config_write_files_template,
    [
      # Replace cloud-init network configuration with systemd-networkd
      # configuration for the cluster bridge
      {
        path        = "/etc/systemd/network/10-${var.options.cfg.gcp.controller_primary_interface_name}.network"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          [Match]
          Name=${var.options.cfg.gcp.controller_primary_interface_name}
          [Network]
          # Both v4 and v6
          DHCP=yes
          LLMNR=no
          LinkLocalAddressing=ipv6
          VXLAN=${local.cluster_vxlan_interface_name}
          [DHCP]
          RouteMetric=100
          # HACK cmm - VXLAN interface won't inherit this MTU, so we set explicitly in link.
          UseMTU=true
        EOF
      },
      {
        path        = "/etc/systemd/network/10-${var.options.cfg.gcp.controller_primary_interface_name}.link"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          [Match]
          Path=pci-${var.options.cfg.gcp.controller_primary_interface_pci_path}
          [Link]
          Name=${var.options.cfg.gcp.controller_primary_interface_name}
          WakeOnLan=off
          MTUBytes=${local.cml_network_mtu}
        EOF
      },
      {
        path        = "/etc/systemd/network/20-${local.cluster_interface_name}.link"
        owner       = "root:root"
        permissions = "0644"
        # MTU has 50 bytes overhead for VXLAN/UDP/IP header.
        # Controller has a fixed MAC address that survives a reboot.  The
        # computes aren't as important.
        content = <<-EOF
          [Match]
          OriginalName=${local.cluster_interface_name}
          [Link]
          Name=${local.cluster_interface_name}
          MTUBytes=${local.cml_network_mtu - 50}
          MACAddress=${local.cluster_controller_interface_mac}
        EOF
      },
      {
        path        = "/etc/virl2-base-config.yml"
        owner       = "root:root"
        permissions = "0640"
        content     = yamlencode(local.cml_config_controller)
      },
      {
        path        = "/etc/frr/frr-base.conf"
        owner       = "root:root"
        permissions = "0640"
        content     = <<-EOF
          router bgp ${local.cluster_bgp_as}
           bgp router-id ${google_compute_address.cml_address_internal.address}
           neighbor VTEP peer-group
           neighbor VTEP remote-as ${local.cluster_bgp_as}
           bgp listen range ${google_compute_subnetwork.cml_subnet.ip_cidr_range} peer-group VTEP
           !
           address-family l2vpn evpn
            neighbor VTEP activate
            neighbor VTEP route-reflector-client
            advertise-all-vni
            advertise-svi-ip
           exit-address-family
          !
          ip nht resolve-via-default
          !
          end
        EOF
      },
      # Only present on controller
    ],
    local.cloud_init_config_libvirt_networks
  )

  cloud_init_config_write_files_compute = concat(local.cloud_init_config_write_files_template,
    [
      # Replace cloud-init network configuration with systemd-networkd
      # configuration for the cluster bridge
      {
        path        = "/etc/systemd/network/10-${var.options.cfg.gcp.compute_primary_interface_name}.network"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          [Match]
          Name=${var.options.cfg.gcp.compute_primary_interface_name}
          [Network]
          # Both v4 and v6
          DHCP=yes
          LLMNR=no
          LinkLocalAddressing=ipv6
          VXLAN=${local.cluster_vxlan_interface_name}
          [DHCP]
          RouteMetric=100
          # HACK cmm - VXLAN interface won't inherit this MTU, so we set explicitly in link.
          UseMTU=true
        EOF
      },
      {
        path        = "/etc/systemd/network/10-${var.options.cfg.gcp.compute_primary_interface_name}.link"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          [Match]
          Path=pci-${var.options.cfg.gcp.compute_primary_interface_pci_path}
          [Link]
          Name=${var.options.cfg.gcp.compute_primary_interface_name}
          WakeOnLan=off
          MTUBytes=${local.cml_network_mtu}
        EOF
      },
      {
        path  = "/etc/systemd/network/20-${local.cluster_interface_name}.link"
        owner = "root:root"

        permissions = "0644"
        # MTU has 50 bytes overhead for VXLAN/UDP/IP header.
        # Computes have random MAC addresses.
        content = <<-EOF
          [Match]
          OriginalName=${local.cluster_interface_name}
          [Link]
          Name=${local.cluster_interface_name}
          MTUBytes=${local.cml_network_mtu - 50}
          MACAddressPolicy=random
        EOF
      },
      {
        path        = "/etc/virl2-base-config.yml"
        owner       = "root:root"
        permissions = "0640"
        content     = yamlencode(local.cml_config_compute)
      },
      {
        path        = "/etc/frr/frr-base.conf"
        owner       = "root:root"
        permissions = "0640"
        content     = <<-EOF
          router bgp ${local.cluster_bgp_as}
           ! bgp router-id will be the primary interface, fixed in cml.sh
           neighbor VTEP peer-group
           neighbor VTEP remote-as ${local.cluster_bgp_as}
           neighbor ${google_compute_address.cml_address_internal.address} peer-group VTEP
           !
           address-family l2vpn evpn
            neighbor VTEP activate
            advertise-all-vni
            advertise-svi-ip
           exit-address-family
          !
          ip nht resolve-via-default
          !
        EOF
      },
    ]
  )

  cloud_init_config_packages_template = [
    "curl",
    "jq",
    "frr",
  ]

  cloud_init_config_runcmd_template = [
    # Changing networks on install after cloud-init is running is full of bugs
    # and race conditions.  It's not recommended, but we have to do it for now
    # so BGP EVPN VXLAN works.

    # Remove cloud-init and NetworkManager network configuration, as we've
    # replaced it with a systemd-networkd configuration
    "rm /etc/netplan/*",
    "rm /run/systemd/network/*",
    # Let the systemd-networkd configuration take effect
    "networkctl reload",
    # HACK cmm - VXLAN MTU won't be inherited by primary interface, so set explicitly
    # during initial configuration.  It's a race condition or a bug.  Subsequent
    # reboots will be fine.
    "sleep 5 && ip link set ${local.cluster_vxlan_interface_name} mtu ${local.cml_network_mtu - 50}",
    # Pick up new systemd-resolved configuration, enable mDNS
    "systemctl restart systemd-resolved",

    # We should be using mDNS/IPv6 on the cluster link.  DNS is bad.
    "echo -n 'Cluster link scope: ' && resolvectl status cluster | awk '/Current Scopes/ { print $3 }'",

    # Enable BGP daemon and restart FRR
    "sed -i 's/bgpd=no/bgpd=yes/' /etc/frr/daemons",
    "systemctl restart frr",

    # TODO cmm - Disable Google OSConfig.  It blocks shutdowns right now.  Need
    # to figure out why.
    "systemctl disable --now google-osconfig-agent.service",
  ]

  cloud_init_config_runcmd_controller = concat(local.cloud_init_config_runcmd_template,
    [
      # Install cml
      "/provision/cml.sh && touch /run/reboot || echo 'CML provisioning failed.  Not rebooting' && false",
      # Remove primary interface from NetworkManager, placed by
      # virl2-initial-setup.py.  This will be handled by systemd-networkd instead.
      "rm /etc/NetworkManager/system-connections/* || true",
      "systemctl restart NetworkManager",
      # Let the systemd-networkd configuration take effect again 
      "networkctl reload",
      # TODO cmm - fix firewalld config.  We're depending on GCP firewall for now.
      "systemctl disable firewalld",
    ]
  )

  cloud_init_config_runcmd_compute = concat(local.cloud_init_config_runcmd_template,
    [
      # Install cml, but do not reboot
      "/provision/cml.sh || echo 'CML provisioning failed.' && false",
      # Remove primary interface from NetworkManager, placed by
      # virl2-initial-setup.py.  This will be handled by systemd-networkd instead.
      "rm /etc/NetworkManager/system-connections/* || true",
      "systemctl restart NetworkManager",
      # Let the systemd-networkd configuration take effect again 
      "networkctl reload",
      # TODO cmm - fix firewalld config.  We're depending on GCP firewall for now.
      "systemctl disable firewalld",
    ]
  )

  cloud_init_config_template = {
    manage_etc_hosts = true

    packages = local.cloud_init_config_packages_template

    power_state = {
      mode      = "reboot"
      condition = "test -f /run/reboot"
    }
  }

  cloud_init_config_controller = merge(local.cloud_init_config_template, {
    hostname = local.controller_hostname

    package_update  = var.options.cfg.gcp.controller_image_family == null ? true : false
    package_upgrade = var.options.cfg.gcp.controller_image_family == null ? true : false

    write_files = local.cloud_init_config_write_files_controller

    runcmd = local.cloud_init_config_runcmd_controller
  })

  cloud_init_config_compute = merge(local.cloud_init_config_template, {
    # Use the hostname provided by the IMDS.  'hostname' is not set.

    package_update  = var.options.cfg.gcp.compute_image_family == null ? true : false
    package_upgrade = var.options.cfg.gcp.compute_image_family == null ? true : false

    write_files = local.cloud_init_config_write_files_compute

    runcmd = local.cloud_init_config_runcmd_compute
  })
}