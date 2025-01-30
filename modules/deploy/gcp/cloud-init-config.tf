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
      # Do nothing for GCP.  We don't need to fix interfaces.
      content = <<-EOF
        #!/usr/bin/env python3
        import sys
        sys.exit(0)
      EOF
    },
    {
      path        = "/provision/license.py"
      owner       = "root:root"
      permissions = "0700"
      content     = var.options.license
    },
    # Enable mDNS globally
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
    # Enable mDNS on cluster interface
    {
      path        = "/etc/systemd/network/10-netplan-cluster.network.d/override.conf"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [Network]
        MulticastDNS=yes
      EOF
    },
    # GCS FUSE config file
    # https://cloud.google.com/storage/docs/cloud-storage-fuse/config-file
    {
      path        = "/etc/gcsfuse/gcsfuse.yaml"
      owner       = "root:root"
      permissions = "0644"
      content     = yamlencode({
        file-cache = {
          max-size-mb = -1
          cache-file-for-range-read = false
        }
        metadata-cache = {
          stat-cache-max-size-mb = 32
          ttl-secs = 3600
          type-cache-max-size-mb = 4
        }
        cache-dir = "/srv/data/gcsfuse-cache"
      })
    },
    ],
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
          <mtu size="%{if config.mtu == null}${(local.cml_network_mtu - 50)}%{else}${config.mtu}%{endif}"/>
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
      {
        path        = "/etc/virl2-base-config.yml"
        owner       = "root:root"
        permissions = "0640"
        content     = yamlencode(local.cml_config_controller)
      },
      {
        path        = "/etc/netplan/60-${local.cluster_interface_name}.yaml"
        owner       = "root:root"
        permissions = "0600"
        content = yamlencode({
          network = {
            version = 2
            tunnels = {
              (local.cluster_vxlan_interface_name) = {
                mode = "vxlan"
                id   = local.cluster_vxlan_vnid
                link = var.options.cfg.gcp.controller_primary_interface_name
                port = 4789
                # MTU has 50 bytes overhead for VXLAN/UDP/IP header.
                mtu          = var.options.cfg.gcp.network_mtu - 50
                macaddress   = "random"
                mac-learning = false
                link-local   = []
              }
            }
            bridges = {
              (local.cluster_interface_name) = {
                interfaces = [
                  local.cluster_vxlan_interface_name,
                ]
                mtu = var.options.cfg.gcp.network_mtu - 50
                parameters = {
                  stp = false
                }
                # Fixed MAC address for the controller, so IPv6 link-local is stable.
                macaddress = local.cluster_controller_interface_mac
                link-local = ["ipv6"]
              }
            }
          }
        })
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
    ],
    # Only present on controller
    local.cloud_init_config_libvirt_networks
  )

  cloud_init_config_write_files_compute = concat(local.cloud_init_config_write_files_template,
    [
      {
        path        = "/etc/virl2-base-config.yml"
        owner       = "root:root"
        permissions = "0640"
        content     = yamlencode(local.cml_config_compute)
      },
      {
        path        = "/etc/netplan/60-${local.cluster_interface_name}.yaml"
        owner       = "root:root"
        permissions = "0600"
        content = yamlencode({
          network = {
            version = 2
            tunnels = {
              (local.cluster_vxlan_interface_name) = {
                mode = "vxlan"
                id   = local.cluster_vxlan_vnid
                link = var.options.cfg.gcp.compute_primary_interface_name
                port = 4789
                # MTU has 50 bytes overhead for VXLAN/UDP/IP header.
                mtu          = local.cml_network_mtu - 50
                macaddress   = "random"
                mac-learning = false
                link-local   = []
              }
            }
            bridges = {
              (local.cluster_interface_name) = {
                interfaces = [
                  local.cluster_vxlan_interface_name,
                ]
                mtu = local.cml_network_mtu - 50
                parameters = {
                  stp = false
                }
                # Random MAC address for the computes
                macaddress = "random"
                link-local = ["ipv6"]
              }
            }
          }
        })
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
      # FIXME cmm - Move to common template
      {
        path        = "/etc/systemd/system/format-gcsfuse-cache.service"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          [Unit]
          Description=Partition and format /dev/nvme0n1 for /srv/data/gcsfuse-cache
          After=dev-nvme0n1.device
          Before=srv-data-gcsfuse\x2dcache.mount
          ConditionPathExists=!/srv/data/gcsfuse-cache/.formatted

          [Service]
          Type=oneshot
          RemainAfterExit=true
          ExecStart=/bin/bash -c ' \
            if ! lsblk -f /dev/nvme0n1 | grep -q ext4; then \
              echo "Partitioning disk..." ; \
              parted /dev/nvme0n1 mklabel gpt ; \
              parted /dev/nvme0n1 mkpart primary ext4 2048s 100% ; \
              partprobe ; \
              echo "Formatting disk..." ; \
              mkfs.ext4 /dev/nvme0n1p1 ; \
              mkdir -p /srv/data/gcsfuse-cache ; \
              touch /srv/data/gcsfuse-cache/.formatted ; \
            fi ; \
          '
          [Install]
          WantedBy=multi-user.target
        EOF
      },
      {
        path        = "/etc/systemd/system/srv-data-gcsfuse\\x2dcache.mount"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          [Unit]
          Description=Mount /srv/data/gcsfuse-cache
          Requires=format-gcsfuse-cache.service
          After=format-gcsfuse-cache.service

          [Mount]
          What=/dev/nvme0n1p1
          Where=/srv/data/gcsfuse-cache
          Type=ext4
          Options=defaults

          [Install]
          WantedBy=multi-user.target
        EOF
      },
      {
        path        = "/etc/systemd/system/var-lib-libvirt-images.mount"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          [Unit]
          Description=libvirt images
          Requires=srv-data-gcsfuse\x2dcache.mount
          After=srv-data-gcsfuse\x2dcache.mount

          [Mount]
          # FIXME cmm - Allow bucket name to be specified
          What=bah-libvirt-images-ue1
          Where=/var/lib/libvirt/images
          Type=fuse.gcsfuse
          # uid libvirt-qemu, gid virl2
          Options=ro,uid=64055,gid=987,allow_other,config_file=/etc/gcsfuse/gcsfuse.yaml,_netdev

          [Install]
          WantedBy=multi-user.target
        EOF
      },
    ]
  )

  cloud_init_config_packages_template = [
    "curl",
    "jq",
    "network-manager",
    "frr",
  ]

  cloud_init_config_runcmd_template = [
    # Pick up new cluster interface
    "netplan apply",

    # Pick up new systemd-resolved configuration, enable mDNS
    "systemctl restart systemd-resolved",

    ## We should be using mDNS/IPv6 on the cluster link.  DNS is bad.
    "echo -n 'Cluster link scope: ' && resolvectl status cluster | awk '/Current Scopes/ { print $3 }'",

    # TODO cmm - fix firewalld config.  We're depending on GCP firewall for now.
    "systemctl disable --now firewalld",

    # Enable BGP daemon and restart FRR.  cml.sh will configure the rest.
    "sed -i 's/bgpd=no/bgpd=yes/' /etc/frr/daemons",
    "systemctl restart frr",

    # TODO cmm - Disable Google OSConfig.  It blocks shutdowns right now.  Need
    # to figure out why.
    "systemctl disable --now google-osconfig-agent.service",
  ]

  cloud_init_config_runcmd_controller = concat(local.cloud_init_config_runcmd_template,
    [
      # Install cml, do not reboot
      "/provision/cml.sh || echo 'CML provisioning failed.  Not rebooting' && false",
      "systemctl stop virl2.target",
      "systemctl disable --now virl2-remount-images.service",
      "rm -rf /var/lib/libvirt/images/*",
      # FIXME cmm - Make a mount unit without caching
      "echo 'bah-libvirt-images-ue1 /var/lib/libvirt/images fuse.gcsfuse ro,uid=64055,gid=987,allow_other,_netdev 1 1' >> /etc/fstab",
      "systemd daemon-reload",
      "mount /var/lib/libvirt/images",
      # Still need to export something, so computes are happy on install.
      "sed -i -e 's#^/var/lib/libvirt/images.*#/srv	fe80::%cluster/64(ro,sync,no_subtree_check,crossmnt,fsid=0,no_root_squash)#' /etc/exports",
      "exportfs -r",
      "systemctl start virl2.target",
    ]
  )

  cloud_init_config_runcmd_compute = concat(local.cloud_init_config_runcmd_template,
    [
      # Install cml, do not reboot
      "/provision/cml.sh || echo 'CML provisioning failed.' && false",
      # HACK FIXME cmm - use Google Cloud Storage instead
      "systemctl stop virl2.target",
      "systemctl disable --now virl2-remount-images.service",
      # Unmount NFS from controller
      "umount /var/lib/libvirt/images",
      # Remove the fstab entry
      "sed -i -e 's#^cml-controller.local.*#d' /etc/fstab",
      "systemctl daemon-reload",
      # Mount GCS FUSE libvir images
      "systemctl enable --now var-lib-libvirt-images.mount",
      # HACK cmm - Allow gcsfuse to work for /var/lib/libvirt/images. Keep the LLD happy.
      "sed -i 's/nfs4/fuse.gcsfuse/' /var/local/virl2/.local/lib/python3.12/site-packages/simple_drivers/low_level_driver/host_statistics.py",
      "systemctl start virl2.target",
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