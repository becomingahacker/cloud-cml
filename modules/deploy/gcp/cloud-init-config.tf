#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2026, Cisco Systems, Inc.
# All rights reserved.
#

data "http" "gcp_cloud_ipranges" {
  url = "https://www.gstatic.com/ipranges/cloud.json"

  lifecycle {
    postcondition {
      condition     = self.status_code == 200
      error_message = "Failed to download GCP cloud IP ranges from https://www.gstatic.com/ipranges/cloud.json"
    }
  }
}

locals {

  # Published Google Cloud IPv4/IPv6 prefixes for this deployment region plus
  # scope "global". Prepended to BGP allow_in / allow_out from YAML; see
  # https://www.gstatic.com/ipranges/cloud.json
  gcp_cloud_ipranges = jsondecode(data.http.gcp_cloud_ipranges.response_body)

  gcp_cloud_iprange_scopes = toset([var.options.cfg.gcp.region, "global"])

  gcp_cloud_ipv4_cidrs = sort(tolist(toset([
    for p in try(local.gcp_cloud_ipranges.prefixes, []) :
    p.ipv4Prefix
    if try(p.ipv4Prefix, null) != null && try(p.service, "") == "Google Cloud" && contains(local.gcp_cloud_iprange_scopes, try(p.scope, ""))
  ])))

  gcp_cloud_ipv6_cidrs = sort(tolist(toset([
    for p in try(local.gcp_cloud_ipranges.prefixes, []) :
    p.ipv6Prefix
    if try(p.ipv6Prefix, null) != null && try(p.service, "") == "Google Cloud" && contains(local.gcp_cloud_iprange_scopes, try(p.scope, ""))
  ])))

  gcp_cloud_ipv4_bgp_entries = [for cidr in local.gcp_cloud_ipv4_cidrs : { cidr = cidr, le = 32 }]
  gcp_cloud_ipv6_bgp_entries = [for cidr in local.gcp_cloud_ipv6_cidrs : { cidr = cidr, ge = 96 }]

  cml_bgp_prefix_lists = {
    for name, cfg in var.options.cfg.gcp.cml_custom_external_connections : name => {
      ipv4_allow_in  = concat(local.gcp_cloud_ipv4_bgp_entries, try(cfg.bgp.ipv4.allow_in, []))
      ipv4_allow_out = concat(local.gcp_cloud_ipv4_bgp_entries, try(cfg.bgp.ipv4.allow_out, []))
      ipv6_allow_in  = concat(local.gcp_cloud_ipv6_bgp_entries, try(cfg.bgp.ipv6.allow_in, []))
      ipv6_allow_out = concat(local.gcp_cloud_ipv6_bgp_entries, try(cfg.bgp.ipv6.allow_out, []))
    }
    if try(cfg.bgp, null) != null
  }

  cloud_init_config_write_files_template = concat(
    [
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
        # Remove the cml2 generated interface, if it exists
        content = <<-EOF
          #!/usr/bin/env python3
          import sys
          import os
          try:
            os.unlink("/etc/netplan/00-cml2-base.yaml") 
          except FileNotFoundError:
            pass
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
      {
        # Google Guest Agent configuration
        # https://github.com/GoogleCloudPlatform/guest-agent/blob/main/google_guest_agent/cfg/cfg.go
        path        = "/etc/default/instance_configs.cfg"
        owner       = "root:root"
        permissions = "0640"
        content     = <<-EOF
          # Disable network setup.  cloud-init will take care of that.
          # Disable passthrough local IP routes (protocol 66).  These will be
          # overridden by the BGP routes advertised from labs.
          [NetworkInterfaces]
          setup = false
          ip_forwarding = false
          manage_primary_nic = false
          # Done by cloud-init
          [InstanceSetup]
          set_host_keys = false
        EOF
      },
      # GCS FUSE config file
      # https://cloud.google.com/storage/docs/cloud-storage-fuse/config-file
      {
        path        = "/etc/gcsfuse/gcsfuse.yaml"
        owner       = "root:root"
        permissions = "0644"
        content = yamlencode({
          file-cache = {
            max-size-mb               = -1
            cache-file-for-range-read = false
            enable-parallel-downloads = true
          }
          file-system = {
            # libvirt-qemu
            uid = 64055
            # virl2
            gid       = 987
            dir-mode  = "775"
            file-mode = "664"
          }
          metadata-cache = {
            stat-cache-max-size-mb = 32
            ttl-secs               = 3600
            type-cache-max-size-mb = 4
          }
          cache-dir = "/srv/data/gcsfuse-cache"
        })
      },
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
          What=${var.options.cfg.gcp.libvirt_images_bucket}
          Where=/var/lib/libvirt/images
          Type=fuse.gcsfuse
          # Change to rw if you want to make changes on the controller.
          Options=ro,allow_other,config_file=/etc/gcsfuse/gcsfuse.yaml,_netdev
  
          [Install]
          WantedBy=multi-user.target
        EOF
      },
      {
        path        = "/etc/tmpfiles.d/sshd.conf"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          # Create sshd privilege separation directory
          d /run/sshd 0755 root root
        EOF
      },
      {
        path        = "/usr/local/bin/virl2-remount-images.sh"
        owner       = "root:root"
        permissions = "0755"
        content     = <<-EOF
          #!/usr/bin/env bash
          #
          # This file is a part of VIRL 2
          # Copyright (c) 2019-2026, Cisco Systems, Inc.
          # All rights reserved.
          #

          # Configuration variables and log prep function
          source /etc/default/virl2
          set -Eeuo pipefail

          state_path="$BASE_DIR/base_images.state"
          image_root="$LIBVIRT_IMAGES/virl-base-images"
          ret=0

          function update_state() {
              if [[ $ret -eq 0 && -d "$image_root" ]]; then
                  find "$image_root" -mindepth 1 -maxdepth 1 -type d | wc -l >"$state_path.new"
                  mv "$state_path.new" "$state_path"
              else
                  rm -f "$state_path"
              fi
          }

          if [[ "$RUN_CONTROLLER" = "1" ]]; then
              update_state
              exit 0
          fi

          do_mount=true
          is_mounted=false
          mount_type=""
          if grep -q "$LIBVIRT_IMAGES.*fuse\.gcsfuse" /proc/mounts; then
              is_mounted=true
              mount_type="gcsfuse"
          elif grep "$LIBVIRT_IMAGES.*nfs4" /proc/mounts | grep -v -e 'vers=3' >/dev/null; then
              is_mounted=true
              mount_type="nfs"
          fi

          # if mount exists, verify the mount point actually works; final stat gets EPERM if not
          # the mount point may also be in stale IO state, the subprocess must be killed then
          (
              $is_mounted &&
                  if [[ "$mount_type" = "nfs" ]]; then
                      stat -f "$LIBVIRT_IMAGES" | grep "Type: nfs" >/dev/null
                  else
                      stat -f "$LIBVIRT_IMAGES" | grep "Type: fuseblk" >/dev/null
                  fi &&
                  stat "$LIBVIRT_IMAGES" >/dev/null
          ) &
          pid=$!
          sleep 0.2

          declare -i counter=10
          while [[ -d /proc/$pid ]]; do
              if [[ $counter -eq 0 ]]; then
                  kill -9 $pid
                  echo "$mount_type share at $LIBVIRT_IMAGES was stuck. Please check cluster network connectivity."
                  break
              fi
              counter+=-1
              sleep 0.5
          done

          wait $pid || ret=$?
          update_state

          if [[ $ret -eq 0 ]]; then
              echo "$mount_type share at $LIBVIRT_IMAGES is mounted."
              do_mount=false
          elif $is_mounted; then
              if [[ "$mount_type" = "nfs" ]]; then
                  umount -fl "$LIBVIRT_IMAGES" || ret=$?
              else
                  systemctl stop var-lib-libvirt-images.mount || ret=$?
              fi
              if [[ $ret -eq 0 ]]; then
                  echo "Umounting stuck $mount_type share succeeded, will try to remount."
              else
                  echo "Umounting stuck $mount_type share failed."
                  do_mount=false
              fi
          fi

          if $do_mount; then
              echo "Mounting $${mount_type:-remote} share..."
              ret=0
              if [[ "$mount_type" = "nfs" ]]; then
                  mount "$LIBVIRT_IMAGES" || ret=$?
              else
                  systemctl start var-lib-libvirt-images.mount || ret=$?
              fi
              if [[ $ret -eq 0 ]]; then
                  echo "Mounting $${mount_type:-remote} share succeeded."
                  update_state
              else
                  echo "Mounting $${mount_type:-remote} share failed."
              fi
          fi
          exit $ret

        EOF
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
          <forward mode="${config.forward_mode}"/>
          <bridge name='${network_name}' stp='off' delay='0' zone='dmz'/>
          <mtu size="%{if try(config.mtu, null) == null}${(local.cml_network_mtu)}%{else}${config.mtu}%{endif}"/>
          %{if config.mac_address != null}<mac address="${config.mac_address}"/>%{endif}
          <ip address='%{if config.gateway == "last"}${cidrhost(config.cidr, -2)}%{else}${cidrhost(config.cidr, 1)}%{endif}' netmask='${cidrnetmask(config.cidr)}'>
            <dhcp>
              <range start='${cidrhost(config.cidr, -3)}' end='%{if config.gateway == "last"}${cidrhost(config.cidr, -2)}%{else}${cidrhost(config.cidr, -3)}%{endif}'/>
            </dhcp>
          </ip>
          <ip family='ipv6' address='${cidrhost(config.cidr_v6, config.gateway_v6 == "last" ? 65535 : 1)}' prefix='64'>
            <dhcp>
              <range start='${cidrhost(cidrsubnet(config.cidr_v6, 16, 0), 32768)}' end='${cidrhost(cidrsubnet(config.cidr_v6, 16, 0), 65534)}'/>
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
        path        = "/etc/sysctl.d/60-cml-ip-forward.conf"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          # Persistent IPv4/IPv6 forwarding (survives reboot). Applied in cloud-init runcmd.
          net.ipv4.ip_forward = 1
          net.ipv4.conf.all.forwarding = 1
          net.ipv4.conf.default.forwarding = 1
          net.ipv6.conf.all.forwarding = 1
          net.ipv6.conf.default.forwarding = 1
        EOF
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
                mtu          = local.cml_network_mtu - 50
                macaddress   = "random"
                mac-learning = false
                link-local   = []
                dhcp4        = false
                dhcp6        = false
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
                # Fixed MAC address for the controller, so IPv6 link-local is stable.
                macaddress = local.cluster_controller_interface_mac
                link-local = ["ipv6"]
                dhcp4      = false
                dhcp6      = false
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
          !
          !ip route ${local.bridge0_cidr} Null0 200
          ! 
          !ipv6 route ${local.bridge0_cidr_v6} Null0 200
          ! 
          %{for network_name, config in var.options.cfg.gcp.cml_custom_external_connections}
          %{if try(config.bgp, null) != null}
          %{for i in range(length(local.cml_bgp_prefix_lists[network_name].ipv4_allow_out))}
          ip prefix-list CML_${network_name}_OUT seq ${i + 1} permit ${local.cml_bgp_prefix_lists[network_name].ipv4_allow_out[i].cidr}%{if try(local.cml_bgp_prefix_lists[network_name].ipv4_allow_out[i].le, null) != null} le ${local.cml_bgp_prefix_lists[network_name].ipv4_allow_out[i].le}%{endif}%{if try(local.cml_bgp_prefix_lists[network_name].ipv4_allow_out[i].ge, null) != null} ge ${local.cml_bgp_prefix_lists[network_name].ipv4_allow_out[i].ge}%{endif}
          %{endfor}
          !
          route-map CML_${network_name}_OUT permit 10
           match ip address prefix-list CML_${network_name}_OUT
          exit
          !
          route-map CML_${network_name}_OUT deny 20
          exit
          !
          %{for i in range(length(local.cml_bgp_prefix_lists[network_name].ipv4_allow_in))}
          ip prefix-list CML_${network_name}_IN seq ${i + 1} permit ${local.cml_bgp_prefix_lists[network_name].ipv4_allow_in[i].cidr}%{if try(local.cml_bgp_prefix_lists[network_name].ipv4_allow_in[i].le, null) != null} le ${local.cml_bgp_prefix_lists[network_name].ipv4_allow_in[i].le}%{endif}%{if try(local.cml_bgp_prefix_lists[network_name].ipv4_allow_in[i].ge, null) != null} ge ${local.cml_bgp_prefix_lists[network_name].ipv4_allow_in[i].ge}%{endif}
          %{endfor}
          !
          route-map CML_${network_name}_IN permit 10
           match ip address prefix-list CML_${network_name}_IN
          exit
          !
          route-map CML_${network_name}_IN deny 20
          exit
          !
          %{for i in range(length(local.cml_bgp_prefix_lists[network_name].ipv6_allow_out))}
          ipv6 prefix-list CML_${network_name}_OUT_V6 seq ${i + 1} permit ${local.cml_bgp_prefix_lists[network_name].ipv6_allow_out[i].cidr}%{if try(local.cml_bgp_prefix_lists[network_name].ipv6_allow_out[i].le, null) != null} le ${local.cml_bgp_prefix_lists[network_name].ipv6_allow_out[i].le}%{endif}%{if try(local.cml_bgp_prefix_lists[network_name].ipv6_allow_out[i].ge, null) != null} ge ${local.cml_bgp_prefix_lists[network_name].ipv6_allow_out[i].ge}%{endif}
          %{endfor}
          !
          route-map CML_${network_name}_OUT_V6 permit 10
           match ipv6 address prefix-list CML_${network_name}_OUT_V6
          exit
          !
          route-map CML_${network_name}_OUT_V6 deny 20
          exit
          !
          %{for i in range(length(local.cml_bgp_prefix_lists[network_name].ipv6_allow_in))}
          ipv6 prefix-list CML_${network_name}_IN_V6 seq ${i + 1} permit ${local.cml_bgp_prefix_lists[network_name].ipv6_allow_in[i].cidr}%{if try(local.cml_bgp_prefix_lists[network_name].ipv6_allow_in[i].le, null) != null} le ${local.cml_bgp_prefix_lists[network_name].ipv6_allow_in[i].le}%{endif}%{if try(local.cml_bgp_prefix_lists[network_name].ipv6_allow_in[i].ge, null) != null} ge ${local.cml_bgp_prefix_lists[network_name].ipv6_allow_in[i].ge}%{endif}
          %{endfor}
          !
          route-map CML_${network_name}_IN_V6 permit 10
           match ipv6 address prefix-list CML_${network_name}_IN_V6
          exit
          !
          route-map CML_${network_name}_IN_V6 deny 20
          exit
          !
          %{endif}
          %{endfor}
          !
          router bgp ${local.cluster_bgp_as}
           bgp router-id ${google_compute_address.cml_controller_internal.address}
           neighbor VTEP peer-group
           neighbor VTEP remote-as ${local.cluster_bgp_as}
           bgp listen range ${google_compute_subnetwork.cml_subnet.ip_cidr_range} peer-group VTEP
           %{for network_name, config in var.options.cfg.gcp.cml_custom_external_connections}
           %{if try(config.bgp, null) != null}
           neighbor CML_${network_name} peer-group
           neighbor CML_${network_name} remote-as ${config.bgp.remote_as}
           neighbor CML_${network_name} ttl-security hops 1
           bgp listen range ${config.cidr} peer-group CML_${network_name}
           neighbor CML_${network_name}_V6 peer-group
           neighbor CML_${network_name}_V6 remote-as ${config.bgp.remote_as}
           neighbor CML_${network_name}_V6 ttl-security hops 1 
           bgp listen range ${cidrsubnet(local.bridge0_cidr_v6, 8, 0)} peer-group CML_${network_name}_V6
           %{endif}
           %{endfor}
           !
           address-family l2vpn evpn
            neighbor VTEP activate
            neighbor VTEP route-reflector-client
            advertise-all-vni
            advertise-svi-ip
           exit-address-family
           !
           address-family ipv4 unicast
           %{for network_name, config in var.options.cfg.gcp.cml_custom_external_connections}
           %{if try(config.bgp, null) != null}
            neighbor CML_${network_name} activate
           %{if try(config.bgp.ipv4.originate_default, false)}
            neighbor CML_${network_name} default-originate
           %{endif}
            neighbor CML_${network_name} route-map CML_${network_name}_IN in
            neighbor CML_${network_name} route-map CML_${network_name}_OUT out
            neighbor CML_${network_name}_V6 activate
           %{if try(config.bgp.ipv6.originate_default, false)}
            neighbor CML_${network_name}_V6 default-originate
           %{endif}
            neighbor CML_${network_name}_V6 route-map CML_${network_name}_IN in
            neighbor CML_${network_name}_V6 route-map CML_${network_name}_OUT out
           %{endif}
           %{endfor}
            neighbor VTEP activate
            neighbor VTEP route-reflector-client
            neighbor VTEP next-hop-self
           exit-address-family
           !
           address-family ipv6 unicast
           %{for network_name, config in var.options.cfg.gcp.cml_custom_external_connections}
           %{if try(config.bgp, null) != null}
            neighbor CML_${network_name}_V6 activate
           %{if try(config.bgp.ipv6.originate_default, false)}
            neighbor CML_${network_name}_V6 default-originate
           %{endif}
            neighbor CML_${network_name}_V6 route-map CML_${network_name}_IN_V6 in
            neighbor CML_${network_name}_V6 route-map CML_${network_name}_OUT_V6 out
           %{endif}
           %{endfor}
           exit-address-family
          exit
          !
          ip nht resolve-via-default
          !
          end
        EOF
      },
      {
        path        = "/etc/radvd.conf"
        owner       = "root:root"
        permissions = "0640"
        # FIXME cmm - only supports one network right now
        content = <<-EOF
          %{for network_name, config in var.options.cfg.gcp.cml_custom_external_connections}
          interface ${network_name}
          {
            AdvSendAdvert on;
            AdvManagedFlag on;
            prefix ${cidrsubnet(local.bridge0_cidr_v6, 8, 0)}
            {
              AdvOnLink on;
              AdvAutonomous on;
              AdvRouterAddr on;
            };
          };
          %{endfor}
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
           neighbor ${google_compute_address.cml_controller_internal.address} peer-group VTEP
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

  # Adding new packages to this will do an automatic `apt update` at install.
  # Not used right now.
  cloud_init_config_packages_template = [
    "curl",
    "jq",
    "network-manager",
    "frr",
  ]

  cloud_init_config_packages_controller = concat(local.cloud_init_config_packages_template,
    [
      "radvd",
  ])

  cloud_init_config_packages_compute = concat(local.cloud_init_config_packages_template,
    [
  ])

  cloud_init_config_runcmd_template = [
    "set -x",
    # Disable Avahi, which may conflict with systemd-resolved for mDNS
    "systemctl disable --now avahi-daemon.socket",
    "systemctl disable --now avahi-daemon.service",

    # Pick up new cluster interface
    "netplan apply",

    # Pick up new systemd-resolved configuration, enable mDNS
    "systemctl restart systemd-resolved",

    # Pick up new guest-agent config, so processes don't fight over network
    # addresses.
    "systemctl restart google-guest-agent.service",
    # We should be using mDNS/IPv6 on the cluster link.  DNS is bad.
    "echo -n 'Cluster link scope: ' && resolvectl status cluster | awk '/Current Scopes/ { print $3 }'",

    #TODO cmm - fix firewalld config.  We're depending on GCP firewall for now.
    "systemctl enable --now firewalld",

    # Make sure primary interface is really in the public zone.  Use ifindex
    # because addressing might be messed up.
    "PRIMARY_INTERFACE=`ip -j link  | jq -r '.[] | select(.ifindex == 2) | .ifname'`",
    "firewall-cmd --zone=public --change-interface=$PRIMARY_INTERFACE",

    # Enable BGP daemon and restart FRR.  cml.sh will configure the rest.
    "sed -i 's/bgpd=no/bgpd=yes/' /etc/frr/daemons",
    "systemctl restart frr",

    # TODO cmm - Disable Google OSConfig.  It blocks shutdowns right now.  Need
    # to figure out why.
    "systemctl disable --now google-osconfig-agent.service",

    "firewall-cmd --permanent --new-service=vxlan",
    "firewall-cmd --permanent --service=vxlan --add-port=4789/udp",
    "firewall-cmd --permanent --service=vxlan --add-source-port=32768-60999/udp",
    "firewall-cmd --reload",

    "systemctl enable --now virl2.target",
  ]

  cloud_init_config_runcmd_controller = concat(local.cloud_init_config_runcmd_template,
    [
      # For troubleshooting, disable when not in use.  Serial console only.
      #"echo 'root:CHANGEME' | /usr/sbin/chpasswd",
      #"exit 0",
      # Install cml, do not reboot
      "/provision/cml.sh || echo 'CML provisioning failed.  Not rebooting' && false",
      "systemctl stop virl2.target",
      # Remove any CML-generated netplan configs
      "rm -f /etc/netplan/*-cml2-* || true",
      # Remove any NM-generated netplan configs
      "rm -f /etc/netplan/90-NM-*.yaml || true",
      "systemctl disable --now virl2-remount-images.service",
      "systemctl daemon-reload",
      # Mount GCS FUSE libvirt images
      "systemctl enable --now var-lib-libvirt-images.mount",
      # Still need to export something, so computes are happy on install.
      "sed -i -e 's#^/var/lib/libvirt/images.*#/srv	fe80::%cluster/64(ro,sync,no_subtree_check,crossmnt,fsid=0,no_root_squash)#' /etc/exports",
      "exportfs -r",
      "systemctl enable --now virl2.target",
      # Start radvd for IPv6 autoconfiguration
      "systemctl enable --now radvd",
      # FIXME cmm - Needs to be made persistent
      "resolvectl mdns bridge0 no",
      # Wait for cluster interface (BGP EVPN) to come up
      "while ! firewall-cmd --zone=cluster-internal --list-interfaces ; do sleep 5; done",
      "firewall-cmd --permanent --zone=public --add-service=bgp",
      "firewall-cmd --permanent --zone=public --add-service=vxlan",
      # Put bridge0 interface in the DMZ and add the same services as the
      # libvirt zone. This interface is used for BAH labs.  We don't want
      # students logging in with SSH.
      "firewall-cmd --permanent --zone=dmz --remove-service=ssh",
      "firewall-cmd --permanent --zone=dmz --add-service=dhcp",
      "firewall-cmd --permanent --zone=dmz --add-service=dhcpv6",
      "firewall-cmd --permanent --zone=dmz --add-service=dns",
      "firewall-cmd --permanent --zone=dmz --add-service=tftp",
      "firewall-cmd --permanent --zone=dmz --add-service=bgp",
      "firewall-cmd --permanent --zone=dmz --add-service=ntp",
      "firewall-cmd --permanent --zone=dmz --add-interface=bridge0",
      # IPv4/IPv6 forwarding for labs (bridge0), BGP, and policy routing; sysctl file persists across reboots.
      "sysctl -p /etc/sysctl.d/60-cml-ip-forward.conf",
      # HACK cmm - Policy names are limited to 18 characters.
      # INVALID_NAME: Policy 'from-public-to-dmz-ssh': name has 22 chars, max is 18
      "firewall-cmd --permanent --new-policy=dmz-to-public",
      "firewall-cmd --permanent --policy=dmz-to-public --add-ingress-zone=dmz",
      "firewall-cmd --permanent --policy=dmz-to-public --add-egress-zone=public",
      # HACK cmm - Remove masquerade so all pods assume a global address. 
      # Leave available for future use.
      #"firewall-cmd --permanent --policy=from-dmz-to-public --add-masquerade",
      # Labs (dmz→public): block cloud instance metadata (e.g. GCP 169.254.169.254) and ports 80, 443, 8080-8083.
      "firewall-cmd --permanent --policy=dmz-to-public --add-rich-rule='rule family=\"ipv4\" destination address=\"169.254.169.254\" port port=\"80\" protocol=\"tcp\" reject'",
      "firewall-cmd --permanent --policy=dmz-to-public --add-rich-rule='rule family=\"ipv4\" destination address=\"169.254.169.254\" port port=\"443\" protocol=\"tcp\" reject'",
      "firewall-cmd --permanent --policy=dmz-to-public --add-rich-rule='rule family=\"ipv4\" destination address=\"169.254.169.254\" port port=\"8080-8083\" protocol=\"tcp\" reject'",
      "firewall-cmd --permanent --policy=dmz-to-public --add-rich-rule='rule family=\"ipv6\" destination address=\"fd20:ce::254\" port port=\"80\" protocol=\"tcp\" reject'",
      "firewall-cmd --permanent --policy=dmz-to-public --add-rich-rule='rule family=\"ipv6\" destination address=\"fd20:ce::254\" port port=\"443\" protocol=\"tcp\" reject'",
      "firewall-cmd --permanent --policy=dmz-to-public --add-rich-rule='rule family=\"ipv6\" destination address=\"fd20:ce::254\" port port=\"8080-8083\" protocol=\"tcp\" reject'",
      "firewall-cmd --permanent --policy=dmz-to-public --set-target=ACCEPT",
      "firewall-cmd --permanent --new-policy=public-to-dmz-ssh",
      "firewall-cmd --permanent --policy=public-to-dmz-ssh --add-ingress-zone=public",
      "firewall-cmd --permanent --policy=public-to-dmz-ssh --add-egress-zone=dmz",
      "firewall-cmd --permanent --policy=public-to-dmz-ssh --add-rich-rule='rule family=\"ipv4\" destination address=\"${local.bridge0_cidr}\" service name=\"ssh\" accept'",
      "firewall-cmd --permanent --policy=public-to-dmz-ssh --add-rich-rule='rule family=\"ipv6\" destination address=\"${local.bridge0_cidr_v6}\" service name=\"ssh\" accept'",
      # Lower firewalld policy priority value = runs first. SSH must precede pub-to-dmz-icmp (REJECT default).
      "firewall-cmd --permanent --policy=public-to-dmz-ssh --set-priority=-100",
      # Non-SSH public→dmz passes to the next policy (ICMP allow + REJECT rest).
      "firewall-cmd --permanent --policy=public-to-dmz-ssh --set-target=CONTINUE",
      # Public → dmz (labs on bridge0): ICMP after SSH policy; REJECT only what SSH did not already accept.
      "firewall-cmd --permanent --new-policy=pub-to-dmz-icmp",
      "firewall-cmd --permanent --policy=pub-to-dmz-icmp --add-ingress-zone=public",
      "firewall-cmd --permanent --policy=pub-to-dmz-icmp --add-egress-zone=dmz",
      "firewall-cmd --permanent --policy=pub-to-dmz-icmp --set-priority=100",
      "firewall-cmd --permanent --policy=pub-to-dmz-icmp --add-rich-rule='rule family=\"ipv4\" protocol value=\"icmp\" accept'",
      "firewall-cmd --permanent --policy=pub-to-dmz-icmp --add-rich-rule='rule family=\"ipv6\" protocol value=\"ipv6-icmp\" accept'",
      "firewall-cmd --permanent --policy=pub-to-dmz-icmp --set-target=REJECT",
      "firewall-cmd --reload",
    ]
  )

  cloud_init_config_runcmd_compute = concat(local.cloud_init_config_runcmd_template,
    [
      # For troubleshooting, disable when not in use.  Serial console only.
      #"echo 'root:CHANGEME' | /usr/sbin/chpasswd",
      #"exit 0",
      # Install cml, do not reboot
      "/provision/cml.sh || echo 'CML provisioning failed.' && false",
      # Remove any CML-generated netplan configs
      "rm -f /etc/netplan/*-cml2-* || true",
      # Remove any NM-generated netplan configs
      "rm -f /etc/netplan/90-NM-*.yaml || true",
      # HACK cmm - use Google Cloud Storage instead
      "systemctl stop virl2.target",
      # Stop process that tries to remount NFS from controller.  Use GCS instead.
      "systemctl disable --now virl2-remount-images.service",
      # Unmount NFS from controller
      "umount /var/lib/libvirt/images || true",
      # Remove the fstab entry
      "sed -i '/^cml-controller.local.*/d' /etc/fstab",
      "systemctl daemon-reload",
      # Mount GCS FUSE libvirt images
      "systemctl enable --now var-lib-libvirt-images.mount",
      # HACK cmm - Allow gcsfuse to work for /var/lib/libvirt/images. Keep the LLD happy.
      "systemctl enable --now virl2.target",
      # Wait for cluster interface to come up
      "while ! firewall-cmd --zone=cluster-internal --list-interfaces ; do sleep 5; done",
      "firewall-cmd --permanent --zone=cluster-internal --add-port=1122/tcp",
      "firewall-cmd --permanent --zone=public --add-service=vxlan",
      "firewall-cmd --reload",
    ]
  )

  cloud_init_config_template = {
    manage_etc_hosts = true


    power_state = {
      mode      = "reboot"
      condition = "test -f /run/reboot"
    }
  }

  cloud_init_config_controller = merge(local.cloud_init_config_template, {
    hostname = local.controller_hostname

    package_update  = try(var.options.cfg.gcp.controller_image_family, null) == null ? true : false
    package_upgrade = try(var.options.cfg.gcp.controller_image_family, null) == null ? true : false

    # Enable if new packages are needed.
    #packages = local.cloud_init_config_packages_controller

    write_files = local.cloud_init_config_write_files_controller

    runcmd = local.cloud_init_config_runcmd_controller
  })

  cloud_init_config_compute = merge(local.cloud_init_config_template, {
    # Use the hostname provided by the IMDS.  'hostname' is not set.

    package_update  = try(var.options.cfg.gcp.compute_image_family, null) == null ? true : false
    package_upgrade = try(var.options.cfg.gcp.compute_image_family, null) == null ? true : false

    # Enable if new packages are needed.
    #packages = local.cloud_init_config_packages_compute

    write_files = local.cloud_init_config_write_files_compute

    runcmd = local.cloud_init_config_runcmd_compute
  })
}