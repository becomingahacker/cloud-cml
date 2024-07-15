#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2024, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  controller_hostname = var.options.cfg.common.controller_hostname
  num_computes        = var.options.cfg.cluster.enable_cluster ? var.options.cfg.cluster.number_of_compute_nodes : 0

  # Late binding required as the token is only known within the module.
  # (Azure specific)
  vars = templatefile("${path.module}/../data/vars.sh", {
    cfg = merge(
      var.options.cfg,
      # Need to have this as it's referenced in the template.
      # (Azure specific)
      { sas_token = "undefined" }
    )
    }
  )

  cml_config_template = {
    admins = {
      controller = {
        username = var.options.cfg.secrets.app.username
        password = var.options.cfg.secrets.app.secret
      }
      system = {
        username = var.options.cfg.secrets.sys.username
        password = var.options.cfg.secrets.sys.secret
      }
    }
    # HACK cmm - This must be set for NFS to work
    cluster_interface = "cluster"
    compute_secret    = var.options.cfg.secrets.cluster.secret
    controller_name   = local.controller_hostname
    copy_iso_to_disk  = false
    interactive       = false
    is_cluster        = var.options.cfg.cluster.enable_cluster
    is_configured     = false
    # HACK cmm - This must be set to do controller steps in virl2-initial-setup.py
    primary_interface   = "ens4"
    ssh_server          = true
    use_ipv4_dhcp       = true
    skip_primary_bridge = true
  }

  cml_config_controller = merge(local.cml_config_template, {
    hostname      = local.controller_hostname
    is_controller = true
    is_compute    = !var.options.cfg.cluster.enable_cluster || var.options.cfg.cluster.allow_vms_on_controller
  })

  cml_config_compute = merge(local.cml_config_template, {
    # Will update this in cml.sh
    hostname      = ""
    is_controller = false
    is_compute    = true
  })

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
      #content     = var.options.cml
      content = file("${path.module}/../data/asig-specific-cml.sh")
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
    # Replace cloud-init network configuration with systemd-networkd
    # configuration for the cluster bridge
    {
      path        = "/etc/systemd/network/10-ens4.network"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [Match]
        Name=ens4
        [Network]
        # Both v4 and v6
        DHCP=yes
        LLMNR=no
        LinkLocalAddressing=ipv6
        VXLAN=vxlan0
        [DHCP]
        RouteMetric=100
        # HACK cmm - VXLAN interface won't inherit this MTU, so we set explicitly in link.
        UseMTU=true
      EOF
    },
    {
      path        = "/etc/systemd/network/20-cluster.netdev"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [NetDev]
        Name=cluster
        Kind=bridge
        [Bridge]
        VLANFiltering=0
      EOF
    },
    {
      path        = "/etc/systemd/network/20-cluster.network"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [Match]
        Name=cluster
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
      path        = "/etc/systemd/network/30-vxlan0.netdev"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [NetDev]
        Name=vxlan0
        Kind=vxlan
        [VXLAN]
        VNI=1
        DestinationPort=4789
      EOF
    },
    {
      path        = "/etc/systemd/network/30-vxlan0.link"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [Match]
        OriginalName=vxlan0
        [Link]
        Name=vxlan0
      EOF
    },
    {
      path        = "/etc/systemd/network/30-vxlan0.network"
      owner       = "root:root"
      permissions = "0644"
      content     = <<-EOF
        [Match]
        Name=vxlan0
        [Network]
        BindCarrier=ens4
        Bridge=cluster
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

  cloud_init_config_packages_template = [
    "curl",
    "jq",
    "frr",
  ]

  cloud_init_config_runcmd_template = [
    # HACK cmm - Messing with networks on install after cloud-init is running is full
    # of bugs and race conditions.  I don't recommend it, but we have to do it for now
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
    "sleep 5 && ip link set vxlan0 mtu ${google_compute_network.cml_network.mtu - 50}",
    # Pick up new systemd-resolved configuration, enable mDNS
    "systemctl restart systemd-resolved",

    # We should be using mDNS/IPv6 on the cluster link.  DNS is bad.
    "echo -n 'Cluster link scope: ' && resolvectl status cluster | awk '/Current Scopes/ { print $3 }'",

    # Enable BGP daemon and restart FRR
    "sed -i 's/bgpd=no/bgpd=yes/' /etc/frr/daemons",
    "systemctl restart frr",
    # Disable OSConfig.  It blocks shutdowns.
    "systemctl disable --now google-osconfig-agent.service",
  ]

  cloud_init_config_runcmd_controller = concat(local.cloud_init_config_runcmd_template,
    [
      # Install cml
      "/provision/cml.sh && touch /run/reboot || echo 'CML provisioning failed.  Not rebooting'",
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
      "/provision/cml.sh || echo 'CML provisioning failed.'",
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
    # HACK cmm - We're using images with Packer, so we leave packages alone.
    # This will be different than the globally merged code.
    package_update  = false
    package_upgrade = false

    manage_etc_hosts = true

    power_state = {
      mode      = "reboot"
      condition = "test -f /run/reboot"
    }
  }

  # TODO cmm - needs to come from configuration
  network_interface_path_controller = "pci-0000:00:04.0"

  cloud_init_config_controller = merge(local.cloud_init_config_template, {
    hostname = local.controller_hostname

    packages = local.cloud_init_config_packages_template

    write_files = concat(local.cloud_init_config_write_files_template, [
      {
        path        = "/etc/systemd/network/10-ens4.link"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          [Match]
          Path=${local.network_interface_path_controller}
          [Link]
          Name=ens4
          WakeOnLan=off
          MTUBytes=${google_compute_network.cml_network.mtu}
        EOF
      },
      {
        path        = "/etc/systemd/network/20-cluster.link"
        owner       = "root:root"
        permissions = "0644"
        # MTU has 50 bytes overhead for VXLAN/UDP/IP header.
        # Controller has a fixed MAC address that survives a reboot.  The
        # computes aren't as important.
        content = <<-EOF
          [Match]
          OriginalName=cluster
          [Link]
          Name=cluster
          MTUBytes=${google_compute_network.cml_network.mtu - 50}
          MACAddress=02:01:02:03:04:05
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
          router bgp 65001
           bgp router-id ${google_compute_address.cml_address_internal.address}
           neighbor VTEP peer-group
           neighbor VTEP remote-as 65001
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
      {
        path        = "/provision/net-bah-external.xml"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          <network>
            <name>bah-external</name>
            <forward mode='route'/>
            <bridge name='virbr1' stp='off' delay='0'/>
            <mtu size="${google_compute_network.cml_network.mtu}"/>
            <mac address='02:00:00:00:00:01'/>
            <ip address='100.64.1.254' netmask='255.255.255.0'>
              <dhcp>
                <range start='100.64.1.1' end='100.64.1.253'/>
              </dhcp>
            </ip>
          </network>
        EOF
      },
    ])

    runcmd = local.cloud_init_config_runcmd_controller
  })

  # TODO cmm - needs to come from configuration
  network_interface_path_compute = "pci-0000:00:04.0"

  cloud_init_config_compute = merge(local.cloud_init_config_template, {

    # Use the hostname provided by the IMDS

    packages = local.cloud_init_config_packages_template

    write_files = concat(local.cloud_init_config_write_files_template, [
      {
        path        = "/etc/systemd/network/10-ens4.link"
        owner       = "root:root"
        permissions = "0644"
        content     = <<-EOF
          [Match]
          Path=${local.network_interface_path_compute}
          [Link]
          Name=ens4
          WakeOnLan=off
          MTUBytes=${google_compute_network.cml_network.mtu}
        EOF
      },
      {
        path        = "/etc/systemd/network/20-cluster.link"
        owner       = "root:root"
        permissions = "0644"
        # MTU has 50 bytes overhead for VXLAN/UDP/IP header.
        # Computes have random MAC addresses.
        content = <<-EOF
          [Match]
          OriginalName=cluster
          [Link]
          Name=cluster
          MTUBytes=${google_compute_network.cml_network.mtu - 50}
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
          router bgp 65001
           ! bgp router-id will be the primary interface, fixed in cml.sh
           neighbor VTEP peer-group
           neighbor VTEP remote-as 65001
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
    ])

    runcmd = local.cloud_init_config_runcmd_compute
  })
}

resource "google_service_account" "cml_service_account" {
  account_id   = "cisco-modeling-labs"
  display_name = "Cisco Modeling Labs Service Account"
}

# Allow CML to write logs at a project level
resource "google_project_iam_member" "cml_iam_member_logging_logwriter" {
  project = var.options.cfgs.gcp.project
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.cml_service_account.email}"
}

# Allow CML to write metrics at a project level
resource "google_project_iam_member" "cml_iam_member_monitoring_metricwriter" {
  project = var.options.cfg.gcp.project
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.cml_service_account.email}"
}

data "google_storage_bucket" "cml_bucket" {
  name = var.options.cfg.gcp.bucket
}

resource "google_tags_tag_key" "cml_tag_cml_key" {
  parent      = "projects/${var.options.cfg.gcp.project}"
  short_name  = "cml"
  description = "For identifying CML resources"
  purpose     = "GCE_FIREWALL"
  purpose_data = {
    network = "${var.options.cfg.gcp.project}/${google_compute_network.cml_network.name}"
  }
}

resource "google_tags_tag_value" "cml_tag_cml_controller" {
  parent      = "tagKeys/${google_tags_tag_key.cml_tag_cml_key.name}"
  short_name  = "controller"
  description = "For identifying CML controllers"
}

resource "google_tags_tag_value" "cml_tag_cml_compute" {
  parent      = "tagKeys/${google_tags_tag_key.cml_tag_cml_key.name}"
  short_name  = "compute"
  description = "For identifying CML computes"
}

resource "google_storage_bucket_iam_member" "cml_bucket_iam_member" {
  bucket = data.google_storage_bucket.cml_bucket.name
  role = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.cml_service_account.email}"
}

data "google_compute_network" "cml_network" {
  name = var.options.gcp.network_name
  count = var.options.gcp.network_name == null ? 1 : 0
}

resource "google_compute_network" "cml_network" {
  count = var.options.gcp.network_name == null ? 0 : 1
  name                            = var.options.gcp.network_name
  auto_create_subnetworks         = false
  mtu                             = 8896
  delete_default_routes_on_create = true
  enable_ula_internal_ipv6        = try(var.options.cfg.gcp.internal_v6_ula_cidr == null) ? true : false
  internal_ipv6_range             = try(var.options.cfg.gcp.internal_v6_ula_cidr != null) ? var.options.cfg.gcp.internal_v6_ula_cidr : null
}

# Allow only select machines, e.g. controller, access to the Internet over IPv4
resource "google_compute_route" "cml_route_default_v4" {
  name             = "cml-route-default-v4"
  network          = google_compute_network.cml_network.id
  dest_range       = "0.0.0.0/0"
  priority         = 100
  next_hop_gateway = "default-internet-gateway"
  tags = [
    "has-internet-access"
  ]
}

# Allow only select machines, e.g. controller, access to the Internet over IPv6
resource "google_compute_route" "cml_route_default_v6" {
  name             = "cml-route-default-v6"
  network          = google_compute_network.cml_network.id
  dest_range       = "::/0"
  priority         = 100
  next_hop_gateway = "default-internet-gateway"
  tags = [
    "has-internet-access"
  ]
}

resource "google_compute_subnetwork" "cml_subnet" {
  name                       = "cml-subnet"
  network                    = google_compute_network.cml_network.id
  ip_cidr_range              = var.options.cfg.gcp.subnet_cidr
  stack_type                 = "IPV4_IPV6"
  ipv6_access_type           = "EXTERNAL"
  private_ip_google_access   = true
  private_ipv6_google_access = true

  #log_config {
  #  aggregation_interval = "INTERVAL_5_SEC"
  #  flow_sampling        = 0.5
  #  metadata             = "INCLUDE_ALL_METADATA"
  #  metadata_fields      = []
  #}
}

# Regional Managed Proxy
resource "google_compute_subnetwork" "cml_region_proxy_subnet" {
  count         = var.options.cfg.gcp.region_proxy_subnet_cidr != null ? 1 : 0
  name          = "cml-region-proxy-subnet"
  network       = google_compute_network.cml_network.id
  ip_cidr_range = var.options.cfg.gcp.region_proxy_subnet_cidr
  stack_type    = "IPV4_IPV6"
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"
}

# Cross-region Managed Proxy
resource "google_compute_subnetwork" "cml_global_proxy_subnet" {
  count         = var.options.cfg.gcp.global_proxy_subnet_cidr != null ? 1 : 0
  name          = "cml-global-proxy-subnet"
  network       = google_compute_network.cml_network.id
  ip_cidr_range = var.options.cfg.gcp.global_proxy_subnet_cidr
  stack_type    = "IPV4_IPV6"
  purpose       = "GLOBAL_MANAGED_PROXY"
  role          = "ACTIVE"
}

# Private Service Connect


resource "google_compute_region_network_firewall_policy" "cml_firewall_policy" {
  name   = "cml-firewall-policy"
  region = var.options.cfg.gcp.region
}

resource "google_network_security_address_group" "cml_allowed_subnets_address_group" {
  name        = "cml-allowed-subnets"
  parent      = "projects/${var.options.cfg.gcp.project}"
  description = "Cisco Modeling Labs address group to filter on sources"
  location    = var.options.cfg.gcp.region
  items       = var.options.cfg.common.allowed_ipv4_subnets
  type        = "IPV4"
  capacity    = 100
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_icmp" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow ICMP from any to any"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = 10
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-icmp"

  match {
    src_ip_ranges = ["0.0.0.0/0"]

    layer4_configs {
      ip_protocol = "icmp"
    }
  }
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_icmpv6" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow ICMPv6 from any to any"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = 11
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-icmpv6"

  match {
    src_ip_ranges = ["::/0"]

    layer4_configs {
      # ipv6-icmp, requires numeric protocol
      # https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
      ip_protocol = 58
    }
  }
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_ssh" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow SSH from allowed subnets"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = 101
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-ssh"

  match {
    src_address_groups = [google_network_security_address_group.cml_allowed_subnets_address_group.id]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["22", "1122"]
    }
  }

  target_service_accounts = [google_service_account.cml_service_account.email]
}

resource "google_compute_region_network_firewall_policy_association" "cml_firewall_policy_association" {
  name              = "cml-firewall-policy-association"
  attachment_target = google_compute_network.cml_network.id
  firewall_policy   = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  project           = var.options.cfg.gcp.project
  region            = var.options.cfg.gcp.region
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_http" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow SSH from allowed subnets"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = 102
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-http"

  match {
    src_address_groups = [google_network_security_address_group.cml_allowed_subnets_address_group.id]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["80", "443", "9090"]
    }
  }

  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_controller.id
  }
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_cml" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow CML services from other CML instances"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = 106
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-cml"

  match {
    src_secure_tags {
      name = google_tags_tag_value.cml_tag_network_cml.id
    }

    dest_ip_ranges = ["::/0"]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["443", "1222", "2049", "8006", "8051"]
    }
  }

  target_service_accounts = [google_service_account.cml_service_account.email]
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_cml_v4" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow CML services from other CML instances IPv4"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = 107
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-cml-v4"

  match {
    src_secure_tags {
      name = google_tags_tag_value.cml_tag_cml_compute.id
    }

    dest_ip_ranges = ["0.0.0.0/0"]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["179"]
    }
  }

  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_controller.id
  }
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_cml_v4_udp" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow CML services from other CML instances IPv4 UDP"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = 108
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-cml-v4-udp"

  match {
    src_secure_tags {
      name = google_tags_tag_value.cml_tag_cml_controller.id
    }

    src_secure_tags {
      name = google_tags_tag_value.cml_tag_cml_compute.id
    }

    dest_ip_ranges = ["0.0.0.0/0"]

    layer4_configs {
      ip_protocol = "udp"
      ports       = ["4789"]
    }
  }

  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_controller.id
  }
  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_compute.id
  }
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_cml_gre" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow GRE from other C8K instances"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = 109
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-cml-gre"

  match {
    src_ip_ranges = ["100.64.2.0/24"]

    layer4_configs {
      ip_protocol = 47
    }
  }

  target_service_accounts = [google_service_account.cml_service_account.email]
}

resource "google_compute_address" "cml_address_internal" {
  name         = "cml-address-internal"
  address_type = "INTERNAL"
  purpose      = "GCE_ENDPOINT"
  subnetwork   = google_compute_subnetwork.cml_subnet.id
}

resource "google_compute_address" "cml_address" {
  name = "cml-address"
}

resource "google_compute_instance" "cml_control_instance" {
  name                      = var.options.cfg.common.controller_hostname
  machine_type              = var.options.cfg.gcp.machine_type
  allow_stopping_for_update = true

  labels = {
    allow_public_ip_address = "true"
  }

  tags = [
    "has-internet-access"
  ]

  params {
    resource_manager_tags = {
      (google_tags_tag_key.cml_tag_cml_key.id) = google_tags_tag_value.cml_tag_cml_controller.id
    }
  }

  boot_disk {
    initialize_params {
      image = "${var.options.cfg.gcp.project}/${var.options.cfg.gcp.controller_image_family}"
      size  = var.options.cfg.common.disk_size
    }
  }

  # Use machine as a router & disable source address checking
  can_ip_forward = true

  network_interface {
    network    = google_compute_network.cml_network.id
    subnetwork = google_compute_subnetwork.cml_subnet.id
    network_ip = google_compute_address.cml_address_internal.address
    access_config {
      nat_ip = google_compute_address.cml_address.address
    }
    ipv6_access_config {
      network_tier = "PREMIUM"
    }
    stack_type = "IPV4_IPV6"
  }

  service_account {
    email  = google_service_account.cml_service_account.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    block-project-ssh-keys = try(var.options.cfg.gcp.ssh_keys != null) ? true : false
    ssh-keys               = try(var.options.cfg.gcp.ssh_keys != null) ? var.options.cfg.gcp.ssh_key : null
    user-data              = sensitive(data.cloudinit_config.cml_controller.rendered)
    serial-port-enable     = true
    enable-osconfig        = "TRUE"
  }

  advanced_machine_features {
    enable_nested_virtualization = true
  }
}

data "cloudinit_config" "cml_controller" {
  gzip          = false
  base64_encode = false # always true if gzip is true

  part {
    filename     = "cloud-config.yaml"
    content_type = "text/cloud-config"
    content      = format("#cloud-config\n%s", yamlencode(local.cloud_init_config_controller))
  }
}

resource "google_compute_region_instance_template" "cml_compute_region_instance_template" {
  name_prefix  = var.options.cfg.cluster.compute_hostname_prefix
  machine_type = var.options.cfg.gcp.compute_machine_type

  resource_manager_tags = {
    (google_tags_tag_key.cml_tag_cml_key.id) = google_tags_tag_value.cml_tag_cml_compute.id
  }


  disk {
    source_image = "${var.options.cfg.gcp.project}/${var.options.cfg.gcp.compute_image_family}"
    disk_size_gb = var.options.cfg.cluster.compute_disk_size
  }

  # Use machine as a router & disable source address checking
  can_ip_forward = true

  network_interface {
    network    = google_compute_network.cml_network.id
    subnetwork = google_compute_subnetwork.cml_subnet.id
    # Should not need an external IP
    #access_config {
    #}
    ipv6_access_config {
      network_tier = "PREMIUM"
    }
    stack_type = "IPV4_IPV6"
  }

  service_account {
    email  = google_service_account.cml_service_account.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    block-project-ssh-keys = try(var.options.cfg.gcp.ssh_key != null) ? true : false
    ssh-keys               = try(var.options.cfg.gcp.ssh_key != null) ? var.options.cfg.gcp.ssh_key : null
    user-data              = sensitive(data.cloudinit_config.cml_compute.rendered)
    serial-port-enable     = true
    enable-osconfig        = "TRUE"
  }

  advanced_machine_features {
    enable_nested_virtualization = true
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = false
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_instance_group_manager" "cml_compute_instance_group_manager" {
  name = "cml-compute-instance-group-manager"

  base_instance_name = var.options.cfg.cluster.compute_hostname_prefix
  zone               = var.options.cfg.gcp.zone

  version {
    instance_template = google_compute_region_instance_template.cml_compute_region_instance_template.id
  }

  #all_instances_config {
  #  metadata = {
  #    metadata_key = "metadata_value"
  #  }
  #  labels = {
  #    label_key = "label_value"
  #  }
  #}

  #target_pools = [google_compute_target_pool.appserver.id]
  target_size = var.options.cfg.cluster.number_of_compute_nodes

  #named_port {
  #  name = "http"
  #  port = 80
  #}

  #named_port {
  #  name = "https"
  #  port = 443
  #}

  #auto_healing_policies {
  #  health_check      = google_compute_health_check.autohealing.id
  #  initial_delay_sec = 300
  #}
}

data "cloudinit_config" "cml_compute" {
  gzip          = false
  base64_encode = false # always true if gzip is true

  part {
    filename     = "cloud-config.yaml"
    content_type = "text/cloud-config"
    content      = format("#cloud-config\n%s", yamlencode(local.cloud_init_config_compute))
  }
}

resource "google_compute_route" "cml_routes" {
  for_each          = var.options.cfg.gcp.cml_route_cidrs
  name              = "cml-route-${each.key}"
  network           = google_compute_network.cml_network.id
  dest_range        = each.value
  next_hop_instance = google_compute_instance.cml_control_instance.self_link
}
