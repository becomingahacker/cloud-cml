#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2024, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  # TODO cmm - what else to enable?
  google_services_enabled = [
    "compute.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "iap.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "certificatemanager.googleapis.com",
    "secretmanager.googleapis.com",
    "storage-component.googleapis.com",
    "storage.googleapis.com",
  ]

  controller_hostname = var.options.cfg.common.controller_hostname
  num_computes        = var.options.cfg.cluster.enable_cluster ? var.options.cfg.cluster.number_of_compute_nodes : 0

  # BGP EVPN bridge
  cluster_interface_name       = "cluster"
  cluster_vxlan_interface_name = "vxlan0"
  cluster_vxlan_vnid           = "1"

  cluster_bgp_as = 65000

  # Specified for ease of troubleshooting on the Controller.   IPv6 link local
  # address computes to fe80::1. Compute bridge MAC addresses are random. 
  cluster_controller_interface_mac = "02:00:00:00:00:01"

  vars = (
    templatefile("${path.module}/../data/vars.sh", {
      cfg = (
        merge(
          var.options.cfg,
          # Need to have this as it's referenced in the template.
          # (Azure specific)
          {
            sas_token = "undefined"
          }
      ))
      }
    )
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
    cluster_interface   = local.cluster_interface_name
    compute_secret      = var.options.cfg.secrets.cluster.secret
    controller_name     = local.controller_hostname
    copy_iso_to_disk    = false
    interactive         = false
    is_cluster          = var.options.cfg.cluster.enable_cluster
    is_configured       = false
    ssh_server          = true
    use_ipv4_dhcp       = true
    skip_primary_bridge = true
  }

  cml_config_controller = merge(local.cml_config_template, {
    hostname          = local.controller_hostname
    primary_interface = var.options.cfg.gcp.compute_primary_interface_name
    is_controller     = true
    is_compute        = !var.options.cfg.cluster.enable_cluster || var.options.cfg.cluster.allow_vms_on_controller
  })

  cml_config_compute = merge(local.cml_config_template, {
    # Will update this in cml-gcp.sh
    hostname      = ""
    is_controller = false
    is_compute    = true
  })

  # Use new or existing service account
  cml_service_account = (
    var.options.cfg.gcp.service_account_id == null
    ) ? (
    google_service_account.cml_service_account[0]
    ) : (
    data.google_service_account.cml_service_account[0]
  )

  # Use new or existing network
  cml_network = (
    try(var.options.cfg.gcp.network_create, true) == true
    ) ? (
    google_compute_network.cml_network[0]
    ) : (
    data.google_compute_network.cml_network[0]
  )

  # data.google_compute_network won't return the existing MTU, so we set it ourselves
  # https://registry.terraform.io/providers/hashicorp/google/latest/docs/data-sources/compute_network
  cml_network_mtu = try(var.options.cfg.gcp.network_mtu, null) == null ? 1460 : var.options.cfg.gcp.network_mtu
}

data "google_compute_zones" "cml_available_zones" {
  status = "UP"
}

resource "google_project_service" "cml_service" {
  for_each           = toset(local.google_services_enabled)
  service            = each.value
  disable_on_destroy = false
}

data "google_service_account" "cml_service_account" {
  count      = var.options.cfg.gcp.service_account_id != null ? 1 : 0
  account_id = var.options.cfg.gcp.service_account_id
}

resource "google_service_account" "cml_service_account" {
  count        = var.options.cfg.gcp.service_account_id == null ? 1 : 0
  account_id   = "cisco-modeling-labs-${var.options.rand_id}"
  display_name = "Cisco Modeling Labs Service Account"
}

# Allow CML to write logs at a project level
resource "google_project_iam_member" "cml_iam_member_logging_logwriter" {
  project = var.options.cfg.gcp.project
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${local.cml_service_account.email}"
}

# Allow CML to write metrics at a project level
resource "google_project_iam_member" "cml_iam_member_monitoring_metricwriter" {
  project = var.options.cfg.gcp.project
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${local.cml_service_account.email}"
}

data "google_storage_bucket" "cml_bucket" {
  name = var.options.cfg.gcp.bucket
}

resource "google_tags_tag_key" "cml_tag_cml_key" {
  parent      = "projects/${var.options.cfg.gcp.project}"
  short_name  = "cml-${var.options.rand_id}"
  description = "For identifying CML resources"
  purpose     = "GCE_FIREWALL"
  purpose_data = {
    network = "${var.options.cfg.gcp.project}/${local.cml_network.name}"
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
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${local.cml_service_account.email}"
}

data "google_compute_network" "cml_network" {
  count = var.options.cfg.gcp.network_name != null ? 1 : 0
  name  = var.options.cfg.gcp.network_name
}

resource "google_compute_network" "cml_network" {
  count                   = try(var.options.cfg.gcp.network_create, true) == true ? 1 : 0
  name                    = try(var.options.cfg.gcp.network_name, null) == null ? "cml-network-${var.options.rand_id}" : var.options.cfg.gcp.network_name
  auto_create_subnetworks = false
  mtu                     = local.cml_network_mtu
  # TODO cmm - route manipulation needed?
  #delete_default_routes_on_create = true
  delete_default_routes_on_create = false
  enable_ula_internal_ipv6        = true
  internal_ipv6_range             = try(var.options.cfg.gcp.network_internal_v6_ula_cidr, null) == null ? null : var.options.cfg.gcp.network_internal_v6_ula_cidr
}

# TODO cmm - route manipulation needed?
## Allow only select machines, e.g. controller, access to the Internet over IPv4
#resource "google_compute_route" "cml_route_default_v4" {
#  name             = "cml-route-default-v4"
#  network          = local.cml_network.id
#  dest_range       = "0.0.0.0/0"
#  priority         = 100
#  next_hop_gateway = "default-internet-gateway"
#  tags = [
#    "has-internet-access-${var.options.rand_id}"
#  ]
#}
#
## Allow only select machines, e.g. controller, access to the Internet over IPv6
#resource "google_compute_route" "cml_route_default_v6" {
#  name             = "cml-route-default-v6"
#  network          = local.cml_network.id
#  dest_range       = "::/0"
#  priority         = 100
#  next_hop_gateway = "default-internet-gateway"
#  tags = [
#    "has-internet-access-${var.options.rand_id}"
#  ]
#}

resource "google_compute_subnetwork" "cml_subnet" {
  name                     = "cml-controller-subnet-${var.options.rand_id}"
  network                  = local.cml_network.id
  ip_cidr_range            = var.options.cfg.gcp.controller_subnet_cidr
  stack_type               = "IPV4_IPV6"
  ipv6_access_type         = "EXTERNAL"
  private_ip_google_access = true

  #log_config {
  #  aggregation_interval = "INTERVAL_5_SEC"
  #  flow_sampling        = 0.5
  #  metadata             = "INCLUDE_ALL_METADATA"
  #  metadata_fields      = []
  #}
}

# Regional Managed Proxy
resource "google_compute_subnetwork" "cml_region_proxy_subnet" {
  count            = var.options.cfg.gcp.region_proxy_subnet_cidr != null ? 1 : 0
  name             = "cml-region-proxy-subnet-${var.options.rand_id}"
  network          = local.cml_network.id
  ip_cidr_range    = var.options.cfg.gcp.region_proxy_subnet_cidr
  stack_type       = "IPV4_IPV6"
  ipv6_access_type = "INTERNAL"
  purpose          = "REGIONAL_MANAGED_PROXY"
  role             = "ACTIVE"
}

# Cross-region Managed Proxy
resource "google_compute_subnetwork" "cml_global_proxy_subnet" {
  count            = var.options.cfg.gcp.global_proxy_subnet_cidr != null ? 1 : 0
  name             = "cml-global-proxy-subnet-${var.options.rand_id}"
  network          = local.cml_network.id
  ip_cidr_range    = var.options.cfg.gcp.global_proxy_subnet_cidr
  stack_type       = "IPV4_IPV6"
  ipv6_access_type = "INTERNAL"
  purpose          = "GLOBAL_MANAGED_PROXY"
  role             = "ACTIVE"
}

# Private Service Connect


resource "google_compute_region_network_firewall_policy" "cml_firewall_policy" {
  name   = "cml-firewall-policy"
  region = var.options.cfg.gcp.region
}

resource "google_network_security_address_group" "cml_allowed_subnets_address_group" {
  name        = "cml-allowed-subnets-${var.options.rand_id}"
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

  target_service_accounts = [local.cml_service_account.email]
}

resource "google_compute_region_network_firewall_policy_association" "cml_firewall_policy_association" {
  name              = "cml-firewall-policy-association"
  attachment_target = local.cml_network.id
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

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_cml_gfe" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow HTTPS from Google Front End"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = 103
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-cml-gfe-${var.options.rand_id}"

  match {
    src_ip_ranges = [
      "130.211.0.0/22",
      "35.191.0.0/16",
    ]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["443"]
    }
  }

  target_service_accounts = [local.cml_service_account.email]
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
      name = google_tags_tag_value.cml_tag_cml_controller.id
    }

    dest_ip_ranges = ["::/0"]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["443", "1222", "2049", "8006", "8051"]
    }
  }

  target_service_accounts = [local.cml_service_account.email]
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

  target_service_accounts = [local.cml_service_account.email]
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
  machine_type              = var.options.cfg.gcp.controller_machine_type
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
    network    = local.cml_network.id
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
    email  = local.cml_service_account.email
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

resource "google_compute_instance_group" "cml_control_instance_group" {
  name      = "cml-control-instance-group-${var.options.rand_id}"
  instances = [google_compute_instance.cml_control_instance.id]

  named_port {
    name = "http"
    port = 80
  }

  named_port {
    name = "https"
    port = 443
  }

  named_port {
    name = "cockpit"
    port = 9000
  }
}

resource "google_compute_health_check" "cml_health_check" {
  name                = "cml-health-check-${var.options.rand_id}"
  check_interval_sec  = 5
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 2
  tcp_health_check {
    port_name = "https"
  }
}

resource "google_compute_region_instance_template" "cml_compute_region_instance_template" {
  name_prefix  = var.options.cfg.cluster.compute_hostname_prefix
  machine_type = var.options.cfg.gcp.compute_on_demand_machine_type

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
    network    = local.cml_network.id
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
    email  = local.cml_service_account.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    block-project-ssh-keys = try(var.options.cfg.gcp.ssh_keys != null) ? true : false
    ssh-keys               = try(var.options.cfg.gcp.ssh_keys != null) ? var.options.cfg.gcp.ssh_keys : null
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

  target_size = var.options.cfg.gcp.compute_machine_provisioning_model == "on-demand" ? var.options.cfg.cluster.number_of_compute_nodes : 0

}

# SPOT instances that can be preempted at any time.  Cheaper, but less reliable.
resource "google_compute_region_instance_template" "cml_compute_region_instance_template_spot" {
  name_prefix  = "${var.options.cfg.cluster.compute_hostname_prefix}-spot"
  machine_type = var.options.cfg.gcp.compute_spot_machine_type

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
    network    = local.cml_network.id
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
    email  = local.cml_service_account.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    block-project-ssh-keys = try(var.options.cfg.gcp.ssh_keys != null) ? true : false
    ssh-keys               = try(var.options.cfg.gcp.ssh_keys != null) ? var.options.cfg.gcp.ssh_key : null
    user-data              = sensitive(data.cloudinit_config.cml_compute.rendered)
    serial-port-enable     = true
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
    create_before_destroy = false
  }

  scheduling {
    preemptible                 = true
    automatic_restart           = false
    provisioning_model          = "SPOT"
    instance_termination_action = "STOP"
  }
}

resource "google_compute_instance_group_manager" "cml_compute_instance_group_manager_spot" {
  name = "cml-compute-instance-group-manager-spot"

  base_instance_name = "${var.options.cfg.cluster.compute_hostname_prefix}-spot"
  zone               = var.options.cfg.gcp.zone

  version {
    instance_template = google_compute_region_instance_template.cml_compute_region_instance_template_spot.id
  }

  target_size = var.options.cfg.gcp.compute_machine_provisioning_model == "spot" ? var.options.cfg.cluster.number_of_compute_nodes : 0
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
  for_each          = var.options.cfg.gcp.cml_custom_external_connections
  name              = "cml-route-${each.key}"
  network           = local.cml_network.id
  dest_range        = each.value.cidr
  next_hop_instance = google_compute_instance.cml_control_instance.self_link
}

data "google_dns_managed_zone" "cml_zone" {
  name = var.options.cfg.gcp.dns_zone_name
}

resource "google_dns_record_set" "cml_controller_dns" {
  name = "${var.options.cfg.common.controller_hostname}.${data.google_dns_managed_zone.cml_zone.dns_name}"
  type = "A"
  ttl  = 300

  managed_zone = data.google_dns_managed_zone.cml_zone.name

  rrdatas = [
    google_compute_address.cml_address.address
  ]
}

resource "google_certificate_manager_dns_authorization" "cml_dns_auth" {
  for_each = toset(var.options.cfg.gcp.load_balancer_fqdns)
  name     = "cml-dns-auth-${replace(each.key, ".", "-")}"
  location = "global"
  #location    = var.options.cfg.gcp.region
  description = "cml-dns-auth-${replace(each.key, ".", "-")}"
  domain      = each.key
}

resource "google_dns_record_set" "cml_dns_auth" {
  for_each = toset(var.options.cfg.gcp.load_balancer_fqdns)
  name     = google_certificate_manager_dns_authorization.cml_dns_auth[each.key].dns_resource_record[0].name
  type     = google_certificate_manager_dns_authorization.cml_dns_auth[each.key].dns_resource_record[0].type
  ttl      = 300

  managed_zone = data.google_dns_managed_zone.cml_zone.name

  rrdatas = [
    google_certificate_manager_dns_authorization.cml_dns_auth[each.key].dns_resource_record[0].data
  ]
}

resource "google_certificate_manager_certificate" "cml_certificate" {
  name        = "cml-certificate"
  description = "cml-certificate"
  #location    = var.options.cfg.gcp.region
  #scope = "ALL_REGIONS"
  scope = "DEFAULT"

  managed {
    domains = var.options.cfg.gcp.load_balancer_fqdns
    dns_authorizations = [for i in var.options.cfg.gcp.load_balancer_fqdns :
    google_certificate_manager_dns_authorization.cml_dns_auth[i].id]
  }
  depends_on = [google_dns_record_set.cml_dns_auth]
}

resource "google_certificate_manager_certificate_map" "cml_certificate_map" {
  name = "cml-certificate-map"
}

resource "google_certificate_manager_certificate_map_entry" "cml_certificate_map_entry" {
  name         = "cml-certificate-map-entry"
  map          = google_certificate_manager_certificate_map.cml_certificate_map.name
  certificates = [google_certificate_manager_certificate.cml_certificate.id]
  matcher      = "PRIMARY"
}

resource "google_compute_global_address" "cml_load_balancer" {
  name = "cml-address-load-balancer-${var.options.rand_id}"
}

resource "google_dns_record_set" "cml_load_balancer_dns" {
  for_each = toset(var.options.cfg.gcp.load_balancer_fqdns)
  name     = "${each.key}."
  type     = "A"
  ttl      = 300

  managed_zone = data.google_dns_managed_zone.cml_zone.name

  rrdatas = [
    google_compute_global_address.cml_load_balancer.address
  ]
}

resource "google_compute_global_address" "cml_load_balancer_v6" {
  name       = "cml-address-load-balancer-v6-${var.options.rand_id}"
  ip_version = "IPV6"
}

resource "google_dns_record_set" "cml_load_balancer_dns_v6" {
  for_each = toset(var.options.cfg.gcp.load_balancer_fqdns)
  name     = "${each.key}."
  type     = "AAAA"
  ttl      = 300

  managed_zone = data.google_dns_managed_zone.cml_zone.name

  rrdatas = [
    google_compute_global_address.cml_load_balancer_v6.address
  ]
}

resource "google_compute_security_policy" "cml_security_policy" {
  name        = "cml-security-policy-${var.options.rand_id}"
  description = "cml-security-policy"
  type        = "CLOUD_ARMOR"
}

resource "google_compute_security_policy_rule" "cml_security_policy_rule" {
  security_policy = google_compute_security_policy.cml_security_policy.name
  description     = "cml-security-policy-rule"
  priority        = 100

  match {
    versioned_expr = "SRC_IPS_V1"
    config {
      src_ip_ranges = ["0.0.0.0/0"]
    }
  }

  #rate_limit_options {
  # TODO cmm - Needs reasonable defaults
  #}

  action = "allow"
  # DO NOT enforce
  preview = true
}

resource "google_compute_backend_service" "cml_backend_controller" {
  name        = "cml-backend-controller-${var.options.rand_id}"
  description = "cml-backend-controller"

  health_checks = [
    google_compute_health_check.cml_health_check.id
  ]

  backend {
    balancing_mode  = "UTILIZATION"
    group           = google_compute_instance_group.cml_control_instance_group.id
    capacity_scaler = 1
    max_utilization = 1
  }

  connection_draining_timeout_sec = 300

  enable_cdn = false

  load_balancing_scheme = "EXTERNAL_MANAGED"
  locality_lb_policy    = "ROUND_ROBIN"

  log_config {
    enable = false
  }

  protocol         = "HTTPS"
  port_name        = "https"
  security_policy  = google_compute_security_policy.cml_security_policy.id
  session_affinity = "NONE"
}

resource "google_compute_url_map" "cml_lb_http_redirect" {
  name        = "cml-lb-http-redirect-${var.options.rand_id}"
  description = "HTTP to HTTPS redirect for the CML forwarding rule"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = true
  }
}

resource "google_compute_target_http_proxy" "cml_target_http_proxy_redirect" {
  name    = "cml-target-http-proxy-redirect-${var.options.rand_id}"
  url_map = google_compute_url_map.cml_lb_http_redirect.id
}

resource "google_compute_global_forwarding_rule" "cml_http_forwarding_rule" {
  name                  = "cml-http-forwarding-rule-${var.options.rand_id}"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.cml_target_http_proxy_redirect.id
  ip_address            = google_compute_global_address.cml_load_balancer.address
}

resource "google_compute_global_forwarding_rule" "cml_http_forwarding_rule_v6" {
  name                  = "cml-http-forwarding-rule-v6-${var.options.rand_id}"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.cml_target_http_proxy_redirect.id
  ip_address            = google_compute_global_address.cml_load_balancer_v6.address
}

resource "google_compute_url_map" "cml_lb_https" {
  name        = "cml-lb-https-${var.options.rand_id}"
  description = "cml-lb-https"
  default_service = google_compute_backend_service.cml_backend_controller.id
}

resource "google_compute_target_https_proxy" "cml_target_https_proxy" {
  name    = "cml-target-https-proxy-${var.options.rand_id}"
  url_map = google_compute_url_map.cml_lb_https.id
  certificate_map = "//certificatemanager.googleapis.com/${google_certificate_manager_certificate_map.cml_certificate_map.id}"
  quic_override = "DISABLE"
  http_keep_alive_timeout_sec = 1200
}

resource "google_compute_global_forwarding_rule" "cml_https_forwarding_rule" {
  name                  = "cml-https-forwarding-rule-${var.options.rand_id}"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.cml_target_https_proxy.id
  ip_address            = google_compute_global_address.cml_load_balancer.address
}

resource "google_compute_global_forwarding_rule" "cml_https_forwarding_rule_v6" {
  name                  = "cml-https-forwarding-rule-v6-${var.options.rand_id}"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.cml_target_https_proxy.id
  ip_address            = google_compute_global_address.cml_load_balancer_v6.address
}
