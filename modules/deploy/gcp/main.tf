#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2026, Cisco Systems, Inc.
# All rights reserved.
#

locals {
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
  cluster_vxlan_interface_name = "vxlan1"
  cluster_vxlan_vnid           = 1

  cluster_bgp_as = var.options.cfg.gcp.bgp.local_as

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
    # Will update the hostname in 02-gcp_tweaks.sh
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

  cml_iap_enabled = try(var.options.cfg.gcp.enable_iap, false)

  cml_iap_https_access_groups = toset(try(var.options.cfg.gcp.iap_https_access_groups, []))

  cml_load_balancer_fqdns = try(var.options.cfg.gcp.load_balancer_fqdns, [])

  # Lab guides: parse each entry's URL into host, port, protocol, and rewrite
  # path so the URL map can reverse-proxy /<name> to the external origin.
  cml_lab_guides = try(var.options.cfg.gcp.lab_guides, [])

  cml_lab_guides_map = {
    for idx, guide in local.cml_lab_guides : guide.name => {
      name         = guide.name
      url          = guide.url
      host         = regex("https?://([^/:]+)", guide.url)[0]
      tls          = startswith(guide.url, "https")
      port         = startswith(guide.url, "https") ? 443 : 80
      rewrite_path = try(regex("https?://[^/]+(/.*)", guide.url)[0], "/")
    }
  }

  # for_each on a map iterates in alphabetical key order, so priorities must
  # follow that same order.  Redirect rules (1..N) come before proxy rules
  # (N+1..2N) to keep the sequence strictly increasing within the path_matcher.
  cml_lab_guides_sorted_keys = sort(keys(local.cml_lab_guides_map))
}

data "google_project" "cml_project" {
  project_id = var.options.cfg.gcp.project
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

data "google_storage_bucket" "cml_libvirt_images_bucket" {
  name = var.options.cfg.gcp.libvirt_images_bucket
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

resource "google_storage_bucket_iam_member" "cml_libvirt_images_bucket_iam_member" {
  bucket = data.google_storage_bucket.cml_libvirt_images_bucket.name
  role   = "roles/storage.objectAdmin"
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

  # HACK cmm - Keep network around if required
  lifecycle {
    prevent_destroy = false
    #prevent_destroy = true
  }
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
  ip_collection            = try(var.options.cfg.gcp.subnet_ip_collection, null)

  #log_config {
  #  aggregation_interval = "INTERVAL_5_SEC"
  #  flow_sampling        = 0.5
  #  metadata             = "INCLUDE_ALL_METADATA"
  #  metadata_fields      = []
  #}
}

# Private Service Connect
# TODO cmm

data "google_compute_lb_ip_ranges" "google_lb_health_check_ranges" {
}

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
  priority        = var.options.cfg.gcp.network_firewall_rule_start_priority
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-icmp-${var.options.rand_id}"

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
  priority        = var.options.cfg.gcp.network_firewall_rule_start_priority + 1
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-icmpv6-${var.options.rand_id}"

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
  priority        = var.options.cfg.gcp.network_firewall_rule_start_priority + 2
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-ssh-${var.options.rand_id}"

  match {
    src_address_groups = [
      google_network_security_address_group.cml_allowed_subnets_address_group.id,
    ]

    src_ip_ranges = [
      # Local hosts over IPv4
      google_compute_subnetwork.cml_subnet.ip_cidr_range
    ]

    dest_ip_ranges = [
      google_compute_subnetwork.cml_subnet.ip_cidr_range
    ]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["22", "1122"]
    }
  }

  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_controller.id
  }

  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_compute.id
  }
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_ssh_v6" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow SSH from IPv6 allowed subnets"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = var.options.cfg.gcp.network_firewall_rule_start_priority + 3
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-ssh-v6-${var.options.rand_id}"

  match {
    # TODO cmm - Needs an address group and configuration from YAML
    src_ip_ranges = [
      "2001:420::/32",
      # GCP Health Check
      "2600:1901:8001::/48",
      # Local hosts over IPv6
      google_compute_subnetwork.cml_subnet.external_ipv6_prefix
    ]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["22", "1122"]
    }

    dest_ip_ranges = [
      cidrsubnet(google_compute_subnetwork.cml_subnet.external_ipv6_prefix, 0, 0)
    ]
  }

  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_controller.id
  }

  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_compute.id
  }
}

resource "google_compute_region_network_firewall_policy_association" "cml_firewall_policy_association" {
  name              = "cml-firewall-policy-association-${var.options.rand_id}"
  attachment_target = local.cml_network.id
  firewall_policy   = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  project           = var.options.cfg.gcp.project
  region            = var.options.cfg.gcp.region
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_http" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow HTTP(S) from allowed subnets"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = var.options.cfg.gcp.network_firewall_rule_start_priority + 4
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-http-${var.options.rand_id}"

  match {
    src_address_groups = [google_network_security_address_group.cml_allowed_subnets_address_group.id]

    dest_ip_ranges = [
      google_compute_address.cml_controller_internal.address,
    ]

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
  priority        = var.options.cfg.gcp.network_firewall_rule_start_priority + 5
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-cml-gfe-${var.options.rand_id}"

  match {
    src_ip_ranges = [
      # Health checks and GFE
      "2600:2d00:1:b029::/64",
      "2600:2d00:1:1::/64",
    ]

    dest_ip_ranges = [
      google_compute_address.cml_controller_v6.address
    ]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["443"]
    }
  }

  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_controller.id
  }
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_cml" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow CML controller to access computes"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = var.options.cfg.gcp.network_firewall_rule_start_priority + 6
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-cml-${var.options.rand_id}"

  match {
    src_secure_tags {
      name = google_tags_tag_value.cml_tag_cml_controller.id
    }

    dest_ip_ranges = ["::/0"]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["443", "1222"]
    }
  }

  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_compute.id
  }
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_cml_v4" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow BGP from CML computes to controller"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = var.options.cfg.gcp.network_firewall_rule_start_priority + 7
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-cml-v4-${var.options.rand_id}"

  match {
    src_secure_tags {
      name = google_tags_tag_value.cml_tag_cml_compute.id
    }

    dest_ip_ranges = [
      google_compute_address.cml_controller_internal.address,
    ]

    layer4_configs {
      ip_protocol = "tcp"
      ports       = ["179"]
    }
  }

  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_controller.id
  }

  target_secure_tags {
    name = google_tags_tag_value.cml_tag_cml_compute.id
  }
}

resource "google_compute_region_network_firewall_policy_rule" "cml_firewall_rule_cml_v4_udp" {
  action          = "allow"
  description     = "Cisco Modeling Labs allow VXLAN between CML computes and controller"
  direction       = "INGRESS"
  disabled        = false
  enable_logging  = false
  firewall_policy = google_compute_region_network_firewall_policy.cml_firewall_policy.id
  priority        = var.options.cfg.gcp.network_firewall_rule_start_priority + 8
  region          = var.options.cfg.gcp.region
  rule_name       = "cml-firewall-rule-cml-v4-udp-${var.options.rand_id}"

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

resource "google_compute_address" "cml_controller_internal" {
  name         = "cml-controller-internal-${var.options.rand_id}"
  address_type = "INTERNAL"
  purpose      = "GCE_ENDPOINT"
  subnetwork   = google_compute_subnetwork.cml_subnet.id
}

#resource "google_compute_address" "cml_controller" {
#  name = "cml-controller-${var.options.rand_id}"
#}

data "google_compute_address" "cml_controller" {
  name = var.options.cfg.gcp.controller_address_name
}

resource "google_compute_address" "cml_controller_v6" {
  name               = "cml-controller-v6-${var.options.rand_id}"
  ip_version         = "IPV6"
  ipv6_endpoint_type = "VM"
  subnetwork         = google_compute_subnetwork.cml_subnet.id
}

resource "google_compute_instance" "cml_control_instance" {
  name         = var.options.cfg.common.controller_hostname
  zone         = var.options.cfg.gcp.zone
  machine_type = var.options.cfg.gcp.controller_machine_type
  # WARNING: Changes to instance cause distruction of the instance and 
  # recreation!
  allow_stopping_for_update = false

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

  # GCS FUSE Cache
  scratch_disk {
    interface = "NVME"
  }

  #scheduling {
  #  on_instance_stop_action {
  #    discard_local_ssd = true
  #  }
  #}

  # Use machine as a router & disable source address checking
  can_ip_forward = true

  network_interface {
    network    = local.cml_network.id
    subnetwork = google_compute_subnetwork.cml_subnet.id
    network_ip = google_compute_address.cml_controller_internal.address
    access_config {
      nat_ip = data.google_compute_address.cml_controller.address
    }
    ipv6_access_config {
      network_tier                = "PREMIUM"
      external_ipv6               = google_compute_address.cml_controller_v6.address
      external_ipv6_prefix_length = google_compute_address.cml_controller_v6.prefix_length
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
    serial-port-enable     = "TRUE"
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
  name = "cml-control-instance-group-${var.options.rand_id}"
  zone = var.options.cfg.gcp.zone
  # Use self_link, not .id — the API often rejects short instance URLs for IGs (provider #9869 / #14157).
  instances = [google_compute_instance.cml_control_instance.self_link]

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

# NEG for labs routed through the controller.  Used by Passthrough Network Loadbalancers.
resource "google_compute_network_endpoint_group" "cml_controller_lab_neg" {
  name                  = "cml-controller-lab-neg-${var.options.rand_id}"
  network               = local.cml_network.id
  subnetwork            = google_compute_subnetwork.cml_subnet.id
  zone                  = var.options.cfg.gcp.zone
  network_endpoint_type = "GCE_VM_IP"
}

# HACK cmm - comment below out to save time with the deploy/debug loop
resource "google_compute_network_endpoint" "cml_controller_endpoint" {
  network_endpoint_group = google_compute_network_endpoint_group.cml_controller_lab_neg.name

  instance   = google_compute_instance.cml_control_instance.name
  ip_address = google_compute_instance.cml_control_instance.network_interface[0].network_ip
}

data "google_compute_machine_types" "cml_compute_on_demand" {
  filter = "name = \"${var.options.cfg.gcp.compute_on_demand_machine_type}\""
  zone   = var.options.cfg.gcp.zone
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

  # GCS FUSE Cache
  disk {
    type         = "SCRATCH"
    disk_type    = "local-ssd"
    interface    = "NVME"
    disk_size_gb = 375
  }
  # FIXME cmm - Need to have four locally attached SSDs for this type - n2-highmem-32
  # Make so this can be specified in the YAML config.
  disk {
    type         = "SCRATCH"
    disk_type    = "local-ssd"
    interface    = "NVME"
    disk_size_gb = 375
  }
  disk {
    type         = "SCRATCH"
    disk_type    = "local-ssd"
    interface    = "NVME"
    disk_size_gb = 375
  }
  disk {
    type         = "SCRATCH"
    disk_type    = "local-ssd"
    interface    = "NVME"
    disk_size_gb = 375
  }

  # Use machine as a router & disable source address checking
  can_ip_forward = true

  network_interface {
    network    = local.cml_network.id
    subnetwork = google_compute_subnetwork.cml_subnet.id
    # Should not need an external IP.  All addresses are ephemeral.
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
    serial-port-enable     = "TRUE"
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

data "google_compute_machine_types" "cml_compute_spot" {
  filter = "name = \"${var.options.cfg.gcp.compute_spot_machine_type}\""
  zone   = var.options.cfg.gcp.zone
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

  # GCS FUSE Cache
  disk {
    type         = "SCRATCH"
    disk_type    = "local-ssd"
    interface    = "NVME"
    disk_size_gb = 375
  }
  disk {
    type         = "SCRATCH"
    disk_type    = "local-ssd"
    interface    = "NVME"
    disk_size_gb = 375
  }
  disk {
    type         = "SCRATCH"
    disk_type    = "local-ssd"
    interface    = "NVME"
    disk_size_gb = 375
  }
  disk {
    type         = "SCRATCH"
    disk_type    = "local-ssd"
    interface    = "NVME"
    disk_size_gb = 375
  }

  # Use machine as a router & disable source address checking
  can_ip_forward = true

  network_interface {
    network    = local.cml_network.id
    subnetwork = google_compute_subnetwork.cml_subnet.id
    # Should not need an external IP
    # access_config {
    # }
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
    serial-port-enable     = "TRUE"
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

  scheduling {
    preemptible                 = true
    automatic_restart           = false
    provisioning_model          = "SPOT"
    instance_termination_action = "STOP"
  }
}

data "google_compute_zones" "cml_compute_zones_available" {
  region = var.options.cfg.gcp.region
}

resource "google_compute_region_instance_group_manager" "cml_compute_instance_group_manager" {
  name = "cml-compute-instance-group-manager-${var.options.rand_id}"

  base_instance_name = var.options.cfg.cluster.compute_hostname_prefix

  distribution_policy_zones        = [for zone in data.google_compute_zones.cml_compute_zones_available.names : zone]
  distribution_policy_target_shape = "EVEN"

  update_policy {
    type                         = "OPPORTUNISTIC"
    instance_redistribution_type = "NONE"
    minimal_action               = "REPLACE"
    replacement_method           = "RECREATE"
    max_unavailable_fixed        = length(data.google_compute_zones.cml_compute_zones_available.names)
    max_surge_fixed              = 0
  }

  version {
    instance_template = var.options.cfg.gcp.compute_machine_provisioning_model == "on-demand" ? google_compute_region_instance_template.cml_compute_region_instance_template.id : google_compute_region_instance_template.cml_compute_region_instance_template_spot.id
  }

  target_size = var.options.cfg.cluster.number_of_compute_nodes
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

data "google_dns_managed_zone" "cml_zone" {
  name = var.options.cfg.gcp.dns_zone_name
}

resource "google_dns_record_set" "cml_controller_dns" {
  name = "${var.options.cfg.common.controller_hostname}.${data.google_dns_managed_zone.cml_zone.dns_name}"
  type = "A"
  ttl  = 300

  managed_zone = data.google_dns_managed_zone.cml_zone.name

  rrdatas = [
    data.google_compute_address.cml_controller.address
  ]
}

resource "google_dns_record_set" "cml_controller_dns_v6" {
  name = "${var.options.cfg.common.controller_hostname}.${data.google_dns_managed_zone.cml_zone.dns_name}"
  type = "AAAA"
  ttl  = 300

  managed_zone = data.google_dns_managed_zone.cml_zone.name

  rrdatas = [
    google_compute_address.cml_controller_v6.address
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
  name        = "cml-certificate-${var.options.rand_id}"
  description = "cml-certificate"
  scope       = "DEFAULT"

  managed {
    domains = var.options.cfg.gcp.load_balancer_fqdns
    dns_authorizations = [for i in var.options.cfg.gcp.load_balancer_fqdns :
    google_certificate_manager_dns_authorization.cml_dns_auth[i].id]
  }
  depends_on = [
    google_dns_record_set.cml_dns_auth,
  ]
}

resource "google_certificate_manager_certificate_map" "cml_certificate_map" {
  name = "cml-certificate-map-${var.options.rand_id}"
}

resource "google_certificate_manager_certificate_map_entry" "cml_certificate_map_entry" {
  name = "cml-certificate-map-entry-${var.options.rand_id}"
  map  = google_certificate_manager_certificate_map.cml_certificate_map.name
  certificates = [
    google_certificate_manager_certificate.cml_certificate.id
  ]
  matcher = "PRIMARY"
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
  description     = "cml-security-policy-rule-${var.options.rand_id}"
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

  ip_address_selection_policy = "IPV4_ONLY"
  protocol                    = "HTTPS"
  port_name                   = "https"
  security_policy             = google_compute_security_policy.cml_security_policy.id
  session_affinity            = "NONE"

  # https://cloud.google.com/iap/docs/load-balancing-howto
  iap {
    enabled = try(var.options.cfg.gcp.enable_iap, false)
  }
}

# https://cloud.google.com/iap/docs/managing-access
resource "google_iap_web_backend_service_iam_member" "cml_iap_https_access" {
  for_each = local.cml_iap_enabled ? local.cml_iap_https_access_groups : toset([])

  web_backend_service = google_compute_backend_service.cml_backend_controller.name
  role                = "roles/iap.httpsResourceAccessor"
  member              = each.value
}

# Trusted / allowed domains for this IAP-protected backend (see API AllowedDomainsSettings).
# https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/iap_settings
resource "google_iap_settings" "cml_lb" {
  count = local.cml_iap_enabled && length(local.cml_load_balancer_fqdns) > 0 ? 1 : 0

  name = "projects/${data.google_project.cml_project.number}/iap_web/compute/services/${google_compute_backend_service.cml_backend_controller.name}"

  access_settings {
    allowed_domains_settings {
      enable  = true
      domains = [for h in local.cml_load_balancer_fqdns : lower(h)]
    }
    oauth_settings {
      programmatic_clients = try([var.options.cfg.gcp.iap_programmatic_oauth_client_id], [])
    }
  }

  application_settings {
    attribute_propagation_settings {
      enable             = false
      output_credentials = []
    }
  }
}

# Lab guide reverse proxy backends.
# Each lab guide entry gets an Internet NEG pointing to the external origin
# and a backend service the URL map can route to.
resource "google_compute_global_network_endpoint_group" "lab_guide" {
  for_each = local.cml_lab_guides_map

  name                  = "cml-lab-guide-${each.key}-${var.options.rand_id}"
  network_endpoint_type = "INTERNET_FQDN_PORT"
  default_port          = each.value.port
}

resource "google_compute_global_network_endpoint" "lab_guide" {
  for_each = local.cml_lab_guides_map

  global_network_endpoint_group = google_compute_global_network_endpoint_group.lab_guide[each.key].id
  fqdn                          = each.value.host
  port                          = each.value.port
}

resource "google_compute_backend_service" "lab_guide" {
  for_each = local.cml_lab_guides_map

  name        = "cml-lab-guide-${each.key}-${var.options.rand_id}"
  description = "Lab guide reverse proxy: /${each.key} -> ${each.value.url}"

  backend {
    group = google_compute_global_network_endpoint_group.lab_guide[each.key].id
  }

  protocol              = each.value.tls ? "HTTPS" : "HTTP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false
  security_policy       = google_compute_security_policy.cml_security_policy.id

  iap {
    enabled = local.cml_iap_enabled
  }

  depends_on = [
    google_compute_global_network_endpoint.lab_guide,
  ]
}

resource "google_iap_web_backend_service_iam_member" "lab_guide_iap_https_access" {
  for_each = local.cml_iap_enabled ? {
    for pair in setproduct(keys(local.cml_lab_guides_map), local.cml_iap_https_access_groups) :
    "${pair[0]}/${pair[1]}" => { guide = pair[0], member = pair[1] }
  } : {}

  web_backend_service = google_compute_backend_service.lab_guide[each.value.guide].name
  role                = "roles/iap.httpsResourceAccessor"
  member              = each.value.member
}

resource "google_iap_settings" "lab_guide" {
  for_each = local.cml_iap_enabled && length(local.cml_load_balancer_fqdns) > 0 ? local.cml_lab_guides_map : {}

  name = "projects/${data.google_project.cml_project.number}/iap_web/compute/services/${google_compute_backend_service.lab_guide[each.key].name}"

  access_settings {
    allowed_domains_settings {
      enable  = true
      domains = [for h in local.cml_load_balancer_fqdns : lower(h)]
    }
    oauth_settings {
      programmatic_clients = try([var.options.cfg.gcp.iap_programmatic_oauth_client_id], [])
    }
  }

  application_settings {
    attribute_propagation_settings {
      enable             = false
      output_credentials = []
    }
  }
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
  name            = "cml-lb-https-${var.options.rand_id}"
  description     = "cml-lb-https"
  default_service = google_compute_backend_service.cml_backend_controller.id

  # When lab guides are configured, add path-based routing so that /<name>
  # transparently reverse-proxies to the external origin URL.
  dynamic "host_rule" {
    for_each = length(local.cml_lab_guides) > 0 ? [1] : []
    content {
      hosts        = ["*"]
      path_matcher = "lab-guides"
    }
  }

  dynamic "path_matcher" {
    for_each = length(local.cml_lab_guides) > 0 ? [1] : []
    content {
      name            = "lab-guides"
      default_service = google_compute_backend_service.cml_backend_controller.id

      # Redirect /<name> (no trailing slash) to /<name>/ so that relative
      # URLs in the proxied response resolve correctly.
      # Priorities 1..N in alphabetical key order.
      dynamic "route_rules" {
        for_each = local.cml_lab_guides_map
        content {
          priority = index(local.cml_lab_guides_sorted_keys, route_rules.key) + 1

          match_rules {
            full_path_match = "/${route_rules.key}"
          }

          url_redirect {
            path_redirect          = "/${route_rules.key}/"
            redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
            strip_query            = false
          }
        }
      }

      # Proxy /<name>/ to the external origin.
      # Priorities N+1..2N in alphabetical key order.
      dynamic "route_rules" {
        for_each = local.cml_lab_guides_map
        content {
          priority = length(local.cml_lab_guides_sorted_keys) + index(local.cml_lab_guides_sorted_keys, route_rules.key) + 1
          service  = google_compute_backend_service.lab_guide[route_rules.key].id

          match_rules {
            prefix_match = "/${route_rules.key}/"
          }

          route_action {
            url_rewrite {
              host_rewrite        = route_rules.value.host
              path_prefix_rewrite = route_rules.value.rewrite_path
            }
          }
        }
      }
    }
  }
}

resource "google_compute_target_https_proxy" "cml_target_https_proxy" {
  name                        = "cml-target-https-proxy-${var.options.rand_id}"
  url_map                     = google_compute_url_map.cml_lb_https.id
  certificate_map             = "//certificatemanager.googleapis.com/${google_certificate_manager_certificate_map.cml_certificate_map.id}"
  quic_override               = "DISABLE"
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

# Target instance for protocol forwarding.  Allows forwarding rules to direct
# traffic directly to the CML controller without going through a load balancer.
# https://cloud.google.com/compute/docs/protocol-forwarding
resource "google_compute_target_instance" "cml_controller_target_instance" {
  count = try(var.options.cfg.gcp.target_instance.enable, false) ? 1 : 0

  name        = try(var.options.cfg.gcp.target_instance.name, null) != null ? var.options.cfg.gcp.target_instance.name : "cml-target-instance-${var.options.rand_id}"
  description = "Target instance for CML controller protocol forwarding"
  zone        = var.options.cfg.gcp.zone
  instance    = google_compute_instance.cml_control_instance.id
  nat_policy  = try(var.options.cfg.gcp.target_instance.nat_policy, "NO_NAT")
}

# Protocol forwarding configuration
locals {
  # bridge0 configuration for protocol forwarding
  bridge0_cfg = try(var.options.cfg.gcp.cml_custom_external_connections.bridge0, null)

  # IPv4 CIDR parsing for protocol forwarding
  # Usable hosts exclude network and broadcast for the configured bridge0 IPv4 prefix
  # length (e.g. /27 → 30 usable, /25 → 126 usable).  Indices 1..(total-2) forward.
  # By default, the last usable address is used as the gateway (CML Controller).
  bridge0_cidr         = try(local.bridge0_cfg.cidr, null)
  bridge0_prefix_len   = local.bridge0_cidr != null ? tonumber(split("/", local.bridge0_cidr)[1]) : 0
  bridge0_total_hosts  = local.bridge0_cidr != null ? pow(2, 32 - local.bridge0_prefix_len) : 0
  bridge0_usable_hosts = local.bridge0_total_hosts > 2 ? local.bridge0_total_hosts - 2 : 0

  # Generate list of usable host indices (1 to total-2, excluding network and broadcast)
  bridge0_host_indices = local.bridge0_usable_hosts > 0 ? range(1, local.bridge0_total_hosts - 1) : []

  # IPv6 configuration
  bridge0_cidr_v6                        = try(local.bridge0_cfg.cidr_v6, null)
  bridge0_load_balancer_ip_collection_v6 = try(local.bridge0_cfg.load_balancer_ip_collection_v6, null)

  # Prefix addressing mode: "hex" (default) or "decimal".
  # In hex mode, the pod number is the cidrsubnet index (standard behavior, up to 256).
  # In decimal mode, each decimal digit of the pod number maps to a hex nibble
  # (BCD encoding), so the address visually reads as the pod number in decimal.
  # Decimal mode is limited to indices 0-99 (0x00-0x99).
  bridge0_prefix_v6_mode = try(local.bridge0_cfg.prefix_v6_mode, "hex")

  # Maximum from config, falling back to the mode-dependent ceiling.
  bridge0_prefix_max_v6 = try(
    local.bridge0_cfg.prefix_count_v6,
    local.bridge0_prefix_v6_mode == "decimal" ? 100 : 256
  )

  # Effective count: the lesser of usable IPv4 hosts and the configured max.
  bridge0_prefix_count_v6 = min(local.bridge0_usable_hosts, local.bridge0_prefix_max_v6)

  # Precomputed cidrsubnet indices per forwarding rule.
  # Hex mode:     index N → cidrsubnet index N  (identity).
  # Decimal mode: index N → BCD(N), e.g. 15 → 0x15 = 21, so cidrsubnet(…, 8, 21)
  #               yields …:1500::/56 which visually reads as pod 15.
  bridge0_prefix_v6_indices = [
    for i in range(local.bridge0_prefix_count_v6) :
    local.bridge0_prefix_v6_mode == "decimal" ? floor(i / 10) * 16 + (i % 10) : i
  ]

  # Enable protocol forwarding only if target instance is enabled and bridge0 has a CIDR
  enable_protocol_forwarding_v4 = try(var.options.cfg.gcp.target_instance.enable, false) && local.bridge0_cidr != null
  enable_protocol_forwarding_v6 = try(var.options.cfg.gcp.target_instance.enable, false) && local.bridge0_cidr_v6 != null && local.bridge0_load_balancer_ip_collection_v6 != null
}

## Fracture the dependency on the target instance
#data "google_compute_instance" "cml_controller_target_instance" {
#  name = "cml-controller"
#  zone = var.options.cfg.gcp.zone
#}

# IPv4 forwarding rules for protocol forwarding
# Forwards all protocols and ports for each usable IP to the target instance
resource "google_compute_forwarding_rule" "cml_protocol_forwarding_rule_v4" {
  for_each = local.enable_protocol_forwarding_v4 ? toset([for i in local.bridge0_host_indices : tostring(i)]) : toset([])
  #for_each = toset([])

  name                  = "cml-pf-v4-${format("%03d", tonumber(each.key))}-${var.options.rand_id}"
  description           = "Protocol forwarding for ${cidrhost(local.bridge0_cidr, tonumber(each.key))}"
  region                = var.options.cfg.gcp.region
  ip_protocol           = "L3_DEFAULT"
  all_ports             = true
  load_balancing_scheme = "EXTERNAL"
  ip_address            = cidrhost(local.bridge0_cidr, tonumber(each.key))
  #target                = data.google_compute_instance.cml_controller_target_instance.id
  target = google_compute_target_instance.cml_controller_target_instance[0].id
}

# IPv6 forwarding rule for protocol forwarding
resource "google_compute_forwarding_rule" "cml_protocol_forwarding_rule_v6" {
  count = local.enable_protocol_forwarding_v6 ? local.bridge0_prefix_count_v6 : 0
  #count = 0

  name                  = "cml-pf-v6-${format("%03d", count.index)}-${var.options.rand_id}"
  description           = "Protocol forwarding for IPv6 ${cidrsubnet(local.bridge0_cidr_v6, 8, local.bridge0_prefix_v6_indices[count.index])}"
  region                = var.options.cfg.gcp.region
  ip_protocol           = "L3_DEFAULT"
  all_ports             = true
  load_balancing_scheme = "EXTERNAL"
  ip_version            = "IPV6"
  ip_address            = cidrsubnet(local.bridge0_cidr_v6, 8, local.bridge0_prefix_v6_indices[count.index])
  ip_collection         = local.bridge0_load_balancer_ip_collection_v6
  #target                = data.google_compute_instance.cml_controller_target_instance.id
  target = google_compute_target_instance.cml_controller_target_instance[0].id

  lifecycle {
    precondition {
      condition     = local.bridge0_prefix_v6_mode == "hex" || local.bridge0_prefix_v6_mode == "decimal"
      error_message = "bridge0.prefix_v6_mode must be \"hex\" or \"decimal\"."
    }
  }
}
