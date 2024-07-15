#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2024, Cisco Systems, Inc.
# All rights reserved.
#

data "google_dns_managed_zone" "cml_zone" {
  name = var.options.cfg.gcp.dns_zone_name
}

resource "google_compute_network_endpoint_group" "cml_endpoint_group" {
  name                  = "cml-endpoint-group"
  network               = google_compute_network.cml_network.id
  subnetwork            = google_compute_subnetwork.cml_subnet.id
  zone                  = var.options.cfg.gcp.zone
  network_endpoint_type = "GCE_VM_IP"
}

resource "google_compute_network_endpoint" "cml_controller_endpoint" {
  network_endpoint_group = google_compute_network_endpoint_group.cml_endpoint_group.name
  instance               = google_compute_instance.cml_control_instance.name
  ip_address             = google_compute_address.cml_address_internal.address
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

resource "google_compute_security_policy" "cml_security_policy" {
  name        = "cml-security-policy"
  description = "cml-security-policy"
}

resource "google_compute_security_policy_rule" "cml_security_policy_rule" {
  security_policy = google_compute_security_policy.cml_security_policy.id
  priority        = 1000
  action          = "allow"
  preview         = false
  match {
    versioned_expr = "SRC_IPS_V1"
    config {
      src_ip_ranges = var.options.cfg.common.allowed_ipv4_subnets
    }
  }
  rate_limit_options {
    rate_limit_threshold {
      count        = 1000
      interval_sec = 5
    }
  }
}

resource "google_compute_network_endpoint_group" "cml_network_endpoint_group" {
  name                  = "cml-lb-neg"
  network               = google_compute_network.cml_network.id
  subnetwork            = google_compute_subnetwork.cml_subnet.id
  zone                  = var.options.cfg.gcp.zone
  network_endpoint_type = "GCE_VM_IP_PORT"
}

resource "google_compute_region_health_check" "cml_health_check" {
  name                = "cml-health-check"
  check_interval_sec  = 5
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 2
  http_health_check {
    request_path = "/"
    port         = 443
  }
}

resource "google_compute_region_backend_service" "cml_backend_service" {
  name                            = "cml-backend-service"
  protocol                        = "HTTPS"
  timeout_sec                     = 86400
  port_name                       = "https"
  connection_draining_timeout_sec = 300
  load_balancing_scheme           = "EXTERNAL_MANAGED"

  health_checks = [google_compute_region_health_check.cml_health_check.id]

  backend {
    group           = google_compute_network_endpoint_group.cml_endpoint_group.id
    balancing_mode  = "RATE"
    max_rate        = 1000
    capacity_scaler = 1.0
  }
}

resource "google_compute_region_url_map" "cml_url_map" {
  name            = "cml-url-map"
  default_service = google_compute_region_backend_service.cml_backend_service.id

  host_rule {
    hosts        = var.options.cfg.gcp.load_balancer_fqdns
    path_matcher = "cml-path-matcher"
  }

  path_matcher {
    name            = "cml-path-matcher"
    default_service = google_compute_region_backend_service.cml_backend_service.id

    path_rule {
      paths   = ["/"]
      service = google_compute_region_backend_service.cml_backend_service.id
    }
  }
}

resource "google_compute_region_target_https_proxy" "cml_https_proxy" {
  name    = "cml-https-proxy"
  url_map = google_compute_region_url_map.cml_url_map.id
  certificate_manager_certificates = [
    google_certificate_manager_certificate.cml_certificate.id
  ]
}

# SPOT instances that can be preempted at any time.  Cheaper, but less reliable.
resource "google_compute_region_instance_template" "cml_compute_region_instance_template_spot" {
  name_prefix  = "${var.options.cfg.cluster.compute_hostname_prefix}-spot"
  machine_type = var.options.cfg.gcp.spot_compute_machine_type

  resource_manager_tags = {
    (google_tags_tag_key.cml_tag_network_key.id) = google_tags_tag_value.cml_tag_network_cml.id
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

  target_size = var.options.cfg.gcp.number_of_spot_compute_nodes
}

