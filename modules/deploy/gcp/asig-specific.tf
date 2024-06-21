#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2024, Cisco Systems, Inc.
# All rights reserved.
#

resource "google_tags_tag_value" "cml_tag_network_router" {
  parent      = "tagKeys/${google_tags_tag_key.cml_tag_network_key.name}"
  short_name  = "router"
  description = "For identifying routers"
}


#resource "google_compute_instance" "cmm_test_instance" {
#  name                      = "cmm-test"
#  machine_type              = var.options.cfg.gcp.machine_type
#  allow_stopping_for_update = true
#
#  boot_disk {
#    initialize_params {
#      image = "ubuntu-os-cloud/ubuntu-2004-lts"
#    }
#  }
#
#  scratch_disk {
#    interface = "NVME"
#  }
#
#  # Use machine as a router & disable source address checking
#  can_ip_forward = true
#
#  network_interface {
#    network    = google_compute_network.cml_network.id
#    subnetwork = google_compute_subnetwork.cml_subnet.id
#    access_config {
#    }
#    ipv6_access_config {
#      network_tier = "PREMIUM"
#    }
#    stack_type = "IPV4_IPV6"
#  }
#
#  service_account {
#    email  = google_service_account.cml_service_account.email
#    scopes = ["cloud-platform"]
#  }
#
#  metadata = {
#    #block-project-ssh-keys = try(length(var.options.cfg.gcp.ssh_key) > 0) ? true : false
#    block-project-ssh-keys = false
#    ssh-keys               = try(length(var.options.cfg.gcp.ssh_key) > 0) ? var.options.cfg.gcp.ssh_key : null
#    user-data              = <<EOF
#      #cloud-config
#      packages:
#        - iperf3
#    EOF
#    serial-port-enable     = true
#    enable-osconfig        = "TRUE"
#  }
#
#  advanced_machine_features {
#    enable_nested_virtualization = true
#  }
#
#  shielded_instance_config {
#    enable_integrity_monitoring = true
#    enable_secure_boot          = true
#    enable_vtpm                 = true
#  }
#}

data "google_dns_managed_zone" "cml_zone" {
  name = var.options.cfg.gcp.dns_zone_name
}

resource "google_compute_network_endpoint_group" "cml_endpoint_group" {
  name = "cml-endpoint-group"
  network = google_compute_network.cml_network.id
  subnetwork = google_compute_subnetwork.cml_subnet.id
  zone = var.options.cfg.gcp.zone
  network_endpoint_type = "GCE_VM_IP"
}

resource "google_compute_network_endpoint" "cml_controller_endpoint" {
  network_endpoint_group = google_compute_network_endpoint_group.cml_endpoint_group.name
  instance = google_compute_instance.cml_control_instance.name
  ip_address = google_compute_address.cml_address_internal.address
}


resource "google_compute_subnetwork" "cml_proxy_subnet" {
  name          = "cml-proxy-subnet"
  network       = google_compute_network.cml_network.id
  ip_cidr_range = var.options.cfg.gcp.proxy_subnet_cidr
  stack_type    = "IPV4_ONLY"
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"
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
