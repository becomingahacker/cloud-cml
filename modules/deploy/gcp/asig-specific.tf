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

resource "google_certificate_manager_dns_authorization" "cml_dns_auth" {
  name        = "cml-dns-auth"
  location    = var.options.cfg.gcp.region
  description = "Cisco Modeling Labs DNS Authorization"
  domain      = var.options.cfg.gcp.load_balancer_fqdn
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

data "google_dns_managed_zone" "prod" {
  name = var.options.cfg.gcp.dns_zone_name
}

resource "google_dns_record_set" "cml_instance_dns" {
  name = "${var.options.cfg.gcp.load_balancer_fqdn}."
  type = "A"
  ttl  = 300

  managed_zone = data.google_dns_managed_zone.prod.name

  rrdatas = [google_compute_address.cml_address.address]
}
