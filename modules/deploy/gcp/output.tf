#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2024, Cisco Systems, Inc.
# All rights reserved.
#

output "public_ip" {
  value = data.google_compute_address.cml_controller.address
}

output "public_ip_v6" {
  value = google_compute_address.cml_controller_v6.address
}

output "public_fqdn" {
  value = google_certificate_manager_certificate.cml_certificate.san_dnsnames[0]
}

output "lab_network_endpoint_group_self_link" {
  value = google_compute_network_endpoint_group.cml_controller_lab_neg.self_link
}

output "firewall_policy_id" {
  value = google_compute_region_network_firewall_policy.cml_firewall_policy.id
}

output "bgp_ipv6_peer" {
  # HACK cmm - needs to be a list
  value = cidrhost(cidrsubnet("${google_compute_address.cml_controller_v6.address}/${google_compute_address.cml_controller_v6.prefix_length}", 16, 1), var.options.cfg.gcp.cml_custom_external_connections.virbr1.gateway == "last" ? 65535 : 1)
}

output "sas_token" {
  value = "undefined"
}
