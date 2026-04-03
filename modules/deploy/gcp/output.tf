#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2026, Cisco Systems, Inc.
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

output "target_instance_self_link" {
  description = "Self link of the target instance for protocol forwarding"
  value       = try(google_compute_target_instance.cml_controller_target_instance[0].self_link, null)
}

# Populated by Google when IAP is enabled on the backend service (Compute API iap.oauth2ClientId).
# Same value as: gcloud compute backend-services describe NAME --global --format='value(iap.oauth2ClientId)'
# https://cloud.google.com/iap/docs/authentication-howto
output "iap_oauth2_client_id" {
  description = "IAP OAuth 2.0 client ID for this HTTPS backend; use as audience when obtaining ID tokens for programmatic access."
  value       = local.cml_iap_enabled ? try(google_compute_backend_service.cml_backend_controller.iap.oauth2_client_id, null) : null
}
