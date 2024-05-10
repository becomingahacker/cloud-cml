#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2024, Cisco Systems, Inc.
# All rights reserved.
#

output "public_ip" {
  value = google_compute_address.cml_address.address
}

output "sas_token" {
  value = "undefined"
}
