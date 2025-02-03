#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

output "public_ip" {
  value = (
    (var.cfg.target == "aws") ?
    module.aws[0].public_ip :
    (var.cfg.target == "azure") ?
    module.azure[0].public_ip :
    (var.cfg.target == "gcp") ?
    module.gcp[0].public_ip :
    "0.0.0.0"
  )
}

output "public_ip_v6" {
  value = (
    (var.cfg.target == "gcp") ?
    module.gcp[0].public_ip_v6 :
    "::"
  )
}

output "public_fqdn" {
  value = (
    (var.cfg.target == "aws") ?
    module.aws[0].public_ip :
    (var.cfg.target == "azure") ?
    module.azure[0].public_ip :
    (var.cfg.target == "gcp") ?
    module.gcp[0].public_fqdn :
    "example.com"
  )
}

output "module" {
  value = (
    (var.cfg.target == "aws") ?
    module.aws[0] :
    (var.cfg.target == "azure") ?
    module.azure[0] :
    (var.cfg.target == "gcp") ?
    module.gcp[0] :
    tomap({})
  )
}
