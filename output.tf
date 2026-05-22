#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

output "cml2info" {
  value = {
    "address" : module.deploy.public_ip
    "address_v6" : module.deploy.public_ip_v6
    "del" : nonsensitive("ssh -p1122 ${local.cfg.secrets.sys.username}@${module.deploy.public_ip} /provision/del.sh")
    "url" : "https://${module.deploy.public_fqdn}"
    "vpc_network" : try(module.deploy.module.vpc_network, null)
    "bridge0_prefixes" : try(module.deploy.module.bridge0_prefixes, null)
    "backend_controller_name" : try(module.deploy.module.backend_controller_name, null)
    #"version" : module.ready.state.version
  }
}

output "deploy" {
  value = module.deploy.module
  sensitive = true
}

output "cml2secrets" {
  value     = local.cfg.secrets
  sensitive = true
}
