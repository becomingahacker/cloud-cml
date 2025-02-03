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
    #"version" : module.ready.state.version
  }
}

output "deploy" {
  value = module.deploy.module
}

output "cml2secrets" {
  value     = local.cfg.secrets
  sensitive = true
}
