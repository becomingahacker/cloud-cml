#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

output "cml2info" {
  value = {
    address            = module.ec2_instance.public_ip
    deregister_license = "ssh -p1122 ${local.cfg.sys.user}@${module.ec2_instance.public_ip} /provision/del.sh"
    url                = "https://${local.lab_fqdn}"
    cockpit            = "https://${local.lab_fqdn}:9090"
    cml_version        = module.ready.state.version
    breakout_tool      = "https://${local.lab_fqdn}/breakout-docs/"
  }
}
