#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

output "cml2info" {
  value = {
    cml2_host_address          = module.ec2_instance.public_ip
    deregister_license_command = "ssh -p1122 ${local.cfg.sys.user}@${module.ec2_instance.public_ip} sudo /provision/del.sh"
    url                        = "https://${local.lab_fqdn}"
    cockpit                    = "https://${local.lab_fqdn}:9090"
    cml_version                = module.ready.state.version
    breakout_tool              = "https://${local.lab_fqdn}/breakout-docs/"
  }
}
