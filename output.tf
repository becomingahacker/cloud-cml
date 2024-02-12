#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

output "cml2info" {
  value = {
    "address" : module.ec2_instance.public_ip
    "del" : "ssh -p1122 ${local.cfg.sys.user}@${module.ec2_instance.public_ip} /provision/del.sh"
    "url" : "https://${local.cfg.lb_fqdn}"
    "cockpit" : "https://${local.cfg.hostname}:9090"
    #"version" : module.ready.state.version
    "breakout_tool" : "https://${local.cfg.lb_fqdn}/breakout-docs/"
  }
}
