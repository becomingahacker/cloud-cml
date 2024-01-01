#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

output "cml2info" {
  value = {
    "address" : module.ec2_instance.public_ip
    "del" : "ssh -p1122 ${local.cfg.sys.user}@${module.ec2_instance.public_ip} /provision/del.sh"
    "url" : "https://${module.ec2_instance.public_ip}"
    "version" : module.ready.state.version
  }
}
