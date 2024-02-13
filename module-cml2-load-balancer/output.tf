#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

output "target_group_arn" {
  value = aws_lb_target_group.bah_lb_tg.arn
}

output "private_ip" {
  value = [for eni in data.aws_network_interface.bah_lb_eni : eni.private_ip][0]
}

output "private_ips" {
  value = [for eni in data.aws_network_interface.bah_lb_eni : eni.private_ip]
}

output "public_ips" {
  value = [for eni in data.aws_network_interface.bah_lb_eni : eni.association[0].public_ip]
}
