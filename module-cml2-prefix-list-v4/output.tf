#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

output "prefix_list_id" {
  value = aws_ec2_managed_prefix_list.cml_prefix_list_v4.id
}
