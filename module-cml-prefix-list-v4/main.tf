
#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

resource "aws_ec2_managed_prefix_list" "cml_prefix_list_v4" {
  name           = var.name
  address_family = "IPv4"
  max_entries    = length(var.entries)

  dynamic "entry" {
    for_each = var.entries
    content {
      description = entry.value.description
      cidr        = entry.value.cidr
    }
  }
  tags = {
    Project = "cloud-cml"
  }
}

