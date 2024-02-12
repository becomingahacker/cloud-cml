#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

output "cml_scripts" {
  value = { for k, v in resource.aws_s3_object.cml_scripts : k => v.id }
}

