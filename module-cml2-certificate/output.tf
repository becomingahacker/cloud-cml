#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

output "certificate_arn" {
  value = aws_acm_certificate.cml2_cert.arn
}
