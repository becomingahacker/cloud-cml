#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

output "conjur_secrets" {
  value = { for k, v in data.conjur_secret.conjur_secret : k => v.value }
}

output "aws_secrets" {
  value = { for k, v in resource.aws_secretsmanager_secret.aws_secret : k => v.id }
}
