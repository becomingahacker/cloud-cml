#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  cfg = yamldecode(var.cfg)
}

data "conjur_secret" "secrets" {
  for_each = toset(local.cfg.secrets)
  name     = each.value
}

resource "aws_secretsmanager_secret" "secret" {
  for_each = toset(local.cfg.secrets)
  name = each.key
  tags = {
    Project = "cloud-cml"
  }
}

resource "aws_secretsmanager_secret_version" "secret" {
  for_each = toset(local.cfg.secrets)
  secret_id = aws_secretsmanager_secret.secret[each.key].id
  secret_string = data.conjur_secret.secrets[each.key].value
}
