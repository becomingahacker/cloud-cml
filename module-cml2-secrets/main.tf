#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  cfg = yamldecode(var.cfg)
}

data "conjur_secret" "conjur_secret" {
  for_each = toset(local.cfg.secrets)
  name     = each.value
}

resource "aws_secretsmanager_secret" "aws_secret" {
  for_each = toset(local.cfg.secrets)
  name     = each.key
  # Destroy without recovery.  Depend on Conjur for recovery.
  recovery_window_in_days = 0
  tags = {
    Project = "cloud-cml"
  }
}

resource "aws_secretsmanager_secret_version" "aws_secret" {
  for_each      = toset(local.cfg.secrets)
  secret_id     = aws_secretsmanager_secret.aws_secret[each.key].id
  secret_string = data.conjur_secret.conjur_secret[each.key].value
}
