#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  cfg      = yamldecode(var.cfg)
}

data "conjur_secret" "secrets" {
  for_each = toset(local.cfg.secrets.retrieve)
  name     = each.value
}