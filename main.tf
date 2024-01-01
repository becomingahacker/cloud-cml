#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  cfg_file = file("config.yml")
  cfg      = yamldecode(local.cfg_file)
}

module "secrets" {
  source = "./module-cml2-secrets"
  cfg    = local.cfg_file
}

module "ec2_instance" {
  source               = "./module-cml2-ec2-instance"
  region               = local.cfg.aws.region
  instance_type        = local.cfg.aws.flavor
  key_name             = local.cfg.aws.key_name
  iam_instance_profile = local.cfg.aws.profile
  disk_size            = local.cfg.aws.disk_size
  cfg                  = local.cfg_file
  secrets              = module.secrets.secrets
}

provider "cml2" {
  address        = "https://${module.ec2_instance.public_ip}"
  username       = local.cfg.app.user
  password       = module.secrets.secrets[local.cfg.app.pass]
  use_cache      = false
  skip_verify    = true
  dynamic_config = true
}

module "ready" {
  source = "./module-cml2-readiness"
  depends_on = [
    module.ec2_instance.public_ip
  ]
}
