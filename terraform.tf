#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

terraform {
  required_providers {
    cml2 = {
      source  = "CiscoDevNet/cml2"
      version = "~>0.7.0"
    }
  }

  required_version = ">= 1.1.0"

  backend "s3" {
    bucket = "bah-cml-terraform-state"
    key    = "cloud-cml/terraform.tfstate"
    region = "us-east-2"
  }
}

provider "cml2" {
  address        = "https://{local.lab_fqdn}:443"
  username       = local.cfg.app.user
  password       = module.secrets.conjur_secrets[local.cfg.app.pass]
  use_cache      = false
  skip_verify    = true
  dynamic_config = true
}
