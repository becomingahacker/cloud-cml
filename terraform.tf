#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

terraform {
  required_providers {
    cml2 = {
      source  = "CiscoDevNet/cml2"
      version = ">=0.6.2"
    }
  }
  required_version = ">= 1.1.0"

  # TODO cmm - remove this when we have a better solution
  backend "gcs" {
    bucket = "bah-cml-terraform-state"
    prefix = "cloud-cml-terraform/state"
  }
}
