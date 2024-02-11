#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

terraform {
  required_providers {
    conjur = {
      source  = "registry.terraform.io/cyberark/conjur"
      version = "0.6.6"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">=4.56.0"
    }
  }
  required_version = ">= 1.1.0"
}
