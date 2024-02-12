#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=4.56.0"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = ">=2.0.0"
    }
  }
  required_version = ">= 1.1.0"
}
