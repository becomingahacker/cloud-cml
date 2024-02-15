#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  cfg = yamldecode(var.cfg)
}

data "aws_s3_bucket" "cml_bucket" {
  bucket = local.cfg.aws.bucket
}

resource "aws_s3_object" "cml_scripts" {
  # TODO cmm - configure_aws_region.sh will be removed if this is destroyed, which means an image can't be built in EC2 Image Builder
  for_each      = fileset("${path.module}/scripts", "*.sh")
  bucket        = data.aws_s3_bucket.cml_bucket.id
  key           = "scripts/${each.value}"
  source        = "${path.module}/scripts/${each.value}"
  force_destroy = true
  tags = {
    Project = "cloud-cml"
  }
}
