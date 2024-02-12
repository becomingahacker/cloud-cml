#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  cfg = yamldecode(var.cfg)
  cml = templatefile("${path.module}/scripts/cml.sh", {
    cfg     = local.cfg,
    secrets = var.secrets,
  })
  del = templatefile("${path.module}/scripts/del.sh", {
    cfg     = local.cfg,
    secrets = var.secrets,
  })
}

resource "aws_s3_bucket" "cml_bucket" {
  bucket = "${local.cfg.aws.bucket}"

  # Never destroy the bucket.
  force_destroy = false
  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Project = "cloud-cml"
  }
}

resource "aws_s3_object" "cml_scripts" {
  for_each = fileset("${path.module}/scripts", "*.sh")
  bucket   = resource.aws_s3_bucket.cml_bucket.id
  key      = "scripts/${each.value}"
  source   = "${path.module}/scripts/${each.value}"
  force_destroy = true
  tags = {
    Project = "cloud-cml"
  }
}
