#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  cfg_file = file("config.yml")
  cfg      = yamldecode(local.cfg_file)
}

data "aws_vpc" "vpc" {
  tags = {
    Name = "${local.cfg.aws.vpc}"
  }
}

data "aws_subnet" "subnet" {
  availability_zone = local.cfg.aws.availability_zone

  tags = {
    Name = local.cfg.aws.subnet
  }
}

data "aws_route53_zone" "zone" {
  name = "${local.cfg.domain_name}."
}

module "secrets" {
  source = "./module-cml2-secrets"
  cfg    = local.cfg_file
}

module "certificate" {
  source  = "./module-cml2-certificate"
  cfg     = local.cfg_file
  fqdn    = local.cfg.lb_fqdn
  zone_id = data.aws_route53_zone.zone.zone_id
}

module "load_balancer" {
  source          = "./module-cml2-load-balancer"
  subnets         = tolist([data.aws_subnet.subnet.id])
  vpc_id          = data.aws_vpc.vpc.id
  fqdn            = local.cfg.lb_fqdn
  zone_id         = data.aws_route53_zone.zone.zone_id
  certificate_arn = module.certificate.certificate_arn
  cfg             = local.cfg_file
}

module "ec2_instance" {
  source               = "./module-cml2-ec2-instance"
  region               = local.cfg.aws.region
  instance_type        = local.cfg.aws.flavor
  key_name             = local.cfg.aws.key_name
  iam_instance_profile = local.cfg.aws.profile
  disk_size            = local.cfg.aws.disk_size
  cfg                  = local.cfg_file
  secrets              = module.secrets.conjur_secrets
  target_group_arn     = module.load_balancer.target_group_arn
  lb_private_ip        = module.load_balancer.private_ip
  zone_id              = data.aws_route53_zone.zone.zone_id
}

#
#provider "cml2" {
#  address        = "https://${module.ec2_instance.public_ip}"
#  username       = local.cfg.app.user
#  password       = module.secrets.secrets[local.cfg.app.pass]
#  use_cache      = false
#  skip_verify    = true
#  dynamic_config = true
#}
#
#module "ready" {
#  source = "./module-cml2-readiness"
#  depends_on = [
#    module.ec2_instance.public_ip
#  ]
#}
#