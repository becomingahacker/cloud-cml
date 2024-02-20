#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  cfg_file = file("config.yml")
  cfg      = yamldecode(local.cfg_file)
  lab_fqdn = local.cfg.lb_fqdn_alias == null ? local.cfg.lb_fqdn : local.cfg.lb_fqdn_alias
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

module "scripts" {
  source  = "./module-cml2-scripts"
  cfg     = local.cfg_file
  secrets = module.secrets.conjur_secrets
}

module "prefix_list_mgmt_v4" {
  source  = "./module-cml2-prefix-list-v4"
  name    = "cml-prefix-list-mgmt-v4"
  entries = concat(
    local.cfg.aws.mgmt_cidrs.v4,
    # Allow machines in the same subnet to use CML mgmt APIs
    # TODO cmm - This is redundant with the load balancer IP in the module-cml2-ec2-instance module
    [
      {
        cidr = data.aws_subnet.subnet.cidr_block
        description = data.aws_subnet.subnet.tags.Name
      },
    ]
  )
}

module "prefix_list_prod_v4" {
  source  = "./module-cml2-prefix-list-v4"
  name    = "cml-prefix-list-prod-v4"
  entries = concat(
    local.cfg.aws.prod_cidrs.v4,
    # Allow machines in the same subnet to use CML prod APIs
    # TODO cmm - This is redundant with the load balancer IP in the module-cml2-ec2-instance module
    [
      {
        cidr = data.aws_subnet.subnet.cidr_block
        description = data.aws_subnet.subnet.tags.Name
      },
    ]
  )
}

module "certificate" {
  source     = "./module-cml2-certificate"
  cfg        = local.cfg_file
  fqdn       = local.cfg.lb_fqdn
  fqdn_alias = local.cfg.lb_fqdn_alias
  zone_id    = data.aws_route53_zone.zone.zone_id
}

module "load_balancer" {
  source                   = "./module-cml2-load-balancer"
  subnets                  = tolist([data.aws_subnet.subnet.id])
  vpc_id                   = data.aws_vpc.vpc.id
  fqdn                     = local.cfg.lb_fqdn
  fqdn_alias               = local.cfg.lb_fqdn_alias
  zone_id                  = data.aws_route53_zone.zone.zone_id
  certificate_arn          = module.certificate.certificate_arn
  certificate_arn_valid_id = module.certificate.certificate_arn_valid_id
  cfg                      = local.cfg_file
}

module "ec2_instance" {
  source                   = "./module-cml2-ec2-instance"
  region                   = local.cfg.aws.region
  instance_type            = local.cfg.aws.flavor
  key_name                 = local.cfg.aws.key_name
  iam_instance_profile     = local.cfg.aws.profile
  disk_size                = local.cfg.aws.disk_size
  cfg                      = local.cfg_file
  secrets                  = module.secrets.conjur_secrets
  target_group_arn         = module.load_balancer.target_group_arn
  target_group_cockpit_arn = module.load_balancer.target_group_cockpit_arn
  lb_private_ip            = module.load_balancer.private_ip
  zone_id                  = data.aws_route53_zone.zone.zone_id
  prod_cidrs_id            = module.prefix_list_prod_v4.prefix_list_id
  mgmt_cidrs_id            = module.prefix_list_mgmt_v4.prefix_list_id
  cml_scripts              = module.scripts.cml_scripts
}

module "ready" {
  source                     = "./module-cml2-readiness"
  target_group_attachment_id = module.ec2_instance.target_group_attachment_id

  depends_on = [
    module.ec2_instance.public_ip,
  ]
}
