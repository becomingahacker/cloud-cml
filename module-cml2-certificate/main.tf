#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  cfg  = yamldecode(var.cfg)
  sans = var.fqdn_alias != null ? [var.fqdn, var.fqdn_alias] : [var.fqdn]
}

resource "aws_acm_certificate" "cml2_cert" {
  domain_name               = var.fqdn
  validation_method         = "DNS"
  subject_alternative_names = local.sans

  tags = {
    Name = var.fqdn
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cml2_cert" {
  for_each = {
    for dvo in aws_acm_certificate.cml2_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.zone_id
}

resource "aws_acm_certificate_validation" "cml_cert_valid" {
  certificate_arn         = resource.aws_acm_certificate.cml2_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cml2_cert : record.fqdn]
}
