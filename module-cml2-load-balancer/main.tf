#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

locals {
  cfg = yamldecode(var.cfg)
}

resource "aws_lb" "bah_lb" {
  name               = "bah-lb"
  internal           = false
  load_balancer_type = "network"
  subnets            = var.subnets

  enable_deletion_protection = false

  tags = {
    Name = "bah-lb"
  }
}

resource "aws_lb_target_group" "bah_lb_tg" {
  name               = "bah-lb-tg"
  port               = 443
  protocol           = "TLS"
  vpc_id             = var.vpc_id
  preserve_client_ip = true

  health_check {
    protocol = "HTTPS"
    path = "/"
    matcher = "200"
  }
}

resource "aws_lb_listener" "bah_lb_lis" {
  load_balancer_arn = aws_lb.bah_lb.arn
  port              = "443"
  protocol          = "TLS"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.bah_lb_tg.arn
  }
}

resource "aws_route53_record" "bah_lb_dns_record" {
  zone_id = var.zone_id
  name    = var.fqdn
  type    = "CNAME"
  ttl     = "300"
  records = [aws_lb.bah_lb.dns_name]
}

data "aws_network_interface" "bah_lb_eni" {
  for_each = var.subnets

  filter {
    name   = "description"
    values = ["ELB ${aws_lb.bah_lb.arn_suffix}"]
  }

  filter {
    name   = "subnet-id"
    values = [each.value]
  }
}