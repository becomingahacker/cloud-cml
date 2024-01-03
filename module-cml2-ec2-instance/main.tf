#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

resource "random_id" "id" {
  byte_length = 4
}

provider "aws" {
  region = var.region
}

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
  use_patty = length(regexall("patty\\.sh", join(" ", local.cfg.app.customize))) > 0
  cml_ingress = [
    {
      "description" : "allow SSH",
      "from_port" : 1122,
      "to_port" : 1122
      "protocol" : "tcp",
      "cidr_blocks" : local.cfg.aws.mgmt_cidrs.v4,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow CML termserver",
      "from_port" : 22,
      "to_port" : 22
      "protocol" : "tcp",
      "cidr_blocks" : local.cfg.aws.mgmt_cidrs.v4,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow Cockpit",
      "from_port" : 9090,
      "to_port" : 9090
      "protocol" : "tcp",
      "cidr_blocks" : local.cfg.aws.mgmt_cidrs.v4,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow HTTPS",
      "from_port" : 443,
      "to_port" : 443
      "protocol" : "tcp",
      "cidr_blocks" : local.cfg.aws.mgmt_cidrs.v4,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow HTTPS from load balancer",
      "from_port" : 443,
      "to_port" : 443
      "protocol" : "tcp",
      "cidr_blocks" : ["${var.lb_private_ip}/32"],
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    }
  ]
  cml_patty_range = [
    {
      "description" : "allow PATty TCP",
      "from_port" : 2000,
      "to_port" : 7999
      "protocol" : "tcp",
      "cidr_blocks" : local.cfg.aws.mgmt_cidrs.v4,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow PATty UDP",
      "from_port" : 2000,
      "to_port" : 7999
      "protocol" : "udp",
      "cidr_blocks" : local.cfg.aws.mgmt_cidrs.v4,
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    }
  ]
}

data "aws_vpc" "vpc-tf" {
  tags = {
    Name = "${local.cfg.aws.vpc}"
  }
}

resource "aws_security_group" "sg-tf" {
  name        = "tf-sg-cml-${random_id.id.hex}"
  description = "CML required ports inbound/outbound"
  vpc_id      = data.aws_vpc.vpc-tf.id
  egress = [
    {
      "description" : "any",
      "from_port" : 0,
      "to_port" : 0
      "protocol" : "-1",
      "cidr_blocks" : [
        "0.0.0.0/0"
      ],
      "ipv6_cidr_blocks" : [
        "::/0"
      ],
      "prefix_list_ids" : [],
      "security_groups" : [],
      "self" : false,
    }
  ]
  ingress = local.use_patty ? concat(local.cml_ingress, local.cml_patty_range) : local.cml_ingress
}

data "aws_subnet" "subnet-tf" {
  availability_zone = local.cfg.aws.availability_zone

  tags = {
    Name = local.cfg.aws.subnet
  }
}

resource "aws_network_interface" "primary" {
  subnet_id       = data.aws_subnet.subnet-tf.id
  security_groups = [aws_security_group.sg-tf.id]

  # TODO cmm - hardcode for now
  ipv4_prefix_count = 1
  ipv6_prefix_count = 1

  tags = {
    Name = "primary"
  }
}

resource "aws_instance" "cml" {
  instance_type        = var.instance_type
  ami                  = data.aws_ami.ubuntu.id
  iam_instance_profile = var.iam_instance_profile
  key_name             = var.key_name

  network_interface {
    network_interface_id = aws_network_interface.primary.id
    device_index         = 0
  }

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_size = var.disk_size
  }

  user_data = templatefile("${path.module}/userdata.txt", {
    cfg     = local.cfg
    cml     = local.cml
    del     = local.del
    path    = path.module
    secrets = var.secrets
  })

  tags = {
    Name = local.cfg.hostname
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Owner ID of Canonical
}

resource "aws_lb_target_group_attachment" "cml2" {
  target_group_arn = var.target_group_arn
  target_id        = aws_instance.cml.id
  port             = 443
}

resource "aws_route53_record" "cml2" {
  zone_id = var.zone_id
  name    = local.cfg.hostname
  type    = "CNAME"
  ttl     = "300"
  records = [aws_instance.cml.public_dns]
}