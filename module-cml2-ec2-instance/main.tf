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
  cml_config_script = templatefile("${path.module}/config.sh.tftpl",
    {
      cfg = local.cfg
    }
  )
  use_patty = length(regexall("patty\\.sh", join(" ", local.cfg.app.customize))) > 0
  cml_ingress = [
    {
      "description" : "allow SSH",
      "from_port" : 1122,
      "to_port" : 1122
      "protocol" : "tcp",
      "cidr_blocks" : [],
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [var.mgmt_cidrs_id],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow CML termserver",
      "from_port" : 22,
      "to_port" : 22
      "protocol" : "tcp",
      "cidr_blocks" : [],
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [var.prod_cidrs_id],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow Cockpit",
      "from_port" : 9090,
      "to_port" : 9090
      "protocol" : "tcp",
      "cidr_blocks" : [],
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [var.mgmt_cidrs_id],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow HTTPS",
      "from_port" : 443,
      "to_port" : 443
      "protocol" : "tcp",
      "cidr_blocks" : [],
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [var.prod_cidrs_id],
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
    },
    {
      "description" : "allow Cockpit from load balancer",
      "from_port" : 9090,
      "to_port" : 9090
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
      "cidr_blocks" : [],
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [var.mgmt_cidrs_id],
      "security_groups" : [],
      "self" : false,
    },
    {
      "description" : "allow PATty UDP",
      "from_port" : 2000,
      "to_port" : 7999
      "protocol" : "udp",
      "cidr_blocks" : [],
      "ipv6_cidr_blocks" : [],
      "prefix_list_ids" : [var.mgmt_cidrs_id],
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

  # HACK cmm - cloud-init doesn't enable IPv6 in certain
  # situations--namely if an IPv6 prefix is present on an ENI, but a
  # non-temporary address is not present.  When it first starts, it temporarily
  # gets a v4 address (only), and hits the IMDS to see if IPv6 address configs
  # are present.  If no IPv6 address is in IMDS, it sets netplan to not try to
  # get an IPv6 address at all and this sticks.  The .metal instances I've tried
  # don't assign IPv6 IA and PD at the same time.  Further, if you assign a
  # prefix without an address, then later on add and IPv6 address to an ENI, PD
  # IAIDs get set to zero and systemd-networkd rejects the DHCPv6 Advertise
  # message from AWS.  This may be fixed on Ubuntu 22.04 and later, which makes
  # systemd-networkd more tolerant to IAIDs mismatching between IA_NAs and
  # IA_PDs.
  #
  # DHCPv6
  #     Message type: Advertise (2)
  #     Transaction ID: 0xf7a337
  #     Client Identifier
  #     ...
  #     Server Identifier
  #     ...
  #     Preference
  #     ...
  #     Identity Association for Non-temporary Address
  #         Option: Identity Association for Non-temporary Address (3)
  #         Length: 40
  #         Value: ed10bdb800000046000000700005001826001f161ec6bc00…
  #         IAID: ed10bdb8 <<<---
  #         T1: 70
  #         T2: 112
  #         IA Address
  #             Option: IA Address (5)
  #             Length: 24
  #             Value: 26001f161ec6bc00000000000000e48b0000008c000001c2
  #             IPv6 address: 2600:1f16:1ec6:bc00::e48b
  #             Preferred lifetime: 140
  #             Valid lifetime: 450
  #     Identity Association for Prefix Delegation
  #         Option: Identity Association for Prefix Delegation (25)
  #         Length: 41
  #         Value: 000000000000004600000070001a00190000008c000001c2…
  #         IAID: 00000000 <<<---
  #         T1: 70
  #         T2: 112
  #         IA Prefix
  #             Option: IA Prefix (26)
  #             Length: 25
  #             Value: 0000008c000001c25026001f161ec6bc002f5d0000000000…
  #             Preferred lifetime: 140
  #             Valid lifetime: 450
  #             Prefix length: 80
  #             Prefix address: 2600:1f16:1ec6:bc00:2f5d::
  #
  # systemd-networkd[18652]: DHCPv6 CLIENT: Sent SOLICIT
  # systemd-networkd[18652]: DHCPv6 CLIENT: Next retransmission in 4s
  # systemd-networkd[18652]: DHCPv6 CLIENT: ADVERTISE has wrong IAID for IA PD
  # systemd-networkd[18652]: DHCPv6 CLIENT: Recv ADVERTISE
  #
  # https://github.com/canonical/cloud-init/issues/3682
  # https://github.com/systemd/systemd/issues/20803 
  ipv6_prefix_count = 1

  tags = {
    Name = local.cfg.hostname
  }
}

data "cloudinit_config" "cloud_init_user_data" {
  gzip          = false
  base64_encode = false

  part {
    content_type = "text/cloud-config"
    content = templatefile("${path.module}/cloud_init_user_data.tftpl",
      {
        cfg               = local.cfg
        secrets           = var.secrets
        cml_scripts       = var.cml_scripts
        cml_config_script = local.cml_config_script
      }
    )
  }
}

resource "aws_instance" "cml" {
  instance_type        = var.instance_type
  ami                  = data.aws_ami.cloud_cml_recipe.id
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

  user_data = data.cloudinit_config.cloud_init_user_data.rendered

  tags = {
    Name    = local.cfg.hostname
    Project = "cloud-cml"
  }
}

data "aws_ami" "cloud_cml_recipe" {
  most_recent = true

  filter {
    name   = "name"
    values = ["cloud-cml-recipe*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "tag:Project"
    values = ["cloud-cml"]
  }

  # TODO cmm - make this configurable
  owners = ["181171279649"] # asig-bah
}

resource "aws_lb_target_group_attachment" "cml2" {
  target_group_arn = var.target_group_arn
  target_id        = aws_instance.cml.id
  port             = 443
}

resource "aws_lb_target_group_attachment" "cml2_cockpit" {
  target_group_arn = var.target_group_cockpit_arn
  target_id        = aws_instance.cml.id
  port             = 9090
}

resource "aws_route53_record" "cml2" {
  zone_id = var.zone_id
  name    = local.cfg.hostname
  type    = "CNAME"
  ttl     = "300"
  records = [aws_instance.cml.public_dns]
}