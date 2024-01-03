#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

variable "cfg" {
  type        = string
  description = "JSON configuration of the CML deployment"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for load balancer"
}

variable "subnets" {
  type        = set(string)
  description = "Subnets to create the loadbalancer"
}

variable "fqdn" {
  type        = string
  description = "loadbalancer fully qualified domain name to register in Route53"
}

variable "zone_id" {
  type        = string
  description = "Route53 zone ID"
}

variable "certificate_arn" {
  type        = string
  description = "ACM certificate ARN to associate with the load balancer for TLS"
}