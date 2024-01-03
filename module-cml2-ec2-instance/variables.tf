#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

variable "cfg" {
  type        = string
  description = "JSON configuration of the CML deployment"
}

variable "region" {
  type        = string
  description = "AWS region where the instance should be started"
}

variable "instance_type" {
  type        = string
  description = "AWS EC2 flavor, typically a metal flavor is required"
}

variable "key_name" {
  type        = string
  description = "SSH key defined in AWS EC2 to be used with CML instances"
}

variable "iam_instance_profile" {
  type        = string
  description = "AWS IAM instance profile defining the access policy used for the EC2 instance"
}

variable "disk_size" {
  type        = number
  default     = 64
  description = "root disk size in GB"
}

variable "secrets" {
  type        = any
  description = "secrets from secrets manager (e.g. Conjur)"
}

variable "target_group_arn" {
  type        = string
  default     = null
  description = "target group to add machine to load balancer"
}

variable "lb_private_ip" {
  type        = string
  default     = null
  description = "private IP of load balancer for health checks"
}
