#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

variable "cfg" {
  type        = string
  description = "JSON configuration of the CML deployment"
}

variable "fqdn" {
  type        = string
  description = "Fully qualified domain name of certificate"
}

variable "fqdn_alias" {
  type        = string
  description = "Fully qualified domain name alias of certificate SAN"
  default     = null
}

variable "zone_id" {
  type        = string
  description = "Route53 zone ID to use for domain validation"
}