#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

variable "name" {
  description = "Name of the prefix list"
  type        = string
}

variable "entries" {
  description = "List of prefix list entries"
  type = list(object({
    description = string
    cidr        = string
  }))
}