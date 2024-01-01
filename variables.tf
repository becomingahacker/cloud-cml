#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

# TODO cmm - These aren't used with `duo-sso` and are set to null.  Eventually remove.
variable "access_key" {
  type        = string
  description = "AWS access key / credential for the provisioning user"
  default     = null
}

variable "secret_key" {
  type        = string
  description = "AWS secret key matching the access key"
  default     = null
}
