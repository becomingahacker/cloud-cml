#!/bin/bash

#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

# set -x
# set -e

function cml_remove_license() {
    API="http://ip6-localhost:8001/api/v0"

    # re-auth with new password
    TOKEN=$(echo '{"username":"'${APP_USER}'","password":"'${APP_PASSWD}'"}' \ |
        curl -s -d@- $API/authenticate | jq -r)

    # de-register the license from the controller
    curl -s -X "DELETE" \
        "$API/licensing/deregistration" \
        -H "Authorization: Bearer $TOKEN" \
        -H "accept: application/json" \
        -H "Content-Type: application/json"
}

cd $(dirname "$0")
source config.sh

# only de-register when the target is active
if [ $(systemctl is-active virl2.target) = "active" ]; then
    cml_remove_license
else
    echo "CML is not active, license can not be de-registered!"
    exit 255
fi
