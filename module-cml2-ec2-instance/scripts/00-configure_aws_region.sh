#!/bin/bash

#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

set -e

# Get the token from the IMDSv2 server
TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`

# Get the current AWS region from the IMDS
AWS_REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)

mkdir -vp /root/.aws

# Output the configured AWS region to the root account user
cat <<EOF > /root/.aws/config
[default]
region = $AWS_REGION
EOF

echo "Configured AWS region: $AWS_REGION"
