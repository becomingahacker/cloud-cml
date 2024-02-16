#!/bin/bash

#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

#set -x
set -e

function base_setup() {
    # current location of the bucket w/ software and images
    AWS_DEFAULT_REGION="${AWS_REGION}"
    APT_OPTS="-o Dpkg::Options::=--force-confmiss -o Dpkg::Options::=--force-confnew"
    APT_OPTS+=" -o DPkg::Progress-Fancy=0 -o APT::Color=0"
    DEBIAN_FRONTEND=noninteractive
    export APT_OPTS DEBIAN_FRONTEND AWS_DEFAULT_REGION

    # copy debian package from bucket into our instance
    aws s3 cp --no-progress "s3://${AWS_BUCKET}/${APP_DEB}" /provision/

    # copy node definitions and images to the instance
    VLLI=/var/lib/libvirt/images
    NDEF=node-definitions
    IDEF=virl-base-images
    mkdir -p $VLLI/$NDEF

    # copy all node definitions as defined in the provisioned config
    if [ $(jq </provision/refplat '.definitions|length') -gt 0 ]; then
        elems=$(jq </provision/refplat -rc '.definitions|join(" ")')
        for item in $elems; do
            aws s3 cp --no-progress "s3://${AWS_BUCKET}/refplat/$NDEF/$item.yaml" "$VLLI/$NDEF/"
        done
    fi

    # copy all image definitions as defined in the provisioned config
    if [ $(jq </provision/refplat '.images|length') -gt 0 ]; then
        elems=$(jq </provision/refplat -rc '.images|join(" ")')
        for item in $elems; do
            mkdir -p $VLLI/$IDEF/$item
            aws s3 cp --no-progress --recursive "s3://${AWS_BUCKET}/refplat/$IDEF/$item/" "$VLLI/$IDEF/$item/"
        done
    fi

    # if there's no images at this point, copy what's available in the bucket
    if [ $(find $VLLI -type f | wc -l) -eq 0 ]; then
        aws s3 cp --no-progress --recursive s3://${AWS_BUCKET}/refplat/ $VLLI/
    fi

    systemctl stop ssh
    apt-get install -y "/provision/${APP_DEB}"
    systemctl start ssh

    FILELIST=$(find /provision/ -type f -regextype posix-egrep -regex '/provision/[0-9]{2}-.*' | sort -u | grep -v '99-dummy.sh')
    # make the bucket available for the scripts
    BUCKET=${AWS_BUCKET}
    export BUCKET
    if [ -n "$FILELIST" ]; then
        systemctl stop virl2.target
        while [ $(systemctl is-active virl2-controller.service) = active ]; do
            sleep 5
        done
        (
            echo "$FILELIST" | sort |
            while read patch; do
                source "$patch"
            done
        )
        sleep 5
        systemctl restart virl2.target
    fi

    # For troubleshooting. To allow console access on AWS, the root user needs a
    # password. Note: not all instance types / flavors provide a serial console!
    # echo "root:secret-password-here" | /usr/sbin/chpasswd

}

function cml_configure() {
    API="http://ip6-localhost:8001/api/v0"

    # create system user
    /usr/sbin/useradd --badname -m -s /bin/bash "${SYS_USER}"
    echo "${SYS_USER}:${SYS_PASSWD}" | /usr/sbin/chpasswd
    /usr/sbin/usermod -a -G sudo "${SYS_USER}"

    # move SSH config from default ubuntu user to new user. This also disables
    # the login for the ubuntu user by removing the SSH key.
    mv /home/ubuntu/.ssh "/home/${SYS_USER}/"
    chown -R "${SYS_USER}.${SYS_USER}" "/home/${SYS_USER}/.ssh"

    # change the ownership of the del.sh script to the sysadmin user
    chown "${SYS_USER}.${SYS_USER}" /provision/del.sh
    # change the ownership of the config.sh script to the sysadmin user
    chown "${SYS_USER}.${SYS_USER}" /provision/config.sh

    until [ "true" = "$(curl -s $API/system_information | jq -r .ready)" ]; do
        echo "Waiting for controller to be ready..."
        sleep 5
    done

    # get token
    PASS=$(cat /etc/machine-id)
    TOKEN=$(echo '{"username":"cml2","password":"'$PASS'"}' \ |
        curl -s -d@- $API/authenticate | jq -r)
    [ "$TOKEN" != "Authentication failed!" ] || { echo $TOKEN; exit 1; }

    # change to provided name and password
    curl -s -X "PATCH" \
        "$API/users/00000000-0000-4000-a000-000000000000" \
        -H "Authorization: Bearer $TOKEN" \
        -H "accept: application/json" \
        -H "Content-Type: application/json" \
        -d '{"username":"'${APP_USER}'","password":{"new_password":"'${APP_PASSWD}'","old_password":"'$PASS'"}}'

    # re-auth with new password
    TOKEN=$(echo '{"username":"'${APP_USER}'","password":"'${APP_PASSWD}'"}' \ |
        curl -s -d@- $API/authenticate | jq -r)

    # this is still local, everything below talks to GCH licensing servers
    curl -s -X "PUT" \
        "$API/licensing/product_license" \
        -H "Authorization: Bearer $TOKEN" \
        -H "accept: application/json" \
        -H "Content-Type: application/json" \
        -d '"'${LICENSE_FLAVOR}'"'

    # licensing steps
    curl -vs -X "POST" \
        "$API/licensing/registration" \
        -H "Authorization: Bearer $TOKEN" \
        -H "accept: application/json" \
        -H "Content-Type: application/json" \
        -d '{"token":"'${LICENSE_TOKEN}'","reregister":false}'

    # no need to put in node licenses - unavailable
    if [[ "${LICENSE_FLAVOR}" =~ ^CML_Personal || "${LICENSE_NODES}" == "0" ]]; then
        return 0
    fi

    ID="regid.2019-10.com.cisco.CML_NODE_COUNT,1.0_2607650b-6ca8-46d5-81e5-e6688b7383c4"
    curl -vs -X "PATCH" \
        "$API/licensing/features" \
        -H "Authorization: Bearer $TOKEN" \
        -H "accept: application/json" \
        -H "Content-Type: application/json" \
        -d '{"'${ID}'":'${LICENSE_NODES}'}"'
}

cd $(dirname "$0")
source config.sh

# only run the base setup when there's a provision directory
# both with Terraform and with Packer but not when deploying an AMI
if [ -d /provision ]; then
    base_setup
fi

# only do a configure when this is not run within Packer / AMI building
if [ ! -f /tmp/PACKER_BUILD ]; then
    cml_configure
fi
