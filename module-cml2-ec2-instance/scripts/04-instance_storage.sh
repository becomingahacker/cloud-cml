#!/bin/bash

#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2023, Cisco Systems, Inc.
# All rights reserved.
#

set -x
set -e

systemctl stop libvirtd.service
while [ $(systemctl is-active libvirtd.service) = active ]; do
    sleep 5
done

STORAGE="$(lshw -c storage -json | jq -r '.[].children[0] | select(.product=="Amazon EC2 NVMe Instance Storage") | .logicalname')n1"
if [ -n "${STORAGE}" ]; then
mkfs.ext4 -F "${STORAGE}"
mkdir -vp /srv/data
cat <<EOF > /etc/systemd/system/srv-data.mount
[Unit]
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
[Mount]
What=$STORAGE
Where=/srv/data
Type=ext4
Options=rw,noatime
[Install]
WantedBy=local-fs.target
EOF
cat <<EOF > /etc/systemd/system/var-lib-libvirt.mount
[Unit]
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
[Mount]
What=/srv/data/libvirt
Where=/var/lib/libvirt
Type=none
Options=bind
[Install]
WantedBy=local-fs.target
EOF
cat <<EOF > /etc/systemd/system/var-local-virl2.mount
[Unit]
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
[Mount]
What=/srv/data/virl2
Where=/var/local/virl2
Type=none
Options=bind
[Install]
WantedBy=local-fs.target
EOF
systemctl daemon-reload
systemctl enable srv-data.mount
systemctl start srv-data.mount
rsync -avp /var/lib/libvirt/ /srv/data/libvirt
rsync -avp /var/local/virl2/ /srv/data/virl2
systemctl enable var-lib-libvirt.mount
systemctl start var-lib-libvirt.mount
systemctl enable var-local-virl2.mount
systemctl start var-local-virl2.mount
systemctl restart libvirtd.service
else
    exit 0
fi
