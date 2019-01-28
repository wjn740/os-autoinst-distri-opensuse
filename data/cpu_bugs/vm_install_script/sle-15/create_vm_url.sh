#!/bin/bash

if [ $# -lt 4 ]; then
    echo "$0 <name> <install_url> <autoyast_url> <logfile_path> [cpu]"
    exit 1
fi

NAME=$1
QCOW2POOL=/tmp/
LOGFILE=$4
INSTALL_URL=$2
AUTOYAST_URL=$3
CPU=$5
if [ -z $CPU ]; then
    CPU=host-model-only
fi

virt-install --name ${NAME} \
    --disk path=$QCOW2POOL/"${NAME}.img",size=20,format=qcow2,bus=virtio,cache=none \
    --os-variant sle15 \
    --noautoconsole \
    --wait=-1 \
    --vnc \
    --vcpus=4 \
    --cpu ${CPU}\
    --ram=1024 \
    --console=log.file=${LOGFILE}\
    --network bridge=br0,model=virtio \
    --location=${INSTALL_URL} \
    -x "console=ttyS0,115200n8
        install=${INSTALL_URL}
	autoyast=${AUTOYAST_URL}"
