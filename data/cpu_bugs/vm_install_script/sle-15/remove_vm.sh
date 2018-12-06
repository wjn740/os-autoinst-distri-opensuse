#!/bin/bash
if [ $# -lt 1 ]; then
    echo "$0 <name>"
    exit 1
fi
NAME=$1
virsh undefine ${NAME}
virsh destroy ${NAME} 
