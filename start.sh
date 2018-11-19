#!/bin/bash
IP=$(ip addr | grep inet | grep -v 127.0.0 | grep -v inet6 | awk '{print $2}')
IP=${IP%/24}
SERVER=$(cat spass | head -n 1)
PASS=$(cat spass | tail -n 1)
node local.js -s $SERVER -l 1080 -m rc4-md5 -k $PASS -b $IP
