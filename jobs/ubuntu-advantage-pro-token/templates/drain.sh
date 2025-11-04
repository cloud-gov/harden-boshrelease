#!/bin/bash


set -eo pipefail

exec 3>&1
exec 1>> /var/vcap/sys/log/ubuntu-advantage-pro-token/drain.stdout.log
exec 2>> /var/vcap/sys/log/ubuntu-advantage-pro-token/drain.stderr.log

echo "Detaching Pro License"
its_ok="pro detach failed. This likely means the machine was already detached from a license token."
pro detach --assume-yes || echo "$its_ok"

echo 0 >&3