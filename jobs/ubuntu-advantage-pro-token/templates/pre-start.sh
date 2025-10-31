#!/bin/bash
set -ex

echo "Attaching Pro License"
pro attach '<%= p("ubuntu_advantage_pro_token") %>'

echo "Checking if fips enabled"
current_kernel_fips=$(uname -r | grep "fips")
if [ -f /proc/sys/crypto/fips_enabled ] && [ ! -z "$current_kernel_fips" ]; then
    echo "FIPs kernel loaded: $(uname -r)"
else 
    echo "FIPs kernel NOT loaded: $(uname -r)"
    exit 1
fi
fips_enabled=$(cat /proc/sys/crypto/fips_enabled)
if [ 1 -eq $fips_enabled ]; then
    echo "FIPs crypto modules enabled"
else 
    echo "FIPs crypto modules NOT enabled"
    exit 1
fi
