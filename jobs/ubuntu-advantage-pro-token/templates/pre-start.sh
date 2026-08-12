#!/bin/bash
set -ex

echo "Attaching Pro License"
its_ok="pro attach failed. This likely means the machine was already attached to a license token."
set +x
pro attach '<%= p("ubuntu_advantage_pro_token") %>' || echo "$its_ok"
set -x
# Enable the usg service (installs the usg package from the Pro/esm mirror).
echo "Enabling usg service"
pro enable usg --assume-yes || echo "pro enable usg failed (already enabled, or egress to esm.ubuntu.com blocked)"

echo "Checking if fips enabled"
current_kernel_fips=$(uname -r | grep "fips" || true)
if [ -f /proc/sys/crypto/fips_enabled ] && [ ! -z "$current_kernel_fips" ] \
   && [ "$(cat /proc/sys/crypto/fips_enabled)" = "1" ]; then
    echo "FIPs kernel loaded and crypto modules enabled: $(uname -r)"
elif [ "<%= p('require_fips') %>" = "true" ]; then
    echo "FIPs required but NOT active: $(uname -r)"
    exit 1
else
    echo "FIPs NOT active and require_fips=false — continuing (non-FIPS stemcell)"
fi
