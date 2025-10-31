#!/bin/bash
echo " "
echo "----Draining----"
existing_token=$(pro status --format json | jq -r '.account.id')
if [ -z "$existing_token" ]; then
    echo "No Pro License Found. Skipping..."
else 
    echo "Detaching Pro License"
    pro detach --assume-yes
fi
echo "--------"