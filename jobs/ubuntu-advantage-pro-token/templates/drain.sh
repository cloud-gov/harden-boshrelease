#!/bin/bash

echo "Detaching Pro License"
its_ok="pro detach failed. This likely means the machine was already detached from a license token."
pro detach --assume-yes || echo "$its_ok"
