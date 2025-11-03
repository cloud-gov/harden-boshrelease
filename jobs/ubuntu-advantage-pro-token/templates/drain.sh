#!/bin/bash

echo "Detaching Pro License"
pro detach --assume-yes || echo "`pro detach` failed. This is probably ok."
