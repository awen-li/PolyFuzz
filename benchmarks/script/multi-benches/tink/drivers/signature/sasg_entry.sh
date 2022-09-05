#!/bin/sh

if [ ! -f "../branch_vars.bv" ]; then
    echo "Warning: branch_vars.bv should be generated......"
    exit 0
fi
cp ../branch_vars.bv ./

sasg -s tests/ -d ./ 
