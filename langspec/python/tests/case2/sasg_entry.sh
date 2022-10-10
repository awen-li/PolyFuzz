#!/bin/sh

if [ ! -f "branch_vars.bv" ]; then
    echo "Warning: branch_vars.bv should be generated......"
    exit 0
fi

sasg -s tests/ -d ./ 
