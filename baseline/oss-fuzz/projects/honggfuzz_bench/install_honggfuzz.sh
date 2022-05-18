#!/bin/sh

apt install libbfd-dev
apt install libunwind8-dev
git clone https://github.com/google/honggfuzz.git
cd honggfuzz
make
make install
cd..
rm -rf honggfuzz
