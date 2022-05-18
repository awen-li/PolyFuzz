#!/bin/sh

apt install libbfd-dev
apt install libunwind8-dev
git clone https://github.com/google/honggfuzz.git
cd honggfuzz
make
make install
cd..
rm -rf honggfuzz

cd badcode/targets

make

cd ..

nohup honggfuzz -n1 -u -i inputfiles -- targets/badcode1 ___FILE___  > full.log 2>&1 &

python extract_log.py
