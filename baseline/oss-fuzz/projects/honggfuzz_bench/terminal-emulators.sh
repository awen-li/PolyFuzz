#!/bin/sh

apt install libbfd-dev
apt install libunwind8-dev
git clone https://github.com/google/honggfuzz.git
cd honggfuzz
make
make install
cd..
rm -rf honggfuzz

cd terminal-emulators

nohup honggfuzz -z -P -i IN/ -E LD_PRELOAD=libclose.so -- xterm -e terminal-test

python extract_log.py

