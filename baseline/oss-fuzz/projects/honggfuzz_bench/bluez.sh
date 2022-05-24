#!/bin/sh

sh install_honggfuzz.sh

cd bluez/

mkdir IN

echo A > IN/1

nohup honggfuzz -i IN/ -- fuzz_sdp ___FILE___ > full.log 2>&1 &

python extract_log.py
