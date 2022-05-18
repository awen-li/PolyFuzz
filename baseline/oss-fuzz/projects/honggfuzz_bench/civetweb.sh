#!/bin/sh

sh install_honggfuzz.sh

cd civetweb/

mkdir IN

echo A > IN/1

nohup honggfuzz -i IN/ -- civetweb_fuzz1 ___FILE___ > full.log 2>&1 &

python extract_log.py
