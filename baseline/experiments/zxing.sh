#!/bin/sh

apt install openjdk-11-jdk

export JAVA_HOME="/usr/lib/jvm/java-1.11.0-openjdk-amd64"

cd /root/jsan_1.2.3/zxing/

nohup sh run.sh > full.log 2>&1 &

python extract_log.py 1800 $0
