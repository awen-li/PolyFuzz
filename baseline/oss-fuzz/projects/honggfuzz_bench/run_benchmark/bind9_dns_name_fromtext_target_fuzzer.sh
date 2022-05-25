#!/bin/sh

cd /root/honggfuzz_bench/bind9/

nohup sh run_dns_name_fromtext_target_fuzzer.sh > full.log 2>&1 &

python3 extract_log.py 1800 $0
