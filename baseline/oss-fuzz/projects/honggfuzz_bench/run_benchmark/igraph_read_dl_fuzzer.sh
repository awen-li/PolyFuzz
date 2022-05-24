#!/bin/sh

cd /root/honggfuzz_bench/igraph/

nohup sh run_read_dl_fuzzer.sh > full.log 2>&1 &

python3 extract_log.py 1800 $0
