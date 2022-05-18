#!/bin/sh

sh install_honggfuzz.sh

cd igraph/

unzip read_dl_fuzzer_seed_corpus.zip

nohup honggfuzz -i read_dl_fuzzer_seed_corpus/ -- read_dl_fuzzer ___FILE___ > full.log 2>&1 &

python extract_log.py
