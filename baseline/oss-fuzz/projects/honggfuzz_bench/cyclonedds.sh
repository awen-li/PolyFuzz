#!/bin/sh

sh install_honggfuzz.sh

cd cyclonedds/

unzip fuzz_config_init_seed_corpus.zip

nohup honggfuzz -i fuzz_config_init_seed_corpus/ -- fuzz_config_init ___FILE___ > full.log 2>&1 &

python extract_log.py
