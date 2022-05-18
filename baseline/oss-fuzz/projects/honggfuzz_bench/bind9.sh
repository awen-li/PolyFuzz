#!/bin/sh

sh install_honggfuzz.sh

cd bind9/

unzip dns_message_parse_seed_corpus.zip

nohup honggfuzz -i dns_message_parse_seed_corpus -- dns_message_parse_fuzzer ___FILE___ /named.conf -g  > full.log 2>&1 &

python extract_log.py
