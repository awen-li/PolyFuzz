#!/bin/sh

python tss.py ../test_aubios > full.log 2>&1 &

python $BENCH/script/extract_log.py "tss.py"

rm -rf full.log




