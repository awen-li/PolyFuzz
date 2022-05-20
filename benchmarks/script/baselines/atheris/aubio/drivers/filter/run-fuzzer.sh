#!/bin/sh

python filter.py ../test_aubios > full.log 2>&1 &

python $BENCH/script/extract_log.py "filter.py"

rm -rf full.log




