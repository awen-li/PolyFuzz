#!/bin/sh

python slicing.py ../test_aubios > full.log 2>&1 &

python $BENCH/script/extract_log.py "slicing.py"

rm -rf full.log
