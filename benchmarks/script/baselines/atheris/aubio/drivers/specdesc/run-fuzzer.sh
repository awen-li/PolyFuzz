#!/bin/sh

python specdesc.py ../test_aubios > full.log 2>&1 &

python $BENCH/script/extract_log.py "specdesc.py"

rm -rf full.log




