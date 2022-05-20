#!/bin/sh

python op_cmos.py ./tests > full.log 2>&1 &

python $BENCH/script/extract_log.py "op_cmos.py"

rm -rf full.log




